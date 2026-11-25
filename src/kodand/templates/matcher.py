"""Kodand v3 matcher: literal + opt-in regex + decoded views, Context Engine v2.

Backward compatible: TemplateMatch keeps all v2 fields and adds `match_kind`
and `decoded_from`. `match_template_file` still returns a list of TemplateMatch.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from kodand.redaction import redact
from kodand.templates.confidence import calculate_confidence
from kodand.templates.context import classify_document, match_context
from kodand.templates.models import KodandTemplate
from kodand.templates.normalize import normalized_views
from kodand.templates.regexguard import MAX_REGEX_LINE, safe_finditer_all

MAX_FILE_BYTES = 50_000_000  # ponytail: hard per-file cap, skip oversized files rather than a smarter streaming scan


@dataclass(frozen=True)
class TemplateMatch:
    template_id: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    column_start: int
    column_end: int
    matched_value: str
    excerpt: str
    context: str
    match_kind: str = "literal"
    decoded_from: str | None = None


def _compiled_regex(template: KodandTemplate):
    out = []
    for rx in getattr(template.detection, "regex", []) or []:
        try:
            out.append(re.compile(rx, re.IGNORECASE))
        except re.error:
            continue
    return out


_BINARY_SNIFF_BYTES = 8192


def decode_text(data: bytes) -> str | None:
    """Bytes -> text for matching. UTF-16/32 by BOM (PowerShell commonly saves as
    UTF-16LE, which a plain UTF-8 decode turns into unmatchable NUL-interleaved
    noise), else UTF-8 with replacement. Returns None for binary content (a NUL
    byte in the first 8 KB of a non-UTF-16/32 file)."""
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return data.decode("utf-32", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8-sig", errors="replace")


def read_file(file_path: Path, repository_root: Path):
    """Cheap phase of `precompute_file_views`: read the file and resolve its
    relative path. Split out so a parallel-scan worker can hash/dispatch on
    `text` before paying for the classify/normalize pass below.

    Returns `(relative_path, text)`, or `None` if the file is unreadable or
    exceeds `MAX_FILE_BYTES`.
    """
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return None
        text = decode_text(file_path.read_bytes())
    except OSError:
        return None
    if text is None:
        return None
    try:
        relative_path = file_path.relative_to(repository_root).as_posix()
    except ValueError:
        relative_path = file_path.as_posix()
    return relative_path, text


def build_views(text: str) -> list[tuple]:
    """Expensive phase of `precompute_file_views`: classify + de-obfuscate a file's
    text ONCE, for reuse across every template.

    `match_template_file` used to do this work itself, which meant a full
    context-classification pass and per-line normalization/decoding pass were
    repeated once per template (46+ times for the builtin pack alone) for the
    exact same file. Hoisting it here so `scan_service.py` can call it once per
    file and reuse the result for all templates is what actually makes scanning
    large repositories/files tractable — see `match_template_views`.

    Returns a list of `(line_number, ctx, line, view_text, decoded_from)`.
    """
    contexts = classify_document(text)
    lines = text.splitlines()
    views = []
    for line_number, line in enumerate(lines, start=1):
        ctx = contexts[line_number - 1] if line_number - 1 < len(contexts) else "instruction"
        # bound per-line work: normalize/decode does several full-line, pure-Python passes, so
        # a long line is matched as overlapping MAX_REGEX_LINE windows (a payload padded past
        # the first 2000 chars is still seen), up to MAX_LINE_WINDOWS; past that the rest of
        # the line is skipped and reported (see LONG_LINES_CLIPPED)
        for scan_line in _line_windows(line, line_number):
            for view_text, decoded_from in normalized_views(scan_line):
                views.append((line_number, ctx, line, view_text, decoded_from))
        # shell line continuations: also match the joined command, attributed to its first line
        if line.rstrip().endswith("\\") and (line_number == 1 or not lines[line_number - 2].rstrip().endswith("\\")):
            joined, j = [line.rstrip()[:-1]], line_number
            while j < len(lines) and len(joined) < MAX_CONTINUATION_LINES:
                nxt = lines[j]
                cont = nxt.rstrip().endswith("\\")
                joined.append(nxt.rstrip()[:-1] if cont else nxt)
                j += 1
                if not cont:
                    break
            views.append((line_number, ctx, line, " ".join(p.strip() for p in joined)[:MAX_REGEX_LINE], None))
    return views


MAX_LINE_WINDOWS = 25            # 25 x 2000 chars of one line, then stop (and report)
_WINDOW_OVERLAP = 200            # a match straddling a window edge still fits in one window
MAX_CONTINUATION_LINES = 10
# (line_number, length) of lines longer than MAX_LINE_WINDOWS windows since the last reset —
# read by the scan to report a coverage warning
LONG_LINES_CLIPPED: list[tuple[int, int]] = []


def _line_windows(line: str, line_number: int):
    if len(line) <= MAX_REGEX_LINE:
        yield line
        return
    step = MAX_REGEX_LINE - _WINDOW_OVERLAP
    for n, start in enumerate(range(0, len(line), step)):
        if n == MAX_LINE_WINDOWS:
            LONG_LINES_CLIPPED.append((line_number, len(line)))
            return
        yield line[start:start + MAX_REGEX_LINE]
        if start + MAX_REGEX_LINE >= len(line):
            return


def precompute_file_views(file_path: Path, repository_root: Path):
    """Read + classify + de-obfuscate a file ONCE — see `read_file`/`build_views`.

    Returns `(relative_path, views)`, or `None` if the file is unreadable or
    exceeds `MAX_FILE_BYTES`.
    """
    result = read_file(file_path, repository_root)
    if result is None:
        return None
    relative_path, text = result
    return relative_path, build_views(text)


def match_template_views(template: KodandTemplate, relative_path: str, views: list[tuple]):
    """Match one template against a file's precomputed views (see `precompute_file_views`)."""
    matches: list[TemplateMatch] = []
    regexes = _compiled_regex(template)
    indicators = [i for i in template.detection.match if i]

    # --- literal substring matching (v2 behavior, on normalized views) ---
    for line_number, ctx, line, view_text, decoded_from in views:
        lowered_line = view_text.lower()
        kind = "decoded" if decoded_from else "literal"
        for indicator in indicators:
            lowered_indicator = indicator.lower()
            search_start = 0
            while True:
                match_index = lowered_line.find(lowered_indicator, search_start)
                if match_index == -1:
                    break
                col_start = match_index + 1
                col_end = match_index + len(indicator) + 1
                matched_value = view_text[match_index:match_index + len(indicator)]
                mctx = match_context(ctx, view_text, match_index, match_index + len(indicator))
                matches.append(TemplateMatch(
                    template_id=template.id, category=template.info.category,
                    severity=template.info.severity,
                    confidence=calculate_confidence(template.info.confidence, mctx),
                    file=relative_path, line=line_number,
                    column_start=col_start, column_end=col_end,
                    matched_value=redact(matched_value), excerpt=redact(line.strip()[:700]),
                    context=mctx, match_kind=kind, decoded_from=decoded_from))
                search_start = match_index + len(indicator)

    # --- opt-in regex matching (v3), ReDoS-guarded per (file, pattern) ---
    for rx in regexes:
        for line_number, ctx, line, view_text, decoded_from, m in safe_finditer_all(rx, views):
            raw = m.group(0)
            if not raw:
                continue
            mctx = match_context(ctx, view_text, m.start(), m.end())
            matches.append(TemplateMatch(
                template_id=template.id, category=template.info.category,
                severity=template.info.severity,
                confidence=calculate_confidence(template.info.confidence, mctx),
                file=relative_path, line=line_number,
                column_start=m.start() + 1, column_end=m.end() + 1,
                matched_value=redact(raw[:200]), excerpt=redact(line.strip()[:700]),
                context=mctx, match_kind="regex" if not decoded_from else "decoded",
                decoded_from=decoded_from))
    return matches


def match_template_file(template: KodandTemplate, file_path: Path, repository_root: Path):
    """Match one template against one file. Convenience wrapper for single-file/single-template
    callers (CLI, tests); scanning many templates against the same file should instead call
    `precompute_file_views` once and reuse it across `match_template_views` calls."""
    precomputed = precompute_file_views(file_path, repository_root)
    if precomputed is None:
        return []
    relative_path, views = precomputed
    return match_template_views(template, relative_path, views)
