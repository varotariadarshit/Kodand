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
from kodand.templates.context import classify_document
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
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
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
    views = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        ctx = contexts[line_number - 1] if line_number - 1 < len(contexts) else "instruction"
        # cap per-line work: normalize/decode does several full-line, pure-Python passes
        # (homoglyph folding, base64/hex/url decode + printable-ratio scoring) that are
        # cheap per line but not bounded by MAX_FILE_BYTES alone — a single pathologically
        # long line (e.g. one huge minified/no-newline blob) could otherwise dominate scan
        # time even in an otherwise-small file.
        scan_line = line if len(line) <= MAX_REGEX_LINE else line[:MAX_REGEX_LINE]
        for view_text, decoded_from in normalized_views(scan_line):
            views.append((line_number, ctx, line, view_text, decoded_from))
    return views


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
                matches.append(TemplateMatch(
                    template_id=template.id, category=template.info.category,
                    severity=template.info.severity,
                    confidence=calculate_confidence(template.info.confidence, ctx),
                    file=relative_path, line=line_number,
                    column_start=col_start, column_end=col_end,
                    matched_value=redact(matched_value), excerpt=redact(line.strip()[:700]),
                    context=ctx, match_kind=kind, decoded_from=decoded_from))
                search_start = match_index + len(indicator)

    # --- opt-in regex matching (v3), ReDoS-guarded per (file, pattern) ---
    for rx in regexes:
        for line_number, ctx, line, view_text, decoded_from, m in safe_finditer_all(rx, views):
            raw = m.group(0)
            if not raw:
                continue
            matches.append(TemplateMatch(
                template_id=template.id, category=template.info.category,
                severity=template.info.severity,
                confidence=calculate_confidence(template.info.confidence, ctx),
                file=relative_path, line=line_number,
                column_start=m.start() + 1, column_end=m.end() + 1,
                matched_value=redact(raw[:200]), excerpt=redact(line.strip()[:700]),
                context=ctx, match_kind="regex" if not decoded_from else "decoded",
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
