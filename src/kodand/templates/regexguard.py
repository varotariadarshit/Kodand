"""ReDoS guard for opt-in template regex (Track A #1).

Two layers of protection:
1. validate_pattern(): rejects catastrophic patterns at load time using a
   heuristic for nested/adjacent unbounded quantifiers, and rejects patterns
   that fail to compile.
2. safe_finditer(): caps input line length and runs the regex under a wall-clock
   budget in a worker thread; if a single match exceeds the budget the line is
   abandoned (fail-safe) instead of hanging the whole scan.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FTimeout

MAX_REGEX_LINE = 2000          # characters; longer lines are truncated before regex
PER_LINE_BUDGET = 0.25         # seconds per (pattern, line) match attempt

# Heuristics for catastrophic backtracking: nested quantifiers like (a+)+ , (a*)* ,
# (a+)* , (.*)+ , or two adjacent unbounded quantifiers on a group.
_NESTED_QUANT = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")
_ADJACENT_STAR = re.compile(r"[.\w\]\)][*+]\s*[.\w\[\(][*+]")


def validate_pattern(pattern: str) -> tuple[bool, str]:
    if not isinstance(pattern, str) or not pattern.strip():
        return False, "empty pattern"
    if len(pattern) > 512:
        return False, "pattern too long"
    if _NESTED_QUANT.search(pattern):
        return False, "nested unbounded quantifier (possible ReDoS)"
    if _ADJACENT_STAR.search(pattern):
        return False, "adjacent unbounded quantifiers (possible ReDoS)"
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return False, f"invalid regex: {e}"
    return True, "ok"


# shared executor (daemon threads); abandoned tasks are simply not awaited.
# ponytail: threads can't be killed, so a run that hits PER_LINE_BUDGET keeps consuming
# a worker slot for the life of the process instead of being freed — a long-running
# `kodand ui` scanning many catastrophic patterns could exhaust this pool over time.
# Custom template regex is already rejected at creation time by validate_pattern(),
# which substantially limits how often this ceiling is actually reached. If it becomes
# a real problem, switch to a process pool (which can be terminated) instead of a thread pool.
#
# Sized at 2, not 4: when scan_service.py parallelizes per-file matching across N worker
# PROCESSES, this module is re-imported fresh in each one (spawn context), so each process
# gets its OWN pool — total threads = N * max_workers, not one shared pool of 4. That's safe
# to shrink because usage within a single process is already strictly sequential (one file's
# templates are matched one at a time, never concurrent submits), so 2 is headroom, not a
# bottleneck, at any worker count.
_EXECUTOR = ThreadPoolExecutor(max_workers=2)


def safe_finditer(compiled: re.Pattern, line: str):
    """Yield match objects for `compiled` on `line`, with length cap + time budget.

    Returns a list (not a live generator) so the time budget bounds total work.
    """
    if len(line) > MAX_REGEX_LINE:
        line = line[:MAX_REGEX_LINE]

    def _run():
        return list(compiled.finditer(line))

    try:
        fut = _EXECUTOR.submit(_run)
        return fut.result(timeout=PER_LINE_BUDGET)
    except FTimeout:
        return []          # fail-safe: abandon this line's regex work
    except Exception:
        return []


FILE_PATTERN_BUDGET = 5.0  # seconds per (file, pattern) sweep across all of a file's lines


def safe_finditer_all(compiled: re.Pattern, views: list[tuple]) -> list[tuple]:
    """Run `compiled` against every (line_number, ctx, line, view_text, decoded_from) in
    `views`, guarded by ONE time budget for the whole sweep instead of one per line.

    `safe_finditer()` submits one executor task per line, which is fine for a handful
    of lines but the thread-pool submit/wait round trip dominates for files with many
    lines — a plain multi-hundred-thousand-line file with no malicious content at all
    could take minutes from that overhead alone, regardless of how fast each individual
    match attempt is. Batching to one submit per (file, pattern) fixes that; the
    tradeoff is a coarser fail-safe: if the budget is exceeded partway through, matches
    already found are kept and the rest of the file is skipped for this pattern only
    (not the whole scan). `views`' `view_text` entries are expected to already be
    length-capped by the caller (matcher.py truncates to MAX_REGEX_LINE before this).
    """
    results: list[tuple] = []

    def _run():
        for line_number, ctx, line, view_text, decoded_from in views:
            for m in compiled.finditer(view_text):
                results.append((line_number, ctx, line, view_text, decoded_from, m))

    try:
        fut = _EXECUTOR.submit(_run)
        fut.result(timeout=FILE_PATTERN_BUDGET)
    except FTimeout:
        pass  # fail-safe: keep whatever was found before the budget ran out
    except Exception:
        pass
    return results
