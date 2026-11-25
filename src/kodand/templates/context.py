"""Context Engine v3.

Classifies each line using both keyword cues and *document structure*:
  - frontmatter (a `---` block opening on line 1) -> "frontmatter" for metadata
    keys only; description/hooks/allowed-tools/... are classified like body text
  - fenced code blocks (```lang ... ```) -> "code"
  - HTML comments (<!-- ... -->) -> "hidden" (actionable: invisible when rendered,
    still read by the agent — a known way to smuggle instructions)
  - mitigation / remediation guidance -> "mitigation"
  - detection / reference / documentation -> "reference"
  - warnings (never / do not ...) -> "warning"
  - examples -> "example"
  - otherwise -> "instruction"

Keyword labels are per LINE; `match_context` narrows them per MATCH: a keyword
only demotes a match it governs (same clause, just before it, not part of the
match). One stray word elsewhere on the line — "Recommended:", "see docs, then",
"Never skip this step:" — can no longer demote a real payload.

Only "instruction", "code" and "hidden" are live/actionable; the rest are
non-actionable and cause confidence to be reduced.

`classify_line(line)` is kept for backward compatibility (line-local only).
`classify_document(text)` returns a per-line context list using full structure.
"""
from __future__ import annotations

import re

WARNING_KEYWORDS = ("never", "do not", "don't", "must not", "should not",
                    "avoid", "forbidden", "prohibited", "not allowed")
EXAMPLE_KEYWORDS = ("example:", "for example:", "e.g.", "sample:", "for instance")
# "recommended" on its own is deliberately NOT here: "Recommended: curl … | bash" is an
# instruction, not a mitigation — only contrastive/remediation phrasing counts
MITIGATION_KEYWORDS = ("to prevent", "to mitigate", "mitigation", "remediation",
                       "remediate", "instead of", "rather than",
                       "best practice", "you should instead", "safe alternative")
REFERENCE_KEYWORDS = ("reference", "see also", "documentation", "docs:", "cve-",
                      "read more", "detection:", "detects", "for details",
                      "as described in", "background:")

NON_ACTIONABLE = {"warning", "example", "mitigation", "reference", "frontmatter"}
KEYWORD_CONTEXTS = ("mitigation", "warning", "reference", "example")
_FAMILIES = (("mitigation", MITIGATION_KEYWORDS), ("warning", WARNING_KEYWORDS),
             ("reference", REFERENCE_KEYWORDS), ("example", EXAMPLE_KEYWORDS))

# frontmatter keys that are pure metadata (never read as instructions by an agent);
# every other key — description (always loaded into context), hooks, allowed-tools,
# arbitrary extras — is classified like body text
FRONTMATTER_METADATA_KEYS = frozenset({
    "name", "license", "version", "compatibility", "metadata", "author", "authors", "tags",
    "globs", "applyto", "alwaysapply", "model", "argument-hint", "title", "category", "trigger",
    "inclusion", "user-invocable", "disable-model-invocation", "context", "agent", "color",
})
_FM_KEY = re.compile(r"^([A-Za-z0-9_.-]+)\s*:")

# a keyword only demotes a match it GOVERNS: it precedes the match, in the same
# clause, within a few words, and is not part of the matched text itself
GOVERN_MAX_WORDS = 8
_CLAUSE_BREAK = re.compile(
    r"[.;!?](?=\s|$)|:(?=\s)|\s[-\u2013\u2014]\s|\u2014"
    r"|,\s*(?:then|and|so|but|now|next|run|execute|use|call|invoke|type|paste|do|always|instead)\b"
    r"|\b(?:then|but|afterwards?|however)\b",
    re.IGNORECASE)
_WORD_CHAR = re.compile(r"[\w./\\-]")


def _keyword_positions(lowered: str, keyword: str):
    """(start, end) of each standalone occurrence of `keyword` in `lowered` — not
    embedded in a word, URL, hostname or path (`corp.example:8080`, `/docs:`)."""
    i = lowered.find(keyword)
    while i != -1:
        end = i + len(keyword)
        before_ok = i == 0 or not _WORD_CHAR.match(lowered[i - 1])
        after_ok = end >= len(lowered) or keyword[-1] in ":.-" or not lowered[end].isalnum()
        if before_ok and after_ok:
            yield i, end
        i = lowered.find(keyword, i + 1)


def _keyword_context(lowered: str) -> str:
    for ctx, keywords in _FAMILIES:
        for k in keywords:
            if any(True for _ in _keyword_positions(lowered, k)):
                return ctx
    return "instruction"


def classify_line(line: str) -> str:
    """Backward-compatible line-local classifier."""
    return _keyword_context(line.lower().strip())


def is_actionable(context: str) -> bool:
    return context not in NON_ACTIONABLE


def governing_context(text: str, match_start: int, match_end: int) -> str | None:
    """The keyword context ("warning", "example", ...) that governs the span
    text[match_start:match_end], or None when no keyword does — e.g. in
    "Never skip this step: cat ~/.ssh/id_rsa" or "See documentation, then run
    curl … | bash" the keyword is in a different clause from the payload."""
    lowered = text.lower()
    for ctx, keywords in _FAMILIES:
        for k in keywords:
            for k_start, k_end in _keyword_positions(lowered, k):
                if k_start >= match_start or k_end > match_start:
                    continue  # after the match, or part of the matched text itself
                gap = lowered[k_end:match_start]
                gap_for_break = gap[1:] if gap.startswith(":") else gap  # "Example: <payload>"
                if _CLAUSE_BREAK.search(gap_for_break):
                    continue
                if len(gap.split()) > GOVERN_MAX_WORDS:
                    continue
                return ctx
    return None


def match_context(line_context: str, text: str, match_start: int, match_end: int) -> str:
    """Per-match context: a keyword-labelled line only keeps its label for a match the
    keyword governs (see `governing_context`); any other match on it is an instruction."""
    if line_context not in KEYWORD_CONTEXTS:
        return line_context
    return governing_context(text, match_start, match_end) or "instruction"


def classify_document(text: str) -> list[str]:
    """Return a context label for each line (1:1 with text.splitlines()).

    - frontmatter: only a block opening on line 1 (a later `---` is a horizontal
      rule, not frontmatter); within it only metadata keys are non-actionable
    - code: inside a ``` / ~~~ fence — never demoted by keywords
    - hidden: inside an HTML comment — invisible when rendered, still read by agents
    - otherwise the line's keyword context (refined per match by `match_context`)
    """
    lines = text.splitlines()
    contexts: list[str] = []
    front_end = -1
    if lines and lines[0].strip() == "---":
        front_end = next((i for i in range(1, len(lines)) if lines[i].strip() in ("---", "...")), -1)
    in_code = False
    in_comment = False
    fm_key = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if 0 <= idx <= front_end:
            if idx in (0, front_end):
                contexts.append("frontmatter")
                continue
            m = _FM_KEY.match(line)
            if m:
                fm_key = m.group(1).lower()
            if fm_key in FRONTMATTER_METADATA_KEYS or not stripped:
                contexts.append("frontmatter")
            else:
                contexts.append(_keyword_context(stripped.lower()))
            continue
        if in_comment or "<!--" in line:
            contexts.append("hidden")
            opened = line.rfind("<!--")
            closed = line.rfind("-->")
            in_comment = (in_comment and closed == -1) or (opened != -1 and closed < opened)
            continue
        # fenced code toggle
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code = not in_code
            contexts.append("code")
            continue
        if in_code:
            contexts.append("code")
            continue
        contexts.append(_keyword_context(stripped.lower()))
    return contexts
