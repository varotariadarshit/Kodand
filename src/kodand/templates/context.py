"""Context Engine v2 (Track A #3).

Classifies each line using both keyword cues and *document structure*:
  - frontmatter (between the first two `---` fences) -> "frontmatter"
  - fenced code blocks (```lang ... ```) -> "code"
  - mitigation / remediation guidance -> "mitigation"
  - detection / reference / documentation -> "reference"
  - warnings (never / do not ...) -> "warning"
  - examples -> "example"
  - otherwise -> "instruction"

Only "instruction" and "code" are treated as live/actionable; the rest are
non-actionable and cause confidence to be reduced.

`classify_line(line)` is kept for backward compatibility (line-local only).
`classify_document(text)` returns a per-line context list using full structure.
"""
from __future__ import annotations

WARNING_KEYWORDS = ("never", "do not", "don't", "must not", "should not",
                    "avoid", "forbidden", "prohibited", "not allowed")
EXAMPLE_KEYWORDS = ("example:", "for example:", "e.g.", "sample:", "for instance")
MITIGATION_KEYWORDS = ("to prevent", "to mitigate", "mitigation", "remediation",
                       "remediate", "recommended", "instead of", "rather than",
                       "best practice", "you should instead", "safe alternative")
REFERENCE_KEYWORDS = ("reference", "see also", "documentation", "docs:", "cve-",
                      "read more", "detection:", "detects", "for details",
                      "as described in", "background:")

NON_ACTIONABLE = {"warning", "example", "mitigation", "reference", "frontmatter"}


def _keyword_context(lowered: str) -> str:
    for k in MITIGATION_KEYWORDS:
        if k in lowered:
            return "mitigation"
    for k in WARNING_KEYWORDS:
        if k in lowered:
            return "warning"
    for k in REFERENCE_KEYWORDS:
        if k in lowered:
            return "reference"
    for k in EXAMPLE_KEYWORDS:
        if k in lowered:
            return "example"
    return "instruction"


def classify_line(line: str) -> str:
    """Backward-compatible line-local classifier."""
    return _keyword_context(line.lower().strip())


def is_actionable(context: str) -> bool:
    return context not in NON_ACTIONABLE


def classify_document(text: str) -> list[str]:
    """Return a context label for each line (1:1 with text.splitlines())."""
    lines = text.splitlines()
    contexts: list[str] = []
    in_front = False
    front_done = False
    in_code = False
    dash_count = 0
    for idx, line in enumerate(lines):
        stripped = line.strip()
        # frontmatter detection: first --- opens, second closes
        if stripped == "---" and not front_done:
            dash_count += 1
            in_front = dash_count == 1
            if dash_count >= 2:
                in_front = False
                front_done = True
            contexts.append("frontmatter")
            continue
        if in_front and not front_done:
            contexts.append("frontmatter")
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
