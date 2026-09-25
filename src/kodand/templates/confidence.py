"""Composite confidence scoring (Track A #4).

v2 returned only a label. v3 computes a 0-100 score from:
  base(confidence) x context_weight x match_kind x evidence x capability corroboration
and maps it back to a high/medium/low label for compatibility.

`calculate_confidence(base, context)` is kept for backward compatibility.
`score_finding(...)` produces the composite 0-100 score.
"""
from __future__ import annotations

from kodand.templates.context import is_actionable

_BASE = {"high": 80, "medium": 55, "low": 32}
_CONTEXT_WEIGHT = {
    "instruction": 1.0,
    "code": 1.05,          # payload inside a code fence is slightly stronger
    "frontmatter": 1.0,
    "warning": 0.35,
    "example": 0.35,
    "mitigation": 0.30,
    "reference": 0.40,
}
_MATCH_KIND = {"literal": 1.0, "regex": 1.05, "decoded": 1.1, "ast": 1.1}


def calculate_confidence(base_confidence: str, context: str) -> str:
    """Backward-compatible label-only mapping used by the v2 matcher path."""
    if is_actionable(context):
        return base_confidence
    return "low"


def score_to_label(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


# Findings whose strongest evidence is non-actionable (only warning / example /
# mitigation / reference / frontmatter context) are capped below the actionable
# threshold and never receive corroboration or proximity boosts.
NON_ACTIONABLE_CAP = 40


def score_finding(base_confidence: str, contexts: list[str], match_kinds: list[str],
                  occurrence_count: int, capability_count: int,
                  proximity: bool = False, relationship: bool = False) -> int:
    base = _BASE.get(base_confidence, 50)
    has_actionable = any(is_actionable(c) for c in contexts)
    ctx_weight = max((_CONTEXT_WEIGHT.get(c, 0.5) for c in contexts), default=1.0)
    mk_weight = max((_MATCH_KIND.get(m, 1.0) for m in match_kinds), default=1.0)
    score = base * ctx_weight * mk_weight
    if not has_actionable:
        # non-actionable evidence: no corroboration/proximity/relationship; hard cap
        return max(0, min(NON_ACTIONABLE_CAP, round(score)))
    # evidence corroboration: +4 per extra occurrence, capped +16
    score += min(max(occurrence_count - 1, 0) * 4, 16)
    if capability_count >= 2:
        score += 8
    if proximity:
        score += 10
    if relationship:
        # the risky file is one the skill's own entrypoint explicitly
        # references/declares — same flat bump as proximity, for parity
        score += 10
    return max(0, min(100, round(score)))
