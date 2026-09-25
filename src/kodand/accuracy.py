"""Accuracy pipeline: dedup + evidence merge (Track A #2) and proximity /
multi-signal escalation (Track A #5).

Operates on the list of CorrelatedFinding produced by the template scan.
"""
from __future__ import annotations

from kodand.models.analysis import CorrelatedFinding
from kodand.templates.confidence import score_finding, score_to_label
from kodand.templates.context import is_actionable

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# capability pairs that, when co-located within PROXIMITY_WINDOW lines in the
# same file, indicate a stronger multi-signal risk
PROXIMITY_PAIRS = {
    frozenset({"credential-access", "network-access"}): "credential-exfiltration",
    frozenset({"credential-access", "external-instruction"}): "credential-exfiltration",
    frozenset({"credential-access", "data-exfiltration"}): "credential-exfiltration",
    frozenset({"shell-execution", "network-access"}): "remote-code-execution",
    frozenset({"shell-execution", "external-instruction"}): "remote-code-execution",
    frozenset({"isolation-escape", "shell-execution"}): "host-compromise",
    frozenset({"scanner-evasion", "code-execution"}): "stealth-payload",
}
PROXIMITY_WINDOW = 12


def dedup_findings(findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
    """Merge findings that describe the same span/issue.

    Two-level:
      1. Within each finding, keep one occurrence per file:line — a literal and a
         regex (or a decoded view) hitting the same line are one piece of evidence.
      2. Across findings of the same category that share an identical
         (file, line, matched_value) span, merge into the highest-severity
         finding and record the others in merged_rule_ids.
    """
    # level 1: occurrence de-dupe
    for f in findings:
        seen = set()
        uniq = []
        for o in f.occurrences:
            key = (o.file, o.line)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(o)
        f.occurrences = uniq
        f.occurrence_count = len(uniq)

    # level 2: cross-rule same-span merge (within a category)
    def span_set(f):
        return {(o.file, o.line, o.matched_value.lower()) for o in f.occurrences}

    findings = sorted(findings, key=lambda f: (SEV_RANK.get(f.severity, 9), f.rule_id))
    merged: list[CorrelatedFinding] = []
    for f in findings:
        target = None
        fs = span_set(f)
        for m in merged:
            if m.category == f.category and fs & span_set(m):
                target = m
                break
        if target is None:
            merged.append(f)
            continue
        # merge f into target
        existing = {(o.file, o.line) for o in target.occurrences}
        for o in f.occurrences:
            key = (o.file, o.line)
            if key not in existing:
                target.occurrences.append(o)
                existing.add(key)
        target.occurrence_count = len(target.occurrences)
        target.affected_files = sorted(set(target.affected_files) | set(f.affected_files))
        target.capabilities = sorted(set(target.capabilities) | set(f.capabilities))
        if f.rule_id not in target.merged_rule_ids and f.rule_id != target.rule_id:
            target.merged_rule_ids.append(f.rule_id)
    return merged


def apply_proximity(findings: list[CorrelatedFinding]) -> None:
    """Flag findings whose capabilities co-occur near another finding's."""
    # build (file -> list of (line, capability, finding))
    index: dict[str, list[tuple[int, str, CorrelatedFinding]]] = {}
    for f in findings:
        for o in f.occurrences:
            for cap in f.capabilities:
                index.setdefault(o.file, []).append((o.line, cap, f))

    for f in findings:
        # non-actionable findings (only warning/example/mitigation evidence) do
        # not participate in proximity escalation
        if not any(is_actionable(o.context) for o in f.occurrences):
            continue
        signals = set()
        for o in f.occurrences:
            if not is_actionable(o.context):
                continue
            near = index.get(o.file, [])
            local_caps = {c for (ln, c, other) in near if abs(ln - o.line) <= PROXIMITY_WINDOW}
            for cap in f.capabilities:
                for other_cap in local_caps:
                    pair = frozenset({cap, other_cap})
                    if pair in PROXIMITY_PAIRS:
                        signals.add(PROXIMITY_PAIRS[pair])
        if signals:
            f.proximity_signals = sorted(signals)


def apply_relationship_signals(findings: list[CorrelatedFinding], declared_files: frozenset) -> None:
    """Flag findings whose occurrences sit in a file the skill's own
    entrypoint explicitly declares/references (see relationships.py)."""
    if not declared_files:
        return
    for f in findings:
        if any(is_actionable(o.context) and o.file in declared_files for o in f.occurrences):
            f.relationship_signals = ["referenced-by-skill-entrypoint"]


def finalize_scores(findings: list[CorrelatedFinding]) -> None:
    """Compute composite 0-100 score + label for each finding."""
    for f in findings:
        contexts = [o.context for o in f.occurrences] or ["instruction"]
        kinds = [o.match_kind for o in f.occurrences] or ["literal"]
        score = score_finding(
            base_confidence=f.confidence, contexts=contexts, match_kinds=kinds,
            occurrence_count=f.occurrence_count, capability_count=len(f.capabilities),
            proximity=bool(f.proximity_signals), relationship=bool(f.relationship_signals),
        )
        f.confidence_score = score
        f.confidence = score_to_label(score)


def run_accuracy_pipeline(findings: list[CorrelatedFinding], declared_files: frozenset = frozenset()) -> list[CorrelatedFinding]:
    findings = dedup_findings(findings)
    apply_proximity(findings)
    apply_relationship_signals(findings, declared_files)
    finalize_scores(findings)
    findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), -f.confidence_score, f.category, f.title))
    return findings
