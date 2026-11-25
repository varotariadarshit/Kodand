"""Suppression framework v2 (Track A #6).

Reads `.kodand.yml` from the repository root — only when the caller explicitly
trusts the scanned repository (`trust_repo=True`: `kodand analyze
--trust-repo-suppressions`, the console's per-project toggle, the MCP `scan`
argument). By default a scanned repo cannot suppress its own findings: a
malicious skill pack could otherwise ship a `.kodand.yml` hiding itself.
Supports both the legacy
`suppress_rules: [ID, ...]` list and a richer `suppressions:` block:

    suppressions:
      - rule: AST03-AWS-CREDENTIALS   # match by rule/template id (optional)
        path: "tests/**"              # glob against occurrence file (optional)
        finding_id: Kodand-XXShort     # match by finding id (optional)
        category: AST03               # match by category (optional)
        reason: "test fixtures"       # required for audit
        expires: 2026-12-31           # optional ISO date; ignored once past

A suppression matches an OCCURRENCE if all *provided* fields match (`rule`
against the occurrence's own rule, `path` against its file). A finding is
suppressed only when every occurrence is; otherwise just the matched
occurrences are dropped and the rest stays active — `path: tests/**` never
hides the same rule's hit in a SKILL.md. Expired suppressions are ignored (so
risk re-surfaces). Suppressed findings are marked status="suppressed" with
suppressed_reason and excluded from active counts.
"""
from __future__ import annotations

import fnmatch
from datetime import date, datetime
from pathlib import Path

import yaml

from kodand.models.analysis import CorrelatedFinding


class Suppression:
    def __init__(self, d: dict):
        self.rule = (d.get("rule") or d.get("rule_id") or "").strip() or None
        self.path = (d.get("path") or "").strip() or None
        self.finding_id = (d.get("finding_id") or "").strip() or None
        self.category = (d.get("category") or "").strip().upper() or None
        self.reason = (d.get("reason") or "unspecified").strip()
        self.expires = self._parse_date(d.get("expires"))

    @staticmethod
    def _parse_date(v):
        if not v:
            return None
        if isinstance(v, date):
            return v
        try:
            return datetime.strptime(str(v), "%Y-%m-%d").date()
        except ValueError:
            return None

    def active(self, today: date | None = None) -> bool:
        if self.expires is None:
            return True
        return (today or date.today()) <= self.expires

    def _selectors(self) -> bool:
        return any([self.rule, self.category, self.finding_id, self.path])

    def matches_occurrence(self, f: CorrelatedFinding, o) -> bool:
        if not self._selectors():
            return False
        if self.rule and self.rule != (getattr(o, "rule_id", None) or f.rule_id):
            return False
        if self.category and self.category != f.category:
            return False
        if self.finding_id and self.finding_id != f.finding_id:
            return False
        if self.path and not fnmatch.fnmatch(o.file, self.path):
            return False
        return True

    def matches(self, f: CorrelatedFinding) -> bool:
        """Finding-level match (used when a finding has no occurrences). A rule
        selector matches the finding's own rule only — never a rule merged into it."""
        if self.rule and self.rule != f.rule_id:
            return False
        if self.category and self.category != f.category:
            return False
        if self.finding_id and self.finding_id != f.finding_id:
            return False
        if self.path:
            if not any(fnmatch.fnmatch(o.file, self.path) for o in f.occurrences) \
               and not any(fnmatch.fnmatch(af, self.path) for af in f.affected_files):
                return False
        # a suppression with no selectors matches nothing (safety)
        if not any([self.rule, self.category, self.finding_id, self.path]):
            return False
        return True


def load_suppressions_v2(root) -> list[Suppression]:
    p = Path(root) / ".kodand.yml"
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return []
    out = []
    for item in data.get("suppressions", []) or []:
        if isinstance(item, dict):
            out.append(Suppression(item))
    # legacy list -> rule suppressions
    for rid in data.get("suppress_rules", []) or []:
        out.append(Suppression({"rule": rid, "reason": "legacy suppress_rules"}))
    return out


def repo_suppression_file(root) -> Path | None:
    p = Path(root) / ".kodand.yml"
    return p if p.exists() else None


def apply_suppressions(findings: list[CorrelatedFinding], root, extra: list[dict] | None = None,
                       trust_repo: bool = False) -> tuple[list[CorrelatedFinding], int]:
    """Mark matching findings as suppressed. Returns (active_findings, suppressed_count). `extra` adds
    entries kept outside the repo (the web console's per-project suppressions). The scanned repo's own
    `.kodand.yml` is only read when `trust_repo` is set."""
    repo_rules = load_suppressions_v2(root) if trust_repo else []
    rules = [s for s in repo_rules + [Suppression(d) for d in extra or []] if s.active()]
    if not rules:
        return findings, 0
    active, suppressed = [], 0
    for f in findings:
        if not f.occurrences:
            hit = next((s for s in rules if s.matches(f)), None)
            if hit:
                f.status, f.suppressed_reason = "suppressed", hit.reason
                suppressed += 1
            else:
                active.append(f)
            continue
        kept, first_hit = [], None
        for o in f.occurrences:
            hit = next((s for s in rules if s.matches_occurrence(f, o)), None)
            if hit:
                first_hit = first_hit or hit
            else:
                kept.append(o)
        if not kept:
            f.status, f.suppressed_reason = "suppressed", first_hit.reason
            suppressed += 1
            continue
        if len(kept) != len(f.occurrences):
            f.occurrences = kept
            f.occurrence_count = len(kept)
            f.affected_files = sorted({o.file for o in kept})
        active.append(f)
    return active, suppressed
