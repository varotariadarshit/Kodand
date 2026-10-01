"""Suppression framework v2 (Track A #6).

Reads `.kodand.yml` from the repository root. Supports both the legacy
`suppress_rules: [ID, ...]` list and a richer `suppressions:` block:

    suppressions:
      - rule: AST03-AWS-CREDENTIALS   # match by rule/template id (optional)
        path: "tests/**"              # glob against occurrence file (optional)
        finding_id: Kodand-XXShort     # match by finding id (optional)
        category: AST03               # match by category (optional)
        reason: "test fixtures"       # required for audit
        expires: 2026-12-31           # optional ISO date; ignored once past

A suppression matches a finding if all *provided* fields match. Expired
suppressions are ignored (so risk re-surfaces). Suppressed findings are marked
status="suppressed" with suppressed_reason and excluded from active counts.
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

    def matches(self, f: CorrelatedFinding) -> bool:
        if self.rule and self.rule != f.rule_id and self.rule not in f.merged_rule_ids:
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


def apply_suppressions(findings: list[CorrelatedFinding], root, extra: list[dict] | None = None) -> tuple[list[CorrelatedFinding], int]:
    """Mark matching findings as suppressed. Returns (active_findings, suppressed_count). `extra` adds
    entries kept outside the repo (the web console's per-project suppressions) to its `.kodand.yml`."""
    rules = [s for s in load_suppressions_v2(root) + [Suppression(d) for d in extra or []] if s.active()]
    if not rules:
        return findings, 0
    active, suppressed = [], 0
    for f in findings:
        hit = next((s for s in rules if s.matches(f)), None)
        if hit:
            f.status = "suppressed"
            f.suppressed_reason = hit.reason
            suppressed += 1
        else:
            active.append(f)
    return active, suppressed
