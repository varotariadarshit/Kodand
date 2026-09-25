from datetime import date, timedelta
from pathlib import Path

from kodand.models.analysis import CorrelatedFinding, FindingOccurrence
from kodand.suppress import Suppression, apply_suppressions, load_suppressions_v2


def _mkf(rule="R1", cat="AST03", file="SKILL.md", fid="KODAND-1"):
    o = FindingOccurrence(file=file, line=1, column_start=1, excerpt="x", matched_value="x",
                          evidence_type="instruction", context="instruction", match_kind="literal", rule_id=rule)
    return CorrelatedFinding(finding_id=fid, rule_id=rule, category=cat, category_name=cat, title=rule,
                             severity="high", confidence="high", description="d", technical_root_cause="d",
                             attack_scenario="d", preconditions="d", potential_impact="d", remediation="d",
                             validation_guidance="d", occurrence_count=1, occurrences=[o])


def test_suppression_matches_by_rule():
    s = Suppression({"rule": "R1", "reason": "test"})
    assert s.matches(_mkf(rule="R1"))
    assert not s.matches(_mkf(rule="R2"))


def test_suppression_matches_by_category_and_finding_id():
    assert Suppression({"category": "AST03", "reason": "t"}).matches(_mkf(cat="AST03"))
    assert not Suppression({"category": "AST05", "reason": "t"}).matches(_mkf(cat="AST03"))
    assert Suppression({"finding_id": "KODAND-1", "reason": "t"}).matches(_mkf(fid="KODAND-1"))


def test_suppression_matches_by_path_glob():
    s = Suppression({"path": "tests/**", "reason": "t"})
    assert s.matches(_mkf(file="tests/fixtures/SKILL.md"))
    assert not s.matches(_mkf(file="src/SKILL.md"))


def test_suppression_with_no_selectors_matches_nothing():
    s = Suppression({"reason": "no selectors"})
    assert not s.matches(_mkf())


def test_suppression_expires():
    past = Suppression({"rule": "R1", "reason": "t", "expires": (date.today() - timedelta(days=1)).isoformat()})
    future = Suppression({"rule": "R1", "reason": "t", "expires": (date.today() + timedelta(days=1)).isoformat()})
    assert not past.active()
    assert future.active()


def test_load_suppressions_v2_legacy_and_rich_formats(tmp_path):
    (tmp_path / ".kodand.yml").write_text(
        "suppress_rules:\n  - LEGACY-RULE\n"
        "suppressions:\n  - rule: RICH-RULE\n    reason: reviewed\n"
    )
    rules = load_suppressions_v2(tmp_path)
    assert any(r.rule == "LEGACY-RULE" for r in rules)
    assert any(r.rule == "RICH-RULE" for r in rules)


def test_apply_suppressions_marks_status_and_excludes_active(tmp_path):
    (tmp_path / ".kodand.yml").write_text("suppressions:\n  - rule: R1\n    reason: reviewed fixture\n")
    findings = [_mkf(rule="R1", fid="KODAND-1"), _mkf(rule="R2", fid="Kodand-2")]
    active, suppressed_count = apply_suppressions(findings, tmp_path)
    assert suppressed_count == 1
    assert len(active) == 1 and active[0].rule_id == "R2"
