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
    active, suppressed_count = apply_suppressions(findings, tmp_path, trust_repo=True)
    assert suppressed_count == 1
    assert len(active) == 1 and active[0].rule_id == "R2"


def test_repo_suppression_file_is_ignored_unless_trusted(tmp_path):
    (tmp_path / ".kodand.yml").write_text("suppress_rules: [R1]\n")
    active, n = apply_suppressions([_mkf(rule="R1")], tmp_path)
    assert n == 0 and len(active) == 1
    # console/project suppressions (extra) still apply without trusting the repo
    active, n = apply_suppressions([_mkf(rule="R1")], tmp_path, extra=[{"rule": "R1", "reason": "console"}])
    assert n == 1 and not active


def _two_files(rule="R1"):
    f = _mkf(rule=rule)
    o2 = f.occurrences[0].model_copy(update={"file": "tests/fixtures/x.md", "line": 9})
    f.occurrences = [f.occurrences[0], o2]
    f.occurrence_count = 2
    f.affected_files = ["SKILL.md", "tests/fixtures/x.md"]
    return f


def test_path_suppression_drops_only_matching_occurrences(tmp_path):
    active, n = apply_suppressions([_two_files()], tmp_path, extra=[{"path": "tests/**", "reason": "fixtures"}])
    assert n == 0 and len(active) == 1
    assert [o.file for o in active[0].occurrences] == ["SKILL.md"]
    assert active[0].occurrence_count == 1 and active[0].affected_files == ["SKILL.md"]


def test_finding_suppressed_when_every_occurrence_matches(tmp_path):
    active, n = apply_suppressions([_two_files()], tmp_path, extra=[{"rule": "R1", "reason": "accepted"}])
    assert n == 1 and not active


def test_suppressing_a_merged_rule_does_not_hide_the_surviving_finding(tmp_path):
    f = _mkf(rule="R2")
    f.merged_rule_ids = ["R1"]
    active, n = apply_suppressions([f], tmp_path, extra=[{"rule": "R1", "reason": "x"}])
    assert n == 0 and len(active) == 1


def test_scan_warns_when_repo_suppressions_are_ignored(tmp_path):
    from kodand.webui.scan_service import run_template_scan
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\ncat ~/.ssh/id_rsa\n")
    (tmp_path / ".kodand.yml").write_text("suppress_rules: [AST03-SSH-KEYS]\n")
    res = run_template_scan(str(tmp_path), use_custom=False, custom_dir=None, out_dir=tmp_path / "a",
                            formats=("json",), use_cache=False)
    assert res["suppressed"] == 0 and any(w["code"] == "REPO_SUPPRESSIONS_IGNORED" for w in res["warnings"])
    res = run_template_scan(str(tmp_path), use_custom=False, custom_dir=None, out_dir=tmp_path / "b",
                            formats=("json",), use_cache=False, trust_repo_suppressions=True)
    assert res["suppressed"] == 1 and not any(w["code"] == "REPO_SUPPRESSIONS_IGNORED" for w in res["warnings"])
