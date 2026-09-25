import json

from kodand.models.analysis import CorrelatedFinding, CoverageItem, FindingOccurrence, RepositoryAnalysis, Summary
from kodand.models.inventory import RepositoryInventory
from kodand.reporting import write_docx, write_html, write_pdf, write_sarif


def _analysis():
    inv = RepositoryInventory(repository_name="demo", repository_root="/tmp/demo")
    occ = FindingOccurrence(file="SKILL.md", line=1, column_start=1, excerpt="x", matched_value="x",
                            evidence_type="instruction", context="instruction", match_kind="literal", rule_id="R1")
    f = CorrelatedFinding(finding_id="KODAND-1", rule_id="R1", category="AST03", category_name="Over-Privileged Skills",
                         title="t", severity="high", confidence="high", description="d", technical_root_cause="d",
                         attack_scenario="d", preconditions="d", potential_impact="d", remediation="d",
                         validation_guidance="d", occurrence_count=1, occurrences=[occ], confidence_score=80)
    cov = [CoverageItem(category="AST03", name="Over-Privileged Skills", status="reviewed-findings", finding_count=1)]
    return RepositoryAnalysis(inventory=inv, findings=[f], coverage=cov,
                              summary=Summary(total=1, high=1, by_category={"AST03": 1}),
                              correlated_risks=["credential-exfiltration-risk"])


def test_write_html(tmp_path):
    p = tmp_path / "report.html"
    write_html(_analysis(), p)
    txt = p.read_text()
    assert "Kodand" in txt and "Correlated Risks" in txt and "credential-exfiltration-risk" in txt


def test_write_sarif(tmp_path):
    p = tmp_path / "r.sarif"
    write_sarif(_analysis(), p)
    data = json.loads(p.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]
    assert data["runs"][0]["results"][0]["ruleId"] == "R1"


def test_write_docx(tmp_path):
    p = tmp_path / "r.docx"
    write_docx(_analysis(), p)
    assert p.exists() and p.stat().st_size > 0


def test_write_pdf(tmp_path):
    p = tmp_path / "r.pdf"
    write_pdf(_analysis(), p)
    assert p.exists() and p.stat().st_size > 0
