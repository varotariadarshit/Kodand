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


def test_html_report_sections_are_collapsible(tmp_path):
    # wired client-side: every top-level .section-title becomes a toggle (checked in a browser);
    # the static HTML keeps its plain structure so print/PDF and no-JS viewers see everything
    p = tmp_path / "report.html"
    write_html(_analysis(), p)
    txt = p.read_text()
    assert "initSections();" in txt and "Collapse all" in txt
    assert ".sec-body.sec-hidden{display:none}" in txt
    assert "@media print{.sec-body.sec-hidden{display:block!important}" in txt
    assert 'class="sec-body' not in txt.split("<script>")[0]  # no section is pre-collapsed in the markup


def test_html_report_shows_the_kodand_agent_scope(tmp_path):
    from kodand.models.inventory import AgentScopeInfo
    a = _analysis()
    a.inventory.agent_scope = AgentScopeInfo(
        status="used", files_total=10, files_crawled=8, binary_skipped=2, batches=1, batches_done=1, duration_s=12,
        added=[{"path": ".assistant/playbooks/deploy.md", "type": "skill", "reason": "Deploy <playbook> for the assistant"}],
        suggestions=[{"kind": "location", "value": ".assistant/playbooks/**/*.md", "example": ".assistant/playbooks/deploy.md"}])
    p = tmp_path / "report.html"
    write_html(a, p)
    txt = p.read_text()
    assert "Kodand Agent Scope" in txt and "Agent-added <b>1</b>" in txt and "Kodand Agent scope expansion" in txt
    assert "Deploy &lt;playbook&gt; for the assistant" in txt  # the agent's reason is escaped
    assert ".assistant/playbooks/**/*.md" in txt and "8 of 8 file(s) crawled" in txt


def test_html_report_without_a_crawl_has_no_scope_section(tmp_path):
    p = tmp_path / "report.html"
    write_html(_analysis(), p)
    assert "Kodand Agent Scope" not in p.read_text()


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
