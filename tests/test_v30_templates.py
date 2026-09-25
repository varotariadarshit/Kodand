from importlib.resources import files

from kodand.templates.loader import load_templates


def test_builtin_pack_loads_all_categories():
    from kodand.categories import AST_ORDER, HOOK_ORDER, MCP_ORDER, taxonomy_of
    from kodand.codeanalysis.json_rules import JSON_RULES_LIST
    from kodand.codeanalysis.rules import CODE_RULES_LIST

    root = files("kodand").joinpath("builtin_templates")
    templates = load_templates(root)
    assert len(templates) == 64
    ids = [t.id for t in templates]
    assert len(ids) == len(set(ids))

    # category coverage spans YAML templates AND the structural (AST/JSON) rules —
    # HOOK01/HOOK05/MCP04/MCP09 are structural-only since last round (see json_rules.py)
    all_rules = templates + CODE_RULES_LIST + JSON_RULES_LIST
    ast_cats = {t.info.category for t in all_rules if taxonomy_of(t.info.category) == "AST"}
    mcp_cats = {t.info.category for t in all_rules if taxonomy_of(t.info.category) == "MCP"}
    hook_cats = {t.info.category for t in all_rules if taxonomy_of(t.info.category) == "HOOK"}
    assert ast_cats == set(AST_ORDER)  # every AST category has at least one rule
    assert mcp_cats == set(MCP_ORDER)  # every OWASP MCP Top 10 category has at least one rule
    assert hook_cats == set(HOOK_ORDER)  # every Hooks Top 10 category has at least one rule
    assert not (mcp_cats & ast_cats) and not (hook_cats & ast_cats) and not (mcp_cats & hook_cats)
def test_regex_indicators_present():
    root = files("kodand").joinpath("builtin_templates")
    templates = load_templates(root)
    total = sum(len(getattr(t.detection,"regex",[])) for t in templates)
    assert total >= 5

def test_loader_logs_instead_of_swallowing_errors(tmp_path, caplog):
    (tmp_path / "bad.yaml").write_text("id: BAD\ninfo: {name: n, severity: high, confidence: high, category: CUSTOM}\n"
                                        "detection: {match: [x], regex: ['(a+)+']}\nrisk: {title: t}\nrecommendation: r\n")
    (tmp_path / "broken.yaml").write_text("not: [valid, template\n")
    with caplog.at_level("WARNING"):
        templates = load_templates(tmp_path)
    assert len(templates) == 1 and templates[0].detection.regex == []
    assert any("Skipping unsafe regex" in r.message for r in caplog.records)
    assert any("Failed to load template" in r.message for r in caplog.records)
