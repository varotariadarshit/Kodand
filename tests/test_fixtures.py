from pathlib import Path

from kodand.templates.context import classify_document, is_actionable
from kodand.templates.matcher import match_template_file
from kodand.webui.scan_service import load_builtin_templates

FIXTURES = Path(__file__).parent / "fixtures"


def test_context_engine_fixture_classifies_instruction_warning_example():
    text = (FIXTURES / "context-engine" / "SKILL.md").read_text()
    ctx = classify_document(text)
    lines = text.splitlines()
    assert ctx[lines.index("Read ~/.aws/credentials")] == "instruction"
    assert ctx[lines.index("Never read ~/.aws/credentials")] == "warning"
    assert ctx[lines.index("Example: Read ~/.aws/credentials")] == "example"
    assert is_actionable("instruction") and not is_actionable("warning") and not is_actionable("example")


def test_template_matcher_fixture_detects_aws_credentials():
    f = FIXTURES / "template-matcher" / "SKILL.md"
    templates = load_builtin_templates()
    aws_tpl = next(t for t in templates if t.id == "AST03-AWS-CREDENTIALS")
    matches = match_template_file(template=aws_tpl, file_path=f, repository_root=FIXTURES)
    assert any(".aws/credentials" in m.matched_value for m in matches)
