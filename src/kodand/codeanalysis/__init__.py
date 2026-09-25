"""AST-level static analysis of scripts referenced by skills/MCP configs — a
second finding source alongside the text/regex template matcher, feeding the
same TemplateMatch/CorrelatedFinding pipeline (see rules.py)."""
from __future__ import annotations

from pathlib import Path

from kodand.templates.matcher import TemplateMatch

PY_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
JSON_EXTENSIONS = {".json"}
CODE_EXTENSIONS = PY_EXTENSIONS | JS_EXTENSIONS
# what scan_service.py gates analyze_file() on — code extensions plus JSON,
# whose structural rules are content-sniffed inside analyze_json_file rather
# than filename-gated (see json_struct.py), so every .json is worth a look.
ANALYZABLE_EXTENSIONS = CODE_EXTENSIONS | JSON_EXTENSIONS

_js_unavailable = False


def analyze_file(file_path: Path, repository_root: Path) -> list[TemplateMatch]:
    """Route to the right AST/structural analyzer by extension. Parse-only;
    never executes `file_path`. Returns [] for anything unsupported, oversized,
    or unparsable, and for JS/TS when the optional `code` extra (tree-sitter)
    isn't installed."""
    global _js_unavailable
    suffix = file_path.suffix.lower()
    if suffix in PY_EXTENSIONS:
        from kodand.codeanalysis.python_ast import analyze_python_file
        return analyze_python_file(file_path, repository_root)
    if suffix in JS_EXTENSIONS:
        if _js_unavailable:
            return []
        try:
            from kodand.codeanalysis.js_ast import analyze_js_file
        except ImportError:
            _js_unavailable = True
            return []
        return analyze_js_file(file_path, repository_root)
    if suffix in JSON_EXTENSIONS:
        from kodand.codeanalysis.json_struct import analyze_json_file
        return analyze_json_file(file_path, repository_root)
    return []
