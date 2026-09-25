"""Python AST analysis via the stdlib `ast` module — no new dependency. Parse-only,
never compiles/execs the target. Mirrors the rule set in `js_ast.py` for the
equivalent Python constructs."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from kodand.codeanalysis.rules import CODE_RULES
from kodand.redaction import redact
from kodand.templates.confidence import calculate_confidence
from kodand.templates.matcher import TemplateMatch

MAX_PY_SOURCE_BYTES = 5_000_000
_CONTEXT = "code"

_EVAL_EXEC_NAMES = {"eval", "exec", "compile"}
_DESERIALIZE_ATTRS = {"loads", "load"}
_DESERIALIZE_MODULES = {"pickle", "marshal"}
_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
_NETWORK_FUNCS = {"post", "get", "put", "request", "urlopen", "send", "sendall"}
_NETWORK_ROOTS = {"requests", "httpx", "urllib", "socket", "http"}
_SECRET_NAME_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD)", re.IGNORECASE)


def _root_name(node) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


class _ExfilVisitor(ast.NodeVisitor):
    """Scoped to one function body: does it read an env var/file (source) AND
    make an outbound network call (sink)? Same-function co-occurrence only —
    deliberately not general taint tracking, see python_ast module docstring."""

    def __init__(self):
        self.has_source = False
        self.sink_node: ast.AST | None = None

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            self.has_source = True
        elif isinstance(func, ast.Attribute):
            root = _root_name(func.value)
            if func.attr == "getenv" and root == "os":
                self.has_source = True
            if func.attr == "get" and isinstance(func.value, ast.Attribute) and func.value.attr == "environ":
                self.has_source = True
            if func.attr in _NETWORK_FUNCS and root in _NETWORK_ROOTS and self.sink_node is None:
                self.sink_node = node
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        value = node.value
        if isinstance(value, ast.Attribute) and value.attr == "environ" and _root_name(value) == "os":
            self.has_source = True
        self.generic_visit(node)


class _RiskVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.hits: list[tuple[str, ast.AST, str]] = []

    def _snippet(self, node: ast.AST) -> str:
        idx = getattr(node, "lineno", 1) - 1
        line = self.source_lines[idx] if 0 <= idx < len(self.source_lines) else ""
        return line.strip()[:200]

    def _record(self, rule_id: str, node: ast.AST, snippet: str | None = None):
        self.hits.append((rule_id, node, snippet if snippet is not None else self._snippet(node)))

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _EVAL_EXEC_NAMES:
                self._record("AST04-PY-EVAL-EXEC", node)
            elif func.id == "__import__":
                if not (node.args and isinstance(node.args[0], ast.Constant)):
                    self._record("AST04-PY-DYNAMIC-IMPORT", node)
        elif isinstance(func, ast.Attribute):
            root = _root_name(func.value)
            if func.attr == "import_module" and root == "importlib":
                if not (node.args and isinstance(node.args[0], ast.Constant)):
                    self._record("AST04-PY-DYNAMIC-IMPORT", node)
            if func.attr in _DESERIALIZE_ATTRS and root in _DESERIALIZE_MODULES:
                self._record("AST04-PY-DESERIALIZATION", node)
            if func.attr == "system" and root == "os":
                self._record("AST01-PY-SHELL-INJECTION", node)
            if func.attr in _SUBPROCESS_FUNCS and root == "subprocess":
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    self._record("AST01-PY-SHELL-INJECTION", node)
        self.generic_visit(node)

    def _check_hardcoded_credential(self, target, value):
        if (isinstance(target, ast.Name) and isinstance(value, ast.Constant)
                and isinstance(value.value, str) and len(value.value) >= 8
                and _SECRET_NAME_RE.search(target.id)):
            self._record("AST03-PY-HARDCODED-CREDENTIAL", value, f"{target.id} = \"...\"")

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            self._check_hardcoded_credential(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self._check_hardcoded_credential(node.target, node.value)
        self.generic_visit(node)

    def _check_exfil(self, node):
        visitor = _ExfilVisitor()
        for stmt in node.body:
            visitor.visit(stmt)
        if visitor.has_source and visitor.sink_node is not None:
            self._record("AST01-PY-EXFIL", visitor.sink_node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_exfil(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_exfil(node)
        self.generic_visit(node)


def analyze_python_file(file_path: Path, repository_root: Path) -> list[TemplateMatch]:
    """Parse-only static analysis of one Python file. Returns [] for anything
    oversized, unreadable, or that fails to parse — never raises, never
    compiles/execs the target."""
    try:
        if file_path.stat().st_size > MAX_PY_SOURCE_BYTES:
            return []
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        relative_path = file_path.relative_to(repository_root).as_posix()
    except ValueError:
        relative_path = file_path.as_posix()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []

    visitor = _RiskVisitor(source.splitlines())
    visitor.visit(tree)

    matches: list[TemplateMatch] = []
    for rule_id, node, snippet in visitor.hits:
        rule = CODE_RULES[rule_id]
        line = getattr(node, "lineno", 1)
        col_start = getattr(node, "col_offset", 0)
        col_end = getattr(node, "end_col_offset", col_start + len(snippet))
        matches.append(TemplateMatch(
            template_id=rule_id, category=rule.info.category, severity=rule.info.severity,
            confidence=calculate_confidence(rule.info.confidence, _CONTEXT),
            file=relative_path, line=line, column_start=col_start + 1, column_end=col_end + 1,
            matched_value=redact(snippet), excerpt=redact(snippet),
            context=_CONTEXT, match_kind="ast", decoded_from=None,
        ))
    return matches


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / "evil.py"
        f.write_text(
            "import subprocess\n"
            "eval(x)\n"
            "subprocess.run(cmd, shell=True)\n"
            "api_key = 'sk-abcdefgh12345678'\n"
        )
        result = analyze_python_file(f, root)
        ids = {m.template_id for m in result}
        assert "AST04-PY-EVAL-EXEC" in ids, ids
        assert "AST01-PY-SHELL-INJECTION" in ids, ids
        assert "AST03-PY-HARDCODED-CREDENTIAL" in ids, ids

        benign = root / "benign.py"
        benign.write_text("subprocess.run(['ls', '-l'])\napi_key = None\n")
        assert analyze_python_file(benign, root) == []
        print("ok", ids)
