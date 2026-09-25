"""JS/TS AST analysis via tree-sitter (optional `code` extra). Parse-only — never
evaluates the target file. Importing this module raises ImportError if the extra
isn't installed; `codeanalysis/__init__.py` catches that and skips JS/TS analysis
for the rest of the scan."""
from __future__ import annotations

import re
from pathlib import Path

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from kodand.codeanalysis.rules import CODE_RULES
from kodand.redaction import redact
from kodand.templates.confidence import calculate_confidence
from kodand.templates.matcher import TemplateMatch

MAX_JS_SOURCE_BYTES = 5_000_000
_CONTEXT = "code"

_SHELL_FUNCS = {"exec", "execSync", "spawn", "spawnSync"}
_NETWORK_ROOTS = {"axios", "http", "https", "fetch"}
_NETWORK_FUNCS = {"fetch", "get", "post", "put", "request"}
_ENV_HINTS = {"env"}
_FS_READ_FUNCS = {"readFile", "readFileSync"}
_SECRET_NAME_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD)", re.IGNORECASE)
_FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition"}
# obfuscation/packer shape: eval(function(p,a,c,k,e,d){...}(...)) is the classic
# "Dean Edwards packer" signature used by most JS obfuscators
_PACKER_RE = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e")

_LANGS = {".js": tsjs.language, ".mjs": tsjs.language, ".cjs": tsjs.language, ".jsx": tsjs.language,
          ".ts": tsts.language_typescript, ".tsx": tsts.language_tsx}


def _pos(node) -> tuple[int, int, int]:
    line = node.start_point[0] + 1
    col_start = node.start_point[1]
    same_line = node.end_point[0] == node.start_point[0]
    col_end = node.end_point[1] if same_line else col_start + (node.end_byte - node.start_byte)
    return line, col_start, col_end


def _root_identifier(node):
    while node is not None and node.type == "member_expression":
        node = node.child_by_field_name("object")
    return node.text.decode("utf-8", "replace") if node is not None and node.type == "identifier" else None


def _is_literal(node) -> bool:
    if node is None:
        return False
    if node.type == "template_string":  # `...` with no ${} placeholder is as fixed as a "..." string
        return not any(c.type == "template_substitution" for c in node.children)
    return node.type == "string"


_CHILD_PROCESS = {"child_process", "node:child_process"}


def _string_value(node) -> str | None:
    return node.text.decode("utf-8", "replace")[1:-1] if node is not None and node.type == "string" else None


def _is_child_process_require(node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    func = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    named = list(args.named_children) if args is not None else []
    return (func is not None and func.type == "identifier" and func.text == b"require"
            and len(named) == 1 and _string_value(named[0]) in _CHILD_PROCESS)


def _child_process_bindings(root) -> tuple[set, set]:
    """Names bound to Node's child_process module in this file: module aliases
    (`const cp = require('child_process')`, `import * as cp from ...`) and directly
    imported shell functions (`const { exec } = require(...)`, `import { exec } from ...`).
    Only these make an `exec(...)` call a shell call — `db.exec`, `regex.exec` are not."""
    modules, funcs = {"child_process"}, set()
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "variable_declarator" and _is_child_process_require(node.child_by_field_name("value")):
            name = node.child_by_field_name("name")
            if name is None:
                continue
            if name.type == "identifier":
                modules.add(name.text.decode("utf-8", "replace"))
            elif name.type == "object_pattern":
                for part in name.named_children:
                    if part.type == "shorthand_property_identifier_pattern" and part.text.decode() in _SHELL_FUNCS:
                        funcs.add(part.text.decode())
                    elif part.type == "pair_pattern":
                        key, value = part.child_by_field_name("key"), part.child_by_field_name("value")
                        if key is not None and value is not None and key.text.decode() in _SHELL_FUNCS:
                            funcs.add(value.text.decode())
        elif node.type == "import_statement" and _string_value(node.child_by_field_name("source")) in _CHILD_PROCESS:
            for clause in (c for c in node.named_children if c.type == "import_clause"):
                for part in clause.named_children:
                    if part.type == "identifier":
                        modules.add(part.text.decode())
                    elif part.type == "namespace_import":
                        modules.update(c.text.decode() for c in part.named_children if c.type == "identifier")
                    elif part.type == "named_imports":
                        for spec in (c for c in part.named_children if c.type == "import_specifier"):
                            name = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias") or name
                            if name is not None and name.text.decode() in _SHELL_FUNCS:
                                funcs.add(alias.text.decode())
    return modules, funcs


def _shell_call_hit(node, prop_name: str, args, first_arg):
    shell_true = False
    if args is not None:
        for child in args.children:
            if child.type == "object" and b"shell" in child.text and b"true" in child.text:
                shell_true = True
    # exec/execSync always run through a shell, so a dynamically-built command is
    # risky on its own; spawn/spawnSync only go through a shell with shell:true
    dynamic_cmd = first_arg is not None and not _is_literal(first_arg)
    always_shell = prop_name in {"exec", "execSync"}
    if shell_true or (always_shell and dynamic_cmd):
        return _Hit("AST01-JS-SHELL-INJECTION", node, _snippet(node))
    return None


class _Hit:
    __slots__ = ("rule_id", "node", "snippet")

    def __init__(self, rule_id, node, snippet):
        self.rule_id = rule_id
        self.node = node
        self.snippet = snippet


def _snippet(node, max_len=200) -> str:
    return node.text.decode("utf-8", "replace")[:max_len]


def _has_source(node) -> bool:
    """Does this subtree read an env var or a file? (env/fs read heuristic, see
    `_check_exfil` — deliberately shallow: one hop of member/call recognition,
    not general taint tracking.)"""
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if prop is not None and prop.text.decode("utf-8", "replace") in _ENV_HINTS and _root_identifier(obj) == "process":
            return True
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            if prop is not None and prop.text.decode("utf-8", "replace") in _FS_READ_FUNCS:
                return True
    for child in node.children:
        if _has_source(child):
            return True
    return False


def _find_sink(node):
    """First outbound-network call in this subtree, or None. See `_has_source`."""
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        name = None
        root = None
        if func is not None and func.type == "identifier":
            name = func.text.decode("utf-8", "replace")
        elif func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            name = prop.text.decode("utf-8", "replace") if prop is not None else None
            root = _root_identifier(func)
        if name in _NETWORK_FUNCS and (root in _NETWORK_ROOTS or name == "fetch"):
            return node
    for child in node.children:
        found = _find_sink(child)
        if found is not None:
            return found
    return None


def _walk(node, hits: list, source_len: int, cp: tuple[set, set]) -> None:
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        first_arg = None
        if args is not None:
            named = [c for c in args.named_children]
            first_arg = named[0] if named else None

        if func is not None and func.type == "identifier":
            name = func.text.decode("utf-8", "replace")
            if name == "eval":
                hits.append(_Hit("AST04-JS-EVAL-EXEC", node, _snippet(node)))
            elif name in cp[1]:
                hit = _shell_call_hit(node, name if name in _SHELL_FUNCS else "exec", args, first_arg)
                if hit:
                    hits.append(hit)
            elif name == "require" and first_arg is not None and not _is_literal(first_arg):
                hits.append(_Hit("AST04-JS-DYNAMIC-IMPORT", node, _snippet(node)))
        elif func is not None and func.type == "import":
            if first_arg is not None and not _is_literal(first_arg):
                hits.append(_Hit("AST04-JS-DYNAMIC-IMPORT", node, _snippet(node)))
        elif func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            prop_name = prop.text.decode("utf-8", "replace") if prop is not None else ""
            receiver = func.child_by_field_name("object")
            from_child_process = _root_identifier(func) in cp[0] or _is_child_process_require(receiver)
            if prop_name in _SHELL_FUNCS and from_child_process:
                hit = _shell_call_hit(node, prop_name, args, first_arg)
                if hit:
                    hits.append(hit)

    elif node.type == "new_expression":
        ctor = node.child_by_field_name("constructor")
        if ctor is not None and ctor.type == "identifier" and ctor.text == b"Function":
            hits.append(_Hit("AST04-JS-EVAL-EXEC", node, _snippet(node)))

    elif node.type == "variable_declarator":
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if (name is not None and name.type == "identifier" and _is_literal(value)
                and _SECRET_NAME_RE.search(name.text.decode("utf-8", "replace"))
                and len(value.text) >= 10):
            hits.append(_Hit("AST03-JS-HARDCODED-CREDENTIAL", node, _snippet(node)))

    elif node.type in _FUNCTION_TYPES:
        if _has_source(node):
            sink = _find_sink(node)
            if sink is not None:
                hits.append(_Hit("AST01-JS-EXFIL", sink, _snippet(sink)))

    for child in node.children:
        _walk(child, hits, source_len, cp)


def analyze_js_file(file_path: Path, repository_root: Path) -> list[TemplateMatch]:
    """tree-sitter parse-only analysis of one JS/TS file. Returns [] for anything
    oversized or that fails to parse into a usable tree — never raises, never
    executes the target."""
    suffix = file_path.suffix.lower()
    lang_fn = _LANGS.get(suffix)
    if lang_fn is None:
        return []
    try:
        if file_path.stat().st_size > MAX_JS_SOURCE_BYTES:
            return []
        source = file_path.read_bytes()
    except OSError:
        return []
    try:
        relative_path = file_path.relative_to(repository_root).as_posix()
    except ValueError:
        relative_path = file_path.as_posix()

    try:
        language = tree_sitter.Language(lang_fn())
        parser = tree_sitter.Parser(language)
        tree = parser.parse(source)
    except Exception:
        return []
    root = tree.root_node
    if root is None or root.has_error and root.child_count == 0:
        return []

    hits: list[_Hit] = []
    _walk(root, hits, len(source), _child_process_bindings(root))

    matches: list[TemplateMatch] = []
    if _PACKER_RE.search(source.decode("utf-8", "replace")):
        matches.append(TemplateMatch(
            template_id="AST04-JS-OBFUSCATED-CODE", category=CODE_RULES["AST04-JS-OBFUSCATED-CODE"].info.category,
            severity=CODE_RULES["AST04-JS-OBFUSCATED-CODE"].info.severity,
            confidence=calculate_confidence(CODE_RULES["AST04-JS-OBFUSCATED-CODE"].info.confidence, _CONTEXT),
            file=relative_path, line=1, column_start=1, column_end=1,
            matched_value="[packer signature]", excerpt="[packer signature detected in file]",
            context=_CONTEXT, match_kind="ast", decoded_from=None,
        ))

    for hit in hits:
        rule = CODE_RULES[hit.rule_id]
        line, col_start, col_end = _pos(hit.node)
        matches.append(TemplateMatch(
            template_id=hit.rule_id, category=rule.info.category, severity=rule.info.severity,
            confidence=calculate_confidence(rule.info.confidence, _CONTEXT),
            file=relative_path, line=line, column_start=col_start + 1, column_end=col_end + 1,
            matched_value=redact(hit.snippet), excerpt=redact(hit.snippet),
            context=_CONTEXT, match_kind="ast", decoded_from=None,
        ))
    return matches


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / "evil.js"
        f.write_text("eval(x); child_process.exec(cmd); const apiKey = 'sk-abcdefgh12345678';")
        result = analyze_js_file(f, root)
        ids = {m.template_id for m in result}
        assert "AST04-JS-EVAL-EXEC" in ids, ids
        assert "AST01-JS-SHELL-INJECTION" in ids, ids
        assert "AST03-JS-HARDCODED-CREDENTIAL" in ids, ids
        print("ok", ids)
