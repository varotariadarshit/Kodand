"""Position-tracking JSON parser, for structural analysis of MCP/hook config
files — a second finding source alongside the text/regex template matcher,
analogous to python_ast.py/js_ast.py but for JSON structure instead of code.

stdlib `json.loads` alone discards line/column info, so this is a small
hand-rolled recursive-descent parser (JSON's grammar is small enough that this
is a bounded, well-understood amount of code), not a wrapper around it.
"""
from __future__ import annotations

from collections import namedtuple
from dataclasses import dataclass
from pathlib import Path

from kodand.codeanalysis.json_rules import JSON_RULES
from kodand.redaction import redact
from kodand.templates.confidence import calculate_confidence
from kodand.templates.matcher import TemplateMatch

MAX_JSON_SOURCE_BYTES = 2_000_000  # config files are never legitimately huge


@dataclass
class JNode:
    kind: str            # "object" | "array" | "string" | "number" | "true" | "false" | "null"
    value: object         # list[JEntry] for object, list[JNode] for array, else the decoded scalar
    line: int
    col: int              # 1-based position of this node's first character


@dataclass
class JEntry:
    key: str
    key_line: int
    key_col: int
    value: JNode


class _ParseError(Exception):
    pass


_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class _Scanner:
    def __init__(self, text: str):
        self.text = text
        self.n = len(text)
        self.pos = 0
        self.line = 1
        self.col = 1

    def _advance(self, count: int = 1) -> None:
        for _ in range(count):
            if self.pos >= self.n:
                break
            if self.text[self.pos] == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
            self.pos += 1

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < self.n else ""

    def _skip_ws(self) -> None:
        while self.pos < self.n and self.text[self.pos] in " \t\r\n":
            self._advance()

    def parse_document(self) -> JNode:
        self._skip_ws()
        node = self._parse_value()
        self._skip_ws()
        if self.pos != self.n:
            raise _ParseError("trailing data")
        return node

    def _parse_value(self) -> JNode:
        self._skip_ws()
        if self.pos >= self.n:
            raise _ParseError("unexpected end of input")
        c = self.text[self.pos]
        if c == "{":
            return self._parse_object()
        if c == "[":
            return self._parse_array()
        if c == '"':
            return self._parse_string()
        if c == "-" or c.isdigit():
            return self._parse_number()
        if self.text.startswith("true", self.pos):
            return self._parse_literal("true", True)
        if self.text.startswith("false", self.pos):
            return self._parse_literal("false", False)
        if self.text.startswith("null", self.pos):
            return self._parse_literal("null", None)
        raise _ParseError(f"unexpected character {c!r}")

    def _parse_literal(self, word: str, value: object) -> JNode:
        line, col = self.line, self.col
        self._advance(len(word))
        return JNode(kind=word, value=value, line=line, col=col)

    def _parse_object(self) -> JNode:
        line, col = self.line, self.col
        self._advance()  # {
        entries: list[JEntry] = []
        self._skip_ws()
        if self._peek() == "}":
            self._advance()
            return JNode(kind="object", value=entries, line=line, col=col)
        while True:
            self._skip_ws()
            if self._peek() != '"':
                raise _ParseError("expected string key")
            key_line, key_col = self.line, self.col
            key_node = self._parse_string()
            self._skip_ws()
            if self._peek() != ":":
                raise _ParseError("expected ':'")
            self._advance()
            value_node = self._parse_value()
            entries.append(JEntry(key=key_node.value, key_line=key_line, key_col=key_col, value=value_node))
            self._skip_ws()
            c = self._peek()
            if c == ",":
                self._advance()
                continue
            if c == "}":
                self._advance()
                break
            raise _ParseError("expected ',' or '}'")
        return JNode(kind="object", value=entries, line=line, col=col)

    def _parse_array(self) -> JNode:
        line, col = self.line, self.col
        self._advance()  # [
        elems: list[JNode] = []
        self._skip_ws()
        if self._peek() == "]":
            self._advance()
            return JNode(kind="array", value=elems, line=line, col=col)
        while True:
            elems.append(self._parse_value())
            self._skip_ws()
            c = self._peek()
            if c == ",":
                self._advance()
                continue
            if c == "]":
                self._advance()
                break
            raise _ParseError("expected ',' or ']'")
        return JNode(kind="array", value=elems, line=line, col=col)

    def _parse_string(self) -> JNode:
        line, col = self.line, self.col
        self._advance()  # opening quote
        out: list[str] = []
        while True:
            if self.pos >= self.n:
                raise _ParseError("unterminated string")
            c = self.text[self.pos]
            if c == '"':
                self._advance()
                break
            if c == "\\":
                self._advance()
                e = self._peek()
                if e == "":
                    raise _ParseError("unterminated escape")
                if e == "u":
                    self._advance()
                    hex4 = self.text[self.pos:self.pos + 4]
                    if len(hex4) != 4:
                        raise _ParseError("bad \\u escape")
                    try:
                        out.append(chr(int(hex4, 16)))
                    except ValueError:
                        raise _ParseError("bad \\u escape") from None
                    self._advance(4)
                    continue
                if e not in _ESCAPES:
                    raise _ParseError(f"bad escape \\{e}")
                out.append(_ESCAPES[e])
                self._advance()
                continue
            if ord(c) < 0x20:
                raise _ParseError("control character in string")
            out.append(c)
            self._advance()
        return JNode(kind="string", value="".join(out), line=line, col=col)

    def _parse_number(self) -> JNode:
        line, col = self.line, self.col
        start = self.pos
        if self._peek() == "-":
            self._advance()
        if self._peek() == "0":
            self._advance()
        elif self._peek().isdigit():
            while self._peek().isdigit():
                self._advance()
        else:
            raise _ParseError("bad number")
        is_float = False
        if self._peek() == ".":
            is_float = True
            self._advance()
            if not self._peek().isdigit():
                raise _ParseError("bad number")
            while self._peek().isdigit():
                self._advance()
        if self._peek() in ("e", "E"):
            is_float = True
            self._advance()
            if self._peek() in ("+", "-"):
                self._advance()
            if not self._peek().isdigit():
                raise _ParseError("bad number")
            while self._peek().isdigit():
                self._advance()
        raw = self.text[start:self.pos]
        return JNode(kind="number", value=float(raw) if is_float else int(raw), line=line, col=col)


def parse(text: str) -> JNode | None:
    """Parse `text` as JSON, returning a position-tracked JNode tree, or None
    on any malformed input — never raises. Deliberately strict (no trailing
    commas, no comments, no unquoted keys), matching standard JSON grammar."""
    try:
        return _Scanner(text).parse_document()
    except (_ParseError, RecursionError, IndexError):
        return None


def entries(node: JNode | None) -> list[JEntry]:
    return node.value if node is not None and node.kind == "object" else []


def items(node: JNode | None) -> list[JNode]:
    return node.value if node is not None and node.kind == "array" else []


def get(node: JNode | None, key: str) -> JNode | None:
    """The value for `key` in an object node, or None. Duplicate keys resolve
    to the LAST occurrence, matching standard JSON object semantics."""
    result = None
    for e in entries(node):
        if e.key == key:
            result = e.value
    return result


# --- structural rules over a parsed hook/MCP config ------------------------
# Each check below correlates two or more keys of the SAME object (a hook
# entry's matcher with its own command; one server's command/args with
# another's) — exactly what the line-based regex these rules used to be could
# not do. See json_rules.py for the corresponding KodandTemplate metadata.

_Hit = namedtuple("_Hit", ["rule_id", "line", "col", "snippet", "severity"], defaults=[None])
_CONTEXT = "instruction"  # matches how these JSON config lines were classified under the line-based matcher

_KNOWN_HOOK_EVENTS = {
    "PreToolUse", "PostToolUse", "UserPromptSubmit", "Notification",
    "Stop", "SubagentStop", "PreCompact", "SessionStart", "SessionEnd",
}


def _is_risky_command(cmd: str) -> bool:
    lc = cmd.lower()
    markers = (
        "sudo ", "doas ", "pkexec ", "crontab -", "systemctl enable",
        "launchctl load", ":(){", "dd if=/dev/zero", "dd if=/dev/random",
        "chmod +s", "chmod 4",
    )
    if any(m in lc for m in markers):
        return True
    if ">>" in cmd:
        return True
    return ("curl" in lc or "wget" in lc) and "|" in cmd


def _check_hook_rules(root: JNode) -> list[_Hit]:
    hooks_node = get(root, "hooks")
    hits: list[_Hit] = []

    # HOOK05: an event key not in the documented set — direct children of
    # "hooks" ONLY, so this can never be confused with the nested per-entry
    # "hooks" array key at another depth (the false-positive class the
    # line-based version needed an exclusion list to avoid).
    for event_entry in entries(hooks_node):
        if event_entry.key not in _KNOWN_HOOK_EVENTS:
            hits.append(_Hit("HOOK05-HIDDEN-DEFINITION", event_entry.key_line, event_entry.key_col,
                              f'hook event "{event_entry.key}"'))

    # HOOK01: a wildcard/empty matcher, escalated to "high" when its OWN
    # hook entry's command looks risky — a correlation regex can't express.
    for event_entry in entries(hooks_node):
        for entry_obj in items(event_entry.value):
            if entry_obj.kind != "object":
                continue
            matcher_node = get(entry_obj, "matcher")
            if matcher_node is None or matcher_node.kind != "string":
                continue
            if matcher_node.value not in ("", "*", ".*"):
                continue
            commands = [c.value for c in
                        (get(co, "command") for co in items(get(entry_obj, "hooks")))
                        if c is not None and c.kind == "string"]
            risky = any(_is_risky_command(c) for c in commands)
            snippet = f'matcher="{matcher_node.value}"'
            if commands:
                snippet += f', command="{commands[0]}"'
            hits.append(_Hit("HOOK01-WILDCARD-MATCHER", matcher_node.line, matcher_node.col, snippet,
                              "high" if risky else None))
    return hits


_LAUNCHER_BASENAMES = {"npx", "npm", "uvx", "pipx", "bunx"}
_FLOATING_VERSION_TAGS = {"latest", "next", "canary", "nightly", "beta", "alpha", "rc"}
_JUNK_PATH_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/", "~/Downloads/")


def _servers_node(root: JNode) -> JNode | None:
    return get(root, "mcpServers") or get(root, "servers")


def _iter_servers(root: JNode):
    """Yield (name, name_entry, command, args, command_node) for each entry
    under mcpServers/servers whose value is itself an object."""
    for e in entries(_servers_node(root)):
        if e.value.kind != "object":
            continue
        cmd_node = get(e.value, "command")
        command = cmd_node.value if cmd_node is not None and cmd_node.kind == "string" else None
        args_node = get(e.value, "args")
        args = [a.value for a in items(args_node) if a.kind == "string"]
        yield e.key, e, command, args, cmd_node


def _launcher_basename(command: str | None) -> str | None:
    if not command:
        return None
    base = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return base if base in _LAUNCHER_BASENAMES else None


def _is_pinned(pkg_arg: str) -> bool:
    """Does this npx/uvx/etc. package argument carry an explicit, non-floating
    version suffix (e.g. `foo@1.4.2`, `@scope/foo@2.0.0`)? `@latest`/no
    suffix/other floating tags all count as unpinned."""
    ident, sep, ver = pkg_arg.rpartition("@")
    if not sep or not ident or not ver:
        return False
    if ver.split(".")[0].lower() in _FLOATING_VERSION_TAGS:
        return False
    return ver[0].isdigit()


def _check_mcp04(root: JNode) -> list[_Hit]:
    hits: list[_Hit] = []
    for name, name_entry, command, args, cmd_node in _iter_servers(root):
        base = _launcher_basename(command)
        if base is None:
            continue
        candidates = [a for a in args if a and not a.startswith("-")]
        if base == "npm":
            if not candidates or candidates[0] not in ("exec", "x"):
                continue  # only `npm exec`/`npm x <pkg>` launches a package this way
            candidates = candidates[1:]
        pkg_arg = candidates[0] if candidates else None
        if pkg_arg is None or not _is_pinned(pkg_arg):
            hits.append(_Hit("MCP04-UNPINNED-LAUNCHER", cmd_node.line, cmd_node.col,
                              f'server "{name}": command="{command}" args={args}'))
    return hits


# Official reference servers (npm @modelcontextprotocol/*, PyPI mcp-server-*) plus a few widely
# used vendor servers. A launched package within edit distance 2 of one of these, but not equal
# to it, is almost always a typo — or a squat registered to catch that typo.
KNOWN_MCP_PACKAGES = frozenset({
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab", "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-slack", "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-redis", "@modelcontextprotocol/server-everart",
    "@modelcontextprotocol/server-aws-kb-retrieval", "@modelcontextprotocol/inspector",
    "mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp-server-sqlite", "mcp-server-sentry",
    "@playwright/mcp", "@upstash/context7-mcp", "@notionhq/notion-mcp-server", "@stripe/mcp",
})


def _package_name(pkg_arg: str) -> str:
    """`@scope/name@1.2.3` -> `@scope/name`; `name==1.2` / `name@1.2` -> `name`."""
    name = pkg_arg.split("==", 1)[0]
    at = name.rfind("@")
    return name[:at] if at > 0 else name


def _check_mcp04_typosquat(root: JNode) -> list[_Hit]:
    hits: list[_Hit] = []
    for e in entries(_servers_node(root)):
        if e.value.kind != "object":
            continue
        cmd_node = get(e.value, "command")
        base = _launcher_basename(cmd_node.value if cmd_node is not None and cmd_node.kind == "string" else None)
        if base is None:
            continue
        for arg in items(get(e.value, "args")):
            if arg.kind != "string" or not arg.value or arg.value[0] in "-/.~" or "\\" in arg.value:
                continue  # flags and filesystem paths, not package names
            name = _package_name(arg.value).lower()
            if name in KNOWN_MCP_PACKAGES or len(name) < 6:
                continue
            max_distance = 1 if len(name) <= 16 else 2  # short names sit too close together for 2
            near = [k for k in KNOWN_MCP_PACKAGES
                    if abs(len(k) - len(name)) <= max_distance and _levenshtein(name, k) <= max_distance]
            if near:
                hits.append(_Hit("MCP04-TYPOSQUAT-PACKAGE", arg.line, arg.col,
                                  f'server "{e.key}" launches "{arg.value}", which resembles the official "{min(near)}"'))
    return hits


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def _normalize_server_name(name: str) -> str:
    return "".join(ch.lower() for ch in name if ch.isalnum())


def _check_mcp09(root: JNode) -> list[_Hit]:
    hits: list[_Hit] = []
    servers = list(_iter_servers(root))

    # (1) launched from an ungoverned/ad hoc path
    for name, name_entry, command, args, cmd_node in servers:
        if command and any(marker in command for marker in _JUNK_PATH_MARKERS):
            hits.append(_Hit("MCP09-UNREGISTERED-SERVER-PATH", cmd_node.line, cmd_node.col,
                              f'server "{name}": command="{command}"'))

    # (2) two distinct server names sharing an identical launcher signature
    by_signature: dict[tuple, list] = {}
    for name, name_entry, command, args, cmd_node in servers:
        if command:
            by_signature.setdefault((command, tuple(args)), []).append((name, name_entry))
    for group in by_signature.values():
        if len(group) < 2:
            continue
        other_names = ", ".join(f'"{n}"' for n, _ in group)
        for name, name_entry in group[1:]:
            hits.append(_Hit("MCP09-UNREGISTERED-SERVER-PATH", name_entry.key_line, name_entry.key_col,
                              f'server "{name}" launches the identical command as: {other_names}'))

    # (3) a server name that closely resembles another configured server's name
    for i in range(len(servers)):
        name_i = servers[i][0]
        norm_i = _normalize_server_name(name_i)
        for j in range(i + 1, len(servers)):
            name_j, entry_j = servers[j][0], servers[j][1]
            if name_i == name_j or not norm_i:
                continue
            norm_j = _normalize_server_name(name_j)
            if not norm_j:
                continue
            close = norm_i == norm_j or (min(len(norm_i), len(norm_j)) >= 4 and _levenshtein(norm_i, norm_j) <= 2)
            if close:
                hits.append(_Hit("MCP09-UNREGISTERED-SERVER-PATH", entry_j.key_line, entry_j.key_col,
                                  f'server "{name_j}" closely resembles configured server "{name_i}"'))
    return hits


def analyze_json_file(file_path: Path, repository_root: Path) -> list[TemplateMatch]:
    """Parse-only structural analysis of one JSON file. Content-sniffed, not
    filename-gated: any `.json` file whose parsed shape has a `hooks` or
    `mcpServers`/`servers` object gets the corresponding rule set; anything
    else (package.json, tsconfig.json, ...) returns [] cheaply. Returns []
    for anything oversized, unreadable, or that fails to parse as JSON —
    never raises, mirrors analyze_python_file's failure behavior."""
    try:
        if file_path.stat().st_size > MAX_JSON_SOURCE_BYTES:
            return []
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        relative_path = file_path.relative_to(repository_root).as_posix()
    except ValueError:
        relative_path = file_path.as_posix()

    root = parse(source)
    if root is None or root.kind != "object":
        return []

    hits: list[_Hit] = []
    hooks_node = get(root, "hooks")
    if hooks_node is not None and hooks_node.kind == "object":
        hits += _check_hook_rules(root)
    if _servers_node(root) is not None and _servers_node(root).kind == "object":
        hits += _check_mcp04(root)
        hits += _check_mcp04_typosquat(root)
        hits += _check_mcp09(root)

    matches: list[TemplateMatch] = []
    for hit in hits:
        rule = JSON_RULES[hit.rule_id]
        matches.append(TemplateMatch(
            template_id=hit.rule_id, category=rule.info.category, severity=hit.severity or rule.info.severity,
            confidence=calculate_confidence(rule.info.confidence, _CONTEXT),
            file=relative_path, line=hit.line, column_start=hit.col, column_end=hit.col + 1,
            matched_value=redact(hit.snippet), excerpt=redact(hit.snippet),
            context=_CONTEXT, match_kind="json-struct", decoded_from=None,
        ))
    return matches
