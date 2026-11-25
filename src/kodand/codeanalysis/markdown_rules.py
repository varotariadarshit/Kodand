"""Structural rules for markdown-like agent files (SKILL.md, rules, commands, prompts).

The YAML templates match one line at a time; these rules need more than that:
  - fenced code blocks are fed to the same Python / JS-TS / JSON analysers that run
    on real source files, with line numbers mapped back to the markdown file
  - AST05-UNTRUSTED-FETCH correlates a fetch action with an untrusted URL source
    across a few lines (indirect prompt injection: the agent reads attacker text)
  - frontmatter is parsed: broad `allowed-tools` grants, hooks declared in
    frontmatter, malformed frontmatter
  - Claude Code's `` !`cmd` `` blocks, which run a shell command when the skill loads
Parse-only; never executes anything.
"""
from __future__ import annotations

import re

import yaml

from kodand.adapters.common import split_frontmatter
from kodand.codeanalysis.rules import CODE_RULES
from kodand.redaction import redact
from kodand.templates.confidence import calculate_confidence
from kodand.templates.context import classify_document, is_actionable, match_context
from kodand.templates.matcher import TemplateMatch

MARKDOWN_SUFFIXES = {".md", ".mdc", ".mdx", ".markdown", ".txt", ".prompt"}
MARKDOWN_NAMES = {".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".rules", "rules"}

_FENCE_OPEN = re.compile(r"^\s*(```+|~~~+)\s*([\w+#.-]*)")
_FENCE_LANGS = {
    "py": "py", "python": "py", "python3": "py",
    "js": ".js", "javascript": ".js", "node": ".js", "mjs": ".js", "cjs": ".js", "jsx": ".jsx",
    "ts": ".ts", "typescript": ".ts", "tsx": ".tsx",
    "json": "json", "jsonc": "json",
}


def is_markdown_like(name: str, suffix: str) -> bool:
    name = name.lower()
    return suffix.lower() in MARKDOWN_SUFFIXES or name in MARKDOWN_NAMES or name.startswith(".roorules")


def _match(rule_id: str, rel: str, line: int, col: int, end: int, value: str, excerpt: str,
           context: str, severity: str | None = None, kind: str = "structural") -> TemplateMatch:
    rule = CODE_RULES[rule_id]
    return TemplateMatch(
        template_id=rule_id, category=rule.info.category, severity=severity or rule.info.severity,
        confidence=calculate_confidence(rule.info.confidence, context),
        file=rel, line=line, column_start=col, column_end=end,
        matched_value=redact(value[:200]), excerpt=redact(excerpt.strip()[:700]),
        context=context, match_kind=kind, decoded_from=None,
    )


# --- fenced code blocks --------------------------------------------------------

def iter_fences(lines: list[str]):
    """Yield (lang, first_content_line_index, body_text) for each fenced block."""
    i = 0
    while i < len(lines):
        m = _FENCE_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        marker, lang = m.group(1), m.group(2).lower()
        j = i + 1
        while j < len(lines) and not lines[j].strip().startswith(marker[:3]):
            j += 1
        yield lang, i + 1, "\n".join(lines[i + 1:j])
        i = j + 1


def _analyse_fences(lines: list[str], rel: str) -> list[TemplateMatch]:
    out: list[TemplateMatch] = []
    for lang, start, body in iter_fences(lines):
        kind = _FENCE_LANGS.get(lang)
        if not kind or not body.strip():
            continue
        if kind == "py":
            from kodand.codeanalysis.python_ast import analyze_python_source
            out += analyze_python_source(body, rel, line_offset=start)
        elif kind == "json":
            from kodand.codeanalysis.json_struct import analyze_json_source
            out += analyze_json_source(body, rel, line_offset=start)
        else:
            try:
                from kodand.codeanalysis.js_ast import analyze_js_source
            except ImportError:  # tree-sitter missing: the scan already warns about it
                continue
            out += analyze_js_source(body.encode("utf-8"), rel, kind, line_offset=start)
    return out


# --- AST05: untrusted web content pulled into context -------------------------

_FETCH_TOOL = re.compile(
    r"\b(?:WebFetch|web_fetch|fetch_url|WebSearch|curl|wget|Invoke-WebRequest|Invoke-RestMethod|"
    r"requests\.get|httpx\.get|urllib|gh\s+(?:issue|pr)\s+view|gh\s+api|playwright|puppeteer|browser_navigate)\b",
    re.IGNORECASE)
_FETCH_VERB = re.compile(
    r"\b(?:fetch|crawl|scrape|download|open|visit|browse|retrieve|read|load|pull|follow)(?:es|s|ed|ing)?\b"
    r"[^.\n]{0,60}?\b(?:url|urls|uri|link|links|web\s?page|webpages|page|pages|website|site|issue|pr|pull request)s?\b",
    re.IGNORECASE)
_UNTRUSTED_SOURCE = re.compile(
    r"\b(?:(?:user|caller|requester)[- ]?(?:provided|supplied|given|specified)|provided|given|supplied|specified|"
    r"arbitrary|any|third[- ]party|external|untrusted|incoming|public)\b[^.\n]{0,40}?"
    r"\b(?:url|urls|uri|link|links|page|pages|site|website|source|sources|issue|content|address)"
    r"|\$ARGUMENTS|\{\{\s*url\s*\}\}|<url>|\bthe user'?s\s+(?:url|link)"
    r"|\b(?:the\s+)?(?:user|caller|requester)\s+(?:gives|gave|provides|provided|passes|pastes|shares|sends|supplies|specifies)\b",
    re.IGNORECASE)
_FOLLOW = re.compile(
    r"\b(?:follow|apply|execute|run|implement|obey|carry out|perform|do)\b[^.\n]{0,40}?"
    r"\b(?:instructions?|steps?|commands?|whatever|it says|they say|described|the page says|the content says)\b",
    re.IGNORECASE)
_FETCH_WINDOW = 4


def _untrusted_fetch(lines: list[str], contexts: list[str], rel: str, grants_shell: bool) -> list[TemplateMatch]:
    out: list[TemplateMatch] = []
    for i, line in enumerate(lines):
        m = _FETCH_TOOL.search(line) or _FETCH_VERB.search(line)
        if not m:
            continue
        ctx = match_context(contexts[i], line, m.start(), m.end())
        if not is_actionable(ctx):
            continue
        lo, hi = max(0, i - _FETCH_WINDOW), min(len(lines), i + _FETCH_WINDOW + 1)
        window = "\n".join(lines[lo:hi])
        if not _UNTRUSTED_SOURCE.search(window):
            continue
        follows = bool(_FOLLOW.search(window))
        severity = "high" if follows or grants_shell else None
        out.append(_match("AST05-UNTRUSTED-FETCH", rel, i + 1, m.start() + 1, m.end() + 1, m.group(0), line, ctx,
                          severity=severity))
    return out[:5]  # one skill repeating the step ten times is still one behaviour


# --- `` !`cmd` `` preload commands (Claude Code skills/commands) --------------

_PRELOAD = re.compile(r"(?<![\w`])!`([^`\n]{1,300})`")
_RISKY_SHELL = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bssh\b|\bscp\b|base64\s+-d|\beval\b|\$\(|~/\.ssh|\.aws/|\.env\b|"
    r"\bprintenv\b|\benv\b|\|\s*(?:ba|z)?sh\b|/etc/passwd|\bsudo\b|\brm\s+-",
    re.IGNORECASE)


def _preload_commands(lines: list[str], contexts: list[str], rel: str) -> list[TemplateMatch]:
    out = []
    for i, line in enumerate(lines):
        if contexts[i] == "code":
            continue
        for m in _PRELOAD.finditer(line):
            risky = bool(_RISKY_SHELL.search(m.group(1)))
            out.append(_match("AST09-PRELOAD-SHELL", rel, i + 1, m.start() + 1, m.end() + 1, m.group(0), line,
                              "instruction", severity="high" if risky else None))
    return out


# --- frontmatter ---------------------------------------------------------------

_TOOL_SPLIT = re.compile(r"[^\s,()]+(?:\([^)]*\))?")


def parse_allowed_tools(value) -> list[str]:
    """`allowed-tools` as a list: a YAML list, or a comma/space separated string
    whose entries may carry parenthesised arguments (`Bash(git add:*), Read`)."""
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        return [t.strip() for t in _TOOL_SPLIT.findall(value)]
    return []


_UNSCOPED_SHELL = re.compile(r"^(?:Bash|Shell|Terminal|run_shell_command|PowerShell)(?:\(\s*\*?(?::\*)?\s*\))?$",
                             re.IGNORECASE)
_WEB_TOOLS = re.compile(r"^(?:WebFetch|WebSearch|web_fetch|google_web_search|fetch|browser\w*)(?:\(.*\))?$",
                        re.IGNORECASE)


def _key_line(lines: list[str], key: str, end: int) -> int:
    for i in range(1, end):
        if re.match(rf"^{re.escape(key)}\s*:", lines[i]):
            return i
    return 0


def _frontmatter(lines: list[str], text: str, rel: str, require: bool) -> tuple[list[TemplateMatch], bool]:
    """Findings from the frontmatter block, plus whether it grants an unscoped shell."""
    raw, _body, errors = split_frontmatter(text, require_frontmatter=require)
    out: list[TemplateMatch] = []
    if errors and (require or errors[0].startswith("Malformed")):
        out.append(_match("AST04-MALFORMED-FRONTMATTER", rel, 1, 1, 2, errors[0], errors[0], "instruction"))
        return out, False
    if errors or not raw:
        return out, False
    end = next((i for i in range(1, len(lines)) if lines[i].strip() in ("---", "...")), len(lines))

    grants_shell = False
    tools = parse_allowed_tools(raw.get("allowed-tools", raw.get("tools")))
    shell = [t for t in tools if _UNSCOPED_SHELL.match(t)]
    if shell:
        grants_shell = True
        web = [t for t in tools if _WEB_TOOLS.match(t)]
        key = "allowed-tools" if "allowed-tools" in raw else "tools"
        ln = _key_line(lines, key, end)
        out.append(_match("AST03-BROAD-TOOL-GRANT", rel, ln + 1, 1, len(lines[ln]) + 1,
                          ", ".join(shell + web), lines[ln], "instruction", severity="high" if web else None))

    hooks = raw.get("hooks")
    if isinstance(hooks, dict) and hooks:
        from kodand.adapters.configs import iter_hook_commands
        ln = _key_line(lines, "hooks", end)
        commands = list(iter_hook_commands(hooks))
        risky = [c for c in commands if _RISKY_SHELL.search(c)]
        shown = (risky or commands or [yaml.safe_dump(hooks, default_flow_style=True).strip()])[0]
        out.append(_match("HOOK02-FRONTMATTER-HOOK", rel, ln + 1, 1, len(lines[ln]) + 1, shown,
                          f"hooks: {shown}", "instruction", severity="high" if risky else None))
    return out, grants_shell


def analyze_markdown_source(text: str, rel: str, name: str) -> list[TemplateMatch]:
    lines = text.splitlines()
    if not lines:
        return []
    contexts = classify_document(text)
    is_skill = name.lower() in ("skill.md", "skills.md")
    out, grants_shell = _frontmatter(lines, text, rel, require=is_skill)
    out += _analyse_fences(lines, rel)
    out += _untrusted_fetch(lines, contexts, rel, grants_shell)
    out += _preload_commands(lines, contexts, rel)
    return out
