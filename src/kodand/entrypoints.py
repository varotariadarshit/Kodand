"""Registry of agent-artifact entrypoints across platforms: skills, instruction
and rules files, commands/prompts/subagents, MCP server configs and hook configs.

Every pattern is a lowercase, `/`-separated glob matched against the TRAILING
path segments of a repo-relative path, i.e. at any depth. A pattern is never
anchored to the scan root: an uploaded folder (`<name>/.github/...`), a GitHub
zip (`<repo>-main/...`) or a monorepo package (`packages/x/.cursor/rules/...`)
all match exactly as a file at the root would. Within a pattern, `*` matches
inside one segment and `**` matches any number of segments (including none).

Order matters: the first matching row wins, so platform-specific locations
(`.cursor/mcp.json`) come before generic basenames (`mcp.json`).

Sources (checked 2026-11): code.claude.com/docs, learn.chatgpt.com/docs (Codex),
geminicli.com/docs, code.visualstudio.com/docs/copilot + docs.github.com,
cursor.com/docs, docs.devin.ai (Windsurf), docs.cline.bot, Roo Code docs,
docs.continue.dev, junie.jetbrains.com, kiro.dev + Amazon Q docs, zed.dev,
opencode.ai/docs, agentskills.io/specification.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Callable

from kodand.adapters.claude.frontmatter import parse_skill_text
from kodand.adapters.claude.json_config import parse_hook_settings, parse_mcp_config
from kodand.adapters.common import parse_generic_markdown
from kodand.adapters.configs import parse_toml_config, parse_yaml_config

# platform keys (free-form strings shown in reports)
CLAUDE = "claude-code"
OPENAI = "chatgpt-openai"
GEMINI = "gemini-cli"
COPILOT = "microsoft-copilot"
CURSOR = "cursor"
WINDSURF = "windsurf"  # incl. its successor Devin Desktop and the Codeium plugin
CLINE = "cline"
ROO = "roo-code"
CONTINUE = "continue"
JUNIE = "jetbrains-junie"
KIRO = "kiro"  # incl. Amazon Q Developer, whose project dirs Kiro still reads
ZED = "zed"
OPENCODE = "opencode"


@dataclass(frozen=True)
class EntrypointSpec:
    """`bundle`: the entrypoint's folder IS the artifact (a skill folder, a plugin
    manifest dir, a hooks dir), so every file in it is agent content and gets scanned.
    Instruction/rules/command files and MCP configs are NOT bundles: they often sit at
    the repo root or in `.github/`, and treating their folder as the artifact turns the
    scan into a whole-repo application-code (SAST) scan. For those, only the file
    itself plus the docs and scripts it points the agent at are scanned."""
    platform: str
    extension_type: str
    parser: Callable
    patterns: tuple[str, ...]
    bundle: bool = False


_MD = parse_generic_markdown
_FM = parse_skill_text

ENTRYPOINTS: tuple[EntrypointSpec, ...] = (
    # --- skills: the Agent Skills standard, read from .claude/.agents/.github/.cursor/.gemini/... skills dirs
    EntrypointSpec(CLAUDE, "agent-skill", _FM, ("skill.md", "skills.md"), bundle=True),

    # --- Claude Code
    EntrypointSpec(CLAUDE, "agent-command", _MD, (".claude/commands/**/*.md",)),
    EntrypointSpec(CLAUDE, "agent-subagent", _MD, (".claude/agents/**/*.md",)),
    EntrypointSpec(CLAUDE, "agent-rule", _MD, (".claude/rules/**/*.md",)),
    EntrypointSpec(CLAUDE, "agent-context", _MD, ("claude.md", "claude.local.md")),
    EntrypointSpec(CLAUDE, "hook-config", parse_hook_settings,
                   (".claude/settings.json", ".claude/settings.local.json"), bundle=True),
    EntrypointSpec(CLAUDE, "plugin-manifest", parse_mcp_config,
                   (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"), bundle=True),

    # --- GitHub Copilot (VS Code, coding agent, CLI)
    EntrypointSpec(COPILOT, "agent-instructions", _MD,
                   (".github/copilot-instructions.md", ".github/instructions/**/*.instructions.md")),
    EntrypointSpec(COPILOT, "agent-prompt", _MD,
                   (".github/prompts/**/*.prompt.md", ".github/agents/**/*.agent.md",
                    ".github/chatmodes/**/*.chatmode.md", "*.chatmode.md")),
    EntrypointSpec(COPILOT, "hook-config", parse_hook_settings,
                   (".github/hooks/*.json", ".github/copilot/settings.json", ".github/copilot/settings.local.json"), bundle=True),
    EntrypointSpec(COPILOT, "mcp-config", parse_mcp_config, (".vscode/mcp.json", ".copilot/mcp-config.json")),

    # --- OpenAI Codex
    EntrypointSpec(OPENAI, "agent-context", _MD, ("agents.md", "agents.override.md", "agents.local.md", "agent.md")),
    EntrypointSpec(OPENAI, "mcp-config", parse_toml_config, (".codex/config.toml",)),
    EntrypointSpec(OPENAI, "hook-config", parse_hook_settings, (".codex/hooks.json",), bundle=True),

    # --- Gemini CLI
    EntrypointSpec(GEMINI, "agent-context", _MD, ("gemini.md",)),
    EntrypointSpec(GEMINI, "agent-config", parse_mcp_config, (".gemini/settings.json", "gemini-extension.json")),
    EntrypointSpec(GEMINI, "agent-command", parse_toml_config, (".gemini/commands/**/*.toml",)),

    # --- Cursor (`.cursor/rules` may itself be a plain file, not only a dir of .mdc)
    EntrypointSpec(CURSOR, "mcp-config", parse_mcp_config, (".cursor/mcp.json",)),
    EntrypointSpec(CURSOR, "hook-config", parse_hook_settings, (".cursor/hooks.json",), bundle=True),
    EntrypointSpec(CURSOR, "agent-rule", _MD,
                   (".cursor/rules", ".cursor/rules/**/*", ".cursorrules", ".cursor/commands/**/*.md")),

    # --- Windsurf / Devin Desktop / Codeium
    EntrypointSpec(WINDSURF, "mcp-config", parse_mcp_config,
                   (".devin/mcp_config.json", ".devin/mcp_config.local.json", "mcp_config.json")),
    EntrypointSpec(WINDSURF, "hook-config", parse_hook_settings, (".devin/hooks.v1.json", ".windsurf/hooks.json"), bundle=True),
    EntrypointSpec(WINDSURF, "agent-rule", _MD,
                   (".windsurfrules", ".windsurf/rules/**/*.md", ".windsurf/workflows/**/*.md",
                    ".windsurf/global_rules.md", ".devin/rules/**/*.md", ".devin/global_rules.md",
                    ".codeium/**/*.md")),

    # --- Cline
    EntrypointSpec(CLINE, "mcp-config", parse_mcp_config, ("cline_mcp_settings.json",)),
    EntrypointSpec(CLINE, "agent-rule", _MD,
                   (".clinerules", ".clinerules/**/*", ".cline/rules/**/*", ".cline/workflows/**/*",
                    ".cline/hooks/**/*")),

    # --- Roo Code
    EntrypointSpec(ROO, "mcp-config", parse_mcp_config, (".roo/mcp.json",)),
    EntrypointSpec(ROO, "agent-config", parse_yaml_config, (".roomodes",)),
    EntrypointSpec(ROO, "agent-rule", _MD, (".roo/rules/**/*", ".roo/rules-*/**/*", ".roorules", ".roorules-*")),

    # --- Continue
    EntrypointSpec(CONTINUE, "mcp-config", parse_yaml_config,
                   (".continue/mcpservers/**/*.yaml", ".continue/mcpservers/**/*.yml", ".continue/config.yaml")),
    EntrypointSpec(CONTINUE, "mcp-config", parse_mcp_config, (".continue/mcpservers/**/*.json",)),
    EntrypointSpec(CONTINUE, "agent-rule", _MD, (".continue/rules/**/*.md", ".continue/*.md")),

    # --- JetBrains Junie
    EntrypointSpec(JUNIE, "mcp-config", parse_mcp_config, (".junie/mcp/mcp.json",)),
    EntrypointSpec(JUNIE, "agent-context", _MD, (".junie/guidelines.md", ".junie/guidelines/**/*.md")),

    # --- Kiro / Amazon Q Developer
    EntrypointSpec(KIRO, "mcp-config", parse_mcp_config, (".kiro/settings/mcp.json", ".amazonq/mcp.json")),
    EntrypointSpec(KIRO, "hook-config", parse_hook_settings, (".kiro/hooks/**/*",), bundle=True),
    EntrypointSpec(KIRO, "agent-rule", _MD, (".kiro/steering/**/*.md", ".amazonq/rules/**/*.md")),

    # --- Zed
    EntrypointSpec(ZED, "agent-rule", _MD, (".rules",)),

    # --- OpenCode
    EntrypointSpec(OPENCODE, "agent-config", parse_mcp_config, ("opencode.json", "opencode.jsonc")),
    EntrypointSpec(OPENCODE, "agent-rule", _MD, (".opencode/**/*.md",)),

    # --- generic basenames (after every platform-specific location above)
    # plugin/extension hook files: Claude Code, Codex and Gemini plugins all ship hooks/hooks.json
    EntrypointSpec(CLAUDE, "hook-config", parse_hook_settings, ("hooks/hooks.json",), bundle=True),
    EntrypointSpec(CLAUDE, "mcp-config", parse_mcp_config,
                   (".mcp.json", "mcp.json", "claude_desktop_config.json", "managed-mcp.json")),
)

_COMPILED: tuple[tuple[EntrypointSpec, tuple[tuple[str, ...], ...]], ...] = tuple(
    (spec, tuple(tuple(p.split("/")) for p in spec.patterns)) for spec in ENTRYPOINTS
)


def _match(path: tuple[str, ...], pat: tuple[str, ...]) -> bool:
    """Glob-match `path` segments against `pat` segments, both full-length."""
    if not pat:
        return not path
    head, rest = pat[0], pat[1:]
    if head == "**":
        return any(_match(path[i:], rest) for i in range(len(path) + 1))
    return bool(path) and fnmatchcase(path[0], head) and _match(path[1:], rest)


def path_matches(rel_low: str, pattern: tuple[str, ...]) -> bool:
    """True when `pattern` matches the trailing segments of `rel_low` (any depth)."""
    return _match(tuple(rel_low.split("/")), ("**",) + pattern)


def match_entrypoint(rel: str, extra: tuple[EntrypointSpec, ...] = ()) -> EntrypointSpec | None:
    """The first registry row matching `rel`, then `extra` rows (user-approved learned
    locations, see kodand.learned_scope) — built-ins always win."""
    rel_low = rel.lower()
    for spec, pats in _COMPILED:
        if any(path_matches(rel_low, p) for p in pats):
            return spec
    for spec in extra:
        if any(path_matches(rel_low, tuple(p.split("/"))) for p in spec.patterns):
            return spec
    return None


def _hint_names() -> tuple[frozenset[str], tuple[str, ...]]:
    """Basenames (and `*.suffix` endings) that identify an agent artifact on their
    own, derived from the registry so the coverage-gap safety net can never drift
    from it. Generic names (settings.json, config.toml, hooks.json, *.md, *.json)
    are left out: too common in unrelated projects to flag by name alone."""
    generic = {"settings.json", "settings.local.json", "hooks.json", "config.toml", "config.yaml",
               "mcp.json", "plugin.json", "marketplace.json", "rules", "guidelines.md"}
    names, suffixes = set(), set()
    for spec in ENTRYPOINTS:
        for p in spec.patterns:
            last = p.split("/")[-1]
            if "*" not in last:
                if last not in generic:
                    names.add(last)
            elif last.startswith("*.") and last.count(".") >= 2:  # *.instructions.md, *.prompt.md ...
                suffixes.add(last[1:])
    suffixes.add(".mdc")
    return frozenset(names), tuple(sorted(suffixes))


ENTRYPOINT_NAME_HINTS, ENTRYPOINT_SUFFIX_HINTS = _hint_names()


def looks_like_entrypoint(name: str) -> bool:
    name = name.lower()
    return name in ENTRYPOINT_NAME_HINTS or name.endswith(ENTRYPOINT_SUFFIX_HINTS)


# directory names that, on their own, mark agent configuration — used to warn
# when such a directory holds text files but nothing in it was recognised
AGENT_DIR_NAMES = frozenset({
    ".claude", ".agents", ".ai", ".codex", ".gemini", ".cursor", ".windsurf", ".devin", ".codeium",
    ".cline", ".clinerules", ".roo", ".continue", ".junie", ".kiro", ".amazonq", ".opencode", ".copilot",
})
