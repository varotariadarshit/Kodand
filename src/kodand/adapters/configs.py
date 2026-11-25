"""Tolerant parsers for the agent config formats beyond plain JSON: JSONC
(VS Code / OpenCode), TOML (OpenAI Codex `config.toml`, Gemini commands) and
YAML (Continue `mcpServers/*.yaml`). Like the JSON adapters, these only feed
inventory metadata — the matcher always scans the raw text regardless of
whether the parse succeeds — so they never raise."""
import json
import re
import tomllib

import yaml

from kodand.adapters.common import Parsed
from kodand.models.inventory import SkillMetadata

# keys under which the various platforms nest their MCP server maps
MCP_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers", "mcp")

_LINE_COMMENT = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*')
_BLOCK_COMMENT = re.compile(r'("(?:\\.|[^"\\])*")|/\*.*?\*/', re.S)
_TRAILING_COMMA = re.compile(r'("(?:\\.|[^"\\])*")|,(\s*[}\]])')


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings."""
    text = _BLOCK_COMMENT.sub(lambda m: m.group(1) or "", text)
    text = _LINE_COMMENT.sub(lambda m: m.group(1) or "", text)
    return _TRAILING_COMMA.sub(lambda m: m.group(1) or m.group(2), text)


def load_json_tolerant(text: str):
    """json.loads, falling back to JSONC. Raises json.JSONDecodeError if neither parses."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(strip_jsonc(text))


def mcp_servers(data) -> dict:
    """The server map from any supported MCP config shape, or {}."""
    if not isinstance(data, dict):
        return {}
    for key in MCP_SERVER_KEYS:
        candidate = data.get(key)
        if isinstance(candidate, dict):
            return candidate
    # Continue's .continue/mcpServers/*.yaml: a list of {name, command, args}
    candidate = data.get("mcpServers")
    if isinstance(candidate, list):
        return {str(s.get("name", i)): s for i, s in enumerate(candidate) if isinstance(s, dict)}
    return {}


def _mcp_parsed(text: str, data, errors: list[str]) -> Parsed:
    o = Parsed(body=text, errors=errors)
    servers = mcp_servers(data)
    o.metadata = SkillMetadata(additional_fields={"servers": sorted(servers), "server_count": len(servers)})
    return o


def parse_toml_config(text: str) -> Parsed:
    """OpenAI Codex `config.toml` (`[mcp_servers.<name>]`), or any TOML agent
    file (Gemini `commands/*.toml`)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return Parsed(body=text, errors=[f"Malformed TOML: {e}"])
    return _mcp_parsed(text, data, [])


def parse_yaml_config(text: str) -> Parsed:
    """Continue `config.yaml` / `mcpServers/*.yaml`, Roo `.roomodes`."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return Parsed(body=text, errors=[f"Malformed YAML: {e}"])
    return _mcp_parsed(text, data, [])


def iter_hook_commands(hooks: dict):
    """Yield every command string in a hooks map, across the shapes in use:
    Claude Code / Gemini / Codex nest `{matcher, hooks: [{command}]}` under each
    event; Cursor and Copilot list `{command}` / `{bash, powershell}` directly."""
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            inner = entry.get("hooks")
            for h in (inner if isinstance(inner, list) else [entry]):
                if not isinstance(h, dict):
                    continue
                for key in ("command", "bash", "powershell", "url"):
                    if isinstance(h.get(key), str):
                        yield h[key]
