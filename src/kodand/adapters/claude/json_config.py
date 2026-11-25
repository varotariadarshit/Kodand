import json

from kodand.adapters.common import Parsed
from kodand.adapters.configs import load_json_tolerant, mcp_servers
from kodand.models.inventory import SkillMetadata


def parse_mcp_config(text):
    """Parser for MCP server config JSON (`.mcp.json`, `mcp.json`,
    `claude_desktop_config.json`, `.vscode/mcp.json`, `opencode.json(c)`, ...) — an
    `{"mcpServers": {name: {command, args, env}}}` (or `"servers"` / `"mcp"`) mapping,
    JSONC tolerated. The matcher scans the raw text for risky indicators regardless
    of this parse; `metadata` only feeds inventory/reporting."""
    o = Parsed(body=text)
    try:
        data = load_json_tolerant(text)
    except json.JSONDecodeError as e:
        o.errors = [f"Malformed JSON: {e}"]
        return o
    servers = mcp_servers(data)
    o.metadata = SkillMetadata(additional_fields={
        "servers": sorted(servers), "server_count": len(servers),
    })
    return o


def parse_hook_settings(text):
    """Parser for hook settings: Claude Code / Gemini / Codex
    `{"hooks": {event: [{"matcher", "hooks": [{command}]}]}}` and Cursor / Copilot
    `{"version": 1, "hooks": {event: [{command} | {bash, powershell}]}}`. The matcher
    scans the raw text directly; this only feeds metadata."""
    o = Parsed(body=text)
    try:
        data = load_json_tolerant(text)
    except json.JSONDecodeError as e:
        o.errors = [f"Malformed JSON: {e}"]
        return o
    hooks = data.get("hooks") if isinstance(data, dict) else None
    hooks = hooks if isinstance(hooks, dict) else {}
    command_count = sum(
        len(entry["hooks"]) if isinstance(entry.get("hooks"), list) else 1
        for entries in hooks.values() if isinstance(entries, list)
        for entry in entries if isinstance(entry, dict)
    )
    o.metadata = SkillMetadata(additional_fields={
        "hook_events": sorted(hooks), "hook_command_count": command_count,
    })
    return o
