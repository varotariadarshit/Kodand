import json

from kodand.adapters.common import Parsed
from kodand.models.inventory import SkillMetadata


def parse_mcp_config(text):
    """Parser for MCP server config JSON (`.mcp.json`, `mcp.json`,
    `claude_desktop_config.json`) — an `{"mcpServers": {name: {command, args, env}}}`
    (or `"servers"`) mapping. The matcher scans the raw text for risky
    indicators regardless of this parse; `metadata` only feeds inventory/reporting."""
    o = Parsed(body=text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        o.errors = [f"Malformed JSON: {e}"]
        return o
    servers = {}
    if isinstance(data, dict):
        for key in ("mcpServers", "servers"):
            candidate = data.get(key)
            if isinstance(candidate, dict):
                servers = candidate
                break
    o.metadata = SkillMetadata(additional_fields={
        "servers": sorted(servers), "server_count": len(servers),
    })
    return o


def parse_hook_settings(text):
    """Parser for Claude Code hook settings (`.claude/settings.json`,
    `.claude/settings.local.json`) — a `{"hooks": {event: [{"hooks": [{command}]}]}}`
    mapping. The matcher scans the raw text directly; this only feeds metadata."""
    o = Parsed(body=text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        o.errors = [f"Malformed JSON: {e}"]
        return o
    hooks = data.get("hooks") if isinstance(data, dict) else None
    hooks = hooks if isinstance(hooks, dict) else {}
    command_count = sum(
        1 for entries in hooks.values() if isinstance(entries, list)
        for entry in entries if isinstance(entry, dict)
        for _ in (entry.get("hooks") or [])
    )
    o.metadata = SkillMetadata(additional_fields={
        "hook_events": sorted(hooks), "hook_command_count": command_count,
    })
    return o
