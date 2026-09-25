#!/usr/bin/env bash
set -euo pipefail
# stop running processes first — an uninstall that leaves the UI service or any MCP server
# process still running behind is a half-uninstall, with no `kodand` command left to manage them
if command -v systemctl >/dev/null 2>&1 && systemctl --user is-enabled kodand-ui.service >/dev/null 2>&1; then
  systemctl --user stop kodand-ui.service || true
fi
# anchored to end-of-line, not a bare substring — see install.sh's matching cleanup for why
if pgrep -f "/kodand mcp\$" >/dev/null 2>&1; then
  pkill -f "/kodand mcp\$" || true
fi
pipx uninstall kodand 2>/dev/null || true
uv tool uninstall kodand 2>/dev/null || true
rm -rf "$HOME/.local/share/kodand";rm -f "$HOME/.local/bin/kodand"
