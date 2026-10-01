#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";BIN="$HOME/.local/bin";mkdir -p "$BIN"
EXTRAS="${1:-all}"  # all = ui + mcp + code; pass e.g. "ui,mcp" for less, or "" for the bare CLI
# Install from a snapshot of the tree taken right now, not the live checkout: the build reads files for
# a while, and a branch switch in another terminal meanwhile once produced an install mixing two
# versions. Tracked + untracked-but-not-ignored files, so uncommitted edits are still included.
SRC="$ROOT"
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  SRC="$(mktemp -d)"; trap 'rm -rf "$SRC"' EXIT
  (cd "$ROOT" && git ls-files -z -co --exclude-standard | while IFS= read -r -d '' f; do if [ -e "$f" ]; then printf '%s\0' "$f"; fi; done \
     | tar --null -T - -cf -) | tar -xf - -C "$SRC"
fi
SPEC="$SRC"; [ -n "$EXTRAS" ] && SPEC="$SRC[$EXTRAS]"
if command -v pipx >/dev/null 2>&1;then pipx install --force "$SPEC";elif command -v uv >/dev/null 2>&1;then uv tool install --force "$SPEC";else ENV="$HOME/.local/share/kodand";python3 -m venv "$ENV";"$ENV/bin/python" -m pip install --upgrade pip setuptools wheel;"$ENV/bin/pip" install --force-reinstall "$SPEC";ln -sf "$ENV/bin/kodand" "$BIN/kodand";fi
VER="$(grep -m1 '^version=' "$SRC/pyproject.toml" | sed -E 's/version="([^"]+)"/\1/')"
echo "Installed Kodand $VER (extras: $EXTRAS). Run: kodand        Web UI: kodand ui"
# a running "kodand ui" process keeps executing the old code in memory after an
# install/upgrade — restart the service so it actually picks up the new build
if command -v systemctl >/dev/null 2>&1 && systemctl --user is-enabled kodand-ui.service >/dev/null 2>&1; then
  systemctl --user restart kodand-ui.service
  echo "Restarted kodand-ui.service to load the new build."
fi
# same for the Claude Agent worker installed with `kodand agent --install-service`; its stop re-queues
# any finding it was verifying, so a restart loses no work
if command -v systemctl >/dev/null 2>&1 && systemctl --user is-enabled kodand-agent.service >/dev/null 2>&1; then
  systemctl --user restart kodand-agent.service
  echo "Restarted kodand-agent.service to load the new build."
fi
# kodand mcp stdio server processes are spawned ad hoc by MCP clients (e.g. `claude mcp add
# kodand -- kodand mcp`), not systemd-managed, so they never got the same "restart to pick up
# the new build" treatment as kodand-ui.service above — a long-lived one can silently keep
# serving stale, pre-upgrade code indefinitely. Clear them out too; a client whose connection
# drops reconnects (spawning a fresh process) on its next tool call.
# Anchored to "/kodand mcp" at end-of-line (not a bare "kodand mcp" substring): pkill -f matches
# against every process's FULL command line on the system, and a bare substring would also
# match anything merely mentioning the words "kodand mcp" — e.g. a shell running this very
# install script, or a diagnostic command in someone's terminal history. The real invocation
# always ends in ".../kodand mcp" (binary path, then the "mcp" subcommand as the last word).
if pgrep -f "/kodand mcp\$" >/dev/null 2>&1; then
  pkill -f "/kodand mcp\$" || true
  echo "Stopped running kodand mcp server process(es) so MCP clients reconnect to the new build."
fi
