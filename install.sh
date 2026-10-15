#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";BIN="$HOME/.local/bin";mkdir -p "$BIN"
# Always the complete install: the web console (ui), the MCP server (mcp) and JS/TS analysis (code), so
# every feature works straight away and nobody has to reinstall to switch one on later.
EXTRAS="all"
ASSUME_YES=0; CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --check) CHECK_ONLY=1 ;;
    -h|--help)
      echo "Usage: ./install.sh [--yes] [--check]"
      echo "  Checks what Kodand needs, offers to install what is missing, then installs Kodand"
      echo "  (web console + MCP server + code analysis)."
      echo "  --yes    don't ask before installing missing dependencies"
      echo "  --check  only report which dependencies are present, then exit"
      exit 0 ;;
    *) echo "Note: install.sh always installs everything (ui, mcp, code); ignoring '$arg'." ;;
  esac
done

# ---- dependency check ------------------------------------------------------------------------------
# What the install itself needs. "required" ones are installed on request; "recommended" ones only make
# it better (git: the install is taken from a snapshot of the tree; claude: Ask AI-CLI and Claude Agent).
py_ok() { command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11, 4) else 1)' 2>/dev/null; }
venv_ok() { py_ok && python3 -c 'import venv, ensurepip' 2>/dev/null; }
MISSING_REQ=""; MISSING_REC=""   # space-separated: python installer tar git
row() { printf '  %-12s %-10s %s\n' "$1" "$2" "$3"; }

check_deps() {
  MISSING_REQ=""; MISSING_REC=""
  echo "Checking dependencies..."
  if py_ok; then row "python3" "OK" "$(python3 -c 'import platform; print(platform.python_version())')"
  elif command -v python3 >/dev/null 2>&1; then row "python3" "MISSING" "found $(python3 -c 'import platform; print(platform.python_version())'), Kodand needs 3.11.4 or newer"; MISSING_REQ="$MISSING_REQ python"
  else row "python3" "MISSING" "needs 3.11.4 or newer"; MISSING_REQ="$MISSING_REQ python"; fi
  if command -v pipx >/dev/null 2>&1; then row "installer" "OK" "pipx"
  elif command -v uv >/dev/null 2>&1; then row "installer" "OK" "uv"
  elif venv_ok; then row "installer" "OK" "python venv + pip"
  else row "installer" "MISSING" "needs one of: pipx, uv, or python3 with venv + pip"; MISSING_REQ="$MISSING_REQ installer"; fi
  if command -v tar >/dev/null 2>&1; then row "tar" "OK" "$(command -v tar)"; else row "tar" "MISSING" "used to snapshot the tree being installed"; MISSING_REQ="$MISSING_REQ tar"; fi
  if command -v git >/dev/null 2>&1; then row "git" "OK" "$(git --version | sed 's/git version //')"
  else row "git" "MISSING" "recommended: installs a consistent snapshot of the tree (falls back to the live checkout)"; MISSING_REC="$MISSING_REC git"; fi
  if command -v claude >/dev/null 2>&1; then row "claude" "OK" "Claude Code found (Ask AI-CLI, Claude Agent)"
  else row "claude" "optional" "Claude Code not found; Ask AI-CLI and Claude Agent need it: https://claude.com/claude-code (not installed by this script)"; fi
  if command -v systemctl >/dev/null 2>&1; then row "systemd" "OK" "can run the console / agent as background services"
  else row "systemd" "optional" "not found; run 'kodand ui' / 'kodand agent' in a terminal instead"; fi
}

# system packages for the missing items, for whichever package manager this machine has
detect_pm() { for pm in apt-get dnf yum pacman zypper brew; do if command -v "$pm" >/dev/null 2>&1; then echo "$pm"; return; fi; done; }
pkgs_for() {  # $1 = package manager, then the missing items
  local pm="$1" out="" item; shift
  for item in "$@"; do
    case "$pm:$item" in
      apt-get:python) out="$out python3 python3-venv python3-pip" ;;
      apt-get:installer) out="$out pipx python3-venv" ;;
      dnf:python|yum:python|zypper:python) out="$out python3 python3-pip" ;;
      dnf:installer|yum:installer) out="$out pipx" ;;
      zypper:installer) out="$out python3-pipx" ;;
      pacman:python) out="$out python python-pip" ;;
      pacman:installer) out="$out python-pipx" ;;
      brew:python) out="$out python@3.12" ;;
      brew:installer) out="$out pipx" ;;
      *:tar) out="$out tar" ;;
      *:git) out="$out git" ;;
    esac
  done
  echo $out
}
install_missing() {  # $@ = missing items; returns non-zero if it couldn't try
  local pm pkgs sudo=""
  pm="$(detect_pm)"
  if [ -z "$pm" ]; then echo "No supported package manager found (apt, dnf, yum, pacman, zypper, brew). Install the missing items yourself." >&2; return 1; fi
  pkgs="$(pkgs_for "$pm" "$@")"
  if [ -z "$pkgs" ]; then return 1; fi
  if [ "$pm" != "brew" ] && [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then sudo="sudo"; else echo "Need root (or sudo) to install: $pkgs" >&2; return 1; fi
  fi
  echo "Installing with $pm: $pkgs"
  case "$pm" in
    apt-get) $sudo apt-get update && $sudo apt-get install -y $pkgs ;;
    dnf|yum) $sudo "$pm" install -y $pkgs ;;
    pacman) $sudo pacman -S --needed --noconfirm $pkgs ;;
    zypper) $sudo zypper --non-interactive install $pkgs ;;
    brew) brew install $pkgs ;;
  esac
}
ask_yes_no() {
  if [ "$ASSUME_YES" = 1 ]; then return 0; fi
  if [ ! -t 0 ]; then echo "(not a terminal, so I can't ask; re-run with --yes to install them without asking)"; return 1; fi
  local reply; read -r -p "$1 [y/N] " reply
  case "$reply" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

check_deps
if [ "$CHECK_ONLY" = 1 ]; then [ -z "$MISSING_REQ" ]; exit $?; fi
if [ -n "$MISSING_REQ$MISSING_REC" ]; then
  echo
  echo "WARNING: missing:$MISSING_REQ$MISSING_REC"
  echo "         Without the required ones Kodand can't be installed or may not work as expected."
  if ask_yes_no "Install the missing dependencies now?"; then
    install_missing $MISSING_REQ $MISSING_REC || echo "Could not install them automatically." >&2
    echo
    check_deps
    if [ -n "$MISSING_REQ" ]; then
      echo "ERROR: still missing:$MISSING_REQ. Install them yourself (Kodand needs Python 3.11.4 or newer), then run ./install.sh again." >&2
      exit 1
    fi
    if [ -n "$MISSING_REC" ]; then echo "Continuing without:$MISSING_REC (recommended, not required)."; fi
  else
    if [ -n "$MISSING_REQ" ]; then echo "ERROR: can't continue without:$MISSING_REQ. Install them, then run ./install.sh again." >&2; exit 1; fi
    echo "Continuing without:$MISSING_REC. Kodand will work, but the install won't be from a consistent snapshot."
  fi
fi
echo "All required dependencies are present. Installing Kodand..."
echo

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
echo "Installed Kodand $VER (ui + mcp + code)."
# prove the install is complete rather than assume it: import every optional dependency with the Python
# the installed `kodand` command itself runs on (its script's shebang), so a broken or partial install
# fails here, loudly, instead of the first time someone runs `kodand ui` or `kodand mcp`
KODAND_BIN="$(command -v kodand || true)"; [ -n "$KODAND_BIN" ] || KODAND_BIN="$BIN/kodand"
KODAND_PY="$(head -n1 "$KODAND_BIN" 2>/dev/null | sed -n 's/^#![[:space:]]*//p')"
if [ -n "$KODAND_PY" ] && [ -x "${KODAND_PY%% *}" ]; then
  if ! ${KODAND_PY} -c 'import fastapi, uvicorn, multipart, mcp, tree_sitter, tree_sitter_javascript, tree_sitter_typescript' 2>/dev/null; then
    echo "ERROR: Kodand installed, but its web console / MCP / code-analysis dependencies did not." >&2
    echo "       Re-run ./install.sh with network access." >&2
    exit 1
  fi
  echo "Verified: web console, MCP server and code analysis are ready."
fi
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "NOTE: $BIN is not on your PATH. Add it (e.g. echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc) and open a new terminal." ;;
esac
cat <<NEXT
Next steps:
  kodand ui                                  web console at http://127.0.0.1:8787 (first login: password "kodand", then you set your own)
  claude mcp add kodand -- kodand mcp        use Kodand from Claude Code (or copy the snippet in Settings -> MCP Server)
  kodand agent --install-service             optional: keep the Claude Agent worker running in the background
  (Ask AI-CLI and Claude Agent use your own Claude Code; install it from https://claude.com/claude-code and sign in)
NEXT
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
