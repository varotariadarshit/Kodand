# Kodand User Guide

Kodand (Agentic Skills Threat and Risk Analyzer) statically scans agentic AI
"skill" files — `SKILL.md`, `GEMINI.md`, `AGENTS.md`, Copilot instructions,
Cursor rules, Windsurf rules — for security risks before they run inside an
agent. This guide covers installation and every way to use it: the CLI, the
web console, and the MCP server (so an AI agent like Claude Code can drive
Kodand directly from a terminal).

All automated findings are **candidates** requiring human validation — Kodand
flags patterns, it doesn't prove exploitability.

## Contents
1. [Install](#1-install)
2. [Three ways to run Kodand](#2-three-ways-to-run-kodand)
3. [CLI reference](#3-cli-reference)
4. [Web console](#4-web-console)
5. [Finding review workflow](#5-finding-review-workflow)
6. [MCP server — scanning from an AI agent](#6-mcp-server--scanning-from-an-ai-agent)
7. [Custom templates](#7-custom-templates)
8. [Suppressions](#8-suppressions-kodandyml)
9. [Report formats](#9-report-formats)
10. [Workspace & data storage](#10-workspace--data-storage)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Install

Requires **Python 3.11.4+** on Linux or macOS (on Windows, use WSL).

```bash
pipx install "kodand[all]"
kodand version
```

- `[all]` installs every optional part. Pick fewer if you like:
  `ui` (web console — FastAPI/uvicorn), `mcp` (MCP server support) and `code`
  (JavaScript/TypeScript code analysis via tree-sitter; Python analysis needs no
  extra). `pipx install kodand` alone gives the CLI only.
- Upgrade with `pipx upgrade kodand`. If an MCP client has
  `kodand mcp` running, restart that client session afterwards so it picks up the
  new build (see the `status` MCP tool in section 6 to check).
- From a clone: `./install.sh` installs `all` by default (or pass extras, e.g.
  `./install.sh ui,mcp`). It uses [`pipx`](https://pipx.pypa.io) if available
  (falls back to `uv tool install`, then a plain venv under
  `~/.local/share/kodand`), restarts the `kodand-ui.service` systemd user service if
  you run the console that way, and stops running `kodand mcp` processes so MCP
  clients reconnect to the new build. Upgrade with `git pull && ./install.sh`.

## 2. Three ways to run Kodand

| Interface | Command | Best for |
|---|---|---|
| **CLI** | `kodand analyze /path/to/repo` | Scripting, CI pipelines, one-off scans |
| **Web console** | `kodand ui` → http://127.0.0.1:8787 | Browsing projects/scans, reviewing findings, dashboards |
| **MCP server** | `kodand mcp` (launched by an MCP client) | Letting an AI agent (Claude Code, Cursor, etc.) scan and verify findings for you during a session |

All three share the same workspace (`~/.kodand/`), the same 46 built-in
detection templates, and the same scan engine — a project or scan created in
one is visible from the others (MCP visibility additionally requires a
project to be explicitly shared — see [§6](#6-mcp-server--scanning-from-an-ai-agent)).

## 3. CLI reference

```bash
kodand version                          # print version + banner

kodand templates list                   # 46 built-in templates, Literals + Regex columns
kodand templates scan /path/to/repo     # quick scan, shows match kind (literal/regex/decoded)

kodand analyze /path/to/repo \
  --output output/analysis.json \
  --html   output/report.html \
  --sarif  output/results.sarif \
  --docx   output/report.docx \
  --pdf    output/report.pdf           # full scan with whichever report formats you request

kodand bench                            # precision/recall/F1 on the packaged corpus
kodand bench /path/to/labeled_corpus --threshold 45

kodand schema --output analysis-schema.json   # dump the RepositoryAnalysis JSON schema

kodand ui [--host 127.0.0.1] [--port 8787] [--allow-remote]   # launch the web console
kodand mcp                                                     # run as an MCP server (stdio)
```

Notes:
- `kodand ui` refuses to bind to a non-loopback host unless you pass
  `--allow-remote` — the console is password-protected, but it can read/scan any
  local path and serves plain HTTP.
- `kodand mcp` prints nothing to stdout itself (stdio carries the MCP
  protocol); it's meant to be launched by an MCP client, not run directly in
  an interactive shell.
- Every command supports `--verbose`/`-v` for debug logging and (where
  applicable) `--no-banner`.

## 4. Web console

```bash
kodand ui
```
Open http://127.0.0.1:8787.

### Signing in
The console requires a password. On a fresh workspace it's **`kodand`** — the login
page says so until you change it — and you're forced to set your own before you can
get in. After that:
- The password is PBKDF2-hashed into `~/.kodand/auth.json`; sessions live in
  `~/.kodand/sessions.json` and survive a service restart, expiring after 7 days.
- Changing the password invalidates every existing session.
- **Forgot it?** Run `kodand password reset` in a terminal on the machine running
  Kodand and enter a new password, or `kodand password reset --to-default` to go back
  to `kodand` and the forced-change prompt. No restart is needed, and every existing
  session is signed out. As a last resort, deleting `~/.kodand/auth.json` also
  restores the default.
- **Log out** from the bottom of the sidebar.
- **Too many wrong passwords** (5 within 5 minutes) locks sign-in for the rest of
  that window. The lock is in memory, so restarting the console clears it.

Note the console serves over plain HTTP, so the session cookie isn't encrypted in
transit — keep it on loopback unless you've put it behind TLS yourself (`--allow-remote`
warns about exactly this).

The sidebar has these tabs:

### Projects
Create a project, then from its page either:
- type a **repository path** (server-side, must be readable by the `kodand
  ui` process), or
- **upload** a folder (`webkitdirectory` picker) or a single `.zip`/`.tar.gz`/`.tgz`.

Give the scan an optional **label**, optionally include **global custom
templates**, and click **Run scan**. Each scan in the list links to its
**Report** (opens the dark, frosted-glass HTML report), its raw **JSON**, and
a **Files** browser (view exactly what was scanned; **Delete Artifacts** wipes
the raw source while keeping findings/report history). A project can be
**shared with MCP agents** via the toggle in its header.

### Live Scans
Shows scans currently running — from the web console *or* from an MCP client
(e.g. a Claude Code terminal). Click one to open a pipeline view:

```
Ingest → Inventory → Template Matching → Accuracy Pipeline → Suppression → Report Generation → Complete
```

Each stage is a clickable block; **Template Matching** shows the live count
(files scanned / total / remaining) and the file currently being scanned. A
badge shows which AI verification path applies to that scan: **"MCP client
agent (Claude Code)"** for MCP-triggered scans, or **"Manual (choose per
finding)"** for scans run from the web console — this is informational only,
scanning itself never calls an AI provider.

### Custom templates
Add organization-specific detection rules (global, apply to every project).
Needs an `id`, at least one literal **match** or **regex** indicator,
severity/confidence, category, capabilities, and a recommendation. See
[§7](#7-custom-templates) for the full field reference.

### Benchmark
Runs the scanner against a labeled corpus and reports precision/recall/F1 per
category (same as `kodand bench`). Leave the corpus path blank to use the
packaged one.

### AI assistant (settings)
Configure the provider used by the **AI Review** button on findings:
ChatGPT (OpenAI), Claude (Anthropic), Gemini (Google), or a **Custom** OpenAI-
compatible endpoint (this is how you'd point Kodand at OpenRouter, a local
vLLM/Ollama server, etc.). Includes a **Test connection** check. API keys are
stored locally in the workspace and only ever sent to the provider you
configure — see [§10](#10-workspace--data-storage).

This is also where **MCP Server** setup lives:
- Check the **data-sharing acknowledgment** box (required before any project
  can be MCP-shared).
- See live **MCP status** (active/idle, which project/tool was last touched).
- Copy the **`.mcp.json` snippet** to paste into another MCP client, or click
  **Register** next to a detected client (currently: Claude Code) to run
  `claude mcp add` for you automatically.

### About
Version, workspace path, and the full AST01–AST10 category legend.

## 5. Finding review workflow

Every finding in a report can be:
- Set to a **status**: Pending Review, True Positive (confirmed), False
  Positive, Remediated, or Suppressed.
- **Commented on** (and comments edited/deleted) to record human analysis.
- Sent for **AI Review** — a one-click call to whichever provider is
  configured in AI assistant settings, using the *full content* of the
  affected file(s), not just the matched excerpt; the verdict is recorded as
  a comment.
- Sent for **Agentic AI Review** — only available with the Claude provider —
  where the model can use tools to pull additional file/finding context
  itself before giving a verdict.
- Followed up with an **AI chat** — ask the AI assistant a free-form question
  about a specific finding; the exchange is recorded as comments too.

## 6. MCP server — scanning from an AI agent

This lets an AI coding agent (Claude Code, Cursor, or anything MCP-capable)
call Kodand as a tool directly from a terminal session — run scans, read
findings, verify them — without touching the web console.

### One-time setup
1. Install with MCP support: `pipx install "kodand[all]"` (or at
   least the `mcp` extra).
2. Register the server with your client. Easiest: web console → **AI
   assistant** tab → MCP Server section → click **Register** next to your
   detected client. Or manually:
   ```bash
   claude mcp add kodand -- kodand mcp
   ```
3. In the same MCP Server section, check the **data-sharing acknowledgment**
   box — this is a hard gate: no project can be shared with MCP clients
   until it's checked.
4. **Restart your agent session.** A running session can't pick up a
   newly-registered MCP server.
5. Share a project: open it in the web console and toggle **"Share with MCP
   agents"** — or just let the MCP tools auto-create/auto-share an ad-hoc
   "MCP" bucket project when you don't specify one.

### Available MCP tools

| Tool | Purpose |
|---|---|
| `create_project(name)` | Create a new project, auto-shared with MCP clients |
| `list_projects()` | List projects that have been shared with MCP clients |
| `scan(path, project?, label?, use_custom?, full_findings?)` | Run a scan on a directory or archive |
| `list_scans(project_id)` | List scans in a shared project |
| `get_finding(project_id, scan_id, finding_id)` | Full detail: root cause, attack scenario, remediation, occurrences |
| `list_scan_files(project_id, scan_id)` | List files Kodand scanned |
| `get_file_content(project_id, scan_id, path)` | Read a scanned file's full content |
| `list_templates(custom_only?)` | List detection templates |
| `verify_finding(project_id, scan_id, finding_id)` | Ask **Kodand's configured AI provider** (from AI assistant settings) to re-examine a finding using full file content |
| `add_finding_comment(project_id, scan_id, finding_id, text)` | Record **your own** (the calling agent's) verdict as a comment — no external AI provider involved |

### Typical flow (what an agent does)
```
create_project("My Review")                       # or skip and let scan() auto-share "MCP"
scan(path="/path/to/skills.zip", project="<id>",
     label="Pre-release review", full_findings=true)
# → returns findings summary + full findings list

get_finding(project, scan, finding_id)             # dig into one finding
get_file_content(project, scan, "Agent-1/SKILL.md")# read the real file
add_finding_comment(project, scan, finding_id,
                     "Confirmed: real payload, not documentation.")
```

`verify_finding` vs. `add_finding_comment` — the key distinction:
- `verify_finding` calls **Kodand's own configured AI provider** (its own API
  key, its own rate limit — e.g. OpenRouter's free tier will run out fast on
  many findings).
- `add_finding_comment` records **the calling agent's own analysis** (e.g.
  Claude Code's own reasoning in that terminal session) — no separate
  provider, no separate quota. This is the recommended path when you're
  already working inside an agent session and want it to do the verification
  itself.

While a scan runs — whether kicked off via MCP or the web UI — it's visible
live in the web console's **Live Scans** tab.

## 7. Custom templates

A minimal custom template:
```yaml
id: CUSTOM-AWS-KEY
info: {name: AWS Access Key, severity: high, confidence: high, category: CUSTOM}
detection:
  match: ["aws_access_key_id"]
  regex: ["AKIA[0-9A-Z]{16}"]
capabilities: [credential-access, secret-output]
risk: {title: AWS Access Key}
recommendation: Never embed long-lived AWS keys; use scoped roles.
```
- `match`: literal substrings (any hit counts).
- `regex`: opt-in structured patterns — validated against a ReDoS guard at
  load time (pattern shape) and runtime (length cap + time budget).
- `category`: use a built-in `AST0x`/`AST10` code, or any custom code (auto-
  registered with a title-cased display name).
- Custom template ids can't collide with a built-in template id.

## 8. Suppressions (`.kodand.yml`)

Drop at the repository root being scanned:
```yaml
suppressions:
  - rule: AST08-SCANNER-BYPASS
    reason: documented anti-pattern, reviewed
    expires: 2027-01-01
  - category: AST05
    path: "docs/**"
    reason: external links expected in docs
```
Selectors: `rule` (template id), `category`, `path` (glob), or `finding`
(finding id) — combine as needed. `expires` is optional; an expired
suppression automatically reactivates the finding.

## 9. Report formats

| Format | Command / where |
|---|---|
| HTML (dark, frosted-glass) | `kodand analyze --html ...`, or the **Report** link on any web-console scan |
| JSON (`analysis.json`) | `kodand analyze` (default), or the **JSON** link on any scan |
| SARIF | `kodand analyze --sarif ...` — for GitHub code scanning / other SARIF consumers |
| DOCX | `kodand analyze --docx ...` |
| PDF | `kodand analyze --pdf ...` |

## 10. Workspace & data storage

Everything lives under `~/.kodand/` by default (override with the
`KODAND_HOME` environment variable): projects, scans, raw scanned source,
reports, review overrides (statuses/comments), custom templates, and AI/MCP
settings (including API keys — stored locally, never sent anywhere except the
provider you explicitly configure).

The workspace directory is created owner-only (`700`), and Kodand tightens it
back to that if it finds it readable by others: it holds the password hash,
session tokens, AI provider keys and copies of scanned code.

**How Kodand protects itself while scanning untrusted code**
- Scanned folders are copied into the workspace **without following symlinks**,
  so a planted link to, say, `~/.ssh/id_rsa` is never copied or shown.
- Archives are extracted with path-escape guards and refused above 1 GB unpacked
  or 100,000 entries.
- Project and scan IDs are validated on every request, so neither the console nor
  an MCP client can reach a project that wasn't shared with it.
- The console only answers to `127.0.0.1`, `localhost` and `::1` (a guard against
  DNS rebinding from malicious websites), refuses cross-site form submissions,
  and sends a Content-Security-Policy that blocks loading or sending data to
  other origins. With `--allow-remote`, set `KODAND_ALLOWED_HOSTS` to the
  host names you'll use (comma-separated), or it accepts any host name.

**MCP data-sharing note:** once a project is MCP-shared, any connected MCP
client can read its scan findings and file content. That data goes to
whichever AI backend the connected agent itself uses — not the provider
configured in AI assistant settings, and outside Kodand's control once it
leaves the process. This is why the sharing toggle requires the explicit
data-sharing acknowledgment first.

## 11. Troubleshooting

- **`kodand ui` says Web UI dependencies missing** → reinstall with the `ui`
  extra: `pipx install --force 'kodand[all]'`.
- **`kodand mcp` says MCP dependencies missing** → same, with the `mcp`
  extra.
- **My agent doesn't see the kodand MCP tools** → confirm registration
  (`claude mcp add kodand -- kodand mcp` or via the web console), then
  **restart the agent session** — a running session can't pick up a newly
  registered MCP server.
- **`verify_finding` / AI Review fails with a rate-limit error** (e.g.
  OpenRouter "free-models-per-day" 429) → that's Kodand's *own configured
  provider* running out of quota, unrelated to the calling agent's own usage.
  Either wait for the provider's daily reset, add credits/switch providers in
  AI assistant settings, or use `add_finding_comment` via MCP instead (no
  external provider involved).
- **A project/tool call fails with "not shared with MCP clients"** → open the
  project in the web console and toggle "Share with MCP agents" (requires
  the data-sharing acknowledgment to be checked first).
- **The console says "Host not allowed" (HTTP 421)** → you opened it under a
  name other than `127.0.0.1`/`localhost`. Use one of those, or add the name to
  `KODAND_ALLOWED_HOSTS` before starting `kodand ui`.
- **Scan says 0 skill files found** → you likely pointed it at a parent
  directory instead of the folder/archive containing `SKILL.md` (or the
  equivalent for another platform) — check the folder structure, or pick the
  `.zip` picker instead of the folder picker if you uploaded a single
  archive.
