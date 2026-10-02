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
kodand agent [--once] [--timeout 600] [--parallel N]   # verify findings queued in the web console with your Claude Code
kodand agent --install-service [--parallel N]           # …or keep it running as a systemd user service (--uninstall-service)
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

Below the scans, **Claude Agent queue** lists every finding waiting for (or
being verified by) `kodand agent`, oldest first, with its project and scan. Tick
rows and **Remove selected**, remove one with ✕, or **Clear queue**. A finding
being verified when you remove it has its Claude run stopped within seconds.

### Custom templates
Add organization-specific detection rules (global, apply to every project).
Needs an `id`, at least one literal **match** or **regex** indicator,
severity/confidence, category, capabilities, and a recommendation. See
[§7](#7-custom-templates) for the full field reference.

### Benchmark
Runs the scanner against a labeled corpus and reports precision/recall/F1 per
category (same as `kodand bench`). Leave the corpus path blank to use the
packaged one.

### Settings
**AI assistant settings** configure the provider used by the **AI Review** and **Ask AI** buttons on findings:
ChatGPT (OpenAI), Claude (Anthropic), Gemini (Google), or a **Custom** OpenAI-
compatible endpoint (this is how you'd point Kodand at OpenRouter, a local
vLLM/Ollama server, etc.). Includes a **Test connection** check. API keys are
stored locally in the workspace and only ever sent to the provider you
configure — see [§10](#10-workspace--data-storage). Below the intro, a line shows
whether Claude Code was found on this machine, which is all **Ask AI-CLI** needs (no API key).

This is also where **MCP Server** setup lives:
- Check the **data-sharing acknowledgment** box (required before any project
  can be MCP-shared).
- See live **MCP status** (active/idle, which project/tool was last touched).
- Copy the **`.mcp.json` snippet** to paste into another MCP client, or click
  **Register** next to a detected client (currently: Claude Code) to run
  `claude mcp add` for you automatically.

It also holds **Claude Agent** (worker status and Claude usage) and **Job files**
(retention, Keep tags, per-scan sizes and the storage graph) — see
[Claude Agent](#claude-agent--verifying-from-the-web-console) and
[§10](#10-workspace--data-storage).

### About
Version, workspace path, and the full AST01–AST10 category legend.

## 5. Finding review workflow

Every finding in a report can be:
- Set to a **status**: Pending Review, True Positive (confirmed), False
  Positive, Remediated, or Suppressed.
- **Commented on** (and comments edited/deleted) to record human analysis.
- Sent for **AI Review** — a one-click call to whichever provider is
  configured in Settings → AI assistant settings. It sends the finding with the *full
  content* of the affected file(s), not just the matched excerpt, so most
  findings are answered in a single request. When that isn't enough (say the
  risk depends on another file in the skill), the model can open the scan's
  other files itself, using its provider's tool calling, for up to 4 rounds.
  This works with OpenAI, Claude and Gemini; a custom endpoint without tool
  support gets a single request. The verdict is recorded as a comment.
- Followed up with an **AI chat** — ask the AI assistant a free-form question
  about a specific finding, with the same access to the scanned files; the
  exchange is recorded as comments too.
- Asked through **Ask AI-CLI** — the same question-and-answer as the AI chat, but
  answered by your own Claude Code (`claude -p`) and its login instead of an
  API key. Type a question in the box and press **Ask AI-CLI**, or leave the box
  empty to have it review the finding. It runs once and right away (no
  `kodand agent` worker needed), sees the full affected file(s) and the earlier
  comments, but has no tools of its own, so it can't open other files. Answers
  are recorded as comments, with the same verdict badge. The AI buttons are
  greyed out with a tooltip when they can't work: **AI Review / Ask AI** until
  a provider has an API key, **Ask AI-CLI** until `claude` is on the PATH. Like
  Claude Agent it only accepts requests from the machine running the console
  (unless `KODAND_AGENT_ALLOW_REMOTE=1`), at most two answers run at once, and
  each has a 2-minute limit. The finding's files are sent to Anthropic under
  your Claude login, as with Claude Agent.
- Sent to **Claude Agent** — your own Claude Code session verifies it with
  your own Claude login, no API key; see
  [Claude Agent](#claude-agent--verifying-from-the-web-console).

Comments that state a verdict ("Verdict: True positive", "False positive …",
"Needs more context …") get a coloured badge, and a **Mark as …** button that
sets the finding's status from it in one click — never automatically. The report
has a verdict filter (each finding's latest verdict) next to the severity filter.
A False-positive verdict also offers **Suppress…**, see
[Suppressions](#8-suppressions-kodandyml).

## 6. MCP server — scanning from an AI agent

This lets an AI coding agent (Claude Code, Cursor, or anything MCP-capable)
call Kodand as a tool directly from a terminal session — run scans, read
findings, verify them — without touching the web console.

### One-time setup
1. Install with MCP support: `pipx install "kodand[all]"` (or at
   least the `mcp` extra).
2. Register the server with your client. Easiest: web console → **Settings**
   → MCP Server section → click **Register** next to your
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

### Claude Agent — verifying from the web console

The MCP tools above are driven from the agent's side: you ask Claude Code to do
something and it calls Kodand. Claude Agent works the other way round. You click
in the web console and your own Claude Code does the verification, using your
own Claude login, with no API key.

MCP doesn't let a server call its client, so the console can't reach Claude Code
directly. Instead it queues jobs, and `kodand agent`, a small worker you leave
running in a terminal, picks them up one at a time. For each finding it runs
Claude Code headless (`claude -p`) with only Kodand's MCP tools. Claude reads the
finding and the scanned files, records its verdict with `complete_job`, and
exits. While no finding is waiting, nothing runs and nothing is spent.

**Set up once**
1. Do steps 1, 3 and 5 of the MCP setup above: install with the `mcp` extra,
   acknowledge data sharing, and share the project with MCP agents.
2. Sign in to Claude Code (`claude`) as usual. Nothing else needs enabling.

**Run it**
```bash
kodand agent
```
Leave that terminal open. Each finding shows up there as it's verified
(`▶ critical: Remote Content Execution … ✓ True positive (28s)`), and Settings →
**Claude Agent** in the console shows the worker as running. Stop it with
Ctrl+C; a finding in progress goes back to the queue.

- `kodand agent --once` runs whatever is queued right now, then exits.
- `kodand agent --timeout 900` gives each finding up to 15 minutes (the default is 10).

**Send it findings**
- **One finding:** open a report and click **Verify with Claude Agent**. The
  badge follows the job, and the verdict appears as a comment.
- **A whole scan:** click **Verify with Claude Agent** on the scan in the
  project's scan list. It tells you how many findings it will send before you
  confirm.
- **Automatically after a scan:** when starting a scan, turn on **Verify
  findings with Claude Agent after the scan**. Every finding is sent unless you
  set a minimum severity or a maximum number of findings. The scan itself never
  waits for Claude; jobs run whenever the worker is up.

Findings you send by hand go ahead of automatic batches. Each verdict is a
comment starting with `Verdict: True positive`, `False positive` or `Needs
review`. Claude Agent never changes a finding's review status; setting that is
up to you. Each verification uses your Claude plan's usage.

**What Claude can do in these runs.** Scanned skills are untrusted input, so
each run has every built-in Claude Code tool switched off (`--tools ""`), loads
only Kodand's MCP server (`--strict-mcp-config`), and denies anything that would
need a permission prompt. In that mode Kodand's server also withholds `scan`,
`create_project`, `verify_finding` and `add_finding_comment`. Claude can read
shared projects and record the verdict for its own job, nothing else, so a
prompt injection in a scanned file can at most produce a wrong verdict. Every
finding gets a fresh run, so one malicious skill can't influence the verdict on
the next. Runs start in an empty folder (`~/.kodand/agent/workdir`), so no
project's `CLAUDE.md` is loaded, and they aren't saved to your Claude Code
history. Jobs can only be queued from the machine running the console, even with
`kodand ui --allow-remote`, unless you start the console with
`KODAND_AGENT_ALLOW_REMOTE=1`.

**When a job doesn't finish.** If Claude exits without a verdict, fails (for
example you're signed out of Claude Code), or runs past the time limit, the job
is marked failed with the reason. If the worker itself is killed mid-run, the
job goes back to the queue, and after 3 such attempts it's marked failed.
Deleting a project or scan, or turning off its MCP sharing, cancels its queued
findings.

**Faster, and in the background.** `kodand agent --parallel 3` verifies up to 3
findings at once (each uses your plan's usage). `kodand agent --install-service
--parallel 2` runs the worker as a systemd user service on Linux, so no terminal
needs to stay open (`journalctl --user -u kodand-agent -f` for its log,
`--uninstall-service` to remove it; `install.sh` restarts it on upgrade).

**Usage.** Settings → Claude Agent shows the tokens and API-equivalent cost of
Claude Agent runs (last 24 h and all time). On a Claude plan that counts toward
your usage limits; it isn't billed. Finished job records are pruned after 30 days.

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

**From the web console.** On a False-positive verdict in a report, **Suppress…**
saves a suppression to the *project* — this finding only, the rule in this file,
the rule under this folder, or the rule anywhere in the project — with a reason
and optional expiry. It's kept in Kodand's workspace (never written into your
source), applies to every later scan of the project alongside the repo's own
`.kodand.yml`, and marks the matching findings of the current scan Suppressed at
once. Setting a finding's status to **Suppressed** in a report does the same for
that one finding (setting it back lifts it). The project page lists them all, with
delete and **Copy as .kodand.yml**; deleting one puts the findings it hid back to
Pending Review, and later scans report them again.

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

**Job files** are the copies of scanned source each scan keeps so findings can
be reviewed in the files. They take most of the space. Settings → **Job files**
lists them per scan (size, file count; click a row for its files), with a
**Keep** tag and **Delete**, and a retention period: job files of scans older than
N days are deleted at the hourly cleanup (or **Clean up now**) — never findings,
reports, comments or verdicts, never scans tagged Keep, and not while Claude
Agent still has jobs queued for the scan. Retention is off until you set it. The
same panel graphs total job-file storage over time.

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
