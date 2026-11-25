# Changelog

All notable changes to this project are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- **MCP server code is scanned again.** 2.0.0 stopped scanning an MCP server's own
  code when it sits next to the `mcp.json` that configures it, which hid
  tool-description prompt injection and exfiltration code. An MCP config now owns its
  folder when that folder holds MCP server code (MCP SDKs, `tools/list`, `tools/call`,
  `inputSchema`). An application's root `.mcp.json` still scans only itself.
- **Instruction override:** now also catches skills that declare safety rules
  "suspended", "ignore ethical/security/content guidelines", "IMPORTANT/ADMIN
  OVERRIDE:" and "reveal your system prompt". Found missed on damn-vulnerable-ai-agent.
- A code comment like "silently captures exfiltrated data" is no longer reported as
  a concealed instruction. The rule now needs an instruction ("silently upload …").
- An inline secret in an MCP config is reported once, as `MCP01`, instead of also as
  `AST03-INLINE-SECRET`.
- `docs/BENCHMARK.md` re-measured: on DVAA commit `30011c1`, Kodand 1.0.0 reports 10
  true positives with 2 misses, and 2.0 reports 11 true positives with 1 known miss.

## [2.0.0] - 2026-11-25

### Added
- **Kodand Agent scope crawl** (web console):
  - with "Expand scope with Kodand Agent" on and `kodand agent` running, the agent
    crawls every text file outside the static scope, one fresh Claude session per
    batch of about 25, and adds the files that are agent content;
  - it can only add files, and only validated ones from its own batch;
  - the crawl runs in the background with live progress, durable log lines,
    Skip crawl and per-file caching;
  - if the agent is offline or the project isn't shared, the scan uses the static scope;
  - the report gains a Kodand Agent Scope section.
- **Learned scope**:
  - each addition raises a location or extension suggestion;
  - approved suggestions (Settings → Learned scope) extend the static registry
    for the console, `kodand analyze` (`--no-learned-scope` to opt out) and MCP
    `scan`, so files like it are found without the agent;
  - catch-all and application-folder patterns are refused.
- HTML report sections collapse and expand (Collapse all / Expand all); the
  closed ones are remembered per browser.
- Discovery of current agent artifacts across platforms: CLAUDE.md, Claude Code
  rules/commands/subagents/plugins, `.agents/skills`, Codex `config.toml`/hooks, Gemini
  `settings.json`/commands, Copilot prompts/agents/hooks/`.vscode/mcp.json`, Cursor hooks
  and plain-file rules, Windsurf/Devin, Cline, Roo, Continue, Junie, Kiro/Amazon Q, Zed and
  OpenCode (`src/kodand/entrypoints.py`). Paths match at any depth.
- Structural markdown rules: fenced code blocks get AST analysis; untrusted URL fetches
  into agent context (AST05-UNTRUSTED-FETCH); unscoped `allowed-tools` shell grants;
  frontmatter hooks; `` !`cmd` `` load-time commands; malformed frontmatter; symlinks
  escaping the repository.
- New templates: approval bypass (`--yolo`, `--dangerously-skip-permissions`,
  `approval_policy=never`, "without asking"), outward writes (`gh release create`,
  `npm publish`, `terraform apply`…), credential stores (`.env`, `~/.netrc`, browser
  profiles, keychain), inline secrets, data exfiltration (DNS, netcat, request
  catchers, `curl -d @~/.aws/…`) and persistence (cron, shell rc files, launch agents).
- Coverage warnings in the HTML report, CLI, MCP result and console: unrecognised agent
  directories, oversized files, regex time-outs, clipped lines, ignored repo suppressions.
- `kodand analyze --trust-repo-suppressions` and a per-project console toggle.
- `requirements.txt` pins the exact, tested version of every runtime dependency, including
  transitive ones, so the versions in use are tracked and visible to security scanners.
  `install.sh` installs exactly these; `pyproject.toml` keeps the supported ranges, and the
  README lists both. Pins refreshed to the newest versions within the ranges (e.g. fastapi
  0.152.0, pydantic 2.14.1, uvicorn 0.54.0), with no known vulnerabilities (`pip-audit`).

### Changed
- Scan scope is agent content only. Instruction/rules/command files and MCP configs
  no longer pull in their folder as "supporting files" — a repo-root `AGENTS.md` used to
  turn the whole application into a SAST scan (OWASP Juice Shop: 19 of 21 findings were
  application code; now 0). Skill folders, hook dirs and plugin manifest dirs are still
  scanned whole. Outside them, only referenced docs, shell scripts and files the text
  tells the agent to run are followed, not bare mentions of application source.
- A scanned repository's `.kodand.yml` is ignored unless explicitly trusted.
- Suppressions match individual occurrences; `path:` scopes no longer hide a rule's
  evidence in other files, and suppressing one rule no longer hides a rule merged with it.
- Context keywords ("never", "e.g.", "see documentation"…) only demote the payload they
  govern; frontmatter is only a line-1 block, and its description/hooks/allowed-tools are
  live; HTML comments are scanned as hidden, actionable text.
- More file types are scanned (shell variants, mjs/tsx, Dockerfile, `.env*`, shebang
  scripts); binary files are skipped and UTF-16 files decoded.
- AST10 cross-platform path/file mentions are informational.
- The scan cache is keyed by content and analyser, and invalidated by any template or
  engine change; `kodand bench` never uses it.
- `kodand templates scan` uses the same pipeline as `kodand analyze`.

### Fixed
- Folder uploads and GitHub zips no longer hide root-anchored files such as
  `.github/copilot-instructions.md` or `.claude/settings.json`.
- Skills in folders named `build` or `dist` are no longer skipped; supporting-file
  listings no longer pull in `node_modules`, `.git` or virtualenvs.
- Payloads padded past 2,000 characters on a line are still matched.
- False positives: `curl -s` to localhost (was critical), `rm -rf` of build output,
  "delete from the list", bare `gcloud` mentions, Jest "auto-update snapshots".

## [1.0.0] - 2026-10-15

Initial release.

### Highlights
- Static security scanning for AI agent skills (`SKILL.md`, `GEMINI.md`,
  `AGENTS.md`, Copilot, Cursor and Windsurf rules), MCP server configs, Claude
  Code hooks and the scripts they reference: 82 rules across three taxonomies
  (Agentic Skills Top 10, OWASP MCP Top 10, Hooks Top 10).
- Three ways to run it: a CLI (JSON, HTML, SARIF, DOCX and PDF reports), a
  password-protected local web console with a review workflow, and an MCP server
  so AI coding agents can scan and verify findings themselves.
- Accuracy you can check: 1.00 precision and recall on the labelled corpus, and
  11 of 11 findings confirmed by hand on OpenA2A's damn-vulnerable-ai-agent
  (see `docs/BENCHMARK.md`).
- Install from the repository with `./install.sh` (Kodand isn't published on PyPI).
  Every install includes everything — CLI, web console, MCP server and JS/TS code
  analysis are all regular dependencies, so there are no extras to pick
  (`[ui]`, `[mcp]`, `[code]` and `[all]` still resolve, as no-ops).
- Free, open-source (MIT) software you run locally, not a hosted service: Claude
  Agent and Ask AI-CLI use the Claude Code CLI on your machine with your own
  Claude account.

### Detection
- 64 YAML templates with literal, regex and decoded (base64/hex/URL) matching,
  plus 18 structural rules: Python AST, JS/TS AST (tree-sitter) and a
  position-tracking JSON parser for MCP and hook configs.
- Catches prompt injection and instruction overrides, instructions hidden from
  the user (including payloads stored by an MCP server and returned by its tools),
  hidden Unicode (zero-width, bidi and tag characters, raw or as HTML entities),
  credential and token access, passwords in connection strings, dynamic code
  execution, shell-injection shapes, env-read-then-send exfiltration, typosquatted
  and unpinned MCP packages, insecure MCP transport, wildcard grants and risky hooks.
- Context-aware scoring: frontmatter, fenced code, examples and mitigation prose
  count less, while proximity and cross-file signals raise confidence. Findings
  list one occurrence per line.
- Secrets are redacted in every report, including passwords inside URLs.
- Suppressions via `.kodand.yml` (by rule, category, path or finding, with expiry).
- Custom templates with ReDoS-guarded regex.
- `kodand bench`: precision, recall and F1 per category against a labelled corpus.

### Scanning
- Directories or `.zip`/`.tar.gz`/`.tgz` archives, extracted with path-escape
  guards and size limits.
- Parallel scanning (`--workers`) and a content-hash scan cache.

### Web console (`kodand ui`)
- Projects, scans, folder or archive upload, and server-side path scans.
- Reports split per taxonomy, with coverage matrices, an **Open File** jump to the
  exact line, and a Files viewer that highlights flagged lines.
- Review workflow: Pending Review / True Positive / False Positive / Remediated /
  Suppressed, threaded comments, one-click AI review (OpenAI, Claude, Gemini or any
  OpenAI-compatible endpoint) and follow-up chat. AI review sends the affected
  files up front and can open the scan's other files through the provider's
  tool calling when it needs more context.
- Live Scans dashboard with per-stage progress and a durable activity log.
- Password sign-in with a forced change from the first-run default, and
  `kodand password reset` to recover access from the terminal.
- Live MCP connection status: Active, Connected with idle time, Disconnected with
  last-seen time, or Not connected.

### MCP server (`kodand mcp`)
- Tools: `scan`, `create_project`, `list_projects`, `list_scans`,
  `list_templates`, `get_finding`, `list_scan_files`, `get_file_content`,
  `verify_finding`, `add_finding_comment` and `status`.
- A project must be explicitly shared with MCP clients before any tool can see it.
- A `kodand-mcp-scan` Claude Code skill that drives a scan end to end.

### Installer
- `install.sh` checks its dependencies first (Python 3.11.4+, pipx/uv/venv, tar,
  git; Claude Code and systemd are reported as optional), offers to install the
  missing ones through apt, dnf, yum, pacman, zypper or brew after a y/N prompt,
  re-checks, and only then installs. It always installs everything
  (`ui` + `mcp` + `code`), verifies the result, and prints next steps.
  `--check` and `--yes` are supported.

### Ask AI-CLI
- A finding's **Ask AI-CLI** button answers a question (or, with the box empty,
  reviews the finding) through your own `claude -p` and Claude login, with no
  API key and no `kodand agent` worker. It runs with no tools and no MCP
  servers; the prompt, with the affected files and earlier comments, goes in on
  stdin. Loopback-only like Claude Agent, two runs at a time, 2-minute limit.
- The AI buttons now grey out, with the reason as a tooltip, when they can't
  work (no API key; `claude` not on PATH): `GET /api/ai/availability`.

### Claude Agent (`kodand agent`)
- Verify findings from the web console with your own Claude Code and Claude
  login, no API key: `kodand agent` is a worker you leave running in a
  terminal. It picks up queued findings one at a time and runs Claude Code
  headless on each; Claude records its verdict through the new `complete_job`
  MCP tool. Nothing runs while no finding is waiting.
- "Verify with Claude Agent" on each finding in a report and on each scan, and an
  optional "Verify findings with Claude Agent" step when starting a scan (off by
  default; optional minimum severity and max findings, no limit by default).
- Verdicts are added as comments; review statuses are left for you to set.
- Each run has every built-in Claude Code tool switched off and only Kodand's
  MCP server, which in that mode withholds `scan`, `create_project`,
  `verify_finding` and `add_finding_comment`. Every finding gets a fresh run.
  Jobs only for projects shared with MCP agents, queued only from the machine
  running the console.
- Settings → Claude Agent shows whether the worker is running, with recent jobs
  you can cancel or retry.

### Review workflow, storage and Claude Agent operations
- Verdict badges with one-click "Mark as …", a verdict filter in reports, and
  re-verify choices (all / without a verdict / current False positives).
- Suppress a False-positive verdict into a per-project suppression (finding,
  rule in file, rule under folder, rule anywhere), applied to later scans and
  marked in the current one at once.
- kodand agent --parallel N and --install-service; Claude usage per job and in
  total; a Claude Agent queue in Live Scans with remove one / selected / all, and
  runs stopped when their finding is removed; queued work cancelled when its
  project or scan is deleted or unshared.
- Job files: per-scan sizes and file lists, a Keep tag, manual delete, an
  optional retention period applied hourly, and a storage graph.

### Security
- Project and scan IDs are validated on every request, so neither the console nor
  an MCP client can reach outside a shared project.
- Scanned folders are copied without following symlinks.
- The console checks the `Host` header (DNS-rebinding guard), refuses
  cross-origin state-changing requests, sends a Content-Security-Policy and
  anti-framing headers, escapes all scanned and user-supplied content, and locks
  sign-in after 5 wrong passwords in 5 minutes.
- The workspace (`~/.kodand`) is owner-only.
- `SECURITY.md` describes private vulnerability reporting.

### Docs and tooling
- README, `USER_GUIDE.md`, `docs/BENCHMARK.md`, `CONTRIBUTING.md`, a code of
  conduct and issue templates.
- CI on Python 3.11–3.14 (Linux and macOS), a wheel smoke test, and a tag-triggered
  release workflow that tests, builds and attaches the wheel and sdist to a GitHub
  release (no PyPI publishing).
