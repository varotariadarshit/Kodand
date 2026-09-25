# Changelog

All notable changes to this project are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - Unreleased

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
- Install with `pipx install "kodand[all]"`.

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
  OpenAI-compatible endpoint) and follow-up chat.
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
  release workflow using PyPI trusted publishing.
