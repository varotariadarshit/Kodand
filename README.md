<p align="center">
  <img src="https://raw.githubusercontent.com/varotariadarshit/Kodand/master/docs/assets/kodand-icon.png" alt="Kodand logo" width="140">
</p>

# Kodand — Agentic AI Skills Threat and Risk Assessment

<p align="center">
  <a href="https://github.com/varotariadarshit/Kodand/actions/workflows/ci.yml"><img src="https://github.com/varotariadarshit/Kodand/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/kodand/"><img src="https://img.shields.io/pypi/v/kodand" alt="PyPI"></a>
  <img src="https://img.shields.io/pypi/pyversions/kodand" alt="Python versions">
  <a href="https://github.com/varotariadarshit/Kodand/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

Kodand is a static security scanner for AI agent skills, **MCP server configs**
and **Claude Code hooks**. It finds credential theft, prompt injection hidden in
skills and tool descriptions, typosquatted MCP packages, unsafe code execution,
scanner evasion and more, before any of it runs inside an agent.

```bash
pipx install "kodand[all]"
kodand analyze ./my-skills --html report.html  # scan a folder or .zip/.tar.gz
kodand ui                                      # or review findings in the web console
```

<p align="center">
  <img src="https://raw.githubusercontent.com/varotariadarshit/Kodand/master/docs/assets/demo.gif" alt="Kodand scanning a vulnerable agent lab: CLI output, the web console, findings, the Files viewer and live MCP status" width="860">
</p>

**Accuracy:** on OpenA2A's deliberately vulnerable
[damn-vulnerable-ai-agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent),
Kodand reports 11 findings, and a hand review of each one found 11 true positives and
0 false positives. Its labelled benchmark scores 1.00 precision and recall
([method and details](https://github.com/varotariadarshit/Kodand/blob/master/docs/BENCHMARK.md)).

It reads Claude's `SKILL.md`, Gemini CLI's `GEMINI.md`, Copilot instructions,
OpenAI/Codex `AGENTS.md`, Cursor and Windsurf rules, MCP configs, hook configs
and the Python/JS/TS scripts they reference. Detection spans **three
independent taxonomies**, and a rule belongs to exactly one:

- **AST Top 10**: Kodand's own Agentic Skills Top 10 (skill/instruction-file risks)
- **MCP Top 10**: the published [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
- **Hooks Top 10**: Kodand's own taxonomy for Claude Code hook-config risks

It ships three ways: a **CLI** for scripting and CI, a local **web console** for
reviewing findings, and an **MCP server** so an AI coding agent (Claude Code,
Cursor, etc.) can scan and verify findings from a terminal session. The
[user guide](https://github.com/varotariadarshit/Kodand/blob/master/USER_GUIDE.md) walks through all three.

All automated findings are candidates requiring human validation; Kodand flags
patterns, it doesn't prove exploitability.

## Highlights
- **64 built-in YAML detection templates** across all three taxonomies
  (48 AST + 8 MCP + 8 Hooks — see below), with literal + regex + decoded
  (base64/hex/URL) matching and a composite 0–100 confidence score per finding,
  plus 18 structural rules (see the next two bullets) — 82 detection rules total.
- **Hidden-text and typosquat detection** — zero-width, bidi-control and
  Unicode tag characters (raw or written as HTML entities), and MCP server
  packages one or two characters away from an official package name.
- **AST-level code analysis** — real parsing (not regex) of Python (stdlib
  `ast`) and JS/TS (tree-sitter, optional `code` extra) scripts referenced by
  a skill: dynamic eval/exec, shell-injection shapes, hardcoded credentials,
  and a same-function env-read → network-send exfiltration heuristic.
- **MCP server config & hook detection**, YAML *and* structural — `.mcp.json` /
  `claude_desktop_config.json` / `.claude/settings.json` are first-class scan
  targets: unpinned/shell launchers, wildcard permission grants, hardcoded
  secrets, tool-description injection, insecure transport, disabled audit
  logging, and more, mapped directly to OWASP MCP Top 10 categories. Five of
  these (HOOK01, HOOK05, two MCP04 rules, MCP09) run on a real position-tracking JSON
  parser rather than line regex, so they can correlate two keys of the same
  object — e.g. a wildcard hook `matcher` escalates severity only when its
  *own* `command` looks risky, and "Shadow MCP Servers" (MCP09) actually
  compares every configured server's launcher and name against every other
  one, instead of just checking a single string.
- **Context-aware scoring** — Context Engine v2 understands frontmatter, fenced
  code, and mitigation/detection/reference/example prose so non-actionable
  lines don't inflate results; proximity and cross-file relationship signals
  escalate genuinely suspicious co-occurrences instead.
- **Parallel scanning** — match files across multiple worker processes
  (`--workers N`) for faster scans of large repositories; sequential by
  default, deterministic output at any worker count.
- **Finding review workflow** — mark findings Pending Review / True Positive /
  False Positive / Remediated / Suppressed, with threaded comments.
- **Open File, highlighted** — every finding and occurrence in a report links
  straight to the exact file and line in the built-in Files viewer, with the
  matched line highlighted and scrolled into view.
- **AI-assisted review** — one-click AI Review (ChatGPT, Claude, Gemini, or any
  custom OpenAI-compatible endpoint) using the full affected file rather than
  just the matched excerpt, an agentic (tool-using) verification mode, and
  follow-up chat on any finding.
- **MCP server** (`kodand mcp`) — scan, list findings, read scanned files, and
  verify findings directly from an MCP-capable agent's terminal session,
  without routing through a separately configured AI provider.
- **Live Scans dashboard** — real-time per-file scan progress and
  AI-verification status, kept as durable history you can review (or delete)
  later instead of disappearing once a scan finishes.
- **Suppression framework** (`.kodand.yml`) with rule/category/path/finding
  selectors and optional expiry.
- **Ground-truth benchmark** (`kodand bench`) reporting precision/recall/F1 per
  category against a labeled corpus, plus a hand-reviewed real-world scan —
  see [Accuracy](#accuracy).

Version **1.0.0**, rule pack `KODAND-1.0`.

## Detection coverage

Every category below is always listed in the web console's About tab and a
report's coverage matrices, even ones with 0 rules today — this is the full
reference, not just "whatever happened to fire." Rule counts include both YAML
templates and structural (AST/JSON) rules.

### AST Top 10 — Agentic Skills (skill/instruction-file risks)

| Code | Category | Rules |
|---|---|---|
| AST01 | Malicious Skills | 10 |
| AST02 | Supply Chain Compromise | 5 |
| AST03 | Over-Privileged Skills | 9 |
| AST04 | Insecure Metadata and Parsing | 11 |
| AST05 | Untrusted External Instructions | 4 |
| AST06 | Weak Isolation | 5 |
| AST07 | Update and Version Drift | 4 |
| AST08 | Insufficient Scanning | 6 |
| AST09 | Governance and Approval Gaps | 4 |
| AST10 | Cross-Platform Reuse | 3 |

### MCP Top 10 — [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)

| Code | Category | Rules |
|---|---|---|
| MCP01 | Token Mismanagement and Secret Exposure | 1 |
| MCP02 | Privilege Escalation via Scope Creep | 1 |
| MCP03 | Tool Poisoning | 1 |
| MCP04 | Software Supply Chain Attacks and Dependency Tampering | 2 |
| MCP05 | Command Injection and Execution | 1 |
| MCP06 | Intent Flow Subversion | 1 |
| MCP07 | Insufficient Authentication and Authorization | 1 |
| MCP08 | Lack of Audit and Telemetry | 1 |
| MCP09 | Shadow MCP Servers | 1 |
| MCP10 | Context Injection and Over-Sharing | 1 |

MCP04 and MCP09 run on the structural JSON analyzer (`kodand/codeanalysis/json_struct.py`)
rather than a YAML template — MCP04 checks the actual `args` array for an
explicit version pin instead of flagging every `npx`/`uvx`/etc. launch, and
compares each launched package name against official MCP packages to catch
typosquats, and
MCP09 compares every configured server's launcher and name against every
other configured server for real duplicate/shadow detection.

### Hooks Top 10 — Claude Code hook-config risks (Kodand original)

| Code | Category | Rules |
|---|---|---|
| HOOK01 | Unscoped Wildcard Trigger | 1 |
| HOOK02 | Arbitrary Shell Execution in Hook Command | 1 |
| HOOK03 | Silent Network Exfiltration via Hook | 1 |
| HOOK04 | Approval and Permission Bypass via Hook | 1 |
| HOOK05 | Undeclared or Hidden Hook Definition | 1 |
| HOOK06 | Hook Persistence and Config Tampering | 1 |
| HOOK07 | Privilege Escalation via Hook Context | 1 |
| HOOK08 | Sensitive File or Credential Access via Hook | 1 |
| HOOK09 | Resource Abuse and Denial of Service via Hook | 1 |
| HOOK10 | Unverified or Remote Hook Script Source | 1 |

HOOK01 and HOOK05 also run on the structural JSON analyzer — HOOK01 escalates
severity when a wildcard/empty `matcher` is paired with a risky `command` in
the *same* hook entry, and HOOK05 only ever looks at the direct children of
the `hooks` object, so it can't be confused with the required nested
`"hooks": [...]` array key the way a line-based regex could.

## Supported agentic platforms

Content is content, whichever file format carries it:

| Platform | File(s) |
|---|---|
| Claude Code | `SKILL.md`, `SKILLS.md` |
| Google Gemini CLI | `GEMINI.md` |
| Microsoft Copilot | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` |
| OpenAI / Codex | `AGENTS.md` |
| Cursor | `.cursor/rules/*.mdc` |
| Windsurf | `.windsurfrules` |
| MCP servers | `.mcp.json`, `mcp.json`, `claude_desktop_config.json` |
| Claude Code hooks | `.claude/settings.json`, `.claude/settings.local.json` |

Referenced Python/JS/TS scripts get real AST-level parsing on top of the
regular text/regex pass (see Highlights above). Subagent/slash-command
definitions and OpenAPI Action schemas are not yet in scope.

## Install

Requires Python 3.11.4+ on Linux or macOS. Windows isn't supported natively;
use [WSL](https://learn.microsoft.com/windows/wsl/).

```bash
pipx install "kodand[all]"
kodand
```

Upgrade with `pipx upgrade kodand`. `uv tool install` and plain
`pip install` work the same way. To install straight from GitHub instead:

```bash
pipx install "kodand[all] @ git+https://github.com/varotariadarshit/Kodand.git"
```

| Extra | Adds |
| --- | --- |
| `ui` | The local web console (`kodand ui`) |
| `mcp` | The MCP server (`kodand mcp`) |
| `code` | JavaScript/TypeScript code analysis (tree-sitter). Python analysis needs no extra |
| `all` | All three |

From a clone, `./install.sh` does the same (it installs `all` by default, or
pass e.g. `./install.sh ui,mcp`). It uses [`pipx`](https://pipx.pypa.io) if
available, then `uv tool install`, then a plain venv under
`~/.local/share/kodand`, and restarts a running console service and MCP server so
they pick up the new build.

## CLI

<img src="https://raw.githubusercontent.com/varotariadarshit/Kodand/master/docs/assets/cli-analyze.svg" alt="kodand analyze output" width="720">

```bash
kodand templates list                 # 64 YAML templates, with Literals + Regex columns
                                      # (plus 18 structural AST/JSON rules not listed here)
kodand templates scan /path/to/repo   # shows match kind (literal/regex/decoded)
kodand analyze /path/to/repo \
  --output output/analysis.json --html output/report.html \
  --sarif output/results.sarif --docx output/report.docx --pdf output/report.pdf \
  --workers 4                        # parallel file matching, sequential by default
kodand bench                           # precision / recall / F1 on packaged corpus
kodand bench /path/to/corpus           # or your own labeled corpus
```

## Accuracy

| Benchmark | Result |
| --- | --- |
| Built-in labelled corpus (`kodand bench`): 54 samples, 50 labelled detections | Precision 1.00 · Recall 1.00 |
| [damn-vulnerable-ai-agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent) 0.9.3, every finding reviewed by hand | 11 findings, 11 true positives, 0 false positives |

The built-in corpus is Kodand's own, so the real-world scan is the check that
matters. Method, the full before/after comparison and how to reproduce both
are in [docs/BENCHMARK.md](https://github.com/varotariadarshit/Kodand/blob/master/docs/BENCHMARK.md).

## Web Console
```bash
kodand ui                     # http://127.0.0.1:8787
```
**First sign-in:** the console is password-protected. A fresh workspace starts with
the default password **`kodand`**, and you're required to replace it before you can
reach the console — the login page shows this hint until you do. Credentials live in
`~/.kodand/auth.json` (PBKDF2-hashed, never stored in plaintext). Changing the
password signs out every existing session.

**Forgot it?** Run `kodand password reset` in a terminal on the machine running Kodand
to set a new one, or `kodand password reset --to-default` to go back to `kodand` and
the forced-change prompt.

Tabs: **Projects** (create/scan/delete, upload a folder or archive, or scan a
server-side path), **Live Scans** (real-time pipeline + AI-verification
progress for any running or recent scan, with a Files viewer that highlights
flagged lines), **Custom Templates** (literal **and** regex, global),
**Benchmark** (run precision/recall/F1 in-app), **AI Assistant** (provider
config for the per-finding AI Review button, plus MCP server setup),
**About** (full AST/MCP/Hooks category reference).

Reports are split into separate sections per taxonomy — Agentic Skills
findings, MCP server findings, and Hook findings never mix in the same list —
each with its own coverage matrix and category chart. Every finding and
occurrence has an **Open File** button that jumps straight to the exact
file/line in the Files viewer, highlighted.

Each finding can be marked **Pending Review / True Positive / False Positive
/ Remediated / Suppressed**, annotated with comments, sent for a one-click
**AI Review**, and followed up with AI chat. Full walkthrough of every tab and
the review workflow is in the [user guide](https://github.com/varotariadarshit/Kodand/blob/master/USER_GUIDE.md).

Workspace defaults to `~/.kodand/` (override with `KODAND_HOME`).

## MCP Server
```bash
claude mcp add kodand -- kodand mcp
```
Lets an MCP-capable agent (Claude Code, Cursor, etc.) scan and verify
findings directly from a terminal session — no separate AI-provider quota
required for verification. Setup, the full tool reference, and the
`verify_finding` vs. `add_finding_comment` distinction are in the [user guide](https://github.com/varotariadarshit/Kodand/blob/master/USER_GUIDE.md).

## Suppression example (`.kodand.yml` at repo root)
```yaml
suppressions:
  - rule: AST08-SCANNER-BYPASS
    reason: documented anti-pattern, reviewed
    expires: 2027-01-01
  - category: AST05
    path: "docs/**"
    reason: external links expected in docs
```

## Custom template with regex
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

## Contributing and security

Bug reports, false positives, missed detections and pull requests are welcome;
see [CONTRIBUTING.md](https://github.com/varotariadarshit/Kodand/blob/master/CONTRIBUTING.md). Please report vulnerabilities in
Kodand itself privately, as described in [SECURITY.md](https://github.com/varotariadarshit/Kodand/blob/master/SECURITY.md).

## License

[MIT](https://github.com/varotariadarshit/Kodand/blob/master/LICENSE)
