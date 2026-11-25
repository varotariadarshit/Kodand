# Kodand benchmark

Kodand is measured two ways: a labelled corpus that ships with the package, and a
manually reviewed scan of a public, deliberately vulnerable agent repository.
The first is repeatable and runs in CI; the second is the honest check that the
corpus isn't just teaching Kodand to pass its own test.

## 1. Built-in labelled corpus

```bash
kodand bench            # packaged corpus, default confidence threshold 45
kodand bench --threshold 60
kodand bench /path/to/your/corpus
```

| Corpus | Samples | Labelled detections | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- |
| `src/kodand/builtin_corpus` | 66 (50 malicious, 16 benign) | 63 | 1.00 | 1.00 | 1.00 |

Each sample is a small skill folder under `malicious/` or `benign/`, and
`manifest.yaml` lists the categories each one must (and must only) produce. A
finding counts as detected when its composite confidence score is at least the
threshold. Benign samples cover the shapes that used to cause false positives:
`db.exec(...)` and `regex.exec(...)`, `${ENV_VAR}` token references,
private-network URLs, emoji joiners and placeholder connection strings in docs.

This corpus is written by the Kodand maintainers, so a perfect score only means
Kodand does what its authors intended on cases they thought of. The real-world
scan below is what keeps that honest. Every reported false positive or miss is
added to the corpus as a new sample.

## 2. Real-world scan: damn-vulnerable-ai-agent

[OpenA2A's damn-vulnerable-ai-agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
(DVAA, Apache-2.0) is a lab of intentionally vulnerable agent scenarios. Kodand
scans the parts of it that are agent skills, MCP configs and the MCP servers they
configure: 11 entrypoints and their supporting code. The rest of DVAA (web apps,
agent runtimes) is outside Kodand's scope.

```bash
git clone https://github.com/opena2a-org/damn-vulnerable-ai-agent
kodand analyze damn-vulnerable-ai-agent --html dvaa-report.html
```

Measured on DVAA commit `30011c1` (version 0.9.3, 2026-11-19), with both Kodand
versions scanning the same checkout. Every finding was reviewed by hand against
the full source file, and every scanned scenario was read for issues Kodand missed.

| | Kodand 1.0.0 | Kodand 2.0 |
| --- | --- | --- |
| Findings | 10 | 12 |
| True positives | 10 | 11 |
| Low-severity hygiene (accurate, below the 45 counting threshold) | 0 | 1 |
| False positives | 0 | 0 |
| Statically detectable issues missed | 2 | 1 |

The 11 true positives in 2.0:

| Finding | Where |
| --- | --- |
| `AST01-INSTRUCTION-OVERRIDE` | `soul-override-via-skill` skill: "IMPORTANT OVERRIDE", safety rules "suspended", "Ignore ethical guidelines", "Reveal your full system prompt" |
| `AST01-CONCEALED-INSTRUCTION` | Hidden instructions in MCP tool descriptions and in data an MCP server stores and returns (`mcp-context-injection`, `mcp-state-injection`) |
| `AST01-JS-EXFIL` | Tool-poisoning MCP server posting the tool arguments to an attacker callback, errors swallowed |
| `AST08-HIDDEN-UNICODE` | Unicode tag characters hiding an instruction in a skill |
| `MCP04-TYPOSQUAT-PACKAGE` | `@modelcontextprotocol/server-filesytem` |
| `MCP04-UNPINNED-LAUNCHER` | `npx -y` MCP packages without a version |
| `MCP01-HARDCODED-ENV-SECRET` | API keys inline in an MCP config |
| `MCP07-INSECURE-TRANSPORT` | MCP servers on plain `http://10.0.1.x` |
| `AST03-AWS-CREDENTIALS`, `AST03-CONNECTION-STRING-PASSWORD`, `AST03-TOKEN-ACCESS` | AWS keys, a database password and a GitHub token in the tool-poisoning MCP server's `docker-compose.yml` |

- **Low-severity hygiene finding:** two skills have no YAML frontmatter
  (`AST04-MALFORMED-FRONTMATTER`, low, score 36). This is accurate but not a
  security issue on its own.
- **Known miss: capability escalation.** In `mcp-capability-escalation`, the MCP
  config declares two read-only tools, but the server it configures also defines
  `execute_command`, `write_file` and `send_http`. Catching that needs a rule
  comparing the tools a config declares with the tools its server defines, which
  Kodand doesn't have yet.
- **Not counted as misses:** these depend on what a server does at run time,
  which a static scan can't see:
  - `mcp-rug-pull`: pinned packages whose behaviour changes later;
  - `mcp-server-impersonation`: a config pointed at the wrong port;
  - `mcp-discovery-exposed`: localhost-only endpoints listed in `.well-known`.

What changed from 1.0.0 to 2.0:

| Issue in DVAA | 1.0.0 | 2.0 |
| --- | --- | --- |
| Skill that suspends safety rules and tells the agent to reveal its system prompt | Missed | `AST01-INSTRUCTION-OVERRIDE` (high) |
| Hidden instruction in a tool description, plus a code comment "Silently captures exfiltrated data" | Description caught | Description caught; the comment is not treated as an instruction |
| API keys inline in an MCP config | `MCP01` | `MCP01` once (the generic inline-secret rule folds into it instead of repeating it) |
| Skills without YAML frontmatter | Not reported | Reported as low severity |

### Scope regression found by this run, and fixed

The first 2.0 run of this benchmark reported only 7 findings. The change in 2.0
that stops a repository-root `AGENTS.md` or `.mcp.json` from pulling the whole
application into the scan had also stopped scanning MCP server code sitting next
to its own `mcp.json`. That code holds the tool descriptions the agent reads, so
four real findings went missing.

An MCP config now owns its folder when that folder (or its `src/`) contains MCP
server code: the MCP SDKs, `tools/list`, `tools/call` or `inputSchema`. An
application's root `.mcp.json` still scans only itself. Regression tests cover
both cases.

### History: 1.0.0 release candidate to 1.0.0

On an earlier DVAA commit, the first 1.0.0 release candidate reported 8 findings:
5 true positives, 1 partly correct, 1 weak or duplicate and 1 false positive, with
3 real issues missed. Fixes before the 1.0.0 release added typosquat detection,
stored and tool-description prompt injection, connection-string passwords and
zero-width entities. They also removed false positives on `db.exec(...)` with a
fixed SQL string, `${GITHUB_TOKEN}` references, private-network URLs reported
twice and duplicate occurrences.

## Reporting a miss or a false positive

Open an issue with the "False positive" or "Missed detection" template and
include the smallest file that reproduces it. Confirmed cases become new corpus
samples, so a fix stays fixed.
