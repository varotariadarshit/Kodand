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
| `src/kodand/builtin_corpus` | 54 (41 malicious, 13 benign) | 50 | 1.00 | 1.00 | 1.00 |

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
scans the parts of it that are agent skills, MCP configs and hooks, which is
11 skill files and their supporting code in version 0.9.3. The rest of DVAA
(web apps, agent runtimes) is outside Kodand's scope.

```bash
git clone https://github.com/opena2a-org/damn-vulnerable-ai-agent
kodand analyze damn-vulnerable-ai-agent --html dvaa-report.html
```

Every finding was reviewed by hand against the full source file.

| | Kodand 1.0.0 (first release candidate) | Kodand 1.0.0 (current) |
| --- | --- | --- |
| Findings | 8 | 11 |
| True positives | 5 | 11 |
| Partly correct | 1 | 0 |
| Weak or duplicate | 1 | 0 |
| False positives | 1 | 0 |
| Real issues missed | 3 | 0 found so far |

What changed between the two columns:

| Issue in DVAA | Before | Now |
| --- | --- | --- |
| Typosquatted `@modelcontextprotocol/server-filesytem` in an MCP config | Only "unpinned launcher" (medium) | `MCP04-TYPOSQUAT-PACKAGE` (high) |
| Stored prompt injection seeded into an MCP server's notes database | Missed | `AST01-CONCEALED-INSTRUCTION` |
| Hidden instruction in an MCP tool description | Missed | `AST01-CONCEALED-INSTRUCTION` |
| Database password in a `postgresql://` connection string | Missed | `AST03-CONNECTION-STRING-PASSWORD` (password redacted in the report) |
| Instruction hidden with `&#x200B;` zero-width entities | Caught only by its wording | Also `AST08-HIDDEN-UNICODE` |
| `db.exec(...)` running a fixed SQL string | False positive as dynamic code evaluation | Not flagged |
| `"${GITHUB_TOKEN}"` environment-variable reference | False positive as token access | Not flagged |
| Private `10.0.1.x` MCP server URLs | Also reported as "external content" | Reported once, as unencrypted transport |
| Same line listed twice within one finding | Yes | One occurrence per line |

## Reporting a miss or a false positive

Open an issue with the "False positive" or "Missed detection" template and
include the smallest file that reproduces it. Confirmed cases become new corpus
samples, so a fix stays fixed.
