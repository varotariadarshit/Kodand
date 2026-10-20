# Contributing

Contributions are welcome: bug fixes, new detection rules, benchmark samples and
docs. For anything large, open an issue first so we can agree on the approach.

- **Found a false positive or a miss?** Use the "False positive" or "Missed
  detection" issue template. A pull request that adds the failing case to the
  benchmark corpus (see below) together with the fix is the fastest way to get it merged.
- **Found a vulnerability in Kodand itself?** Don't open an issue; follow
  [SECURITY.md](SECURITY.md).
- By participating you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -c requirements.txt -e ".[dev]"
```

## Tests

```bash
pytest -q
```

## Benchmark

Precision/recall/F1 against the packaged labeled corpus (`src/kodand/builtin_corpus/`):

```bash
kodand bench
```

If you add or change detection templates, run `kodand bench` before and after
and note any regression in the PR description. If you add new corpus samples,
keep `src/kodand/builtin_corpus/manifest.yaml`'s expected categories accurate — run
`kodand analyze <sample-dir>` on the new sample and check which categories
actually fire (some phrasing legitimately triggers more than one category).

## Lint

```bash
ruff check .
```

## Updating dependencies

`requirements.txt` pins the exact version of every runtime dependency (what `install.sh` installs and
what security scanners read); `pyproject.toml` keeps the supported ranges. To move to the newest
versions within those ranges (needs [uv](https://docs.astral.sh/uv/)):

```bash
uv lock --upgrade
uv export --frozen --no-hashes --no-emit-project --no-dev --no-header -o requirements.txt
uvx pip-audit -r requirements.txt --no-deps --disable-pip   # no known vulnerabilities
uv sync --extra dev --frozen && pytest -q && kodand bench
```

Then update the "Pinned (tested)" column of the README's Dependencies table;
`tests/test_dependency_pins.py` fails until the pins, the ranges and the table agree.

## Adding a built-in template

Templates live under `src/kodand/builtin_templates/{ast,mcp,hooks}/*.yaml`, one
directory per taxonomy. See `README.md`'s "Custom template with regex" section
for the schema. New
regex indicators must pass the ReDoS guard (`kodand.templates.regexguard`) —
`load_templates()` will silently drop (with a logged warning) any pattern
that fails validation.

## Adding a structural rule

Some rules need to correlate two or more keys of the same object (or compare
several objects against each other) — a wildcard hook `matcher` escalated by
its own `command`, or one MCP server's launcher compared against every other
configured server. A YAML template's line-based `match`/`regex` can't express
that, so these instead live as ordinary Python code:

- `src/kodand/codeanalysis/json_struct.py` — a small stdlib-only,
  position-tracking JSON parser (`parse(text) -> JNode | None`), plus the
  actual rule-check functions (`_check_hook_rules`, `_check_mcp04`,
  `_check_mcp09`) and the `analyze_json_file` entry point. Content-sniffed,
  not filename-gated: any `.json` file whose parsed shape has a `hooks` or
  `mcpServers`/`servers` object gets the relevant checks; everything else is
  skipped cheaply.
- `src/kodand/codeanalysis/json_rules.py` — the `KodandTemplate` metadata
  (id/category/severity/recommendation) for each structural rule, mirroring
  `codeanalysis/rules.py`'s pattern for the Python/JS AST rules. `detection`
  is left empty; the real logic lives in `json_struct.py`.

A structural rule's `id`/`category` should match the taxonomy exactly like a
YAML template's would (and if it's replacing one, delete the YAML file rather
than leaving both — `load_templates()`'s dedup-by-id would otherwise silently
drop whichever loads second). Add a test to `tests/test_json_rules.py`, and a
corpus fixture the same way as a YAML template (see below).

## Scope

Kodand scans agent instruction files (`SKILL.md`, `GEMINI.md`, `AGENTS.md`,
Copilot, Cursor and Windsurf rules), MCP server configs, Claude Code hooks, and
the scripts they reference. All automated findings are candidates requiring
human validation — the project does not claim to prove runtime exploitability.
Benchmark method and results are in [docs/BENCHMARK.md](docs/BENCHMARK.md).
