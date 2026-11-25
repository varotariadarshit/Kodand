"""Template-engine scan producing rich RepositoryAnalysis + reports (v3).

v3 additions wired here:
  - literal + regex + decoded matches (matcher v3)
  - Context Engine v2 (per-occurrence context)
  - dedup + evidence merge + proximity + composite scoring (accuracy.py)
  - suppression framework v2 (suppress.py)
"""
from __future__ import annotations

import hashlib
import multiprocessing
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from kodand.accuracy import run_accuracy_pipeline
from kodand.categories import BUILTIN_NAMES, category_name, ordered_categories, register_category
from kodand.codeanalysis import ANALYZABLE_EXTENSIONS, analyze_file
from kodand.codeanalysis.hidden_text import RULE_ID as HIDDEN_TEXT_RULE_ID
from kodand.codeanalysis.hidden_text import find_hidden_text
from kodand.codeanalysis.json_rules import JSON_RULES_LIST
from kodand.codeanalysis.markdown_rules import analyze_markdown_source, is_markdown_like
from kodand.codeanalysis.rules import CODE_RULES, CODE_RULES_LIST
from kodand.learned_scope import EMPTY as NO_LEARNED_SCOPE
from kodand.learned_scope import LearnedScope
from kodand.models.analysis import (
    CorrelatedFinding,
    CoverageItem,
    FindingOccurrence,
    RepositoryAnalysis,
    Summary,
)
from kodand.models.inventory import AgentScopeInfo, ScanWarning
from kodand.reporting import write_docx, write_html, write_pdf, write_sarif
from kodand.scanner import build_extension, inventory_repository
from kodand.scope_agent import spec_for
from kodand.suppress import apply_suppressions, repo_suppression_file
from kodand.templates import matcher, regexguard
from kodand.templates.correlation import correlate_capabilities
from kodand.templates.loader import load_templates
from kodand.templates.matcher import MAX_FILE_BYTES, TemplateMatch, build_views, match_template_views, read_file
from kodand.webui import scan_cache

BUILTIN_CATS = set(BUILTIN_NAMES)  # every AST/MCP/HOOK code — see kodand.categories
MAX_SCAN_FILES = 10000  # hard cutoff once max_scan_files budget is exhausted — see _select_scan_files
SCANNABLE_EXTENSIONS = {
    # docs / instructions
    ".md", ".mdc", ".mdx", ".txt", ".rst", ".html", ".htm", ".xml",
    # config
    ".yaml", ".yml", ".json", ".jsonc", ".json5", ".toml", ".cfg", ".ini", ".conf", ".properties",
    # scripts a skill can ship or tell the agent to run
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".ps1", ".psm1", ".psd1", ".bat", ".cmd",
    ".rb", ".pl", ".php", ".lua", ".go", ".rs", ".java", ".kt", ".swift", ".r", ".applescript", ".scpt", ".vbs",
}
# extensionless (or dot-named) files worth scanning by name — agent rule files, env and build files
SCANNABLE_NAMES = {
    ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".rules", ".roomodes", ".envrc",
    "dockerfile", "containerfile", "makefile", "justfile", "procfile", "gemfile", "rakefile", "brewfile",
}
_SHEBANG_SNIFF_BYTES = 64


def is_scannable(path: Path, learned: LearnedScope = NO_LEARNED_SCOPE) -> bool:
    """Text a scan should match: known extensions, known names, `.env*` files and
    extensionless scripts with a shebang (`scripts/install` with `#!/bin/sh`), plus any
    extensions/names the user approved from Kodand Agent suggestions (`learned`)."""
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in SCANNABLE_EXTENSIONS or name in SCANNABLE_NAMES:
        return True
    if suffix in learned.extensions or name in learned.names:
        return True
    if name.startswith(".env") or name.startswith(".roorules-"):
        return True
    if path.suffix == "" or name.startswith("."):
        try:
            with open(path, "rb") as fh:
                return fh.read(_SHEBANG_SNIFF_BYTES).startswith(b"#!")
        except OSError:
            return False
    return False
# extensions prioritized ahead of plain docs when a repo exceeds max_scan_files — see _select_scan_files
_HIGH_PRIORITY_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".ps1", ".json", ".yaml", ".yml"}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

# module-level so a spawned worker PROCESS can see them after _init_worker runs there;
# unused (and harmless) in the sequential/in-process path, which calls _init_worker directly.
_worker_templates: list | None = None
_worker_root: Path | None = None
_worker_cache: dict | None = None


def _init_worker(templates: list, root_str: str, cache: dict | None = None) -> None:
    global _worker_templates, _worker_root, _worker_cache
    _worker_templates = templates
    _worker_root = Path(root_str)
    _worker_cache = cache or {}


def _scan_one_file(file_path_str: str):
    """Match every loaded template against one file. Runs either directly in the
    main process (workers<=1) or inside a worker process (workers>1) — same code
    path either way, so parallel and sequential scans are guaranteed to produce
    identical per-file results, just in a different order of completion.

    Checks `_worker_cache` (keyed by sha256 of the file's exact text, scoped to
    the active template set by `run_template_scan` — see `scan_cache.py`) before
    paying for `build_views`/matching; a hit reconstructs `TemplateMatch`
    objects straight from the cached dicts instead of recomputing them.

    Returns `(relative_path | None, {template_id: [TemplateMatch, ...]},
    content_hash | None, was_cache_hit)`. Coverage problems for this file (skipped
    for size, regex budget exhausted, overlong line clipped) come back under the
    reserved `WARNINGS_KEY` as `[code, message]` pairs, cached with the matches.
    """
    file_path = Path(file_path_str)
    result = read_file(file_path, _worker_root)
    if result is None:
        try:
            too_big = file_path.stat().st_size > MAX_FILE_BYTES
        except OSError:
            too_big = False
        if too_big:
            rel = file_path.relative_to(_worker_root).as_posix()
            return rel, {WARNINGS_KEY: [["FILE_SKIPPED_OVERSIZE", rel]]}, None, False
        return None, {}, None, False
    relative_path, text = result
    content_hash = scan_cache.cache_key(hashlib.sha256(text.encode("utf-8")).hexdigest(),
                                        analyser_class(file_path))

    cached = _worker_cache.get(content_hash)
    if cached is not None:
        # cached matches carry whatever `file` was baked in the FIRST time this exact
        # content was scanned, which may be a different relative path (two files with
        # byte-identical content, e.g. copy-pasted boilerplate) — always re-stamp the
        # current file's relative_path rather than trusting the cached value.
        out = {tid: ([list(w[:1]) + [relative_path] for w in ms] if tid == WARNINGS_KEY else
                     [TemplateMatch(**{**m, "file": relative_path}) for m in ms])
               for tid, ms in cached.items()}
        return relative_path, out, content_hash, True

    regexguard.TIMED_OUT_PATTERNS.clear()
    matcher.LONG_LINES_CLIPPED.clear()
    views = build_views(text)
    out: dict[str, list] = {}
    for t in _worker_templates:
        ms = match_template_views(t, relative_path, views)
        if ms:
            out[t.id] = ms

    hidden_rule = CODE_RULES[HIDDEN_TEXT_RULE_ID]
    hidden = find_hidden_text(text, relative_path, hidden_rule.info.category, hidden_rule.info.confidence)
    if hidden:
        out[HIDDEN_TEXT_RULE_ID] = hidden

    if file_path.suffix.lower() in ANALYZABLE_EXTENSIONS:
        # structural findings from a real parser (see kodand.codeanalysis), not the
        # text/regex templates above — merged into the same per-file result shape
        for m in analyze_file(file_path, _worker_root):
            out.setdefault(m.template_id, []).append(m)
    elif is_markdown_like(file_path.name, file_path.suffix):
        # fenced code blocks, frontmatter, multi-line fetch/follow correlation
        for m in analyze_markdown_source(text, relative_path, file_path.name):
            out.setdefault(m.template_id, []).append(m)

    warnings = []
    if regexguard.TIMED_OUT_PATTERNS:
        warnings.append(["REGEX_TIMEOUT", relative_path])
    if matcher.LONG_LINES_CLIPPED:
        warnings.append(["LINE_CLIPPED", relative_path])
    limit = _AST_SIZE_LIMITS.get(file_path.suffix.lower())
    if limit and len(text.encode("utf-8", "replace")) > limit:
        warnings.append(["ANALYSIS_SKIPPED_OVERSIZE", relative_path])
    if warnings:
        out[WARNINGS_KEY] = warnings

    return relative_path, out, content_hash, False


WARNINGS_KEY = "__warnings__"
_WARNING_TEXT = {
    "FILE_SKIPPED_OVERSIZE": "file(s) larger than the 50 MB per-file cap were not scanned",
    "REGEX_TIMEOUT": "file(s) where a detection pattern ran out of its time budget, so the rest of the file "
                     "was not checked against that pattern",
    "LINE_CLIPPED": "file(s) with a line longer than about 45,000 characters; only its first 45,000 or so characters were matched",
    "ANALYSIS_SKIPPED_OVERSIZE": "code/JSON file(s) over the structural-analysis size cap (5 MB code, 2 MB JSON); "
                                 "only text templates ran on them",
}


def _size_limits() -> dict:
    from kodand.codeanalysis.json_struct import MAX_JSON_SOURCE_BYTES
    from kodand.codeanalysis.python_ast import MAX_PY_SOURCE_BYTES
    out = {s: MAX_PY_SOURCE_BYTES for s in (".py",)}
    out.update({s: 5_000_000 for s in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")})
    out[".json"] = MAX_JSON_SOURCE_BYTES
    return out


_AST_SIZE_LIMITS = _size_limits()


def _js_analysis_unavailable() -> bool:
    try:
        import kodand.codeanalysis.js_ast  # noqa: F401
    except ImportError:
        return True
    return False


def warnings_from_results(results) -> list[ScanWarning]:
    """Fold per-file `[code, path]` coverage warnings into one ScanWarning per code."""
    by_code: dict[str, list[str]] = {}
    for r in results:
        if r is None or r[0] is None:
            continue
        for code, path in r[1].get(WARNINGS_KEY, []):
            by_code.setdefault(code, []).append(path)
    out = []
    for code, paths in by_code.items():
        paths = sorted(set(paths))
        shown = ", ".join(paths[:10]) + (f", and {len(paths) - 10} more" if len(paths) > 10 else "")
        out.append(ScanWarning(code=code, message=f"{len(paths)} {_WARNING_TEXT.get(code, code)}: {shown}",
                               path=paths[0]))
    return out


def analyser_class(file_path: Path) -> str:
    """Which structural analysers a file goes through — part of its cache key."""
    suffix = file_path.suffix.lower()
    if suffix in ANALYZABLE_EXTENSIONS:
        return "code" + suffix
    if is_markdown_like(file_path.name, file_path.suffix):
        return "md-skill" if file_path.name.lower() in ("skill.md", "skills.md") else "md"
    return "text"


def load_builtin_templates():
    return load_templates(files("kodand").joinpath("builtin_templates"))


def _synth(template):
    cat = template.info.category
    name = template.info.name
    caps = ", ".join(template.capabilities) or "no explicit capabilities"
    return {
        "description": f"Kodand matched detection template '{template.id}' ({name}) indicating content consistent with {category_name(cat).lower()}.",
        "technical_root_cause": f"Skill content contains indicators associated with {name.lower()} ({caps}). Static indicators were located in repository-controlled SKILL content.",
        "attack_scenario": f"An adversary or unsafe workflow could leverage the '{name}' behavior to exercise the detected capabilities ({caps}) against the agent runtime.",
        "preconditions": "Exploitability depends on the agent runtime actually granting the referenced capability and access at execution time.",
        "potential_impact": "Potential impact includes unauthorized access, modification, execution, or disclosure depending on effective permissions.",
        "validation_guidance": "Review the matched line in context, confirm whether the behavior is real (not a warning/example/mitigation), verify effective runtime permissions, and retest after remediation.",
    }


def _select_scan_files(entry_files: set[Path], supporting_files: set[Path], max_scan_files: int) -> list[Path]:
    """Below `max_scan_files`, identical to the old `sorted(entry_files | supporting_files)` —
    no behavior change for the common case. Over budget, keep every entrypoint (there are
    typically few — one per detected skill/extension) and fill the remaining budget from
    supporting files, code/config extensions first, instead of a blind sorted-path slice."""
    entries = sorted(entry_files)
    total = len(entry_files) + len(supporting_files)
    if total <= max_scan_files:
        return sorted(entry_files | supporting_files)
    if len(entries) >= max_scan_files:
        return entries[:max_scan_files]
    budget = max_scan_files - len(entries)
    support_sorted = sorted(supporting_files)
    high = [f for f in support_sorted if f.suffix.lower() in _HIGH_PRIORITY_EXTENSIONS]
    low = [f for f in support_sorted if f.suffix.lower() not in _HIGH_PRIORITY_EXTENSIONS]
    return sorted(entries + (high + low)[:budget])


def static_scope(inv) -> set[str]:
    """Repo-relative paths the static pass already scans: entrypoints, bundle files, references."""
    out = {e.entrypoint for e in inv.extensions}
    out |= {sf.relative_path for e in inv.extensions for sf in e.supporting_files}
    out |= {r for e in inv.extensions for r in e.referenced_files}
    return out


_SCOPE_WARNINGS = {
    "partial": "AGENT_SCOPE_PARTIAL",
    "skipped": "AGENT_SCOPE_PARTIAL",
    "offline": "AGENT_SCOPE_UNAVAILABLE",
    "not_shared": "AGENT_SCOPE_UNAVAILABLE",
    "error": "AGENT_SCOPE_UNAVAILABLE",
}


def _apply_agent_scope(inv, root: Path, provider, progress) -> None:
    """Run the Kodand Agent scope crawl and add what it found as agent-discovered entrypoints.
    Any failure leaves the static scope exactly as it was (plus a warning)."""
    try:
        info = provider(root, inv, static_scope(inv), progress)
    except Exception as exc:  # the crawl is best-effort; the scan must still complete
        info = AgentScopeInfo(status="error", detail=f"Kodand Agent scope crawl failed: {exc}"[:500])
    known = {e.entrypoint for e in inv.extensions}
    for add in info.added:
        rel = add["path"]
        target = root / rel
        if rel in known or target.is_symlink() or not target.is_file():
            continue
        inv.extensions.append(build_extension(target, root, spec_for(add["type"]), rel,
                                              discovered_by="kodand-agent", reason=add.get("reason")))
        known.add(rel)
    inv.agent_scope = info
    code = _SCOPE_WARNINGS.get(info.status)
    if code and info.detail:
        inv.warnings.append(ScanWarning(code=code, message=info.detail))


def run_template_scan(repo_path: str, use_custom: bool, custom_dir: Path | None,
                      out_dir: Path, formats=("html", "json", "sarif"), on_progress=None,
                      *, workers: int = 1, use_cache: bool = True, max_scan_files: int | None = None,
                      extra_suppressions: list[dict] | None = None,
                      trust_repo_suppressions: bool = False,
                      learned_scope: LearnedScope = NO_LEARNED_SCOPE,
                      scope_provider=None) -> dict:
    """`on_progress(stage: str, detail: dict)`, called at each pipeline stage transition and once per
    file during template matching (stage="matching", detail has current_file/scanned/total) — feeds the
    web console's live scan-progress dashboard. Optional; scanning behaves identically without it.

    `workers=1` (default) matches every file against every template sequentially in this
    process, exactly as before. `workers>1` matches files in parallel across that many worker
    processes — findings are identical either way (see `_scan_one_file`'s docstring), just
    produced faster on a multi-file repo and a multi-core machine.

    `use_cache=True` (default) consults/updates the workspace-global content-hash cache
    (`scan_cache.py`) so an unchanged file isn't re-matched on a later scan; pass `False` for
    a guaranteed-fresh scan that neither reads nor writes the cache. `max_scan_files` bounds
    how many files a single scan matches (see `_select_scan_files`).

    `learned_scope`: user-approved locations/extensions (kodand.learned_scope) the static scope
    also uses. `scope_provider(root, inventory, static_scope, progress) -> AgentScopeInfo`: the
    Kodand Agent scope crawl (console only). It runs after the static inventory and can only ADD
    entrypoints — its `added` files join the scan as agent-discovered entrypoints."""
    def _progress(stage, **detail):
        if on_progress:
            on_progress(stage, detail)

    # read the module global at call time (not as a bound default) so tests/callers can
    # still monkeypatch scan_service.MAX_SCAN_FILES the same way they always could.
    if max_scan_files is None:
        max_scan_files = MAX_SCAN_FILES

    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)

    templates = load_builtin_templates()
    custom_used = []
    if use_custom and custom_dir and Path(custom_dir).is_dir():
        custom_used = load_templates(Path(custom_dir))
        for t in custom_used:
            if t.info.category not in BUILTIN_CATS:
                register_category(t.info.category, t.info.category.replace("-", " ").title())
        templates = templates + custom_used
    # AST/JSON-structural rules (kodand.codeanalysis) carry no detection.match/regex, so
    # they're inert in match_template_views — merged here purely so tmap/_synth/capability
    # rollup treat a structural finding exactly like a YAML template finding (see _scan_one_file)
    templates = templates + CODE_RULES_LIST + JSON_RULES_LIST

    seen, uniq = set(), []
    for t in templates:
        if t.id in seen:
            continue
        seen.add(t.id); uniq.append(t)
    templates = uniq
    tmap = {t.id: t for t in templates}

    cache_hash = scan_cache.template_set_hash(templates) if use_cache else None
    cache = scan_cache.load_cache(cache_hash) if use_cache else {}

    _progress("inventory")
    inv = inventory_repository(repo_path, extra_entrypoints=learned_scope.entrypoint_specs())
    root = Path(inv.repository_root)
    # a repo_path pointing at an archive gets extracted to a temp dir by
    # validate_repository; clean it up once this scan is done with it (matters
    # most here since the web UI process outlives any single scan)
    extracted_root = Path(repo_path).expanduser().resolve() != root
    try:
        if scope_provider is not None:
            _apply_agent_scope(inv, root, scope_provider, _progress)
        # entrypoints come from inventory_repository's platform registry (scanner.ENTRYPOINTS) —
        # covers every supported platform's skill/instruction file, not just Claude's SKILL.md
        entry_files = {root / e.entrypoint for e in inv.extensions}

        supporting_files = {
            root / sf.relative_path
            for ext in inv.extensions for sf in ext.supporting_files
            if not sf.is_symlink and is_scannable(root / sf.relative_path, learned_scope)
        }
        # files an entrypoint references outside its own folder (resolved inside the repo)
        supporting_files |= {
            root / rel for ext in inv.extensions for rel in ext.referenced_files
            if is_scannable(root / rel, learned_scope)
        }
        supporting_files -= entry_files
        total_candidates = len(entry_files) + len(supporting_files)
        scan_files = _select_scan_files(entry_files, supporting_files, max_scan_files)
        if total_candidates > max_scan_files:
            skipped = total_candidates - len(scan_files)
            inv.warnings.append(ScanWarning(
                code="SCAN_TRUNCATED",
                message=(f"Repository has {total_candidates} scannable files; kept all "
                         f"{len(entry_files)} entrypoint(s) and {len(scan_files) - len(entry_files)} "
                         f"higher-priority supporting files ({len(scan_files)} total, {max_scan_files} max). "
                         f"{skipped} lower-priority file(s) — mostly plain docs/text — were not scanned."),
            ))

        grouped: dict[str, list] = {}
        all_caps: list[str] = []
        total_files = len(scan_files)
        _progress("matching", current_file=None, scanned=0, total=total_files)

        # results collected by original (sorted) index so the merge below happens in a fixed
        # order regardless of which worker/file finishes first — this is what keeps finding
        # occurrence order identical between workers=1 and workers=N (see _scan_one_file).
        results: list[tuple[str | None, dict, str | None, bool] | None] = [None] * total_files
        if workers <= 1:
            _init_worker(templates, str(root), cache)
            for i, sf in enumerate(scan_files):
                results[i] = _scan_one_file(str(sf))
                _progress("matching", current_file=results[i][0], scanned=i + 1, total=total_files)
        else:
            scanned = 0
            ctx = multiprocessing.get_context("spawn")
            with ProcessPoolExecutor(max_workers=workers, mp_context=ctx,
                                      initializer=_init_worker, initargs=(templates, str(root), cache)) as ex:
                futures = {ex.submit(_scan_one_file, str(sf)): i for i, sf in enumerate(scan_files)}
                for fut in as_completed(futures):
                    i = futures[fut]
                    results[i] = fut.result()
                    scanned += 1
                    _progress("matching", current_file=results[i][0], scanned=scanned, total=total_files)

        if use_cache:
            new_entries = dict(cache)
            for relative_path, matches_by_tid, content_hash, was_hit in results:
                if relative_path is None or was_hit or content_hash is None:
                    continue
                new_entries[content_hash] = {tid: (ms if tid == WARNINGS_KEY else [asdict(m) for m in ms])
                                             for tid, ms in matches_by_tid.items()}
            scan_cache.save_cache(cache_hash, new_entries)

        for relative_path, matches_by_tid, _content_hash, _was_hit in results:
            if relative_path is None:
                continue
            for tid, ms in matches_by_tid.items():
                if tid == WARNINGS_KEY:
                    continue
                grouped.setdefault(tid, []).extend(ms)
                all_caps.extend(tmap[tid].capabilities)

        inv.warnings.extend(warnings_from_results(results))
        if _js_analysis_unavailable() and any(
                sf.suffix.lower() in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"} for sf in scan_files):
            inv.warnings.append(ScanWarning(
                code="JS_ANALYSIS_UNAVAILABLE",
                message=("tree-sitter is not installed, so JavaScript/TypeScript files (and ts/js code fences) "
                         "got text templates only, no AST rules. Re-run ./install.sh to install it."),
            ))

        # symlinks escaping the repository: never followed or scanned (see
        # copy_snapshot/scan file selection), so report the link itself
        seen_links = set()
        for ext in inv.extensions:
            for sf in ext.supporting_files:
                if sf.is_symlink and sf.escapes_repository and sf.relative_path not in seen_links:
                    seen_links.add(sf.relative_path)
                    rule = tmap["AST08-SYMLINK-ESCAPE"]
                    shown = f"{sf.relative_path} -> {sf.symlink_target}"
                    grouped.setdefault(rule.id, []).append(TemplateMatch(
                        template_id=rule.id, category=rule.info.category, severity=rule.info.severity,
                        confidence=rule.info.confidence, file=sf.relative_path, line=1, column_start=1,
                        column_end=1, matched_value=shown, excerpt=shown, context="instruction",
                        match_kind="structural", decoded_from=None))
                    all_caps.extend(rule.capabilities)

        findings: list[CorrelatedFinding] = []
        for tid, ms in grouped.items():
            t = tmap[tid]
            occ = [FindingOccurrence(
                file=m.file, line=m.line, column_start=m.column_start, column_end=m.column_end,
                excerpt=m.excerpt, matched_value=m.matched_value, evidence_type="instruction",
                evidence_hash=hashlib.sha256(f"{m.file}:{m.line}:{m.matched_value}".encode()).hexdigest(),
                context=m.context, match_kind=m.match_kind, rule_id=tid, decoded_from=m.decoded_from,
            ) for m in ms]
            n = _synth(t)
            fid = "KODAND-" + hashlib.sha256(tid.encode()).hexdigest()[:16].upper()
            # per-match severity is almost always uniform (every regex/literal template match
            # carries the same static template.info.severity) EXCEPT a structural rule can
            # correlate keys of one object and escalate a specific occurrence (e.g. HOOK01's
            # wildcard matcher paired with a risky command) — take the worst of the group
            # rather than the template's base severity, so that escalation actually surfaces.
            severity = max((m.severity for m in ms), key=lambda s: _SEVERITY_RANK.get(s, 0))
            findings.append(CorrelatedFinding(
                finding_id=fid, rule_id=tid, category=t.info.category, category_name=category_name(t.info.category),
                title=t.risk.title or t.info.name, severity=severity, confidence=t.info.confidence,
                description=n["description"], technical_root_cause=n["technical_root_cause"],
                attack_scenario=n["attack_scenario"], preconditions=n["preconditions"],
                potential_impact=n["potential_impact"], remediation=t.recommendation,
                validation_guidance=n["validation_guidance"],
                affected_platforms=[p.platform for p in inv.platforms] or ["unknown"],
                affected_extensions=[e.entrypoint for e in inv.extensions],
                affected_files=sorted({o.file for o in occ}),
                capabilities=sorted(set(t.capabilities)),
                occurrence_count=len(occ), occurrences=occ,
            ))

        # declared supporting files: what each skill's own entrypoint actually
        # names (supporting_files minus undeclared_supporting_files) — feeds the
        # relationship-signal escalation in the accuracy pipeline below
        declared_files = frozenset(
            sf.relative_path
            for ext in inv.extensions for sf in ext.supporting_files
            if sf.relative_path not in set(ext.undeclared_supporting_files)
        )
        # v3 accuracy pipeline: dedup + proximity + relationship + composite scoring
        _progress("accuracy")
        findings = run_accuracy_pipeline(findings, declared_files=declared_files)
        # v3 suppression framework
        _progress("suppression")
        findings, suppressed = apply_suppressions(findings, root, extra_suppressions,
                                                  trust_repo=trust_repo_suppressions)
        if not trust_repo_suppressions and repo_suppression_file(root):
            inv.warnings.append(ScanWarning(
                code="REPO_SUPPRESSIONS_IGNORED",
                message=("The scanned repository ships a .kodand.yml; its suppressions were NOT applied, so "
                         "the repo can't hide its own findings. Trust it explicitly to apply them "
                         "(kodand analyze --trust-repo-suppressions, or the project's toggle in the console)."),
                path=".kodand.yml"))

        sev = {k: 0 for k in ["critical", "high", "medium", "low", "informational"]}
        by = {}
        for f in findings:
            sev[f.severity] += 1
            by[f.category] = by.get(f.category, 0) + 1
        overall = next((x for x in ["Critical", "High", "Medium", "Low"] if sev[x.lower()]), "Informational")

        cats = ordered_categories(extra=[t.info.category for t in templates])
        coverage = [CoverageItem(category=c, name=category_name(c),
                                 status="reviewed-findings" if by.get(c) else "reviewed-no-findings",
                                 finding_count=by.get(c, 0)) for c in cats]

        correlated = correlate_capabilities(all_caps)
        analysis = RepositoryAnalysis(
            inventory=inv, findings=findings, coverage=coverage,
            summary=Summary(total=len(findings), overall_risk=overall, by_category=by, suppressed=suppressed, **sev),
            correlated_risks=correlated,
        )

        _progress("reports")
        artifacts = {}
        if "json" in formats:
            (out_dir / "analysis.json").write_text(analysis.model_dump_json(indent=2), encoding="utf-8"); artifacts["json"] = "analysis.json"
        if "html" in formats:
            write_html(analysis, out_dir / "report.html"); artifacts["html"] = "report.html"
        if "sarif" in formats:
            write_sarif(analysis, out_dir / "results.sarif"); artifacts["sarif"] = "results.sarif"
        if "docx" in formats:
            write_docx(analysis, out_dir / "report.docx"); artifacts["docx"] = "report.docx"
        if "pdf" in formats:
            write_pdf(analysis, out_dir / "report.pdf"); artifacts["pdf"] = "report.pdf"

        return {
            "repository": inv.repository_name, "repository_root": str(root),
            "skills": len(inv.extensions), "skill_files": len(entry_files),
            "templates_total": len(templates), "templates_custom": len(custom_used),
            "use_custom": bool(use_custom), "findings": len(findings), "suppressed": suppressed,
            "overall_risk": overall, "severity": sev, "by_category": by,
            "correlated_risks": correlated, "artifacts": artifacts,
            "warnings": [w.model_dump() for w in inv.warnings],
        }
    finally:
        if extracted_root:
            shutil.rmtree(root, ignore_errors=True)
