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
from kodand.codeanalysis.rules import CODE_RULES, CODE_RULES_LIST
from kodand.models.analysis import (
    CorrelatedFinding,
    CoverageItem,
    FindingOccurrence,
    RepositoryAnalysis,
    Summary,
)
from kodand.models.inventory import ScanWarning
from kodand.reporting import write_docx, write_html, write_pdf, write_sarif
from kodand.scanner import inventory_repository
from kodand.suppress import apply_suppressions
from kodand.templates.correlation import correlate_capabilities
from kodand.templates.loader import load_templates
from kodand.templates.matcher import TemplateMatch, build_views, match_template_views, read_file
from kodand.webui import scan_cache

BUILTIN_CATS = set(BUILTIN_NAMES)  # every AST/MCP/HOOK code — see kodand.categories
MAX_SCAN_FILES = 10000  # hard cutoff once max_scan_files budget is exhausted — see _select_scan_files
SCANNABLE_EXTENSIONS = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py", ".js", ".ts", ".sh", ".ps1"}
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
    content_hash | None, was_cache_hit)`.
    """
    file_path = Path(file_path_str)
    result = read_file(file_path, _worker_root)
    if result is None:
        return None, {}, None, False
    relative_path, text = result
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    cached = _worker_cache.get(content_hash)
    if cached is not None:
        # cached matches carry whatever `file` was baked in the FIRST time this exact
        # content was scanned, which may be a different relative path (two files with
        # byte-identical content, e.g. copy-pasted boilerplate) — always re-stamp the
        # current file's relative_path rather than trusting the cached value.
        out = {tid: [TemplateMatch(**{**m, "file": relative_path}) for m in ms] for tid, ms in cached.items()}
        return relative_path, out, content_hash, True

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

    return relative_path, out, content_hash, False


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


def run_template_scan(repo_path: str, use_custom: bool, custom_dir: Path | None,
                      out_dir: Path, formats=("html", "json", "sarif"), on_progress=None,
                      *, workers: int = 1, use_cache: bool = True, max_scan_files: int | None = None) -> dict:
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
    how many files a single scan matches (see `_select_scan_files`)."""
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
    inv = inventory_repository(repo_path)
    root = Path(inv.repository_root)
    # a repo_path pointing at an archive gets extracted to a temp dir by
    # validate_repository; clean it up once this scan is done with it (matters
    # most here since the web UI process outlives any single scan)
    extracted_root = Path(repo_path).expanduser().resolve() != root
    try:
        # entrypoints come from inventory_repository's platform registry (scanner.ENTRYPOINTS) —
        # covers every supported platform's skill/instruction file, not just Claude's SKILL.md
        entry_files = {root / e.entrypoint for e in inv.extensions}

        supporting_files = {
            root / sf.relative_path
            for ext in inv.extensions for sf in ext.supporting_files
            if not sf.is_symlink and Path(sf.relative_path).suffix.lower() in SCANNABLE_EXTENSIONS
        }
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
                new_entries[content_hash] = {tid: [asdict(m) for m in ms] for tid, ms in matches_by_tid.items()}
            scan_cache.save_cache(cache_hash, new_entries)

        for relative_path, matches_by_tid, _content_hash, _was_hit in results:
            if relative_path is None:
                continue
            for tid, ms in matches_by_tid.items():
                grouped.setdefault(tid, []).extend(ms)
                all_caps.extend(tmap[tid].capabilities)

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
        findings, suppressed = apply_suppressions(findings, root)

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
        }
    finally:
        if extracted_root:
            shutil.rmtree(root, ignore_errors=True)
