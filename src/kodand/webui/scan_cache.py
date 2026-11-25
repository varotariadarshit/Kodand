"""Content-hash scan cache: skip re-matching a file's templates when its exact
content (and the active template set) haven't changed since a prior scan. One
workspace-global cache (not per-project) so identical file content scanned in
different projects/repos still benefits. See `scan_service.py::_scan_one_file`
for where this is consulted, and `run_template_scan`'s `use_cache` param for
how a caller opts out.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from kodand.webui.store import workspace_root

# Bound on-disk growth; entries beyond this are dropped oldest-inserted-first
# when saving, mirroring the cap already used on ~/.kodand/active_scans.json.
MAX_CACHE_ENTRIES = 20000


def cache_path() -> Path:
    return workspace_root() / "scan_cache.json"


# Modules whose code decides what a cached entry contains, beyond the templates
# themselves: matching, context/normalisation and every structural analyser.
_ENGINE_MODULES = (
    "templates/matcher.py", "templates/context.py", "templates/normalize.py", "templates/confidence.py",
    "templates/regexguard.py", "redaction.py", "codeanalysis/__init__.py", "codeanalysis/rules.py",
    "codeanalysis/json_rules.py", "codeanalysis/json_struct.py", "codeanalysis/python_ast.py",
    "codeanalysis/js_ast.py", "codeanalysis/hidden_text.py", "codeanalysis/markdown_rules.py",
    "codeanalysis/secrets.py", "webui/scan_service.py",
)
_engine_fp: str | None = None


def engine_fingerprint() -> str:
    """Hash of the Kodand version plus the source of every module that shapes a
    cached result, so upgrading Kodand or changing any analyser/context rule
    invalidates the cache without anyone remembering to bump a constant."""
    global _engine_fp
    if _engine_fp is None:
        from kodand import __version__
        root = Path(__file__).resolve().parent.parent
        h = hashlib.sha256(__version__.encode())
        for rel in _ENGINE_MODULES:
            try:
                h.update(rel.encode() + b"\0" + (root / rel).read_bytes())
            except OSError:
                h.update(rel.encode() + b"\0missing")
        _engine_fp = h.hexdigest()
    return _engine_fp


def template_set_hash(templates) -> str:
    """Sha256 over every template's full definition (id, info incl. severity/
    category/confidence, detection, capabilities, ...), sorted by id, plus the
    engine fingerprint. Any template or engine change invalidates every cached
    entry rather than risking a finding computed under an old rule set
    silently surviving a rule change."""
    basis = sorted((t.model_dump(mode="json") for t in templates), key=lambda d: d["id"])
    return hashlib.sha256(json.dumps({"engine": engine_fingerprint(), "templates": basis},
                                     sort_keys=True).encode()).hexdigest()


def cache_key(content_hash: str, analyser_class: str) -> str:
    """Entries are per (content, analyser): the same bytes in a .md and a .py file
    go through different structural analysers and must not share a result."""
    return f"{content_hash}:{analyser_class}"


def load_cache(current_hash: str) -> dict:
    """Return `{content_sha256: {template_id: [match_dict, ...]}}` for the
    current template set, or `{}` if the cache file is missing, unreadable, or
    was built under a different template set (see `template_set_hash`)."""
    p = cache_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except Exception:
        return {}
    if data.get("template_set_hash") != current_hash:
        return {}
    entries = data.get("entries")
    return entries if isinstance(entries, dict) else {}


def save_cache(current_hash: str, entries: dict) -> None:
    """Persist `entries` (the full, merged cache content for `current_hash`,
    not just one run's new misses — callers should merge onto what
    `load_cache` returned before calling this)."""
    if len(entries) > MAX_CACHE_ENTRIES:
        entries = dict(list(entries.items())[-MAX_CACHE_ENTRIES:])
    cache_path().write_text(json.dumps({"template_set_hash": current_hash, "entries": entries}))


def clear_cache() -> None:
    p = cache_path()
    if p.exists():
        p.unlink()
