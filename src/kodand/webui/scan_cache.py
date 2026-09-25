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


def template_set_hash(templates) -> str:
    """Sha256 over each template's (id, match, regex), sorted by id. Changes
    whenever any builtin or custom template is added, removed, or edited, so a
    template-set change invalidates every cached entry rather than risking a
    finding computed under an old rule set silently surviving a rule change."""
    basis = sorted(
        (t.id, list(t.detection.match), list(t.detection.regex))
        for t in templates
    )
    return hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()


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
