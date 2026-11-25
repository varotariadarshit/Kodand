"""User-approved scope additions: what the Kodand Agent taught the static scanner.

When the scope crawl adds a file the static registry missed, it raises suggestions (a file
extension Kodand doesn't scan, or a location pattern the registry doesn't match). Suggestions the
user approves in the console land in `<KODAND_HOME>/scope_learned.json`; every scan path — the
console, `kodand analyze` and the MCP `scan` tool — loads them, so the same file is found next time
with no agent running. Entries are re-validated on load: a hand-edited or tampered file can't turn
a catch-all pattern into scope (that would be a SAST scan of the application, not agent content).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from kodand.entrypoints import EntrypointSpec
from kodand.scope_agent import (
    AGENT_FILE_TYPES,
    kind_for_extension_type,
    spec_for,
    validate_extension,
    validate_location_pattern,
    validate_name,
)

LEARNED_FILE = "scope_learned.json"
LEARNED_PLATFORM = "learned"


def workspace_home() -> Path:
    return Path(os.environ.get("KODAND_HOME", str(Path.home() / ".kodand")))


@dataclass(frozen=True)
class LearnedScope:
    extensions: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    locations: tuple[tuple[str, str], ...] = ()  # (pattern, extension_type)

    def entrypoint_specs(self) -> tuple[EntrypointSpec, ...]:
        out = []
        for pattern, ext_type in self.locations:
            kind = kind_for_extension_type(ext_type)
            if kind:
                out.append(spec_for(kind, platform=LEARNED_PLATFORM, patterns=(pattern,)))
        return tuple(out)

    def __bool__(self) -> bool:
        return bool(self.extensions or self.names or self.locations)


EMPTY = LearnedScope()


def parse_learned(data) -> LearnedScope:
    if not isinstance(data, dict):
        return EMPTY
    exts = {e for e in (validate_extension(x) for x in data.get("extensions") or [] if isinstance(x, str)) if e}
    names = {n for n in (validate_name(x) for x in data.get("names") or [] if isinstance(x, str)) if n}
    locs = []
    for item in data.get("locations") or []:
        if not isinstance(item, dict):
            continue
        pat = validate_location_pattern(item.get("pattern"))
        ext_type = item.get("extension_type")
        if pat and kind_for_extension_type(ext_type) in AGENT_FILE_TYPES and (pat, ext_type) not in locs:
            locs.append((pat, ext_type))
    return LearnedScope(frozenset(exts), frozenset(names), tuple(locs))


def load_learned_scope(home: Path | None = None) -> LearnedScope:
    """Approved learned scope from the workspace; empty if none, unreadable or malformed."""
    p = (home or workspace_home()) / LEARNED_FILE
    try:
        return parse_learned(json.loads(p.read_text()))
    except (OSError, ValueError):
        return EMPTY
