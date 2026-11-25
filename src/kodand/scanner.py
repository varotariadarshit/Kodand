import hashlib
from collections import Counter
from pathlib import Path

from kodand.core.artifacts import build_artifact
from kodand.core.repository import iter_tree, validate_repository, walk_repository
from kodand.entrypoints import AGENT_DIR_NAMES, ENTRYPOINTS, looks_like_entrypoint, match_entrypoint
from kodand.models.inventory import AgentExtension, RepositoryInventory, ScanWarning
from kodand.platforms import detect_platforms
from kodand.relationships import find_broken_references, find_external_references, find_undeclared_files

__all__ = ["ENTRYPOINTS", "inventory_repository"]


def _skill_relative(path: str, root_path: str) -> str:
    prefix = root_path + "/"
    return path[len(prefix):] if root_path not in ("", ".") and path.startswith(prefix) else path


def _match_entrypoint(path, root):
    """(spec, rel) for a registered agent artifact, else None.
    Patterns match at any depth (see kodand.entrypoints), so a wrapper directory from a
    folder upload or a GitHub zip never hides `.github/copilot-instructions.md` & co."""
    rel = path.relative_to(root).as_posix()
    spec = match_entrypoint(rel)
    return (spec, rel) if spec else None


def _owns_folder(entry: Path, spec, root: Path) -> bool:
    """Whether `entry`'s whole folder is the artifact (and so gets scanned): true for a
    bundle (a skill dir, a hooks dir, a plugin manifest dir), false for instruction /
    rules / command files and MCP configs. A repo-root `AGENTS.md` must not turn the
    application's source tree into "supporting files" — that's a SAST scan, not an
    agent assessment. Only a skill may claim the repo root (a repo that IS one skill)."""
    return spec.bundle and (entry.parent != root or spec.extension_type == "agent-skill")


_looks_like_entrypoint = looks_like_entrypoint


def _coverage_gap_warning(files, root, extensions):
    """A cheap, app-agnostic safety net, independent of any one platform's matcher logic
    above: if a file's basename looks like a known agent-entrypoint but wasn't recognized
    as one (excluded by a path constraint, or a matcher bug), say so instead of silently
    under-scanning — for any repository, not just ones we've already special-cased."""
    recognized = {e.entrypoint for e in extensions}
    missed = []
    for p in files:
        if not p.is_file() or not _looks_like_entrypoint(p.name):
            continue
        rel = p.relative_to(root).as_posix()
        if rel not in recognized:
            missed.append(rel)
    if not missed:
        return None
    missed.sort()
    shown = ", ".join(missed[:10]) + (f", and {len(missed) - 10} more" if len(missed) > 10 else "")
    return ScanWarning(
        code="ENTRYPOINT_COVERAGE_GAP",
        message=(f"{len(missed)} file(s) look like agent-skill entrypoints by name but "
                 f"weren't recognized/scanned: {shown} — verify these aren't being missed."),
        path=missed[0],
    )


def _agent_dir_warning(files, root, extensions):
    """A directory named like an agent config dir (`.ai/`, `.claude/`, `.cursor/` ...)
    holding text files of which none was recognised as, or sits under, an entrypoint —
    e.g. a new tool's skills layout the registry doesn't know yet."""
    covered = {e.entrypoint for e in extensions}
    covered |= {r for e in extensions for r in e.referenced_files}
    # a recognised artifact inside a dir vouches for that dir; one at the repo root
    # (a root AGENTS.md / .mcp.json) vouches for nothing below it
    covered_dirs = {e.root_path for e in extensions if e.root_path not in ("", ".")}
    unrecognised = Counter()
    for p in files:
        if not p.is_file() or p.suffix.lower() not in {".md", ".mdc", ".txt", ".json", ".yaml", ".yml", ".toml", ""}:
            continue
        rel = p.relative_to(root).as_posix()
        parts = rel.split("/")
        idx = next((i for i, part in enumerate(parts[:-1]) if part.lower() in AGENT_DIR_NAMES), None)
        if idx is None or rel in covered or any(rel.startswith(d + "/") for d in covered_dirs):
            continue
        unrecognised["/".join(parts[:idx + 1])] += 1
    if not unrecognised:
        return None
    dirs = sorted(unrecognised)
    shown = ", ".join(f"{d}/ ({unrecognised[d]} file(s))" for d in dirs[:10])
    return ScanWarning(
        code="AGENT_DIR_UNRECOGNISED",
        message=(f"Agent configuration director{'y' if len(dirs) == 1 else 'ies'} with files Kodand "
                 f"doesn't recognise as an agent artifact: {shown} — they were not scanned."),
        path=dirs[0],
    )


def inventory_repository(path):
    root = validate_repository(path)
    walk = walk_repository(root)
    inv = RepositoryInventory(repository_name=root.name, repository_root=str(root), files_examined=len(walk.files),
                              directories_examined=walk.directories_examined, excluded_paths=walk.excluded_paths)
    inv.platforms = detect_platforms(root, walk.files)
    for path2, msg in walk.errors:
        inv.warnings.append(ScanWarning(code="WALK_ERROR", message=msg, path=path2))
    for e in [p for p in walk.files if p.is_file()]:
        match = _match_entrypoint(e, root)
        if not match:
            continue
        spec, rel = match
        platform, ext_type = spec.platform, spec.extension_type
        raw_text = e.read_text(errors="replace")
        pa = spec.parser(raw_text)
        owns_folder = _owns_folder(e, spec, Path(root))
        sup = [build_artifact(x, root) for x in iter_tree(e.parent)
               if x != e and (x.is_file() or x.is_symlink())] if owns_folder else []
        root_path = e.parent.relative_to(root).as_posix()
        skill_rel_map = {_skill_relative(sf.relative_path, root_path): sf.relative_path for sf in sup}
        undeclared = [skill_rel_map[x] for x in find_undeclared_files(raw_text, list(skill_rel_map))]
        # the entrypoint may reference itself by name (e.g. "see SKILL.md above") —
        # that's never a broken reference, so it's a known file for this check only
        broken = find_broken_references(raw_text, e.parent, [*skill_rel_map, e.name])
        # referenced from the entrypoint, inside the repo but outside its folder: scanned too
        external = [r for r in find_external_references(raw_text, e.parent, Path(root), bundle=owns_folder)
                    if r not in skill_rel_map.values() and r != rel]
        broken = [b for b in broken if not any(x.endswith(b.lstrip("./")) for x in external)]
        inv.extensions.append(AgentExtension(
            extension_id=platform + '-' + hashlib.sha256(rel.encode()).hexdigest()[:16], platform=platform,
            extension_type=ext_type, root_path=root_path, entrypoint=rel, metadata=pa.metadata,
            instruction_line_count=len(pa.body.splitlines()), supporting_files=sup, parse_errors=pa.errors,
            undeclared_supporting_files=sorted(undeclared), broken_references=broken, referenced_files=external))
    for warning in (_coverage_gap_warning(walk.files, root, inv.extensions),
                    _agent_dir_warning(walk.files, root, inv.extensions)):
        if warning:
            inv.warnings.append(warning)
    return inv
