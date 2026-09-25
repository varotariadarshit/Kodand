import hashlib

from kodand.adapters.claude.frontmatter import parse_skill_text
from kodand.adapters.claude.json_config import parse_hook_settings, parse_mcp_config
from kodand.adapters.common import parse_generic_markdown
from kodand.core.artifacts import build_artifact
from kodand.core.repository import validate_repository, walk_repository
from kodand.models.inventory import AgentExtension, RepositoryInventory, ScanWarning
from kodand.platforms import detect_platforms
from kodand.relationships import find_broken_references, find_undeclared_files


def _skill_relative(path: str, root_path: str) -> str:
    prefix = root_path + "/"
    return path[len(prefix):] if root_path not in ("", ".") and path.startswith(prefix) else path

# (platform, extension_type, parser, matcher(name_lower, rel_posix_lower) -> bool)
# Order matters only in that patterns are mutually exclusive by construction.
ENTRYPOINTS = [
    ("claude-code", "agent-skill", parse_skill_text,
     lambda name, rel: name in {"skill.md", "skills.md"}),
    ("gemini-cli", "agent-context", parse_generic_markdown,
     lambda name, rel: name == "gemini.md"),
    ("microsoft-copilot", "agent-instructions", parse_generic_markdown,
     lambda name, rel: rel == ".github/copilot-instructions.md"
     or (name.endswith(".instructions.md") and rel.startswith(".github/instructions/"))),
    ("chatgpt-openai", "agent-context", parse_generic_markdown,
     lambda name, rel: name == "agents.md"),
    ("cursor", "agent-rule", parse_generic_markdown,
     lambda name, rel: name.endswith(".mdc") and rel.startswith(".cursor/rules/")),
    ("windsurf", "agent-rule", parse_generic_markdown,
     lambda name, rel: name == ".windsurfrules"),
    ("claude-code", "mcp-config", parse_mcp_config,
     lambda name, rel: name in {".mcp.json", "mcp.json", "claude_desktop_config.json"}),
    ("claude-code", "hook-config", parse_hook_settings,
     lambda name, rel: rel in {".claude/settings.json", ".claude/settings.local.json"}),
]


def _match_entrypoint(path, root):
    rel = path.relative_to(root).as_posix()
    name = path.name.lower()
    rel_low = rel.lower()
    for platform, ext_type, parser, matcher in ENTRYPOINTS:
        if matcher(name, rel_low):
            return platform, ext_type, parser, rel
    return None


# Distinctive entrypoint basenames worth a coverage sanity-check — deliberately excludes
# hook config names (settings.json/settings.local.json), which are too generic (common in
# unrelated JS/web projects) to name-match without heavy false positives.
_ENTRYPOINT_NAME_HINTS = {"skill.md", "skills.md", "gemini.md", "agents.md",
                          ".mcp.json", "mcp.json", "claude_desktop_config.json",
                          ".windsurfrules"}
_ENTRYPOINT_SUFFIX_HINTS = (".instructions.md", ".mdc")


def _looks_like_entrypoint(name: str) -> bool:
    name = name.lower()
    return name in _ENTRYPOINT_NAME_HINTS or name.endswith(_ENTRYPOINT_SUFFIX_HINTS)


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


def inventory_repository(path):
 root=validate_repository(path);walk=walk_repository(root);inv=RepositoryInventory(repository_name=root.name,repository_root=str(root),files_examined=len(walk.files),directories_examined=walk.directories_examined,excluded_paths=walk.excluded_paths);inv.platforms=detect_platforms(root,walk.files)
 for path2,msg in walk.errors:inv.warnings.append(ScanWarning(code="WALK_ERROR",message=msg,path=path2))
 for e in [p for p in walk.files if p.is_file()]:
  match=_match_entrypoint(e,root)
  if not match:continue
  platform,ext_type,parser,rel=match
  raw_text=e.read_text(errors="replace")
  pa=parser(raw_text);sup=[build_artifact(x,root) for x in e.parent.rglob('*') if x!=e and (x.is_file() or x.is_symlink())]
  root_path=e.parent.relative_to(root).as_posix()
  skill_rel_map={_skill_relative(sf.relative_path,root_path):sf.relative_path for sf in sup}
  undeclared=[skill_rel_map[x] for x in find_undeclared_files(raw_text,list(skill_rel_map))]
  # the entrypoint may reference itself by name (e.g. "see SKILL.md above") —
  # that's never a broken reference, so it's a known file for this check only
  broken=find_broken_references(raw_text,e.parent,[*skill_rel_map,e.name])
  inv.extensions.append(AgentExtension(extension_id=platform+'-'+hashlib.sha256(rel.encode()).hexdigest()[:16],platform=platform,extension_type=ext_type,root_path=root_path,entrypoint=rel,metadata=pa.metadata,instruction_line_count=len(pa.body.splitlines()),supporting_files=sup,parse_errors=pa.errors,undeclared_supporting_files=sorted(undeclared),broken_references=broken))
 gap=_coverage_gap_warning(walk.files,root,inv.extensions)
 if gap:inv.warnings.append(gap)
 return inv
