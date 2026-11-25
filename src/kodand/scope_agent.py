"""Kodand Agent scope crawl: the pure, store-free half.

The static registry (kodand.entrypoints) decides scope first. When a Kodand Agent worker is
running, the console then has it crawl every other text file in the scan's snapshot, in small
batches (one fresh `claude -p` session each), and ADD files that are agent content the static
pass missed. Nothing here talks to Claude or the workspace; it plans the batches, reads file
heads safely, validates what the agent reports, and derives learning suggestions so an approved
location/extension lets the static scanner find the same file next time on its own.

Security model: the crawler reads untrusted files, so everything it returns is validated here —
it can only add, only files from the batch it was given, only regular non-symlink files inside the
snapshot, only with an agent-content type. Scope never shrinks because of anything it says.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from kodand.adapters.claude.frontmatter import parse_skill_text
from kodand.adapters.claude.json_config import parse_hook_settings, parse_mcp_config
from kodand.adapters.common import parse_generic_markdown
from kodand.core.repository import iter_tree
from kodand.entrypoints import EntrypointSpec, match_entrypoint, path_matches
from kodand.templates.matcher import decode_text

# bump when the crawl prompt or the type set changes: cached verdicts from an older prompt are re-crawled
PROMPT_VERSION = "1"
AGENT_PLATFORM = "kodand-agent"
BATCH_FILES = 25
BATCH_BYTES = 60_000
HEAD_BYTES = 2_000
MAX_REASON = 300
MAX_ADDITIONS_PER_BATCH = BATCH_FILES
MAX_PATTERN_MATCHES = 100  # a learned location matching more files than this in one repo is too broad

# agent-content types the crawler may report -> (extension_type, parser). Nothing else is accepted:
# application source, tests, data, CI and docs about the app are not agent content.
AGENT_FILE_TYPES: dict[str, tuple[str, object]] = {
    "skill": ("agent-skill", parse_skill_text),
    "instructions": ("agent-instructions", parse_generic_markdown),
    "prompt": ("agent-prompt", parse_generic_markdown),
    "subagent": ("agent-subagent", parse_generic_markdown),
    "mcp-config": ("mcp-config", parse_mcp_config),
    "hook-config": ("hook-config", parse_hook_settings),
    "agent-script": ("agent-script", parse_generic_markdown),
}
_EXT_TYPE_TO_KIND = {v[0]: k for k, v in AGENT_FILE_TYPES.items()}


def spec_for(file_type: str, platform: str = AGENT_PLATFORM, patterns: tuple[str, ...] = ()) -> EntrypointSpec:
    """An EntrypointSpec for an agent-added (or learned) file of `file_type`. Never a bundle: an added
    file is scanned on its own (every other file in its folder is crawled and judged separately),
    so one wrong classification can't pull a whole directory — let alone the repo — into scope."""
    ext_type, parser = AGENT_FILE_TYPES[file_type]
    return EntrypointSpec(platform, ext_type, parser, patterns)


def kind_for_extension_type(ext_type: str) -> str | None:
    return _EXT_TYPE_TO_KIND.get(ext_type)


# --- planning -------------------------------------------------------------------

@dataclass
class CrawlPlan:
    batches: list[list[str]] = field(default_factory=list)
    total: int = 0              # files outside the static scope
    binary: int = 0             # skipped: not text
    cached: int = 0             # verdict reused from an earlier crawl of the same content
    cached_additions: list[dict] = field(default_factory=list)
    shas: dict[str, str] = field(default_factory=dict)
    all_files: list[str] = field(default_factory=list)  # every regular file in the snapshot (pattern checks)

    @property
    def to_crawl(self) -> int:
        return sum(len(b) for b in self.batches)


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cache_key(rel: str, sha: str) -> str:
    return f"{PROMPT_VERSION}:{rel}:{sha}"


def plan_crawl(root: Path, in_scope: set[str], cache: dict | None = None, *,
               batch_files: int = BATCH_FILES, batch_bytes: int = BATCH_BYTES) -> CrawlPlan:
    """Every regular, non-binary file under `root` that the static pass didn't already put in
    scope, minus those whose (path, content) verdict is cached, grouped into batches."""
    root = Path(root)
    cache = cache or {}
    plan = CrawlPlan()
    pending: list[tuple[str, int]] = []
    for p in iter_tree(root):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        plan.all_files.append(rel)
        if rel in in_scope:
            continue
        plan.total += 1
        try:
            with open(p, "rb") as fh:
                head = fh.read(8192)
            size = p.stat().st_size
        except OSError:
            continue
        if decode_text(head) is None:
            plan.binary += 1
            continue
        sha = file_sha256(p)
        plan.shas[rel] = sha
        hit = cache.get(cache_key(rel, sha))
        if hit is not None:
            plan.cached += 1
            if hit.get("add") and hit.get("type") in AGENT_FILE_TYPES:
                plan.cached_additions.append({"path": rel, "type": hit["type"], "reason": hit.get("reason", ""),
                                              "suggested_pattern": hit.get("suggested_pattern")})
            continue
        pending.append((rel, min(size, HEAD_BYTES) + len(rel) + 64))
    batch: list[str] = []
    used = 0
    for rel, cost in sorted(pending):
        if batch and (len(batch) >= batch_files or used + cost > batch_bytes):
            plan.batches.append(batch)
            batch, used = [], 0
        batch.append(rel)
        used += cost
    if batch:
        plan.batches.append(batch)
    return plan


# --- reading for the agent ----------------------------------------------------------

def _contained(root: Path, rel: str) -> Path | None:
    """`root/rel` if it is a regular, non-symlink file inside root (resolved), else None."""
    if not isinstance(rel, str) or not rel or rel.startswith(("/", "\\")) or "\x00" in rel:
        return None
    root = Path(root).resolve()
    cand = root / rel
    try:
        if cand.is_symlink():
            return None
        target = cand.resolve()  # a symlinked parent dir resolves outside or is caught below
    except (OSError, RuntimeError, ValueError):
        return None
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return target


def read_head(root: Path, rel: str, max_bytes: int = HEAD_BYTES) -> str | None:
    target = _contained(root, rel)
    if target is None:
        return None
    try:
        with open(target, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return None
    return decode_text(data)


def batch_payload(root: Path, paths: list[str], max_bytes: int = HEAD_BYTES) -> list[dict]:
    out = []
    for rel in paths:
        target = _contained(root, rel)
        if target is None:
            continue
        size = target.stat().st_size
        out.append({"path": rel, "size": size, "head": read_head(root, rel, max_bytes) or "",
                    "truncated": size > max_bytes})
    return out


# --- validating what the agent reports ---------------------------------------------------

def _norm_rel(path) -> str | None:
    if not isinstance(path, str):
        return None
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p or None


def validate_additions(root: Path, batch_paths, additions) -> tuple[list[dict], list[dict]]:
    """(accepted, rejected). Accepted: in this batch, a real file inside the snapshot, a known
    agent-content type, a non-empty reason. The agent can't widen its own reach: a path outside
    its batch (another batch's file, `/etc/passwd`, `../x`) is rejected, whatever the file says."""
    allowed = set(batch_paths)
    accepted, rejected, seen = [], [], set()
    if not isinstance(additions, list):
        return [], [{"item": str(additions)[:200], "why": "additions must be a list"}]
    for item in additions[:MAX_ADDITIONS_PER_BATCH * 2]:
        if not isinstance(item, dict):
            rejected.append({"item": str(item)[:200], "why": "not an object"})
            continue
        rel = _norm_rel(item.get("path"))
        ftype = item.get("type")
        reason = item.get("reason")
        why = None
        if rel is None or rel not in allowed:
            why = "path is not in this batch"
        elif ftype not in AGENT_FILE_TYPES:
            why = f"type must be one of {', '.join(AGENT_FILE_TYPES)}"
        elif not isinstance(reason, str) or not reason.strip():
            why = "a reason is required"
        elif _contained(root, rel) is None:
            why = "not a regular file inside the snapshot"
        elif rel in seen:
            why = "duplicate"
        if why:
            rejected.append({"item": str(item.get("path"))[:200], "why": why})
            continue
        seen.add(rel)
        pat = item.get("suggested_pattern")
        accepted.append({"path": rel, "type": ftype, "reason": " ".join(reason.split())[:MAX_REASON],
                         "suggested_pattern": pat[:200] if isinstance(pat, str) else None})
        if len(accepted) >= MAX_ADDITIONS_PER_BATCH:
            break
    return accepted, rejected


# --- learning suggestions -------------------------------------------------------------

GENERIC_DIRS = frozenset({
    "src", "lib", "app", "apps", "test", "tests", "spec", "specs", "docs", "doc", "packages", "pkg",
    "internal", "config", "configs", "data", "public", "static", "assets", "frontend", "backend",
    "server", "client", "web", "scripts", "tools", "bin", "build", "dist", "vendor", "examples",
    "example", "routes", "models", "views", "components", "utils", "util", "common", "shared", "core",
    "main", "resources", "res", "fixtures", "cmd", "api", "modules", "node_modules",
})
GENERIC_FILES = frozenset({
    "readme.md", "readme", "index.md", "index.js", "index.ts", "license", "license.md", "changelog.md",
    "contributing.md", "package.json", "config.json", "settings.json", "config.yml", "config.yaml",
    "main.py", "__init__.py", "setup.py", "makefile", "dockerfile",
})
_PAT_SEG = re.compile(r"^(?:\*\*|[a-z0-9._*-]{1,80})$")
_EXT_RE = re.compile(r"^\.[a-z0-9][a-z0-9_-]{0,15}$")
_NAME_RE = re.compile(r"^\.?[a-z0-9][a-z0-9._-]{0,63}$")


def validate_extension(value: str) -> str | None:
    v = (value or "").strip().lower()
    return v if _EXT_RE.match(v) else None


def validate_name(value: str) -> str | None:
    """An extensionless file name (`playbook`, `.assistantrc`)."""
    v = (value or "").strip().lower()
    return v if _NAME_RE.match(v) and not PurePosixPath(v).suffix else None


def validate_location_pattern(pattern, rel: str | None = None) -> str | None:
    """A registry-style pattern (lowercase, `/`-separated, `*` and `**`) specific enough to learn:
    it has a literal, non-generic directory (`.assistant/playbooks/**/*.md`) or a distinctive literal
    basename, and is not a catch-all (`*.md`, `**/*`, `src/**`). With `rel`, it must match it."""
    if not isinstance(pattern, str):
        return None
    p = pattern.strip().strip("/").lower()
    if not p or len(p) > 200:
        return None
    segs = p.split("/")
    if len(segs) > 8 or not all(_PAT_SEG.match(s) for s in segs):
        return None
    dirs, last = segs[:-1], segs[-1]
    if last == "**":
        return None
    literal_dirs = [s for s in dirs if "*" not in s and s not in GENERIC_DIRS]
    distinctive_last = "*" not in last and last not in GENERIC_FILES and len(last) >= 5
    if not literal_dirs and not distinctive_last:
        return None
    if rel is not None and not path_matches(rel.lower(), tuple(segs)):
        return None
    return p


def derive_location_pattern(rel: str) -> str | None:
    """`.assistant/playbooks/deploy.md` -> `.assistant/playbooks/**/*.md`: anchored at the first dot
    directory (else the first non-generic one), any depth below it, same suffix."""
    segs = rel.lower().split("/")
    dirs, name = segs[:-1], segs[-1]
    anchor = next((i for i, d in enumerate(dirs) if d.startswith(".")), None)
    if anchor is None:
        anchor = next((i for i, d in enumerate(dirs) if d not in GENERIC_DIRS), None)
    suffix = PurePosixPath(name).suffix
    if anchor is None:
        return validate_location_pattern(name, rel)
    tail = f"*{suffix}" if suffix else name
    return validate_location_pattern("/".join(dirs[anchor:]) + "/**/" + tail, rel)


def pattern_match_count(pattern: str, rels) -> int:
    segs = tuple(pattern.split("/"))
    return sum(1 for r in rels if path_matches(r.lower(), segs))


def suggestions_for(addition: dict, *, scannable, extra_specs=(), repo_files=()) -> list[dict]:
    """What the static scanner would need to find this agent-added file on its own next time:
    an `extension` (or extensionless `name`) it doesn't scan today, and/or a `location` pattern
    the registry doesn't match. `scannable(rel) -> bool` is the scan's is_scannable."""
    rel, ftype = addition["path"], addition["type"]
    out = []
    path = PurePosixPath(rel)
    if not scannable(rel):
        if path.suffix:
            ext = validate_extension(path.suffix)
            if ext:
                out.append({"kind": "extension", "value": ext})
        else:
            name = validate_name(path.name)
            if name:
                out.append({"kind": "name", "value": name})
    if match_entrypoint(rel, tuple(extra_specs)) is None:
        pat = None
        if addition.get("suggested_pattern"):
            pat = validate_location_pattern(addition["suggested_pattern"], rel)
        pat = pat or derive_location_pattern(rel)
        if pat and (not repo_files or pattern_match_count(pat, repo_files) <= MAX_PATTERN_MATCHES):
            out.append({"kind": "location", "value": pat, "extension_type": AGENT_FILE_TYPES[ftype][0]})
    for s in out:
        s.update(example=rel, reason=addition.get("reason", ""), type=ftype)
    return out
