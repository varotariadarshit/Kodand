"""Cross-file relationship checks for a skill's entrypoint (SKILL.md et al.):
does its prose actually name the supporting files sitting next to it, and do
its references resolve to real files? Two directions, both heuristic —
candidate signals for human review, same spirit as every other Kodand finding.
"""
from __future__ import annotations

import re
from pathlib import Path

_BACKTICK_RE = re.compile(r"`([^`\n]{1,300})`")
_MD_LINK_RE = re.compile(r"\]\(([^)\s]{1,300})\)")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_PATH_CHAR = r"[\w./-]"
KNOWN_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".ts", ".sh", ".ps1", ".yaml", ".yml",
    ".json", ".toml", ".csv", ".html", ".pdf", ".docx", ".xlsx",
}


def _looks_like_path(s: str) -> bool:
    s = s.strip().strip("'\"")
    if not s or " " in s or "\n" in s:
        return False
    if "/" in s:
        # a real file/dir reference either ends the path with a filename
        # that has a dot (an extension) or ends in '/' (a directory) — this
        # excludes domain/product-name mentions like 'example.com/feature'
        # that merely contain a slash (confirmed as a real false positive
        # against a live sample skill package: 'thirtysix.net/smartdocs')
        last = s.rsplit("/", 1)[-1]
        return last == "" or "." in last
    return Path(s).suffix.lower() in KNOWN_EXTENSIONS


def extract_referenced_paths(text: str) -> set[str]:
    """Backtick spans and markdown link targets that look like file paths."""
    candidates: set[str] = set()
    for m in _BACKTICK_RE.findall(text) + _MD_LINK_RE.findall(text):
        m = m.strip().strip("'\"")
        if _looks_like_path(m):
            candidates.add(m)
    return candidates


def _mentioned(needle: str, text: str) -> bool:
    """Whole-token substring match: `needle` must not be embedded inside a
    longer path/filename (e.g. 'template-analysis.md' inside
    'word-proposal-template-analysis.md' doesn't count — those are different
    files, confirmed as a real false-positive-shaped case against a live
    sample skill package)."""
    pattern = re.compile(rf"(?<!{_PATH_CHAR}){re.escape(needle)}(?!{_PATH_CHAR})")
    return pattern.search(text) is not None


def find_undeclared_files(entrypoint_text: str, supporting_relative_paths: list[str]) -> list[str]:
    """Supporting files (skill-relative paths) never named anywhere in the
    entrypoint's raw text — neither by full path nor by filename alone.

    Known limitation: a file referenced only under a different/similar name
    still shows up here. Accepted — candidate signal for human review, not a
    hard failure.
    """
    undeclared = [
        rel for rel in supporting_relative_paths
        if not _mentioned(rel, entrypoint_text) and not _mentioned(Path(rel).name, entrypoint_text)
    ]
    return sorted(undeclared)


def find_broken_references(entrypoint_text: str, root_path: Path, supporting_relative_paths: list[str]) -> list[str]:
    """References extracted from the entrypoint's text that match no known
    supporting file and don't resolve to a real file under the skill's root.
    Absolute paths and URLs are skipped (e.g. cross-skill `/mnt/skills/...`
    references) — intentionally outside this skill's own package.
    """
    # case-insensitive: a doc casually referencing its own entrypoint or a
    # supporting file with different casing (e.g. `SKILL.md` vs the actual
    # `SKILL.MD` on disk) isn't a broken reference, just a harmless typo
    supporting_set = {p.lower() for p in supporting_relative_paths}
    basenames = {Path(p).name.lower() for p in supporting_relative_paths}
    broken = []
    for ref in extract_referenced_paths(entrypoint_text):
        if ref.startswith("/") or _URL_RE.match(ref):
            continue
        if ref.lower() in supporting_set or Path(ref).name.lower() in basenames:
            continue
        if (root_path / ref).exists():
            continue
        broken.append(ref)
    return sorted(broken)


if __name__ == "__main__":
    import tempfile

    text = ("See `scripts/run.py`, [mapping](references/map.md), and "
            "`references/ghost.md` which doesn't exist.")
    assert extract_referenced_paths(text) == {"scripts/run.py", "references/map.md", "references/ghost.md"}
    assert find_undeclared_files(text, ["scripts/run.py", "references/orphan.md"]) == ["references/orphan.md"]
    # a real false-positive-shaped case: 'analysis.md' must not count as declared
    # just because it's embedded inside the unrelated 'word-proposal-analysis.md'
    collision_text = "see that skill's `references/word-proposal-analysis.md` for details"
    assert find_undeclared_files(collision_text, ["references/analysis.md"]) == ["references/analysis.md"]
    # a domain/product mention with a slash isn't a file path
    assert "thirtysix.net/smartdocs" not in extract_referenced_paths("open `thirtysix.net/smartdocs` and load a template")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "scripts").mkdir(); (root / "scripts" / "run.py").write_text("x")
        (root / "references").mkdir(); (root / "references" / "map.md").write_text("x")
        broken = find_broken_references(text, root, ["scripts/run.py", "references/map.md"])
        assert broken == ["references/ghost.md"], broken
    print("relationships.py self-check OK")
