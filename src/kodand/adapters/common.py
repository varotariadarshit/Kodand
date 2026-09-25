from dataclasses import dataclass, field

import yaml

from kodand.models.inventory import SkillMetadata


@dataclass
class Parsed:
    metadata: SkillMetadata = field(default_factory=SkillMetadata)
    body: str = ""
    errors: list[str] = field(default_factory=list)


def split_frontmatter(text, require_frontmatter=False):
    """Split a `---\\nYAML\\n---\\nbody` document into (frontmatter_dict, body, errors).

    Returns (None, text, []) for plain text with no frontmatter block, unless
    `require_frontmatter` is set (Claude's SKILL.md format mandates it; most
    other platforms' instruction files don't).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return (None, text, ["Missing YAML frontmatter"]) if require_frontmatter else (None, text, [])
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return None, text, ["Unterminated YAML frontmatter"]
    try:
        raw = yaml.safe_load("\n".join(lines[1:end])) or {}
    except yaml.YAMLError as e:
        return None, text, [f"Malformed YAML frontmatter: {e}"]
    if not isinstance(raw, dict):
        return None, text, ["YAML frontmatter must be a mapping"]
    return raw, "\n".join(lines[end + 1:]), []


def parse_generic_markdown(text):
    """Parser for platforms whose instruction files are plain markdown with, at
    most, a simple `name`/`description` frontmatter (Gemini's GEMINI.md, AGENTS.md,
    Copilot's copilot-instructions.md/*.instructions.md, Cursor's *.mdc,
    Windsurf's .windsurfrules). Frontmatter is optional; any other fields
    (e.g. Cursor's `globs`/`alwaysApply`, Copilot's `applyTo`) are preserved
    in `additional_fields` rather than being dropped."""
    o = Parsed(body=text)
    raw, body, errors = split_frontmatter(text, require_frontmatter=False)
    o.errors = errors
    o.body = body
    if raw:
        known = {"name", "description"}
        o.metadata = SkillMetadata(name=raw.get("name"), description=raw.get("description"),
                                   additional_fields={k: v for k, v in raw.items() if k not in known})
    return o
