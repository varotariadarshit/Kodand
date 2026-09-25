"""Hidden-text detection over a file's raw text.

Template matching runs on normalized views, which strip zero-width characters
so split keywords still match (see templates/normalize.py). That same step makes
the hiding itself invisible to templates, so it is detected here instead: raw
zero-width / bidi-control / Unicode tag characters, and the same characters
written as HTML entities (which render invisibly in a markdown viewer).
"""
from __future__ import annotations

import re

from kodand.redaction import redact
from kodand.templates.confidence import calculate_confidence
from kodand.templates.matcher import TemplateMatch

RULE_ID = "AST08-HIDDEN-UNICODE"

# zero-width, word joiner/invisible operators, bidi embeddings/overrides/isolates, BOM, tag block
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
_ENTITY = re.compile(
    r"&#(?:x0*(?:200[b-f]|202[a-e]|206[0-46-9]|feff)|0*(?:820[3-7]|823[4-8]|828[89]|829[0-2]|829[4-7]|65279));",
    re.IGNORECASE,
)
_ZWJ = "‍"


def _is_emoji_joiner(line: str, i: int) -> bool:
    # ZWJ between two symbols is how multi-part emoji are built (family, flags) — not hiding
    before = line[i - 1] if i > 0 else ""
    after = line[i + 1] if i + 1 < len(line) else ""
    return bool(before and after) and ord(before) > 0x2000 and ord(after) > 0x2000


def find_hidden_text(text: str, relative_path: str, category: str, base_confidence: str) -> list[TemplateMatch]:
    matches = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        raw = [m for m in _INVISIBLE.finditer(line)
               if not (m.group() == _ZWJ and _is_emoji_joiner(line, m.start()))
               and not (m.group() == "﻿" and line_number == 1 and m.start() == 0)]
        entities = list(_ENTITY.finditer(line))
        hits = raw + entities
        if not hits:
            continue
        first = min(hits, key=lambda m: m.start())
        kind = "HTML-entity" if entities else "raw"
        visible = _INVISIBLE.sub("", _ENTITY.sub("", line)).strip()
        matches.append(TemplateMatch(
            template_id=RULE_ID, category=category,
            severity="high" if len(hits) >= 2 else "medium",
            confidence=calculate_confidence(base_confidence, "instruction"),
            file=relative_path, line=line_number,
            column_start=first.start() + 1, column_end=first.end() + 1,
            matched_value=f"{len(hits)} invisible character(s) ({kind})",
            excerpt=redact(visible[:700]), context="instruction",
            match_kind="hidden-text", decoded_from=None,
        ))
    return matches
