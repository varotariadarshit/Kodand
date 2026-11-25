"""Shared helpers for hardcoded-credential checks (Python/JS AST, markdown fences)."""
import re

# key names that hold a credential when they're an object/dict key or keyword arg —
# stricter than the variable-name check (no bare "key": `{key: 'id'}` is everywhere)
CREDENTIAL_KEY_RE = re.compile(
    r"^(?:.*[_-])?(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)$",
    re.IGNORECASE)

# obvious template/placeholder values: never a real credential. Deliberately does NOT
# include "dummy"/"fake"/"test" — a working hardcoded value is a finding regardless
_PLACEHOLDER_RE = re.compile(
    r"^\s*$|[<>]|\$\{|\{\{|%\(|^\$[A-Z_]|^(?:x+|\*+|\.+|-+|_+)$|your[_ -]|changeme|change[_-]me|placeholder|"
    r"redacted|^none$|^null$|^undefined$|^env\b|process\.env|os\.environ",
    re.IGNORECASE)


def is_credential_key(name: str) -> bool:
    return bool(CREDENTIAL_KEY_RE.match(name.strip("'\"` ")))


def looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value))
