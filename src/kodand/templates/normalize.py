"""Encoding / obfuscation normalization (Track A #7).

Before matching, Kodand v3 additionally scans *decoded* views of a line so that
payloads hidden with base64 / hex / URL-encoding, or split with zero-width /
homoglyph characters, are still caught. Decoded segments are attributed to the
original line with match_kind="decoded" and decoded_from set to the scheme.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

# Zero-width and BOM-like characters used to break up keywords
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

# Common homoglyphs -> ASCII
_HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0501": "d", "\u04bb": "h",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o",
}

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}){8,}")
_URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")


def strip_obfuscation(text: str) -> str:
    """Remove zero-width chars and fold homoglyphs to ASCII."""
    t = text.translate(_ZERO_WIDTH)
    if any(ch in _HOMOGLYPHS for ch in t):
        t = "".join(_HOMOGLYPHS.get(ch, ch) for ch in t)
    return t


def _try_b64(s: str) -> str | None:
    try:
        pad = s + "=" * (-len(s) % 4)
        raw = base64.b64decode(pad, validate=True)
        dec = raw.decode("utf-8", "ignore")
        if dec and sum(c.isprintable() for c in dec) / max(len(dec), 1) > 0.8:
            return dec
    except (binascii.Error, ValueError):
        return None
    return None


def _try_hex(s: str) -> str | None:
    h = s[2:] if s.lower().startswith("0x") else s
    if len(h) % 2:
        return None
    try:
        dec = bytes.fromhex(h).decode("utf-8", "ignore")
        if dec and sum(c.isprintable() for c in dec) / max(len(dec), 1) > 0.8:
            return dec
    except ValueError:
        return None
    return None


def decoded_variants(line: str) -> list[tuple[str, str]]:
    """Return list of (decoded_text, scheme) for encoded blobs found in the line."""
    out: list[tuple[str, str]] = []
    for m in _B64.finditer(line):
        d = _try_b64(m.group(0))
        if d and d != m.group(0):
            out.append((d, "base64"))
    for m in _HEX.finditer(line):
        d = _try_hex(m.group(0))
        if d:
            out.append((d, "hex"))
    for m in _URLENC.finditer(line):
        try:
            d = urllib.parse.unquote(m.group(0))
            if d and d != m.group(0):
                out.append((d, "url"))
        except Exception:
            pass
    return out


def normalized_views(line: str) -> list[tuple[str, str | None]]:
    """All views to scan for a line: the de-obfuscated raw line plus decoded blobs.

    Returns list of (text, decoded_from) where decoded_from is None for the
    primary de-obfuscated line.
    """
    views: list[tuple[str, str | None]] = []
    base = strip_obfuscation(line)
    views.append((base, None))
    for dec, scheme in decoded_variants(line):
        views.append((strip_obfuscation(dec), scheme))
    return views
