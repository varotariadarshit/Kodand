from __future__ import annotations

import colorsys
import hashlib
import json
import os
from pathlib import Path

# Three independent, non-overlapping taxonomies. AST0x is Kodand's own "Agentic
# Skills Top 10" (skill/instruction-file risks). MCP0x is the published OWASP
# MCP Top 10 (2025) — see https://owasp.org/www-project-mcp-top-10/ — used for
# MCP server config findings. HOOK0x is Kodand's own "Hooks Top 10", modeled the
# same way as AST0x, for Claude Code hook-config findings. A category code is
# never reused across taxonomies, and a rule belongs to exactly one.
AST_NAMES = {"AST01":"Malicious Skills","AST02":"Supply Chain Compromise","AST03":"Over-Privileged Skills","AST04":"Insecure Metadata and Parsing","AST05":"Untrusted External Instructions","AST06":"Weak Isolation","AST07":"Update and Version Drift","AST08":"Insufficient Scanning","AST09":"Governance and Approval Gaps","AST10":"Cross-Platform Reuse"}
AST_COLORS = {"AST01":"#ef4444","AST02":"#f97316","AST03":"#f59e0b","AST04":"#eab308","AST05":"#84cc16","AST06":"#22c55e","AST07":"#14b8a6","AST08":"#06b6d4","AST09":"#3b82f6","AST10":"#8b5cf6"}
AST_ORDER = [f"AST0{i}" for i in range(1, 10)] + ["AST10"]

MCP_NAMES = {
    "MCP01": "Token Mismanagement and Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks and Dependency Tampering",
    "MCP05": "Command Injection and Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication and Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection and Over-Sharing",
}
MCP_COLORS = {
    "MCP01": "#a855f7", "MCP02": "#c026d3", "MCP03": "#db2777", "MCP04": "#e11d48",
    "MCP05": "#ea580c", "MCP06": "#ca8a04", "MCP07": "#65a30d", "MCP08": "#059669",
    "MCP09": "#0891b2", "MCP10": "#4f46e5",
}
MCP_ORDER = [f"MCP0{i}" for i in range(1, 10)] + ["MCP10"]

HOOK_NAMES = {
    "HOOK01": "Unscoped Wildcard Trigger",
    "HOOK02": "Arbitrary Shell Execution in Hook Command",
    "HOOK03": "Silent Network Exfiltration via Hook",
    "HOOK04": "Approval and Permission Bypass via Hook",
    "HOOK05": "Undeclared or Hidden Hook Definition",
    "HOOK06": "Hook Persistence and Config Tampering",
    "HOOK07": "Privilege Escalation via Hook Context",
    "HOOK08": "Sensitive File or Credential Access via Hook",
    "HOOK09": "Resource Abuse and Denial of Service via Hook",
    "HOOK10": "Unverified or Remote Hook Script Source",
}
HOOK_COLORS = {
    "HOOK01": "#78716c", "HOOK02": "#57534e", "HOOK03": "#0d9488", "HOOK04": "#0369a1",
    "HOOK05": "#6d28d9", "HOOK06": "#a16207", "HOOK07": "#b91c1c", "HOOK08": "#15803d",
    "HOOK09": "#525252", "HOOK10": "#334155",
}
HOOK_ORDER = [f"HOOK0{i}" for i in range(1, 10)] + ["HOOK10"]

TAXONOMIES = {
    "AST": {"label": "Agentic Skills Top 10", "names": AST_NAMES, "colors": AST_COLORS, "order": AST_ORDER},
    "MCP": {"label": "OWASP MCP Top 10 (2025)", "names": MCP_NAMES, "colors": MCP_COLORS, "order": MCP_ORDER},
    "HOOK": {"label": "Hooks Top 10", "names": HOOK_NAMES, "colors": HOOK_COLORS, "order": HOOK_ORDER},
}

BUILTIN_NAMES = {**AST_NAMES, **MCP_NAMES, **HOOK_NAMES}
BUILTIN_COLORS = {**AST_COLORS, **MCP_COLORS, **HOOK_COLORS}
BUILTIN_ORDER = AST_ORDER + MCP_ORDER + HOOK_ORDER


def taxonomy_of(code: str) -> str:
    """Which of AST/MCP/HOOK a category code belongs to, or "" for an unknown/custom code."""
    code = code.upper()
    for prefix, t in TAXONOMIES.items():
        if code in t["names"]:
            return prefix
    return ""


def _registry_path() -> Path:
    root = Path(os.environ.get("KODAND_HOME", str(Path.home() / ".kodand"))); root.mkdir(parents=True, exist_ok=True); return root / "categories.json"
def load_registry() -> dict:
    p=_registry_path()
    if not p.exists(): return {}
    try: return json.loads(p.read_text()) or {}
    except Exception: return {}
def register_category(code: str, name: str) -> None:
    code=code.strip().upper()
    if code in BUILTIN_NAMES: return
    reg=load_registry(); reg[code]={"name": name or code}; _registry_path().write_text(json.dumps(reg, indent=2), encoding="utf-8")
def _deterministic_color(code: str) -> str:
    h=int(hashlib.sha256(code.encode()).hexdigest(),16); hue=(h%360)/360.0
    r,g,b=colorsys.hls_to_rgb(hue,0.62,0.62); return "#%02x%02x%02x"%(int(r*255),int(g*255),int(b*255))
def category_name(code: str) -> str:
    code=code.upper()
    if code in BUILTIN_NAMES: return BUILTIN_NAMES[code]
    return load_registry().get(code,{}).get("name",code)
def category_color(code: str) -> str:
    code=code.upper()
    if code in BUILTIN_COLORS: return BUILTIN_COLORS[code]
    return _deterministic_color(code)
def ordered_categories(extra=None) -> list:
    cats=list(BUILTIN_ORDER); seen=set(cats)
    for c in sorted(load_registry().keys()):
        if c not in seen: cats.append(c); seen.add(c)
    for c in (extra or []):
        c=c.upper()
        if c not in seen: cats.append(c); seen.add(c)
    return cats
