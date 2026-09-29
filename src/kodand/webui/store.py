from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import time
import uuid
from pathlib import Path

import yaml

from kodand.templates.loader import load_templates
from kodand.templates.models import KodandTemplate
from kodand.templates.regexguard import validate_pattern


def workspace_root() -> Path:
    root = Path(os.environ.get("KODAND_HOME", str(Path.home() / ".kodand")))
    if not root.exists():
        # holds the password hash, session tokens, AI provider keys and scanned code: owner-only
        root.mkdir(parents=True, mode=0o700)
    elif os.name != "nt" and root.stat().st_mode & 0o077:
        root.chmod(0o700)
    (root / "projects").mkdir(parents=True, exist_ok=True)
    (root / "custom_templates").mkdir(parents=True, exist_ok=True)
    return root
def _slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).lower()
    s = re.sub(r"\.{2,}", ".", s).strip("-._")[:100]; return s or "project"
def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def projects_dir() -> Path:
    return workspace_root() / "projects"
def list_projects() -> list:
    out = []
    for d in sorted(projects_dir().iterdir() if projects_dir().exists() else []):
        meta = d / "project.json"
        if meta.exists():
            data = json.loads(meta.read_text()); data["scan_count"] = len(list((d/"scans").glob("*"))) if (d/"scans").exists() else 0; out.append(data)
    return sorted(out, key=lambda p: p.get("created", ""), reverse=True)
def create_project(name: str, description: str = "") -> dict:
    pid = f"{_slug(name)}-{uuid.uuid4().hex[:6]}"; d = projects_dir()/pid; (d/"scans").mkdir(parents=True, exist_ok=True)
    data = {"id": pid, "name": name.strip() or pid, "description": (description or "").strip(), "created": _now()}
    (d/"project.json").write_text(json.dumps(data, indent=2)); return data
def delete_project(pid: str) -> bool:
    try:
        d = _project_dir(pid)
    except FileNotFoundError:
        return False
    if d.is_dir():
        shutil.rmtree(d)
        _remove_project_from_registry(pid)
        return True
    return False
def set_project_mcp_sharing(pid: str, shared: bool) -> dict:
    d = _project_dir(pid); meta_path = d/"project.json"
    data = json.loads(meta_path.read_text()); data["mcp_shared"] = bool(shared)
    if shared: data["mcp_shared_since"] = _now()
    meta_path.write_text(json.dumps(data, indent=2)); return data
# Project and scan ids arrive from URLs and MCP tool arguments. Anything but the exact shape
# create_project/new_scan_dir mint is refused, so an id like "../other-project" can never
# walk outside its project — the MCP sharing gate depends on this.
_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}$")
_SCAN_ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")


def _project_dir(pid: str) -> Path:
    if not isinstance(pid, str) or not _PROJECT_ID_RE.match(pid) or ".." in pid:
        raise FileNotFoundError("project not found")
    d = projects_dir()/pid
    if not (d/"project.json").exists(): raise FileNotFoundError("project not found")
    return d
def list_scans(pid: str) -> list:
    d = _project_dir(pid)/"scans"; out = []
    for s in sorted(d.iterdir() if d.exists() else []):
        meta = s/"scan.json"
        if meta.exists(): out.append(json.loads(meta.read_text()))
    return sorted(out, key=lambda x: x.get("created", ""), reverse=True)
def scan_dir(pid: str, sid: str) -> Path:
    if not isinstance(sid, str) or not _SCAN_ID_RE.match(sid):
        raise FileNotFoundError("scan not found")
    return _project_dir(pid)/"scans"/sid
def new_scan_dir(pid: str):
    sid = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex[:4]; sd = _project_dir(pid)/"scans"/sid; (sd/"target").mkdir(parents=True, exist_ok=True); return sid, sd
def save_scan_meta(pid: str, sid: str, meta: dict) -> None:
    sd = scan_dir(pid, sid); sd.mkdir(parents=True, exist_ok=True); (sd/"scan.json").write_text(json.dumps(meta, indent=2))
def delete_scan(pid: str, sid: str) -> bool:
    sd = scan_dir(pid, sid)
    if sd.exists(): shutil.rmtree(sd); return True
    return False
def delete_scan_target(pid: str, sid: str) -> bool:
    """Remove just the raw scanned source (target/), keeping analysis.json/reports/review history intact."""
    t = scan_dir(pid, sid)/"target"
    if t.exists(): shutil.rmtree(t); return True
    return False
def list_scan_files(pid: str, sid: str) -> list:
    target = scan_dir(pid, sid)/"target"
    if not target.exists(): return []
    return [{"path": p.relative_to(target).as_posix(), "size": p.stat().st_size}
            for p in sorted(target.rglob("*")) if p.is_file()]
def get_file_content(pid: str, sid: str, path: str, max_bytes: int = 300_000) -> str:
    target = (scan_dir(pid, sid)/"target").resolve()
    p = (target/path).resolve()
    if (p != target and target not in p.parents) or not p.is_file():
        raise FileNotFoundError("file not found")
    return p.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
def read_scan_files(pid: str, sid: str, paths: list, max_bytes: int = 20_000) -> dict:
    """Best-effort batch read for AI-review context — silently skips missing/deleted/escaping paths."""
    out = {}
    for rel in paths or []:
        try:
            out[rel] = get_file_content(pid, sid, rel, max_bytes=max_bytes)
        except FileNotFoundError:
            continue
    return out
def custom_templates_dir() -> Path:
    return workspace_root()/"custom_templates"
def list_custom_templates() -> list:
    out = []
    for t in load_templates(custom_templates_dir()):
        out.append({"id": t.id, "name": t.info.name, "category": t.info.category, "severity": t.info.severity, "confidence": t.info.confidence, "match": t.detection.match, "regex": getattr(t.detection,"regex",[]), "capabilities": t.capabilities, "recommendation": t.recommendation, "risk_title": t.risk.title})
    return sorted(out, key=lambda x: x["id"])
def builtin_template_ids() -> set:
    from kodand.webui.scan_service import load_builtin_templates
    return {t.id for t in load_builtin_templates()}
_TEMPLATE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_CONFIDENCES = {"high", "medium", "low"}


def add_custom_template(doc: dict) -> dict:
    tpl = KodandTemplate.model_validate(doc)
    # id and category end up in file names, URLs, report markup and badges — keep them plain tokens
    if not _TEMPLATE_TOKEN_RE.match(tpl.id) or not _TEMPLATE_TOKEN_RE.match(tpl.info.category):
        raise ValueError("Template id and category may only contain letters, digits, '.', '_' and '-' (max 80).")
    if tpl.info.severity not in _SEVERITIES or tpl.info.confidence not in _CONFIDENCES:
        raise ValueError(f"Severity must be one of {sorted(_SEVERITIES)} and confidence one of {sorted(_CONFIDENCES)}.")
    for rx in tpl.detection.regex or []:
        ok, reason = validate_pattern(rx)
        if not ok:
            raise ValueError(f"Invalid regex '{rx}': {reason}")
    if tpl.id in builtin_template_ids():
        raise ValueError(f"Template id '{tpl.id}' collides with a built-in template. Use a unique id (e.g. CUSTOM-...).")
    existing = {t["id"] for t in list_custom_templates()}
    fname = re.sub(r"[^a-zA-Z0-9._-]+", "-", tpl.id).strip("-").lower() + ".yaml"; path = custom_templates_dir()/fname
    if tpl.id in existing and not path.exists():
        for f in custom_templates_dir().glob("*.yaml"):
            try:
                if yaml.safe_load(f.read_text()).get("id") == tpl.id: path = f; break
            except Exception: continue
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    if tpl.info.category not in {f"AST0{i}" for i in range(1,10)} | {"AST10"}:
        from kodand.categories import register_category
        register_category(tpl.info.category, tpl.info.category.replace("-", " ").title())
    return {"id": tpl.id, "file": path.name}
def delete_custom_template(tid: str) -> bool:
    for f in custom_templates_dir().glob("*.yaml"):
        try:
            if yaml.safe_load(f.read_text()).get("id") == tid: f.unlink(); return True
        except Exception: continue
    return False


# --- Finding review: status + comments (overlay on the immutable analysis.json) ---

REVIEW_STATUSES = {"needs-review", "confirmed", "false-positive", "remediated", "suppressed"}
STATUS_LABELS = {"candidate": "Pending Review", "needs-review": "Pending Review", "confirmed": "True Positive",
                 "false-positive": "False Positive", "accepted-risk": "Accepted Risk",
                 "remediated": "Remediated", "suppressed": "Suppressed"}

def _analysis(pid: str, sid: str) -> dict:
    p = scan_dir(pid, sid) / "analysis.json"
    if not p.exists(): raise FileNotFoundError("scan not found")
    return json.loads(p.read_text())
def _review_path(pid: str, sid: str) -> Path:
    return scan_dir(pid, sid) / "review.json"
def _load_overrides(pid: str, sid: str) -> dict:
    p = _review_path(pid, sid)
    return json.loads(p.read_text()) if p.exists() else {}
def _save_overrides(pid: str, sid: str, data: dict) -> None:
    _review_path(pid, sid).write_text(json.dumps(data, indent=2))
def find_finding(pid: str, sid: str, finding_id: str) -> dict:
    for f in _analysis(pid, sid).get("findings", []):
        if f["finding_id"] == finding_id: return f
    raise FileNotFoundError("finding not found")
def get_review(pid: str, sid: str) -> dict:
    overrides = _load_overrides(pid, sid)
    out = {}
    for f in _analysis(pid, sid).get("findings", []):
        fid = f["finding_id"]; ov = overrides.get(fid, {})
        out[fid] = {"status": ov.get("status") or f.get("status", "candidate"), "comments": ov.get("comments", [])}
    return out
def set_finding_status(pid: str, sid: str, finding_id: str, status: str) -> dict:
    if status not in REVIEW_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Expected one of: {', '.join(sorted(REVIEW_STATUSES))}")
    find_finding(pid, sid, finding_id)  # raises FileNotFoundError if unknown
    overrides = _load_overrides(pid, sid)
    entry = overrides.setdefault(finding_id, {}); entry["status"] = status
    _save_overrides(pid, sid, overrides)
    return {"finding_id": finding_id, "status": status, "comments": entry.get("comments", [])}
# A comment's verdict drives the badge on it in the report. Claude Agent passes its structured verdict;
# for anything else (AI Review, chat, a typed comment) it's read from how the text opens —
# "Verdict: True positive", "**False Positive**", "Needs more context: …" and the like.
COMMENT_VERDICTS = ("true_positive", "false_positive", "needs_review")
_VERDICT_RE = re.compile(r"^[\s>#*_`\-]*(?:verdict\s*[:\-–—]?\s*[*_`\s]*)?"
                         r"(true[\s-]+positive|false[\s-]+positive|needs[\s-]+(?:more[\s-]+context|review))", re.I)
_VERDICT_ANYWHERE_RE = re.compile(r"\bverdict\s*[:\-–—]\s*[*_`\s]*"
                                  r"(true[\s-]+positive|false[\s-]+positive|needs[\s-]+(?:more[\s-]+context|review))", re.I)


def parse_verdict(text: str) -> str | None:
    head = (text or "")[:400]
    m = _VERDICT_RE.match(head) or _VERDICT_ANYWHERE_RE.search(head)
    if not m: return None
    word = m.group(1).lower()
    return "true_positive" if word.startswith("true") else "false_positive" if word.startswith("false") else "needs_review"


def add_comment(pid: str, sid: str, finding_id: str, text: str, author: str = "You", kind: str = "user",
                verdict: str | None = None) -> dict:
    text = (text or "").strip()
    if not text: raise ValueError("Comment text is required")
    find_finding(pid, sid, finding_id)  # raises FileNotFoundError if unknown
    overrides = _load_overrides(pid, sid)
    entry = overrides.setdefault(finding_id, {}); comments = entry.setdefault("comments", [])
    comment = {"id": uuid.uuid4().hex[:10], "author": author, "kind": kind, "text": text, "created": _now()}
    verdict = verdict if verdict in COMMENT_VERDICTS else parse_verdict(text)
    if verdict: comment["verdict"] = verdict
    comments.append(comment); _save_overrides(pid, sid, overrides)
    return comment
def edit_comment(pid: str, sid: str, finding_id: str, comment_id: str, text: str) -> dict:
    text = (text or "").strip()
    if not text: raise ValueError("Comment text is required")
    overrides = _load_overrides(pid, sid)
    comments = (overrides.get(finding_id) or {}).get("comments") or []
    for c in comments:
        if c["id"] == comment_id:
            c["text"] = text; c["edited"] = _now()
            verdict = parse_verdict(text)  # an edit that changes (or removes) the verdict line moves the badge with it
            if verdict: c["verdict"] = verdict
            else: c.pop("verdict", None)
            _save_overrides(pid, sid, overrides)
            return c
    raise FileNotFoundError("comment not found")
def delete_comment(pid: str, sid: str, finding_id: str, comment_id: str) -> None:
    overrides = _load_overrides(pid, sid)
    entry = overrides.get(finding_id) or {}
    comments = entry.get("comments") or []
    kept = [c for c in comments if c["id"] != comment_id]
    if len(kept) == len(comments):
        raise FileNotFoundError("comment not found")
    entry["comments"] = kept; overrides[finding_id] = entry
    _save_overrides(pid, sid, overrides)


# --- AI assistant settings (global, workspace-level) ---

AI_PROVIDERS = ("openai", "claude", "gemini", "custom")

def ai_settings_path() -> Path:
    return workspace_root() / "ai_settings.json"
def load_ai_settings() -> dict:
    p = ai_settings_path()
    data = json.loads(p.read_text()) if p.exists() else {}
    data.setdefault("active_provider", "openai")
    for prov in AI_PROVIDERS: data.setdefault(prov, {})
    return data
def merge_ai_settings(payload: dict) -> dict:
    """Overlay a (possibly partial) settings payload onto what's already saved, without persisting."""
    current = load_ai_settings(); payload = payload or {}
    if payload.get("active_provider"): current["active_provider"] = payload["active_provider"]
    for prov in AI_PROVIDERS:
        cfg = dict(current.get(prov, {}))
        for k, v in (payload.get(prov) or {}).items():
            if k == "api_key" and not v:
                continue  # blank means "keep the existing key", never overwrite with empty
            cfg[k] = v
        current[prov] = cfg
    return current
def save_ai_settings(payload: dict) -> dict:
    merged = merge_ai_settings(payload)
    ai_settings_path().write_text(json.dumps(merged, indent=2))
    return merged
def masked_ai_settings() -> dict:
    data = load_ai_settings(); out = {"active_provider": data["active_provider"]}
    for prov in AI_PROVIDERS:
        cfg = dict(data.get(prov, {})); cfg["api_key_set"] = bool(cfg.pop("api_key", None))
        out[prov] = cfg
    return out


# --- MCP server: global consent + live-activity heartbeat ---

def mcp_settings_path() -> Path:
    return workspace_root() / "mcp_settings.json"
def load_mcp_settings() -> dict:
    p = mcp_settings_path()
    data = json.loads(p.read_text()) if p.exists() else {}
    data.setdefault("data_sharing_acknowledged", False)
    return data
def save_mcp_settings(payload: dict) -> dict:
    data = load_mcp_settings(); data["data_sharing_acknowledged"] = bool((payload or {}).get("data_sharing_acknowledged"))
    mcp_settings_path().write_text(json.dumps(data, indent=2)); return data
def mcp_status_path() -> Path:
    return workspace_root() / "mcp_status.json"
def _write_json_atomic(p: Path, data: dict) -> None:
    # the web UI polls these while the MCP process rewrites them — never let it read half a file
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2)); os.replace(tmp, p)
def _read_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
def touch_mcp_activity(project: str = None, tool: str = None) -> None:
    _write_json_atomic(mcp_status_path(), {"last_activity": _now(), "project": project, "tool": tool})


# One presence file per running `kodand mcp` process (several Claude sessions can each spawn one).
# Tool calls alone can't tell "connected but quiet" from "gone", so each process refreshes its
# file on a timer; a file that stops being refreshed means that process died without saying so.
MCP_PRESENCE_INTERVAL = 20
MCP_PRESENCE_TTL = 60
MCP_PRESENCE_RETENTION = 30 * 24 * 3600  # keep stopped records this long so "last seen" survives


def mcp_servers_dir() -> Path:
    d = workspace_root() / "mcp_servers"; d.mkdir(exist_ok=True); return d
def touch_mcp_server(pid: int, version: str, started_at: str, stopped: bool = False) -> None:
    _write_json_atomic(mcp_servers_dir() / f"{pid}.json",
                       {"pid": pid, "version": version, "started_at": started_at, "last_seen": _now(), "stopped": stopped})
def _pid_alive(pid) -> bool:
    if os.name == "nt":
        return True  # os.kill(pid, 0) terminates the process on Windows; fall back to the TTL alone
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except (TypeError, ValueError, OSError):
        return False
    return True
def list_mcp_servers() -> list:
    """Every presence record, each with a computed `connected` flag. Records past retention are pruned."""
    out = []
    for p in mcp_servers_dir().glob("*.json"):
        rec = _read_json(p)
        if rec is None: continue
        age = _age(rec.get("last_seen"))
        if age > MCP_PRESENCE_RETENTION:
            p.unlink(missing_ok=True); continue
        # the TTL catches a reused PID; the liveness check catches a kill before the TTL runs out
        rec["connected"] = not rec.get("stopped") and age <= MCP_PRESENCE_TTL and _pid_alive(rec.get("pid"))
        out.append(rec)
    return out
def read_mcp_status(stale_after: int = 45) -> dict:
    """`active`: a tool call in the last `stale_after`s. `connected`: at least one live server
    process. `idle_seconds`: how long a connected server has gone without a tool call.
    `seconds_ago`: since the last sign of MCP life at all (call or heartbeat)."""
    data = _read_json(mcp_status_path()) or {}
    servers = list_mcp_servers()
    live = [s for s in servers if s["connected"]]
    call_age = _age(data.get("last_activity")) if data.get("last_activity") else float("inf")
    out = {**data, "active": call_age <= stale_after, "connected": bool(live), "servers": len(live)}
    if live:
        # idle since the later of the last tool call and the oldest live server's start — a call
        # made by some earlier, now-gone process doesn't count as activity on this connection
        out["idle_seconds"] = int(min(call_age, max(_age(s.get("started_at")) for s in live)))
    last_seen_age = min([call_age] + [_age(s.get("last_seen")) for s in servers])
    if last_seen_age != float("inf"):
        out["seconds_ago"] = int(last_seen_age)
    return out


# --- Claude Agent: verification jobs the web console hands to the user's own Claude Code ---
#
# The console can't call Claude Code itself (MCP only lets the client call the server), so it
# leaves jobs here and the `kodand agent` worker — running in the user's own terminal — picks them
# up one at a time and runs the user's Claude Code headless on each; Claude reports back through the
# complete_job / fail_job MCP tools. Two OS processes touch these files (console and worker, plus
# the per-job MCP server), so every change goes through _agent_lock.

AGENT_JOB_TIMEOUT = 15 * 60   # backstop for a running job whose worker hung; the worker's own limit is lower
AGENT_MAX_ATTEMPTS = 3        # runs cut short by a worker dying before the job is given up
AGENT_OPEN_STATES = ("queued", "running")
AGENT_VERDICTS = {"true_positive": "True positive", "false_positive": "False positive", "needs_review": "Needs review"}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_AGENT_JOB_ID_RE = re.compile(r"^[0-9a-f]{12}$")
_AGENT_LOCK_STALE = 10


def agent_dir() -> Path:
    d = workspace_root() / "agent"
    for sub in ("jobs", "workers"): (d / sub).mkdir(parents=True, exist_ok=True)
    return d
def _agent_job_path(jid: str) -> Path:
    if not isinstance(jid, str) or not _AGENT_JOB_ID_RE.match(jid):
        raise FileNotFoundError("job not found")
    return agent_dir() / "jobs" / f"{jid}.json"


class _agent_lock:
    """Cross-process lock for the job files: O_EXCL create works the same on every OS. A lock
    left by a killed process is broken after _AGENT_LOCK_STALE seconds."""
    def __enter__(self):
        self.path = agent_dir() / ".lock"
        deadline = time.monotonic() + 2 * _AGENT_LOCK_STALE
        while True:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)); return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > _AGENT_LOCK_STALE:
                        self.path.unlink(missing_ok=True); continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError("Claude Agent job store is locked")
                time.sleep(0.02)
    def __exit__(self, *exc):
        self.path.unlink(missing_ok=True)


def _load_agent_jobs() -> list:
    out = []
    for p in (agent_dir() / "jobs").glob("*.json"):
        job = _read_json(p)
        if job: out.append(job)
    return sorted(out, key=lambda j: j.get("seq", 0))  # creation order; `created` only has 1s resolution
def _save_agent_job(job: dict) -> dict:
    job["updated"] = _now(); _write_json_atomic(_agent_job_path(job["id"]), job); return job


def get_agent_job(jid: str) -> dict:
    job = _read_json(_agent_job_path(jid))
    if job is None: raise FileNotFoundError("job not found")
    return job


def list_agent_jobs(pid: str | None = None, sid: str | None = None, limit: int = 200) -> list:
    """Newest first. Expiry runs first, so a job whose worker died shows as re-queued, not stuck."""
    expire_agent_jobs()
    jobs = [j for j in _load_agent_jobs() if (pid is None or j["project_id"] == pid) and (sid is None or j["scan_id"] == sid)]
    return list(reversed(jobs))[:limit]


def require_mcp_shared(pid: str) -> None:
    if not json.loads((_project_dir(pid) / "project.json").read_text()).get("mcp_shared"):
        # Claude reads the finding through the MCP tools, which refuse unshared projects
        raise ValueError("Share this project with MCP agents first (toggle on the project page) — "
                         "Claude Agent reads findings through Kodand's MCP tools.")


def _new_agent_job(pid: str, sid: str, finding: dict, origin: str) -> dict:
    return {"id": uuid.uuid4().hex[:12], "kind": "verify_finding", "project_id": pid, "scan_id": sid,
            "finding_id": finding["finding_id"], "title": finding.get("title", ""),
            "severity": finding.get("severity", ""), "origin": origin, "status": "queued",
            "created": _now(), "seq": time.time_ns(), "attempts": 0}


def enqueue_agent_job(pid: str, sid: str, finding_id: str, origin: str = "manual") -> dict:
    """Queue one finding for Claude Agent. A finding that already has an open job gets that job back."""
    require_mcp_shared(pid)
    finding = find_finding(pid, sid, finding_id)
    with _agent_lock():
        for j in _load_agent_jobs():
            if (j["project_id"], j["scan_id"], j["finding_id"]) == (pid, sid, finding_id) and j["status"] in AGENT_OPEN_STATES:
                return j
        return _save_agent_job(_new_agent_job(pid, sid, finding, origin))


def select_findings_for_agent(pid: str, sid: str, min_severity: str | None = None, max_findings: int | None = None) -> list:
    """Findings a bulk/auto run would queue, most severe first. No filter means every finding."""
    if min_severity and min_severity not in _SEVERITY_RANK:
        raise ValueError(f"Unknown severity '{min_severity}'")
    floor = _SEVERITY_RANK.get(min_severity or "informational", 0)
    findings = [f for f in _analysis(pid, sid).get("findings", []) if _SEVERITY_RANK.get(f.get("severity"), 0) >= floor]
    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.get("severity"), 0))
    return findings[:max_findings] if max_findings else findings


def enqueue_scan_verification(pid: str, sid: str, min_severity: str | None = None,
                              max_findings: int | None = None, origin: str = "auto") -> list:
    require_mcp_shared(pid)
    findings = select_findings_for_agent(pid, sid, min_severity, max_findings)
    with _agent_lock():
        open_ids = {j["finding_id"] for j in _load_agent_jobs()
                    if j["project_id"] == pid and j["scan_id"] == sid and j["status"] in AGENT_OPEN_STATES}
        return [_save_agent_job(_new_agent_job(pid, sid, f, origin)) for f in findings if f["finding_id"] not in open_ids]


def expire_agent_jobs() -> None:
    """Re-queue running jobs whose worker died, and fail ones that ran past AGENT_JOB_TIMEOUT."""
    with _agent_lock():
        for j in _load_agent_jobs():
            if j["status"] != "running":
                continue
            if not _pid_alive(j.get("claimed_by")):
                if j.get("attempts", 0) >= AGENT_MAX_ATTEMPTS:
                    j.update(status="failed", error="Claude Agent worker stopped before finishing it", finished=_now())
                else:
                    j.update(status="queued", error="Claude Agent worker stopped before finishing it")
                j.pop("claimed_by", None); _save_agent_job(j)
            elif _age(j.get("started")) > AGENT_JOB_TIMEOUT:
                j.update(status="failed", error="Timed out waiting for a verdict", finished=_now()); _save_agent_job(j)


def claim_next_agent_job(agent_id: str) -> dict | None:
    """The next job for this worker to run, or None while it still has one running. Manual
    requests go before auto-verify batches so a click in the UI doesn't wait behind a whole scan."""
    expire_agent_jobs()
    with _agent_lock():
        jobs = _load_agent_jobs()
        if any(j.get("claimed_by") == agent_id and j["status"] == "running" for j in jobs):
            return None
        queued = sorted((j for j in jobs if j["status"] == "queued"), key=lambda j: (j.get("origin") != "manual", j.get("seq", 0)))
        if not queued:
            return None
        job = queued[0]
        job.update(status="running", claimed_by=agent_id, started=_now(), attempts=job.get("attempts", 0) + 1)
        return _save_agent_job(job)


def _claimed_job(jid: str, agent_id: str) -> dict:
    job = get_agent_job(jid)
    if job.get("claimed_by") != agent_id or job["status"] != "running":
        raise ValueError(f"Job {jid} isn't currently assigned to this session (status: {job['status']}).")
    return job


def complete_agent_job(jid: str, agent_id: str, verdict: str, comment_id: str) -> dict:
    with _agent_lock():
        job = _claimed_job(jid, agent_id)
        job.update(status="done", verdict=verdict, comment_id=comment_id, finished=_now()); job.pop("error", None)
        return _save_agent_job(job)


def fail_agent_job(jid: str, agent_id: str, reason: str) -> dict:
    with _agent_lock():
        job = _claimed_job(jid, agent_id)
        job.update(status="failed", error=(reason or "Claude Agent gave up").strip()[:500], finished=_now())
        return _save_agent_job(job)


def release_agent_job(jid: str, agent_id: str) -> None:
    """Put a job back in the queue untouched — the worker was stopped (Ctrl+C) mid-run."""
    with _agent_lock():
        try:
            job = _claimed_job(jid, agent_id)
        except (ValueError, FileNotFoundError):
            return
        job.update(status="queued", attempts=max(0, job.get("attempts", 1) - 1))
        for k in ("claimed_by", "started"): job.pop(k, None)
        _save_agent_job(job)


def cancel_agent_job(jid: str) -> dict:
    with _agent_lock():
        job = get_agent_job(jid)
        if job["status"] not in AGENT_OPEN_STATES:
            raise ValueError(f"Job is already {job['status']}")
        job.update(status="cancelled", finished=_now()); job.pop("claimed_by", None)
        return _save_agent_job(job)


def retry_agent_job(jid: str) -> dict:
    with _agent_lock():
        job = get_agent_job(jid)
        if job["status"] not in ("failed", "cancelled"):
            raise ValueError(f"Only failed or cancelled jobs can be retried (this one is {job['status']})")
        job.update(status="queued", attempts=0)
        for k in ("error", "finished", "claimed_by", "started"): job.pop(k, None)
        return _save_agent_job(job)


def touch_agent_worker(pid: int, started_at: str, stopped: bool = False) -> None:
    _write_json_atomic(agent_dir() / "workers" / f"{pid}.json",
                       {"pid": pid, "started_at": started_at, "last_seen": _now(), "stopped": stopped})
def list_agent_workers() -> list:
    """Live `kodand agent` workers — same heartbeat/TTL/liveness rules as the MCP presence records."""
    out = []
    for p in (agent_dir() / "workers").glob("*.json"):
        rec = _read_json(p)
        if rec is None: continue
        if rec.get("stopped") or _age(rec.get("last_seen")) > MCP_PRESENCE_TTL or not _pid_alive(rec.get("pid")):
            p.unlink(missing_ok=True); continue
        out.append(rec)
    return out


def agent_status() -> dict:
    """`state`: offline (no `kodand agent` worker running), busy, or idle."""
    workers = list_agent_workers()
    jobs = list_agent_jobs(limit=10_000)
    count = lambda *states: sum(1 for j in jobs if j["status"] in states)  # noqa: E731
    state = "offline" if not workers else "busy" if count("running") else "idle"
    return {"state": state, "workers": len(workers), "queued": count("queued"), "running": count("running"),
            "done": count("done"), "failed": count("failed")}


# --- Console auth: one local password + server-side sessions ---
#
# Kodand is a single-user local tool, so this is deliberately one password rather than a user
# table. PBKDF2-HMAC-SHA256 from hashlib keeps it dependency-free (no bcrypt/passlib for one
# local credential). The default password is documented, not secret — it exists only so a fresh
# install has a known way in, and `must_change_password` forces it to be replaced on first login.

DEFAULT_PASSWORD = "kodand"
PBKDF2_ITERATIONS = 200_000
SESSION_TTL_SECONDS = 7 * 24 * 3600


def auth_path() -> Path:
    return workspace_root() / "auth.json"
def _hash_password(password: str, salt: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
def _new_auth_record(password: str, must_change: bool) -> dict:
    salt = secrets.token_hex(16)
    return {"salt": salt, "hash": _hash_password(password, salt), "iterations": PBKDF2_ITERATIONS,
            "must_change_password": must_change, "updated": _now()}
def load_auth() -> dict:
    """Read auth.json, provisioning it with the documented default password on first use."""
    p = auth_path()
    if p.exists():
        return json.loads(p.read_text())
    data = _new_auth_record(DEFAULT_PASSWORD, must_change=True)
    p.write_text(json.dumps(data, indent=2)); return data
def verify_password(password: str) -> bool:
    data = load_auth()
    candidate = _hash_password(password or "", data["salt"], data.get("iterations", PBKDF2_ITERATIONS))
    return hmac.compare_digest(candidate, data["hash"])
def set_password(new_password: str) -> dict:
    if len(new_password or "") < 8:
        raise ValueError("Password must be at least 8 characters.")
    if new_password == DEFAULT_PASSWORD:
        raise ValueError("Choose a password other than the default.")
    data = _new_auth_record(new_password, must_change=False)
    auth_path().write_text(json.dumps(data, indent=2))
    # anything issued under the old password dies with it — enforced here rather than at the
    # call site so no future caller can change a password and leave old sessions alive
    drop_all_sessions()
    return data
def reset_password_to_default() -> dict:
    data = _new_auth_record(DEFAULT_PASSWORD, must_change=True)
    auth_path().write_text(json.dumps(data, indent=2))
    drop_all_sessions()
    return data
def must_change_password() -> bool:
    return bool(load_auth().get("must_change_password"))
def default_password_active() -> bool:
    """Whether the stored password is still the documented default — drives the login page's
    first-run hint, so it disappears the moment a real password is set."""
    return verify_password(DEFAULT_PASSWORD)


def sessions_path() -> Path:
    return workspace_root() / "sessions.json"
def _load_sessions() -> dict:
    p = sessions_path()
    if not p.exists(): return {}
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    # prune expired on every read so the file can't grow without bound
    fresh = {t: s for t, s in data.items() if _age(s.get("created")) <= SESSION_TTL_SECONDS}
    if len(fresh) != len(data): _save_sessions(fresh)
    return fresh
def _save_sessions(data: dict) -> None:
    sessions_path().write_text(json.dumps(data, indent=2))
def create_session() -> str:
    """Persisted (not in-memory) so restarting kodand-ui.service — which install.sh now does on
    every upgrade — doesn't silently log the user out mid-session."""
    token = secrets.token_urlsafe(32)
    data = _load_sessions(); data[token] = {"created": _now()}; _save_sessions(data)
    return token
def get_session(token: str) -> dict | None:
    return _load_sessions().get(token or "")
def drop_session(token: str) -> None:
    data = _load_sessions()
    if data.pop(token or "", None) is not None: _save_sessions(data)
def drop_all_sessions() -> None:
    """Every existing session dies when the password changes — a password change should
    invalidate anything issued under the old one."""
    _save_sessions({})


# --- Scan activity: pipeline + AI-verification progress, kept as durable history (not just
# "currently running") so the Live Scans dashboard can show a finished scan's full timeline and
# distinguish a clean finish from one that stalled. Web UI and MCP server run as separate OS
# processes (the MCP server is a stdio subprocess launched by the calling agent), so this has to
# live on disk like the MCP heartbeat above rather than in an in-memory dict — that's what lets a
# scan kicked off from a Claude Code terminal via MCP show up live in the web console, and vice versa.

# ponytail: age-based heuristics, not a real "did the process die" signal — raise if a slow
# provider/huge repo legitimately needs longer than this between updates.
RUNNING_STALE_AFTER = 120   # no pipeline-stage update in this long -> assume the scan process died
VERIFY_STALE_AFTER = 300    # no verify_finding/add_finding_comment call in this long -> assume the
                            # agent/session verifying findings ended before finishing all of them

def _progress_path(pid: str, sid: str) -> Path:
    return scan_dir(pid, sid) / "progress.json"
def _log_path(pid: str, sid: str) -> Path:
    return scan_dir(pid, sid) / "activity_log.json"
def scan_registry_path() -> Path:
    return workspace_root() / "active_scans.json"
def _load_registry() -> dict:
    p = scan_registry_path()
    return json.loads(p.read_text()) if p.exists() else {}
def _save_registry(data: dict) -> None:
    scan_registry_path().write_text(json.dumps(data, indent=2))
def _remove_project_from_registry(pid: str) -> None:
    """Drop every Live Scans registry entry for a deleted project — otherwise
    list_scan_activity() finds a scan pointing at a project directory that no
    longer exists next time anyone loads the dashboard (see the FileNotFoundError
    guard there too, which covers any orphan this proactive cleanup still misses)."""
    reg = _load_registry()
    kept = {k: v for k, v in reg.items() if v.get("project") != pid}
    if len(kept) != len(reg):
        _save_registry(kept)
def _age(timestamp: str | None) -> float:
    try:
        return time.time() - calendar.timegm(time.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return float("inf")

def read_scan_progress(pid: str, sid: str) -> dict:
    p = _progress_path(pid, sid)
    return json.loads(p.read_text()) if p.exists() else {"stage": None, "detail": {}}
def read_scan_log(pid: str, sid: str) -> list:
    p = _log_path(pid, sid)
    return json.loads(p.read_text()) if p.exists() else []
def _append_scan_log(pid: str, sid: str, stage: str, detail: dict) -> None:
    p = _log_path(pid, sid)
    log = json.loads(p.read_text()) if p.exists() else []
    log.append({"stage": stage, "detail": detail, "at": _now()})
    p.write_text(json.dumps(log, indent=2))

def write_scan_progress(pid: str, sid: str, stage: str, detail: dict | None = None) -> None:
    detail = detail or {}
    prev = read_scan_progress(pid, sid)
    # log one entry per pipeline-stage transition, plus one per finding actually verified — not
    # every "matching" per-file tick, which would blow up an already-durable log for a big repo
    changed_stage = prev.get("stage") != stage
    changed_finding = stage == "verifying" and (prev.get("detail") or {}).get("finding_id") != detail.get("finding_id")
    if changed_stage or changed_finding:
        _append_scan_log(pid, sid, stage, detail)
    scan_dir(pid, sid).mkdir(parents=True, exist_ok=True)
    _progress_path(pid, sid).write_text(json.dumps({"stage": stage, "detail": detail, "updated": _now()}, indent=2))

def _touch_registry(pid: str, sid: str, label: str | None = None, source: str | None = None) -> None:
    reg = _load_registry()
    key = f"{pid}:{sid}"
    entry = reg.get(key) or {"project": pid, "scan": sid, "started": _now()}
    if label: entry["label"] = label
    if source: entry["source"] = source
    if not entry.get("label"):
        try:
            meta = json.loads((scan_dir(pid, sid) / "scan.json").read_text())
            entry["label"] = meta.get("label") or meta.get("repository") or sid
        except (FileNotFoundError, json.JSONDecodeError):
            entry["label"] = sid
    reg[key] = entry
    # cap the registry so it can't grow forever across a long-lived workspace — oldest drop first
    if len(reg) > 200:
        for k in sorted(reg, key=lambda k: reg[k].get("started", ""))[:len(reg) - 200]:
            reg.pop(k, None)
    _save_registry(reg)

def start_scan_progress(pid: str, sid: str, label: str, source: str) -> None:
    write_scan_progress(pid, sid, "starting")
    _touch_registry(pid, sid, label, source)
def finish_scan_progress(pid: str, sid: str, stage: str, detail: dict | None = None) -> None:
    write_scan_progress(pid, sid, stage, detail)
def mark_verifying(pid: str, sid: str, verified: int, total: int, finding_id: str | None = None) -> None:
    """Called on every verify_finding/add_finding_comment MCP call — surfaces AI-verification
    activity (which happens as many separate tool calls well after scan() itself returned) in the
    same Live Scans dashboard as the scan pipeline, instead of going dark the moment scan() finishes."""
    write_scan_progress(pid, sid, "verifying", {"verified": verified, "total": total, "finding_id": finding_id})
    _touch_registry(pid, sid, source="mcp")

def scan_activity(pid: str, sid: str) -> dict:
    """Two independent statuses for one scan, since "the scan finished" and "AI verification of
    its findings finished" are separate facts a user cares about separately:
      - scan_status: unknown/running/completed/interrupted/failed — the scan pipeline itself,
        unaffected by whether anyone has since verified any findings.
      - verify_status: None (no verification attempted yet) / pending / verified / interrupted —
        only meaningful once verify_finding/add_finding_comment has been called at least once.
    Both are derived from the latest progress snapshot and elapsed time, not a stored field, so a
    scan whose process died mid-pipeline (or an agent that stopped verifying findings partway
    through) is reflected the next time anyone looks, without a background watcher.
    `status`/`status_label` fold the two into one (verification takes precedence once it exists) —
    kept for the activity list's single badge and for deciding when polling should stop."""
    prog = read_scan_progress(pid, sid)
    stage, detail, updated = prog.get("stage"), prog.get("detail") or {}, prog.get("updated")
    age = _age(updated)

    if stage is None:
        scan_status, scan_label = "unknown", "No activity recorded"
    elif stage == "error":
        scan_status, scan_label = "failed", f"Failed — {detail.get('message', 'unknown error')}"
    elif stage in ("complete", "verifying"):
        scan_status, scan_label = "completed", "Scan Completed"
    elif age <= RUNNING_STALE_AFTER:
        scan_status, scan_label = "running", "Scan Running"
    else:
        scan_status, scan_label = "interrupted", f"Interrupted during {stage}"

    verify_status = verify_label = None
    if stage == "verifying":
        verified, total = detail.get("verified", 0), detail.get("total", 0)
        if total and verified >= total:
            verify_status, verify_label = "verified", f"AI Verified ({verified}/{total})"
        elif age <= VERIFY_STALE_AFTER:
            verify_status, verify_label = "pending", f"AI Verification Pending ({verified}/{total})"
        else:
            verify_status, verify_label = "interrupted", f"AI Verification Interrupted ({verified}/{total})"

    if verify_status == "pending":
        status, status_label = "verifying", verify_label
    elif verify_status:
        status, status_label = verify_status, verify_label
    else:
        status, status_label = scan_status, scan_label

    # "status_label" (not "label") — a scan's registry entry already has its own display-name
    # "label" field, and list_scan_activity merges this dict on top of that entry
    return {
        "stage": stage, "detail": detail, "updated": updated,
        "status": status, "status_label": status_label,
        "scan_status": scan_status, "scan_status_label": scan_label,
        "verify_status": verify_status, "verify_status_label": verify_label,
    }

def list_scan_activity(limit: int = 50) -> list:
    """Recent scans (running or finished) with their computed status — the Live Scans dashboard's
    feed. Newest-activity-first; capped at `limit` so a long-lived workspace stays fast to list.

    Self-healing: a registry entry whose project/scan no longer exists on disk (a project deleted
    before this cleanup existed, or any other way the two got out of sync) is dropped here rather
    than raising — one dead entry must never 500 the whole dashboard for every OTHER scan too."""
    reg = _load_registry()
    out, stale_keys = [], []
    for key, entry in reg.items():
        try:
            out.append({**entry, **scan_activity(entry["project"], entry["scan"])})
        except FileNotFoundError:
            stale_keys.append(key)
    if stale_keys:
        reg = _load_registry()
        for k in stale_keys:
            reg.pop(k, None)
        _save_registry(reg)
    out.sort(key=lambda x: x.get("updated") or x.get("started") or "", reverse=True)
    return out[:limit]

def delete_scan_activity(pid: str, sid: str) -> bool:
    """Remove this scan from the Live Scans dashboard — its registry entry, progress snapshot, and
    log. Does not touch the scan's own findings/report/source; deleting those is the separate
    "Delete"/"Delete Artifacts" actions on the Projects tab."""
    reg = _load_registry()
    key = f"{pid}:{sid}"
    existed = reg.pop(key, None) is not None
    if existed:
        _save_registry(reg)
    _progress_path(pid, sid).unlink(missing_ok=True)
    _log_path(pid, sid).unlink(missing_ok=True)
    return existed
