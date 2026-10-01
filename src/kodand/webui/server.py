"""Kodand Web UI — FastAPI app (v3)."""
from __future__ import annotations

import asyncio
import os
import shutil
import threading
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from kodand import __version__
from kodand.categories import TAXONOMIES, category_color, category_name
from kodand.codeanalysis.json_rules import JSON_RULES_LIST
from kodand.codeanalysis.rules import CODE_RULES_LIST
from kodand.core.repository import copy_snapshot, extract_archive_into, is_archive_file
from kodand.exceptions import InvalidRepositoryError
from kodand.models.analysis import RepositoryAnalysis
from kodand.reporting import write_html
from kodand.webui import ai_review, store
from kodand.webui.scan_service import MAX_SCAN_FILES, load_builtin_templates, run_template_scan

STATIC_DIR = Path(__file__).parent / "static"
app = FastAPI(title="Kodand UI", version=__version__)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
INDEX = STATIC_DIR / "index.html"
LOGO = STATIC_DIR / "kodand-logo-full.png"


SESSION_COOKIE = "kodand_session"
# Reachable without a session. /static is inert assets the login page itself needs — every
# piece of actual scan *data* lives behind /api/*, which is guarded. Anything not listed here
# is denied by default, so a route added later is protected without anyone remembering to.
_PUBLIC_PATHS = {"/login", "/favicon.ico"}
_PUBLIC_PREFIXES = ("/static/", "/api/auth/")
# Reachable with a session that still has to change its password, so the forced-change step
# is enforced server-side rather than only in the login page's JavaScript.
_PASSWORD_CHANGE_PATHS = {"/api/auth/change-password", "/api/auth/logout", "/api/auth/status"}


def _is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if _is_public(path):
        return await call_next(request)
    session = store.get_session(request.cookies.get(SESSION_COOKIE, ""))
    if session is None:
        if _wants_html(request):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    if store.must_change_password() and path not in _PASSWORD_CHANGE_PATHS:
        if _wants_html(request):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": "Password change required"}, status_code=403)
    return await call_next(request)


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Scanned content is attacker-controlled, so the console assumes an injected script is
# possible and limits what one could do: no loading or sending to other origins.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
_SECURITY_HEADERS = {"Content-Security-Policy": _CSP, "X-Content-Type-Options": "nosniff",
                     "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}


def _allowed_hosts() -> set | None:
    """Host names the console answers to; None = any (`kodand ui --allow-remote` sets that).
    Checking Host stops DNS rebinding: a web page whose domain re-resolves to 127.0.0.1
    still sends its own domain as Host, so it never reaches the API or the login form."""
    raw = os.environ.get("KODAND_ALLOWED_HOSTS", "")
    if raw.strip() == "*":
        return None
    return _LOOPBACK_HOSTS | {h.strip().lower() for h in raw.split(",") if h.strip()}


def _hostname(value: str) -> str:
    return (urlsplit("//" + value).hostname or "").lower() if value else ""


@app.middleware("http")
async def security_guard(request: Request, call_next):
    allowed = _allowed_hosts()
    if allowed is not None:
        if _hostname(request.headers.get("host", "")) not in allowed:
            return PlainTextResponse("Host not allowed", status_code=421)
        origin = request.headers.get("origin")
        # a browser always sends Origin on a cross-site POST/PUT/DELETE; reject any from elsewhere
        if request.method in _UNSAFE_METHODS and origin and _hostname(urlsplit(origin).netloc) not in allowed:
            return PlainTextResponse("Cross-origin request refused", status_code=403)
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
_login_failures: dict[str, deque] = {}
_login_lock = threading.Lock()


def _login_retry_after(client: str) -> int:
    """Seconds until `client` may try again, 0 if not locked out. In-memory on purpose: a
    restart clears it, which is fine for a local single-user console."""
    now = time.monotonic()
    with _login_lock:
        q = _login_failures.setdefault(client, deque())
        while q and now - q[0] > LOGIN_WINDOW_SECONDS:
            q.popleft()
        return int(LOGIN_WINDOW_SECONDS - (now - q[0])) + 1 if len(q) >= LOGIN_MAX_FAILURES else 0


def _record_login_failure(client: str) -> None:
    with _login_lock:
        _login_failures.setdefault(client, deque()).append(time.monotonic())


def _with_cache_busted_logo(html: str) -> str:
    # the logo filename never changes across redeploys, so browsers keep
    # serving a stale cached copy after we swap the file — tag it with the
    # file's own mtime so an edited logo gets a new URL automatically
    v = int(LOGO.stat().st_mtime) if LOGO.exists() else 0
    return html.replace("kodand-logo-full.png", f"kodand-logo-full.png?v={v}")


@app.get("/", response_class=HTMLResponse)
def index():
    return _with_cache_busted_logo(INDEX.read_text(encoding="utf-8"))


@app.get("/login", response_class=HTMLResponse)
def login():
    return _with_cache_busted_logo((STATIC_DIR / "login.html").read_text(encoding="utf-8"))


@app.get("/api/auth/status")
def api_auth_status(request: Request):
    session = store.get_session(request.cookies.get(SESSION_COOKIE, ""))
    return {"authenticated": session is not None,
            "must_change_password": store.must_change_password(),
            "default_password_active": store.default_password_active()}


@app.post("/api/auth/login")
def api_auth_login(request: Request, response: Response, payload: dict = Body(...)):
    client = request.client.host if request.client else "unknown"
    wait = _login_retry_after(client)
    if wait:
        raise HTTPException(429, f"Too many failed sign-in attempts. Try again in {wait // 60 + 1} minute(s).",
                            headers={"Retry-After": str(wait)})
    if not store.verify_password((payload or {}).get("password", "")):
        _record_login_failure(client)
        raise HTTPException(401, "Incorrect password")
    with _login_lock:
        _login_failures.pop(client, None)
    token = store.create_session()
    # No Secure flag: the console is served over plain http on loopback by default, and
    # setting Secure there would stop the cookie being stored at all, locking everyone out.
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", path="/")
    return {"ok": True, "must_change_password": store.must_change_password()}


@app.post("/api/auth/change-password")
def api_auth_change_password(request: Request, payload: dict = Body(...)):
    payload = payload or {}
    client = request.client.host if request.client else "unknown"
    if _login_retry_after(client):
        raise HTTPException(429, "Too many failed attempts. Try again later.")
    if not store.verify_password(payload.get("current_password", "")):
        _record_login_failure(client)
        raise HTTPException(401, "Current password is incorrect")
    try:
        store.set_password(payload.get("new_password", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    # set_password wipes every session, so re-issue one for the browser that just changed it
    token = store.create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", path="/")
    return resp


@app.post("/api/auth/logout")
def api_auth_logout(request: Request):
    store.drop_session(request.cookies.get(SESSION_COOKIE, ""))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/meta")
def meta():
    builtin = load_builtin_templates()
    structural = CODE_RULES_LIST + JSON_RULES_LIST
    # category/rule_count coverage must include the structural (AST/JSON) rules, not just
    # YAML templates — HOOK01, HOOK05, MCP04, and MCP09 have NO YAML template at all (they're
    # detected entirely by codeanalysis/json_struct.py) and would otherwise show as "0 rules"
    # here despite firing normally in an actual scan, which already merges all three sources
    # (see run_template_scan). `builtin_templates`/`regex_indicators` stay YAML-only below —
    # a distinct, still-meaningful metric — while category coverage reflects the true total.
    all_rules = builtin + structural
    cats = sorted({t.info.category for t in all_rules})
    regex_total = sum(len(getattr(t.detection, "regex", [])) for t in builtin)
    rule_count = {c: sum(1 for t in all_rules if t.info.category == c) for c in cats}
    # Three independent, non-overlapping taxonomies (see kodand.categories) — every
    # category in each is listed here even if this build has 0 rules for it yet,
    # so the About page always shows the full AST/MCP/Hooks Top 10 lists.
    taxonomies = [
        {
            "prefix": prefix, "label": t["label"],
            "categories": [{"code": c, "name": t["names"][c], "color": t["colors"][c],
                             "rule_count": rule_count.get(c, 0)} for c in t["order"]],
        }
        for prefix, t in TAXONOMIES.items()
    ]
    return {
        "version": __version__, "builtin_templates": len(builtin), "structural_rules": len(structural),
        "custom_templates": len(store.list_custom_templates()), "regex_indicators": regex_total,
        "categories": [{"code": c, "name": category_name(c), "color": category_color(c)} for c in cats],
        "taxonomies": taxonomies,
        "workspace": str(store.workspace_root()), "max_scan_files": MAX_SCAN_FILES,
    }


@app.get("/api/projects")
def api_projects():
    return store.list_projects()


@app.post("/api/projects")
def api_create_project(payload: dict = Body(...)):
    name = (payload or {}).get("name", "").strip()
    if not name:
        raise HTTPException(400, "Project name is required")
    description = ((payload or {}).get("description") or "").strip()
    return store.create_project(name, description)


@app.delete("/api/projects/{pid}")
def api_delete_project(pid: str):
    if not store.delete_project(pid):
        raise HTTPException(404, "Project not found")
    return {"ok": True}


@app.put("/api/projects/{pid}/mcp-sharing")
def api_set_project_mcp_sharing(pid: str, payload: dict = Body(...)):
    shared = bool((payload or {}).get("shared"))
    if shared and not store.load_mcp_settings().get("data_sharing_acknowledged"):
        raise HTTPException(400, "Acknowledge MCP data sharing in Settings -> MCP Server first.")
    try:
        return store.set_project_mcp_sharing(pid, shared)
    except FileNotFoundError:
        raise HTTPException(404, "Project not found")


@app.get("/api/projects/{pid}/scans")
def api_scans(pid: str):
    try:
        return store.list_scans(pid)
    except FileNotFoundError:
        raise HTTPException(404, "Project not found")


def _agent_filters(min_severity, max_findings) -> tuple[str | None, int | None]:
    """Blank means no filter: by default every finding is queued."""
    min_severity = (str(min_severity or "")).strip().lower() or None
    try:
        max_findings = int(max_findings) if str(max_findings or "").strip() else None
    except ValueError:
        raise HTTPException(400, "Max findings must be a whole number")
    if max_findings is not None and max_findings < 1:
        raise HTTPException(400, "Max findings must be at least 1")
    return min_severity, max_findings


def _require_local_agent_request(request: Request) -> None:
    """Queuing Claude Agent work spends the user's own Claude plan, so it's only accepted from this
    machine even when the console is exposed with --allow-remote, unless explicitly opened up."""
    host = request.client.host if request.client else ""
    if host not in _LOOPBACK_HOSTS and os.environ.get("KODAND_AGENT_ALLOW_REMOTE") != "1":
        raise HTTPException(403, "Claude Agent jobs can only be queued from this machine "
                                 "(set KODAND_AGENT_ALLOW_REMOTE=1 before `kodand ui` to allow remote clients).")


@app.post("/api/projects/{pid}/scans")
async def api_create_scan(pid: str, request: Request):
    # FastAPI's File()/Form() params always go through Starlette's default
    # request.form(), which caps multipart uploads at 1000 files — parse the
    # form manually so a scan can upload as many files as it can scan
    # (MAX_SCAN_FILES, kept in sync with the server-side scan cutoff)
    form = await request.form(max_files=MAX_SCAN_FILES)
    repo_path = form.get("repo_path") or None
    use_custom = str(form.get("use_custom", "")).lower() == "true"
    label = form.get("label") or None
    try:
        workers = min(max(1, int(form.get("workers", 1))), os.cpu_count() or 1)
    except (TypeError, ValueError):
        workers = 1
    agent_verify = str(form.get("agent_verify", "")).lower() == "true"
    if agent_verify:
        # refuse up front, not after a long scan the user then has to re-run
        _require_local_agent_request(request)
        agent_min_severity, agent_max = _agent_filters(form.get("agent_min_severity"), form.get("agent_max_findings"))
        try:
            store.require_mcp_shared(pid)
        except FileNotFoundError:
            raise HTTPException(404, "Project not found")
        except ValueError as e:
            raise HTTPException(400, str(e))
    files = form.getlist("files")
    try:
        sid, sd = store.new_scan_dir(pid)
    except FileNotFoundError:
        raise HTTPException(404, "Project not found")
    target = (sd / "target").resolve(); source = "path"; saved = 0; saved_paths = []
    for uf in files or []:
        rel = (uf.filename or "file").replace("\\", "/").lstrip("/")
        dest = (target / rel).resolve()
        if dest != target and target not in dest.parents:
            continue  # reject path escaping the upload target
        dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(await uf.read()); saved += 1; saved_paths.append(dest)
    if saved == 1 and is_archive_file(saved_paths[0]):
        # a single uploaded .zip/.tar.gz — the "Choose files" picker lets a user
        # pick one file as readily as a folder, and an unextracted archive would
        # otherwise scan as one opaque, unreadable file (0 skills, wrong file count)
        archive_path = saved_paths[0]
        try:
            extract_archive_into(archive_path, target)
        except InvalidRepositoryError as e:
            store.delete_scan(pid, sid); raise HTTPException(400, str(e))
        archive_path.unlink()
    # a multi-file upload is a folder of skill files: scanned as-is, with any
    # archive inside it left alone as an unscannable asset (same as before)
    if saved:
        scan_root = str(target); source = "upload"
    elif repo_path and Path(repo_path).expanduser().exists():
        # snapshot into this scan's own target/ dir — same as the upload flow above and
        # the MCP scan tool — otherwise Files/Delete-Artifacts/verify_finding have nothing
        # to read back afterward for a server-side-path scan.
        src = Path(repo_path).expanduser()
        try:
            if is_archive_file(src):
                extract_archive_into(src, target)
            elif src.is_dir():
                copy_snapshot(src, target)
            else:
                raise HTTPException(400, f"Path not found or not a directory/archive: {repo_path}")
        except InvalidRepositoryError as e:
            store.delete_scan(pid, sid); raise HTTPException(400, str(e))
        scan_root = str(target); source = "path"
    else:
        store.delete_scan(pid, sid); raise HTTPException(400, "Provide an existing repo_path or upload files containing SKILL.md")
    store.start_scan_progress(pid, sid, label or Path(scan_root).name, source)
    try:
        # off the event loop so a concurrent GET .../progress can actually observe live updates
        # while this request is still in flight — an inline call here would block the whole
        # server (this handler is `async def`) for the entire scan duration.
        result = await asyncio.to_thread(
            run_template_scan, repo_path=scan_root, use_custom=bool(use_custom),
            custom_dir=store.custom_templates_dir(), out_dir=sd, formats=("html", "json", "sarif"),
            on_progress=lambda stage, detail: store.write_scan_progress(pid, sid, stage, detail),
            workers=workers)
    except Exception as e:
        store.finish_scan_progress(pid, sid, "error", {"message": str(e)})
        # keep progress.json/activity_log.json (delete_scan would wipe them too) so the failure
        # is still visible in Live Scans history — only the raw source gets cleaned up
        store.delete_scan_target(pid, sid); raise HTTPException(500, f"Scan failed: {e}")
    meta = {"id": sid, "project": pid, "label": label or result["repository"], "created": store._now(),
            "source": source, "use_custom": bool(use_custom), **result}
    store.save_scan_meta(pid, sid, meta)
    store.finish_scan_progress(pid, sid, "complete")
    if agent_verify:
        # the scan itself never waits on Claude: jobs are queued and run whenever the agent session is up
        try:
            jobs = store.enqueue_scan_verification(pid, sid, agent_min_severity, agent_max, origin="auto")
        except ValueError as e:  # sharing switched off while the scan ran: keep the scan, report why
            return {**meta, "agent_jobs_queued": 0, "agent_error": str(e)}
        return {**meta, "agent_jobs_queued": len(jobs)}
    return meta


@app.get("/api/scans/activity")
def api_scan_activity():
    """Recent scan activity anywhere — this web UI or an MCP client (e.g. Claude Code) — running,
    completed, AI-verified, interrupted, or failed. Feed for the Live Scans dashboard tab."""
    return store.list_scan_activity()


@app.get("/api/projects/{pid}/scans/{sid}/progress")
def api_scan_progress(pid: str, sid: str):
    return store.scan_activity(pid, sid)


@app.get("/api/projects/{pid}/scans/{sid}/log")
def api_scan_log(pid: str, sid: str):
    """Durable pipeline/verification timeline for one scan — survives a page reload or the scan
    having finished long ago, unlike the live-poll-only progress endpoint above."""
    return store.read_scan_log(pid, sid)


@app.delete("/api/projects/{pid}/scans/{sid}/activity")
def api_delete_scan_activity(pid: str, sid: str):
    """Remove this scan from the Live Scans dashboard only — its findings/report are untouched."""
    if not store.delete_scan_activity(pid, sid):
        raise HTTPException(404, "No activity record for this scan")
    return {"ok": True}


@app.delete("/api/projects/{pid}/scans/{sid}")
def api_delete_scan(pid: str, sid: str):
    if not store.delete_scan(pid, sid):
        raise HTTPException(404, "Scan not found")
    return {"ok": True}


def _regenerate_report_html(pid: str, sid: str) -> Path:
    """Rebuild report.html from analysis.json, in place, and return its path. `write_html` is a
    pure function of the stored analysis — regenerating on every read (instead of trusting
    whatever static report.html a past scan happened to write) means a scan run before some
    later report-template change (e.g. the "Open File" button, or a review-workflow addition)
    still gets the current template the next time anyone looks, not whatever existed back then."""
    sd = store.scan_dir(pid, sid)
    aj = sd / "analysis.json"
    if not aj.exists():
        raise HTTPException(404, "Report not found")
    analysis = RepositoryAnalysis.model_validate_json(aj.read_text())
    rp = sd / "report.html"
    write_html(analysis, rp)
    return rp


@app.get("/api/projects/{pid}/scans/{sid}/report", response_class=HTMLResponse)
def api_report(pid: str, sid: str):
    rp = _regenerate_report_html(pid, sid)
    return rp.read_text(encoding="utf-8")


@app.get("/api/projects/{pid}/scans/{sid}/download/{kind}")
def api_download(pid: str, sid: str, kind: str):
    fmap = {"json": "analysis.json", "sarif": "results.sarif", "html": "report.html", "docx": "report.docx", "pdf": "report.pdf"}
    if kind not in fmap:
        raise HTTPException(400, "Unknown artifact")
    if kind == "html":
        fp = _regenerate_report_html(pid, sid)
    else:
        fp = store.scan_dir(pid, sid) / fmap[kind]
        if not fp.exists():
            raise HTTPException(404, "Artifact not found")
    return FileResponse(str(fp), filename=fp.name)


@app.get("/api/projects/{pid}/scans/{sid}/files")
def api_scan_files(pid: str, sid: str):
    return store.list_scan_files(pid, sid)


@app.get("/api/projects/{pid}/scans/{sid}/files/content", response_class=PlainTextResponse)
def api_scan_file_content(pid: str, sid: str, path: str):
    try:
        return store.get_file_content(pid, sid, path)
    except FileNotFoundError:
        raise HTTPException(404, "File not found (it may have been removed via Delete Artifacts)")


@app.delete("/api/projects/{pid}/scans/{sid}/target")
def api_delete_scan_target(pid: str, sid: str):
    if not store.delete_scan_target(pid, sid):
        raise HTTPException(404, "Scan source not found (already deleted?)")
    return {"ok": True}


@app.get("/api/projects/{pid}/scans/{sid}/review")
def api_get_review(pid: str, sid: str):
    try:
        return store.get_review(pid, sid)
    except FileNotFoundError:
        raise HTTPException(404, "Scan not found")


@app.put("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/status")
def api_set_finding_status(pid: str, sid: str, finding_id: str, payload: dict = Body(...)):
    try:
        return store.set_finding_status(pid, sid, finding_id, (payload or {}).get("status", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Finding or scan not found")


@app.post("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/comments")
def api_add_comment(pid: str, sid: str, finding_id: str, payload: dict = Body(...)):
    try:
        return store.add_comment(pid, sid, finding_id, (payload or {}).get("text", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Finding or scan not found")


@app.put("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/comments/{comment_id}")
def api_edit_comment(pid: str, sid: str, finding_id: str, comment_id: str, payload: dict = Body(...)):
    try:
        return store.edit_comment(pid, sid, finding_id, comment_id, (payload or {}).get("text", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Comment not found")


@app.delete("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/comments/{comment_id}")
def api_delete_comment(pid: str, sid: str, finding_id: str, comment_id: str):
    try:
        store.delete_comment(pid, sid, finding_id, comment_id)
    except FileNotFoundError:
        raise HTTPException(404, "Comment not found")
    return {"ok": True}


@app.post("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/ai-review")
def api_ai_review(pid: str, sid: str, finding_id: str):
    try:
        finding = store.find_finding(pid, sid, finding_id)
    except FileNotFoundError:
        raise HTTPException(404, "Finding or scan not found")
    file_contents = store.read_scan_files(pid, sid, finding.get("affected_files", []))
    settings = store.load_ai_settings()
    provider = settings.get("active_provider", "openai")
    try:
        # the scan ids let the model open other scanned files when the affected ones aren't enough
        text = ai_review.call_provider(provider, settings.get(provider, {}), finding, file_contents=file_contents,
                                       project_id=pid, scan_id=sid)
    except ai_review.NotConfiguredError:
        raise HTTPException(400, ai_review.NOT_CONFIGURED_MESSAGE)
    except Exception as e:
        raise HTTPException(502, f"AI review failed ({provider}): {e}")
    return store.add_comment(pid, sid, finding_id, text, author=f"AI Assistant ({provider})", kind="ai")


@app.post("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/ai-review-agentic", deprecated=True)
def api_ai_review_agentic(pid: str, sid: str, finding_id: str):
    """Old "Verify with Agent" endpoint. AI Review now does what it did, with any provider."""
    return api_ai_review(pid, sid, finding_id)


@app.post("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/agent-verify")
def api_agent_verify_finding(pid: str, sid: str, finding_id: str, request: Request):
    """Queue one finding for the user's Claude Agent session (`kodand agent`)."""
    _require_local_agent_request(request)
    try:
        return store.enqueue_agent_job(pid, sid, finding_id, origin="manual")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Finding or scan not found")


@app.post("/api/projects/{pid}/scans/{sid}/agent-verify")
def api_agent_verify_scan(pid: str, sid: str, request: Request, payload: dict = Body(default={})):
    """Queue a scan's findings (optionally filtered) for Claude Agent. `dry_run` only counts them,
    so the console can say how many jobs it's about to queue before the user confirms."""
    payload = payload or {}
    min_severity, max_findings = _agent_filters(payload.get("min_severity"), payload.get("max_findings"))
    try:
        if payload.get("dry_run"):
            return {"count": len(store.select_findings_for_agent(pid, sid, min_severity, max_findings))}
        _require_local_agent_request(request)
        jobs = store.enqueue_scan_verification(pid, sid, min_severity, max_findings, origin="manual")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Scan not found")
    return {"queued": len(jobs), "jobs": jobs}


@app.get("/api/agent/status")
def api_agent_status():
    return {**store.agent_status(), "claude_found": bool(shutil.which("claude"))}


@app.get("/api/agent/jobs")
def api_agent_jobs(project: str | None = None, scan: str | None = None, limit: int = 200):
    return store.list_agent_jobs(project, scan, limit=min(max(1, limit), 1000))


@app.post("/api/agent/jobs/{jid}/cancel")
def api_agent_cancel_job(jid: str):
    try:
        return store.cancel_agent_job(jid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Job not found")


@app.post("/api/agent/jobs/{jid}/retry")
def api_agent_retry_job(jid: str, request: Request):
    _require_local_agent_request(request)
    try:
        return store.retry_agent_job(jid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "Job not found")


@app.post("/api/projects/{pid}/scans/{sid}/findings/{finding_id}/ai-chat")
def api_ai_chat(pid: str, sid: str, finding_id: str, payload: dict = Body(...)):
    message = (payload or {}).get("message", "").strip()
    if not message:
        raise HTTPException(400, "Message is required")
    try:
        finding = store.find_finding(pid, sid, finding_id)
        prior_comments = store.get_review(pid, sid)[finding_id]["comments"]
    except FileNotFoundError:
        raise HTTPException(404, "Finding or scan not found")
    file_contents = store.read_scan_files(pid, sid, finding.get("affected_files", []))
    user_comment = store.add_comment(pid, sid, finding_id, message, author="You", kind="user")
    settings = store.load_ai_settings()
    provider = settings.get("active_provider", "openai")
    try:
        reply = ai_review.chat_reply(provider, settings.get(provider, {}), finding, prior_comments, message,
                                     file_contents=file_contents, project_id=pid, scan_id=sid)
    except ai_review.NotConfiguredError:
        raise HTTPException(400, ai_review.NOT_CONFIGURED_MESSAGE)
    except Exception as e:
        raise HTTPException(502, f"AI chat failed ({provider}): {e}")
    ai_comment = store.add_comment(pid, sid, finding_id, reply, author=f"AI Assistant ({provider})", kind="ai")
    return {"user_comment": user_comment, "ai_comment": ai_comment}


@app.get("/api/settings/ai")
def api_get_ai_settings():
    return store.masked_ai_settings()


@app.put("/api/settings/ai")
def api_save_ai_settings(payload: dict = Body(...)):
    store.save_ai_settings(payload)
    return store.masked_ai_settings()


@app.post("/api/settings/ai/test")
def api_test_ai_settings(payload: dict = Body(...)):
    payload = payload or {}
    merged = store.merge_ai_settings(payload)
    provider = payload.get("active_provider") or merged.get("active_provider", "openai")
    try:
        sample = ai_review.test_connection(provider, merged.get(provider, {}))
    except Exception as e:
        raise HTTPException(502, f"Connection test failed ({provider}): {e}")
    return {"ok": True, "provider": provider, "sample": sample}


@app.get("/api/mcp/status")
def api_mcp_status():
    return store.read_mcp_status()


@app.get("/api/settings/mcp")
def api_get_mcp_settings():
    claude_path = shutil.which("claude")
    kodand_bin = shutil.which("kodand") or shutil.which("Kodand") or "kodand"
    return {
        **store.load_mcp_settings(),
        "status": store.read_mcp_status(),
        "shared_projects": [p["id"] for p in store.list_projects() if p.get("mcp_shared")],
        "mcp_json_snippet": {"mcpServers": {"kodand": {"command": kodand_bin, "args": ["mcp"]}}},
        "clients": [{"name": "Claude Code", "id": "claude-code", "detected": bool(claude_path), "path": claude_path}],
    }


@app.put("/api/settings/mcp")
def api_save_mcp_settings(payload: dict = Body(...)):
    return store.save_mcp_settings(payload)


@app.post("/api/settings/mcp/register")
def api_register_mcp_client(payload: dict = Body(...)):
    client = (payload or {}).get("client")
    if client != "claude-code":
        raise HTTPException(400, f"Unsupported client '{client}'")
    claude_path = shutil.which("claude")
    if not claude_path:
        raise HTTPException(400, "Claude Code CLI not found on PATH")
    kodand_bin = shutil.which("kodand") or shutil.which("Kodand")
    if not kodand_bin:
        raise HTTPException(400, "Kodand binary not found on PATH — install with pipx/uv first")
    import subprocess
    try:
        # "user" scope, not the "local" default: local is keyed to whatever directory this
        # server process happens to run from, which would make the tools invisible from every
        # other project the user actually works in — this is a general-purpose scanner, not
        # something scoped to one repo.
        proc = subprocess.run([claude_path, "mcp", "add", "--scope", "user", "kodand", "--", kodand_bin, "mcp"],
                               capture_output=True, text=True, timeout=20)
    except Exception as e:
        raise HTTPException(500, f"Failed to run claude CLI: {e}")
    if proc.returncode != 0:
        raise HTTPException(500, f"claude mcp add failed: {(proc.stderr or proc.stdout).strip()[:500]}")
    return {"ok": True, "output": proc.stdout.strip()}


@app.get("/api/templates")
def api_templates():
    return {"builtin": len(load_builtin_templates()), "custom": store.list_custom_templates()}


@app.post("/api/templates")
def api_add_template(payload: dict = Body(...)):
    try:
        if "detection" in payload and "info" in payload:
            doc = payload
        else:
            match = payload.get("match")
            if isinstance(match, str):
                match = [m.strip() for m in match.splitlines() if m.strip()]
            regex = payload.get("regex")
            if isinstance(regex, str):
                regex = [r.strip() for r in regex.splitlines() if r.strip()]
            caps = payload.get("capabilities")
            if isinstance(caps, str):
                caps = [c.strip() for c in caps.replace(",", "\n").splitlines() if c.strip()]
            doc = {
                "id": payload["id"].strip(),
                "info": {"name": payload.get("name", payload["id"]).strip(),
                         "severity": payload.get("severity", "medium"),
                         "confidence": payload.get("confidence", "medium"),
                         "category": payload.get("category", "CUSTOM").strip().upper()},
                "detection": {"match": match or [], "regex": regex or []},
                "capabilities": caps or [],
                "risk": {"title": payload.get("risk_title", payload.get("name", payload["id"]))},
                "recommendation": payload.get("recommendation", "Review and remediate the matched pattern."),
            }
        if not doc["detection"].get("match") and not doc["detection"].get("regex"):
            raise ValueError("At least one match or regex indicator is required.")
        rec = store.add_custom_template(doc)
        return {"ok": True, **rec}
    except KeyError as e:
        raise HTTPException(400, f"Missing field: {e}")
    except Exception as e:
        raise HTTPException(400, str(e))


@app.delete("/api/templates/{tid}")
def api_delete_template(tid: str):
    if not store.delete_custom_template(tid):
        raise HTTPException(404, "Custom template not found")
    return {"ok": True}


@app.post("/api/bench")
def api_bench(payload: dict = Body(...)):
    from kodand.bench import run_bench
    corpus = (payload or {}).get("corpus", "").strip()
    if not corpus:
        from importlib.resources import files
        corpus = str(files("kodand").joinpath("builtin_corpus"))
    if not Path(corpus).expanduser().exists():
        raise HTTPException(400, f"Corpus path not found: {corpus}")
    threshold = (payload or {}).get("threshold", 45)
    try:
        return run_bench(corpus, score_threshold=int(threshold))
    except Exception as e:
        raise HTTPException(500, f"Benchmark failed: {e}")
