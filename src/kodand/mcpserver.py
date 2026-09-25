"""Kodand MCP server — exposes the scanner to MCP-capable clients (Claude Code, Cursor, etc.)
over stdio. Every tool is a thin wrapper over the same functions the CLI and web UI already use
(`run_template_scan`, `kodand.webui.store`) — one workspace (`~/.kodand`), multiple front doors.

A project must be explicitly shared (`store.set_project_mcp_sharing`, off by default) before any
MCP tool can see it — this is a hard gate, not just a UI hint: `_require_shared` raises for any
project that hasn't opted in, even ones that exist and are visible in the web console.
"""
from __future__ import annotations

import atexit
import functools
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kodand import __version__
from kodand.core.repository import copy_snapshot, extract_archive_into, is_archive_file
from kodand.exceptions import InvalidRepositoryError
from kodand.webui import ai_review, store
from kodand.webui.scan_service import load_builtin_templates, run_template_scan

mcp = FastMCP("kodand")
_STARTED_AT = datetime.now(timezone.utc).isoformat()


def _tool(fn):
    """Register `fn` as an MCP tool that also records the call, so the web console sees every
    tool as MCP activity — not just the few that used to touch the heartbeat by hand."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        store.touch_mcp_activity(project=kwargs.get("project_id") or kwargs.get("project"), tool=fn.__name__)
        return fn(*args, **kwargs)
    return mcp.tool()(wrapper)


def _require_shared(pid: str) -> dict:
    for p in store.list_projects():
        if p["id"] == pid:
            if not p.get("mcp_shared"):
                raise ValueError(f"Project '{pid}' is not shared with MCP clients. Enable sharing in Kodand -> Settings -> MCP Server.")
            return p
    raise ValueError(f"Project '{pid}' not found.")


def _require_consent() -> None:
    if not store.load_mcp_settings().get("data_sharing_acknowledged"):
        raise ValueError("MCP data sharing has not been acknowledged yet. Open Kodand -> Settings -> MCP Server and check the consent box first.")


def _touch_verification(pid: str, sid: str, finding_id: str) -> None:
    review = store.get_review(pid, sid)
    verified = sum(1 for v in review.values() if v["comments"])
    store.mark_verifying(pid, sid, verified, len(review), finding_id)


def _default_project() -> str:
    for p in store.list_projects():
        if p.get("mcp_shared") and p["name"] == "MCP":
            return p["id"]
    _require_consent()  # auto-creating and auto-sharing a project must not bypass the same gate a manual toggle would hit
    created = store.create_project("MCP")
    store.set_project_mcp_sharing(created["id"], True)
    return created["id"]


@_tool
def create_project(name: str) -> dict:
    """Create a new Kodand project, automatically shared with MCP clients (since it's being
    created for that purpose) — use this to scan into a named project instead of the ad-hoc
    "MCP" bucket that `scan` falls back to when no project is given."""
    _require_consent()
    created = store.create_project(name)
    return store.set_project_mcp_sharing(created["id"], True)


@_tool
def scan(path: str, project: str | None = None, label: str | None = None, use_custom: bool = False,
         full_findings: bool = False, workers: int = 1, use_cache: bool = True) -> dict:
    """Run a Kodand static security scan on a directory or archive (.zip/.tar.gz/.tgz) of agentic AI skill files
    (SKILL.md, GEMINI.md, AGENTS.md, etc). Returns a summary (findings count, severity breakdown, overall risk).
    `label` sets the scan's display name under the project (e.g. "Pre-release review") — defaults to the
    scanned directory's name if omitted. Pass full_findings=True to also get the complete findings list.
    `workers` matches files in parallel across that many processes for a large repo (default 1 = sequential).
    `use_cache` (default True) reuses cached results for files whose content hasn't changed since a prior
    scan; pass False to force a fresh match of every file."""
    pid = project or _default_project()
    _require_shared(pid)
    sid, sd = store.new_scan_dir(pid)
    target = sd / "target"
    src = Path(path).expanduser()
    # persist a snapshot into the scan's own target/ dir, exactly like the web UI's upload flow —
    # otherwise list_scan_files/get_file_content/verify_finding have nothing to read afterward,
    # since scanning `src` in place would leave Kodand's own workspace with an empty target/.
    try:
        if is_archive_file(src):
            extract_archive_into(src, target)
        elif src.is_dir():
            copy_snapshot(src, target)
        else:
            raise ValueError(f"Path not found or not a directory/archive: {path}")
    except (InvalidRepositoryError, ValueError) as e:
        store.delete_scan(pid, sid)
        raise ValueError(str(e)) from e
    store.start_scan_progress(pid, sid, label or target.name, "mcp")
    try:
        # same artifact set as the web UI's own scan flow — otherwise the console's "Report" link
        # (rendered identically for every scan regardless of source) 404s for MCP-triggered scans
        result = run_template_scan(
            repo_path=str(target), use_custom=bool(use_custom), custom_dir=store.custom_templates_dir(),
            out_dir=sd, formats=("html", "json", "sarif"),
            # written to disk (not memory) so the web console's Live Scans tab — a separate OS
            # process from this MCP stdio server — can watch this scan's progress in real time
            on_progress=lambda stage, detail: store.write_scan_progress(pid, sid, stage, detail),
            workers=min(max(1, int(workers)), os.cpu_count() or 1), use_cache=bool(use_cache))
    except Exception as e:
        store.finish_scan_progress(pid, sid, "error", {"message": str(e)})
        # keep progress.json/activity_log.json around (delete_scan would wipe them too) so the
        # failure is still visible in Live Scans history — only the raw source gets cleaned up
        store.delete_scan_target(pid, sid)
        raise ValueError(f"Scan failed: {e}") from e
    meta = {"id": sid, "project": pid, "label": label or result["repository"], "created": store._now(),
            "source": "mcp", "use_custom": bool(use_custom), **result}
    store.save_scan_meta(pid, sid, meta)
    store.finish_scan_progress(pid, sid, "complete")
    store.touch_mcp_activity(project=pid, tool="scan")
    out = {**result, "project_id": pid, "scan_id": sid}
    if full_findings:
        analysis_path = sd / "analysis.json"
        out["findings"] = json.loads(analysis_path.read_text()).get("findings", []) if analysis_path.exists() else []
    return out


@_tool
def status() -> dict:
    """Report this MCP server process's version, PID, and start time — the fastest way to
    check whether a running kodand mcp connection is serving current code or a stale,
    pre-upgrade process that was never restarted after an install/upgrade (a long-lived
    process keeps executing whatever code it originally imported; reinstalling the package
    on disk does not affect it — see install.sh, which now kills these on every reinstall
    specifically so this can't linger unnoticed)."""
    return {"version": __version__, "pid": os.getpid(), "started_at": _STARTED_AT}


@_tool
def list_templates(custom_only: bool = False) -> list:
    """List Kodand's detection templates (id, category, severity, confidence, capabilities)."""
    out = list(store.list_custom_templates())
    if not custom_only:
        builtin = [{"id": t.id, "name": t.info.name, "category": t.info.category, "severity": t.info.severity,
                    "confidence": t.info.confidence, "capabilities": t.capabilities} for t in load_builtin_templates()]
        out = builtin + out
    return out


@_tool
def list_projects() -> list:
    """List Kodand projects that have been explicitly shared with MCP clients (others are not visible here)."""
    return [p for p in store.list_projects() if p.get("mcp_shared")]


@_tool
def list_scans(project_id: str) -> list:
    """List scans for an MCP-shared Kodand project."""
    _require_shared(project_id)
    return store.list_scans(project_id)


@_tool
def get_finding(project_id: str, scan_id: str, finding_id: str) -> dict:
    """Get full detail for one finding: root cause, attack scenario, remediation, all occurrences."""
    _require_shared(project_id)
    return store.find_finding(project_id, scan_id, finding_id)


@_tool
def list_scan_files(project_id: str, scan_id: str) -> list:
    """List the files Kodand scanned for a given scan (relative path + size in bytes)."""
    _require_shared(project_id)
    return store.list_scan_files(project_id, scan_id)


@_tool
def get_file_content(project_id: str, scan_id: str, path: str) -> str:
    """Read the full content of one scanned file, exactly as Kodand saw it at scan time."""
    _require_shared(project_id)
    return store.get_file_content(project_id, scan_id, path)


@_tool
def verify_finding(project_id: str, scan_id: str, finding_id: str) -> str:
    """Ask Kodand's configured AI provider to verify a finding using the full content of the affected
    file(s) — not just the matched excerpt — and record the verdict as a comment on the finding.
    This calls out to whatever provider is set in Kodand -> Settings -> AI Provider (its own API key,
    its own quota) — NOT the MCP client's model. To have the calling agent itself do the verification
    instead (no external provider, no separate quota), call `get_finding` + `get_file_content` for the
    affected files, reason about it yourself, then call `add_finding_comment` with your verdict."""
    _require_shared(project_id)
    finding = store.find_finding(project_id, scan_id, finding_id)
    file_contents = store.read_scan_files(project_id, scan_id, finding.get("affected_files", []))
    settings = store.load_ai_settings()
    provider = settings.get("active_provider", "openai")
    text = ai_review.call_provider(provider, settings.get(provider, {}), finding, file_contents=file_contents)
    store.add_comment(project_id, scan_id, finding_id, text, author=f"AI Assistant ({provider}) via MCP", kind="ai")
    _touch_verification(project_id, scan_id, finding_id)
    return text


@_tool
def add_finding_comment(project_id: str, scan_id: str, finding_id: str, text: str) -> dict:
    """Record a verdict/comment on a finding, authored by the calling agent itself rather than
    Kodand's configured AI provider. Use this after reading `get_finding` + `get_file_content` for the
    affected files and reasoning about the finding yourself — the MCP-client alternative to
    `verify_finding`, which instead calls out to Kodand's own configured provider."""
    _require_shared(project_id)
    comment = store.add_comment(project_id, scan_id, finding_id, text, author="Claude Code (MCP client)", kind="ai")
    _touch_verification(project_id, scan_id, finding_id)
    return comment


DEFAULT_MAX_LIFETIME_SECONDS = 48 * 3600  # generous backstop, not idle-detection — see _self_expire


def _self_expire(interval_seconds: float, exit_fn=None) -> None:
    """Sleep for `interval_seconds` then call `exit_fn` (default `os._exit(0)`).

    Defense-in-depth backstop for a stdio MCP server that's meant to die when its parent
    client disconnects (stdin EOF) but doesn't — a client crashing instead of exiting
    cleanly orphans this process, which then keeps serving whatever code it originally
    imported indefinitely (install.sh's reinstall-time `pkill` is the primary fix for the
    common case; this bounds the damage for whatever it misses, e.g. a process spawned
    after the last reinstall that later gets orphaned). A call in flight at the exact
    expiry moment is interrupted, same as any process restart — acceptable at a multi-day
    default cadence. `exit_fn` is injectable so this is unit-testable without actually
    exiting the test process."""
    exit_fn = exit_fn or (lambda: os._exit(0))
    time.sleep(interval_seconds)
    exit_fn()


def _start_self_expire_thread() -> None:
    interval = float(os.environ.get("KODAND_MCP_MAX_LIFETIME_SECONDS", DEFAULT_MAX_LIFETIME_SECONDS))
    if interval <= 0:
        return  # 0 or negative disables the backstop entirely
    threading.Thread(target=_self_expire, args=(interval,), daemon=True).start()


_PRESENCE_STARTED = store._now()


def _touch_presence(stopped: bool = False) -> None:
    try:
        store.touch_mcp_server(os.getpid(), __version__, _PRESENCE_STARTED, stopped=stopped)
    except OSError:
        pass  # a missed heartbeat only makes the console show "disconnected"; it must not kill the server


def _presence_loop(stop: threading.Event, interval: float) -> None:
    while not stop.wait(interval):
        _touch_presence()


def _start_presence_thread() -> None:
    _touch_presence()
    stop = threading.Event()
    threading.Thread(target=_presence_loop, args=(stop, store.MCP_PRESENCE_INTERVAL), daemon=True).start()
    # clean exit (client closed stdin) records the disconnect at once; a kill falls back to the TTL
    atexit.register(lambda: (stop.set(), _touch_presence(stopped=True)))


def run() -> None:
    _start_self_expire_thread()
    _start_presence_thread()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
