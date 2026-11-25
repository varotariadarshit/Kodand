"""Kodand Agent scope crawl, the console's half: turns kodand.scope_agent's plan into scope_batch jobs
for the running `kodand agent` worker, waits for them while reporting progress to Live Scans, and
hands the validated additions back to run_template_scan (its `scope_provider`).

The crawl only ever adds to the static scope, and the scan never depends on it: with no worker
running, or the project not shared with MCP, it records why and the scan uses the static scope.
There is no overall time limit — a big repo takes as long as it takes — but a worker that goes away
mid-crawl doesn't hang the scan (WORKER_GONE_SECONDS), and the user can skip the rest at any time.
"""
from __future__ import annotations

import time
from pathlib import Path

from kodand import scope_agent
from kodand.learned_scope import EMPTY, LearnedScope
from kodand.models.inventory import AgentScopeInfo
from kodand.webui import store
from kodand.webui.scan_service import is_scannable

POLL_SECONDS = 2.0
WORKER_GONE_SECONDS = 120   # no live worker for this long: stop waiting, keep what was found


def _batch_cache_entries(job: dict, shas: dict) -> dict:
    """Crawl-cache verdicts for every file of a finished batch: added (with type/reason) or not."""
    added = {a["path"]: a for a in job.get("additions") or []}
    out = {}
    for rel in job.get("paths") or []:
        sha = shas.get(rel)
        if not sha:
            continue
        a = added.get(rel)
        out[scope_agent.cache_key(rel, sha)] = (
            {"add": True, "type": a["type"], "reason": a.get("reason", ""), "suggested_pattern": a.get("suggested_pattern")}
            if a else {"add": False})
    return out


def make_scope_provider(pid: str, sid: str, learned: LearnedScope = EMPTY):
    """A run_template_scan `scope_provider` for console scan `pid/sid`."""

    def provider(root: Path, inv, in_scope: set[str], progress) -> AgentScopeInfo:
        t0 = time.monotonic()
        poll, worker_gone_seconds = POLL_SECONDS, WORKER_GONE_SECONDS  # read at call time (tests shorten them)

        def log(message: str, **extra):
            progress("agent_scope", log=True, message=message, **extra)

        if store.agent_status()["state"] == "offline":
            log("Kodand Agent not running — using the static scope")
            return AgentScopeInfo(status="offline", detail=(
                "Kodand Agent wasn't running, so the scan used the static scope only. Start it with "
                "`kodand agent` to have it crawl for agent files the static scan misses."))
        try:
            store.require_mcp_shared(pid)
        except ValueError:
            log("Kodand Agent can't read this project (not shared with MCP) — using the static scope")
            return AgentScopeInfo(status="not_shared", detail=(
                "This project isn't shared with MCP agents, so the Kodand Agent couldn't crawl it and the "
                "scan used the static scope only. Turn on sharing on the project page to enable it."))

        plan = scope_agent.plan_crawl(root, in_scope, store.load_scope_crawl_cache())
        info = AgentScopeInfo(status="used", files_total=plan.total, files_cached=plan.cached,
                              binary_skipped=plan.binary, batches=len(plan.batches))
        log(f"Kodand Agent crawling scope: {plan.total} file(s) outside the static scope — {plan.to_crawl} to "
            f"crawl in {len(plan.batches)} batch(es), {plan.cached} from cache, {plan.binary} binary skipped",
            files_total=plan.to_crawl, batches=len(plan.batches))

        added: list[dict] = []
        for a in plan.cached_additions:
            if (root / a["path"]).is_file():
                added.append(a)
                log(f"Kodand Agent added {a['path']} ({a['type']}, cached) — {a['reason']}", path=a["path"])

        jobs = store.enqueue_scope_batches(pid, sid, plan.batches, context=sorted(in_scope)[:40]) if plan.batches else []
        ids = {j["id"] for j in jobs}
        finished: set[str] = set()
        cache_entries: dict = {}
        no_worker_since: float | None = None
        crawled = failed = cancelled = 0
        while ids - finished:
            for j in store.scope_batch_jobs(pid, sid):
                if j["id"] not in ids or j["id"] in finished or j["status"] in store.AGENT_OPEN_STATES:
                    continue
                finished.add(j["id"])
                if j["status"] == "done":
                    crawled += len(j.get("paths") or [])
                    cache_entries.update(_batch_cache_entries(j, plan.shas))
                    for a in j.get("additions") or []:
                        added.append(a)
                        log(f"Kodand Agent added {a['path']} ({a['type']}) — {a['reason']}", path=a["path"])
                elif j["status"] == "cancelled":
                    cancelled += 1
                else:
                    failed += 1
                    log(f"Kodand Agent scope batch {j.get('batch_no')}/{j.get('batch_total')} failed: "
                        f"{j.get('error') or 'unknown error'}")
            if not ids - finished:
                break
            if store.list_agent_workers():
                no_worker_since = None
            else:
                no_worker_since = no_worker_since or time.monotonic()
                if time.monotonic() - no_worker_since > worker_gone_seconds:
                    left = [j["id"] for j in store.scope_batch_jobs(pid, sid)
                            if j["id"] in ids and j["status"] in store.AGENT_OPEN_STATES]
                    store.cancel_agent_jobs(ids=left)
                    log(f"Kodand Agent stopped during the crawl — continuing with what it found "
                        f"({len(left)} batch(es) not crawled)")
                    info.detail = (f"The Kodand Agent stopped during the scope crawl; {len(left)} of "
                                   f"{len(plan.batches)} batch(es) weren't crawled.")
                    info.status = "partial"
                    failed += len(left)
                    finished |= set(left)
                    break
            progress("agent_scope", batches=len(plan.batches), batches_done=len(finished), files_crawled=crawled,
                     files_total=plan.to_crawl, added=len(added), workers=len(store.list_agent_workers()))
            time.sleep(poll)

        store.update_scope_crawl_cache(cache_entries)
        info.files_crawled, info.batches_done, info.batches_failed = crawled, len(finished) - failed - cancelled, failed
        if cancelled and info.status == "used":
            info.status = "skipped"
            info.detail = (f"The scope crawl was skipped after {crawled} of {plan.to_crawl} file(s); "
                           f"{cancelled} batch(es) weren't crawled.")
        elif failed and info.status == "used":
            info.status = "partial"
            info.detail = f"{failed} of {len(plan.batches)} scope-crawl batch(es) failed; their files weren't crawled."

        seen, suggestions = set(), []
        for a in added:
            for s in scope_agent.suggestions_for(
                    a, scannable=lambda rel: is_scannable(root / rel, learned),
                    extra_specs=learned.entrypoint_specs(), repo_files=plan.all_files):
                key = (s["kind"], s["value"])
                if key not in seen:
                    seen.add(key)
                    suggestions.append(s)
        fresh = store.record_scope_suggestions(suggestions, pid, sid)
        info.added = [{"path": a["path"], "type": a["type"], "reason": a.get("reason", "")} for a in added]
        info.suggestions = suggestions
        info.duration_s = round(time.monotonic() - t0, 1)
        outcome = {"used": "finished", "partial": "finished partially", "skipped": "skipped"}.get(info.status, info.status)
        log(f"Kodand Agent scope crawl {outcome}: {len(added)} file(s) added in {info.duration_s:.0f}s"
            + (f"; {len(fresh)} new scope suggestion(s) — review them in Settings → Learned scope" if fresh else ""),
            added=len(added), suggestions=len(fresh))
        return info

    return provider


def skip_scope_crawl(pid: str, sid: str) -> int:
    """Cancel this scan's remaining scope batches; the scan continues with what was found so far."""
    ids = [j["id"] for j in store.scope_batch_jobs(pid, sid) if j["status"] in store.AGENT_OPEN_STATES]
    return store.cancel_agent_jobs(ids=ids) if ids else 0
