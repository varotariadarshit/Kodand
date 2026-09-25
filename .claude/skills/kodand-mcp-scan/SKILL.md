---
description: Scan a skill folder with Kodand via the kodand MCP server, asking for any missing details (path to scan, which project, optional label)
---

You are running the `kodand-mcp-scan` skill. Goal: scan a directory or archive of agentic AI
skill files with Kodand's MCP tools, asking the user for whatever details weren't given up front,
then report the results clearly.

Arguments passed to this invocation (may be empty, partial, or full): `$ARGUMENTS`
- If the first token looks like a path, treat it as the scan target.
- If more text follows, treat it as the project name to use/create.
- Anything not supplied here must be asked for in step 2 below — don't guess a path or invent a
  project name the user didn't give you.

## Steps

1. **Confirm the kodand MCP server is actually connected in this session.** Check your available
   tools for `mcp__kodand__*` (e.g. via a tool search, or by noting whether `scan`/`create_project`
   etc. appear in your tool list). If they're NOT available, stop here and tell the user:
   - The kodand MCP server isn't connected to this session.
   - It needs to be registered (Kodand web console -> Settings -> MCP Server -> Register, or
     `claude mcp add kodand -- kodand mcp`), and any Claude Code session must be *restarted* after
     registering — a running session can't pick up a newly-added MCP server.
   - Do not proceed past this point until the tools are confirmed available.

2. **Gather whatever wasn't already given in `$ARGUMENTS`**, asking the user directly:
   - **Path to scan** (required) — a directory, or a `.zip`/`.tar.gz`/`.tgz` archive.
   - **Project**: ask whether to scan into an existing Kodand project or create a new one.
     - If existing: call `list_projects` to show the MCP-shared ones and ask which to use.
     - If new: ask for a name, then call `create_project` with it.
     - If the user has no preference, it's fine to omit `project` entirely — `scan` falls back to
       an auto-shared "MCP" bucket project. Say so explicitly so it's not a silent default.
   - **Scan label** (optional) — what the scan should be called under the project. Skip asking
     twice if it was already given in `$ARGUMENTS`; otherwise ask once, and it's fine to leave
     blank (falls back to the scanned directory's name).
   - **Custom templates** (optional) — ask only if it seems relevant; default to `use_custom=false`
     without asking if the user seems to just want a quick scan.

3. **Run the scan**: call `scan` with `path`, `project` (if any), `label` (if any), `use_custom`,
   and `full_findings=true` (so you have real finding titles/severities to report, not just counts).

4. **Report back concisely**:
   - Skills scanned, total findings, severity breakdown, overall risk.
   - Title + severity for each finding (a short table is fine).
   - The project/scan id, and a one-line reminder that this is now visible in the Kodand web
     console under that project (Report / Files / Delete Artifacts).
   - If Kodand's own reasoning suggests some findings might be documentation-about-threats rather
     than live payloads (e.g. many matches inside prose/example blocks), say so plainly rather
     than presenting every match as equally certain.

5. **Offer, don't assume, the next step**: ask if the user wants any specific finding verified
   (`verify_finding` — reads full file content, not just the matched excerpt, for a real verdict)
   or the scanned files browsed (`list_scan_files` / `get_file_content`). Don't run these
   automatically for every finding unless asked — that's a lot of extra AI-provider calls for
   findings the user may not care about.
