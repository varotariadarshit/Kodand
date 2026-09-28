import json
import logging
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from kodand import __version__
from kodand.banner import show_banner
from kodand.exceptions import KodandError
from kodand.scanner import inventory_repository
from kodand.templates.cli import app as template_app

# no_args_is_help stays off here: it prints help and exits before main() runs, so a bare
# `kodand` never got to show the banner. main() prints banner + help itself instead.
app = typer.Typer(rich_markup_mode="rich",
                  help="[bold #38bdf8]Kodand[/] — Agentic AI Skills Threat and Risk Assessment. "
                       "Scan agent skills, MCP servers and hooks for security risks.")
c = Console()
app.add_typer(template_app, name="templates")


def save(m, p):
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(m.model_dump_json(indent=2), encoding='utf-8')


def run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except KodandError as e:
        c.print(f"[red]{e}[/red]"); raise typer.Exit(2)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, verbose: bool = typer.Option(False, '--verbose', '-v', help='Enable debug logging')):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING, format='%(levelname)s %(name)s: %(message)s', force=True)
    if ctx.invoked_subcommand is None:
        show_banner(c); c.print(ctx.get_help())


@app.command()
def version():
    """Show the kodand version and detection coverage."""
    show_banner(c); c.print(f"kodand version {__version__}")


@app.command()
def inventory(repository: Path, output: Path = typer.Option(Path('inventory.json'), '--output', '-o'), no_banner: bool = typer.Option(False, '--no-banner')):
    """List the agent skills, MCP servers and hooks found in a directory, without scanning them."""
    if not no_banner:
        show_banner(c, 'INVENTORY')
    r = run(inventory_repository, repository); save(r, output); c.print(f"Inventory written to {output}")


@app.command()
def analyze(repository: Path, output: Path = typer.Option(Path('analysis.json'), '--output', '-o'),
            html_report: Path = typer.Option(None, '--html'), sarif: Path = typer.Option(None, '--sarif'),
            docx: Path = typer.Option(None, '--docx'), pdf: Path = typer.Option(None, '--pdf'),
            workers: int = typer.Option(1, '--workers', help='Match files in parallel across this many worker processes (1 = sequential).'),
            no_cache: bool = typer.Option(False, '--no-cache', help='Skip the content-hash scan cache: neither read nor update it, for a guaranteed-fresh scan.'),
            max_files: int = typer.Option(None, '--max-files', help='Cap on how many files a single scan matches (default: 10000). Entrypoints are always kept; code/config files are prioritized over docs when over budget.'),
            no_banner: bool = typer.Option(False, '--no-banner')):
    """Scan a directory for security risks and write JSON, plus optional HTML, SARIF, DOCX or PDF reports."""
    if not no_banner:
        show_banner(c, 'ANALYZING')
    from kodand.webui.scan_service import run_template_scan
    out_dir = output.parent if output.parent.as_posix() != '' else Path('.')
    formats = ['json']
    if html_report: formats.append('html')
    if sarif: formats.append('sarif')
    if docx: formats.append('docx')
    if pdf: formats.append('pdf')
    res = run(run_template_scan, str(repository), False, None, out_dir, tuple(formats),
              workers=workers, use_cache=not no_cache, max_scan_files=max_files)
    # move default json to requested output name
    default_json = out_dir / 'analysis.json'
    if default_json.exists() and default_json != output:
        output.parent.mkdir(parents=True, exist_ok=True); output.write_text(default_json.read_text(), encoding='utf-8')
    for k, dest in (('html', html_report), ('sarif', sarif), ('docx', docx), ('pdf', pdf)):
        src = out_dir / {'html': 'report.html', 'sarif': 'results.sarif', 'docx': 'report.docx', 'pdf': 'report.pdf'}[k]
        if dest and src.exists() and src != dest:
            dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(src.read_bytes())
    t = Table(title='Kodand Analysis', title_style='bold #38bdf8', border_style='#3b82f6'); t.add_column('Metric'); t.add_column('Value')
    t.add_row('Repository', res['repository']); t.add_row('Skills', str(res['skills']))
    t.add_row('Findings', str(res['findings'])); t.add_row('Suppressed', str(res['suppressed']))
    t.add_row('Overall Risk', res['overall_risk']); c.print(t)
    c.print('[yellow]Candidate findings require human validation.[/yellow]')


@app.command()
def bench(corpus: Path = typer.Argument(None, help="Path to a labeled corpus (defaults to the packaged corpus)."), no_banner: bool = typer.Option(False, '--no-banner'),
          threshold: int = typer.Option(45, '--threshold', help="Minimum confidence score (0-100) for a finding to count as detected.")):
    """Benchmark detection accuracy (precision / recall / F1) against a labeled corpus."""
    if not no_banner:
        show_banner(c, 'BENCHMARK')
    from kodand.bench import run_bench
    if corpus is None:
        from importlib.resources import files
        corpus = files('kodand').joinpath('builtin_corpus')
    if not Path(corpus).exists():
        c.print(f"[red]Corpus not found:[/red] {corpus}"); raise typer.Exit(2)
    res = run_bench(str(corpus), score_threshold=threshold)
    t = Table(title=f"Kodand Benchmark — {res['samples']} samples (threshold {res['score_threshold']})")
    t.add_column('Category'); t.add_column('TP'); t.add_column('FP'); t.add_column('FN'); t.add_column('Precision'); t.add_column('Recall'); t.add_column('F1')
    for cat, d in res['per_category'].items():
        t.add_row(cat, str(d['tp']), str(d['fp']), str(d['fn']), f"{d['precision']:.2f}", f"{d['recall']:.2f}", f"{d['f1']:.2f}")
    o = res['overall']
    t.add_row('[bold]OVERALL[/bold]', str(o['tp']), str(o['fp']), str(o['fn']), f"[bold]{o['precision']:.2f}[/bold]", f"[bold]{o['recall']:.2f}[/bold]", f"[bold]{o['f1']:.2f}[/bold]")
    c.print(t)
    po = res['presence_only']
    if po['tp'] or po['fn']:
        c.print(f"Presence-only samples: detected {po['tp']}, missed {po['fn']}")


@app.command()
def schema(output: Path = typer.Option(Path('analysis-schema.json'), '--output', '-o')):
    """Write the JSON Schema for analysis.json output."""
    from kodand.models.analysis import RepositoryAnalysis
    output.write_text(json.dumps(RepositoryAnalysis.model_json_schema(), indent=2))


@app.command()
def ui(host: str = typer.Option('127.0.0.1', '--host'), port: int = typer.Option(8787, '--port'), no_banner: bool = typer.Option(False, '--no-banner'),
       allow_remote: bool = typer.Option(False, '--allow-remote', help='Allow binding to a non-loopback host')):
    """Launch the Kodand web console (projects, scans, custom templates, reports, benchmark)."""
    if not no_banner:
        show_banner(c, 'WEB UI')
    if host not in ('127.0.0.1', 'localhost', '::1') and not allow_remote:
        c.print(f"[red]Refusing to bind to non-loopback host '{host}'.[/red] The Kodand console is "
                "password-protected, but it can scan/read any local path this user can and it serves over "
                "plain HTTP — exposing it beyond localhost puts both the session cookie and that filesystem "
                "access on the network. Pass --allow-remote to proceed anyway.")
        raise typer.Exit(2)
    try:
        import uvicorn
    except ImportError:
        c.print("[red]Web UI dependencies missing.[/red] Install with: pip install 'kodand[ui]'  (or: pip install fastapi uvicorn python-multipart)"); raise typer.Exit(2)
    if allow_remote and "KODAND_ALLOWED_HOSTS" not in os.environ:
        # the console refuses Host headers it doesn't recognise (DNS-rebinding guard); a wildcard
        # bind can be reached under any name, so only a specific bound address is pinned
        os.environ["KODAND_ALLOWED_HOSTS"] = "*" if host in ("0.0.0.0", "::", "") else host
    c.print(f"Kodand Console: [cyan]http://{host}:{port}[/cyan]  (Ctrl+C to stop)")
    from kodand.webui import store
    if store.default_password_active():
        c.print("[yellow]First run:[/yellow] sign in with the default password [bold]kodand[/bold] — "
                "you'll be asked to set your own before the console lets you in.")
    uvicorn.run("kodand.webui.server:app", host=host, port=port, log_level="info")


cache_app = typer.Typer(no_args_is_help=True, help='Manage the workspace-global scan cache (~/.kodand/scan_cache.json).')
app.add_typer(cache_app, name='cache')


@cache_app.command('clear')
def cache_clear():
    """Delete the content-hash scan cache. The next scan starts cold; nothing else is affected."""
    from kodand.webui.scan_cache import clear_cache
    clear_cache()
    c.print('Scan cache cleared.')


password_app = typer.Typer(no_args_is_help=True, help='Manage the web console password (~/.kodand/auth.json).')
app.add_typer(password_app, name='password')


@password_app.command('reset')
def password_reset(to_default: bool = typer.Option(False, '--to-default', help="Reset to the default password 'kodand' and force a change on next sign-in")):
    """Set a new web console password from the terminal — the recovery path for a forgotten one."""
    from kodand.webui import store
    if to_default:
        store.reset_password_to_default()
        c.print("Password reset to the default [bold]kodand[/bold]; you'll be asked to change it on next sign-in.")
    else:
        new = typer.prompt('New password', hide_input=True, confirmation_prompt=True)
        try:
            store.set_password(new)
        except ValueError as e:
            c.print(f"[red]{e}[/red]"); raise typer.Exit(2)
        c.print('Password updated.')
    c.print('All existing console sessions have been signed out.')


@app.command()
def mcp(agent: bool = typer.Option(False, '--agent', help="Also act as the Claude Agent channel that `kodand agent` sessions use (you normally don't pass this yourself).")):
    """Run Kodand as an MCP server over stdio, for MCP-capable clients (Claude Code, Cursor, Claude Desktop, etc.)."""
    # no banner, no stray prints: stdio MCP framing shares stdout with this process — any
    # non-protocol byte written there corrupts the client's JSON-RPC stream.
    try:
        from kodand.mcpserver import run
    except ImportError:
        c.print("[red]MCP dependencies missing.[/red] Install with: pip install 'kodand[mcp]'"); raise typer.Exit(2)
    run(agent=agent)


# Every built-in Claude Code tool is switched off (--tools ""), so the only thing the agent session
# can do is call Kodand's MCP tools: scanned skills are hostile input, and a prompt injection in one
# must not reach a shell, the filesystem or the network.
AGENT_SESSION_NAME = "Kodand Claude Agent"
AGENT_BLOCKED_TOOLS = ("scan", "create_project", "verify_finding", "add_finding_comment")  # = mcpserver's; not imported, the mcp extra may be missing


def agent_command(claude: str) -> list[str]:
    import sys

    from kodand.webui import store
    d = store.agent_dir()
    cfg = d / "mcp.json"
    # sys.executable pins the agent's MCP server to this same Kodand install, whatever is on PATH,
    # and an explicit KODAND_HOME keeps it on the same workspace as the console that queues the jobs
    server = {"type": "stdio", "command": sys.executable, "args": ["-m", "kodand", "mcp", "--agent"]}
    if os.environ.get("KODAND_HOME"):
        server["env"] = {"KODAND_HOME": str(store.workspace_root())}
    cfg.write_text(json.dumps({"mcpServers": {"kodand": server}}, indent=2))
    return [claude, "--name", AGENT_SESSION_NAME, "--strict-mcp-config", "--mcp-config", str(cfg),
            "--dangerously-load-development-channels", "server:kodand",
            "--tools", "", "--allowedTools", "mcp__kodand",
            # the server already withholds these in agent mode; denying them here too costs nothing
            "--disallowedTools", ",".join(f"mcp__kodand__{t}" for t in AGENT_BLOCKED_TOOLS)]


@app.command()
def agent(print_only: bool = typer.Option(False, '--print', help='Print the Claude Code command instead of running it.')):
    """Start your Claude Code session as Kodand's Claude Agent: findings you send from the web console get verified in it.

    Leave it running in its own terminal. It uses your own Claude Code login; Kodand never sees it.
    """
    import shlex
    import shutil
    import subprocess

    from kodand.webui import store
    claude = shutil.which("claude")
    if not claude:
        c.print("[red]Claude Code not found on PATH.[/red] Install it and sign in first: https://code.claude.com/docs/en/quickstart")
        raise typer.Exit(2)
    cmd = agent_command(claude)
    workdir = store.agent_dir() / "workdir"; workdir.mkdir(exist_ok=True)  # empty: no project CLAUDE.md or settings leak in
    if print_only:
        c.print(f"cd {shlex.quote(str(workdir))} && {shlex.join(cmd)}", soft_wrap=True, highlight=False, markup=False)
        return
    if not store.load_mcp_settings().get("data_sharing_acknowledged"):
        c.print("[yellow]Heads-up:[/yellow] MCP data sharing isn't acknowledged yet (web console → Settings → MCP Server), "
                "so Claude Agent can't read any project until you do.")
    c.print("Starting Claude Code as [bold #38bdf8]Kodand Claude Agent[/]. Confirm the development-channel prompt, "
            "then leave this terminal open — jobs from the web console will appear here.")
    os.chdir(workdir)
    if os.name == "nt":
        raise typer.Exit(subprocess.call(cmd))
    os.execvp(claude, cmd)  # hand the terminal straight to Claude Code
