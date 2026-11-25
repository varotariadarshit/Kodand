from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from kodand.templates.loader import load_templates

app = typer.Typer(help="Manage and test Kodand detection templates.", no_args_is_help=True)
console = Console()
def load_builtin_templates():
    return load_templates(files("kodand").joinpath("builtin_templates"))
@app.command("list")
def list_templates():
    templates = load_builtin_templates()
    table = Table(title="Kodand Detection Templates")
    table.add_column("Template ID"); table.add_column("Category"); table.add_column("Severity"); table.add_column("Confidence"); table.add_column("Literals"); table.add_column("Regex")
    for t in sorted(templates, key=lambda t: t.id):
        table.add_row(t.id, t.info.category, t.info.severity.upper(), t.info.confidence.upper(), str(len(t.detection.match)), str(len(getattr(t.detection,"regex",[]))))
    console.print(table)
    console.print(f"\nTemplates Loaded: {len(templates)}")
@app.command("scan")
def scan_templates(repository: Path = typer.Argument(..., help="Repository containing agent skill/instruction files."), templates_directory: Path = typer.Option(None, "--templates", "-t", help="Optional directory containing custom YAML templates.")):
    repository_root = repository.expanduser().resolve()
    if not repository_root.exists() or not repository_root.is_dir():
        console.print(f"[red]Repository does not exist or is not a directory:[/red] {repository_root}"); raise typer.Exit(code=2)
    builtin_templates = load_builtin_templates(); custom_templates = []
    if templates_directory is not None:
        custom_root = templates_directory.expanduser().resolve()
        if not custom_root.is_dir():
            console.print(f"[red]Custom template path is not a directory:[/red] {custom_root}"); raise typer.Exit(code=2)
        custom_templates = load_templates(custom_root)
    templates = builtin_templates + custom_templates
    ids = [t.id for t in templates]; dups = sorted(t for t in set(ids) if ids.count(t) > 1)
    if dups:
        console.print("[red]Duplicate template IDs detected:[/red] " + ", ".join(dups)); raise typer.Exit(code=2)
    # the same pipeline as `kodand analyze`, the web console and MCP (supporting files,
    # code/JSON structural rules, context scoring) — a template tested here behaves
    # exactly as it will in a real scan; the cache is skipped so edits always apply
    import json
    import tempfile

    from kodand.webui.scan_service import run_template_scan
    with tempfile.TemporaryDirectory(prefix="kodand-tscan-") as td:
        res = run_template_scan(str(repository_root), use_custom=templates_directory is not None,
                                custom_dir=templates_directory.expanduser().resolve() if templates_directory else None,
                                out_dir=Path(td), formats=("json",), use_cache=False)
        analysis = json.loads((Path(td) / "analysis.json").read_text(encoding="utf-8"))
    findings = analysis.get("findings", [])
    table = Table(title="Kodand Template Scan (v3)")
    table.add_column("Template"); table.add_column("Category"); table.add_column("Severity"); table.add_column("Kind"); table.add_column("Location"); table.add_column("Matched Value")
    n_matches = 0
    for f in findings:
        for o in f.get("occurrences", []):
            n_matches += 1
            table.add_row(o.get("rule_id") or f["rule_id"], f["category"], f["severity"].upper(), o.get("match_kind") or "",
                          f"{o['file']}:{o['line']}:{o.get('column_start') or 1}", o.get("matched_value") or "")
    console.print(table); console.print()
    console.print(f"Built-in Templates : {len(builtin_templates)}")
    console.print(f"Custom Templates : {len(custom_templates)}")
    console.print(f"Combined Templates : {len(templates)}")
    console.print(f"Entry Files Scanned : {res['skill_files']}")
    console.print(f"Template Matches : {n_matches}")
    for w in res.get("warnings", []):
        console.print(f"[yellow]Warning ({w['code']}):[/yellow] " + escape(w["message"]), highlight=False)
    all_caps = sorted({c for f in findings for c in f.get("capabilities", [])})
    print(); print("Capabilities"); print("------------")
    for c in all_caps: print(c)
    print(); print("Correlated Risks"); print("----------------")
    for r in analysis.get("correlated_risks", []): print(r)
