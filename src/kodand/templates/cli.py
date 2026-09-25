from importlib.resources import files
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from kodand.scanner import inventory_repository
from kodand.templates.correlation import correlate_capabilities
from kodand.templates.loader import load_templates
from kodand.templates.matcher import match_template_views, precompute_file_views

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
    inv = inventory_repository(repository_root)
    entry_files = sorted({repository_root / e.entrypoint for e in inv.extensions})
    all_matches = []; all_caps = []
    for sf in entry_files:
        precomputed = precompute_file_views(sf, repository_root)
        if precomputed is None:
            continue
        relative_path, views = precomputed
        for t in templates:
            ms = match_template_views(t, relative_path, views)
            if ms:
                all_caps.extend(t.capabilities); all_matches.extend(ms)
    table = Table(title="Kodand Template Scan (v3)")
    table.add_column("Template"); table.add_column("Category"); table.add_column("Severity"); table.add_column("Kind"); table.add_column("Location"); table.add_column("Matched Value")
    for m in all_matches:
        table.add_row(m.template_id, m.category, m.severity.upper(), m.match_kind, f"{m.file}:{m.line}:{m.column_start}", m.matched_value)
    console.print(table); console.print()
    console.print(f"Built-in Templates : {len(builtin_templates)}")
    console.print(f"Custom Templates : {len(custom_templates)}")
    console.print(f"Combined Templates : {len(templates)}")
    console.print(f"Entry Files Scanned : {len(entry_files)}")
    console.print(f"Template Matches : {len(all_matches)}")
    print(); print("Capabilities"); print("------------")
    for c in sorted(set(all_caps)): print(c)
    print(); print("Correlated Risks"); print("----------------")
    for r in correlate_capabilities(all_caps): print(r)
