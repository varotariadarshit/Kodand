from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from kodand import __version__

LOGO = [
    "██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗██████╗ ",
    "██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔══██╗",
    "█████╔╝ ██║   ██║██║  ██║███████║██╔██╗ ██║██║  ██║",
    "██╔═██╗ ██║   ██║██║  ██║██╔══██║██║╚██╗██║██║  ██║",
    "██║  ██╗╚██████╔╝██████╔╝██║  ██║██║ ╚████║██████╔╝",
    "╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ",
]
# the web console's brand gradient: logo cyan -> button blue -> button violet
GRADIENT = [(0x38, 0xBD, 0xF8), (0x3B, 0x82, 0xF6), (0x7C, 0x3A, 0xED)]
NAME = "Agentic AI Skills Threat and Risk Assessment"
TAGLINE = "Secure Skills. Intelligent Agents. Resilient Future."


def _gradient_color(pos: float) -> str:
    pos = min(max(pos, 0.0), 1.0) * (len(GRADIENT) - 1)
    i = min(int(pos), len(GRADIENT) - 2)
    t = pos - i
    r, g, b = (round(a + (c - a) * t) for a, c in zip(GRADIENT[i], GRADIENT[i + 1]))
    return f"#{r:02x}{g:02x}{b:02x}"


def gradient_text(line: str, bold: bool = True) -> Text:
    text = Text()
    width = max(len(line) - 1, 1)
    for x, ch in enumerate(line):
        text.append(ch, style=f"{'bold ' if bold else ''}{_gradient_color(x / width)}")
    return text


def _rule_count() -> int:
    from kodand.codeanalysis.json_rules import JSON_RULES_LIST
    from kodand.codeanalysis.rules import CODE_RULES_LIST
    from kodand.webui.scan_service import load_builtin_templates
    return len(load_builtin_templates()) + len(CODE_RULES_LIST) + len(JSON_RULES_LIST)


def show_banner(c: Console, mode: str = "READY") -> None:
    c.print()
    if c.width >= len(LOGO[0]) + 2:
        for line in LOGO:
            c.print(gradient_text(line), highlight=False)
    else:  # too narrow for the block letters — the wordmark alone still reads as the brand
        c.print(gradient_text("K O D A N D"), highlight=False)
    c.print(Text(NAME, style="bold"), highlight=False)
    c.print(Text(TAGLINE, style="dim italic"), highlight=False)

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim", no_wrap=True)
    info.add_column()
    info.add_row("Version", f"[bold #38bdf8]{__version__}[/]")
    info.add_row("Coverage", "Agentic Skills · MCP · Hooks  [dim](3 × Top 10)[/dim]")
    info.add_row("Engine", f"{_rule_count()} rules · regex · code AST · JSON structure")
    info.add_row("Status", f"[bold #22c55e]●[/] [bold]{mode}[/bold]")
    c.print(Panel(Group(info), border_style="#3b82f6", expand=False, padding=(0, 2)), highlight=False)
