"""JSON-structural rules, expressed as ordinary KodandTemplate instances so they
carry a normal rule_id/category/severity/base-confidence and flow through the
rest of the pipeline (accuracy/suppress/reporting) exactly like a YAML
template. `detection` is left empty since the actual detection logic lives in
json_struct.py, not in a `match`/`regex` list — mirrors rules.py's CODE_RULES
for the Python/JS AST rules."""
from kodand.templates.models import DetectionRule, KodandTemplate, RiskDefinition, TemplateInfo


def _rule(rule_id: str, name: str, severity: str, confidence: str, category: str,
          capabilities: list[str], recommendation: str) -> KodandTemplate:
    return KodandTemplate(
        id=rule_id,
        info=TemplateInfo(name=name, severity=severity, confidence=confidence, category=category),
        detection=DetectionRule(),
        capabilities=capabilities,
        risk=RiskDefinition(title=name),
        recommendation=recommendation,
    )


JSON_RULES: dict[str, KodandTemplate] = {
    r.id: r for r in [
        _rule("HOOK01-WILDCARD-MATCHER", "Hook Fires on Every Tool Call", "medium", "medium", "HOOK01",
              ["isolation-escape"],
              "Scope hook `matcher` patterns to the specific tool(s) they need to observe instead of "
              "a wildcard/empty matcher, which runs the hook's command on every tool invocation. "
              "Severity is escalated when the paired command itself looks risky (shell/network/"
              "persistence/privilege-escalation shape) — a wildcard trigger compounds whatever that "
              "command can already do."),
        _rule("HOOK05-HIDDEN-DEFINITION", "Hook Registered Under an Undocumented Event Name", "medium", "medium", "HOOK05",
              ["isolation-escape"],
              "This hook fires on an event name outside Claude Code's documented set (PreToolUse, "
              "PostToolUse, UserPromptSubmit, Notification, Stop, SubagentStop, PreCompact, "
              "SessionStart, SessionEnd). An unrecognized or typo-squatted event key is easy to miss "
              "in review and may be a leftover, a mistake, or an attempt to hide a hook from someone "
              "scanning for the well-known trigger names — confirm it is intentional and remove it if not."),
        _rule("MCP04-UNPINNED-LAUNCHER", "Unpinned MCP Server Launcher", "medium", "medium", "MCP04",
              ["supply-chain"],
              "Pin MCP server packages to an exact, reviewed version (e.g. `pkg@1.4.2`, not `pkg`, "
              "`pkg@latest`, or `pkg@next`) — or vendor/mirror them — instead of launching a "
              "floating version via npx/uvx/pipx/bunx. A floating reference can change what code "
              "runs on your machine without any change to your own config."),
        _rule("MCP04-TYPOSQUAT-PACKAGE", "Typosquatted MCP Server Package", "high", "high", "MCP04",
              ["supply-chain"],
              "This server launches a package whose name is one or two characters away from an "
              "official MCP server package — the classic shape of a typosquat. Replace it with the "
              "exact official name, pin the version, and check whether the lookalike package was "
              "ever run on this machine."),
        _rule("MCP09-UNREGISTERED-SERVER-PATH", "Shadow or Ungoverned MCP Server", "medium", "medium", "MCP09",
              ["governance-gap"],
              "Install MCP servers through a package manager or a reviewed, version-controlled "
              "location, give each one a distinct name, and never point two different server "
              "entries at the same launcher — an ad hoc launch path, a duplicated launcher across "
              "server names, or a server name that closely resembles another configured one are all "
              "signs of a server running outside normal governance/inventory, or of one server "
              "impersonating another."),
    ]
}
JSON_RULES_LIST: list[KodandTemplate] = list(JSON_RULES.values())
