"""AST-detected rules, expressed as ordinary KodandTemplate instances so they carry
a normal rule_id/category/severity/base-confidence and flow through the rest of
the pipeline (accuracy/suppress/reporting) exactly like a YAML template. `detection`
is left empty since the actual detection logic lives in python_ast.py/js_ast.py,
not in a `match`/`regex` list."""
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


CODE_RULES: dict[str, KodandTemplate] = {
    r.id: r for r in [
        _rule("AST04-PY-EVAL-EXEC", "Dynamic Code Evaluation (Python AST)", "high", "high", "AST04",
              ["code-execution"],
              "Avoid eval/exec/compile on any value not fully known at review time; if dynamic "
              "execution is unavoidable, restrict it to a narrow, explicitly-allowed grammar."),
        _rule("AST04-PY-DYNAMIC-IMPORT", "Dynamic Module Import (Python AST)", "medium", "medium", "AST04",
              ["code-execution"],
              "Avoid __import__/importlib.import_module with a non-literal module name — it can "
              "load arbitrary code chosen at runtime rather than reviewed at commit time."),
        _rule("AST04-PY-DESERIALIZATION", "Unsafe Deserialization (Python AST)", "high", "high", "AST04",
              ["deserialization"],
              "Never unpickle/unmarshal data from an untrusted source — use a safe serialization "
              "format (e.g. JSON) instead."),
        _rule("AST01-PY-SHELL-INJECTION", "Shell Command Injection Shape (Python AST)", "high", "high", "AST01",
              ["shell-execution"],
              "Never build a shell command from untrusted/dynamic input with shell=True — pass "
              "argument lists directly to subprocess without invoking a shell."),
        _rule("AST01-PY-EXFIL", "Credential/Env Read Followed by Network Send (Python AST)", "high", "medium", "AST01",
              ["data-exfiltration", "network-access"],
              "Review why this function reads environment variables or files and then makes an "
              "outbound network call — this shape matches credential/data exfiltration."),
        _rule("AST03-PY-HARDCODED-CREDENTIAL", "Hardcoded Credential (Python AST)", "high", "medium", "AST03",
              ["credential-access"],
              "Never hardcode API keys/tokens/passwords in source — load them from environment "
              "variables or a secret manager."),
        _rule("AST04-JS-EVAL-EXEC", "Dynamic Code Evaluation (JS/TS AST)", "high", "high", "AST04",
              ["code-execution"],
              "Avoid eval()/new Function() on any value not fully known at review time."),
        _rule("AST04-JS-DYNAMIC-IMPORT", "Dynamic Module Import (JS/TS AST)", "medium", "medium", "AST04",
              ["code-execution"],
              "Avoid require()/import() with a non-literal module specifier — it can load "
              "arbitrary code chosen at runtime rather than reviewed at commit time."),
        _rule("AST01-JS-SHELL-INJECTION", "Shell Command Injection Shape (JS/TS AST)", "high", "high", "AST01",
              ["shell-execution"],
              "Never pass untrusted/dynamic input to child_process.exec/execSync or spawn with "
              "shell:true — use spawn/execFile with an argument array instead."),
        _rule("AST01-JS-EXFIL", "Credential/Env Read Followed by Network Send (JS/TS AST)", "high", "medium", "AST01",
              ["data-exfiltration", "network-access"],
              "Review why this function reads environment variables or files and then makes an "
              "outbound network call — this shape matches credential/data exfiltration."),
        _rule("AST03-JS-HARDCODED-CREDENTIAL", "Hardcoded Credential (JS/TS AST)", "high", "medium", "AST03",
              ["credential-access"],
              "Never hardcode API keys/tokens/passwords in source — load them from environment "
              "variables or a secret manager."),
        _rule("AST08-HIDDEN-UNICODE", "Hidden Text (Invisible Unicode Characters)", "medium", "high", "AST08",
              ["scanner-evasion"],
              "Remove zero-width, bidirectional-control and Unicode tag characters (and their "
              "HTML-entity forms such as `&#x200B;`). They hide text from a human reviewer while "
              "the agent still reads it, a common way to smuggle instructions into a skill."),
        _rule("AST04-JS-OBFUSCATED-CODE", "Obfuscated/Packed Code (JS/TS AST)", "medium", "medium", "AST04",
              ["scanner-evasion"],
              "Obfuscated/packed code defeats human review — ship readable source and build "
              "artifacts separately, with the build step reproducible from source."),
        # --- markdown / frontmatter structural rules (markdown_rules.py) ---
        _rule("AST05-UNTRUSTED-FETCH", "Untrusted Web Content Pulled Into Agent Context", "medium", "medium", "AST05",
              ["external-instruction", "network-access"],
              "The skill tells the agent to fetch or crawl a URL that comes from the user, an issue or another "
              "untrusted source. Whatever that page says lands in the agent's context and can carry injected "
              "instructions (indirect prompt injection). Treat fetched content strictly as data: summarise or "
              "extract fields only, never follow instructions found in it, restrict fetching to an allow-list of "
              "domains, and avoid pairing web fetching with an unrestricted shell. Escalated to high when the "
              "skill also tells the agent to follow/run what it reads, or grants an unscoped shell tool."),
        _rule("AST09-PRELOAD-SHELL", "Shell Command Runs When the Skill Loads", "medium", "high", "AST09",
              ["shell-execution"],
              "A `!`command`` block runs in the user's shell as soon as the skill or command is invoked, before "
              "the model or the user sees its output. Keep these to read-only, local, side-effect-free commands "
              "(git status, ls); never fetch from the network, read credentials or pipe into a shell. Escalated "
              "to high for network, credential, eval or pipe-to-shell commands."),
        _rule("AST03-BROAD-TOOL-GRANT", "Unrestricted Shell Tool Grant", "medium", "high", "AST03",
              ["shell-execution"],
              "`allowed-tools` pre-approves an unscoped shell (`Bash`, `Bash(*)`), so every command the skill "
              "leads the agent to run executes without a permission prompt. Scope the grant to the exact "
              "commands needed, e.g. `Bash(git status:*)`. Escalated to high when web fetch/search tools are "
              "granted alongside it: untrusted web content plus an unprompted shell is a direct injection path."),
        _rule("HOOK02-FRONTMATTER-HOOK", "Hook Declared in Skill or Agent Frontmatter", "medium", "medium", "HOOK02",
              ["shell-execution"],
              "Hooks declared in a skill's or subagent's frontmatter run shell commands automatically while it "
              "is active, and are easy to miss because they don't live in settings.json. Review every command; "
              "prefer project-level hooks that go through normal review. Escalated to high for network, "
              "credential, eval or pipe-to-shell commands."),
        _rule("AST04-MALFORMED-FRONTMATTER", "Malformed or Missing Skill Frontmatter", "low", "low", "AST04",
              [],
              "Fix the YAML frontmatter block (`---` / name / description / `---`). Malformed metadata can make "
              "platforms parse the skill differently from what a reviewer sees, or skip its restrictions."),
        _rule("AST08-SYMLINK-ESCAPE", "Symlink Pointing Outside the Repository", "high", "high", "AST08",
              ["credential-access", "scanner-evasion"],
              "A file in the skill is a symbolic link to a path outside the repository (e.g. ~/.ssh/id_rsa). "
              "When the agent reads the 'reference' it reads that target instead, and static scans never see "
              "its content. Replace the link with the real file content, or remove it."),
    ]
}
CODE_RULES_LIST: list[KodandTemplate] = list(CODE_RULES.values())
