from kodand.models.inventory import PlatformDetection


def detect_platforms(root,files):
 evidence={k:set() for k in ["claude-code","microsoft-copilot","gemini-cli","chatgpt-openai","generic-agent-framework","cursor","windsurf"]}
 for p in files:
  rel=p.relative_to(root).as_posix();low=rel.lower();name=p.name.lower();parts={x.lower() for x in p.parts}
  if name in {"claude.md","skill.md","skills.md",".mcp.json","mcp.json","claude_desktop_config.json"} or ".claude" in parts:evidence["claude-code"].add(rel)
  if low==".github/copilot-instructions.md" or low.startswith(".github/instructions/") or ".copilot" in parts:evidence["microsoft-copilot"].add(rel)
  if name in {"gemini.md","gemini-extension.json"} or ".gemini" in parts:evidence["gemini-cli"].add(rel)
  if ".openai" in parts or name in {"openai.yaml","openai.yml","openai.json","gpt-actions.yaml","gpt-actions.json","agents.md","agents.override.md"}:evidence["chatgpt-openai"].add(rel)
  if any(x in parts for x in {"agents","prompts","orchestrator","workflows"}):evidence["generic-agent-framework"].add(rel)
  if (name.endswith(".mdc") and low.startswith(".cursor/rules/")) or ".cursor" in parts:evidence["cursor"].add(rel)
  if name==".windsurfrules" or ".windsurf" in parts:evidence["windsurf"].add(rel)
 out=[]
 for k,v in evidence.items():
  if v:out.append(PlatformDetection(platform=k,confidence="high" if len(v)>1 or k=="claude-code" else "medium",evidence=sorted(v)))
 return sorted(out,key=lambda x:x.platform)
