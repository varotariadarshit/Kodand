from kodand.entrypoints import match_entrypoint
from kodand.models.inventory import PlatformDetection

# directory-level hints, on top of the entrypoint registry: a platform's config
# dir is evidence it's in use even when no file in it is a scannable entrypoint
_DIR_HINTS = {
 ".claude":"claude-code",".claude-plugin":"claude-code",".copilot":"microsoft-copilot",".gemini":"gemini-cli",
 ".openai":"chatgpt-openai",".codex":"chatgpt-openai",".agents":"chatgpt-openai",".cursor":"cursor",
 ".windsurf":"windsurf",".devin":"windsurf",".codeium":"windsurf",".cline":"cline",".clinerules":"cline",
 ".roo":"roo-code",".continue":"continue",".junie":"jetbrains-junie",".kiro":"kiro",".amazonq":"kiro",".opencode":"opencode",
}
_OPENAI_NAMES={"openai.yaml","openai.yml","openai.json","gpt-actions.yaml","gpt-actions.json"}


def detect_platforms(root,files):
 """Platform evidence derived from the entrypoint registry (kodand.entrypoints), so a
 platform is never reported for a file type the scanner doesn't actually scan, plus
 directory-level hints for config dirs that hold no entrypoint."""
 evidence={}
 for p in files:
  rel=p.relative_to(root).as_posix();parts=[x.lower() for x in p.relative_to(root).parts];name=p.name.lower()
  spec=match_entrypoint(rel)
  if spec:evidence.setdefault(spec.platform,set()).add(rel)
  for d in parts[:-1]:
   if d in _DIR_HINTS:evidence.setdefault(_DIR_HINTS[d],set()).add(rel)
  if name in _OPENAI_NAMES:evidence.setdefault("chatgpt-openai",set()).add(rel)
  if any(x in parts[:-1] for x in ("agents","prompts","orchestrator","workflows")):evidence.setdefault("generic-agent-framework",set()).add(rel)
 out=[]
 for k,v in evidence.items():
  out.append(PlatformDetection(platform=k,confidence="high" if len(v)>1 or k=="claude-code" else "medium",evidence=sorted(v)))
 return sorted(out,key=lambda x:x.platform)
