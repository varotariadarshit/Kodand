from kodand.adapters.common import Parsed, split_frontmatter
from kodand.models.inventory import SkillMetadata


def parse_skill_text(t):
 o=Parsed(body=t)
 raw,body,errors=split_frontmatter(t,require_frontmatter=True)
 o.errors=errors;o.body=body
 if raw is None:return o
 allowed=raw.get("allowed-tools",[]);allowed=allowed.split() if isinstance(allowed,str) else [str(x) for x in allowed] if isinstance(allowed,list) else []
 known={"name","description","license","compatibility","allowed-tools"};o.metadata=SkillMetadata(name=raw.get("name"),description=raw.get("description"),license=raw.get("license"),compatibility=raw.get("compatibility"),allowed_tools=allowed,additional_fields={k:v for k,v in raw.items() if k not in known})
 return o
