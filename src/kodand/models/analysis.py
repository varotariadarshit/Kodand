from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from kodand import __version__
from kodand.models.inventory import RepositoryInventory


class FindingOccurrence(BaseModel):
 file:str;line:int;column_start:int|None=None;column_end:int|None=None;excerpt:str;matched_value:str;evidence_type:str;evidence_hash:str="";context:str="instruction";match_kind:str="literal";rule_id:str="";decoded_from:str|None=None
class CorrelatedFinding(BaseModel):
 finding_id:str;rule_id:str;category:str;category_name:str;title:str
 severity:Literal["critical","high","medium","low","informational"]
 confidence:Literal["high","medium","low"]
 confidence_score:int=0
 status:Literal["candidate","needs-review","confirmed","false-positive","accepted-risk","remediated","suppressed"]="candidate"
 description:str;technical_root_cause:str;attack_scenario:str;preconditions:str;potential_impact:str;remediation:str;validation_guidance:str
 affected_platforms:list[str]=Field(default_factory=list);affected_extensions:list[str]=Field(default_factory=list);affected_files:list[str]=Field(default_factory=list);capabilities:list[str]=Field(default_factory=list);occurrence_count:int=0;occurrences:list[FindingOccurrence]=Field(default_factory=list);requires_human_validation:bool=True
 merged_rule_ids:list[str]=Field(default_factory=list);proximity_signals:list[str]=Field(default_factory=list);relationship_signals:list[str]=Field(default_factory=list);suppressed_reason:str|None=None
class CoverageItem(BaseModel):
 category:str;name:str;status:Literal["reviewed-findings","reviewed-no-findings","partially-reviewed","not-supported","not-applicable"];finding_count:int=0
class Summary(BaseModel):
 total:int=0;critical:int=0;high:int=0;medium:int=0;low:int=0;informational:int=0;overall_risk:str="Informational";by_category:dict[str,int]=Field(default_factory=dict);suppressed:int=0
class RepositoryAnalysis(BaseModel):
 schema_version:str="3.0";scanner_version:str=__version__;rule_pack_version:str="KODAND-1.0";scan_type:str="analysis";analyzed_at:datetime=Field(default_factory=lambda:datetime.now(timezone.utc));inventory:RepositoryInventory;findings:list[CorrelatedFinding]=Field(default_factory=list);coverage:list[CoverageItem]=Field(default_factory=list);summary:Summary=Field(default_factory=Summary);correlated_risks:list[str]=Field(default_factory=list);limitations:list[str]=Field(default_factory=lambda:["Static analysis does not prove runtime exploitability.","Candidate findings require human validation.","Platform fingerprinting indicates matching artifacts, not confirmed deployment."])
