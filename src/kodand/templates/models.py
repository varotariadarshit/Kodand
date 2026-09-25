from typing import List

from pydantic import BaseModel, Field


class TemplateInfo(BaseModel):
    name: str
    severity: str
    confidence: str
    category: str
class DetectionRule(BaseModel):
    match: List[str] = Field(default_factory=list)
    regex: List[str] = Field(default_factory=list)
class RiskDefinition(BaseModel):
    title: str
class KodandTemplate(BaseModel):
    id: str
    info: TemplateInfo
    detection: DetectionRule
    capabilities: List[str] = Field(default_factory=list)
    risk: RiskDefinition
    recommendation: str
