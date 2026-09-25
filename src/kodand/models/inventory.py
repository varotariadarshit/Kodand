from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from kodand import __version__


class FileArtifact(BaseModel):
 relative_path:str;artifact_type:str="file";size_bytes:int=0;sha256:str|None=None;is_symlink:bool=False;symlink_target:str|None=None;escapes_repository:bool=False;read_error:str|None=None
class SkillMetadata(BaseModel):
 name:str|None=None;description:str|None=None;license:str|None=None;compatibility:str|None=None;allowed_tools:list[str]=Field(default_factory=list);additional_fields:dict[str,Any]=Field(default_factory=dict)
class AgentExtension(BaseModel):
 extension_id:str;platform:str;extension_type:str;root_path:str;entrypoint:str;metadata:SkillMetadata;instruction_line_count:int=0;supporting_files:list[FileArtifact]=Field(default_factory=list);parse_errors:list[str]=Field(default_factory=list);undeclared_supporting_files:list[str]=Field(default_factory=list);broken_references:list[str]=Field(default_factory=list)
class PlatformDetection(BaseModel):
 platform:str;confidence:Literal["high","medium","low"];evidence:list[str]=Field(default_factory=list)
class ScanWarning(BaseModel):
 code:str;message:str;path:str|None=None
class RepositoryInventory(BaseModel):
 scanner_version:str=__version__;scan_type:str="inventory";repository_name:str;repository_root:str;scanned_at:datetime=Field(default_factory=lambda:datetime.now(timezone.utc));platforms:list[PlatformDetection]=Field(default_factory=list);extensions:list[AgentExtension]=Field(default_factory=list);repository_artifacts:list[FileArtifact]=Field(default_factory=list);warnings:list[ScanWarning]=Field(default_factory=list);files_examined:int=0;directories_examined:int=0;excluded_paths:list[str]=Field(default_factory=list)
