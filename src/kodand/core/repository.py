import atexit
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from kodand.exceptions import InvalidRepositoryError

EX={".git",".venv","venv","node_modules","dist","build","__pycache__",".pytest_cache"}
# build output dirs: skipped as noise, EXCEPT where the name is a skill/command's own
# name (`.claude/skills/build/SKILL.md`) — never let an exclusion hide an agent artifact
BUILD_OUTPUT_DIRS={"dist","build"}
_AGENT_CONTAINERS={"skills","agents","commands","rules","workflows","prompts","steering"}
def is_excluded_dir(path):
 """True for a directory the walk (and every supporting-file listing) skips."""
 path=Path(path);name=path.name
 if name not in EX:return False
 if name not in BUILD_OUTPUT_DIRS:return True
 if path.parent.name.lower() in _AGENT_CONTAINERS:return False
 from kodand.entrypoints import match_entrypoint  # local: entrypoints imports the adapters, not this module
 try:
  return not any(c.is_file() and match_entrypoint(c.name) for c in path.iterdir())
 except OSError:
  return True
def iter_tree(directory):
 """Every file and symlink under `directory`, pruning excluded dirs exactly as
 walk_repository does — so an entrypoint at the repo root (AGENTS.md, CLAUDE.md)
 never drags node_modules/.git/.venv into its supporting files."""
 for cur,dirs,names in os.walk(directory,topdown=True,followlinks=False):
  cp=Path(cur);keep=[]
  for d in sorted(dirs):
   child=cp/d
   if child.is_symlink():yield child
   elif not is_excluded_dir(child):keep.append(d)
  dirs[:]=keep
  for n in sorted(names):yield cp/n
ARCHIVE_SUFFIXES=(".zip",".tar.gz",".tgz")
# scanned archives are untrusted: bound what one can unpack to, so a small "zip bomb" can't fill the disk
MAX_EXTRACT_BYTES=1024*1024*1024
MAX_EXTRACT_ENTRIES=100_000
@dataclass
class WalkResult:
 files:list=field(default_factory=list);directories_examined:int=0;excluded_paths:list=field(default_factory=list);errors:list=field(default_factory=list)
def is_archive_file(p):
 p=Path(p)
 return p.is_file() and p.name.lower().endswith(ARCHIVE_SUFFIXES)
_is_archive=is_archive_file
def extract_archive_into(p,dest):
 """Extract archive `p` into the existing directory `dest`, guarding every
 entry so it can't escape `dest` (zip-slip). Shared by validate_repository
 (extracts to a fresh temp dir) and the web UI's single-archive upload
 (extracts directly into the scan's own target dir)."""
 dest=Path(dest).resolve()
 try:
  if p.name.lower().endswith(".zip"):
   with zipfile.ZipFile(p) as zf:
    _check_archive_size([m.file_size for m in zf.infolist()],p)
    for m in zf.infolist():
     target=(dest/m.filename).resolve()
     if target!=dest and dest not in target.parents:
      raise InvalidRepositoryError(f"Archive contains an unsafe path escaping the extraction root: {m.filename}")
    zf.extractall(dest)
  else:
   with tarfile.open(p) as tf:
    _check_archive_size([m.size for m in tf.getmembers()],p)
    tf.extractall(dest,filter="data")  # stdlib zip-slip + symlink-escape guard (PEP 706)
 except (zipfile.BadZipFile,tarfile.TarError) as e:
  raise InvalidRepositoryError(f"Invalid or corrupt archive: {p}") from e
def _check_archive_size(sizes,p):
 if len(sizes)>MAX_EXTRACT_ENTRIES or sum(sizes)>MAX_EXTRACT_BYTES:
  raise InvalidRepositoryError(f"Archive is too large to scan safely ({len(sizes)} entries, {sum(sizes)//(1024*1024)} MB unpacked; limits are {MAX_EXTRACT_ENTRIES} entries and {MAX_EXTRACT_BYTES//(1024*1024)} MB): {p.name}")
def copy_snapshot(src,dest):
 """Copy a scanned directory into Kodand's workspace, skipping excluded dirs and every
 symlink. Following a symlink here would copy whatever it points at (e.g. a planted
 link to ~/.ssh/id_rsa) into the scan, where the Files viewer and MCP clients read it."""
 def ignore(dirpath,names):
  return {n for n in names if os.path.islink(os.path.join(dirpath,n)) or (os.path.isdir(os.path.join(dirpath,n)) and is_excluded_dir(os.path.join(dirpath,n)))}
 shutil.copytree(src,dest,dirs_exist_ok=True,ignore=ignore)
def _extract_archive(p):
 dest=Path(tempfile.mkdtemp(prefix="kodand-archive-")).resolve()
 try:
  extract_archive_into(p,dest)
 except InvalidRepositoryError:
  shutil.rmtree(dest,ignore_errors=True);raise
 atexit.register(shutil.rmtree,dest,ignore_errors=True)
 return dest
def validate_repository(p):
 p=Path(p).expanduser()
 if _is_archive(p):return _extract_archive(p)
 if not p.exists() or not p.is_dir(): raise InvalidRepositoryError(f"Invalid repository: {p}")
 return p.resolve()
def walk_repository(p):
 root=validate_repository(p);o=WalkResult()
 def err(e):o.errors.append((getattr(e,"filename","unknown") or "unknown",str(e)))
 for cur,dirs,names in os.walk(root,topdown=True,followlinks=False,onerror=err):
  o.directories_examined+=1;cp=Path(cur);keep=[]
  for d in sorted(dirs):
   child=cp/d
   if child.is_symlink():o.files.append(child)
   elif is_excluded_dir(child):o.excluded_paths.append(child.relative_to(root).as_posix())
   else:keep.append(d)
  dirs[:]=keep;o.files += [cp/n for n in sorted(names)]
 return o
