"""requirements.txt pins the exact, tested version of every runtime dependency (what install.sh installs
and what security scanners read); pyproject.toml keeps the supported ranges. The two, and the README's
dependency table, must agree."""
import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def _pins() -> dict:
    pins = {}
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            req = Requirement(line)
            [spec] = req.specifier
            assert spec.operator == "==", f"{line}: pin an exact version"
            pins[canonicalize_name(req.name)] = spec.version
    return pins


def _ranges() -> dict:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    return {canonicalize_name(r.name): r.specifier for r in map(Requirement, deps)}


def test_every_dependency_is_pinned_within_its_supported_range():
    pins = _pins()
    for name, supported in _ranges().items():
        assert name in pins, f"{name} is missing from requirements.txt"
        assert supported.contains(pins[name]), f"{name}=={pins[name]} is outside the supported range {supported}"


def test_readme_dependency_table_matches_the_pins():
    pins, ranges = _pins(), _ranges()
    rows = re.findall(r"^\| `([^`]+)` \| ([^|]+?) \| ([^|]+?) \|", (ROOT / "README.md").read_text(), re.M)
    table = {canonicalize_name(n): (s.strip(), v.strip()) for n, s, v in rows}
    assert set(table) == set(ranges), "README's dependency table should list exactly the pyproject dependencies"
    for name, (supported, pinned) in table.items():
        assert pinned == pins[name], f"README says {name} {pinned}, requirements.txt pins {pins[name]}"
        assert SpecifierSet(supported) == ranges[name], f"README's range for {name} is out of date"
