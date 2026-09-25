"""Hardening of Kodand's own attack surface: it scans untrusted repositories, so
paths, archives and the console's HTTP layer are all treated as hostile input."""
import io
import os
import stat
import tarfile
import zipfile

import pytest
from fastapi.testclient import TestClient

from kodand.core import repository
from kodand.exceptions import InvalidRepositoryError
from kodand.webui import server, store


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("KODAND_HOME", str(tmp_path / "home"))
    server._login_failures.clear()
    yield


def _signed_in_client():
    store.set_password("a-strong-password")
    c = TestClient(server.app, follow_redirects=False)
    c.cookies.set(server.SESSION_COOKIE, store.create_session())
    return c


def test_ids_that_walk_out_of_their_project_are_refused():
    pid = store.create_project("Real")["id"]
    other = store.create_project("Other")["id"]
    for bad_sid in ["..", "../../" + other + "/scans/20260101-000000-abcd", "x/../y", ""]:
        with pytest.raises(FileNotFoundError):
            store.scan_dir(pid, bad_sid)
    for bad_pid in ["..", "../" + other, ".hidden", "a/b", "A-UPPER"]:
        with pytest.raises(FileNotFoundError):
            store.list_scans(bad_pid)
    assert store.delete_project("..") is False
    sid, _ = store.new_scan_dir(pid)
    assert store.scan_dir(pid, sid).is_dir()


def test_mcp_get_file_content_cannot_reach_an_unshared_project():
    from kodand import mcpserver

    shared = store.create_project("Shared")["id"]
    store.set_project_mcp_sharing(shared, True)
    secret = store.create_project("Secret")["id"]
    sid, sd = store.new_scan_dir(secret)
    (sd / "target" / "creds.txt").write_text("top secret")
    with pytest.raises(FileNotFoundError):
        mcpserver.get_file_content(shared, f"../../{secret}/scans/{sid}", "creds.txt")


def test_snapshot_copy_skips_symlinks(tmp_path):
    outside = tmp_path / "outside-secret"
    outside.write_text("ssh key")
    src = tmp_path / "skill"
    (src / "lib").mkdir(parents=True)
    (src / "SKILL.md").write_text("---\nname: x\n---\n")
    (src / "id_rsa").symlink_to(outside)
    (src / "linked-dir").symlink_to(tmp_path)
    (src / "node_modules").mkdir()
    dest = tmp_path / "dest"
    repository.copy_snapshot(src, dest)
    assert (dest / "SKILL.md").exists() and (dest / "lib").is_dir()
    assert not (dest / "id_rsa").exists() and not (dest / "linked-dir").exists()
    assert not (dest / "node_modules").exists()


def test_oversized_archives_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(repository, "MAX_EXTRACT_BYTES", 1000)
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", "0" * 5000)
    with pytest.raises(InvalidRepositoryError, match="too large"):
        repository.extract_archive_into(z, tmp_path / "out-zip")

    t = tmp_path / "bomb.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        data = b"0" * 5000
        info = tarfile.TarInfo("big.txt"); info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(InvalidRepositoryError, match="too large"):
        repository.extract_archive_into(t, tmp_path / "out-tar")


def test_unknown_host_header_is_refused():
    c = TestClient(server.app, base_url="http://evil.example")
    assert c.get("/login").status_code == 421
    assert c.post("/api/auth/login", json={"password": "x"}).status_code == 421


def test_loopback_hosts_allowed_and_wildcard_disables_check(monkeypatch):
    assert TestClient(server.app, base_url="http://127.0.0.1:8787").get("/login").status_code == 200
    assert TestClient(server.app, base_url="http://localhost:8787").get("/login").status_code == 200
    monkeypatch.setenv("KODAND_ALLOWED_HOSTS", "*")
    assert TestClient(server.app, base_url="http://evil.example").get("/login").status_code == 200


def test_cross_origin_state_change_is_refused():
    c = _signed_in_client()
    assert c.post("/api/projects", json={"name": "x"}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/projects", json={"name": "x"}, headers={"Origin": "http://testserver"}).status_code == 200


def test_security_headers_on_every_response():
    r = TestClient(server.app).get("/login")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "connect-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"


def test_repeated_failed_logins_are_locked_out():
    store.set_password("a-strong-password")
    c = TestClient(server.app)
    for _ in range(server.LOGIN_MAX_FAILURES):
        assert c.post("/api/auth/login", json={"password": "wrong"}).status_code == 401
    locked = c.post("/api/auth/login", json={"password": "a-strong-password"})
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0


def test_successful_login_clears_failure_count():
    store.set_password("a-strong-password")
    c = TestClient(server.app)
    for _ in range(server.LOGIN_MAX_FAILURES - 1):
        c.post("/api/auth/login", json={"password": "wrong"})
    assert c.post("/api/auth/login", json={"password": "a-strong-password"}).status_code == 200
    assert c.post("/api/auth/login", json={"password": "wrong"}).status_code == 401


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_workspace_is_owner_only(tmp_path, monkeypatch):
    home = tmp_path / "loose"
    home.mkdir(mode=0o755)
    monkeypatch.setenv("KODAND_HOME", str(home))
    store.workspace_root()
    assert stat.S_IMODE(home.stat().st_mode) == 0o700


def test_custom_template_fields_must_be_plain_tokens():
    base = {"id": "CUSTOM-OK", "info": {"name": "n", "severity": "high", "confidence": "high", "category": "CUSTOM"},
            "detection": {"match": ["zzz"]}, "risk": {"title": "t"}, "recommendation": "r"}
    store.add_custom_template(base)
    for bad in [{"id": 'x"><img src=x onerror=alert(1)>'},
                {"info": {**base["info"], "category": "<script>"}},
                {"info": {**base["info"], "severity": "high onmouseover=x"}}]:
        with pytest.raises(ValueError):
            store.add_custom_template({**base, **bad})


def test_report_escapes_rule_id_and_category(tmp_path):
    from kodand.models.analysis import CorrelatedFinding, RepositoryAnalysis, Summary
    from kodand.models.inventory import RepositoryInventory
    from kodand.reporting import write_html

    payload = '"><img src=x onerror=alert(1)>'
    f = CorrelatedFinding(finding_id="KODAND-1", rule_id=payload, category=payload, category_name="c", title="t",
                          severity="high", confidence="high", description="", technical_root_cause="",
                          attack_scenario="", preconditions="", potential_impact="", remediation="",
                          validation_guidance="", affected_platforms=[], affected_extensions=[],
                          affected_files=[], capabilities=[], occurrence_count=0, occurrences=[],
                          merged_rule_ids=[payload])
    inv = RepositoryInventory.model_validate({"repository_name": "r", "repository_root": str(tmp_path)})
    analysis = RepositoryAnalysis(inventory=inv, findings=[f], coverage=[], summary=Summary(total=1, overall_risk="High", high=1))
    out = tmp_path / "report.html"
    write_html(analysis, out)
    assert "<img src=x onerror" not in out.read_text()
