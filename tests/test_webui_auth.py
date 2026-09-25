import os
import shutil

AUTH_HOME = "/tmp/kodand_webui_auth"
os.environ["KODAND_HOME"] = AUTH_HOME
shutil.rmtree(AUTH_HOME, ignore_errors=True)

import pytest
from fastapi.testclient import TestClient

from kodand.webui import store
from kodand.webui.server import app

NEW_PASSWORD = "a-strong-password"


@pytest.fixture(autouse=True)
def _fresh_workspace():
    os.environ["KODAND_HOME"] = AUTH_HOME
    shutil.rmtree(AUTH_HOME, ignore_errors=True)
    yield


@pytest.fixture
def client():
    # follow_redirects=False so the /login bounce is observable rather than silently followed
    return TestClient(app, follow_redirects=False)


def _sign_in_and_set_password(client, password=NEW_PASSWORD):
    client.post("/api/auth/login", json={"password": store.DEFAULT_PASSWORD})
    return client.post("/api/auth/change-password",
                       json={"current_password": store.DEFAULT_PASSWORD, "new_password": password})


def test_fresh_workspace_provisions_the_default_password():
    assert store.default_password_active() is True
    assert store.must_change_password() is True
    assert store.verify_password(store.DEFAULT_PASSWORD) is True


def test_protected_routes_require_a_session(client):
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/meta").status_code == 401
    html = client.get("/", headers={"accept": "text/html"})
    assert html.status_code == 303 and html.headers["location"] == "/login"


def test_login_page_and_static_assets_stay_reachable_signed_out(client):
    assert client.get("/login").status_code == 200
    assert client.get("/static/login.html").status_code == 200
    assert client.get("/api/auth/status").json()["authenticated"] is False


def test_wrong_password_is_rejected_and_issues_no_session(client):
    r = client.post("/api/auth/login", json={"password": "not-the-password"})
    assert r.status_code == 401
    assert client.get("/api/projects").status_code == 401


def test_must_change_password_blocks_the_app_until_changed(client):
    r = client.post("/api/auth/login", json={"password": store.DEFAULT_PASSWORD})
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    # authenticated, but still gated: the forced change is enforced server-side, not just in the UI
    assert client.get("/api/projects").status_code == 403
    assert client.get("/api/auth/status").json() == {
        "authenticated": True, "must_change_password": True, "default_password_active": True}

    assert _sign_in_and_set_password(client).status_code == 200
    assert client.get("/api/projects").status_code == 200
    assert client.get("/api/auth/status").json() == {
        "authenticated": True, "must_change_password": False, "default_password_active": False}


def test_change_password_rejects_wrong_current_and_weak_new(client):
    client.post("/api/auth/login", json={"password": store.DEFAULT_PASSWORD})
    assert client.post("/api/auth/change-password",
                       json={"current_password": "wrong", "new_password": NEW_PASSWORD}).status_code == 401
    assert client.post("/api/auth/change-password",
                       json={"current_password": store.DEFAULT_PASSWORD, "new_password": "short"}).status_code == 400
    assert store.must_change_password() is True  # still gated after both failures


def test_new_password_works_on_a_later_sign_in(client):
    _sign_in_and_set_password(client)
    fresh = TestClient(app, follow_redirects=False)
    assert fresh.post("/api/auth/login", json={"password": store.DEFAULT_PASSWORD}).status_code == 401
    r = fresh.post("/api/auth/login", json={"password": NEW_PASSWORD})
    assert r.status_code == 200 and r.json()["must_change_password"] is False
    assert fresh.get("/api/projects").status_code == 200


def test_changing_the_password_invalidates_other_sessions(client):
    _sign_in_and_set_password(client)
    other = TestClient(app, follow_redirects=False)
    other.post("/api/auth/login", json={"password": NEW_PASSWORD})
    assert other.get("/api/projects").status_code == 200

    client.post("/api/auth/change-password",
                json={"current_password": NEW_PASSWORD, "new_password": "yet-another-password"})
    assert other.get("/api/projects").status_code == 401  # old session died with the old password


def test_logout_invalidates_the_session(client):
    _sign_in_and_set_password(client)
    assert client.get("/api/projects").status_code == 200
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/projects").status_code == 401


def _cli_reset(*args, input=None):
    from typer.testing import CliRunner

    from kodand.cli import app as cli_app
    return CliRunner().invoke(cli_app, ["password", "reset", *args], input=input)


def test_cli_reset_sets_a_new_password_and_signs_out_sessions(client):
    _sign_in_and_set_password(client)
    assert client.get("/api/projects").status_code == 200

    r = _cli_reset(input="recovered-password\nrecovered-password\n")
    assert r.exit_code == 0, r.output
    assert store.verify_password("recovered-password")
    assert not store.must_change_password()
    assert client.get("/api/projects").status_code == 401


def test_cli_reset_rejects_weak_or_default_password():
    for bad in ("short", store.DEFAULT_PASSWORD):
        r = _cli_reset(input=f"{bad}\n{bad}\n")
        assert r.exit_code == 2, r.output


def test_cli_reset_to_default_forces_a_change(client):
    _sign_in_and_set_password(client)
    r = _cli_reset("--to-default")
    assert r.exit_code == 0, r.output
    assert store.default_password_active()
    assert store.must_change_password()
    assert client.get("/api/projects").status_code == 401
