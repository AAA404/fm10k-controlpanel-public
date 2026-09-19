import json

import pytest
from fastapi.testclient import TestClient

from fm10k_controlpanel.app import create_app
from fm10k_controlpanel.auth import Auth, AccountWriteUncertain
from fm10k_controlpanel.models import AdministratorUpdate, Credentials

OLD = "original-local-password"
NEW = "replacement-local-password"


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(state_dir=tmp_path)) as client:
        result = client.post("/api/v1/auth/setup", json={"username":"admin", "password":OLD})
        client.headers["x-csrf-token"] = result.json()["csrf"]
        yield client


def test_change_account_rotates_current_session_and_revokes_others(client, tmp_path):
    old_cookie = client.cookies.get("fm10k_session")
    old_csrf = client.headers["x-csrf-token"]
    other, _ = client.app.state.auth.login(Credentials(username="admin", password=OLD), "other")
    response = client.post("/api/v1/auth/administrator", json={"username":"operator", "current_password":OLD,
                           "new_password":NEW, "confirm_password":NEW})
    assert response.status_code == 200
    assert response.json()["username"] == "operator"
    assert response.json()["csrf"] != old_csrf
    assert client.cookies.get("fm10k_session") != old_cookie
    assert client.app.state.auth.session(other) is None
    assert client.app.state.auth.session(old_cookie) is None
    assert client.get("/api/v1/config").status_code == 200
    assert client.post("/api/v1/auth/logout").status_code == 403  # old CSRF
    assert client.post("/api/v1/auth/login", json={"username":"admin", "password":OLD}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username":"operator", "password":NEW}).status_code == 200
    persisted = (tmp_path / "accounts.json").read_text() + (tmp_path / "audit.jsonl").read_text()
    assert OLD not in persisted and NEW not in persisted
    assert "administrator_updated" in persisted


def test_username_only_change_keeps_password_and_rejects_wrong_current(client, tmp_path):
    before = (tmp_path / "accounts.json").read_bytes()
    body = {"username":"renamed", "current_password":"incorrect"}
    assert client.post("/api/v1/auth/administrator", json=body).status_code == 400
    assert (tmp_path / "accounts.json").read_bytes() == before
    body["current_password"] = OLD
    response = client.post("/api/v1/auth/administrator", json=body)
    assert response.status_code == 200
    updated = json.loads((tmp_path / "accounts.json").read_text())
    assert updated["digest"] == json.loads(before)["digest"]
    assert client.post("/api/v1/auth/login", json={"username":"renamed", "password":OLD}).status_code == 200


def test_account_validation_csrf_and_throttle(client):
    path = "/api/v1/auth/administrator"
    body = {"username":"admin", "current_password":OLD, "new_password":NEW, "confirm_password":"does-not-match"}
    assert client.post(path, json=body).status_code == 422
    assert client.post(path, json={"username":"admin", "current_password":OLD}).status_code == 400
    csrf = client.headers.pop("x-csrf-token")
    assert client.post(path, json={"username":"renamed", "current_password":OLD}).status_code == 403
    client.headers["x-csrf-token"] = csrf
    for _ in range(5):
        assert client.post(path, json={"username":"renamed", "current_password":"incorrect"}).status_code == 400
    assert client.post(path, json={"username":"renamed", "current_password":OLD}).status_code == 429
    assert client.post("/api/v1/auth/login", json={"username":"admin", "password":OLD}).status_code == 429


def test_uncertain_account_storage_revokes_sessions(tmp_path, monkeypatch):
    auth = Auth(tmp_path)
    token, _ = auth.setup(Credentials(username="admin", password=OLD))
    def fail(*args):
        raise OSError("simulated directory fsync failure")
    monkeypatch.setattr("fm10k_controlpanel.auth.atomic_json", fail)
    with pytest.raises(AccountWriteUncertain):
        auth.update_administrator(token, AdministratorUpdate(username="renamed", current_password=OLD), "test")
    assert auth.session(token) is None


def test_changed_session_cannot_apply_a_second_account_update(tmp_path):
    auth = Auth(tmp_path)
    token, _ = auth.setup(Credentials(username="admin", password=OLD))
    auth.update_administrator(token, AdministratorUpdate(username="renamed", current_password=OLD), "test")
    with pytest.raises(ValueError, match="会话已失效"):
        auth.update_administrator(token, AdministratorUpdate(username="intruder", current_password=OLD), "test")


def test_ntp_clock_steps_do_not_change_session_or_login_throttle_duration(tmp_path):
    wall, elapsed = [1_700_000_000.0], [100.0]
    auth = Auth(tmp_path, clock=lambda: wall[0], monotonic=lambda: elapsed[0])
    credentials = Credentials(username="admin", password=OLD)
    token, value = auth.setup(credentials)
    assert value["expires"] == wall[0] + 12 * 3600 and "deadline" not in value
    wall[0] += 86400
    elapsed[0] += 1
    assert auth.session(token) is not None  # Forward NTP correction is not 24h of session use.
    for _ in range(5):
        with pytest.raises(ValueError, match="用户名或密码错误"):
            auth.login(Credentials(username="admin", password="invalid-password"), "test")
    wall[0] -= 172800
    with pytest.raises(PermissionError): auth.login(credentials, "test")
    elapsed[0] += 61
    replacement, _ = auth.login(credentials, "test")
    assert auth.session(replacement) is not None  # Backward correction cannot extend a one-minute lockout.
    elapsed[0] += 12 * 3600 + 1
    assert auth.session(replacement) is None  # Nor can it extend a session beyond 12h.
