import pytest
from fastapi.testclient import TestClient

from fm10k_controlpanel.app import create_app


def test_simulator_requires_auth_and_cannot_install(tmp_path):
    with TestClient(create_app(state_dir=tmp_path)) as client:
        assert client.get("/api/v1/updates").status_code == 401
        session = client.post("/api/v1/auth/setup", json={"username":"admin","password":"local-password-only"}).json()
        state = client.get("/api/v1/updates").json()
        assert state["enabled"] is False and state["state"] == "unavailable"
        assert state["repository"] == "AAA404/fm10k-controlpanel-public"
        assert "token" not in state and state["job"] is None
        before = client.get("/api/v1/config").json()
        for route in ("check", "install"):
            path = "/api/v1/updates/"+route
            assert client.post(path,json={}).status_code == 403
            response = client.post(path,json={"url":"https://unrelated.example/package.deb"},
                                   headers={"x-csrf-token":session["csrf"]})
            assert response.status_code == 422
        assert client.get("/api/v1/config").json() == before
        assert client.app.state.service.jobs == {}


class FakeUpdates:
    def __init__(self):
        self.calls = []
        self.locked = False

    def maintenance(self):
        return self.locked

    def request(self, action, body=None):
        self.calls.append((action, body))
        return {"state": "queued" if action == "install" else "available", "enabled": True}


def test_update_api_validates_requests_and_maintenance(tmp_path):
    updates = FakeUpdates()
    with TestClient(create_app(state_dir=tmp_path, update_client=updates)) as client:
        session = client.post("/api/v1/auth/setup", json={"username":"admin","password":"local-password-only"}).json()
        headers = {"x-csrf-token":session["csrf"]}
        body = {"version":"0.2.0", "manifest_sha256":"a"*64, "confirm_restart":True}
        assert client.post("/api/v1/updates/install", json=body).status_code == 403
        assert client.post("/api/v1/updates/check", json={"url":"https://example.invalid"}, headers=headers).status_code == 422
        for invalid in ({**body,"url":"https://example.invalid"}, {**body,"confirm_restart":False}, {"version":"0.2.0"}):
            assert client.post("/api/v1/updates/install", json=invalid, headers=headers).status_code == 422
        assert updates.calls == []
        assert client.post("/api/v1/updates/check", json={}, headers=headers).status_code == 200
        assert client.post("/api/v1/updates/install", json=body, headers=headers).status_code == 202
        assert updates.calls[-1] == ("install", body)
        updates.locked = True
        assert client.post("/api/v1/config/preview", json={}, headers=headers).status_code == 423
        assert client.get("/api/v1/updates").status_code == 200
        assert client.post("/api/v1/auth/logout", json={}, headers=headers).status_code == 200


def test_update_api_refuses_pending_configuration(tmp_path):
    updates = FakeUpdates()
    app = create_app(state_dir=tmp_path, update_client=updates)
    with TestClient(app) as client:
        session = client.post("/api/v1/auth/setup", json={"username":"admin","password":"local-password-only"}).json()
        app.state.service.busy_job = "configuration-in-progress"
        response = client.post("/api/v1/updates/install", json={"version":"0.2.0","manifest_sha256":"a"*64,"confirm_restart":True},
                               headers={"x-csrf-token":session["csrf"]})
        assert response.status_code == 409
        assert updates.calls == []
