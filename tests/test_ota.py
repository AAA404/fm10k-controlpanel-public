from fastapi.testclient import TestClient

from fm10k_controlpanel.app import create_app


def test_ota_reserved_requires_auth_and_cannot_modify_device(tmp_path):
    with TestClient(create_app(state_dir=tmp_path)) as client:
        assert client.get("/api/v1/updates").status_code == 401
        session = client.post("/api/v1/auth/setup", json={"username":"admin","password":"local-password-only"}).json()
        state = client.get("/api/v1/updates").json()
        assert state["enabled"] is False and state["state"] == "reserved"
        assert state["repository"] == "AAA404/fm10k-controlpanel-public"
        assert "token" not in state and "job" not in state
        before = client.get("/api/v1/config").json()
        for route in ("check", "install"):
            path = "/api/v1/updates/"+route
            assert client.post(path,json={}).status_code == 403
            response = client.post(path,json={"url":"https://unrelated.example/package.deb"},
                                   headers={"x-csrf-token":session["csrf"]})
            assert response.status_code == 501 and response.json()["code"] == "update_not_enabled"
        assert client.get("/api/v1/config").json() == before
        assert client.app.state.service.jobs == {}
