import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from fm10k_controlpanel.app import create_app
from fm10k_controlpanel.profiles import PROFILES


@pytest.fixture
def client(tmp_path):
    app = create_app(state_dir=tmp_path)
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/setup", json={"username": "admin", "password": "correct-horse-123"})
        assert response.status_code == 200
        client.headers["x-csrf-token"] = response.json()["csrf"]
        yield client


def wait_job(client, job_id):
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["state"] not in {"queued", "running"}: return job
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_authentication_csrf_and_l3_boundary(client):
    assert client.get("/api/v1/capabilities").json()["l3"]["enabled"] is False
    assert client.post("/api/v1/l3/routes", json={}).status_code == 501
    token = client.headers.pop("x-csrf-token")
    assert client.post("/api/v1/fans/manual", json={"pwm_percent": 50}).status_code == 403
    client.headers["x-csrf-token"] = token
    client.post("/api/v1/auth/logout")
    assert client.get("/api/v1/config").status_code == 401


def test_preview_commit_confirm_and_no_global_restart(client):
    state = client.get("/api/v1/config").json()
    state["configuration"]["groups"][0]["mode"] = "split"
    response = client.post("/api/v1/config/preview", json={"expected_revision": state["revision"], "configuration": state["configuration"]})
    assert response.status_code == 200, response.text
    draft = response.json()
    assert draft["affected_epls"] == [0] and draft["requires_restart"] is False
    assert client.post("/api/v1/config/commit", json={"draft_id": draft["id"]}).status_code == 409
    response = client.post("/api/v1/config/commit", json={"draft_id": draft["id"], "accept_bandwidth_warning": True})
    assert response.status_code == 202
    job = wait_job(client, response.json()["id"])
    assert job["state"] == "awaiting_confirmation", job
    result = client.post(f"/api/v1/jobs/{job['id']}/confirm")
    assert result.status_code == 200, result.text
    assert client.get("/api/v1/config").json()["pending"] is None


def test_stale_revision_and_validation(client):
    state = client.get("/api/v1/config").json()
    response = client.post("/api/v1/config/preview", json={"expected_revision": 99, "configuration": state["configuration"]})
    assert response.status_code == 409
    state["configuration"]["ports"]["2"]["enabled"] = True
    response = client.post("/api/v1/config/preview", json={"expected_revision": 1, "configuration": state["configuration"]})
    assert response.status_code == 422


def test_backup_has_no_credentials_and_checks_integrity(client):
    backup = client.get("/api/v1/backups/export").json()
    assert "password" not in str(backup) and "salt" not in str(backup)
    response = client.post("/api/v1/backups/preview", json=backup)
    assert response.status_code == 200, response.text
    backup["configuration"]["fan"]["idle_speed_percent"] = 90
    assert client.post("/api/v1/backups/preview", json=backup).status_code == 400


def test_sensor_requests_share_cache(client):
    backend = client.app.state.service.backend
    before = backend.sample_count
    for _ in range(10):
        result = client.get("/api/v1/sensors").json()
        assert result["quality"] == "simulated"
    assert backend.sample_count == before


def test_sensitive_responses_not_cached(client):
    response = client.get("/api/v1/config")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"


def test_same_site_origin_and_stream_limit(client):
    assert client.post("/api/v1/fans/manual", json={"pwm_percent": 50},
                       headers={"Origin": "https://unrelated.example"}).status_code == 403
    response = client.post("/api/v1/config/preview", content=b"x" * 2_000_001,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_reporting_and_cross_board_backup_rejection(client, profile):
    service = client.app.state.service
    # Select the installed configuration through the authority thread before
    # exercising the API; the online API cannot change this profile.
    service.scheduler.call(lambda: setattr(service.backend.configuration, "profile", profile))
    assert client.get("/api/v1/capabilities").json()["profile"] == profile
    assert client.get("/api/v1/system").json()["profile"] == profile
    state = client.get("/api/v1/config").json()
    other = next(name for name in PROFILES if name != profile)
    state["configuration"]["profile"] = other
    result = client.post("/api/v1/config/preview", json={
        "expected_revision": state["revision"], "configuration": state["configuration"]})
    assert result.status_code == 409 and result.json()["code"] == "profile_mismatch"
    backup = client.get("/api/v1/backups/export").json()
    assert client.post("/api/v1/backups/preview", json=backup).status_code == 200
    backup["configuration"]["profile"] = other
    content = {key: value for key, value in backup.items() if key != "sha256"}
    backup["sha256"] = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result = client.post("/api/v1/backups/preview", json=backup)
    assert result.status_code == 409 and result.json()["code"] == "profile_mismatch"
    assert service.backend.configuration.profile == profile and service.backend.revision == state["revision"]


def test_roce_preflight_is_read_only_and_reuses_commit_rules(client):
    before = client.get("/api/v1/config").json()
    import copy
    draft = copy.deepcopy(before["configuration"])
    draft["qos"]["roce"].update(enabled=True, ports=[])
    response = client.post("/api/v1/roce/preflight", json={"configuration": draft, "expected_revision": before["revision"]})
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is False
    assert len(response.json()["ports"]) == 24
    assert any("两个" in issue["message"] for issue in response.json()["issues"])
    assert client.get("/api/v1/config").json() == before
    assert client.post("/api/v1/config/preview", json={"configuration": draft, "expected_revision": before["revision"]}).status_code == 422
    assert client.post("/api/v1/roce/preflight", json={"configuration": draft, "expected_revision": -1}).status_code == 409
    caps = client.get("/api/v1/capabilities").json()["roce"]
    assert caps["modes"][0]["status"] == "configurable"
    assert caps["modes"][1]["status"] == "unsupported"
    assert {f["id"] for f in caps["features"] if f["status"] == "configurable"} >= {"dscp", "dcbx", "pause-observation"}
    assert 100 in caps["speeds_gbps"]
    assert caps["qualifications"] == []
    token = client.headers.pop("x-csrf-token")
    assert client.post("/api/v1/roce/preflight", json={"configuration": draft, "expected_revision": before["revision"]}).status_code == 403
    client.headers["x-csrf-token"] = token


def test_operational_reports_device_time_without_retimestamping_samples(client, monkeypatch):
    service = client.app.state.service
    monkeypatch.setattr(service, "clock", lambda: 1789665100.0)
    monkeypatch.setattr(service.backend, "operational", lambda feature: {
        "quality": "simulated", "sampled_at": 1789665040.0, "traffic_validation": "not-run"})
    result = client.get("/api/v1/operational/roce").json()
    assert result["server_time"] == 1789665100.0
    assert result["server_time"] - result["data"]["sampled_at"] == 60
    assert result["data"]["quality"] == "simulated"
    assert result["data"]["traffic_validation"] == "not-run"


def test_time_sync_auth_validation_simulation_and_pending_guard(client):
    status = client.get("/api/v1/system/time").json()
    assert status["state"] == "simulated" and not status["synchronized"]
    token = client.headers.pop("x-csrf-token")
    assert client.post("/api/v1/system/time/sync", json={}).status_code == 403
    client.headers["x-csrf-token"] = token
    assert client.post("/api/v1/system/time/sync", json={"servers":["host\n[Time]"]}).status_code == 422
    before = client.get("/api/v1/config").json()
    result = client.post("/api/v1/system/time/sync", json={"servers":["192.168.100.1"]})
    assert result.status_code == 200 and result.json()["state"] == "simulated"
    assert client.get("/api/v1/config").json() == before
    service = client.app.state.service
    service.scheduler.call(lambda: service.jobs.update({"fixture": {"state":"running"}}))
    assert client.post("/api/v1/system/time/sync", json={}).status_code == 409
    assert client.get("/api/v1/system/time").json()["servers"] == ["192.168.100.1"]
    service.scheduler.call(lambda: service.jobs.clear())
    client.post("/api/v1/auth/logout")
    assert client.get("/api/v1/system/time").status_code == 401
    assert client.post("/api/v1/system/time/sync", json={}).status_code == 401


def test_roce_draft_preview_confirm_and_stop_rollback(client):
    current = client.get("/api/v1/config").json()
    raw = current["configuration"]
    for group in raw["groups"]: group["mode"] = "40g"
    raw["vlans"].append({"id": 10, "name": "RDMA"})
    for n in ("13", "17"):
        raw["ports"][n].update(enabled=True, vlan_mode="trunk", tagged_vlans=[10])
    raw["qos"]["roce"].update(enabled=True, ports=[13, 17])
    draft = client.post("/api/v1/config/preview", json={"configuration": raw, "expected_revision": current["revision"]})
    assert draft.status_code == 200, draft.text
    assert draft.json()["roce_preflight"]["valid"]
    submitted = client.post("/api/v1/config/commit", json={"draft_id": draft.json()["id"], "accept_bandwidth_warning": True})
    assert submitted.status_code == 202, submitted.text
    job = wait_job(client, submitted.json()["id"])
    assert job["state"] == "awaiting_confirmation"
    assert client.post(f'/api/v1/jobs/{job["id"]}/confirm').status_code == 200
    configured = client.get("/api/v1/config").json()
    assert configured["configuration"]["qos"]["roce"]["enabled"]
    configured["configuration"]["qos"]["roce"]["enabled"] = False
    stopped = client.post("/api/v1/config/preview", json={"configuration": configured["configuration"], "expected_revision": configured["revision"]})
    assert stopped.status_code == 200, stopped.text
    submitted = client.post("/api/v1/config/commit", json={"draft_id": stopped.json()["id"]})
    job = wait_job(client, submitted.json()["id"])
    assert job["state"] == "awaiting_confirmation"
    assert client.post(f'/api/v1/jobs/{job["id"]}/rollback').status_code == 200
    restored = client.get("/api/v1/config").json()["configuration"]
    assert restored["qos"]["roce"]["enabled"]
    assert restored["ports"]["13"]["tagged_vlans"] == [10]
