#!/usr/bin/env python3
"""Check installed Debian runtime with distro dependencies and no TCP listener."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, "/usr/lib/fm10k-controlpanel/python")
from fastapi.testclient import TestClient
from fm10k_controlpanel.app import create_app

with tempfile.TemporaryDirectory(prefix="fm10k-installed-") as directory:
    with TestClient(create_app(state_dir=Path(directory))) as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200 and health.json()["mode"] == "mock"
        setup = client.post("/api/v1/auth/setup", json={"username": "testadmin", "password": "container-validation-only!"})
        assert setup.status_code == 200, setup.text
        client.headers["x-csrf-token"] = setup.json()["csrf"]
        state = client.get("/api/v1/config").json()
        state["configuration"]["ports"]["1"]["name"] = "installed-test"
        preview = client.post("/api/v1/config/preview", json={"configuration": state["configuration"], "expected_revision": state["revision"]})
        assert preview.status_code == 200, preview.text
        assert client.post("/api/v1/l3/routes", json={}).status_code == 501
print("Installed Debian Web runtime: setup, configuration validation and L3 rejection passed.")
