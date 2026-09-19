import threading
import time

import pytest
from fastapi.testclient import TestClient

from fm10k_controlpanel.app import create_app
from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.netlab import NetlabBackend
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.simulator import MockConfigd
from test_netlab_codec import NativeFixture


class RecoveryTransport(NativeFixture):
    def __init__(self, *, startup="control", supports=True, repairs=True):
        super().__init__(bound=False)
        self.startup, self.supports, self.repairs = startup, supports, repairs

    def send_request(self, service, method, payload=b"", **options):
        if method == 24:
            self.calls.append((service, method, payload))
            assert service == 2 and payload == b"1"
            self.bound = self.repairs
            return 0, 0, b""
        error, _, data = super().send_request(service, method, payload, **options)
        if method == 19:
            attributes = f' startup-mode="{self.startup}"'
            if self.supports:
                attributes += ' recovery="active-replay-v1"'
            data = data.replace(b'api="1"', b'api="1"' + attributes.encode())
        return error, len(data), data


def test_recovery_replays_the_current_revision_and_requires_readback():
    transport = RecoveryTransport()
    assert NetlabBackend(transport).recover_control()["hardware_write_ready"]
    assert [method for _, method, _ in transport.calls] == [19, 24, 19]
    with pytest.raises(HardwareError, match="尚未同步"):
        NetlabBackend(RecoveryTransport(repairs=False)).recover_control()


@pytest.mark.parametrize("options", [{"startup": "observe"}, {"startup": "basic100g"}, {"supports": False}])
def test_recovery_never_upgrades_observation_or_old_native_services(options):
    transport = RecoveryTransport(**options)
    with pytest.raises(HardwareError, match="不支持恢复控制"):
        NetlabBackend(transport).recover_control()
    assert all(method == 19 for _, method, _ in transport.calls)


def test_apply_preserves_the_original_failure_when_snapshot_is_unreachable():
    backend = NetlabBackend()
    def rpc(*args, **kwargs):
        raise HardwareError("service=2 method=21 code=2007")
    def snapshot():
        raise HardwareError("service=2 method=19 code=3002")
    backend._rpc, backend.snapshot = rpc, snapshot
    with pytest.raises(HardwareError, match="method=21.*后续状态核对失败.*method=19"):
        backend.apply(SwitchConfiguration(), 1, "a" * 32, 60)


def test_matching_pending_commit_is_not_success_without_hardware_sync():
    transport = NativeFixture(bound=False)
    with pytest.raises(HardwareError, match="提交不一致"):
        NetlabBackend(transport).apply(SwitchConfiguration(), 1, "a" * 32, 60)


def test_recovery_api_authentication_serialization_and_failed_retry(tmp_path):
    gate = threading.Event()
    class Recoverable(MockConfigd):
        mode = "netlab"
        attempts = 0
        contract = {"startup-mode": "control", "board-hal": "unbound", "synchronized": "false",
                    "recovery": "active-replay-v1"}
        def recover_control(self):
            self.attempts += 1
            assert gate.wait(5)
            if self.attempts == 1:
                raise HardwareError("fixture: reload failed")
            self.contract = {**self.contract, "board-hal": "bound", "synchronized": "true"}
            return self.snapshot()

    backend = Recoverable(tmp_path)
    app = create_app(state_dir=tmp_path, backend=backend, secure_cookie=False)
    with TestClient(app) as client:
        assert client.post("/api/v1/control/recover").status_code == 401
        auth = client.post("/api/v1/auth/setup", json={"username": "admin", "password": "correct-horse-123"}).json()
        assert client.post("/api/v1/control/recover").status_code == 403
        client.headers["x-csrf-token"] = auth["csrf"]
        first = client.post("/api/v1/control/recover")
        assert first.status_code == 202
        assert client.post("/api/v1/control/recover").status_code == 409
        gate.set()
        def wait(identity):
            for _ in range(100):
                result = client.get("/api/v1/jobs/" + identity).json()
                if result["state"] in {"done", "failed"}: return result
                time.sleep(.01)
            pytest.fail("recovery did not finish")
        assert wait(first.json()["id"])["state"] == "failed"
        app.state.service.scheduler.call(lambda: None)
        assert client.get("/api/v1/telemetry").json()["native_integration"]["synchronized"] == "false"
        second = client.post("/api/v1/control/recover")
        assert wait(second.json()["id"])["state"] == "done"
        app.state.service.scheduler.call(lambda: None)
        assert client.get("/api/v1/telemetry").json()["native_integration"]["synchronized"] == "true"
