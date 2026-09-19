import pytest

from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.netlab import NetlabBackend


def test_native_rpc_uses_one_authenticated_connection_per_request(monkeypatch):
    backend = NetlabBackend()
    sessions = []

    class OneRequest:
        calls = 0
        closed = False

        def send_request(self, service, method, payload, timeout_ms):
            assert not self.closed and self.calls == 0
            self.calls += 1
            return (-1, 0, b"") if payload == b"lost-reply" else (0, 2, b"ok")

        def close(self):
            self.closed = True

    def connect():
        if backend.transport is None:
            backend.transport = OneRequest()
            sessions.append(backend.transport)

    monkeypatch.setattr(backend, "_connect", connect)
    assert backend._rpc(2, 19) == b"ok"
    assert backend._rpc(7, 132) == b"ok"
    with pytest.raises(HardwareError):
        backend._rpc(2, 21, b"lost-reply")
    assert len(sessions) == 3
    assert all(session.closed and session.calls == 1 for session in sessions)
    assert backend.transport is None
