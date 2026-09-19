import threading

import pytest

from fm10k_controlpanel.service import OwnerQueue, PanelError, PanelService
from fm10k_controlpanel.simulator import MockConfigd


def test_shutdown_closes_transport_on_its_owner_after_inflight_work():
    queue = OwnerQueue()
    entered, release, finalized = threading.Event(), threading.Event(), threading.Event()
    threads = []
    def work():
        entered.set()
        assert release.wait(3)
        threads.append(threading.get_ident())
    def finish():
        threads.append(threading.get_ident())
        finalized.set()
    future = queue.submit(work)
    assert entered.wait(1)
    queue.close(finish, timeout=0.01)
    assert not finalized.is_set()
    with pytest.raises(PanelError, match="退出"):
        queue.submit(lambda: None)
    release.set()
    future.result(3)
    assert finalized.wait(3)
    assert threads == [queue.thread.ident, queue.thread.ident]


def test_audit_disk_failure_does_not_change_authoritative_commit_result(tmp_path):
    backend = MockConfigd(tmp_path)
    panel = PanelService(backend, tmp_path)
    try:
        (tmp_path / "audit.jsonl").mkdir()
        panel.audit("sample")
        assert panel.audit_error
        assert panel.telemetry()["audit_error"]
    finally:
        panel.close()
