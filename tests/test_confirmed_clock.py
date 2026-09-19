from pathlib import Path
import copy
import subprocess
import sys

import pytest

from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab import NetlabBackend
from fm10k_controlpanel.netlab_codec import compile_configuration
from fm10k_controlpanel.service import PanelService


def test_native_pending_countdown_decode():
    backend = NetlabBackend()
    xml = compile_configuration(SwitchConfiguration())
    def response(remaining):
        attribute = f' remaining-seconds="{remaining}"' if remaining is not None else ''
        return (f'<fm10k-panel-state api="1" revision="2" pending="true" job-id="clock-test" deadline="1700000060"{attribute}>'.encode()
                + xml + b'</fm10k-panel-state>')
    backend._rpc = lambda *args: response(45)
    assert backend.snapshot()["pending"]["remaining_seconds"] == 45
    for invalid in ("unknown", -1):
        backend._rpc = lambda *args: response(invalid)
        with pytest.raises(HardwareError, match="倒计时"):
            backend.snapshot()
    backend._rpc = lambda *args: response(None)
    assert "remaining_seconds" not in backend.snapshot()["pending"]


def test_cached_job_countdown_uses_elapsed_time_and_refreshes(tmp_path):
    wall, mono = [1700000000], [100]
    state = {"revision": 2, "configuration": SwitchConfiguration().model_dump(mode="json"),
             "pending": {"job_id": "clock-test", "phase": "awaiting_confirmation",
                         "deadline": wall[0] + 20, "remaining_seconds": 20}}

    class Backend:
        mode = "netlab"
        def snapshot(self): return copy.deepcopy(state)
        def ports(self): return []
        def sensors(self): return {"temperatures": [], "fan": {}}
        def optics(self): return []

    service = PanelService(Backend(), tmp_path, clock=lambda: wall[0], monotonic=lambda: mono[0])
    try:
        assert service.config()["pending"]["remaining_seconds"] == 20
        assert service.job("clock-test")["remaining_seconds"] == 20
        wall[0] += 86400; mono[0] += 5
        assert service.job("clock-test")["remaining_seconds"] == 15
        wall[0] -= 2 * 86400; mono[0] += 5
        assert service.job("clock-test")["remaining_seconds"] == 10
        state["pending"].update(remaining_seconds=9, deadline=wall[0] + 9)
        service.scheduler.call(service._sample)
        assert service.job("clock-test")["remaining_seconds"] == 9
        mono[0] += 10
        job = service.job("clock-test")
        assert job["remaining_seconds"] == 0 and job["state"] == "awaiting_confirmation"
        assert "confirmation_deadlines" not in job  # Native state alone authorizes the outcome.
    finally:
        service.scheduler.close()


@pytest.mark.skipif(sys.platform != "linux", reason="native deadlines use the Linux boot ID")
def test_confirmed_clock_survives_corrections_and_daemon_restart(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    binary = tmp_path / "confirmed-clock-test"
    subprocess.run([
        "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
        "-Wno-error=format-truncation", "-I", str(netlab / "include"),
        str(root / "tests/native_confirmed_clock_test.c"),
        str(netlab / "lib/libconfig/commit_journal.c"),
        str(netlab / "lib/liblog/log.c"), "-Wl,--wrap=time,--wrap=clock_gettime",
        "-o", str(binary),
    ], check=True)
    state = tmp_path / "journal"
    for stage in ("create", "resume"):
        subprocess.run([str(binary), str(state), stage], check=True, timeout=20)
