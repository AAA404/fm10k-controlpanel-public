import subprocess
from pathlib import Path

import pytest

from fm10k_controlpanel import native_guard as guard


def cpu_device(tmp_path, monkeypatch, *, mtu=1500, flags="0x1002"):
    device = tmp_path / "pci" / "0000:01:00.0"
    interface = device / "net" / "enp1s0"
    interface.mkdir(parents=True)
    (interface / "mtu").write_text(str(mtu))
    (interface / "flags").write_text(flags)
    monkeypatch.setattr(guard, "CPU_DEVICE", device)
    return interface


def test_cpu_dma_is_enabled_without_reconfiguring_management_network(tmp_path, monkeypatch):
    interface = cpu_device(tmp_path, monkeypatch)
    calls = []

    def ip(command, **kwargs):
        calls.append(command)
        assert kwargs == {"check": True, "timeout": 10}
        (interface / "mtu").write_text("1518")
        (interface / "flags").write_text("0x1003")  # UP, even without carrier.

    monkeypatch.setattr(guard.subprocess, "run", ip)
    assert guard.prepare_cpu_network() == {"interface": "enp1s0", "mtu": 1518, "admin_up": True}
    assert calls == [["/usr/sbin/ip", "link", "set", "dev", "enp1s0", "mtu", "1518", "up"]]
    guard.prepare_cpu_network()
    assert len(calls) == 1, "already prepared interfaces need no further writes"


def test_existing_cpu_mtu_is_preserved(tmp_path, monkeypatch):
    cpu_device(tmp_path, monkeypatch, mtu=9000, flags="0x1003")
    monkeypatch.setattr(guard.subprocess, "run", lambda *args, **kwargs: pytest.fail("unexpected link change"))
    assert guard.prepare_cpu_network()["mtu"] == 9000


def test_ambiguous_cpu_interface_is_rejected_before_writes(tmp_path, monkeypatch):
    interface = cpu_device(tmp_path, monkeypatch)
    (interface.parent / "another").mkdir()
    monkeypatch.setattr(guard.subprocess, "run", lambda *args, **kwargs: pytest.fail("ambiguous link changed"))
    with pytest.raises(ValueError, match="ambiguous"):
        guard.prepare_cpu_network()


def test_cpu_ready_state_must_be_read_back(tmp_path, monkeypatch):
    cpu_device(tmp_path, monkeypatch)
    monkeypatch.setattr(guard.subprocess, "run", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="administratively ready"):
        guard.prepare_cpu_network()


def test_confirmed_record_migration_preserves_current_authority(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    binary = tmp_path / "confirmed-migration-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-I", str(netlab / "include"),
                    str(root / "tests/native_confirmed_migration_test.c"),
                    str(netlab / "lib/libconfig/commit_journal.c"),
                    str(netlab / "lib/liblog/log.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(tmp_path)], check=True, timeout=20)
