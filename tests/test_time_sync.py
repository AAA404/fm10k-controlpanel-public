import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fm10k_controlpanel.time_sync import TimeSyncClient, TimeSyncError, TimeSyncRequest, receive_json
from fm10k_controlpanel.time_helper import TimeManager, handle


@pytest.mark.parametrize("servers", [[], ["a"]*5, ["https://time.example.com"], ["time.example.com:123"],
    ["pool.ntp.org\nExecStart=bad"], ["-bad.example"], ["a;reboot"], ["$(id)"], ["a b"],
    ["0.0.0.0"], ["239.1.1.1"], ["::"], ["ff02::1"], ["1.2.3.999"], ["a"*64+".com"]])
def test_server_validation_rejects_non_ntp_addresses(servers):
    with pytest.raises(ValidationError):
        TimeSyncRequest(servers=servers)


def test_servers_support_lan_ipv6_and_deduplication():
    assert TimeSyncRequest(servers=[" NTP.EXAMPLE.COM ", "192.168.100.1", "2001:db8::1", "ntp.example.com"]).servers == [
        "ntp.example.com", "192.168.100.1", "2001:db8::1"]


class System:
    def __init__(self, path):
        self.path = path
        self.commands = []
        self.enabled = True
        self.synchronized = False
        self.message = ""
        self.fail_restart = False
        self.other_active = False
        self.mismatch = False

    def run(self, *args):
        self.commands.append(args)
        if args[:2] == ("/usr/bin/timedatectl", "show"):
            return f'Timezone=Asia/Shanghai\nNTP={"yes" if self.enabled else "no"}\nNTPSynchronized={"yes" if self.synchronized else "no"}\n'
        if args[:2] == ("/usr/bin/timedatectl", "show-timesync"):
            servers = ""
            if self.path.exists():
                for line in self.path.read_text().splitlines():
                    if line.startswith("NTP="): servers = line[4:]
            return f'SystemNTPServers={"override.example" if self.mismatch else servers}\nServerName=time.example.com\nServerAddress=192.0.2.1\nNTPMessage={self.message}\n'
        if args[:3] == ("/usr/bin/systemctl", "show", "systemd-timesyncd.service"):
            return 'LoadState=loaded\nActiveState=active\nStatusText=Idle.\n'
        if args[:2] == ("/usr/bin/systemctl", "show"):
            return f'ActiveState={"active" if self.other_active else "inactive"}\n'
        if args == ("/usr/bin/timedatectl", "set-ntp", "true"):
            self.enabled = True
            return ""
        if args == ("/usr/bin/timedatectl", "set-ntp", "false"):
            self.enabled = False
            return ""
        if args == ("/usr/bin/systemctl", "restart", "systemd-timesyncd.service"):
            if self.fail_restart:
                self.fail_restart = False
                raise TimeSyncError("fixture restart failed")
            return ""
        raise AssertionError(args)


def manager(tmp_path):
    path = tmp_path / "99-panel.conf"
    system = System(path)
    return TimeManager(path, tmp_path / "synchronized", system.run), system


def test_restart_is_not_reported_as_synchronized(tmp_path):
    m, s = manager(tmp_path)
    s.synchronized = True  # Kernel's old flag must not certify the new attempt.
    m.marker.touch()
    result = m.sync(["ntp.example.com", "192.168.100.1"])
    assert result["state"] == "waiting" and not result["synchronized"]
    assert result["servers"] == ["ntp.example.com", "192.168.100.1"]
    assert "FallbackNTP=\n" in s.path.read_text()
    s.message = "{ Ignored=no, PacketCount=1, Jitter=2ms }"
    assert m.status()["synchronized"]
    s.message = "{ Ignored=yes, PacketCount=1, Jitter=2ms }"
    assert not m.status()["synchronized"]


@pytest.mark.parametrize("old", [None, b"[Time]\nNTP=original.example\n"])
@pytest.mark.parametrize("fault", ["restart", "readback"])
def test_failed_setting_restores_original_configuration(tmp_path, old, fault):
    m, s = manager(tmp_path)
    if old is not None: s.path.write_bytes(old)
    s.fail_restart = fault == "restart"
    s.mismatch = fault == "readback"
    with pytest.raises(TimeSyncError, match="已恢复原设置"):
        m.sync(["new.example"])
    assert (s.path.read_bytes() if s.path.exists() else None) == old


def test_failure_restores_disabled_ntp_and_other_provider_is_not_replaced(tmp_path):
    m, s = manager(tmp_path)
    s.enabled = False; s.fail_restart = True
    with pytest.raises(TimeSyncError): m.sync(["time.example"])
    assert not s.enabled and not s.path.exists()
    s.other_active = True
    with pytest.raises(TimeSyncError, match="其他 NTP 服务"):
        m.sync(["time.example"])
    assert not s.path.exists()


def test_helper_has_no_arbitrary_command_or_path_action(tmp_path):
    m, s = manager(tmp_path)
    for request in [{"action": "reboot"}, {"action": "sync", "path": "/etc/passwd"},
                    {"action": "status", "command": "id"}]:
        with pytest.raises(TimeSyncError): handle(request, m)
    with pytest.raises(ValidationError): handle({"action": "sync", "servers": ["a\nUser=root"]}, m)
    assert s.commands == []


def test_simulation_never_contacts_host_or_claims_success(tmp_path):
    client = TimeSyncClient("mock", tmp_path, "/no-such-socket")
    assert client.request("status")["state"] == "simulated"
    value = client.request("sync", ["time.example.com"])
    assert value["enabled"] and not value["synchronized"]
    assert TimeSyncClient("mock", tmp_path).request("status")["servers"] == ["time.example.com"]
    with pytest.raises(TimeSyncError):
        TimeSyncClient("netlab", tmp_path, "/no-such-socket").request("status")


def test_invalid_or_oversize_messages_are_rejected():
    class Peer:
        def __init__(self, data): self.data = data
        def recv(self, n):
            result, self.data = self.data[:n], self.data[n:]
            return result
    for data in [b'{}', b'[]\n', b'{}\n{}\n', b'x'*17000]:
        with pytest.raises((TimeSyncError, ValueError)):
            receive_json(Peer(data))
    assert receive_json(Peer(b'{"action":"status"}\n')) == {"action": "status"}


def test_socket_activation_authenticates_peer_and_uses_private_lock(tmp_path, monkeypatch):
    import struct
    from types import SimpleNamespace
    from fm10k_controlpanel import time_helper as helper
    peer = SimpleNamespace(uid=123, output=None)
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, seconds): pass
        def getsockopt(self, *args): return struct.pack("3i", 1000, peer.uid, 123)
        def recv(self, size): return b'{"action":"status"}\n'
        def sendall(self, value): peer.output = json.loads(value)
    monkeypatch.setattr(helper.os, "geteuid", lambda:0)
    monkeypatch.setattr(helper.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(helper.socket, "socket", lambda **kwargs:Connection())
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda name:SimpleNamespace(pw_uid=123))
    monkeypatch.setattr(helper, "LOCK", tmp_path / "operation.lock")
    monkeypatch.setattr(helper, "TimeManager", lambda:SimpleNamespace(status=lambda:{"state":"waiting"}))
    assert helper.main() == 0
    assert peer.output == {"ok":True,"data":{"state":"waiting"}}
    assert helper.LOCK.stat().st_mode & 0o777 == 0o600
    peer.uid = 999
    with pytest.raises(SystemExit, match="unauthorized"):
        helper.main()


def test_sensor_sampling_survives_clock_moving_backwards(tmp_path, monkeypatch):
    from fm10k_controlpanel.service import PanelService
    from fm10k_controlpanel.simulator import MockConfigd
    wall, monotonic, samples = [100000], [100], []
    backend = MockConfigd(tmp_path, clock=lambda: wall[0])
    original = backend.sensors
    def read_sensors():
        samples.append(wall[0])
        return original()
    monkeypatch.setattr(backend, "sensors", read_sensors)
    service = PanelService(backend, tmp_path, clock=lambda:wall[0], monotonic=lambda:monotonic[0])
    try:
        service.scheduler.call(service._sample)
        wall[0] -= 86400; monotonic[0] += 5
        service.scheduler.call(service._sample)
        assert len(samples) == 2
    finally:
        service.close()
