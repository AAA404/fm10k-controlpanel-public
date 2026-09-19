import copy
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from fm10k_controlpanel.app import create_app
from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.models import PHYSICAL, PortGroup
from fm10k_controlpanel.netlab import NetlabBackend
from fm10k_controlpanel.optics import PhyModeChanged, decode_phy
from fm10k_controlpanel.service import PanelError, PanelService
from fm10k_controlpanel.simulator import MockConfigd


# Fixed, read-only RPC 120 sample from a physical port. Contains no account
# or configuration secrets; clock conversion is supplied by each test.
CAPTURE = (Path(__file__).parent / "fixtures/phy-p13-100g.xml").read_bytes()
SAMPLED_MS = 19_655_055


def decode(payload=CAPTURE, **kwargs):
    return decode_phy(payload, PortGroup(epl=5), wall=2000, monotonic_ms=SAMPLED_MS + 5000, **kwargs)


def test_real_capture_decodes_signed_values_without_inventing_optical_measurements():
    result = decode()
    assert result["quality"] == "valid"
    assert result["sampled_at"] == 1995
    assert result["pcs"] == {"block_lock": [False] * 4, "am_lock": [False] * 4,
                             "aligned": False, "high_ber": False, "raw": "0x000000e4"}
    lane = result["lanes"][3]
    assert (lane["tx_ready"], lane["rx_ready"], lane["rx_activity"], lane["rx_idle"]) == (True, True, True, False)
    assert (lane["tx_post"], lane["coarse_dfe"], lane["fine_dfe"]) == (-1, 2, 2)
    assert result["lanes"][2]["tx_pre"] == 1
    for lane in result["lanes"]:
        for name in ("tx_power_dbm", "rx_power_dbm", "eye_height_mv", "eye_width_ui"):
            assert lane[name] is None


def test_status_bits_and_failed_fields_are_not_confused_with_zero():
    root = ET.fromstring(CAPTURE)
    root.find("field[@name='pcs_ml_baser_rx_status']").set("value", str(0x01500A00))
    root.find("lane/field[@name='lane_serdes_status']").set("value", str(-2080374784))  # 0x84000000
    failed = root.find("lane/field[@name='fine_dfe']")
    failed.set("status", "-5")
    failed.attrib.pop("value")
    root.find("lane").remove(root.find("lane/field[@name='tx_pre']"))
    result = decode(ET.tostring(root))
    assert result["quality"] == "partial"
    assert result["pcs"]["block_lock"] == [False, True, False, True]
    assert result["pcs"]["am_lock"] == [True, False, True, False]
    assert result["pcs"]["high_ber"] is True
    assert result["pcs"]["aligned"] is False
    lane = result["lanes"][0]
    assert (lane["tx_ready"], lane["rx_ready"], lane["rx_activity"], lane["rx_idle"]) == (False, False, False, True)
    assert lane["serdes_raw"] == "0x84000000"
    assert lane["fine_dfe"] is None and lane["tx_pre"] is None and lane["tx_cursor"] == 0
    assert result["errors"] == {"lane0.fine_dfe": -5, "lane0.tx_pre": "missing"}


def test_unavailable_pcs_is_unknown_and_lane_order_is_canonical():
    root = ET.fromstring(CAPTURE)
    root.remove(root.find("field[@name='pcs_ml_baser_rx_status']"))
    for lane in reversed(root.findall("lane")):
        root.remove(lane)
        root.append(lane)
    result = decode(ET.tostring(root))
    assert result["pcs"] == {"block_lock": [None] * 4, "am_lock": [None] * 4,
                             "aligned": None, "high_ber": None, "raw": None}
    assert [lane["lane"] for lane in result["lanes"]] == [0, 1, 2, 3]
    assert result["quality"] == "partial"


@pytest.mark.parametrize("attribute,value", [("port", "17"), ("epl", "6"), ("port", "invalid")])
def test_rejects_wrong_or_invalid_scope(attribute, value):
    root = ET.fromstring(CAPTURE)
    root.set(attribute, value)
    with pytest.raises(ValueError):
        decode(ET.tostring(root))


@pytest.mark.parametrize("mutation", ["root", "missing_lane", "duplicate_lane", "invalid_lane", "duplicate_field", "overflow"])
def test_rejects_malformed_snapshot(mutation):
    root = ET.fromstring(CAPTURE)
    if mutation == "root": root.tag = "other"
    if mutation == "missing_lane": root.remove(root.find("lane"))
    if mutation == "duplicate_lane": root.append(copy.deepcopy(root.find("lane")))
    if mutation == "invalid_lane": root.find("lane").set("id", "4")
    if mutation == "duplicate_field": root.find("lane").append(copy.deepcopy(root.find("lane/field[@name='tx_pre']")))
    if mutation == "overflow": root.find("lane/field[@name='tx_pre']").set("value", str(1 << 31))
    with pytest.raises(ValueError):
        decode(ET.tostring(root))


def test_mode_change_is_pending_until_the_native_cache_matches():
    with pytest.raises(PhyModeChanged):
        decode_phy(CAPTURE, PortGroup(epl=5, mode="40g"), wall=2000, monotonic_ms=SAMPLED_MS)
    root = ET.fromstring(CAPTURE)
    root.set("ethernet-mode-raw", "458757")
    result = decode_phy(ET.tostring(root), PortGroup(epl=5, mode="40g"), wall=2000, monotonic_ms=SAMPLED_MS)
    assert result["quality"] == "valid"


@pytest.mark.parametrize("age,quality", [(0, "valid"), (5, "valid"), (15, "valid"), (15.001, "stale")])
def test_native_cache_age_and_stale_boundary(age, quality):
    result = decode_phy(CAPTURE, PortGroup(epl=5), wall=2000, monotonic_ms=SAMPLED_MS + age * 1000)
    assert result["sampled_at"] == pytest.approx(2000 - age)
    assert result["quality"] == quality


@pytest.mark.parametrize("wall,mono", [(float("nan"), SAMPLED_MS), (2000, float("inf")), (2000, SAMPLED_MS - 2)])
def test_invalid_or_future_monotonic_samples_fail(wall, mono):
    with pytest.raises(ValueError, match="时钟"):
        decode_phy(CAPTURE, PortGroup(epl=5), wall=wall, monotonic_ms=mono)


@pytest.mark.parametrize("epl", PHYSICAL)
def test_netlab_uses_only_fixed_read_rpc_and_never_reads_split_phy(monkeypatch, epl):
    import fm10k_controlpanel.netlab as netlab
    backend = NetlabBackend()
    calls = []
    root = ET.fromstring(CAPTURE)
    root.set("port", str(PHYSICAL[epl]["base"]))
    root.set("epl", str(epl))
    def rpc(*args, **kwargs):
        calls.append((args, kwargs))
        return ET.tostring(root)
    monkeypatch.setattr(backend, "_rpc", rpc)
    monkeypatch.setattr(netlab, "time", SimpleNamespace(time=lambda: 2000, monotonic=lambda: SAMPLED_MS / 1000))
    assert backend.optical_diagnostics(PortGroup(epl=epl, mode="split"))["quality"] == "unsupported"
    assert calls == []
    assert backend.optical_diagnostics(PortGroup(epl=epl))["quality"] == "valid"
    assert calls == [((7, 120, f"phy-port={PHYSICAL[epl]['base']}".encode()), {"timeout": 6000})]


@pytest.fixture
def diagnostic_service(tmp_path):
    now = [1000.0]
    class DiagnosticBackend(MockConfigd):
        fail = None
        calls = []
        def optical_diagnostics(self, group):
            self.calls.append((group.epl, threading.get_ident()))
            if self.fail:
                raise self.fail
            return super().optical_diagnostics(group)
    backend = DiagnosticBackend(tmp_path, clock=lambda: now[0])
    service = PanelService(backend, tmp_path, clock=lambda: now[0], monotonic=lambda: now[0])
    try:
        yield service, backend, now
    finally:
        service.close()


def settle(service):
    # A lower-priority barrier waits for the existing diagnostic work only.
    service.scheduler.submit(lambda: None, priority=30).result(3)


def collect(service, port):
    service.port_optics(port)
    settle(service)
    return service.port_optics(port)


def test_requests_return_immediately_deduplicate_epl_and_yield_to_existing_work(diagnostic_service, monkeypatch):
    service, backend, _ = diagnostic_service
    entered, release = threading.Event(), threading.Event()
    order = []
    original = backend.optical_diagnostics
    def diagnostic(group):
        order.append("optics")
        return original(group)
    monkeypatch.setattr(backend, "optical_diagnostics", diagnostic)
    def blocker():
        entered.set()
        assert release.wait(3)
    service.scheduler.submit(blocker)
    assert entered.wait(1)
    try:
        started = time.monotonic()
        responses = [service.port_optics(port) for port in [13, 14, 15, 16] * 5]
        assert time.monotonic() - started < 0.5
        assert all(result["phy"]["quality"] == "pending" and result["refreshing"] for result in responses)
        assert len(service.scheduler.keys) == 1
        assert backend.calls == []
        service.scheduler.submit(lambda: order.append("write"), priority=0)
        service.scheduler.submit(lambda: order.append("telemetry"), priority=10)
    finally:
        release.set()
    settle(service)
    assert order == ["write", "telemetry", "optics"]
    assert backend.calls == [(5, service.scheduler.thread.ident)]
    result = service.port_optics(16)
    assert result["port"] == 16 and result["owner_port"] == 13 and result["epl"] == 5
    assert result["phy"]["quality"] == "simulated" and not result["refreshing"]
    assert backend.trace == []


def test_rate_limit_stale_retention_and_recovery_are_per_epl(diagnostic_service):
    service, backend, now = diagnostic_service
    original = collect(service, 13)
    now[0] += 4.99
    assert service.port_optics(14)["refreshing"] is False
    assert len(backend.calls) == 1
    now[0] = 1005
    backend.fail = HardwareError("测试读取失败")
    failed = collect(service, 13)
    assert failed["phy"]["quality"] == "stale"
    assert failed["phy"]["sampled_at"] == original["phy"]["sampled_at"]
    assert failed["phy"]["lanes"] == original["phy"]["lanes"]
    assert failed["phy"]["error"] == "测试读取失败"
    assert original["phy"]["quality"] == "simulated"
    assert len(backend.calls) == 2
    backend.fail = None
    assert collect(service, 17)["phy"]["quality"] == "simulated"
    assert service.port_optics(13)["phy"]["quality"] == "stale"
    now[0] += 5
    recovered = collect(service, 13)
    assert recovered["phy"]["quality"] == "simulated" and "error" not in recovered["phy"]
    assert recovered["phy"]["sampled_at"] == now[0]


def test_revision_invalidates_unsupported_and_old_measurements(diagnostic_service):
    service, backend, now = diagnostic_service
    collect(service, 1)
    def change_mode(mode):
        backend.configuration.groups[0].mode = mode
        backend.revision += 1
        service._read_config()
    service.scheduler.call(lambda: change_mode("split"))
    split = collect(service, 1)
    assert split["mode"] == "split" and split["phy"]["quality"] == "unsupported"
    assert split["phy"]["lanes"] == []
    calls = len(backend.calls)
    now[0] += 100
    assert service.port_optics(2)["refreshing"] is False
    assert len(backend.calls) == calls
    service.scheduler.call(lambda: change_mode("40g"))
    backend.fail = PhyModeChanged("等待当前模式")
    pending = collect(service, 1)
    assert pending["mode"] == "40g" and pending["phy"]["quality"] == "pending"
    assert pending["phy"]["reason"] == "mode_changed" and pending["phy"]["lanes"] == []
    backend.fail = HardwareError("新模式读取失败")
    now[0] += 5
    failed = collect(service, 1)
    assert failed["phy"]["quality"] == "unavailable" and failed["phy"]["lanes"] == []


def test_failing_telemetry_still_invalidates_observed_revision(diagnostic_service, monkeypatch):
    service, backend, _ = diagnostic_service
    collect(service, 1)
    backend.revision += 1
    def fail_ports(): raise HardwareError("端口读取失败")
    monkeypatch.setattr(backend, "ports", fail_ports)
    with pytest.raises(HardwareError): service.scheduler.call(service._sample)
    assert not service._optics_cache


def test_config_failure_without_metadata_and_queue_shutdown_are_reported(diagnostic_service, monkeypatch):
    service, backend, now = diagnostic_service
    def fail_config(): raise HardwareError("配置读取失败")
    monkeypatch.setattr(backend, "snapshot", fail_config)
    result = collect(service, 1)
    assert result["phy"]["quality"] == "unavailable" and result["mode"] is None
    assert result["phy"]["error"] == "配置读取失败"
    assert backend.calls == []
    service.scheduler.close()
    now[0] += 5
    stopped = service.port_optics(1)
    assert stopped["phy"]["quality"] == "unavailable" and "退出" in stopped["phy"]["error"]
    assert stopped["refreshing"] is False


def test_response_age_and_caller_mutation_do_not_change_the_cached_sample(diagnostic_service):
    service, _, now = diagnostic_service
    original = collect(service, 1)
    now[0] += 16
    entered, release = threading.Event(), threading.Event()
    def block():
        entered.set()
        assert release.wait(3)
    service.scheduler.submit(block)
    assert entered.wait(1)
    try:
        result = service.port_optics(1)
        assert result["phy"]["quality"] == "stale" and result["refreshing"]
        assert result["server_time"] == now[0]
        result["phy"]["lanes"][0]["tx_ready"] = None
        assert service._optics_cache[0]["phy"] == original["phy"]
    finally:
        release.set()


@pytest.mark.parametrize("port", [0, 25, True, 1.0, "1"])
def test_rejects_invalid_port_before_scheduling(diagnostic_service, port):
    service, backend, _ = diagnostic_service
    with pytest.raises(PanelError) as error:
        service.port_optics(port)
    assert error.value.status == 422
    assert backend.calls == []


def test_optical_api_is_authenticated_read_only_and_simulated(tmp_path):
    backend = MockConfigd(tmp_path)
    app = create_app(state_dir=tmp_path, backend=backend)
    with TestClient(app) as client:
        assert client.get("/api/v1/optics/ports/13").status_code == 401
        assert client.post("/api/v1/auth/setup", json={"username": "fixture", "password": "fixture-optics-123"}).status_code == 200
        before = backend.snapshot()
        for port in [0, 25, "bad"]:
            assert client.get(f"/api/v1/optics/ports/{port}").status_code == 422
        assert client.get("/api/v1/optics/ports/14").status_code == 200
        settle(app.state.service)
        response = client.get("/api/v1/optics/ports/14")
        assert response.headers["cache-control"] == "no-store"
        result = response.json()
        assert result["phy"]["quality"] == "simulated"
        assert result["owner_port"] == 13 and result["epl"] == 5 and result["mpo"] == 2
        assert result["capabilities"]["rx_power"] == "unqualified"
        assert result["capabilities"]["eye_diagram"] == "on_demand_sampler"
        assert client.post("/api/v1/optics/ports/14").status_code == 405
        assert backend.snapshot() == before
