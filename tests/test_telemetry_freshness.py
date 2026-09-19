from types import SimpleNamespace

import pytest

from fm10k_controlpanel.service import PanelService


@pytest.fixture
def sampled_service(tmp_path):
    clock = [100.0]
    service = PanelService(SimpleNamespace(mode="mock", close=lambda: None), tmp_path, clock=lambda: clock[0])
    service.cache["ports"] = [{"id": 1, "sampled_at": 100.0, "quality": "valid", "state_quality": "valid", "link": "up", "rx_bytes": 123}]
    service.cache["sampled_at"] = 100.0
    try:
        yield service, clock
    finally:
        service.close()


@pytest.mark.parametrize("elapsed,expected", [(-86400, "stale"), (0, "valid"), (3, "valid"), (3.01, "stale"), (60, "stale")])
def test_device_clock_and_stale_boundary_share_one_response(sampled_service, elapsed, expected):
    service, clock = sampled_service
    clock[0] += elapsed
    result = service.telemetry()
    assert result["server_time"] == clock[0]
    assert result["port_sample_interval_seconds"] == 1
    assert result["port_stale_after_seconds"] == 3
    assert result["ports"][0]["quality"] == expected
    assert result["ports"][0]["sampled_at"] == 100.0
    assert result["ports"][0]["link"] == "up"
    assert result["ports"][0]["state_quality"] == "valid"
    assert service.cache["ports"][0]["quality"] == "valid"


def test_failed_sampling_keeps_error_and_last_known_values(sampled_service):
    service, _ = sampled_service
    service.last_error = "telemetry transport failed"
    service.cache["ports"][0]["quality"] = "stale"
    result = service.telemetry()
    assert result["error"] == "telemetry transport failed"
    assert result["ports"][0]["rx_bytes"] == 123
    assert result["ports"][0]["sampled_at"] == 100.0
    assert result["ports"][0]["quality"] == "stale"


def test_clock_metadata_is_available_before_first_sample(sampled_service):
    service, _ = sampled_service
    service.cache["ports"] = []
    result = service.telemetry()
    assert result["server_time"] == 100.0
    assert result["ports"] == []
    assert result["sensors"]["quality"] == "pending"


def test_clock_rollback_invalidates_cached_sensor_times(sampled_service):
    from fm10k_controlpanel.optics import diagnostic_shell
    service, clock = sampled_service
    service.cache["sensors"] = {
        "sampled_at": 100, "quality": "valid",
        "temperatures": [{"sampled_at": 100, "quality": "valid", "value": 45}],
        "fan": {"sampled_at": 100, "quality": "valid", "pwm_sampled_at": 100, "pwm_quality": "valid"},
    }
    service.cache["optics"] = [{"sampled_at": 100, "quality": "valid", "rx_power_sampled_at": 100, "rx_power_quality": "valid"}]
    service._optics_cache[0] = diagnostic_shell(0)
    service._optics_cache[0]["phy"].update(sampled_at=100, quality="valid")
    service._optics_due[0] = float("inf")
    clock[0] = 99
    result = service.telemetry()
    sensor, module = result["sensors"], result["optics"][0]
    assert sensor["quality"] == sensor["temperatures"][0]["quality"] == "stale"
    assert sensor["fan"]["quality"] == sensor["fan"]["pwm_quality"] == "stale"
    assert module["quality"] == module["rx_power_quality"] == "stale"
    assert sensor["temperatures"][0]["value"] == 45
    assert service.cache["sensors"]["quality"] == "valid"
    assert service.port_optics(1)["phy"]["quality"] == "stale"
    assert service._optics_cache[0]["phy"]["quality"] == "valid"
