import pytest
from pydantic import ValidationError

from fm10k_controlpanel.board import BoardIdentity, HardwareError, RollbackError, apply_fan_curve, lut_points, read_tx_mask, tach_rpm, update_tx_mask
from fm10k_controlpanel.models import FanCurve, ManualPwm, SwitchConfiguration
from fm10k_controlpanel.simulator import MockConfigd, SimulatedBus


@pytest.mark.parametrize("profile,version", [("sil001-hw4-b0", "0490"), ("sil001-hw5-a11", "0680")])
def test_identity_cannot_be_relabelled_to_another_board_profile(profile, version):
    BoardIdentity(profile, "1374", "01d0", version, "PE31625G24DiRA-MPS").validate()
    other = "sil001-hw5-a11" if profile.endswith("b0") else "sil001-hw4-b0"
    with pytest.raises(HardwareError, match="身份"):
        BoardIdentity(other, "1374", "01d0", version, "PE31625G24DiRA-MPS").validate()
    for bad in ("0000", "680", "0680\n", "abcd", "０６８０"):
        with pytest.raises(HardwareError):
            BoardIdentity(profile, "1374", "01d0", bad, "PE31625G24DiRA-MPS").validate()


def split(configuration, epl=0):
    value = configuration.model_dump(mode="json")
    next(group for group in value["groups"] if group["epl"] == epl)["mode"] = "split"
    return SwitchConfiguration.model_validate(value)


def test_fixed_slots_and_port_mapping():
    config = SwitchConfiguration()
    assert config.active_ports() == {1, 5, 9, 13, 17, 21}
    assert len(config.ports) == 24
    config = split(config)
    assert config.active_ports() == {1, 2, 3, 4, 5, 9, 13, 17, 21}
    assert config.speed(2) == 25
    assert config.speed(13) == 100


def test_cannot_collapse_referenced_lane():
    value = split(SwitchConfiguration()).model_dump(mode="json")
    value["ports"]["2"]["pvid"] = 1
    value["groups"][0]["mode"] = "100g"
    with pytest.raises(ValidationError, match="解除引用"):
        SwitchConfiguration.model_validate(value)


@pytest.mark.parametrize("bad", [dict(idle_speed_percent=24), dict(response_time_s=8), dict(load_temperature_c=40), dict(critical_temperature_c=65)])
def test_fan_invalid_inputs(bad):
    with pytest.raises(ValidationError): FanCurve(**bad)


@pytest.mark.parametrize("seconds,register", [(5.45, 0x11), (10.9, 0x13), (21.6, 0x15), (43.7, 0x17)])
def test_all_hardware_fan_response_encodings(seconds, register):
    bus = SimulatedBus()
    apply_fan_curve(bus, FanCurve(response_time_s=seconds))
    assert bus.registers[(8, 0x4C, 0x45)] == register


def test_hardware_lut_matches_verified_default():
    points = lut_points(FanCurve())
    assert len(points) == 12
    assert [p["temperature_c"] for p in points] == [0, 35, 39, 44, 48, 52, 57, 61, 66, 70, 80, 127]
    assert points[-2]["pwm_percent"] == 100
    bus = SimulatedBus()
    apply_fan_curve(bus, FanCurve())
    assert bus.mux == 1
    assert bus.registers[(8, 0x4C, 0x4A)] == 0x10
    assert bus.registers[(8, 0x4C, 0x45)] == 0x13
    assert bus.registers[(8, 0x4C, 0x19)] == 80
    writes = [(r, v) for mux, addr, r, v in bus.events if mux == 8 and addr == 0x4C]
    assert writes.index((0x4C, b"\xff")) < writes.index((0x50, b"\x00"))


def test_failed_fan_curve_preserves_full_speed_and_restores_mux():
    bus = SimulatedBus()
    bus.mux = 2
    bus.drop_writes[(8, 0x4C, 0x45)] = 1
    with pytest.raises(HardwareError): apply_fan_curve(bus, FanCurve())
    assert bus.mux == 2
    assert bus.registers[(8, 0x4C, 0x4C)] == 255
    assert bus.registers[(8, 0x4C, 0x4A)] == 0x30


def test_optical_mask_preserves_sibling_epls_and_other_obt():
    bus = SimulatedBus()
    update_tx_mask(bus, 1, 0xFFF, 0xFFF)
    update_tx_mask(bus, 2, 0xFFF, 0xABC)
    update_tx_mask(bus, 1, 0xF0, 0x20)
    assert read_tx_mask(bus, 1) == 0xF2F
    assert read_tx_mask(bus, 2) == 0xABC
    assert not any(address == 0x50 and register == 86 for _, address, register, _ in bus.events)


def test_optical_latch_retry_and_restore():
    bus = SimulatedBus()
    bus.mux = 8
    bus.drop_writes[(1, 0x50, 57)] = 2
    update_tx_mask(bus, 1, 0xFFF, 0x123)
    assert read_tx_mask(bus, 1) == 0x123
    assert bus.mux == 8
    assert len([e for e in bus.events if e[:3] == (1, 0x50, 57)]) == 3


def test_optical_retry_is_bounded():
    bus = SimulatedBus()
    bus.drop_writes[(1, 0x50, 57)] = 100
    with pytest.raises(HardwareError): update_tx_mask(bus, 1, 0xFFF, 0xFFF)
    assert bus.mux == 1


@pytest.mark.parametrize("count", [0, 0xFFFF])
def test_invalid_tach_is_not_zero_rpm(count):
    assert tach_rpm(count & 255, count >> 8) == (count, None)


def test_live_group_change_never_restarts_switch(tmp_path):
    authority = MockConfigd(tmp_path)
    target = split(authority.configuration, 5)
    result = authority.apply(target, 1, "test-job", 60)
    assert result["revision"] == 2
    assert {e["epl"] for e in authority.trace if e["epl"] is not None} == {5}
    assert all("restart" not in e["step"] for e in authority.trace)
    assert authority.counter_epoch[1] == 0 and authority.counter_epoch[13] == 1
    authority.confirm("test-job")
    assert authority.pending is None


@pytest.mark.parametrize("phase", ["quiesce_protocols", "disable_group", "set_ethernet_mode", "restore_group_configuration", "verify_group", "resume_protocols", "apply_l2", "readback"])
def test_failure_rolls_back_only_target_group(tmp_path, phase):
    authority = MockConfigd(tmp_path)
    before = authority.configuration.model_copy(deep=True)
    authority.failure = phase
    with pytest.raises(HardwareError): authority.apply(split(before, 6), 1, "failure", 60)
    assert authority.configuration == before and authority.hardware == before
    assert authority.revision == 1
    assert {e["epl"] for e in authority.trace if e["step"] == "rollback_group"} == {6}
    assert authority.pending is None


def test_rollback_failure_does_not_disable_other_groups(tmp_path):
    authority = MockConfigd(tmp_path)
    authority.failure, authority.fail_rollback = "set_ethernet_mode", True
    with pytest.raises(RollbackError): authority.apply(split(authority.configuration, 1), 1, "failure", 60)
    assert authority.degraded_ports == {5, 6, 7, 8}


def test_confirmed_timeout_and_restart_recover_before_image(tmp_path):
    now = [1000.0]
    authority = MockConfigd(tmp_path, clock=lambda: now[0])
    authority.apply(split(authority.configuration), 1, "pending", 30)
    now[0] += 31
    state = authority.snapshot()
    assert state["configuration"]["groups"][0]["mode"] == "100g"
    assert state["revision"] == 3 and state["pending"] is None
    authority.apply(split(authority.configuration), 3, "restart", 60)
    restarted = MockConfigd(tmp_path, clock=lambda: now[0])
    assert restarted.configuration.groups[0].mode == "100g"
    assert restarted.pending is None


def test_manual_pwm_expires_in_authority(tmp_path):
    now = [1000.0]
    authority = MockConfigd(tmp_path, clock=lambda: now[0])
    authority.manual(ManualPwm(pwm_percent=30, duration_seconds=10))
    assert authority.sensors()["fan"]["mode"] == "manual"
    now[0] += 11
    assert authority.sensors()["fan"]["mode"] == "hardware_lut"
    authority.temperature_c = 90
    assert authority.manual(ManualPwm(pwm_percent=25))["pwm_percent"] == 100


def test_igmp_fast_leave_requires_direct_receiver():
    value = SwitchConfiguration().model_dump(mode="json")
    value["ports"]["1"].update(enabled=True, pvid=1)
    value["igmp"].update(enabled=True, vlans=[1], fast_leave_ports=[1])
    with pytest.raises(ValidationError, match="直连"):
        SwitchConfiguration.model_validate(value)
    value["ports"]["1"]["direct_receiver"] = True
    assert SwitchConfiguration.model_validate(value).igmp.fast_leave_ports == [1]
