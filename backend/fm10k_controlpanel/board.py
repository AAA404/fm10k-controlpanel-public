"""Board algorithms exercised by the simulator and mirrored by switchd's C HAL.

No Linux I2C/UIO implementation is provided here: the HTTP process must never
be a second SDK owner. Production operations go through authenticated NetLab IPC.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from .models import EPLS, PHYSICAL, FanCurve, PortGroup, SwitchConfiguration


class HardwareError(RuntimeError):
    pass


class RollbackError(HardwareError):
    pass


class Bus(Protocol):
    def read(self, address: int, register: int | None, length: int = 1) -> bytes: ...
    def write(self, address: int, register: int | None, value: bytes) -> None: ...


@contextmanager
def selected_bus(bus: Bus, branch: int):
    previous = bus.read(0x58, None)[0]
    try:
        bus.write(0x58, None, bytes([branch]))
        yield
    finally:
        bus.write(0x58, None, bytes([previous]))


def lut_points(curve: FanCurve) -> list[dict]:
    points = [{"temperature_c": 0, "pwm_percent": curve.idle_speed_percent}]
    for index in range(9):
        ratio = index / 8
        points.append({
            "temperature_c": round(curve.idle_temperature_c + (curve.load_temperature_c - curve.idle_temperature_c) * ratio),
            "pwm_percent": round(curve.idle_speed_percent + (curve.load_speed_percent - curve.idle_speed_percent) * ratio),
        })
    return points + [{"temperature_c": curve.critical_temperature_c, "pwm_percent": 100},
                     {"temperature_c": 127, "pwm_percent": 100}]


def fan_register_program(curve: FanCurve) -> list[tuple[int, int]]:
    # Direct mode and full PWM precede any LUT or critical-limit change.
    # LM96163 0x45: high-resolution PWM bit 4, ramp selection bits 2:1,
    # and smoothing-enable bit 0 (TI SNAS433D, register 0x45).
    response = {5.45: 0x11, 10.9: 0x13, 21.6: 0x15, 43.7: 0x17}[curve.response_time_s]
    values = [(0x30, 0x02), (0x4A, 0x30), (0x4B, 0x3F), (0x4D, 0x08), (0x4C, 0xFF),
              (0x45, response), (0x4E, 0), (0x4F, curve.hysteresis_c)]
    for index, point in enumerate(lut_points(curve)):
        values += [(0x50 + 2 * index, point["temperature_c"]),
                   (0x51 + 2 * index, round(point["pwm_percent"] * 255 / 100))]
    values += [(0x03, 0x06), (0x19, curve.critical_temperature_c), (0x21, curve.hysteresis_c)]
    return values


def apply_fan_curve(bus: Bus, curve: FanCurve) -> None:
    with selected_bus(bus, 0x08):
        try:
            for register, value in fan_register_program(curve):
                bus.write(0x4C, register, bytes([value]))
                if bus.read(0x4C, register)[0] != value:
                    raise HardwareError(f"LM96163 回读不一致，寄存器 0x{register:02x}")
            bus.write(0x4C, 0x4A, b"\x10")
            if bus.read(0x4C, 0x4A)[0] != 0x10:
                raise HardwareError("LM96163 未进入硬件 LUT 模式")
        except Exception:
            # Best effort only: a disconnected bus cannot promise a PWM write.
            try:
                bus.write(0x4C, 0x4A, b"\x30")
                bus.write(0x4C, 0x4C, b"\xff")
            except Exception:
                pass
            raise


def tach_rpm(lsb: int, msb: int, factor: float = 5_400_000.0) -> tuple[int, int | None]:
    count = (msb << 8) | lsb
    return count, None if count in (0, 0xFFFF) else round(factor / count)


def read_tx_mask(bus: Bus, mpo: int) -> int:
    with selected_bus(bus, 1 << (mpo - 1)):
        return ((bus.read(0x50, 56)[0] & 0x0F) << 8) | bus.read(0x50, 57)[0]


def update_tx_mask(bus: Bus, mpo: int, lane_mask: int, enabled_mask: int, retries: int = 12) -> int:
    if mpo not in (1, 2) or lane_mask & ~0xFFF or enabled_mask & ~lane_mask:
        raise ValueError("无效的 OBT 12-bit 发射掩码")
    with selected_bus(bus, 1 << (mpo - 1)):
        high = bus.read(0x50, 56)[0]
        before = ((high & 0x0F) << 8) | bus.read(0x50, 57)[0]
        target = (before & ~lane_mask) | enabled_mask
        desired = [(56, (high & 0xF0) | (target >> 8)), (57, target & 0xFF)]
        for register, value in desired:
            for attempt in range(retries + 1):
                if bus.read(0x50, register)[0] == value:
                    break
                if attempt == retries:
                    raise HardwareError(f"OBT{mpo} offset {register} 写入在 {retries} 次重试后仍不锁存")
                bus.write(0x50, register, bytes([value]))
        observed = ((bus.read(0x50, 56)[0] & 0x0F) << 8) | bus.read(0x50, 57)[0]
        if observed != target:
            raise HardwareError(f"OBT{mpo} 掩码回读不一致")
        return observed


def group_enabled_mask(configuration: SwitchConfiguration, group: PortGroup) -> int:
    physical = PHYSICAL[group.epl]
    value = 0
    for port in group.active_ports():
        if configuration.ports[port].enabled:
            lanes = range(4) if group.mode != "split" else [port - physical["base"]]
            for lane in lanes:
                value |= 1 << (physical["position"] * 4 + lane)
    return value


def changed_groups(before: SwitchConfiguration, after: SwitchConfiguration) -> list[int]:
    old = {g.epl: g for g in before.groups}
    return [g.epl for g in after.groups
            if (g.mode, g.lane_speeds) != (old[g.epl].mode, old[g.epl].lane_speeds)]


def group_for_port(port: int) -> int:
    return EPLS[(port - 1) // 4]


def bandwidth(configuration: SwitchConfiguration) -> dict:
    external = sum(configuration.speed(p) for p in configuration.active_ports())
    return {"external_gbps": external, "internal_reserved_gbps": 20,
            "total_scheduler_gbps": external + 20, "sku_budget_gbps": 600,
            "reference_hard_limit_gbps": 647.5, "over_sku_budget": external + 20 > 600,
            "throughput_verified": False}


@dataclass(frozen=True)
class BoardIdentity:
    profile: str
    subsystem_vendor: str
    subsystem_device: str
    vpd_version: str
    model: str

    def validate(self) -> None:
        from .profiles import PROFILES
        value = self.vpd_version.lstrip("0")
        family = ("A11" if value[0] >= "6" else "B0") if value else None
        profile = PROFILES.get(self.profile)
        if (profile is None or profile.family != family or self.subsystem_vendor.lower() != "1374"
                or self.subsystem_device.lower() != "01d0" or self.model.upper() not in
                {"PE31625G24DIRA", "PE31625G24DIRA-MPS"}
                or len(self.vpd_version) != 4 or not self.vpd_version.isascii()
                or not self.vpd_version.isdecimal()):
            raise HardwareError("板卡身份与配置 Profile 不匹配，硬件写入已关闭")
