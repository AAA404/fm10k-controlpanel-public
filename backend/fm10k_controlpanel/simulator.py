from __future__ import annotations

import copy
import threading
import time
from pathlib import Path

from .board import (HardwareError, RollbackError, apply_fan_curve, changed_groups,
                    group_enabled_mask, group_for_port, lut_points, read_tx_mask,
                    tach_rpm, update_tx_mask)
from .models import EPLS, PHYSICAL, FanCurve, ManualPwm, SwitchConfiguration
from .storage import atomic_json, read_json


class SimulatedBus:
    def __init__(self):
        self.mux = 1
        self.registers = {(branch, 0x50, reg): 0 for branch in (1, 2) for reg in (56, 57)}
        self.events: list[tuple] = []
        self.drop_writes: dict[tuple[int, int, int], int] = {}
        self.unavailable = False

    def read(self, address, register, length=1):
        if self.unavailable: raise HardwareError("模拟 I²C 失联")
        if address == 0x58: return bytes([self.mux])
        return bytes(self.registers.get((self.mux, address, register + offset), 0) for offset in range(length))

    def write(self, address, register, value):
        if self.unavailable: raise HardwareError("模拟 I²C 失联")
        self.events.append((self.mux, address, register, bytes(value)))
        if address == 0x58:
            self.mux = value[0]
            return
        key = (self.mux, address, register)
        if self.drop_writes.get(key, 0):
            self.drop_writes[key] -= 1
            return
        for offset, byte in enumerate(value):
            self.registers[(self.mux, address, register + offset)] = byte


class MockConfigd:
    """An explicit simulator of the configd authority, never a hardware fallback.

    The active configuration and pending before-image are atomically persisted
    together, so a restart during a confirmed commit restores the before-image.
    """
    mode = "mock"

    def __init__(self, state_dir: Path, clock=time.time):
        self.path = state_dir / "mock-configd.json"
        self.clock = clock
        self.lock = threading.RLock()
        stored = read_json(self.path, {})
        self.configuration = SwitchConfiguration.model_validate(stored.get("configuration", {}))
        self.revision = stored.get("revision", 1)
        self.pending = stored.get("pending")
        self.last_transaction = stored.get("last_transaction")
        self.degraded_ports: set[int] = set()
        if self.pending:
            self.last_transaction = {"job_id": self.pending["job_id"], "revision": self.revision,
                                     "state": "rolled_back"}
            self.configuration = SwitchConfiguration.model_validate(self.pending["before"])
            self.revision += 1
            self.pending = None
        self.bus = SimulatedBus()
        self.hardware = self.configuration.model_copy(deep=True)
        self.trace: list[dict] = []
        self.failure: str | None = None
        self.fail_rollback = False
        self.sample_count = 0
        self.manual_until = 0.0
        self.manual_pwm: int | None = None
        self.temperature_c = 42.25
        self.tach_count = 0x0DF3
        self.sensor_error = False
        self.counter_epoch = {p: 0 for p in range(1, 25)}
        self.counter_start = self.clock()
        self.last_sensor: dict | None = None
        self._restore_hardware(self.configuration)
        self._persist()

    def _persist(self):
        atomic_json(self.path, {"revision": self.revision, "configuration": self.configuration.model_dump(mode="json"),
                               "pending": self.pending, "last_transaction": self.last_transaction})

    def snapshot(self):
        with self.lock:
            self.tick()
            return {"revision": self.revision, "configuration": self.configuration.model_dump(mode="json"),
                    "pending": copy.deepcopy(self.pending), "mode": self.mode,
                    "last_transaction": copy.deepcopy(self.last_transaction),
                    "degraded_ports": sorted(self.degraded_ports)}

    def _step(self, name: str, epl=None):
        self.trace.append({"step": name, "epl": epl, "time": self.clock()})
        if self.failure == name:
            self.failure = None
            raise HardwareError(f"故障注入：{name}")

    def _restore_hardware(self, configuration):
        for group in configuration.groups:
            update_tx_mask(self.bus, PHYSICAL[group.epl]["mpo"], 0xF << (PHYSICAL[group.epl]["position"] * 4), group_enabled_mask(configuration, group))
        apply_fan_curve(self.bus, configuration.fan)
        self.hardware = configuration.model_copy(deep=True)

    def _apply_hardware(self, before, target):
        topology_groups = changed_groups(before, target)
        admin_groups = {group_for_port(p) for p in target.ports if target.ports[p].enabled != before.ports[p].enabled}
        affected = sorted(set(topology_groups) | admin_groups)
        masks = {mpo: read_tx_mask(self.bus, mpo) for mpo in {PHYSICAL[e]["mpo"] for e in affected}}
        try:
            for epl in affected:
                physical = PHYSICAL[epl]
                group = next(g for g in target.groups if g.epl == epl)
                self._step("quiesce_protocols", epl)
                self._step("disable_group", epl)
                update_tx_mask(self.bus, physical["mpo"], 0xF << (physical["position"] * 4), 0)
                if epl in topology_groups:
                    self._step("set_ethernet_mode", epl)
                    for p in range(physical["base"], physical["base"] + 4): self.counter_epoch[p] += 1
                self._step("restore_group_configuration", epl)
                update_tx_mask(self.bus, physical["mpo"], 0xF << (physical["position"] * 4), group_enabled_mask(target, group))
                self._step("verify_group", epl)
                self._step("resume_protocols", epl)
            if target.fan != before.fan:
                self._step("fan_write")
                apply_fan_curve(self.bus, target.fan)
                self.manual_pwm = None
                self.manual_until = 0
            self._step("apply_l2")
            self.hardware = target.model_copy(deep=True)
            self._step("readback")
            if self.hardware != target: raise HardwareError("配置回读不一致")
            self.degraded_ports.difference_update(p for e in affected for p in range(PHYSICAL[e]["base"], PHYSICAL[e]["base"] + 4))
        except Exception as error:
            try:
                if self.fail_rollback: raise HardwareError("模拟回滚失败")
                for epl in affected:
                    physical = PHYSICAL[epl]
                    mask = 0xF << (physical["position"] * 4)
                    update_tx_mask(self.bus, physical["mpo"], mask, masks[physical["mpo"]] & mask)
                    self.trace.append({"step": "rollback_group", "epl": epl, "time": self.clock()})
                if target.fan != before.fan: apply_fan_curve(self.bus, before.fan)
                self.hardware = before.model_copy(deep=True)
            except Exception as rollback_error:
                for epl in affected:
                    physical = PHYSICAL[epl]
                    for p in range(physical["base"], physical["base"] + 4):
                        self.degraded_ports.add(p)
                    try: update_tx_mask(self.bus, physical["mpo"], 0xF << (physical["position"] * 4), 0)
                    except Exception: pass
                raise RollbackError(f"{error}；局部恢复失败：{rollback_error}") from rollback_error
            raise

    def apply(self, configuration, expected_revision, job_id, confirm_timeout):
        with self.lock:
            self.tick()
            if self.pending: raise HardwareError("存在尚未确认的配置，不能交叠提交")
            if expected_revision != self.revision: raise HardwareError("配置版本已变化，请重新预览")
            before = self.configuration.model_copy(deep=True)
            self.pending = {"job_id": job_id, "before": before.model_dump(mode="json"),
                            "phase": "applying", "deadline": self.clock() + confirm_timeout}
            self._persist()
            try:
                self._apply_hardware(before, configuration)
            except Exception:
                self.pending = None
                self._persist()
                raise
            self.configuration = configuration.model_copy(deep=True)
            self.revision += 1
            self.pending["phase"] = "awaiting_confirmation"
            self.pending["deadline"] = self.clock() + confirm_timeout
            self._persist()
            return self.snapshot()

    def confirm(self, job_id):
        with self.lock:
            self.tick()
            if not self.pending or self.pending["job_id"] != job_id:
                raise HardwareError("该提交已过期或不再等待确认")
            self.last_transaction = {"job_id": job_id, "revision": self.revision, "state": "confirmed"}
            self.pending = None
            self._persist()
            return self.snapshot()

    def rollback(self, job_id):
        with self.lock:
            if not self.pending or self.pending["job_id"] != job_id:
                raise HardwareError("没有匹配的待确认提交")
            target = SwitchConfiguration.model_validate(self.pending["before"])
            self._apply_hardware(self.configuration, target)
            self.last_transaction = {"job_id": job_id, "revision": self.revision, "state": "rolled_back"}
            self.configuration = target
            self.revision += 1
            self.pending = None
            self._persist()
            return self.snapshot()

    def tick(self):
        if self.pending and self.pending["phase"] == "awaiting_confirmation" and self.clock() >= self.pending["deadline"]:
            self.rollback(self.pending["job_id"])
        if self.manual_pwm is not None and self.clock() >= self.manual_until:
            apply_fan_curve(self.bus, self.configuration.fan)
            self.manual_pwm = None
            self.manual_until = 0

    def manual(self, request: ManualPwm):
        with self.lock:
            self.tick()
            if self.pending: raise HardwareError("配置提交待确认时不能开始手动 PWM 测试")
            if self.sensor_error: raise HardwareError("核心温度无有效读数，不能降低风扇 PWM")
            self.manual_pwm = 100 if self.temperature_c >= self.configuration.fan.critical_temperature_c else request.pwm_percent
            self.manual_until = self.clock() + request.duration_seconds
            return {"pwm_percent": self.manual_pwm, "expires_at": self.manual_until}

    def sensors(self):
        with self.lock:
            self.tick()
            self.sample_count += 1
            now = self.clock()
            if self.sensor_error:
                result = copy.deepcopy(self.last_sensor or {"temperatures": [], "fan": {"rpm": None}})
                result.update(quality="stale" if self.last_sensor else "unavailable", error="模拟温度读取失败")
                return result
            curve = self.configuration.fan
            pwm = self.manual_pwm
            if pwm is None:
                points = lut_points(curve)
                pwm = next((point["pwm_percent"] for point in reversed(points) if point["temperature_c"] <= self.temperature_c), curve.idle_speed_percent)
            if self.temperature_c >= curve.critical_temperature_c: pwm = 100
            count, rpm = tach_rpm(self.tach_count & 255, self.tach_count >> 8)
            result = {"mode": "mock", "quality": "simulated", "sampled_at": now,
                      "temperatures": [{"id": "fm10840_core", "label": "FM10840 核心", "celsius": self.temperature_c, "source": "LM96163 remote"},
                                       {"id": "obt1", "label": "OBT 1 内部", "celsius": 38.5, "source": "FCI 0x16/0x17"},
                                       {"id": "obt2", "label": "OBT 2 内部", "celsius": 39.25, "source": "FCI 0x16/0x17"},
                                       {"id": "atom_cpu", "label": "Intel Atom CPU", "celsius": 43.5,
                                        "source": "模拟 CPU DTS", "sampled_at": now, "quality": "simulated"}],
                      "fan": {"rpm": rpm, "rpm_estimated": True, "tach_count": count,
                              "quality": "simulated" if rpm is not None else "invalid_tach", "pwm_percent": pwm,
                              "mode": "manual" if self.manual_pwm is not None else "hardware_lut", "manual_expires_at": self.manual_until or None}}
            self.last_sensor = result
            return copy.deepcopy(result)

    def ports(self):
        with self.lock:
            self.tick()
            now = self.clock()
            result = []
            for group in sorted(self.configuration.groups, key=lambda g: EPLS.index(g.epl)):
                info = PHYSICAL[group.epl]
                for lane in range(4):
                    port = info["base"] + lane
                    active = port in group.active_ports()
                    cfg = self.configuration.ports[port]
                    up = active and cfg.enabled and port not in self.degraded_ports
                    # Synthetic counters are explicitly tagged and never used as qualification evidence.
                    octets = int(max(0, now - self.counter_start) * (port + 1) * 12500) if up else 0
                    result.append({"id": port, "epl": group.epl, "mpo": info["mpo"], "lane": lane,
                                   "active": active, "enabled": cfg.enabled, "name": cfg.name,
                                   "speed_gbps": group.speed(port), "link": "up" if up else "down",
                                   "quality": "simulated", "counter_epoch": self.counter_epoch[port],
                                   "rx_bytes": octets, "tx_bytes": octets, "crc_errors": 0,
                                   "sampled_at": now, "degraded": port in self.degraded_ports})
            return result

    def optics(self):
        return [{"mpo": mpo, "vendor": "FCI MergeOptics (模拟)", "part_number": "10124588-211",
                 "tx_enable_mask": read_tx_mask(self.bus, mpo), "rx_power": None,
                 "rx_power_quality": "unqualified", "quality": "simulated", "sampled_at": self.clock()} for mpo in (1, 2)]

    def eye_start(self, port, request):
        from .eye import ACTIVE
        previous = getattr(self, "_eye", None)
        if previous and previous["id"] == request.request_id: return self.eye_read()
        if previous and previous["state"] in ACTIVE:
            raise HardwareError("已有模拟眼图正在采集")
        self._eye = {"id": request.request_id, "state": "preparing", "source": "simulator",
                     "signal_source": "internal_prbs31_loopback" if request.signal_source == "internal_loopback" else "external",
                     "port": port, "epl": tuple(PHYSICAL)[(port-1)//4], "lane": request.lane,
                     "speed_mbps": 25000, "x_resolution": request.x_resolution,
                     "x_points": request.x_resolution*2+1, "y_points": 256//request.y_step,
                     "y_step": request.y_step, "y_min": -128, "dwell_bits": request.dwell_bits,
                     "columns_done": 0, "column_offset": 0, "errors": [], "started_at": self.clock(),
                     "elapsed_ms": 0, "restored": False, "restore_failed": False, "error": "",
                     "vertical_unit": "DAC", "measurement": "offset-sampler-xor"}
        return self.eye_read()

    def eye_read(self, job_id=None, column=0):
        import math
        value = getattr(self, "_eye", None)
        if value is None: return {"state": "idle", "source": "simulator"}
        if job_id and job_id != value["id"]: raise HardwareError("此模拟采集已被替换")
        if value["state"] in {"preparing", "running"}:
            elapsed = max(0, self.clock()-value["started_at"])
            value["elapsed_ms"] = int(elapsed*1000)
            value["columns_done"] = min(value["x_points"], int(elapsed*32))
            value["state"] = "complete" if value["columns_done"] == value["x_points"] else "running"
            value["restored"] = value["state"] == "complete"
        result = {**value, "column_offset": column, "errors": []}
        for x in range(column, min(value["columns_done"], column+4)):
            phase = (x-value["x_resolution"])/value["x_resolution"]
            opening = max(0, 1-abs(phase)*1.8)*80
            row = []
            for y in range(value["y_points"]):
                threshold = abs(-128+y*value["y_step"])
                ratio = min(0.5, 10**min(0, (threshold-opening)/12-5))
                row.append(int(value["dwell_bits"]*ratio))
            result["errors"].append(row)
        return result

    def eye_cancel(self, job_id):
        value = self.eye_read(job_id)
        if value["state"] in {"preparing", "running"}:
            self._eye.update(state="cancelled", restored=True, error="user_cancelled")
        return self.eye_read(job_id)

    def optical_diagnostics(self, group):
        if group.mode == "split":
            return {"quality": "unsupported", "reason": "split_mode", "sampled_at": None, "lanes": [], "pcs": None}
        enabled = self.configuration.ports[PHYSICAL[group.epl]["base"]].enabled
        return {"quality": "simulated", "sampled_at": self.clock(), "source": "simulator",
                "pcs": {"block_lock": [enabled] * 4, "am_lock": [enabled] * 4, "aligned": enabled, "high_ber": False, "raw": None},
                "lanes": [{"lane": lane, "tx_ready": enabled, "rx_ready": enabled, "rx_activity": enabled, "rx_idle": not enabled,
                           "tx_power_dbm": None, "rx_power_dbm": None, "eye_height_mv": None, "eye_width_ui": None,
                           "coarse_dfe": 2 if enabled else 0, "fine_dfe": 2 if enabled else 0,
                           "dfe_mode": 1, "tx_pre": 0, "tx_cursor": 0, "tx_post": 0,
                           "rx_polarity": 0, "tx_polarity": 0, "rx_termination": 0,
                           "signal_transition_threshold": 20, "serdes_raw": None} for lane in range(4)]}

    def operational(self, feature):
        config = self.configuration
        if feature == "roce":
            return {"quality": "simulated", "configuration_applied": False, "traffic_validation": "not-run",
                    "buffer_ready": False, "ports": [], "tc_smp_map": [], "ecn": "unsupported"}
        if feature == "fdb": return [dict(m.model_dump(), type="static", quality="simulated") for m in config.static_macs]
        if feature == "lldp": return []
        if feature == "lags": return [dict(l.model_dump(), state="simulated", synchronized=False) for l in config.lags]
        if feature == "rstp": return {"enabled": config.rstp.enabled, "quality": "simulated", "ports": []}
        if feature == "igmp": return [g.model_dump() for g in config.igmp.static_groups]
        return []

    def clear_fdb(self, port=None, vlan=None):
        self._step("clear_dynamic_fdb")
        return {"cleared": True, "port": port, "vlan": vlan, "mode": "mock"}

    def close(self):
        # Timers are deliberately authority-owned; only simulated process exit
        # ends the in-process simulator. A real switchd remains independent.
        pass
