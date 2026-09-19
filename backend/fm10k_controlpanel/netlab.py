"""Restricted authenticated NetLab IPC; no SDK/I2C imports or shell execution."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .board import HardwareError
from .models import PHYSICAL, SwitchConfiguration
from .netlab_codec import compile_configuration, decode_configuration, parse_xml
from .netlab_wire import decode_mac_snapshot
from .host_sensors import AtomTemperature
from .optics import decode_phy
from .roce_monitor import RoceMonitor

CONFIGD, SWITCHD = 2, 7
SNAPSHOT, VALIDATE, APPLY, CONFIRM, ROLLBACK, RECOVER = 19, 20, 21, 22, 23, 24
BOARD_TELEMETRY, FAN_MANUAL = 132, 133


class NetlabBackend:
    mode = "netlab"

    def __init__(self, transport=None):
        self.transport = transport
        self._owns_transport = transport is None
        self._configuration = None
        self._board_sample = None
        self.contract = {}
        self.host_temperature = AtomTemperature()
        self.roce_monitor = RoceMonitor()

    def _connect(self):
        if self.transport is not None:
            return
        if not sys.platform.startswith("linux"):
            raise HardwareError("原生 NetLab 后端仅支持 Linux；不会自动切换为模拟设备")
        root = Path(os.environ.get("PANEL_NETLAB_ROOT", Path(__file__).resolve().parents[2] / "vendor/netlab"))
        path = root / "bin/cli/session.py"
        if not path.is_file():
            raise HardwareError("缺少 NetLab 的受信 IPC 客户端")
        spec = importlib.util.spec_from_file_location("fm10k_netlab_session", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = module.CliSession()
        if not session.connect():
            raise HardwareError("无法连接 mgmtd；请检查原生服务、套接字权限和身份代理")
        self.transport = session

    def _rpc(self, service, method, payload=b"", timeout=30000):
        self._connect()
        try:
            try:
                error, size, data = self.transport.send_request(service, method, payload, timeout_ms=timeout)
            except (OSError, TimeoutError) as error:
                self.close()
                raise HardwareError(f"NetLab IPC 连接失败：{error}") from error
            if error or size != len(data):
                detail = data.decode("utf-8", errors="replace").strip() or f"service={service} method={method} code={error}"
                if error == -1:
                    self.close()
                raise HardwareError(f"NetLab 操作未完成：{detail}")
            return data
        finally:
            # libdaemon authenticates, dispatches one request and closes the
            # connection. Open a fresh authenticated session for the next RPC;
            # never retry a potentially applied write after losing its reply.
            if self._owns_transport:
                self.close()

    def snapshot(self):
        root = parse_xml(self._rpc(CONFIGD, SNAPSHOT))
        if root.tag != "fm10k-panel-state" or root.get("api") != "1":
            raise HardwareError("configd 未提供兼容的 FM10K 原子事务接口，硬件写入已关闭")
        node = root.find("netlab-config")
        if node is None:
            raise HardwareError("configd 未返回活动配置")
        configuration = decode_configuration(ET.tostring(node, encoding="utf-8"))
        self._configuration = configuration
        self.contract = dict(root.attrib)
        pending = None
        if root.get("pending") == "true":
            pending = {"job_id": root.get("job-id"), "deadline": int(root.get("deadline", "0")),
                       "phase": "awaiting_confirmation"}
            if root.get("remaining-seconds") is not None:
                try:
                    remaining = int(root.get("remaining-seconds"))
                except (ValueError, TypeError):
                    raise HardwareError("configd 待确认倒计时无效") from None
                if remaining < 0:
                    raise HardwareError("configd 待确认倒计时不可用")
                pending["remaining_seconds"] = remaining
        return {"revision": int(root.attrib["revision"]), "configuration": configuration.model_dump(mode="json"),
                "pending": pending, "mode": self.mode, "degraded_ports": [],
                "last_transaction": {"revision": int(root.get("transaction-revision", "0")),
                                     "state": root.get("transaction-state", "unknown")},
                "synchronized": root.get("synchronized") == "true",
                "hardware_write_ready": root.get("board-hal") == "bound" and root.get("synchronized") == "true",
                "integration": root.get("board-hal", "unbound")}

    def _envelope(self, config, expected_revision, job_id="0" * 32, timeout=60):
        return f"{expected_revision}\n{job_id}\n{timeout}\n".encode() + compile_configuration(config, job_id)

    def validate(self, configuration):
        current = self.snapshot()
        if not current["hardware_write_ready"]:
            raise HardwareError("原生板级 HAL 尚未通过绑定检查；当前禁止硬件配置写入")
        if configuration.qos.roce.enabled:
            flow = parse_xml(self._rpc(SWITCHD, 68, b"flow-control")).find("flow-control")
            if flow is None or flow.get("roce-buffer-status") != "0":
                raise HardwareError("RoCE 混合缓冲尚未就绪，请先完成维护窗口初始化并核对水位")
        self._rpc(CONFIGD, VALIDATE, self._envelope(configuration, current["revision"]))

    def apply(self, configuration, expected_revision, job_id, confirm_timeout):
        try:
            self._rpc(CONFIGD, APPLY, self._envelope(configuration, expected_revision, job_id, confirm_timeout), timeout=120000)
        except HardwareError as apply_error:
            # The reply can be lost after configd's durable commit point.
            # Only matching authority evidence can recover that success.
            try:
                state = self.snapshot()
            except HardwareError as read_error:
                raise HardwareError(f"{apply_error}；后续状态核对失败：{read_error}") from apply_error
            if ((state.get("pending") or {}).get("job_id") != job_id or
                    state["configuration"] != configuration.model_dump(mode="json") or
                    not state["hardware_write_ready"]):
                raise
            return state
        state = self.snapshot()
        if ((state.get("pending") or {}).get("job_id") != job_id or
                state["configuration"] != configuration.model_dump(mode="json") or
                not state["hardware_write_ready"]):
            raise HardwareError("configd 返回结果与提交不一致，请检查原生事务状态")
        return state

    def _finish(self, job_id, method):
        before = self.snapshot()
        if (before.get("pending") or {}).get("job_id") != job_id:
            raise HardwareError("该提交已过期或不再等待确认")
        rpc_error = None
        try:
            self._rpc(CONFIGD, method, job_id.encode("ascii"), timeout=120000)
        except HardwareError as error:
            rpc_error = error
        state = self.snapshot()
        terminal = state["last_transaction"]
        outcome = "confirmed" if method == CONFIRM else "rolled_back"
        if (state["synchronized"] and not state.get("pending") and
                terminal["revision"] == before["revision"] and terminal["state"] == outcome):
            return state
        if rpc_error:
            raise rpc_error
        raise HardwareError("configd 尚未提供已核实的事务结果，请检查原生事务状态")

    def confirm(self, job_id):
        return self._finish(job_id, CONFIRM)

    def rollback(self, job_id):
        return self._finish(job_id, ROLLBACK)

    def recover_control(self):
        before = self.snapshot()
        if (self.contract.get("startup-mode") != "control" or
                self.contract.get("recovery") != "active-replay-v1"):
            raise HardwareError("当前原生服务不支持恢复控制，请先安装配套原生更新")
        self._rpc(CONFIGD, RECOVER, str(before["revision"]).encode("ascii"), timeout=120000)
        state = self.snapshot()
        if not state["hardware_write_ready"]:
            raise HardwareError("恢复后硬件尚未同步，控制仍保持锁定")
        return state

    def ports(self):
        root = parse_xml(self._rpc(SWITCHD, 120, b"counters=1", timeout=10000))
        if root.tag != "port-snapshot":
            raise HardwareError("端口快照响应类型错误")
        cfg = self._configuration
        if cfg is None:
            self.snapshot()
            cfg = self._configuration
        indexed = {int(p.attrib["id"]): p for p in root.findall("port")}
        now, result = time.time(), []
        for group in cfg.groups:
            physical = PHYSICAL[group.epl]
            for lane in range(4):
                number = physical["base"] + lane
                node = indexed.get(number)
                if node is None:
                    raise HardwareError(f"switchd 缺少固定逻辑槽位 {number}，请核对平台配置")
                state_valid = node.get("state-status") == "0"
                counters_valid = node.get("counter-status") == "0" and root.get("counters") == "true"
                valid = state_valid and counters_valid
                mode = node.get("ethernet-mode", "")
                rate = re.match(r"^(10|25|40|100)GBase-", mode, re.IGNORECASE)
                line_rate = int(rate[1]) if rate else 0 if mode == "DISABLED" else None
                result.append({
                    "id": number, "epl": group.epl, "mpo": physical["mpo"], "lane": lane,
                    "active": number in group.active_ports(), "name": cfg.ports[number].name,
                    "enabled": node.get("admin") in {"up", "enabled", "1"},
                    "speed_gbps": line_rate if state_valid else None,
                    "scheduler_speed_gbps": int(node.get("speed", "0")) / 1000 if state_valid else None,
                    "ethernet_mode": mode,
                    "link": node.get("link", "unknown") if state_valid else "unknown",
                    "quality": "valid" if valid else "unavailable",
                    # generation is a sample sequence, not a counter-reset epoch.
                    "sample_generation": root.get("generation"), "counter_epoch": None,
                    "sampled_at": now, "degraded": False,
                    "state_quality": "valid" if state_valid else "unavailable",
                    "counter_quality": "valid" if counters_valid else "unavailable",
                    **{target: int(node.attrib[source]) if source in node.attrib and counters_valid else None
                       for target, source in [("rx_bytes", "rx-bytes"), ("tx_bytes", "tx-bytes"),
                                              ("rx_packets", "rx-packets"), ("tx_packets", "tx-packets"),
                                              ("rx_errors", "rx-errors"), ("tx_errors", "tx-errors"),
                                              ("rx_drops", "rx-drops"), ("tx_drops", "tx-drops"),
                                              ("crc_errors", "rx-fcs-errors")]},
                })
        return result

    def sensors(self):
        if self._configuration is None:
            self.snapshot()
        try:
            sample = json.loads(self._rpc(SWITCHD, BOARD_TELEMETRY))
        except (ValueError, TypeError) as error:
            raise HardwareError("switchd 板级遥测响应无效") from error
        if sample.get("api") != 1 or sample.get("profile") != self._configuration.profile:
            raise HardwareError("板级遥测协议或 Profile 不匹配")
        self._board_sample = sample
        sensors = sample["sensors"]
        sensors["temperatures"] = [sensor for sensor in sensors.get("temperatures", []) if sensor.get("id") != "atom_cpu"]
        sensors["temperatures"].append(self.host_temperature.sample())
        return sensors

    def optics(self):
        if self._board_sample is None:
            self.sensors()
        return self._board_sample["optics"]

    def optical_diagnostics(self, group):
        if group.mode == "split":
            return {"quality": "unsupported", "reason": "split_mode", "sampled_at": None, "lanes": [], "pcs": None}
        payload = self._rpc(SWITCHD, 120, f"phy-port={PHYSICAL[group.epl]['base']}".encode(), timeout=6000)
        return decode_phy(payload, group, wall=time.time(), monotonic_ms=time.monotonic() * 1000)

    def eye_start(self, port, request):
        from .eye import validate_chunk
        command = f"start {request.request_id} {port} {request.lane} {request.x_resolution} {request.y_step} {request.dwell_bits} {request.signal_source}"
        return validate_chunk(json.loads(self._rpc(SWITCHD, 137, command.encode(), timeout=6000)))

    def eye_read(self, job_id=None, column=0):
        from .eye import validate_chunk
        if job_id is not None and not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise HardwareError("眼图任务编号无效")
        if type(column) is not int or not 0 <= column <= 129:
            raise HardwareError("眼图分页无效")
        command = f"get {job_id} {column}" if job_id else f"latest {column}"
        return validate_chunk(json.loads(self._rpc(SWITCHD, 136, command.encode(), timeout=6000)))

    def eye_cancel(self, job_id):
        from .eye import validate_chunk
        if not re.fullmatch(r"[0-9a-f]{32}", job_id): raise HardwareError("眼图任务编号无效")
        return validate_chunk(json.loads(self._rpc(SWITCHD, 137, f"cancel {job_id}".encode(), timeout=6000)))

    def manual(self, request):
        return json.loads(self._rpc(SWITCHD, FAN_MANUAL,
                                     f"{request.pwm_percent} {request.duration_seconds}".encode()))

    def sample_roce(self):
        last = self.roce_monitor.last_read
        if last is not None and time.monotonic() - last < self.roce_monitor.interval_seconds:
            return
        self.operational("roce")

    def _read_roce(self):
        from .roce import decode_operational
        before = self.snapshot()
        if before["pending"] or not before["synchronized"]:
            raise HardwareError("配置事务进行中，暂停 RoCE 采样")
        parts = {name: parse_xml(self._rpc(SWITCHD, 68, name.encode()))
                 for name in ("flow-control", "forwarding", "interfaces", "dscp-map", "scheduler", "queues", "watermarks")}
        parts["dcbx"] = parse_xml(self._rpc(10, 7))
        parts["ports"] = parse_xml(self._rpc(SWITCHD, 120, b"counters=1", timeout=10000))
        after = self.snapshot()
        if before["revision"] != after["revision"] or after["pending"] or not after["synchronized"]:
            raise HardwareError("RoCE 采样期间配置正在变更或未同步，请稍后重试")
        result = decode_operational(parts, self._configuration, after["revision"])
        result["diagnostics"] = self.roce_monitor.observe(result, time.monotonic())
        return result

    def operational(self, feature):
        if feature == "roce":
            try:
                return self._read_roce()
            except HardwareError:
                self.roce_monitor.gap()
                raise
        if feature == "fdb":
            return decode_mac_snapshot(self._rpc(SWITCHD, 125))
        routes = {"lldp": (10, 1), "lags": (11, 1), "rstp": (16, 3), "igmp": (14, 9)}
        if feature not in routes:
            raise HardwareError("未知的二层运行状态")
        root = parse_xml(self._rpc(*routes[feature]))
        expected_root = {"lldp": "lldp-neighbors", "lags": "lags", "rstp": "stp-state", "igmp": "igmp-snooping"}
        if root.tag != expected_root[feature]:
            raise HardwareError("二层运行状态响应类型错误，不能将无效回复解释为空表")
        if feature == "lldp":
            return [{key: node.findtext(tag) for key, tag in
                     [("port", "local-interface"), ("system_name", "sys-name"), ("chassis_id", "chassis-id"),
                      ("port_id", "port-id"), ("ttl", "ttl")]} for node in root.findall(".//neighbor")]
        if feature == "lags":
            result = []
            for node in root.findall(".//lag"):
                members = [dict(member.attrib) for member in node.findall("member")]
                selected = [member for member in members if member.get("selected") == "true"]
                synchronized = None
                if node.get("mode") != "static" and members and all("sync" in member for member in members):
                    synchronized = bool(selected) and all(member["sync"] == "true" for member in selected)
                result.append({"name": node.get("name"), "state": node.get("status"), "mode": node.get("mode"),
                               "synchronized": synchronized, "members": members})
            return result
        if feature == "rstp":
            return {"source": "stpd", "quality": "valid", "ports": [dict(p.attrib) for p in root.findall(".//port")],
                    "attributes": dict(root.attrib)}
        if feature == "igmp":
            if root.get("recovery-state") == "retrying":
                raise HardwareError("IGMP 运行记录保存失败，相关硬件下发正在等待恢复")
            hardware = root.find("./multicast-owner")
            if hardware is not None and hardware.get("status") not in (None, "ok"):
                raise HardwareError("IGMP 硬件成员回读不可用，不能确认缓存成员已安装")
            groups = {}
            def get_group(vlan, address):
                key = (int(vlan), address)
                return groups.setdefault(key, {"vlan": key[0], "address": key[1], "ports": [],
                    "listener_ports": [], "pending_listener_ports": [], "retiring_listener_ports": [],
                    "router_ports": [], "pending_router_ports": [], "members": []})
            # l2d emits one member element per (VLAN, group, physical port).
            for member in root.findall("./member"):
                group = get_group(member.attrib["vlan"], member.attrib["group"])
                port = int(member.attrib["port"])
                state = member.get("hardware-state", "installed")
                if member.get("source") == "dynamic" and state != "installed":
                    if state not in ("pending", "retiring"):
                        raise HardwareError("IGMP 动态成员状态无效")
                    key = "pending_listener_ports" if state == "pending" else "retiring_listener_ports"
                    if port not in group[key]: group[key].append(port)
                    group["members"].append(dict(member.attrib))
                    continue
                if port not in group["ports"]:
                    group["ports"].append(port)
                kind = "router_ports" if member.get("source") == "static-router" else "listener_ports"
                if port not in group[kind]: group[kind].append(port)
                group["members"].append(dict(member.attrib))
            for router in root.findall("./router-group"):
                group = get_group(router.attrib["vlan"], router.attrib["group"])
                applied = int(router.attrib["applied-mask"], 16)
                desired = int(router.attrib["desired-mask"], 16)
                uncertain = int(router.attrib["uncertain-mask"], 16)
                if (applied | desired | uncertain) & ~0xffffff:
                    raise HardwareError("IGMP 路由器端口回读超出板卡范围")
                for port in range(1, 25):
                    bit = 1 << (port - 1)
                    if applied & bit and not uncertain & bit:
                        if port not in group["ports"]: group["ports"].append(port)
                        if port not in group["router_ports"]: group["router_ports"].append(port)
                    if ((applied ^ desired) | uncertain) & bit:
                        if port not in group["pending_router_ports"]: group["pending_router_ports"].append(port)
                    if (applied | desired | uncertain) & bit:
                        group["members"].append({"port": str(port), "source": "router",
                            "applied": bool(applied & bit), "desired": bool(desired & bit), "uncertain": bool(uncertain & bit)})
            return list(groups.values())
        # Keep raw structured fields when native output varies; do not invent
        # learned addresses, group members or protocol success.
        return [{"source": "l2d", **node.attrib,
                 **{child.tag.replace("-", "_"): child.text for child in node if len(child) == 0}}
                for node in root.findall(".//entry" if feature == "fdb" else ".//group")]

    def clear_fdb(self, port=None, vlan=None):
        fields = []
        if port is not None:
            fields.append(f"port={int(port)}")
        if vlan is not None:
            fields.append(f"vid={int(vlan)}")
        result = self._rpc(SWITCHD, 53, " ".join(fields).encode())
        return {"mode": self.mode, "native_result": result.decode("utf-8")}

    def close(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None
