"""Static PFC commissioning envelope; no claim of traffic validation."""
from __future__ import annotations

SEGMENT = 192
PAUSE_BUFFER_BYTES = 49152
MAX_CARDINAL_PORTS = 30
MEMORY_SEGMENTS = 24576
RESERVED_SEGMENTS = 256
CNP_PRIORITY = 6
CNP_TC = 7  # FM10000 requires the DRR groups to be contiguous.


def dscp_map(configuration):
    r = configuration.qos.roce
    values = [0] * 64
    if r.enabled and r.classification == "dscp":
        values[r.dscp], values[r.cnp_dscp] = 3, CNP_PRIORITY
    return values


def dcbx_policy(configuration):
    """The advertised ETS percentages are also the actual scheduler weights."""
    r = configuration.qos.roce
    classes = [tc for tc in range(8) if not (r.classification == "dscp" and tc == CNP_TC)]
    weights = configuration.qos.weights
    total = sum(weights[tc] for tc in classes)
    # Reserve 1% per ETS class, then allocate the remainder deterministically.
    remaining = 100 - len(classes)
    bandwidth = [0] * 8
    for tc in classes:
        bandwidth[tc] = 1 + remaining * weights[tc] // total
    order = sorted(classes, key=lambda tc: (-(remaining * weights[tc] % total), tc))
    for tc in order[:100-sum(bandwidth)]:
        bandwidth[tc] += 1
    apps = [{"selector": 5, "protocol": r.dscp, "priority": 3},
            {"selector": 5, "protocol": r.cnp_dscp, "priority": 6}] if r.classification == "dscp" else [
                {"selector": 3, "protocol": 4791, "priority": 3}]
    return {"enabled": r.enabled and r.dcbx == "ieee", "pfc_mask": 8,
            "priority_map": list(configuration.qos.priority_map), "bandwidth": bandwidth,
            "tsa_map": [2 if tc in classes else 0 for tc in range(8)], "applications": apps}


def port_vlans(port, classification):
    if classification == "pcp":
        return set(port.tagged_vlans) if port.vlan_mode == "trunk" else set()
    return set(port.tagged_vlans) | ({port.pvid} if port.pvid is not None else set())


def headroom_bytes(speed_gbps: int, l2_mtu: int, cable_m: int, response_ns: int) -> int:
    # Round trip fibre propagation (5 ns/m each way), peer reaction, two
    # complete frames and the FM10000 documented committed pipeline bytes.
    frame = (l2_mtu + 25) & ~3
    flight = (speed_gbps * (response_ns + 10 * cable_m) + 7) // 8
    return ((flight + 2 * frame + 1500 + SEGMENT - 1) // SEGMENT) * SEGMENT


def buffer_budget(max_l2_mtu: int, cardinal_ports: int = MAX_CARDINAL_PORTS) -> dict:
    frame = (max_l2_mtu + 25) & ~3
    partition = ((MEMORY_SEGMENTS - RESERVED_SEGMENTS) // 2) * SEGMENT
    overshoot = ((cardinal_ports * frame + SEGMENT - 1) // SEGMENT) * SEGMENT
    available = partition - overshoot - cardinal_ports * PAUSE_BUFFER_BYTES
    return {"pause_buffer_bytes": PAUSE_BUFFER_BYTES, "cardinal_ports": cardinal_ports,
            "lossless_partition_bytes": partition, "remaining_bytes": available,
            "valid": 0 < cardinal_ports <= MAX_CARDINAL_PORTS and available > SEGMENT}


def decode_operational(parts: dict, configuration, revision: int) -> dict:
    import time
    from .board import HardwareError

    def number(text):
        try:
            value = int(text, 16 if str(text).startswith("0x") else 10)
            return value if value >= 0 else None
        except (ValueError, TypeError):
            return None

    flow = parts["flow-control"].find("flow-control")
    watermarks = parts["watermarks"].find("watermarks")
    if flow is None or watermarks is None or parts["ports"].get("status") != "ok":
        raise HardwareError("RoCE 原生诊断返回不完整")
    mapping = {number(p.get("id")): p.get("smp") for p in flow.findall("traffic-class")}
    if set(mapping) != set(range(8)):
        raise HardwareError("RoCE TC/SMP 映射读取不完整")
    forwarding = {number(p.get("priority")): number(p.get("traffic-class"))
                  for p in parts["forwarding"].findall("./forwarding/switch-priority")}
    classifiers = {number(p.get("port")): dict(p.attrib)
                   for p in parts["interfaces"].findall("./interfaces/interface")}
    counters = {number(p.get("id")): p for p in parts["ports"].findall("port")}
    roce = configuration.qos.roce
    selected = set(roce.ports) if roce.enabled else set()
    dscp_enabled = bool(selected) and roce.classification == "dscp"
    ieee = dcbx_policy(configuration)
    actual_dscp = None
    if "dscp-map" in parts:
        entries = parts["dscp-map"].findall("./dscp-map/entry")
        values = {number(p.get("dscp")): number(p.get("switch-priority")) for p in entries}
        if len(entries) != 64 or set(values) != set(range(64)) or any(v is None or v > 15 for v in values.values()):
            raise HardwareError("DSCP 全局映射回读不完整")
        actual_dscp = [values[i] for i in range(64)]
    ready = flow.get("roce-buffer-status") == "0"
    matches = all(mapping[tc] == ("smp-1" if selected and tc == 3 else "smp-0") for tc in range(8))
    matches = matches and all(forwarding.get(p) == tc for p, tc in enumerate(configuration.qos.priority_map))
    if actual_dscp is not None:
        matches = matches and actual_dscp == dscp_map(configuration)
    elif dscp_enabled:
        matches = False
    if selected:
        matches = matches and all(forwarding.get(p) == (0 if p == 11 or dscp_enabled and p == 15 else p & 7) for p in range(8, 16))
        import re
        mac = flow.get("pause-smac", "")
        matches = matches and bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac))
        if matches:
            matches = int(mac.replace(":", ""), 16) != 0 and not (int(mac[:2], 16) & 1)
    ports, seen = [], set()
    for node in flow.findall("interface"):
        port = number(node.get("port"))
        if port not in configuration.ports or port in seen:
            raise HardwareError("RoCE 端口快照编号无效或重复")
        seen.add(port)
        counter = counters.get(port)
        wanted = port in selected
        rx, tx = number(node.get("rx-class-mask")), number(node.get("tx-class-mask"))
        wd_enabled = wanted and roce.watchdog.enabled
        wd_supported = node.get("watchdog-supported") == "1"
        wd_actual = [number(node.get("watchdog-" + key + "-ms")) for key in ("detect", "recovery", "cooldown")]
        wd_expected = [roce.watchdog.detect_ms if wd_enabled else 0,
                       roce.watchdog.recovery_ms if wanted else 100,
                       roce.watchdog.cooldown_ms if wanted else 30000]
        wd_matches = wd_actual == wd_expected and (wd_supported or not wd_enabled)
        # Older native releases have no watchdog fields. They may only satisfy
        # the default disabled policy, never an enabled recovery request.
        if wd_actual == [None, None, None] and wd_expected == [0, 100, 30000]:
            wd_matches = True
        wd_phase = {0: "disabled", 1: "observing", 2: "suspect", 3: "recovering",
                    4: "cooldown", 5: "suspended", 6: "restore-failed"}.get(number(node.get("watchdog-phase")), "unavailable")
        wd_saved = number(node.get("watchdog-saved-rx-mask"))
        hw_rx = number(node.get("rx-class-mask-hardware"))
        leased = wd_enabled and wd_matches and wd_phase == "recovering" and wd_saved == 8 and rx == hw_rx == 0
        wd_sampled = number(node.get("watchdog-sampled-ms"))
        wd_fresh = wd_sampled is not None and 0 <= time.monotonic() * 1000 - wd_sampled <= 1500
        watchdog = {"supported": wd_supported, "enabled": wd_enabled, "phase": wd_phase,
                    "quality": "valid" if wd_supported and (wd_phase == "disabled" or wd_fresh and node.get("watchdog-sample-status") == "0") else "unavailable",
                    "configuration_matches": wd_matches, "saved_rx_mask": wd_saved, "hardware_rx_mask": hw_rx,
                    **{key: number(node.get("watchdog-" + key)) for key in ("detections", "restorations", "failures", "gaps")}}
        lossless, shared = number(node.get("smp-lossless-mask")), number(node.get("shared-pause-mask"))
        good = (rx == (8 if wanted else 0) or leased) and lossless == (2 if wanted else 0) and shared == (2 if wanted else 0)
        good = good and wd_matches and wd_phase != "restore-failed"
        if wanted or "pc3-smp" in node.attrib:
            good = good and number(node.get("pc3-smp")) == (1 if wanted else 2)
        if hw_rx is not None:
            good = good and (hw_rx == (8 if wanted else 0) or leased)
        if wanted:
            good = good and tx == 8 and node.get("tx-pause-mode") == "class-based" and number(node.get("tc3-pause-class")) == 3
            good = good and classifiers.get(port, {}).get("trust") == ("dscp" if dscp_enabled else "ieee-802.1p") and node.get("rx-pause") == "off"
        scheduler_matches = None
        if wanted and ("scheduler" in parts or dscp_enabled or ieee["enabled"]):
            scheduler = parts["scheduler"].find(f"./scheduler/interface[@port='{port}']") if "scheduler" in parts else None
            scheduler_matches = scheduler is not None
            if scheduler is not None:
                scheduler_matches = number(scheduler.get("sched-groups")) == 8 and number(scheduler.get("tc-enable-mask")) == 255
                max_frame = (configuration.ports[port].mtu + 25) & ~3
                for tc in range(8):
                    group = scheduler.find(f"group[@id='{tc}']")
                    mapping_node = scheduler.find(f"traffic-class[@id='{tc}']")
                    weight = max(1, ieee["bandwidth"][tc]) if ieee["enabled"] else configuration.qos.weights[tc]
                    strict = "on" if dscp_enabled and tc == CNP_TC else "off"
                    scheduler_matches = scheduler_matches and group is not None and group.get("strict") == strict and number(group.get("weight")) == 2 * max_frame * weight
                    scheduler_matches = scheduler_matches and number(group.get("tc-boundary-a")) == tc and number(group.get("tc-boundary-b")) == tc
                    if not configuration.ports[port].egress_kbps:
                        scheduler_matches = scheduler_matches and mapping_node is not None and number(mapping_node.get("shaping-group")) == tc
            good = good and scheduler_matches
        matches = matches and good
        if port not in configuration.active_ports():
            continue
        valid_state = counter is not None and counter.get("state-status") == "0"
        valid_counter = (parts["ports"].get("counters") == "true" and counter is not None and
                         counter.get("counter-status") == "0")
        pause_valid = node.get("pause-state-status") == "0"
        quanta = [number(v) for v in node.get("rx-pause-quanta", "").split()]
        pause_valid = pause_valid and len(quanta) == 8 and all(v is not None and v <= 65535 for v in quanta)
        stats = {key.replace("-", "_"): number(counter.get(key)) if valid_counter else None for key in
                 ("rx-pfc-packets", "tx-pfc-packets", "rx-pause-packets", "tx-pause-packets",
                  "rx-congestion-drops", "tx-congestion-drops", "rx-errors", "tx-errors", "rx-bytes", "tx-bytes")}
        ports.append({"port": port, "selected": wanted, "configuration_matches": bool(good),
                      "watchdog": watchdog,
                      "scheduler_matches": scheduler_matches,
                      "counter_epoch": counter.get("counter-epoch") if counter is not None else None,
                      "pause": {"quality": "valid" if pause_valid else "unavailable",
                                "rx_quanta": quanta if pause_valid else None,
                                "paused_class_mask": number(node.get("paused-class-mask")) if pause_valid else None,
                                "generated_smp_mask": number(node.get("generated-smp-pause-mask")) if pause_valid else None},
                      "cnp_usage_bytes": number(node.get("cnp-tc-usage")),
                      "link": counter.get("link", "unknown") if valid_state else "unknown",
                      "state_quality": "valid" if valid_state else "unavailable",
                      "counter_quality": "valid" if valid_counter and all(v is not None for v in stats.values()) else "unavailable",
                      "rx_class_mask": rx, "tx_class_mask": tx,
                      "pc3_smp": number(node.get("pc3-smp")),
                      "tc3_usage_bytes": number(node.get("tc3-usage")),
                      "rx_smp0_usage_bytes": number(node.get("rx-smp0-usage")),
                      "rx_smp1_usage_bytes": number(node.get("rx-smp1-usage")),
                      "counters": stats, "quality": "valid" if valid_state and valid_counter and all(v is not None for v in stats.values()) else "unavailable"})
    if set(configuration.active_ports()) - seen:
        raise HardwareError("RoCE 参与端口回读缺失")
    dcbx = {"mode": "off", "quality": "unavailable", "configuration_matches": not ieee["enabled"], "ports": []}
    if "dcbx" in parts:
        from .dcbx import decode
        dcbx = decode(parts["dcbx"], configuration, {p["port"]: p["link"] for p in ports})
    matches = matches and dcbx["configuration_matches"]
    return {"revision": revision, "sampled_at": time.time(), "quality": "valid",
            "sample_generation": number(parts["ports"].get("generation")),
            "configuration_applied": bool(matches and (not selected or ready)),
            "enabled": bool(selected), "buffer_ready": ready, "buffer_status": flow.get("roce-buffer-status", "unsupported"),
            "pause_source_mac": flow.get("pause-smac"),
            "traffic_validation": "not-run", "ecn": "unsupported", "dcbx": dcbx,
            "classification": roce.classification, "dscp_map": actual_dscp,
            "cnp_queue": {"enabled": dscp_enabled, "dscp": roce.cnp_dscp, "priority": CNP_PRIORITY, "traffic_class": CNP_TC, "pfc": False, "scheduler": "strict"},
            "tc_smp_map": [mapping[tc] for tc in range(8)], "ports": ports,
            "smp_usage_bytes": [number(flow.get(f"smp{smp}-usage")) for smp in range(2)],
            "shared_watermarks": [dict(p.attrib) for p in watermarks.findall("shared-memory")],
            "watermarks": [{"port": number(p.get("port")), "partitions": [dict(q.attrib) for q in p.findall("memory-partition")],
                            "traffic_classes": [dict(q.attrib) for q in p.findall("traffic-class")]}
                           for p in watermarks.findall("interface")],
            "budget": buffer_budget(max(p.mtu for p in configuration.ports.values()))}


def capabilities():
    """Software exposure, not a claim that every board or traffic path was qualified."""
    return {
        "qualifications": [],
        "modes": [{"id": "static-pfc", "label": "静态 PFC", "status": "configurable",
                   "reason": "PCP3 → TC3；单板二层、无环网络"},
                  {"id": "pfc-ecn", "label": "PFC + ECN", "status": "unsupported",
                   "reason": "FM10000/IES 4.3.2 的二层拥塞路径没有队列水位触发 CE 标记接口；隧道 ECN 复制不等同于拥塞标记"},
                  {"id": "ecn-only", "label": "仅 ECN", "status": "unsupported",
                   "reason": "本机无法提供拥塞 CE 标记；端点 DCQCN 仍需支持 ECN 的网络节点"}],
        "features": [
            {"id": "100g", "label": "100G RoCE", "status": "configurable", "reason": "支持 100G 端口配置；实际吞吐、headroom 与拥塞恢复需按部署拓扑验收"},
            {"id": "dscp", "label": "DSCP 分类 / CNP 队列", "status": "configurable", "reason": "数据 DSCP → TC3 无损队列；CNP 优先级 6 → TC7 严格优先级有损队列，完整映射回读与回滚"},
            {"id": "dcbx", "label": "IEEE DCBX 策略交换", "status": "configurable", "reason": "提供在线通告、策略差异检查及对端有效期管理；本机 non-willing，不接受邻居覆盖配置。网卡自动采纳策略需单独核实"},
            {"id": "pause-observation", "label": "PFC 暂停与队列诊断", "status": "configurable", "reason": "读取各优先级剩余暂停时间，每 10 秒采样、记录队列峰值与可疑停滞；历史保留在本次服务进程中"},
            {"id": "watchdog", "label": "PFC watchdog", "status": "configurable", "reason": "默认关闭；暂停停滞时临时释放队列并恢复掩码。采用保守检测，存在调度延迟和漏检可能，恢复期间可能丢包"}],
        "speeds_gbps": [10, 25, 40, 100], "priorities": [3], "minimum_ports": 2,
        "cable_length_m": {"min": 0, "max": 100, "default": 10},
        "response_time_ns": {"min": 500, "max": 10000, "default": 3000},
        "scope": "single-board-l2", "buffer_scope": "whole-chip",
    }


def configuration_issues(config):
    """Single authority for RoCE validation and the explanatory preflight UI."""
    r = config.qos.roce
    if not r.enabled:
        return []
    issues = []
    def add(path, message, port=None):
        issues.append({"path": path, "message": message, "port": port})
    selected = set(r.ports)
    active = config.active_ports()
    members = {p for lag in config.lags for p in lag.members}
    if len(selected) < 2:
        add("qos.roce.ports", "RoCE 至少需要两个参与端口")
    if config.qos.priority_map[3] != 3 or any(tc == 3 for p, tc in enumerate(config.qos.priority_map) if p != 3):
        add("qos.priority_map", "RoCE 保留 PCP3 → TC3，其他优先级不能使用 TC3")
    if config.qos.default_priority == 3:
        add("qos.default_priority", "RoCE 不允许将未标记流量的默认优先级设为 3")
    if r.classification == "dscp":
        if config.qos.priority_map[CNP_PRIORITY] != CNP_TC or any(tc == CNP_TC for i, tc in enumerate(config.qos.priority_map) if i != CNP_PRIORITY):
            add("qos.priority_map", "CNP 保留优先级 6 → TC7，其他优先级不能使用 TC7")
        if config.qos.default_priority == 6:
            add("qos.default_priority", "普通流量不能使用 CNP 的默认优先级 6")
    if r.dcbx == "ieee" and not config.lldp.enabled:
        add("lldp.enabled", "IEEE DCBX 需要启用 LLDP")
    if config.qos.trust != "none" and any(p.enabled and n not in selected for n, p in config.ports.items()):
        add("qos.trust", "非 RoCE 端口存在 802.1p 分类冲突；请将全局信任模式设为不信任")
    common = None
    for n in r.ports:
        p = config.ports[n]
        if n not in active or n in members:
            add("qos.roce.ports", f"RoCE P{n} 仅支持有效物理端口，不支持 LAG 成员", n)
        if not p.enabled or config.speed(n) not in (10, 25, 40, 100):
            add(f"ports.{n}.enabled", f"RoCE P{n} 必须启用且速率为 10/25/40G/100G", n)
        if not port_vlans(p, r.classification):
            add(f"ports.{n}.tagged_vlans", f"RoCE P{n} 必须配置" + ("带标签 VLAN" if r.classification == "pcp" else "VLAN 成员关系"), n)
        if r.dcbx == "ieee" and not p.lldp:
            add(f"ports.{n}.lldp", f"DCBX P{n} 需要启用端口 LLDP", n)
        if r.classification == "dscp" and p.egress_kbps:
            add(f"ports.{n}.egress_kbps", f"CNP 独立队列与 P{n} 共享出口整形组冲突", n)
        if p.ingress_kbps:
            add(f"ports.{n}.ingress_kbps", f"RoCE P{n} 不能启用会丢包的入口限速", n)
        if headroom_bytes(config.speed(n), p.mtu, r.cable_length_m, r.response_time_ns) > PAUSE_BUFFER_BYTES:
            add("qos.roce.response_time_ns", f"RoCE P{n} 暂停响应预算超出已配置 headroom", n)
        vlans = port_vlans(p, r.classification)
        common = vlans if common is None else common & vlans
    if selected and not common:
        add("qos.roce.ports", "RoCE 参与端口必须具有共同的" + ("带标签 VLAN" if r.classification == "pcp" else " VLAN"))
    if not buffer_budget(max(p.mtu for p in config.ports.values()))["valid"]:
        add("qos.roce", "RoCE 全芯片共享缓冲预算不足")
    return issues


def preflight(raw):
    """Validate incomplete drafts without bypassing validation at commit time."""
    import copy
    from pydantic import ValidationError
    from .models import SwitchConfiguration, PHYSICAL
    candidate = copy.deepcopy(raw)
    if not isinstance(candidate.get("qos", {}), dict) or not isinstance(candidate.get("qos", {}).get("roce", {}), dict):
        return {"valid": False, "issues": [{"path": "qos.roce", "message": "QoS / RoCE 配置必须是对象"}], "ports": [], "suggestions": []}
    try:
        # Validate field types/ranges and all other subsystem constraints first.
        requested = candidate.get("qos", {}).get("roce", {}).get("enabled", False)
        candidate.setdefault("qos", {}).setdefault("roce", {})["enabled"] = False
        config = SwitchConfiguration.model_validate(candidate)
        # model_copy avoids assignment's two-port check; collect it below instead.
        config = config.model_copy(update={"qos": config.qos.model_copy(update={
            "roce": config.qos.roce.model_copy(update={"enabled": requested is True})})})
        if not isinstance(requested, bool):
            return {"valid": False, "issues": [{"path": "qos.roce.enabled", "message": "启用状态必须是布尔值"}], "ports": [], "suggestions": []}
    except ValidationError as error:
        return {"valid": False, "issues": [{"path": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in error.errors()], "ports": [], "suggestions": []}
    issues = configuration_issues(config)
    selected = set(config.qos.roce.ports)
    members = {p for lag in config.lags for p in lag.members}
    rows, suggestions = [], []
    def suggest(path, before, after, label):
        if before != after:
            suggestions.append({"path": path, "before": before, "after": after, "label": label})
    for g in config.groups:
        physical = PHYSICAL[g.epl]
        for n in range(physical["base"], physical["base"] + 4):
            p = config.ports[n]
            speed = config.speed(n)
            reason = "拆合口后非活动槽位" if not speed else "LAG 成员暂不支持" if n in members else "当前速率不支持 RoCE" if speed not in (10, 25, 40, 100) else ""
            rows.append({"port": n, "epl": g.epl, "obt": physical["mpo"], "speed_gbps": speed,
                         "eligible": not reason, "reason": reason, "enabled": p.enabled,
                         "mtu": p.mtu, "tagged_vlans": p.tagged_vlans,
                         "headroom_bytes": headroom_bytes(speed, p.mtu, config.qos.roce.cable_length_m, config.qos.roce.response_time_ns) if speed else None,
                         "capacity_bytes": PAUSE_BUFFER_BYTES})
            if config.qos.roce.enabled and n in selected and not reason:
                suggest(f"ports.{n}.enabled", p.enabled, True, f"启用 P{n}")
                suggest(f"ports.{n}.ingress_kbps", p.ingress_kbps, 0, f"关闭 P{n} 入口限速")
                if config.qos.roce.classification == "dscp":
                    suggest(f"ports.{n}.egress_kbps", p.egress_kbps, 0, f"关闭 P{n} 共享出口整形，保留 CNP 独立队列")
                if config.qos.roce.dcbx == "ieee":
                    suggest(f"ports.{n}.lldp", p.lldp, True, f"启用 P{n} LLDP")
    if config.qos.roce.enabled:
        mapping = [0 if tc == 3 and i != 3 else tc for i, tc in enumerate(config.qos.priority_map)]
        mapping[3] = 3
        if config.qos.roce.classification == "dscp":
            if mapping[7] == CNP_TC:
                mapping[7] = 6
            mapping = [0 if tc == CNP_TC and i != CNP_PRIORITY else tc for i, tc in enumerate(mapping)]
            mapping[CNP_PRIORITY] = CNP_TC
        suggest("qos.priority_map", config.qos.priority_map, mapping,
                "保留数据优先级 3 → TC3、CNP 优先级 6 → TC7；普通优先级 7 使用 TC6" if config.qos.roce.classification == "dscp" else "保留 PCP3 → TC3，冲突优先级改用 TC0")
        if config.qos.default_priority == 3:
            suggest("qos.default_priority", 3, 0, "未标记流量使用优先级 0")
        if config.qos.roce.classification == "dscp" and config.qos.default_priority == 6:
            suggest("qos.default_priority", 6, 0, "普通流量使用优先级 0，保留 CNP 队列")
        if config.qos.roce.dcbx == "ieee":
            suggest("lldp.enabled", config.lldp.enabled, True, "启用 LLDP 以交换 DCBX 通告")
        if any(i["path"] == "qos.trust" for i in issues):
            suggest("qos.trust", config.qos.trust, "none", "全局不信任；仅参与端口信任 PCP")
    common = set.intersection(*(port_vlans(config.ports[n], config.qos.roce.classification) for n in selected)) if selected else set()
    warnings = ["缓冲与映射变更可能影响全芯片，最终以配置预览和原生校验为准。"]
    if len({config.ports[n].mtu for n in selected}) > 1:
        warnings.append("参与端口 MTU 不一致，请确认端到端报文大小不会超过最小 MTU。")
    return {"valid": not issues, "issues": issues, "warnings": warnings, "ports": rows,
            "dscp_map": dscp_map(config), "dcbx_policy": dcbx_policy(config),
            "suggestions": suggestions, "common_vlans": sorted(common),
            "budget": buffer_budget(max(p.mtu for p in config.ports.values())),
            "affected_epls": sorted(PHYSICAL)}
