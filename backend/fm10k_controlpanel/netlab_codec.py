"""Canonical translation to configd's YANG tree.

The projection lives inside the same immutable configd snapshot as its native
leaves. It preserves UI-only names and disabled slots, not an independent
active configuration. Native panel RPCs reserve this tree against CLI edits.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from .board import HardwareError
from .models import SwitchConfiguration

NS = "urn:netlab:config"
MAX_XML = 250_000


def interface(port: int) -> str:
    if not 1 <= port <= 24:
        raise ValueError("外部端口必须在 1–24 范围内")
    return f"et-0/0/{port - 1}"


def element(parent, tag, value=None):
    child = ET.SubElement(parent, tag)
    if value is not None:
        child.text = str(value).lower() if isinstance(value, bool) else str(value)
    return child


def vlan_name(vid: int) -> str:
    return f"V{vid}"


def compile_configuration(configuration: SwitchConfiguration, job_id="0" * 32) -> bytes:
    """Generate native L2 leaves and the typed board extension, with no shell."""
    c = SwitchConfiguration.model_validate(configuration.model_dump())
    root = ET.Element("netlab-config", xmlns=NS)
    chassis = element(root, "chassis")
    panel = element(chassis, "fm10k-panel")
    element(panel, "profile", c.profile)
    element(panel, "schema-version", 1)
    element(panel, "job-id", job_id)
    element(panel, "intent", json.dumps(c.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    for group in c.groups:
        node = element(panel, "port-group")
        element(node, "epl", group.epl)
        element(node, "mode", group.mode)
        for index, speed in enumerate(group.lane_speeds):
            lane = element(node, "lane")
            element(lane, "index", index)
            element(lane, "speed", speed)
    fan = element(panel, "fan")
    for key, value in c.fan.model_dump().items():
        element(fan, key.replace("_", "-"), value)
    vlans = element(root, "vlans")
    for vlan in c.vlans:
        node = element(vlans, "vlan")
        element(node, "name", vlan_name(vlan.id))
        element(node, "vlan-id", vlan.id)
        if vlan.name:
            element(node, "description", vlan.name)
    interfaces = element(root, "interfaces")
    members = {p: lag.name for lag in c.lags for p in lag.members}

    def vlan_profile(node, port):
        if port.vlan_mode == "trunk" and port.pvid is not None:
            element(node, "native-vlan-id", port.pvid)
        if port.pvid is not None or port.tagged_vlans:
            unit = element(element(node, "unit"), "logical-unit")
            element(unit, "unit-id", 0)
            switching = element(element(unit, "family"), "ethernet-switching")
            element(switching, "interface-mode", port.vlan_mode)
            for vid in sorted(set(port.tagged_vlans) | ({port.pvid} if port.pvid else set())):
                element(switching, "vlan-members", vlan_name(vid))

    for number, port in sorted(c.ports.items()):
        node = element(interfaces, "interface")
        element(node, "name", interface(number))
        element(node, "disable", not port.enabled)
        if port.name:
            element(node, "description", port.name)
        element(node, "mtu", port.mtu)
        if number in c.active_ports() and c.speed(number) in (10, 25):
            element(node, "speed", f"{c.speed(number)}g")
        if number in members:
            element(element(node, "ether-options"), "ieee8023ad", members[number])
        else:
            vlan_profile(node, port)
        board = element(node, "fm10k-port")
        element(board, "ingress-filtering", port.ingress_filtering)
        element(board, "direct-receiver", port.direct_receiver)
        for name, value in port.storm.model_dump().items():
            element(board, name.replace("_", "-"), value)
    for lag in c.lags:
        node = element(interfaces, "interface")
        element(node, "name", lag.name)
        first = c.ports[lag.members[0]]
        element(node, "mtu", first.mtu)
        element(element(node, "fm10k-port"), "ingress-filtering", first.ingress_filtering)
        agg = element(node, "aggregated-ether-options")
        element(agg, "minimum-links", lag.minimum_links)
        if lag.mode == "static":
            element(agg, "static", True)
        else:
            lacp = element(agg, "lacp")
            element(lacp, "mode", lag.mode)
            element(lacp, "periodic", lag.periodic)
        vlan_profile(node, first)
    es = element(root, "ethernet-switching-options")
    element(es, "mac-table-aging-time", c.mac_aging_seconds)
    if c.static_macs:
        static = element(es, "static")
        for entry in c.static_macs:
            node = element(static, "mac-table-entry")
            element(node, "mac-address", entry.mac)
            element(node, "vlan", vlan_name(entry.vlan))
            element(node, "interface", members.get(entry.port, interface(entry.port)))
    for name in ("ingress", "egress"):
        rates = [(p, getattr(port, name + "_kbps")) for p, port in c.ports.items() if getattr(port, name + "_kbps")]
        if rates:
            section = element(es, name + "-rate-limit")
            for number, rate in rates:
                node = element(section, "interface")
                element(node, "name", interface(number))
                element(node, "bandwidth", rate)
                element(node, "burst-size", 32768)
    protocols = element(root, "protocols")
    lldp = element(protocols, "lldp")
    from .roce import dcbx_policy
    ieee_policy = dcbx_policy(c)
    element(lldp, "disable", not c.lldp.enabled)
    element(lldp, "transmit-interval", c.lldp.transmit_interval)
    element(lldp, "hold-multiplier", c.lldp.hold_multiplier)
    for number in sorted(c.active_ports()):
        node = element(lldp, "interface")
        element(node, "name", interface(number))
        element(node, "disable", not c.ports[number].lldp)
        if ieee_policy["enabled"] and number in c.qos.roce.ports:
            dcbx = element(node, "dcbx")
            element(dcbx, "enabled", True)
            element(dcbx, "pfc-mask", ieee_policy["pfc_mask"])
            for key in ("priority_map", "bandwidth", "tsa_map"):
                element(dcbx, key.replace("_", "-"), " ".join(map(str, ieee_policy[key])))
            for app in ieee_policy["applications"]:
                entry = element(dcbx, "application")
                for key, value in app.items():
                    element(entry, key, value)
    if c.rstp.enabled:
        rstp = element(protocols, "rstp")
        element(rstp, "bridge-priority", c.rstp.bridge_priority)
        for number in sorted(c.active_ports()):
            if number in members:
                continue
            port = c.ports[number]
            node = element(rstp, "interface")
            element(node, "name", interface(number))
            element(node, "edge", port.edge)
            element(node, "bpdu-block-on-edge", port.bpdu_guard)
            if port.path_cost:
                element(node, "path-cost", port.path_cost)
            element(node, "port-priority", port.port_priority)
        for lag in c.lags:
            node = element(rstp, "interface")
            element(node, "name", lag.name)
    if c.igmp.enabled:
        igmp = element(protocols, "igmp-snooping")
        element(igmp, "membership-timeout", c.igmp.membership_timeout)
        for vid in sorted(set(c.igmp.vlans) | {g.vlan for g in c.igmp.static_groups}):
            vnode = element(igmp, "vlan")
            element(vnode, "name", vlan_name(vid))
            for number in sorted(c.active_ports()):
                port = c.ports[number]
                if vid not in {port.pvid, *port.tagged_vlans}:
                    continue
                inode = element(vnode, "interface")
                element(inode, "name", interface(number))
                element(inode, "mrouter", number in c.igmp.router_ports)
                element(inode, "fast-leave", number in c.igmp.fast_leave_ports)
                for group in c.igmp.static_groups:
                    if group.vlan == vid and number in group.ports:
                        element(inode, "static-group", group.address)
    qos = element(root, "class-of-service")
    roce_ports = set(c.qos.roce.ports) if c.qos.roce.enabled else set()
    dscp_mode = bool(roce_ports) and c.qos.roce.classification == "dscp"
    # The map is global. Emit all entries so disabling/changing the profile
    # removes old classifiers and startup replay repairs drift.
    classifiers = element(qos, "dscp-map")
    for dscp in range(64):
        node = element(classifiers, "entry")
        element(node, "dscp", dscp)
        priority = 3 if dscp_mode and dscp == c.qos.roce.dscp else 6 if dscp_mode and dscp == c.qos.roce.cnp_dscp else 0
        element(node, "switch-priority", priority)
    # Explicit zeros permit disable, rollback and startup drift repair.
    memory = element(qos, "shared-memory")
    for tc in range(8):
        entry = element(memory, "traffic-class")
        element(entry, "class", tc)
        element(entry, "partition", int(bool(roce_ports) and tc == 3))
    qifs = element(qos, "interfaces")
    forwarding = element(qos, "forwarding")
    for priority, tc in enumerate(c.qos.priority_map):
        node = element(forwarding, "switch-priority")
        element(node, "priority", priority)
        element(node, "traffic-class", tc)
    if roce_ports:
        # Internal priorities also use the global map. SWPRI11 must not
        # inherit the SDK's modulo-eight mapping into the lossless TC3.
        for priority in range(8, 16):
            node = element(forwarding, "switch-priority")
            element(node, "priority", priority)
            element(node, "traffic-class", 0 if priority == 11 or dscp_mode and priority == 15 else priority & 7)
    scheduler_ifs = element(element(qos, "scheduler"), "interfaces")
    for number in sorted(c.active_ports()):
        node = element(qifs, "interface")
        element(node, "name", interface(number))
        element(node, "trust", ("dscp" if dscp_mode else "ieee-802.1p") if number in roce_ports else c.qos.trust)
        element(node, "default-priority", c.qos.default_priority)
        if number in roce_ports:
            pfc = element(node, "priority-flow-control")
            for name, value in (("rx-class-mask", 8), ("tx-class-mask", 8),
                                ("lossless-smp-mask", 2), ("shared-pause-mask", 2)):
                element(pfc, name, value)
            watchdog = c.qos.roce.watchdog
            element(pfc, "watchdog-detect-ms", watchdog.detect_ms if watchdog.enabled else 0)
            element(pfc, "watchdog-recovery-ms", watchdog.recovery_ms)
            element(pfc, "watchdog-cooldown-ms", watchdog.cooldown_ms)
        sched = element(scheduler_ifs, "interface")
        element(sched, "name", interface(number))
        element(sched, "traffic-class-enable-mask", 255)
        for tc in range(8):
            # The port limiter owns the common shaping group. Scheduler
            # groups are independent and keep their SP/DRR configuration.
            if not c.ports[number].egress_kbps:
                tnode = element(sched, "traffic-class")
                element(tnode, "class", tc)
                element(tnode, "shaping-group", tc)
            group = element(sched, "group")
            element(group, "id", tc)
            element(group, "strict-priority", (tc == 7 and dscp_mode) if number in roce_ports else c.qos.scheduler == "strict")
            # IES uses byte quanta, not relative weights. Below 2*MTU the
            # resulting bandwidth ratio depends on queued frame sizes.
            # Match hal_port_mtu_to_max_frame(): 22 bytes overhead, rounded
            # up to the SDK's four-byte frame-size granularity.
            max_frame = (c.ports[number].mtu + 22 + 3) & ~3
            weight = max(1, ieee_policy["bandwidth"][tc]) if number in roce_ports and ieee_policy["enabled"] else c.qos.weights[tc]
            element(group, "weight", 2 * max_frame * weight)
    if c.mirror.enabled:
        mirror = element(element(element(root, "forwarding-options"), "port-mirroring"), "instance")
        element(mirror, "name", "panel")
        element(element(mirror, "output"), "interface", interface(c.mirror.destination))
        src = element(element(mirror, "input"), "interface")
        element(src, "name", interface(c.mirror.source))
        element(src, "direction", {"rx": "ingress", "tx": "egress", "both": "both"}[c.mirror.direction])
    result = ET.tostring(root, encoding="utf-8")
    if len(result) > MAX_XML:
        raise HardwareError("配置超出 NetLab IPC 容量，请减少配置条目")
    return result


def parse_xml(payload: bytes):
    if len(payload) > 256 * 1024 or b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise HardwareError("不接受超大 XML 或 XML 实体声明")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise HardwareError("NetLab 返回了无效 XML") from exc
    for node in root.iter():
        node.tag = node.tag.rsplit("}", 1)[-1]
    return root


def decode_configuration(payload: bytes) -> SwitchConfiguration:
    root = parse_xml(payload)
    if root.tag != "netlab-config":
        raise HardwareError("NetLab 配置根节点不正确")
    intent = root.findtext("./chassis/fm10k-panel/intent")
    if intent is None:
        raise HardwareError("configd 尚未初始化本板的固定槽位配置；请先执行板卡预检与初始化")
    try:
        return SwitchConfiguration.model_validate_json(intent)
    except ValueError as error:
        raise HardwareError("configd 中的面板配置投影无效") from error
