"""Output formatters for LLDP and spanning-tree show commands."""
import xml.etree.ElementTree as ET
from typing import Optional

from output_common import _age_text, _port_to_ifname, _text


def format_lldp_neighbors(xml: str) -> str:
    """Format show lldp neighbors output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["Local Interface    Parent Interface    Chassis Id           Port info       System Name"]
    count = 0
    for nb in root.findall("neighbor"):
        local = _text(nb, "local-interface") or "-"
        chassis = _text(nb, "chassis-id") or "-"
        port = _text(nb, "port-id") or "-"
        sysname = _text(nb, "sys-name") or "-"
        lines.append(f"{local:<18} {'-':<19} {chassis:<20} {port:<15} {sysname}")
        count += 1
    if count == 0:
        return "LLDP neighbors: none"
    return "\n".join(lines)


def format_lldp_neighbors_detail(xml: str) -> str:
    """Format show lldp neighbors detail output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["LLDP neighbor information:"]
    count = 0
    for nb in root.findall("neighbor"):
        count += 1
        lines.extend([
            f"Local interface    : {_text(nb, 'local-interface') or '-'}",
            f"Chassis ID         : {_text(nb, 'chassis-id') or '-'}",
            f"Chassis ID subtype : {_text(nb, 'chassis-id-subtype') or '-'}",
            f"Port ID            : {_text(nb, 'port-id') or '-'}",
            f"Port ID subtype    : {_text(nb, 'port-id-subtype') or '-'}",
            f"Port description   : {_text(nb, 'port-description') or '-'}",
            f"System name        : {_text(nb, 'sys-name') or '-'}",
            f"System description : {_text(nb, 'sys-description') or '-'}",
            f"Capabilities       : {_text(nb, 'system-capabilities') or '-'}",
            f"Enabled caps       : {_text(nb, 'enabled-capabilities') or '-'}",
            f"Management address : {_text(nb, 'management-address') or '-'}",
            f"Age                : {_age_text(_text(nb, 'age') or '-1')}",
            f"Time remaining     : {_age_text(_text(nb, 'time-remaining') or '-1')}",
            "",
        ])
    if count == 0:
        return "LLDP neighbors: none"
    return "\n".join(lines).rstrip()


def format_lldp_statistics(xml: str) -> str:
    """Format show lldp statistics output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    def attr(name, default="0"):
        return root.attrib.get(name, default)

    lines = [
        "LLDP statistics:",
        f"  Neighbors      : {attr('neighbors')}",
        f"  TX frames      : {attr('tx-frames')}",
        f"  TX failures    : {attr('tx-failures')}",
        f"  RX frames      : {attr('rx-frames')}",
        f"  RX valid       : {attr('rx-valid')}",
        f"  RX dropped     : {attr('rx-dropped')}",
        f"  Aged out       : {attr('aged-out')}",
        f"  Packetd resets : {attr('packetd-reconnects')}",
        f"  Last RX age    : {_age_text(attr('last-rx-age', '-1'))}",
        f"  Last TX age    : {_age_text(attr('last-tx-age', '-1'))}",
        f"  Disabled       : {attr('disabled', 'false')}",
        f"  TX interval    : {attr('tx-interval')}s",
        f"  Hold multiplier: {attr('hold-multiplier')}",
        f"  Advertised TTL : {attr('ttl')}s",
    ]
    return "\n".join(lines)


def format_lldp_local(xml: str) -> str:
    """Format show lldp local-information output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    return "\n".join([
        "LLDP local information:",
        f"  Disabled        : {root.attrib.get('disabled', 'false')}",
        f"  TX interval     : {root.attrib.get('tx-interval', '-')}s",
        f"  Hold multiplier : {root.attrib.get('hold-multiplier', '-')}",
        f"  Advertised TTL  : {root.attrib.get('ttl', '-')}s",
        f"  System name     : {root.attrib.get('system-name', '-') or '-'}",
        f"  System desc     : {root.attrib.get('system-description', '-') or '-'}",
        f"  Management addr : {root.attrib.get('management-address', '-') or '-'}",
    ])


def format_lldp_interfaces(xml: str) -> str:
    """Format show lldp interfaces output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = [
        "LLDP interfaces:",
        "Interface       Admin     Link   Neighbors  RX     TX     Last-RX Last-TX",
    ]
    count = 0
    for iface in root.findall("interface"):
        count += 1
        name = iface.attrib.get("name", "-")
        admin = iface.attrib.get("admin", "-")
        link = iface.attrib.get("link", "-")
        neighbors = iface.attrib.get("neighbors", "0")
        rx = iface.attrib.get("rx-frames", "0")
        tx = iface.attrib.get("tx-frames", "0")
        last_rx = _age_text(iface.attrib.get("last-rx-age", "-1"))
        last_tx = _age_text(iface.attrib.get("last-tx-age", "-1"))
        lines.append(
            f"{name:<15} {admin:<9} {link:<6} {neighbors:>9} "
            f"{rx:>6} {tx:>6} {last_rx:>7} {last_tx:>7}")
    if count == 0:
        lines.append("(no LLDP interfaces)")
    return "\n".join(lines)


def format_spanning_tree(xml: str, interface_filter: Optional[str] = None) -> str:
    """Format switchd hardware STP table output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    entries = []
    for entry in root.findall("stp-entry"):
        port = entry.attrib.get("port", "")
        ifname = _port_to_ifname(port)
        if interface_filter and ifname != interface_filter:
            continue
        entries.append((entry.attrib.get("vlan", "-"),
                        ifname,
                        entry.attrib.get("state", "?")))

    title = "Spanning tree hardware table"
    if interface_filter:
        title += f" for {interface_filter}"
    if not entries:
        return title + ": no entries"

    lines = [title + ":", "VLAN      Interface       State"]
    for vlan, ifname, state in entries:
        lines.append(f"{vlan:<9} {ifname:<15} {state}")
    lines.append("")
    lines.append("Note: this is the hardware forwarding table; use show spanning-tree for protocol state.")
    return "\n".join(lines)


def _parse_stp_hw_states(xml: Optional[str]) -> dict:
    states = {}
    if not xml:
        return states
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return states

    for entry in root.findall("stp-entry"):
        ifname = _port_to_ifname(entry.attrib.get("port", ""))
        vlan = entry.attrib.get("vlan", "")
        state = entry.attrib.get("state", "")
        if not ifname or ifname == "unknown" or not vlan or not state:
            continue
        states.setdefault(ifname, []).append((int(vlan), state))
    for ifname in states:
        states[ifname].sort(key=lambda item: item[0])
    return states


def _short_stp_state(state: str) -> str:
    if state == "FORWARDING":
        return "FWD"
    if state == "DISCARDING":
        return "DISC"
    if state == "LEARNING":
        return "LRN"
    return state or "?"


def _format_hw_vlan_states(entries) -> str:
    if not entries:
        return "-"
    rendered = [f"{vlan}:{_short_stp_state(state)}"
                for vlan, state in entries]
    text = ",".join(rendered)
    if len(text) <= 22:
        return text
    return ",".join(rendered[:3]) + ",..."


def _if_sort_key(ifname: str):
    parts = []
    for token in ifname.replace("-", "/").split("/"):
        try:
            parts.append((0, int(token)))
        except ValueError:
            parts.append((1, token))
    return parts


def _format_stp_timer_ticks(ticks: str, valid: str) -> str:
    if valid != "true":
        return "-"
    try:
        value = int(ticks)
    except (TypeError, ValueError):
        return "-"
    if value < 0:
        return "-"
    if value % 256 == 0:
        return f"{value // 256}s"
    return f"{value / 256.0:.2f}s"


def _format_stp_peer_timers(port) -> str:
    valid = port.attrib.get("peer-timers-valid", "false")
    if valid != "true":
        return "-"
    msg = _format_stp_timer_ticks(
        port.attrib.get("peer-message-age-ticks", "-1"), valid)
    hello = _format_stp_timer_ticks(
        port.attrib.get("peer-hello-time-ticks", "-1"), valid)
    max_age = _format_stp_timer_ticks(
        port.attrib.get("peer-max-age-ticks", "-1"), valid)
    fwd = _format_stp_timer_ticks(
        port.attrib.get("peer-forward-delay-ticks", "-1"), valid)
    return f"{msg}/{hello}/{max_age}/{fwd}"


def format_spanning_tree_state(xml: str, interface_filter: Optional[str] = None,
                               hw_xml: Optional[str] = None) -> str:
    """Format stpd RSTP operational state."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml
    hw_states = _parse_stp_hw_states(hw_xml)

    ports = []
    for port in root.findall("port"):
        iface = port.attrib.get("interface", "-")
        if interface_filter and iface != interface_filter:
            continue
        ports.append(port)

    protocol = root.attrib.get('protocol', 'rstp').upper()
    root_port = root.attrib.get("root-port", "0")
    root_port_text = "-" if root_port in ("", "0") else _port_to_ifname(root_port)
    lines = [
        "Spanning tree status:",
        f"  Protocol : {protocol}",
        f"  Bridge ID: {root.attrib.get('bridge-id', '-')}",
        f"  Root ID  : {root.attrib.get('root-id', '-')}",
        f"  Root port: {root_port_text}",
        f"  Root cost: {root.attrib.get('root-path-cost', '0')}",
        f"  Timers   : hello {root.attrib.get('hello-time', '2')}s, "
        f"max age {root.attrib.get('max-age', '20')}s, "
        f"forward delay {root.attrib.get('forward-delay', '15')}s",
    ]
    if protocol == "MSTP":
        lines.extend([
            f"  MST name : {root.attrib.get('mst-name', '-') or '-'}",
            f"  MST rev  : {root.attrib.get('mst-revision', '0')}",
            f"  MST digest: {root.attrib.get('mst-digest', '-') or '-'}",
            f"  MST hops : {root.attrib.get('mst-max-hops', '20')}",
            f"  MSTIs    : {root.attrib.get('mst-instances', '0')}",
        ])
        instances = root.findall("mst-instance")
        if instances:
            lines.extend(["", "MSTI    Priority  Root port       Root cost  Hops  VLANs"])
            for inst in instances:
                root_port_attr = inst.attrib.get("root-port", "0")
                root_port_i = "-" if root_port_attr in ("", "0") else _port_to_ifname(root_port_attr)
                lines.append(
                    f"{inst.attrib.get('id', '-'):<7} "
                    f"{inst.attrib.get('bridge-priority', '-'):<9} "
                    f"{root_port_i:<15} "
                    f"{inst.attrib.get('root-path-cost', '0'):>9}  "
                    f"{inst.attrib.get('remaining-hops', '-'):>4}  "
                    f"{inst.attrib.get('vlans', '-')}")
        mst_ports = root.findall("mst-port")
        if mst_ports:
            lines.extend(["", "MSTI port states:",
                          "Interface       MSTI    Role        State       Cost       Pri  PortID  PeerRole    RX  Prop/Agree  TX Prop/Agree Last-RX Last-TX Hops SyncReset Sync       Reset reason"])
            for port in mst_ports:
                prop = port.attrib.get("proposals", "0")
                agree = port.attrib.get("agreements", "0")
                tx_prop = port.attrib.get("tx-proposals", "0")
                tx_agree = port.attrib.get("tx-agreements", "0")
                sync = "pending" if port.attrib.get("agreement-pending") == "true" else "-"
                reset_reason = port.attrib.get("sync-reset-reason", "-") or "-"
                lines.append(
                    f"{port.attrib.get('interface', '-'):<15} "
                    f"{port.attrib.get('msti', '-'):>4}    "
                    f"{port.attrib.get('role', '-'):<11} "
                    f"{port.attrib.get('state', '-'):<11} "
                    f"{port.attrib.get('path-cost', '-'):>8} "
                    f"{port.attrib.get('port-priority', '-'):>4} "
                    f"{port.attrib.get('port-id', '-'):<7} "
                    f"{port.attrib.get('peer-role', '-'):<10} "
                    f"{port.attrib.get('rx-bpdus', '0'):>6} "
                    f"{prop:>4}/{agree:<5} "
                    f"{tx_prop:>7}/{tx_agree:<5} "
                    f"{_age_text(port.attrib.get('last-rx-age', '-1')):>7} "
                    f"{_age_text(port.attrib.get('last-tx-age', '-1')):>7} "
                    f"{port.attrib.get('remaining-hops', '-'):>4} "
                    f"{port.attrib.get('sync-resets', '0'):>9} "
                    f"{sync:<10} "
                    f"{reset_reason}")
    lines.extend([
        "",
        "Interface       Role        State       Cost       Pri  PortID  HW-VLANs               RX     TX     Last-RX Last-TX Guard           Loop",
    ])
    if not ports:
        fallback_states = hw_states
        if interface_filter:
            fallback_states = {}
            if hw_states.get(interface_filter):
                fallback_states[interface_filter] = hw_states[interface_filter]
        if not fallback_states:
            lines.append(f"(no {protocol} interfaces configured)")
            return "\n".join(lines)
        for iface in sorted(fallback_states, key=_if_sort_key):
            hw_vlan_state = _format_hw_vlan_states(fallback_states[iface])
            lines.append(
                f"{iface:<15} {'-':<11} {'hardware':<11} "
                f"{'-':>8} {'-':>4} {'-':<7} "
                f"{hw_vlan_state:<22} {'-':>6} {'-':>6} "
                f"{'-':>7} {'-':>7} {'-':<15} {'-'}")
        lines.append("")
        lines.append(
            f"Note: no {protocol} interfaces are configured; HW-VLANs is the effective per-VLAN hardware forwarding state.")
        return "\n".join(lines)
    if not any(port.attrib.get("enabled") == "true" for port in ports):
        lines.append(f"(no {protocol} interfaces configured) showing observed BPDU history")

    for port in ports:
        iface = port.attrib.get("interface", "-")
        role = port.attrib.get("role", "-")
        state = port.attrib.get("state", "-")
        rx = port.attrib.get("rx-bpdus", "0")
        tx = port.attrib.get("tx-bpdus", "0")
        hw_vlan_state = _format_hw_vlan_states(hw_states.get(iface, []))
        last_rx = _age_text(port.attrib.get("last-rx-age", "-1"))
        last_tx = _age_text(port.attrib.get("last-tx-age", "-1"))
        guard = port.attrib.get("guard-state", "off")
        block_reason = port.attrib.get("block-reason", "none")
        if port.attrib.get("protocol-blocked") == "true" and block_reason != "none":
            guard = block_reason
        peer = port.attrib.get("loop-peer-port", "0")
        loop = "-" if peer in ("", "0") else _port_to_ifname(peer)
        lines.append(
            f"{iface:<15} {role:<11} {state:<11} "
            f"{port.attrib.get('path-cost', '-'):>8} "
            f"{port.attrib.get('port-priority', '-'):>4} "
            f"{port.attrib.get('port-id', '-'):<7} "
            f"{hw_vlan_state:<22} {rx:>6} {tx:>6} "
            f"{last_rx:>7} {last_tx:>7} {guard:<15} {loop}")
    if hw_states:
        lines.append("")
        lines.append("Note: Role/State is the CIST protocol view; HW-VLANs is the effective per-VLAN hardware forwarding state.")
    return "\n".join(lines)


def format_stp_monitor(xml: str) -> str:
    """Format BPDU monitor state from stpd."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    ports = root.findall("port")
    lines = [
        "Spanning tree BPDU monitor:",
        f"  Total BPDUs       : {root.attrib.get('total-bpdus', '0')}",
        f"  Topology changes  : {root.attrib.get('topology-change-bpdus', '0')}",
        f"  Proposals/Agree   : {root.attrib.get('proposals', '0')}/"
        f"{root.attrib.get('agreements', '0')}",
        f"  MAC flushes       : {root.attrib.get('mac-flushes', '0')}",
        f"  TX BPDUs          : {root.attrib.get('tx-bpdus', '0')}",
        f"  TX Proposal/Agree : {root.attrib.get('tx-proposals', '0')}/"
        f"{root.attrib.get('tx-agreements', '0')}",
        f"  TX TC BPDUs       : {root.attrib.get('tx-tc', '0')}",
        f"  TX failures       : {root.attrib.get('tx-failures', '0')}",
        f"  Sync resets       : {root.attrib.get('sync-resets', '0')}",
        f"  Malformed BPDUs   : {root.attrib.get('malformed-bpdus', '0')}",
        f"  Packetd resets    : {root.attrib.get('packetd-reconnects', '0')}",
        f"  Last BPDU age     : {_age_text(root.attrib.get('last-rx-age', '-1'))}",
        f"  Last MAC flush    : {_age_text(root.attrib.get('last-mac-flush-age', '-1'))}",
        f"  Last flush scope  : {root.attrib.get('last-mac-flush-scope', '-')}",
        f"  Last flush reason : {root.attrib.get('last-mac-flush-reason', '-')}",
    ]
    if not ports:
        lines.append("")
        lines.append("Interface       RX     TX   Prop Agree   TC  Flush Reset Last-RX Last-TX Guard           Protocol Peer timers       Root ID                    Reset reason")
        lines.append("(no BPDUs observed)")
        return "\n".join(lines)

    lines.append("")
    lines.append("Interface       RX     TX   Prop Agree   TC  Flush Reset Last-RX Last-TX Guard           Protocol Peer timers       Root ID                    Reset reason")
    for port in ports:
        iface = port.attrib.get("interface", "-")
        bpdus = port.attrib.get("rx-bpdus", "0")
        tx_bpdus = port.attrib.get("tx-bpdus", "0")
        proposal = port.attrib.get("proposals", "0")
        agreement = port.attrib.get("agreements", "0")
        tc = port.attrib.get("topology-change-bpdus", "0")
        flushes = port.attrib.get("mac-flushes", "0")
        resets = port.attrib.get("sync-resets", "0")
        last = _age_text(port.attrib.get("last-age", "-1"))
        last_tx = _age_text(port.attrib.get("last-tx-age", "-1"))
        guard = port.attrib.get("guard-state", "off")
        block_reason = port.attrib.get("block-reason", "none")
        if port.attrib.get("protocol-blocked") == "true" and block_reason != "none":
            guard = block_reason
        proto = port.attrib.get("protocol", "unknown")
        peer_timers = _format_stp_peer_timers(port)
        root_id = port.attrib.get("root-id", "-")
        reset_reason = port.attrib.get("sync-reset-reason", "-") or "-"
        lines.append(f"{iface:<15} {bpdus:>6} {tx_bpdus:>6} {proposal:>6} "
                     f"{agreement:>5} {tc:>4} {flushes:>6} "
                     f"{resets:>5} {last:>7} {last_tx:>7} "
                     f"{guard:<15} {proto:<8} {peer_timers:<17} "
                     f"{root_id:<26} {reset_reason}")
    lines.append("")
    lines.append(
        "Note: BPDU guard blocks configured edge ports; root-protection prevents "
        "protected ports from becoming root ports; loop-protection keeps stale "
        "alternate paths blocked. RSTP and MSTP share the CIST guard path; "
        "MSTI interoperability should be verified with live peers.")
    return "\n".join(lines)


def format_spanning_tree_capabilities() -> str:
    """Describe the supported RSTP/MSTP control-plane and data-plane scope."""
    rows = [
        ("RSTP CIST", "config", "yes", "BPDU/state/hardware STP gate"),
        ("MST region/digest", "config", "yes", "Nexus reconfigure gate"),
        ("MSTI VLAN mapping", "config", "yes", "per-VLAN hardware STP gate"),
        ("MSTI BPDU records", "runtime", "yes", "show spanning-tree"),
        ("MSTI remaining hops", "runtime", "yes", "M-record validity gate"),
        ("MSTP max-hops", "config", "yes", "CIST/MSTI remaining-hops budget"),
        ("MSTP port vector", "config", "yes", "path-cost/port-priority"),
        ("per-MSTI port vector", "config", "yes", "instance interface path-cost/port-priority"),
        ("MSTI peer role decode", "runtime", "yes", "M-record role-aware selection"),
        ("Peer BPDU timers", "runtime", "yes", "show spanning-tree statistics"),
        ("MSTI proposal/agreement", "runtime", "yes", "independent sync TX gate"),
        ("MSTI sync reset epoch", "runtime", "yes", "root/role/timeout invalidates old agreement"),
        ("MSTI agreement timeout", "runtime", "yes", "stale peer agreement re-enters sync"),
        ("multi-MSTI traffic", "runtime", "yes", "TRex MSTP long-soak"),
        ("802.1s sync edge cases", "validation", "n/a", "timer/topology soak"),
        ("PVST/Rapid-PVST", "deferred", "no", "rejected"),
        ("additional topologies", "validation", "yes", "P1/overnight gate"),
    ]
    lines = [
        "Spanning-tree capabilities:",
        "Feature                    Config      Hardware  Validation",
    ]
    for feature, config, hardware, validation in rows:
        lines.append(f"{feature:<26} {config:<11} {hardware:<9} {validation}")
    lines.extend([
        "",
        "Notes:",
        "  MSTP uses IEEE MST/CIST behavior. Cisco PVST+/Rapid-PVST private compatibility remains intentionally closed.",
        "  Full 802.1s promotion still depends on peer timer edge cases, alternate topology shapes, and overnight traffic soak.",
        "  Use the P1 or overnight L2 conformance gate before treating a new topology as production-ready.",
    ])
    return "\n".join(lines)


def format_lacp(xml: str) -> str:
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception:
        return xml

    lines = ["LACP interfaces:"]
    lags = root.findall("lag")
    if not lags:
        lines.append("  no LAGs configured")
    for lag in lags:
        name = lag.attrib.get("name", "ae?")
        lag_id = lag.attrib.get("id", "-")
        lport = lag.attrib.get("logical-port", "-")
        status = lag.attrib.get("status", "unknown")
        actor = lag.attrib.get("actor-system", "-")
        key = lag.attrib.get("actor-key", "-")
        mode = lag.attrib.get("mode", "-")
        periodic = lag.attrib.get("periodic", "-")
        sys_prio = lag.attrib.get("actor-system-priority", "-")
        port_prio = lag.attrib.get("actor-port-priority", "-")
        min_links = lag.attrib.get("minimum-links", lag.attrib.get("min-links", "1"))
        up_members = lag.attrib.get("up-members", "0")
        configured_members = lag.attrib.get("configured-members", "0")
        lines.append(
            f"  {name}  status={status} lag-id={lag_id} logical-port={lport} "
            f"actor={actor} key={key} mode={mode} periodic={periodic} "
            f"sys-priority={sys_prio} port-priority={port_prio} min-links={min_links} "
            f"members={up_members}/{configured_members}")
        members = lag.findall("member")
        if not members:
            lines.append("    no members")
            continue
        for member in members:
            iface = member.attrib.get("interface", "?")
            mstatus = member.attrib.get("status", "unknown")
            partner = member.attrib.get("partner-system", "00:00:00:00:00:00")
            partner_system_priority = member.attrib.get("partner-system-priority", "-")
            partner_key = member.attrib.get("partner-key", "-")
            sync = member.attrib.get("sync", "false")
            collecting = member.attrib.get("collecting", "false")
            distributing = member.attrib.get("distributing", "false")
            link = member.attrib.get("link", "-")
            hw_attached = member.attrib.get("hw-attached", "-")
            partner_consistent = member.attrib.get("partner-consistent", "-")
            partner_aggregation = member.attrib.get("partner-aggregation", "-")
            selected = member.attrib.get("selected", "-")
            partner_group_members = member.attrib.get("partner-group-members", "-")
            actor_consistent = member.attrib.get("actor-consistent", "-")
            view_system = member.attrib.get("partner-view-system", "-")
            view_key = member.attrib.get("partner-view-key", "-")
            view_port = member.attrib.get("partner-view-port", "-")
            port_prio = member.attrib.get("actor-port-priority", "-")
            rx = member.attrib.get("rx-pdus", "0")
            tx = member.attrib.get("tx-pdus", "0")
            age = member.attrib.get("last-rx-age", "-1")
            lines.append(
                f"    {iface:<12s} {mstatus:<5s} partner={partner} "
                f"partner-priority={partner_system_priority} key={partner_key} "
                f"link={link} hw-attached={hw_attached} "
                f"partner-consistent={partner_consistent} "
                f"partner-aggregation={partner_aggregation} "
                f"selected={selected} partner-group-members={partner_group_members} "
                f"actor-consistent={actor_consistent} "
                f"partner-view={view_system}/{view_key}/{view_port} "
                f"port-priority={port_prio} "
                f"sync={sync} collecting={collecting} distributing={distributing} "
                f"rx={rx} tx={tx} age={age}s")
    return "\n".join(lines)
