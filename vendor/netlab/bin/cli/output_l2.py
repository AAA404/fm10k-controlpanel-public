"""Output formatters for VLAN and Ethernet switching show commands."""
import struct
import textwrap
import xml.etree.ElementTree as ET
from typing import List

from output_common import (_age_text, _is_user_visible_mac,
                           _port_to_ifname, _text)
from public_capabilities import (GENERAL_ACL_INDEPENDENT,
                                 public_capability_enabled)


_MAC_SNAPSHOT_MAGIC = 0x4E4D4143
_MAC_SNAPSHOT_VERSION = 1
_MAC_SNAPSHOT_COMPLETE = 1
_MAC_SNAPSHOT_MAX_ENTRIES = 16384
_MAC_SNAPSHOT_HEADER = struct.Struct("!IHHQIII")
_MAC_SNAPSHOT_ENTRY = struct.Struct("!HHb6sI")
_MAC_SNAPSHOT_STATIC = 1 << 31


def _vlan_rows(root):
    rows = []
    for vlan in root.findall("vlan"):
        rows.append({
            "name": _text(vlan, "name"),
            "vid": _text(vlan, "vlan-id"),
            "state": _text(vlan, "state"),
            "interfaces": _text(vlan, "interfaces") or "-",
        })
    return rows


def _format_vlan_detail(row, extensive: bool = False) -> List[str]:
    interfaces = row["interfaces"]
    members = [] if interfaces == "-" else [
        item for item in interfaces.split(",") if item
    ]
    lines = [
        f"VLAN: {row['name']}",
        f"  802.1Q Tag      : {row['vid']}",
        f"  Hardware state  : {row['state']}",
        f"  Interfaces      : {interfaces}",
    ]
    if extensive:
        lines.extend([
            f"  Interface count : {len(members)}",
            "  Member detail:",
        ])
        if members:
            for member in members:
                lines.append(f"    {member}")
        else:
            lines.append("    -")
    return lines


def format_vlans(xml: str, style: str = "brief", vlan_filter: str = "") -> str:
    """Format show vlans output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    rows = _vlan_rows(root)
    if vlan_filter:
        rows = [row for row in rows
                if row["name"] == vlan_filter or row["vid"] == vlan_filter]
        if not rows:
            return f"VLAN {vlan_filter}: not found"

    if style in ("detail", "extensive"):
        rendered = []
        for row in rows:
            if rendered:
                rendered.append("")
            rendered.extend(_format_vlan_detail(
                row, extensive=(style == "extensive")))
        return "\n".join(rendered) if rendered else "VLANs: none"

    lines = ["Name        Tag   State   Interfaces"]
    for row in rows:
        lines.append(
            f"{row['name']:<11} {row['vid']:<5} "
            f"{row['state']:<7} {row['interfaces']}")
    return "\n".join(lines)


def format_eth_sw_interfaces(xml: str) -> str:
    """Format show ethernet-switching interfaces output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["Interface     State  VLAN members   Mode    HW sync"]
    for iface in root.findall("interface"):
        name = _text(iface, "name")
        mode = _text(iface, "mode")
        state = _text(iface, "state")
        hwsync = _text(iface, "hw-sync")
        member = _text(iface, "vlan-member") or "-"
        lines.append(f"{name:<13} {state:<6} {member:<14} {mode:<7} {hwsync}")
    return "\n".join(lines)


def format_mac_snapshot(payload: bytes) -> str:
    """Format the complete, versioned switchd MAC snapshot."""
    if len(payload) < _MAC_SNAPSHOT_HEADER.size:
        return "error: invalid MAC snapshot: truncated header"
    try:
        (magic, version, entry_size, _generation, total, count,
         flags) = _MAC_SNAPSHOT_HEADER.unpack_from(payload)
    except struct.error:
        return "error: invalid MAC snapshot: malformed header"
    if magic != _MAC_SNAPSHOT_MAGIC or version != _MAC_SNAPSHOT_VERSION:
        return "error: invalid MAC snapshot: unsupported protocol"
    if entry_size != _MAC_SNAPSHOT_ENTRY.size:
        return "error: invalid MAC snapshot: unsupported entry size"
    if flags & ~_MAC_SNAPSHOT_COMPLETE:
        return "error: invalid MAC snapshot: unknown flags"
    if not flags & _MAC_SNAPSHOT_COMPLETE or total != count:
        return "error: incomplete MAC snapshot"
    if count > _MAC_SNAPSHOT_MAX_ENTRIES:
        return "error: invalid MAC snapshot: entry count exceeds capacity"
    expected = _MAC_SNAPSHOT_HEADER.size + count * entry_size
    if len(payload) != expected:
        return "error: invalid MAC snapshot: payload length mismatch"

    entries = []
    offset = _MAC_SNAPSHOT_HEADER.size
    for _ in range(count):
        vlan, port, ae_id, mac_raw, age_flags = _MAC_SNAPSHOT_ENTRY.unpack_from(
            payload, offset)
        offset += entry_size
        if not 1 <= vlan <= 4094 or port == 0 or ae_id < -1:
            return "error: invalid MAC snapshot: malformed entry"
        mac = ":".join(f"{octet:02x}" for octet in mac_raw)
        typ = "static" if age_flags & _MAC_SNAPSHOT_STATIC else "dynamic"
        age = age_flags & ~_MAC_SNAPSHOT_STATIC
        ifname = f"ae{ae_id}" if ae_id >= 0 else _port_to_ifname(str(port))
        if _is_user_visible_mac(mac, typ, str(port), ifname):
            entries.append((vlan, mac, typ, age, ifname))

    lines = [
        "Ethernet switching table :",
        "VLAN              MAC address        Type      Age  Interfaces",
    ]
    for vlan, mac, typ, age, ifname in entries:
        age_text = "-" if typ == "static" else str(age)
        lines.append(
            f"{vlan:<17} {mac:<18} {typ:<8} {age_text:<4} {ifname}")
    lines.append(f"\nTotal learned addresses : {len(entries)}")
    return "\n".join(lines)


def format_mac_move(xml: str) -> str:
    """Format show ethernet-switching mac-move output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["MAC move events:"]
    policy = root.find("mac-move-policy")
    if policy is not None and policy.attrib.get("configured") == "true":
        lines.append(
            "  Dampening: threshold={threshold} window={window}s action={action}".format(
                threshold=policy.attrib.get("threshold", "-"),
                window=policy.attrib.get("window", "-"),
                action=policy.attrib.get("action", "alarm")))
    else:
        lines.append("  Dampening: disabled")

    moves = root.findall("move")
    if not moves:
        lines.append("(none)")
        return "\n".join(lines)

    lines.append(
        "VLAN      MAC address        From            To              Moves Window  Last move  Dampened")
    for move in moves:
        vlan = move.attrib.get("vlan", "-")
        mac = move.attrib.get("mac", "-")
        old_if = move.attrib.get("from", "-")
        new_if = move.attrib.get("to", "-")
        count = move.attrib.get("count", "0")
        window_count = move.attrib.get("window-count", "0")
        age = _age_text(move.attrib.get("last-age", "-1"))
        dampened = "yes" if move.attrib.get("dampened") == "true" else "no"
        if dampened == "yes":
            dampened += f"({move.attrib.get('dampened-if', '-')})"
        lines.append(
            f"{vlan:<9} {mac:<18} {old_if:<15} {new_if:<15} "
            f"{count:>5} {window_count:>6}  {age:<9} {dampened}")
    return "\n".join(lines)


def format_secure_access_port(xml: str) -> str:
    """Format show ethernet-switching secure-access-port output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["Secure access port status:"]
    lines.append("Interface       Dynamic MACs  Limit     Action    Status")
    count = 0
    for iface in root.findall("interface"):
        configured = iface.attrib.get("configured", "false") == "true"
        dynamic = iface.attrib.get("dynamic", "0")
        limit = iface.attrib.get("limit", "-")
        action = iface.attrib.get("action", "alarm")
        status = iface.attrib.get("status", "ok")
        if not configured and dynamic == "0":
            continue
        count += 1
        extra = ""
        if iface.attrib.get("enforced", "false") == "true":
            age_value = iface.attrib.get("last-drop-age", "-1")
            if age_value in ("", "-1"):
                age_value = iface.attrib.get("last-shutdown-age", "-1")
            age = _age_text(age_value)
            reason = iface.attrib.get("reason", "")
            extra = f" ({age}"
            if reason:
                extra += f", {reason}"
            extra += ")"
        lines.append(f"{iface.attrib.get('name', '-'):<15} {dynamic:>12}  "
                     f"{limit:<8} {action:<8} {status}{extra}")
    if count == 0:
        lines.append("(no configured limits or learned dynamic MACs)")
    return "\n".join(lines)


def _format_security_vlan_list(root, container_name: str) -> str:
    names = [v.attrib.get("name", "-") for v in root.findall(container_name + "/vlan")]
    return ", ".join(names) if names else "-"


def _format_security_trusted_interfaces(root, container_name: str) -> str:
    names = [i.attrib.get("name", "-") for i in root.findall(container_name + "/interface")
             if i.attrib.get("trusted") == "true"]
    return ", ".join(names) if names else "-"


def _format_dhcp_bindings(root) -> List[str]:
    rows = []
    for binding in root.findall("dhcp-snooping/binding"):
        rows.append((
            binding.attrib.get("vlan", "-"),
            binding.attrib.get("mac", "-"),
            binding.attrib.get("ip", "-"),
            binding.attrib.get("interface", "-"),
            binding.attrib.get("source", "static"),
        ))
    if not rows:
        return ["  Bindings          : -"]
    lines = ["  Bindings:"]
    lines.append("    VLAN   MAC address        IP address       Interface     Source")
    for vlan, mac, ip, ifname, source in rows:
        lines.append(f"    {vlan:<6} {mac:<18} {ip:<16} {ifname:<13} {source}")
    return lines


def format_dhcp_snooping(xml: str) -> str:
    """Format show ethernet-switching dhcp-snooping output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["DHCP snooping status:"]
    lines.append(f"  VLANs             : {_format_security_vlan_list(root, 'dhcp-snooping')}")
    lines.append(f"  Trusted interfaces: {_format_security_trusted_interfaces(root, 'dhcp-snooping')}")
    lines.extend(_format_dhcp_bindings(root))
    lines.append("  Binding source    : static config (dynamic ACK learning not enabled)")
    lines.append("  Enforcement       : hardware drop of DHCP server replies on untrusted ports")
    return "\n".join(lines)


def format_arp_inspection(xml: str) -> str:
    """Format show ethernet-switching arp-inspection output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["Dynamic ARP inspection status:"]
    lines.append(f"  VLANs             : {_format_security_vlan_list(root, 'arp-inspection')}")
    lines.append(f"  Trusted interfaces: {_format_security_trusted_interfaces(root, 'arp-inspection')}")
    lines.extend(_format_dhcp_bindings(root))
    lines.append("  Binding source    : DHCP snooping static bindings")
    lines.append("  Enforcement       : hardware binding permit plus untrusted ARP deny")
    return "\n".join(lines)


def _format_l2_filter(xml: str, container: str, title: str, empty: str) -> str:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = [title]
    lines.append(
        "Term                 VLAN      Interface       Match            MAC                "
        "Action  Enforcement          Counter       Packets       Octets")
    rows = root.findall(f"{container}/term")
    if not rows:
        lines.append(empty)
        return "\n".join(lines)
    for term in rows:
        match = term.attrib.get("match", "source-mac")
        mac = term.attrib.get("source-mac") or term.attrib.get("destination-mac", "-")
        counter_state = term.attrib.get("counter-state", "unavailable")
        packets = term.attrib.get("packets", "-")
        octets = term.attrib.get("octets", "-")
        lines.append(
            f"{term.attrib.get('name', '-'):<20} "
            f"{term.attrib.get('vlan', '-'):<9} "
            f"{term.attrib.get('interface', '-'):<15} "
            f"{match:<16} "
            f"{mac:<18} "
            f"{term.attrib.get('action', 'drop'):<7} "
            f"{term.attrib.get('enforcement', '-'):<20} "
            f"{counter_state:<12} "
            f"{packets:>10} "
            f"{octets:>12}")
    return "\n".join(lines)


def format_user_filter(xml: str) -> str:
    """Format show ethernet-switching user-filter output."""
    return _format_l2_filter(
        xml, "user-filter", "L2 user filter status:",
        "(no configured hardware user-filter terms)")


def format_ingress_acl(xml: str) -> str:
    """Format show ethernet-switching ingress-acl output."""
    return _format_l2_filter(
        xml, "ingress-acl", "L2 ingress ACL status:",
        "(no configured hardware ingress-acl terms)")


def format_acl_policer(xml: str) -> str:
    """Format ACL policer read-back output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["ACL policer status:"]
    lines.append(
        "Term                 Interface       Destination MAC    Rate Kbps    "
        "Burst bytes   Enforcement          Counter       Packets       Octets")
    rows = root.findall("acl-policer/term")
    if not rows:
        lines.append("(no configured firewall policer terms)")
        return "\n".join(lines)
    for term in rows:
        lines.append(
            f"{term.attrib.get('name', '-'):<20} "
            f"{term.attrib.get('interface', '-'):<15} "
            f"{term.attrib.get('destination-mac', '-'):<18} "
            f"{term.attrib.get('bandwidth', '-'):<12} "
            f"{term.attrib.get('burst-size', '-'):<13} "
            f"{term.attrib.get('enforcement', '-'):<20} "
            f"{term.attrib.get('counter-state', 'unavailable'):<12} "
            f"{term.attrib.get('packets', '-'):>10} "
            f"{term.attrib.get('octets', '-'):>12}")
    return "\n".join(lines)


def format_egress_acl(xml: str) -> str:
    """Format egress firewall read-back output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["L2 egress ACL status:"]
    lines.append(
        "Term                 Interface       Source MAC         Destination MAC    "
        "Action  Enforcement          Counter       Packets       Octets")
    rows = root.findall("egress-acl/term")
    if not rows:
        lines.append("(no configured firewall egress terms)")
        return "\n".join(lines)
    for term in rows:
        lines.append(
            f"{term.attrib.get('name', '-'):<20} "
            f"{term.attrib.get('interface', '-'):<15} "
            f"{(term.attrib.get('source-mac') or '-'):<18} "
            f"{(term.attrib.get('destination-mac') or '-'):<18} "
            f"{term.attrib.get('action', 'drop'):<7} "
            f"{term.attrib.get('enforcement', '-'):<20} "
            f"{term.attrib.get('counter-state', 'unavailable'):<12} "
            f"{term.attrib.get('packets', '-'):>10} "
            f"{term.attrib.get('octets', '-'):>12}")
    return "\n".join(lines)


def format_ingress_ipv4_acl(xml: str) -> str:
    """Format show ethernet-switching ingress-ipv4-acl output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["Ingress IPv4 ACL status:"]
    lines.append(
        "Term                 VLAN      Interface       Source          "
        "Destination     DSCP  ECN  Proto  SrcPort       DstPort       Flags Mask Action  Enforcement          "
        "Counter       Packets       Octets")
    rows = root.findall("ingress-ipv4-acl/term")
    if not rows:
        lines.append("(no configured hardware ingress-ipv4-acl terms)")
        return "\n".join(lines)
    for term in rows:
        counter_state = term.attrib.get("counter-state", "unavailable")
        packets = term.attrib.get("packets", "-")
        octets = term.attrib.get("octets", "-")
        source = term.attrib.get("source-prefix",
                                 term.attrib.get("source-ip", "-"))
        destination = term.attrib.get("destination-prefix",
                                      term.attrib.get("destination-ip", "-"))
        lines.append(
            f"{term.attrib.get('name', '-'):<20} "
            f"{term.attrib.get('vlan', '-'):<9} "
            f"{term.attrib.get('interface', '-'):<15} "
            f"{source:<15} "
            f"{destination:<15} "
            f"{term.attrib.get('dscp', '-'):<5} "
            f"{term.attrib.get('ecn', '-'):<4} "
            f"{term.attrib.get('protocol', '-'):<6} "
            f"{term.attrib.get('source-port-range', term.attrib.get('source-port', '-')):<13} "
            f"{term.attrib.get('destination-port-range', term.attrib.get('destination-port', '-')):<13} "
            f"{term.attrib.get('tcp-flags', '-'):<5} "
            f"{term.attrib.get('tcp-flags-mask', '-'):<4} "
            f"{term.attrib.get('action', 'drop'):<7} "
            f"{term.attrib.get('enforcement', '-'):<20} "
            f"{counter_state:<12} "
            f"{packets:>10} "
            f"{octets:>12}")
    return "\n".join(lines)


def _acl_counter_text(term) -> str:
    state = term.attrib.get("counter-state", "unavailable")
    packets = term.attrib.get("packets")
    if state == "installed" and packets is not None:
        return f"{state}:{packets}"
    return state


def _acl_match_summary(kind: str, term) -> str:
    if kind == "ingress-acl":
        match_kind = term.attrib.get("match", "source-mac")
        mac = term.attrib.get(match_kind, "-")
        return f"vlan={term.attrib.get('vlan', '-')} {match_kind}={mac}"
    if kind == "ingress-ipv4-acl":
        parts = []
        for attr in ("source-prefix", "source-ip",
                     "destination-prefix", "destination-ip",
                     "dscp", "ecn", "protocol",
                     "source-port-range", "source-port",
                     "destination-port-range", "destination-port",
                     "tcp-flags", "tcp-flags-mask"):
            value = term.attrib.get(attr)
            if value is not None:
                parts.append(f"{attr}={value}")
        return " ".join(parts) if parts else "ipv4-any"
    if kind == "acl-policer":
        return (
            f"dst-mac={term.attrib.get('destination-mac', '-')} "
            f"rate={term.attrib.get('bandwidth', '-')}kbps")
    if kind == "egress-acl":
        parts = []
        if term.attrib.get("source-mac"):
            parts.append(f"src-mac={term.attrib.get('source-mac')}")
        if term.attrib.get("destination-mac"):
            parts.append(f"dst-mac={term.attrib.get('destination-mac')}")
        return " ".join(parts) if parts else "mac-any"
    if kind == "acl-independent":
        parts = [f"family={term.attrib.get('family', '-')}"]
        for attr in ("vlan", "source-mac", "destination-mac",
                     "source-prefix", "source-ip",
                     "destination-prefix", "destination-ip",
                     "dscp", "protocol", "source-port-range",
                     "source-port", "destination-port-range",
                     "destination-port", "tcp-flags",
                     "tcp-flags-mask"):
            value = term.attrib.get(attr)
            if value is not None and value != "":
                parts.append(f"{attr}={value}")
        if term.attrib.get("bandwidth") not in (None, "", "0"):
            parts.append(f"rate={term.attrib.get('bandwidth')}kbps")
        return " ".join(parts)
    return "-"


def _acl_group_term_parts(term_name: str):
    """Decode the public ACL group alias stored as group.term."""
    if "." not in term_name:
        return "-", term_name
    group, term = term_name.split(".", 1)
    if not group or not term:
        return "-", term_name
    return group, term


def _acl_public_pipeline(owner: str) -> str:
    return {
        "ingress-acl": "ethernet-switching",
        "ingress-ipv4-acl": "inet",
        "acl-policer": "policer",
        "egress-acl": "egress",
        "acl-independent": "general",
    }.get(owner, owner or "-")


def format_acl_summary(xml: str) -> str:
    """Format a unified public ACL operational view."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    sections = [
        ("ingress-acl", "ingress", "flow-tcam"),
        ("ingress-ipv4-acl", "ingress", "flow-tcam"),
        ("acl-policer", "ingress", "acl-compiler"),
        ("egress-acl", "egress", "egress-acl"),
        ("acl-independent", "ingress", "general-acl-independent"),
    ]
    lines = ["Ethernet-switching ACL status:"]
    lines.append(
        "Pipeline          Dir      Interface       Group       Term                 "
        "Action   Counter          Enforcement          Match")
    count = 0
    for owner, direction, default_enforcement in sections:
        for term in root.findall(f"{owner}/term"):
            count += 1
            if owner == "acl-independent":
                group_name = term.attrib.get("group", "-")
                term_name = term.attrib.get("name", "-")
            else:
                group_name, term_name = _acl_group_term_parts(
                    term.attrib.get("name", "-"))
            action = term.attrib.get("action", "drop")
            if owner == "acl-policer":
                action = "police"
            lines.append(
                f"{_acl_public_pipeline(owner):<17} "
                f"{direction:<8} "
                f"{term.attrib.get('interface', '-'):<15} "
                f"{group_name:<11} "
                f"{term_name:<20} "
                f"{action:<8} "
                f"{_acl_counter_text(term):<16} "
                f"{term.attrib.get('enforcement', default_enforcement):<20} "
                f"{_acl_match_summary(owner, term)}")
    if count == 0:
        lines.append("(no configured hardware ACL terms)")
    lines.extend([
        "",
        "Notes:",
        "  This unified view covers ethernet-switching, inet, policer, egress, and general ACL pipelines.",
        "  The Group column preserves firewall filter <group> term <term> grouping.",
        "  Counter state is shown per pipeline; policer and general counters are per term, while egress counters are per physical egress port.",
        "  unavailable means the pipeline has no live counter read-back path yet.",
        "  general ACLs are currently ingress-only; egress independent groups remain deferred until equivalent gates exist.",
    ])
    return "\n".join(lines)


def _format_rate_controller(xml: str, title: str, empty: str) -> str:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = [title]
    lines.append("Interface       Rate Kbps    Burst bytes  Controller  Packets")
    count = 0
    for entry in root.findall("entry"):
        count += 1
        lines.append(
            f"{entry.attrib.get('interface', '-'):<15} "
            f"{entry.attrib.get('rate', '-'):>9}    "
            f"{entry.attrib.get('burst', '-'):>11}  "
            f"{entry.attrib.get('controller', '-'):>10}  "
            f"{entry.attrib.get('packets', '0'):>7}")
    if count == 0:
        lines.append(empty)
    return "\n".join(lines)


def format_storm_control(xml: str) -> str:
    """Format show ethernet-switching storm-control output."""
    return _format_rate_controller(
        xml, "Storm control status:",
        "(no configured hardware storm controllers)")


def format_ingress_rate_limit(xml: str) -> str:
    """Format show ethernet-switching ingress-rate-limit output."""
    return _format_rate_controller(
        xml, "Ingress rate limit status:",
        "(no configured hardware ingress-rate-limit controllers)")


def format_egress_rate_limit(xml: str) -> str:
    """Format show ethernet-switching egress-rate-limit output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    lines = ["Egress rate limit status:"]
    lines.append("Interface       Rate Kbps    Burst bytes  Group")
    count = 0
    for entry in root.findall("entry"):
        count += 1
        lines.append(
            f"{entry.attrib.get('interface', '-'):<15} "
            f"{entry.attrib.get('rate', '-'):>9}    "
            f"{entry.attrib.get('burst', '-'):>11}  "
            f"{entry.attrib.get('group', '-'):>5}")
    if count == 0:
        lines.append("(no configured hardware egress-rate-limit shapers)")
    return "\n".join(lines)


def format_class_of_service_interfaces(xml: str) -> str:
    """Format show class-of-service interfaces output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    interfaces = root.find("interfaces")
    rows = interfaces.findall("interface") if interfaces is not None else []
    lines = ["Class of service interfaces:"]
    lines.append("Interface       Trust         Default priority")
    if not rows:
        lines.append("(no hardware interface CoS state)")
        return "\n".join(lines)
    for iface in rows:
        lines.append(
            f"{iface.attrib.get('name', '-'):<15} "
            f"{iface.attrib.get('trust', '-'):<13} "
            f"{iface.attrib.get('default-priority', '-'):>5}")
    return "\n".join(lines)


def format_class_of_service_forwarding(xml: str) -> str:
    """Format show class-of-service forwarding output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    forwarding = root.find("forwarding")
    rows = (forwarding.findall("switch-priority")
            if forwarding is not None else [])
    lines = ["Class of service forwarding map:"]
    lines.append("Switch priority  Traffic class")
    if not rows:
        lines.append("(no hardware forwarding map state)")
        return "\n".join(lines)
    for row in rows:
        lines.append(
            f"{row.attrib.get('priority', '-'):>15}  "
            f"{row.attrib.get('traffic-class', '-'):>13}")
    return "\n".join(lines)


def format_class_of_service_flow_control(xml: str) -> str:
    """Format show class-of-service flow-control output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    flow = root.find("flow-control")
    rows = flow.findall("interface") if flow is not None else []
    lines = ["Class of service flow control:"]
    if flow is not None:
        lines.append(
            "Global: "
            f"auto-pause {flow.attrib.get('auto-pause', '-')}, "
            f"drop-pause {flow.attrib.get('drop-pause', '-')}, "
            f"pause-smac {flow.attrib.get('pause-smac', '-')}")

        tc_rows = flow.findall("traffic-class")
        if tc_rows:
            tc_map = ", ".join(
                f"{tc.attrib.get('id', '-')}:"
                f"{tc.attrib.get('smp', '-')}"
                for tc in tc_rows)
            lines.append(f"Traffic class to SMP: {tc_map}")
    lines.append(
        "Interface       RX pause  RX classes  TX mode      TX classes  "
        "Lossless  Shared")
    if not rows:
        lines.append("(no hardware flow-control state)")
        return "\n".join(lines)
    for iface in rows:
        lines.append(
            f"{iface.attrib.get('name', '-'):<15} "
            f"{iface.attrib.get('rx-pause', '-'):>8}  "
            f"{iface.attrib.get('rx-class-mask', '-'):>10}  "
            f"{iface.attrib.get('tx-pause-mode', '-'):<11}  "
            f"{iface.attrib.get('tx-class-mask', '-'):>10}  "
            f"{iface.attrib.get('smp-lossless-mask', '-'):>8}  "
            f"{iface.attrib.get('shared-pause-mask', '-'):>6}")
    return "\n".join(lines)


def format_class_of_service_scheduler(xml: str) -> str:
    """Format show class-of-service scheduler output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    scheduler = root.find("scheduler")
    rows = scheduler.findall("interface") if scheduler is not None else []
    lines = ["Class of service scheduler:"]
    lines.append("Interface       Groups  Free BW  TC enable  TC zero-len")
    if not rows:
        lines.append("(no hardware scheduler state)")
        return "\n".join(lines)

    for iface in rows:
        lines.append(
            f"{iface.attrib.get('name', '-'):<15} "
            f"{iface.attrib.get('sched-groups', '-'):>6}  "
            f"{iface.attrib.get('free-bandwidth-percent', '-'):>7}  "
            f"{iface.attrib.get('tc-enable-mask', '-'):>9}  "
            f"{iface.attrib.get('tc-zero-length-mask', '-'):>11}")

        tc_rows = iface.findall("traffic-class")
        if tc_rows:
            tc_map = ", ".join(
                f"{tc.attrib.get('id', '-')}:"
                f"{tc.attrib.get('shaping-group', '-')}"
                for tc in tc_rows)
            lines.append(f"  TC -> shaping group: {tc_map}")

        group_rows = iface.findall("group")
        if group_rows:
            lines.append(
                "  Group  PriSet       Strict       Weight    TC range  "
                "Rate bps      Burst bits")
            for group in group_rows:
                boundary_a = group.attrib.get("tc-boundary-a", "-")
                boundary_b = group.attrib.get("tc-boundary-b", "-")
                lines.append(
                    f"  {group.attrib.get('id', '-'):>5}  "
                    f"{group.attrib.get('priset', '-'):<11} "
                    f"{group.attrib.get('strict', '-'):<12} "
                    f"{group.attrib.get('weight', '-'):>8}    "
                    f"{boundary_a:>2}-{boundary_b:<2}  "
                    f"{group.attrib.get('rate-bps', '-'):>12}  "
                    f"{group.attrib.get('burst-bits', '-'):>12}")
    return "\n".join(lines)


def format_class_of_service_ets(xml: str) -> str:
    """Format hardware-backed ETS view from FM10000 scheduler read-back."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    scheduler = root.find("scheduler")
    rows = scheduler.findall("interface") if scheduler is not None else []
    lines = [
        "Class of service ETS:",
        "Backing: FM10000 scheduler groups",
        "Note: ETS queue-profile/drop-profile/ECN remain unsupported; "
        "this view shows the scheduler-backed ETS subset.",
        "Interface       TC enable  TC -> group                 Group policy",
    ]
    if not rows:
        lines.append("(no hardware ETS scheduler state)")
        return "\n".join(lines)

    for iface in rows:
        tc_rows = iface.findall("traffic-class")
        tc_map = ", ".join(
            f"{tc.attrib.get('id', '-')}:"
            f"{tc.attrib.get('shaping-group', '-')}"
            for tc in tc_rows) or "-"

        group_rows = iface.findall("group")
        if not group_rows:
            group_policy = "-"
        else:
            group_bits = []
            for group in group_rows:
                strict = group.attrib.get("strict", "-")
                group_bits.append(
                    f"g{group.attrib.get('id', '-')}:"
                    f"{'strict' if strict == 'on' else 'drr'} "
                    f"weight={group.attrib.get('weight', '-')} "
                    f"rate={group.attrib.get('rate-bps', '-')} "
                    f"burst={group.attrib.get('burst-bits', '-')}")
            group_policy = "; ".join(group_bits)

        lines.append(
            f"{iface.attrib.get('name', '-'):<15} "
            f"{iface.attrib.get('tc-enable-mask', '-'):>9}  "
            f"{tc_map:<27} "
            f"{group_policy}")
    return "\n".join(lines)


def format_class_of_service_queues(xml: str) -> str:
    """Format show class-of-service queues output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    queues = root.find("queues")
    iface_rows = queues.findall("interface") if queues is not None else []
    lines = ["Class of service queues:"]
    if queues is not None:
        lines.append(
            "Backing: forwarding queue inventory "
            f"(config-open={queues.attrib.get('config-open', '-')})")
    if not iface_rows:
        lines.append("(no forwarding queue read-back state)")
        return "\n".join(lines)

    lines.append(
        "Interface       Queue  State    TC  Min Mbps      Max Mbps      ASIC status")
    for iface in iface_rows:
        present = [q for q in iface.findall("queue")
                   if q.attrib.get("state") == "present"]
        absent = [q for q in iface.findall("queue")
                  if q.attrib.get("state") != "present"]
        if not present:
            status = absent[0].attrib.get("sdk-status", "-") if absent else "-"
            lines.append(
                f"{iface.attrib.get('name', '-'):<15} "
                f"{'-':>5}  {'absent':<7} {'-':>2}  "
                f"{'-':>12}  {'-':>12}  "
                f"{status} ({len(absent)} probes)")
            continue
        for queue in present:
            lines.append(
                f"{iface.attrib.get('name', '-'):<15} "
                f"{queue.attrib.get('id', '-'):>5}  "
                f"{queue.attrib.get('state', '-'):<7} "
                f"{queue.attrib.get('traffic-class', '-'):>2}  "
                f"{queue.attrib.get('min-bw-mbps', '-'):>12}  "
                f"{queue.attrib.get('max-bw-mbps', '-'):>12}  "
                f"{queue.attrib.get('sdk-status', '-')}")
    lines.append(
        "Note: this is read-only forwarding queue inventory; the operator-assisted QoS "
        "queue probe method 94 validates temporary add/set/read/delete cleanup, "
        "while diagnostic methods 95/96/97 provide a guarded queue transaction "
        "for apply/read-back/rollback and diagnostic methods "
        "105/106/107 provide a multi-queue profile transaction. queue profile, "
        "drop profile, and public ETS writes remain disabled.")
    return "\n".join(lines)


def format_class_of_service_watermarks(xml: str) -> str:
    """Format show class-of-service watermarks output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    watermarks = root.find("watermarks")
    lines = ["Class of service watermarks:"]
    if watermarks is None:
        lines.append("(no hardware watermark state)")
        return "\n".join(lines)

    lines.append(
        "Global: "
        f"auto-pause {watermarks.attrib.get('auto-pause', '-')}, "
        f"CN mode {watermarks.attrib.get('cn-mode', '-')}, "
        f"priv {watermarks.attrib.get('priv-wm', '-')}, "
        f"high {watermarks.attrib.get('high-wm', '-')}, "
        f"low {watermarks.attrib.get('low-wm', '-')}")
    lines.append(
        "CN frame: "
        f"etype {watermarks.attrib.get('cn-frame-etype', '-')}, "
        f"vpri {watermarks.attrib.get('cn-frame-vpri', '-')}, "
        f"vlan {watermarks.attrib.get('cn-frame-vlan', '-')}, "
        f"source-port {watermarks.attrib.get('cn-frame-src-port', '-')}, "
        f"smac {watermarks.attrib.get('cn-frame-smac', '-')}, "
        f"dmac {watermarks.attrib.get('cn-frame-dmac', '-')}")

    smp_rows = watermarks.findall("shared-memory")
    if smp_rows:
        lines.append("Shared memory watermarks:")
        lines.append("SMP  Pause on     Pause off")
        for smp in smp_rows:
            lines.append(
                f"{smp.attrib.get('id', '-'):>3}  "
                f"{smp.attrib.get('pause-on-wm', '-'):>10}  "
                f"{smp.attrib.get('pause-off-wm', '-'):>10}")

    priority_rows = watermarks.findall("switch-priority")
    if priority_rows:
        lines.append("Switch priority watermarks:")
        lines.append(
            "Priority  Shared-pri   Soft-drop  Jitter  Soft-drop-hog")
        for pri in priority_rows:
            lines.append(
                f"{pri.attrib.get('id', '-'):>8}  "
                f"{pri.attrib.get('shared-pri-wm', '-'):>10}  "
                f"{pri.attrib.get('soft-drop-wm', '-'):>10}  "
                f"{pri.attrib.get('soft-drop-jitter', '-'):>6}  "
                f"{pri.attrib.get('soft-drop-hog-wm', '-'):>13}")

    iface_rows = watermarks.findall("interface")
    if not iface_rows:
        lines.append("(no per-interface watermark state)")
        return "\n".join(lines)

    lines.append("Interface watermarks:")
    for iface in iface_rows:
        lines.append(f"Interface {iface.attrib.get('name', '-')}:")
        tc_rows = iface.findall("traffic-class")
        if tc_rows:
            lines.append("  TC  TX hog      TX private")
            for tc in tc_rows:
                lines.append(
                    f"  {tc.attrib.get('id', '-'):>2}  "
                    f"{tc.attrib.get('tx-hog-wm', '-'):>10}  "
                    f"{tc.attrib.get('tx-private-wm', '-'):>10}")
        partition_rows = iface.findall("memory-partition")
        if partition_rows:
            lines.append("  SMP  RX hog      RX private  Pause on    Pause off")
            for smp in partition_rows:
                lines.append(
                    f"  {smp.attrib.get('id', '-'):>3}  "
                    f"{smp.attrib.get('rx-hog-wm', '-'):>10}  "
                    f"{smp.attrib.get('rx-private-wm', '-'):>10}  "
                    f"{smp.attrib.get('private-pause-on-wm', '-'):>10}  "
                    f"{smp.attrib.get('private-pause-off-wm', '-'):>10}")
        port_priority_rows = iface.findall("switch-priority")
        if port_priority_rows:
            lines.append(
                "  Priority  TX soft-drop on private  "
                "TX soft-drop on RXMP-free")
            for priority in port_priority_rows:
                on_private = priority.attrib.get(
                    "tx-soft-drop-on-private", "-")
                on_rxmp_free = priority.attrib.get(
                    "tx-soft-drop-on-rxmp-free", "-")
                lines.append(
                    f"  {priority.attrib.get('id', '-'):>8}  "
                    f"{on_private:>23}  "
                    f"{on_rxmp_free:>25}")
    return "\n".join(lines)


def format_class_of_service_capabilities(diagnostics: bool = False) -> str:
    """Describe the public CoS surface and optional diagnostic boundaries."""
    feature_w = 31
    config_w = 11
    hardware_w = 24
    rows = [
        ("trust/default-priority", "config", "yes", "commit/read-back"),
        ("priority-flow-control", "config", "yes", "commit/read-back"),
        ("switch-priority TC map", "config", "yes", "commit/read-back"),
        ("scheduler template/policy", "config", "yes", "TRex template gate"),
        ("ETS scheduler subset", "config/show", "scheduler groups/DRR", "diagnostics ets"),
        ("group strict/DRR", "config", "yes", "TRex DRR ratio gate"),
        ("group shaping", "config", "yes", "TRex shaping gate"),
        ("TX watermarks", "config", "tx-hog/tx-private", "commit/read-back"),
        ("switch soft-drop wm", "config", "soft-drop/jitter/hog", "commit/read-back"),
        ("switch soft-drop enable", "read-only", "platform controlled", "diagnostics watermarks"),
        ("RX/pause watermarks", "read-only", "auto-pause controlled", "diagnostics watermarks"),
        ("ASIC queue read-back", "read-only", "queue id/TC/min/max BW", "diagnostics queues"),
        ("advanced QoS contract", "planned", "ETS/queue/drop/wm/ECN", "dry-run contract"),
        ("queue profile/drop profile", "deferred", "no public config", "rejected"),
        ("ETS queue policy", "deferred", "queue policy not open", "rejected"),
        ("QoS ECN/CN", "deferred", "not FM10000-backed", "rejected"),
    ]
    if diagnostics:
        rows[13:13] = [
            ("QoS queue probe", "operator", "add/set/read/delete", "method 94 cleanup"),
            ("QoS queue transaction", "diagnostic", "apply/read-back/rollback", "methods 95/96/97"),
            ("QoS queue profile transaction", "diagnostic", "multi-queue profile", "methods 105/106/107"),
            ("QoS watermark transaction", "diagnostic", "broader primitive matrix", "methods 108/109/110"),
        ]
    lines = [
        ("Class of service capabilities (diagnostics):"
         if diagnostics else "Class of service capabilities:"),
        "Feature                         Config      Hardware                 Validation",
    ]
    for feature, config, hardware, validation in rows:
        lines.append(
            f"{feature:<{feature_w}} {config:<{config_w}} "
            f"{hardware:<{hardware_w}} {validation}")
    lines.extend([
        "",
        "Notes:",
        "  Public watermarks include per-port/per-traffic-class tx-hog/tx-private and per switch-priority soft-drop/jitter/hog.",
        "  RX/pause watermarks and per-interface TX soft-drop enable bits remain platform controlled and intentionally read-only.",
        "  Queue hardware is exposed as read-only inventory; implementation probes live under diagnostics.",
        "  Diagnostics capabilities include implementation apply/read-back/rollback gates for bring-up and audit.",
        "  Advanced QoS evidence defines the read-back/rollback/traffic gates required before complete ETS, queue profile, drop profile, RX/pause watermark policy, or ECN/CN can open.",
        "  Scheduler policy and ETS policy are compatibility aliases of scheduler template and use the same hardware-backed scheduler path.",
        "  class-of-service ets policy/interfaces and show diagnostics class-of-service ets present the scheduler-backed ETS subset without opening queue-profile/drop-profile/ECN writes.",
        "  NetLab does not yet expose public queue allocation, drop policy, or ETS queue policy.",
        "  Queue profile, drop profile, ETS queue policy, and QoS ECN/CN stay closed until they have safe apply/read-back/rollback and traffic gates.",
    ])
    if diagnostics:
        lines.extend([
            "  diagnostic transaction methods 95/96/97 own the bounded queue apply/read-back/rollback transaction for queue-id, traffic-class, and min/max bandwidth.",
            "  diagnostic transaction methods 105/106/107 own the bounded multi-queue profile apply/read-back/rollback transaction; public queue-profile config remains closed.",
            "  diagnostic transaction methods 108/109/110 validate the broader watermark primitive matrix; RX/pause paths remain closed.",
        ])
    return "\n".join(lines)


def format_ethernet_switching_acl_capabilities() -> str:
    """Describe hardware-backed ACL scope and explicit deferred ACL work."""
    feature_w = 21
    direction_w = 10
    match_w = 56
    action_w = 13
    independent_open = public_capability_enabled(GENERAL_ACL_INDEPENDENT)
    independent_row = (
        ("general ACL independent", "ingress",
         "independent ethernet/inet/policer groups on general ingress ACL pipeline",
         "drop/count/police", "commit/read-back/rollback")
        if independent_open else
        ("general ACL independent", "closed",
         "implemented ingress ethernet/inet/policer assets; public SET is sealed closed",
         "drop/count/police", "DELETE cleanup-only")
    )
    rows = [
        ("ingress-acl L2 MAC", "ingress", "src/dst MAC", "drop+count", "TRex source/destination"),
        ("ingress-ipv4-acl", "ingress", "IPv4 exact/prefix, DSCP/ECN, protocol, exact/range L4, TCP flags", "drop/count", "TRex IPv4 all"),
        ("acl-policer", "ingress", "dst MAC + ingress port-set", "police+count", "compiler transaction"),
        ("acl compiler", "mixed", "firewall policer/egress facade plus ethernet/inet compatibility aliases over hardware-backed pipelines", "drop/count/police", "config normalization"),
        ("ACL policer probe", "operator", "CoPP ACL image 3100, dst-mac + port-set", "police+count", "method 77 read-back/cleanup"),
        ("ACL policer transaction", "diagnostic", "CoPP ACL image 3100, dst-mac + port-set", "police+count", "methods 98/99/100"),
        ("egress ACL", "egress", "egress physical port + src/dst MAC", "drop", "read-back/rollback"),
        ("egress ACL probe", "operator", "egress port association + src/dst MAC", "drop", "method 101 cleanup"),
        ("general ACL allocator", "diagnostic", "ACL images 3300-3315/3400-3415, policers 301-332", "count+policer compiler smoke", "methods 102/103/104"),
        independent_row,
        ("general ACL compiler contract", "planned", "traffic evidence, restart/replay, egress pipeline, wider selectors", "drop/count/police matrix", "dry-run contract"),
        ("IPv4 action policer", "ingress", "Flow TCAM action policer", "-", "rejected/deferred"),
        ("independent ACL egress", "egress", "standalone egress group candidate, no hardware transaction yet", "-", "commit rejected"),
    ]
    lines = [
        "Ethernet-switching ACL capabilities:",
        "Feature               Direction  Match                                                    Action        Validation",
    ]
    for feature, direction, match, action, validation in rows:
        match_lines = textwrap.wrap(match, width=match_w) or ["-"]
        lines.append(
            f"{feature:<{feature_w}} {direction:<{direction_w}} "
            f"{match_lines[0]:<{match_w}} {action:<{action_w}} {validation}")
        for continuation in match_lines[1:]:
            lines.append(
                f"{'':<{feature_w}} {'':<{direction_w}} "
                f"{continuation:<{match_w}} {'':<{action_w}}")
    lines.extend([
        "",
        "Notes:",
        "  Supported ACLs share the l2-security Flow TCAM budget with DHCP snooping, ARP inspection, user-filter, and ingress-acl.",
        "  firewall family ethernet-switching filter <filter> term <term> policer is the narrow public ACL compiler policer: up to 8 active terms, each with a unique physical ingress port plus destination MAC.",
        "  firewall family ethernet-switching filter <filter> term <term> egress is the narrow public egress pipeline: up to 8 active terms, one term per physical egress port, source/destination-MAC drop only.",
        "  acl term <name> ethernet|inet and acl group <group> term <term> ethernet|inet remain diagnostic compatibility compiler aliases for ingress ACLs.",
        "  firewall filter names flatten the stored scoped term name to <filter>.<term>; they do not allocate an independent ACL group object.",
        "  The ACL policer probe remains an operator-assisted cleanup probe; methods 98/99/100 are the underlying forwarding transaction.",
        "  The egress ACL probe remains an operator-assisted method 101 cleanup probe for the hardware primitive.",
        ("  acl independent-group ingress SET is open under the immutable public capability; egress stays closed."
         if independent_open else
         "  General ACL independent implementation assets are present, but the immutable public capability is promotion-closed: SET is rejected and DELETE is cleanup-only."),
        "  The general ACL allocator has diagnostic methods 102/103/104 for reserve/read-back/rollback and a count+policer compiler smoke.",
        "  The general ACL compiler contract tracks remaining evidence separately: traffic, restart/replay, egress pipeline, and wider selector expansion.",
        ("  ingress-ipv4-acl action policer remains deferred; use independent-group policer or firewall family ethernet-switching policer where their narrower contracts fit."
         if independent_open else
         "  ingress-ipv4-acl action policer remains deferred; the narrow firewall family ethernet-switching policer is the only public policer path while independent-group is promotion-closed."),
    ])
    return "\n".join(lines)
