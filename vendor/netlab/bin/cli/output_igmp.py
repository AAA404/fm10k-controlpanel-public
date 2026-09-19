"""Operational formatting for IPv4 IGMP snooping."""

import xml.etree.ElementTree as ET


def format_igmp_snooping(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, TypeError):
        return "IGMP snooping state unavailable"

    enabled = root.get("enabled", "false")
    timeout = root.get("timeout", "-")
    summary = root.find("summary")
    hardware = root.find("multicast-owner")
    hw_summary = hardware.find("summary") if hardware is not None else None
    lines = [
        f"IGMP snooping : {'enabled' if enabled == 'true' else 'disabled'}",
        f"Member timeout: {timeout} seconds",
        ("Members       : static {static}, dynamic {dynamic}".format(
            static=summary.get("static", "0") if summary is not None else "0",
            dynamic=summary.get("dynamic", "0") if summary is not None else "0")),
        ("Hardware      : groups {groups}, listeners {listeners}".format(
            groups=hw_summary.get("groups", "-")
            if hw_summary is not None else "-",
            listeners=hw_summary.get("listeners", "-")
            if hw_summary is not None else "-")),
    ]
    members = root.findall("member")
    if members:
        lines.extend(["", "Source   VLAN  Port  Group            Expires"])
        for member in members:
            expires = member.get("expires-in")
            lines.append(
                f"{member.get('source', '-'):8} "
                f"{member.get('vlan', '-'):>4}  "
                f"{member.get('port', '-'):>4}  "
                f"{member.get('group', '-'):15}  "
                f"{expires + 's' if expires is not None else '-'}")
    return "\n".join(lines)
