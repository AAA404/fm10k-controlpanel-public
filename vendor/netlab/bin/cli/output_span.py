"""Formatter for hardware-backed local port mirroring state."""

import xml.etree.ElementTree as ET


def _name(node):
    return node.tag.split("}")[-1]


def _child(node, tag):
    if node is None:
        return None
    return next((item for item in list(node) if _name(item) == tag), None)


def format_port_mirroring(xml):
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, TypeError):
        return xml
    if _name(root) != "span":
        return xml

    desired = _child(root, "desired")
    desired_session = _child(desired, "session")
    hardware = _child(root, "hardware")
    hardware_root = _child(hardware, "port-mirroring")
    hardware_session = _child(hardware_root, "session")
    lines = ["Port mirroring:"]
    lines.append(f"  State       : {root.get('state', 'unavailable')}")
    lines.append(f"  Capacity    : {root.get('capacity', '1')} session")

    if desired_session is None:
        lines.append("  Configured  : no")
    else:
        lines.append("  Configured  : yes")
        lines.append(f"  Session     : {desired_session.get('name', '-')}")
        lines.append(
            "  Destination : %s (port %s)" % (
                desired_session.get("destination-interface", "-"),
                desired_session.get("destination-port", "-"),
            )
        )
        lines.append("  Sources:")
        for source in list(desired_session):
            if _name(source) != "source":
                continue
            lines.append(
                "    %-18s port %-4s %s" % (
                    source.get("interface", "-"),
                    source.get("port", "-"),
                    source.get("direction", "ingress"),
                )
            )

    available = hardware is not None and hardware.get("available") == "true"
    lines.append(f"  Hardware    : {'available' if available else 'unavailable'}")
    if available:
        if hardware_session is None:
            lines.append("  Installed   : no")
        else:
            lines.append("  Installed   : yes")
            lines.append(
                "  HW group    : %s, destination port %s, %s source(s)" % (
                    hardware_session.get("group", "-"),
                    hardware_session.get("destination-port", "-"),
                    hardware_session.get("source-count", "0"),
                )
            )
    return "\n".join(lines)
