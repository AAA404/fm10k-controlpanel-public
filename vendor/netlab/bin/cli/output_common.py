"""Shared helpers for CLI output formatters."""
import math

from platform_profile import port_to_ifname


def _text(elem, tag):
    child = elem.find(tag)
    return child.text.strip() if child is not None and child.text else ""


def _attr(elem, name, default="-"):
    if elem is None:
        return default
    value = elem.attrib.get(name, default)
    return default if value == "-1" else value


def _fit(value, width):
    text = str(value)
    if len(text) >= width:
        return text[:width]
    return f"{text:<{width}}"


def _capacity_text(used, capacity):
    if used in (None, ""):
        used = "-"
    if capacity in (None, ""):
        capacity = "-"
    if capacity == "-":
        return f"{used}/unknown", "-"
    try:
        used_i = int(used)
        capacity_i = int(capacity)
    except (TypeError, ValueError):
        return f"{used}/{capacity}", "-"
    if capacity_i <= 0 or used_i < 0:
        return f"{used}/{capacity}", "-"
    return f"{used_i}/{capacity_i}", f"{used_i * 100.0 / capacity_i:.1f}%"


def _capacity_cells(elem, used_name, capacity_name):
    return _capacity_text(_attr(elem, used_name), _attr(elem, capacity_name))


def _used_from_free(capacity, free):
    try:
        capacity_i = int(capacity)
        free_i = int(free)
    except (TypeError, ValueError):
        return "-"
    if capacity_i < 0 or free_i < 0:
        return "-"
    used = capacity_i - free_i
    return str(used if used >= 0 else 0)


def _range_attr(elem, first_name, last_name):
    first = _attr(elem, first_name)
    last = _attr(elem, last_name)
    if first == "-" or last == "-":
        return "-"
    return f"{first}-{last}"


def _float_text(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return 0.0


def _format_speed(speed):
    try:
        mbps = int(speed)
    except (TypeError, ValueError):
        mbps = 0
    if mbps <= 0:
        return "Unknown"
    if mbps % 1000 == 0:
        gbps = mbps // 1000
        return f"{gbps}Gbps"
    return f"{mbps}Mbps"


def _format_bps(value):
    try:
        bps = int(value)
    except (TypeError, ValueError):
        return "Unknown"
    if bps <= 0:
        return "Unknown"
    units = [("Tbps", 10**12), ("Gbps", 10**9), ("Mbps", 10**6), ("Kbps", 10**3)]
    for suffix, scale in units:
        if bps >= scale and bps % scale == 0:
            return f"{bps // scale}{suffix}"
        if bps >= scale:
            return f"{bps / scale:.2f}{suffix}"
    return f"{bps}bps"


def _format_rate(value):
    try:
        rate = float(value)
    except (TypeError, ValueError):
        rate = 0.0
    if rate >= 1_000_000_000:
        return f"{rate / 1_000_000_000:.2f}G"
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f}M"
    if rate >= 1_000:
        return f"{rate / 1_000:.2f}K"
    return f"{rate:.0f}"


def _format_pps(value):
    try:
        pps = float(value)
    except (TypeError, ValueError):
        pps = 0.0
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f}M"
    if pps >= 1_000:
        return f"{pps / 1_000:.2f}K"
    return f"{pps:.0f}"


def _u64(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _age_text(text):
    try:
        age = int(text)
    except (TypeError, ValueError):
        age = -1
    if age < 0:
        return "never"
    return f"{age}s"


def _mw_to_dbm(mw):
    if mw <= 0:
        return "-Inf"
    return f"{10 * math.log10(mw):.2f}"


def _xcvr_type_name(type_text):
    names = {
        "0": "not-present",
        "1": "unknown (raw=1)",
        "2": "1000BASE-T",
        "3": "SFP-DAC",
        "4": "SFP-OPT",
        "5": "QSFP-DAC",
        "6": "QSFP-AOC",
        "7": "QSFP-OPT",
        "8": "QSFP28-DAC",
        "9": "QSFP28-AOC",
        "10": "QSFP28-OPT",
        "11": "FCI-OPT",
        "12": "FCI",
    }
    return names.get(type_text, f"unknown (raw={type_text})")


def _port_to_ifname(port_text):
    return port_to_ifname(port_text)


def _is_multicast_mac(mac_text):
    try:
        first_octet = int((mac_text or "").split(":", 1)[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x01)


def _is_user_visible_mac(mac, typ, port_text, ifname=""):
    if typ not in ("dynamic", "static"):
        return False
    if _is_multicast_mac(mac):
        return False
    if (ifname or "").startswith("ae"):
        return True
    mapped_ifname = _port_to_ifname(port_text)
    return bool(mapped_ifname and mapped_ifname not in ("-", port_text) and
                not mapped_ifname.startswith("logical-port-"))


def _local_name(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def _walk_set(elem, path, lines):
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    current = f"{path} {tag}".strip()
    children = list(elem)
    if not children and elem.text and elem.text.strip():
        lines.append(f"set {current} {elem.text.strip()}")
    else:
        for child in children:
            _walk_set(child, current, lines)
