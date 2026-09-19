"""Output formatters for chassis, forwarding, and management show commands."""
import math
import re
import time
import xml.etree.ElementTree as ET

from output_common import (_attr, _capacity_cells, _capacity_text, _fit,
                           _local_name, _range_attr, _used_from_free)
try:
    from platform_profile import (ifname_to_mux_optics_mapping,
                                  load_profile,
                                  physical_interface_names)
    from port_mode import port_mode_status
except ImportError:  # pragma: no cover - defensive for standalone formatter use
    ifname_to_mux_optics_mapping = None
    load_profile = None
    physical_interface_names = None
    port_mode_status = None

SUPERVISOR_STATE = "/var/run/netlab/supervisor.state"


def _speed_label(speed_bps):
    try:
        speed_bps = int(speed_bps)
    except (TypeError, ValueError):
        return str(speed_bps or "-")
    mapping = {
        0: "0",
        1_000_000_000: "1G",
        10_000_000_000: "10G",
        25_000_000_000: "25G",
        40_000_000_000: "40G",
        100_000_000_000: "100G",
    }
    return mapping.get(speed_bps, str(speed_bps))


def _profile_speed(entry):
    for key in ("default-speed", "line-rate", "scheduler-speed"):
        value = entry.get(key)
        if value not in (None, ""):
            return int(value, 0)
    return 0


def _profile_external(entry):
    role = (entry.get("role") or "").lower()
    flags = {flag.strip().lower() for flag in
             (entry.get("flags") or "").split(",") if flag.strip()}
    return role == "external" or "external" in flags


def _route_slices_enabled(ffu):
    for first_name, last_name in (
        ("ipv4-uc-first", "ipv4-uc-last"),
        ("ipv4-mc-first", "ipv4-mc-last"),
        ("ipv6-uc-first", "ipv6-uc-last"),
        ("ipv6-mc-first", "ipv6-mc-last"),
    ):
        try:
            first = int(ffu.get(first_name, "-1"), 0)
            last = int(ffu.get(last_name, "-1"), 0)
        except (TypeError, ValueError):
            continue
        if first >= 0 and last >= first:
            return True
    return False


def _public_forwarding_text(value):
    text = str(value or "-")
    replacements = (
        ("ies-sdk", "forwarding-plane"),
        ("hardware-owner", "hardware-forwarding-state"),
        ("sdk", "hardware"),
        ("SDK", "hardware"),
        ("owner", "state"),
        ("Owner", "State"),
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def _public_chassis_mode_text(value):
    text = str(value or "-")
    text = re.sub(r"\bprofile/RDI\b", "chassis port-mode", text,
                  flags=re.IGNORECASE)
    text = re.sub(r"\bRDI\b", "platform attributes", text)
    text = re.sub(r"\bprofile\b", "chassis mode", text,
                  flags=re.IGNORECASE)
    text = re.sub(r"/[^\s,;]+", "<path>", text)
    return text


def _public_status_presence(entry, *keys):
    if entry.get("error"):
        return "unavailable"
    for key in keys:
        value = entry.get(key)
        if value not in (None, "", "-"):
            return "present"
    return "missing"


def _format_public_port_mode_status(data):
    configured = data.get("configured", {})
    applied = data.get("applied", {})
    attributes = data.get("rdi", {})
    tx = data.get("transaction", {})
    chassis_mode = applied.get("chassis-profile") or (
        "configured" if _public_status_presence(applied, "path") == "present"
        else "-")
    lines = [
        "Port-mode apply status:",
        "  Configured port-mode  : %s" % configured.get("port-mode", "-"),
        "  Configured services   : %s" %
        configured.get("network-services", "-"),
        "  Config source         : %s" %
        _public_chassis_mode_text(configured.get("source", "-")),
        "  Applied port-mode     : %s" % applied.get("port-mode", "-"),
        "  Applied services      : %s" %
        applied.get("network-services", "-"),
        "  Applied chassis mode  : %s" %
        _public_chassis_mode_text(chassis_mode),
        "  Platform attributes   : %s" %
        _public_status_presence(attributes, "path", "sha256"),
        "  Config/applied drift  : %s" %
        ("yes" if data.get("drift") else "no"),
        "  Last transaction      : %s tx=%s action=%s" % (
            _public_chassis_mode_text(tx.get("state", "none")),
            _public_chassis_mode_text(tx.get("tx-id", "-")),
            _public_chassis_mode_text(tx.get("action", "-")),
        ),
    ]
    if configured.get("error"):
        lines.append("  Config state          : unavailable (%s)" %
                     _public_chassis_mode_text(configured["error"]))
    if applied.get("error"):
        lines.append("  Applied state         : unavailable (%s)" %
                     _public_chassis_mode_text(applied["error"]))
    if tx.get("last-error"):
        lines.append("  Last error            : %s" %
                     _public_chassis_mode_text(tx["last-error"]))
    return "\n".join(lines)


def _infer_port_mode(external_ports):
    counts = {}
    for entry in external_ports:
        label = _speed_label(_profile_speed(entry))
        counts[label] = counts.get(label, 0) + 1
    if counts == {"10G": 24}:
        return "24x10g"
    if counts == {"25G": 24}:
        return "24x25g"
    if counts == {"25G": 12, "10G": 12}:
        return "12x25g-12x10g"
    if counts == {"10G": 12, "40G": 3}:
        return "12x10g-3x40g"
    if counts == {"25G": 12, "100G": 3}:
        return "12x25g-3x100g"
    if counts == {"40G": 6}:
        return "6x40g"
    if counts == {"100G": 6}:
        return "6x100g"
    return "custom"


def _infer_network_services(profile, external_ports):
    platform = profile.get("platform", {})
    mode = platform.get("network-services")
    if mode:
        return mode
    route_caps = any(
        "ROUTE" in {cap.strip().upper() for cap in
                    (entry.get("capabilities") or "").split(",")
                    if cap.strip()}
        for entry in external_ports
    )
    return "l3" if _route_slices_enabled(profile.get("ffu", {})) and route_caps else "l2"


def format_chassis_port_mode() -> str:
    """Format active chassis port-mode and network-services profile facts."""
    if load_profile is None:
        return "Chassis port-mode: platform mode support unavailable"
    try:
        profile = load_profile()
    except Exception as exc:  # pragma: no cover - live error path
        return ("Chassis port-mode: unavailable (%s)" %
                _public_chassis_mode_text(exc))

    platform = profile.get("platform", {})
    external_ports = [
        entry for entry in profile.get("ports", []) if _profile_external(entry)
    ]
    port_mode = platform.get("port-mode") or _infer_port_mode(external_ports)
    network_services = _infer_network_services(profile, external_ports)
    speed_counts = {}
    for entry in external_ports:
        label = _speed_label(_profile_speed(entry))
        speed_counts[label] = speed_counts.get(label, 0) + 1
    speed_text = ", ".join(
        f"{count}x{label}" for label, count in sorted(speed_counts.items())
    ) or "-"
    ffu = profile.get("ffu", {})
    route_slices = "enabled" if _route_slices_enabled(ffu) else "disabled"
    acl_range = _range_attr_dict(ffu, "acl-first", "acl-last")

    lines = [
        "Chassis port-mode:",
        f"  Active port-mode       : {port_mode}",
        f"  Network services       : {network_services}",
        f"  Chassis mode           : {platform.get('chassis-name', '-')}",
        f"  External ports         : {len(external_ports)} ({speed_text})",
        f"  Route lookup slices    : {route_slices}",
        f"  ACL/filter slices      : {acl_range}",
        "  Apply model            : restart-time chassis port-mode selection",
    ]
    if port_mode_status is not None:
        lines.append("")
        try:
            lines.append(_format_public_port_mode_status(port_mode_status()))
        except Exception as exc:  # pragma: no cover - live error path
            lines.append("Port-mode apply status: unavailable (%s)" %
                         _public_chassis_mode_text(exc))
    return "\n".join(lines)


def _range_attr_dict(entry, first_name, last_name):
    try:
        first = int(entry.get(first_name, "-1"), 0)
        last = int(entry.get(last_name, "-1"), 0)
    except (TypeError, ValueError):
        return "-"
    if first < 0 or last < first:
        return "-"
    return f"{first}-{last}"


def _supervisor_state():
    entries = []
    recovery = {}
    updated = "-"
    try:
        with open(SUPERVISOR_STATE, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("updated="):
                    updated = line.split("=", 1)[1]
                    continue
                if line.startswith("supervisor "):
                    for token in line.split()[1:]:
                        if "=" not in token:
                            continue
                        key, value = token.split("=", 1)
                        recovery[key] = value
                    continue
                if not line.startswith("daemon "):
                    continue
                data = {}
                for token in line.split()[1:]:
                    if "=" not in token:
                        continue
                    key, value = token.split("=", 1)
                    data[key] = value
                if data:
                    entries.append(data)
    except OSError:
        return "-", {}, []
    return updated, recovery, entries


def _int_attr(elem, key, default=0):
    try:
        return int(_attr(elem, key), 0)
    except (TypeError, ValueError):
        return default


def _hex_to_bytes(text):
    text = (text or "").strip()
    if not text:
        return []
    try:
        return list(bytes.fromhex(text))
    except ValueError:
        return []


def _dump_kind(data):
    if not data:
        return "empty"
    if all(b == 0 for b in data):
        return "all-zero"
    if all(b == 0xff for b in data):
        return "all-ff"
    printable = sum(1 for b in data if 32 <= b < 127)
    if printable >= max(8, len(data) // 2):
        return "ascii-heavy"
    return "binary"


def _ascii_preview(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _short_hex(data, limit=16):
    if not data:
        return "-"
    shown = bytes(data[:limit]).hex()
    if len(data) > limit:
        return f"{shown}..."
    return shown


def _spaced_hex(data, limit=24):
    if not data:
        return "-"
    shown = " ".join(f"{b:02x}" for b in data[:limit])
    if len(data) > limit:
        return f"{shown} ..."
    return shown


def _text_field(data, start, length):
    if len(data) < start + length:
        return ""
    return bytes(data[start:start + length]).decode(
        "ascii", "replace").strip()


def _oui_field(data, start):
    if len(data) < start + 3:
        return ""
    return ":".join(f"{b:02x}" for b in data[start:start + 3])


def _u16_be(data, offset):
    if len(data) < offset + 2:
        return None
    return (data[offset] << 8) | data[offset + 1]


def _s16_be(data, offset):
    value = _u16_be(data, offset)
    if value is None:
        return None
    return value - 0x10000 if value & 0x8000 else value


def _mw_to_dbm_text(mw):
    if mw <= 0:
        return "no signal"
    return f"{10.0 * math.log10(mw):.2f} dBm"


def _fci_identity(data):
    if len(data) < 0xdd:
        return {}
    if _text_field(data, 0x98, 16) != "FCI MergeOptics":
        return {}
    return {
        "vendor-name": _text_field(data, 0x98, 16),
        "vendor-oui": _oui_field(data, 0xa8),
        "vendor-pn": _text_field(data, 0xab, 16),
        "vendor-rev": _text_field(data, 0xbb, 2),
        "vendor-sn": _text_field(data, 0xbd, 16),
        "vendor-date": _text_field(data, 0xcd, 8),
    }


def _standard_identity(data):
    if len(data) < 220:
        return {}
    return {
        "identifier-raw": f"0x{data[0]:02x}",
        "vendor-name": _text_field(data, 148, 16),
        "vendor-oui": _oui_field(data, 165),
        "vendor-pn": _text_field(data, 168, 16),
        "vendor-rev": _text_field(data, 184, 2),
        "vendor-sn": _text_field(data, 196, 16),
        "vendor-date": _text_field(data, 212, 8),
    }


def _ascii_pair_count(values):
    count = 0
    for value in values:
        if (32 <= ((value >> 8) & 0xff) < 127 and
                32 <= (value & 0xff) < 127):
            count += 1
    return count


def _fci_rx_power_vector(data, offset):
    if len(data) < offset + 24:
        return []
    values = [_u16_be(data, offset + i * 2) for i in range(12)]
    if any(v is None for v in values):
        return []
    if not any(values):
        return []
    if _ascii_pair_count(values) > 2:
        return []
    return values


def _fci_rx_power_vector_from_dumps(by_key):
    # FCI LOBT RX power is in 0x40 page 1 upper memory at absolute 0xce.
    # The RPC returns that dump as page=1 offset=128, so parse relative 0x4e.
    page1_upper = by_key.get((0x40, 1, 128), [])
    values = _fci_rx_power_vector(page1_upper, 0xce - 0x80)
    if values:
        return values

    full_page1 = by_key.get((0x40, 1, 0), [])
    values = _fci_rx_power_vector(full_page1, 0xce)
    if values:
        return values

    # Older/debug probes may have captured the active page as a single lower
    # dump. Keep this only as a guarded fallback to avoid exposing ASCII EEPROM.
    return _fci_rx_power_vector(by_key.get((0x40, -1, 0), []), 0xce)


def _module_sensor_values(module_eeprom):
    values = {}
    temp_raw = _s16_be(module_eeprom, 22)
    if temp_raw is not None:
        temp_c = temp_raw / 256.0
        if -40.0 <= temp_c <= 125.0:
            values["temperature-c"] = temp_c
    voltage_raw = _u16_be(module_eeprom, 26)
    if voltage_raw is not None:
        voltage_v = voltage_raw / 10000.0
        if 2.5 <= voltage_v <= 3.8:
            values["voltage-v"] = voltage_v
    return values


def _fci_max_temp_c(by_key, module_eeprom):
    page0_upper = by_key.get((0x50, 0, 128), [])
    if len(page0_upper) > 4:
        value = page0_upper[4]
        if 0 < value < 150:
            return value
    if len(module_eeprom) > 0x84:
        value = module_eeprom[0x84]
        if 0 < value < 150:
            return value
    return None


def _optics_mux_branch_hint(mux_value):
    try:
        value = int(mux_value, 0)
    except (TypeError, ValueError):
        return "-", "unknown"
    if value == 1:
        return "0", "et-0/0/0..et-0/0/11"
    if value == 2:
        return "1", "et-0/0/12..et-0/0/23"
    return "-", "unknown"


def _optics_mux_addr_map(branch):
    by_key = {}
    for addr in branch.findall("addr"):
        try:
            addr_value = int(addr.attrib.get("value", "0"), 0)
            page = int(addr.attrib.get("page", "-1"), 0)
            offset = int(addr.attrib.get("offset", "0"), 0)
        except ValueError:
            continue
        by_key[(addr_value, page, offset)] = _hex_to_bytes(addr.text)
    return by_key


def _optics_mux_addr_rows(branch):
    rows = []
    for addr in branch.findall("addr"):
        try:
            addr_value = int(addr.attrib.get("value", "0"), 0)
            page = int(addr.attrib.get("page", "-1"), 0)
            offset = int(addr.attrib.get("offset", "0"), 0)
            status = int(addr.attrib.get("status", "-1"), 0)
            length = int(addr.attrib.get("length", "0"), 0)
        except ValueError:
            continue
        rows.append({
            "addr": addr_value,
            "page": page,
            "offset": offset,
            "status": status,
            "length": length,
            "data": _hex_to_bytes(addr.text),
        })
    return rows


def _scan_status(branch, wanted_addr):
    scan = branch.find("scan")
    if scan is None:
        return None
    for dev in scan.findall("dev"):
        try:
            addr = int(dev.attrib.get("addr", "0"), 0)
            status = int(dev.attrib.get("status", "-1"), 0)
        except ValueError:
            continue
        if addr == wanted_addr:
            return status
    return None


def _append_mux_detail(lines, branch, by_key):
    rows = _optics_mux_addr_rows(branch)
    if not rows:
        return

    lines.append("  Detail data    : read-only raw mux capture")
    for dev_addr in (0x40, 0x50):
        dev_rows = [row for row in rows if row["addr"] == dev_addr]
        if not dev_rows:
            continue
        summary = []
        for row in sorted(dev_rows, key=lambda r: (r["page"], r["offset"])):
            page = "lower" if row["page"] < 0 else f"p{row['page']}"
            status = "ok" if row["status"] == 0 else f"err{row['status']}"
            summary.append(
                f"{page}@0x{row['offset']:02x}:{status}/{_dump_kind(row['data'])}")
        lines.append(f"  Page coverage 0x{dev_addr:02x}:")
        for item in summary:
            lines.append(f"    {item}")

    status_51 = _scan_status(branch, 0x51)
    if status_51 is not None and status_51 != 0:
        lines.append(f"  Address 0x51   : not responding (status={status_51})")

    pca9538 = []
    for offset in range(4):
        data = by_key.get((0x64, -1, offset), [])
        if data:
            pca9538.append(data[0])
    if len(pca9538) == 4:
        lines.append(
            "  PCA9538 0x64   : "
            f"input=0x{pca9538[0]:02x} output=0x{pca9538[1]:02x} "
            f"polarity=0x{pca9538[2]:02x} direction=0x{pca9538[3]:02x}")

    for dev_addr in (0x49, 0x59):
        sideband = [
            row for row in rows
            if row["addr"] == dev_addr and row["page"] < 0 and
            row["offset"] == 0
        ]
        if not sideband:
            continue
        row = sideband[-1]
        data = row["data"]
        status = "ok" if row["status"] == 0 else f"err{row['status']}"
        label = ("CPLD RAM 0x59" if dev_addr == 0x59
                 else "Raw sideband 0x49")
        lines.append(
            f"  {label}: "
            f"status={status} len={row['length']} {_dump_kind(data)} "
            f"hex={_short_hex(data)} ascii={_ascii_preview(data[:16])}")

    descriptor = by_key.get((0x50, 0, 128), [])
    descriptor_source = "0x50"
    if not descriptor:
        descriptor = by_key.get((0x40, 0, 128), [])
        descriptor_source = "0x40"
    if not descriptor:
        full_eeprom = by_key.get((0x50, -1, 0), [])
        if len(full_eeprom) > 128:
            descriptor = full_eeprom[128:]
            descriptor_source = "0x50"
    if not descriptor:
        full_eeprom = by_key.get((0x40, -1, 0), [])
        if len(full_eeprom) > 128:
            descriptor = full_eeprom[128:]
            descriptor_source = "0x40"
    if descriptor:
        lines.append(
            "  Descriptor raw : "
            f"{descriptor_source} page0 0x80..0x97 = {_spaced_hex(descriptor)}")
        lines.append(
            "  Descriptor note: max-temp byte 0x84 is decoded above; "
            "power-class/CDR bits remain raw pending FCI mapping.")

    lines.append(
        "  Detail note    : 0x59 is CPLD dual-port RAM, 0x64 is the "
        "read-only FCI reset GPIO state, and neither is per-interface "
        "optical power; 0x49 remains raw platform sideband.")


def _optics_mux_branch(root, mux_value):
    wanted = f"0x{mux_value:02x}"
    for branch in root.findall("branch"):
        value = _attr(branch, "value")
        try:
            if int(value, 0) == mux_value:
                return branch
        except (TypeError, ValueError):
            if value == wanted:
                return branch
    return None


def _format_rx_power(raw):
    mw = raw / 10000.0
    return f"{mw:.4f} mW / {_mw_to_dbm_text(mw)}"


def _mux_mapping_warning(rx_values, channels):
    if not rx_values or not channels:
        return ""
    selected = [rx_values[ch] for ch in channels if 0 <= ch < len(rx_values)]
    if not selected:
        return ""
    selected_max = max(selected)
    module_max = max(rx_values)
    if module_max < 1000:
        return ""
    if selected_max >= max(1000, module_max // 4):
        return ""
    strongest = rx_values.index(module_max)
    return (
        f"mapped channel is low while CH{strongest:02d} reports "
        f"{_format_rx_power(module_max)}; run one-channel calibration"
    )


_MUX_AUTHORITATIVE_STATUSES = {"calibrated", "inferred"}


def _mux_status_is_authoritative(status):
    return status in _MUX_AUTHORITATIVE_STATUSES


def _mux_mapping_is_authoritative(mapping):
    return _mux_status_is_authoritative(
        (mapping or {}).get("calibration-status"))


def _public_mux_mapping_status(status):
    mapping = {
        "profile-derived": "configured",
        "profile-inferred": "inferred",
        "profile-override": "calibrated-override",
    }
    return mapping.get(status or "-", status or "-")


def _mux_coverage_text(coverage, unit="configured ports"):
    total = coverage.get("total", 0)
    accepted = coverage.get("calibrated", 0)
    inferred = coverage.get("inferred", 0)
    measured = coverage.get("measured", accepted - inferred)
    if inferred:
        return (
            f"{accepted}/{total} {unit} mapped "
            f"({measured} calibrated, {inferred} inferred)")
    return f"{accepted}/{total} {unit} calibrated"


def _mux_calibrated_channel_owners(ifname, mapping):
    owners = {}
    if ifname_to_mux_optics_mapping is None or physical_interface_names is None:
        return owners
    try:
        names = physical_interface_names()
    except Exception:
        return owners
    for name in names:
        if name == ifname:
            continue
        try:
            other = ifname_to_mux_optics_mapping(name)
        except Exception:
            continue
        if not other or not _mux_mapping_is_authoritative(other):
            continue
        if other.get("mux-value") != mapping.get("mux-value"):
            continue
        for channel in other.get("channels") or []:
            owners.setdefault(channel, []).append(name)
    return owners


def _mux_channel_ownership_warning(channels, owners):
    conflicts = []
    for channel in channels:
        names = owners.get(channel)
        if names:
            conflicts.append(f"CH{channel:02d}->{','.join(names)}")
    if not conflicts:
        return ""
    return (
        "mapped channel is already calibrated for "
        + "; ".join(conflicts)
        + "; run one-channel calibration before treating this interface power as authoritative"
    )


def _mux_calibrated_channel_owner_map(module_mappings):
    owners = {}
    for name in sorted(module_mappings):
        mapping = module_mappings.get(name) or {}
        if not _mux_mapping_is_authoritative(mapping):
            continue
        for channel in mapping.get("channels") or []:
            owners.setdefault(channel, []).append(name)
    return owners


def _mux_channel_owner_rows(owners):
    return [
        f"CH{channel:02d}->{','.join(sorted(owners[channel]))}"
        for channel in sorted(owners)
    ]


def _mux_uncalibrated_link_up_ports(link_up, module_mappings):
    out = []
    for name in sorted(link_up or []):
        mapping = module_mappings.get(name) or {}
        if not _mux_mapping_is_authoritative(mapping):
            out.append(name)
    return out


def _mux_discoverable_strong_channels(strong, calibrated_owners):
    return [
        channel for channel in strong
        if not calibrated_owners.get(channel)
    ]


def _mux_uncalibrated_channel_conflicts(module_mappings, owners):
    conflicts = []
    for name in sorted(module_mappings):
        mapping = module_mappings.get(name) or {}
        if _mux_mapping_is_authoritative(mapping):
            continue
        for channel in mapping.get("channels") or []:
            channel_owners = owners.get(channel)
            if channel_owners:
                conflicts.append(
                    f"{name}->CH{channel:02d} already mapped to "
                    f"{','.join(sorted(channel_owners))}")
    return conflicts


def _mux_profile_mappings_by_module():
    modules = {}
    if ifname_to_mux_optics_mapping is None or physical_interface_names is None:
        return modules
    try:
        names = physical_interface_names()
    except Exception:
        return modules
    for name in names:
        try:
            mapping = ifname_to_mux_optics_mapping(name)
        except Exception:
            continue
        if not mapping:
            continue
        modules.setdefault(mapping.get("module-index"), {})[name] = mapping
    return modules


def _append_mux_mapping_summary(lines, module_mappings, detail=False):
    if not module_mappings:
        lines.append("  Channel mapping: no platform channel mapping")
        return
    total = len(module_mappings)
    calibrated = {
        name: mapping
        for name, mapping in module_mappings.items()
        if _mux_mapping_is_authoritative(mapping)
    }
    inferred = sum(
        1 for mapping in calibrated.values()
        if mapping.get("calibration-status") == "inferred")
    if len(calibrated) == total:
        state = "mapped" if inferred else "calibrated"
    elif calibrated:
        state = "partially mapped" if inferred else "partially calibrated"
    else:
        state = "uncalibrated"
    if inferred:
        measured = len(calibrated) - inferred
        suffix = (
            f"{len(calibrated)}/{total} configured ports mapped; "
            f"{measured} calibrated, {inferred} inferred")
    else:
        suffix = f"{len(calibrated)}/{total} configured ports calibrated"
    lines.append(f"  Channel mapping: {state} ({suffix})")

    owners = _mux_calibrated_channel_owner_map(module_mappings)
    owner_rows = _mux_channel_owner_rows(owners)
    if owner_rows:
        owner_label = "Accepted channels" if inferred else "Calibrated channels"
        lines.append(f"  {owner_label}: {', '.join(owner_rows)}")

    if detail and len(calibrated) != total:
        uncalibrated = [
            name for name in module_mappings
            if name not in calibrated
        ]
        lines.append(
            "  Uncalibrated ports: "
            + (", ".join(uncalibrated) if uncalibrated else "none"))


def _mux_module_calibration_context(mapping, channels):
    module_mappings = _mux_profile_mappings_by_module().get(
        mapping.get("module-index"), {})
    total = len(module_mappings)
    calibrated = sum(
        1 for item in module_mappings.values()
        if _mux_mapping_is_authoritative(item))
    inferred = sum(
        1 for item in module_mappings.values()
        if item.get("calibration-status") == "inferred")
    owners = _mux_calibrated_channel_owner_map(module_mappings)
    selected_owners = []
    for channel in channels:
        names = owners.get(channel) or []
        if names:
            selected_owners.append(
                f"CH{channel:02d}->{','.join(sorted(names))}")
    return {
        "total": total,
        "calibrated": calibrated,
        "measured": calibrated - inferred,
        "inferred": inferred,
        "selected_owners": selected_owners,
    }


def _mux_strong_channels(rx_values, threshold_raw=1000):
    return [idx for idx, raw in enumerate(rx_values) if raw >= threshold_raw]


def _interface_link_states(xml):
    states = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return states
    for iface in root.findall("interface"):
        name = (iface.findtext("name") or "").strip()
        if not name:
            continue
        states[name] = (iface.findtext("link") or "").strip().lower()
    return states


def _channel_rows(rx_values, channels):
    rows = []
    for channel in channels:
        if not (0 <= channel < len(rx_values)):
            continue
        raw = rx_values[channel]
        mw = raw / 10000.0
        rows.append({
            "channel": channel,
            "name": f"CH{channel:02d}",
            "channel_name": f"CH{channel:02d}",
            "raw": raw,
            "mw": mw,
            "dbm": _mw_to_dbm_text(mw),
            "text": _format_rx_power(raw),
        })
    return rows


def _rx_power_text_for_channels(rx_rows, channels):
    by_channel = {row.get("channel"): row for row in rx_rows}
    selected = []
    for channel in channels:
        row = by_channel.get(channel)
        if not row:
            return "-"
        selected.append(row)
    if not selected:
        return "-"
    if len(selected) == 1:
        return selected[0].get("text") or "-"
    avg_mw = sum(row.get("mw", 0.0) for row in selected) / len(selected)
    return f"{avg_mw:.4f} mW / {_mw_to_dbm_text(avg_mw)}"


def _selected_channel_owner_text(owners_by_channel, channels):
    rows = []
    for channel in channels:
        owners = owners_by_channel.get(channel) or []
        if owners:
            rows.append(f"CH{channel:02d}->{','.join(sorted(owners))}")
    return ", ".join(rows) if rows else "-"


def _selected_channel_owner_rows(owners_by_channel, channels):
    rows = []
    for channel in channels:
        owners = owners_by_channel.get(channel) or []
        if owners:
            rows.append({
                "channel": channel,
                "channel_name": f"CH{channel:02d}",
                "owners": sorted(owners),
            })
    return rows


def _mux_interface_map_rows(profile_rows, link_up, rx_rows,
                            owners_by_channel, ownership_conflicts):
    conflicts = {
        row.get("interface")
        for row in ownership_conflicts
        if row.get("interface")
    }
    link_up_set = set(link_up or [])
    rows = []
    for row in profile_rows:
        ifname = row.get("interface") or "-"
        channels = row.get("channels") or []
        channel_names = row.get("channel_names") or [
            f"CH{channel:02d}" for channel in channels
        ]
        owner_rows = _selected_channel_owner_rows(owners_by_channel, channels)
        owner_text = _selected_channel_owner_text(owners_by_channel, channels)
        if ifname in conflicts:
            rx_text = "unavailable"
            use = "blocked-mapping"
            authoritative = False
        else:
            rx_text = _rx_power_text_for_channels(rx_rows, channels)
            use = ("authoritative"
                   if _mux_status_is_authoritative(
                       row.get("calibration_status"))
                   else "uncalibrated")
            authoritative = use == "authoritative"
        rows.append({
            "interface": ifname,
            "link": "up" if ifname in link_up_set else "down",
            "channels": list(channels),
            "channel_names": list(channel_names),
            "mapping_status": row.get("mapping_status") or "-",
            "calibration_status": row.get("calibration_status") or "-",
            "owner": owner_text,
            "owners": owner_rows,
            "rx_power": rx_text,
            "use": use,
            "authoritative": authoritative,
        })
    return rows


def mux_calibration_status(optics_xml: str, interfaces_xml: str = "") -> dict:
    """Return machine-readable PE31625G24DIRA mux calibration status."""
    if ifname_to_mux_optics_mapping is None or physical_interface_names is None:
        return {
            "status": "unavailable",
            "reason": "platform channel mapping is unavailable",
            "modules": [],
        }

    try:
        root = ET.fromstring(optics_xml)
    except ET.ParseError:
        return {
            "status": "unavailable",
            "reason": "mux telemetry RPC returned invalid XML",
            "modules": [],
        }
    if root.attrib.get("error"):
        return {
            "status": "unavailable",
            "reason": f"mux telemetry error {root.attrib.get('error')}",
            "modules": [],
        }

    link_states = _interface_link_states(interfaces_xml)
    names = physical_interface_names()
    module_ports = {}
    module_link_up = {}
    module_mapping_by_name = {}
    for name in names:
        mapping = ifname_to_mux_optics_mapping(name)
        if not mapping:
            continue
        module = mapping["module-index"]
        profile_entry = {
            "interface": name,
            "channels": list(mapping["channels"]),
            "channel_names": [f"CH{ch:02d}" for ch in mapping["channels"]],
            "calibration_status": mapping["calibration-status"],
            "mapping_status": mapping["mapping-status"],
            "calibration_source": mapping.get("calibration-source", "-"),
            "resource_id": mapping["resource-id"],
            "mux_value": mapping["mux-value"],
        }
        module_ports.setdefault(module, []).append(profile_entry)
        module_mapping_by_name.setdefault(module, {})[name] = mapping
        if link_states.get(name) == "up":
            module_link_up.setdefault(module, []).append(name)

    modules = []
    for branch in root.findall("branch"):
        module, ports_hint = _optics_mux_branch_hint(_attr(branch, "value"))
        try:
            module_index = int(module)
        except (TypeError, ValueError):
            module_index = -1
        try:
            mux_value = int(_attr(branch, "value"), 0)
        except (TypeError, ValueError):
            mux_value = -1

        by_key = _optics_mux_addr_map(branch)
        rx_values = _fci_rx_power_vector_from_dumps(by_key)
        strong = _mux_strong_channels(rx_values)
        link_up = list(module_link_up.get(module_index, []))
        profile_rows = list(module_ports.get(module_index, []))
        module_mappings = module_mapping_by_name.get(module_index, {})
        calibrated_owners = _mux_calibrated_channel_owner_map(module_mappings)
        ownership_conflict_text = _mux_uncalibrated_channel_conflicts(
            module_mappings, calibrated_owners)
        calibrated_rows = [
            row for row in profile_rows
            if _mux_status_is_authoritative(row["calibration_status"])
        ]
        measured_rows = [
            row for row in profile_rows
            if row["calibration_status"] == "calibrated"
        ]
        inferred_rows = [
            row for row in profile_rows
            if row["calibration_status"] == "inferred"
        ]
        uncalibrated_rows = [
            row for row in profile_rows
            if not _mux_status_is_authoritative(row["calibration_status"])
        ]
        ownership_conflicts = []
        for name in module_mappings:
            mapping = module_mappings.get(name) or {}
            if _mux_mapping_is_authoritative(mapping):
                continue
            for channel in mapping.get("channels") or []:
                owners = calibrated_owners.get(channel) or []
                if owners:
                    ownership_conflicts.append({
                        "interface": name,
                        "channel": channel,
                        "channel_name": f"CH{channel:02d}",
                        "owners": sorted(owners),
                    })
        rx_rows = _channel_rows(rx_values, range(len(rx_values)))
        interface_map = _mux_interface_map_rows(
            profile_rows, link_up, rx_rows, calibrated_owners,
            ownership_conflicts)

        profile_flat = []
        profile_pairs = []
        profile_all_calibrated = bool(link_up)
        for name in link_up:
            mapping = module_mappings.get(name)
            if not mapping or not _mux_mapping_is_authoritative(mapping):
                profile_all_calibrated = False
                break
            for channel in mapping.get("channels") or []:
                profile_flat.append(channel)
                profile_pairs.append({
                    "interface": name,
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                })

        candidate_map = []
        reverse_candidate_map = []
        candidate_status = "no-active-signal"
        profile_match = None
        profile_update_hint = None
        uncalibrated_link_up = _mux_uncalibrated_link_up_ports(
            link_up, module_mappings)
        discoverable_strong = _mux_discoverable_strong_channels(
            strong, calibrated_owners)

        if (profile_all_calibrated and profile_flat and strong and
                sorted(profile_flat) == strong):
            detail = "live strong channels"
            if len(profile_flat) == len(strong):
                if profile_flat == strong:
                    detail = "candidate order"
                elif profile_flat == list(reversed(strong)):
                    detail = "reverse candidate order"
            candidate_status = "not-needed"
            profile_match = {
                "matched": True,
                "detail": detail,
                "calibrated_map": profile_pairs,
            }
        elif (discoverable_strong and uncalibrated_link_up and
              len(discoverable_strong) == len(uncalibrated_link_up)):
            candidate_status = "candidate"
            candidate_map = [
                {
                    "interface": name,
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                }
                for name, channel in zip(uncalibrated_link_up,
                                         discoverable_strong)
            ]
            reverse_candidate_map = [
                {
                    "interface": name,
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                }
                for name, channel in zip(
                    uncalibrated_link_up, reversed(discoverable_strong))
            ]
            if len(discoverable_strong) == 1:
                name = uncalibrated_link_up[0]
                channel = discoverable_strong[0]
                mapping = module_mappings.get(name) or {}
                channel_owners = [
                    owner for owner in calibrated_owners.get(channel, [])
                    if owner != name
                ]
                if channel_owners:
                    profile_update_hint = {
                        "status": "blocked",
                        "interface": name,
                        "channel": channel,
                        "channel_name": f"CH{channel:02d}",
                        "owners": sorted(channel_owners),
                    }
                elif (not _mux_mapping_is_authoritative(mapping) or
                      mapping.get("channels") != [channel]):
                    profile_update_hint = {
                        "status": "set",
                        "interface": name,
                        "channel": channel,
                        "channel_name": f"CH{channel:02d}",
                    }
        elif (strong and uncalibrated_link_up and len(strong) == 1 and
              len(uncalibrated_link_up) == 1 and
              calibrated_owners.get(strong[0])):
            candidate_status = "candidate"
            name = uncalibrated_link_up[0]
            channel = strong[0]
            candidate_map = [{
                "interface": name,
                "channel": channel,
                "channel_name": f"CH{channel:02d}",
            }]
            channel_owners = [
                owner for owner in calibrated_owners.get(channel, [])
                if owner != name
            ]
            if channel_owners:
                profile_update_hint = {
                    "status": "blocked",
                    "interface": name,
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                    "owners": sorted(channel_owners),
                }
        elif strong and link_up and len(strong) == len(link_up):
            candidate_status = "candidate"
            candidate_map = [
                {
                    "interface": name,
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                }
                for name, channel in zip(link_up, strong)
            ]
            reverse_candidate_map = [
                {
                    "interface": name,
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                }
                for name, channel in zip(link_up, reversed(strong))
            ]
        elif strong or link_up:
            candidate_status = "unresolved-count-mismatch"

        modules.append({
            "module": module_index,
            "mux_value": mux_value,
            "mux": _attr(branch, "value"),
            "ports_hint": ports_hint,
            "rx_source": "0x40 page 1 offset 0xce",
            "rx_power": rx_rows,
            "strong_rx_channels": _channel_rows(rx_values, strong),
            "link_up_ports": link_up,
            "profile_map": profile_rows,
            "interface_map": interface_map,
            "calibrated_channels": [
                {
                    "channel": channel,
                    "channel_name": f"CH{channel:02d}",
                    "owners": sorted(owners),
                }
                for channel, owners in sorted(calibrated_owners.items())
            ],
            "ownership_conflicts": ownership_conflicts,
            "ownership_conflict_text": ownership_conflict_text,
            "calibration_coverage": {
                "calibrated": len(calibrated_rows),
                "measured": len(measured_rows),
                "inferred": len(inferred_rows),
                "total": len(profile_rows),
                "uncalibrated_ports": [
                    row["interface"] for row in uncalibrated_rows
                ],
            },
            "candidate_status": candidate_status,
            "candidate_map": candidate_map,
            "reverse_candidate_map": reverse_candidate_map,
            "profile_match": profile_match,
            "profile_update_hint": profile_update_hint,
        })

    return {
        "status": "ok",
        "mode": "read-only",
        "method": "compare configured ports with live strong RX channels",
        "caveat": "candidate maps are hints only; confirm by one known link at a time",
        "modules": modules,
        "next_step": (
            "leave exactly one known peer link up on the target module, rerun "
            "this command, then record the observed CHxx mapping in the platform channel mapping"
        ),
    }


def format_chassis_optics_mux(xml: str, detail: bool = False) -> str:
    """Format PE31625G24DIRA/RubyRapid module mux optics output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if root.attrib.get("error"):
        return f"Chassis optics mux: unavailable (status={root.attrib.get('error')})"

    lines = [
        "Chassis optics mux:",
        f"  Bus            : {_attr(root, 'bus')}",
        f"  PCA mux        : {_attr(root, 'mux')}",
        f"  Control before : {_attr(root, 'control-before')}",
        f"  Restore status : {_attr(root, 'restore-status')}",
    ]
    truncated = (root.findtext("truncated") or "").strip()
    if truncated == "1":
        lines.append("  Warning        : probe XML was truncated")

    branches = root.findall("branch")
    if not branches:
        lines.append("")
        lines.append("  No module branches returned")
        return "\n".join(lines)

    profile_mappings = _mux_profile_mappings_by_module()
    for branch in branches:
        module, ports = _optics_mux_branch_hint(_attr(branch, "value"))
        try:
            module_index = int(module)
        except (TypeError, ValueError):
            module_index = None
        lines.extend([
            "",
            f"Module {module} (mux {_attr(branch, 'value')}, ports {ports})",
            f"  Select status : {_attr(branch, 'select-status')}",
            f"  Control after : {_attr(branch, 'control-after')}",
        ])

        scan = branch.find("scan")
        if scan is not None:
            responders = []
            for dev in scan.findall("dev"):
                if _attr(dev, "status") == "0":
                    responders.append(_attr(dev, "addr"))
            lines.append(
                "  I2C responders : " +
                (", ".join(responders) if responders else "none"))

        by_key = _optics_mux_addr_map(branch)
        module_eeprom = by_key.get((0x50, -1, 0), [])
        rx_eeprom = by_key.get((0x40, -1, 0), [])
        identity = _fci_identity(module_eeprom)
        identity_source = "FCI vendor page 0"
        if not identity:
            identity = _standard_identity(module_eeprom)
            identity_source = "standard page 0" if identity else "-"
        if identity:
            lines.extend([
                f"  Identity source: {identity_source}",
                f"  Vendor name    : {identity.get('vendor-name') or '-'}",
                f"  Vendor OUI     : {identity.get('vendor-oui') or '-'}",
                f"  Vendor PN      : {identity.get('vendor-pn') or '-'}",
                f"  Vendor Rev     : {identity.get('vendor-rev') or '-'}",
                f"  Vendor SN      : {identity.get('vendor-sn') or '-'}",
                f"  Vendor Date    : {identity.get('vendor-date') or '-'}",
            ])
            if identity.get("identifier-raw"):
                lines.append(
                    f"  Identifier raw : {identity.get('identifier-raw')}")
        else:
            lines.append("  Identity       : unavailable")

        module_sensors = _module_sensor_values(module_eeprom)
        rx_sensors = _module_sensor_values(rx_eeprom)
        max_temp_c = _fci_max_temp_c(by_key, module_eeprom)
        if module_sensors.get("temperature-c") is not None:
            temp_c = module_sensors["temperature-c"]
            lines.append(
                "  Module temperature: "
                f"{temp_c:.1f} degrees C / {temp_c * 9 / 5 + 32:.1f} degrees F")
        if module_sensors.get("voltage-v") is not None:
            lines.append(
                f"  Module voltage    : {module_sensors['voltage-v']:.4f} V")
        if rx_sensors.get("voltage-v") is not None:
            lines.append(
                f"  RX-side voltage   : {rx_sensors['voltage-v']:.4f} V")
        if max_temp_c is not None:
            lines.append(f"  Max temperature   : {max_temp_c} degrees C")

        rx_values = _fci_rx_power_vector_from_dumps(by_key)
        lines.extend([
            "  RX source      : 0x40 page 1 offset 0xce",
            "  RX power       :",
            "    Channel  Raw    mW       dBm",
        ])
        if rx_values:
            for idx, raw in enumerate(rx_values):
                mw = raw / 10000.0
                lines.append(
                    f"    CH{idx:02d}     {raw:<5d}  {mw:0.4f}   "
                    f"{_mw_to_dbm_text(mw)}")
        else:
            lines.append("    unavailable")
        _append_mux_mapping_summary(
            lines, profile_mappings.get(module_index, {}), detail=detail)
        if detail:
            _append_mux_detail(lines, branch, by_key)

    lines.extend([
        "",
        "Note: this is module-level mux telemetry. Interface diagnostics can",
        "      show configured channels, but CHxx order is not calibrated.",
    ])
    return "\n".join(lines)


def format_interface_optics_mux(xml: str, ifname: str) -> str:
    """Format per-interface optics using PE31625G24DIRA mux telemetry."""
    lines = [f"Physical interface: {ifname}"]
    if ifname_to_mux_optics_mapping is None:
        lines.extend([
            "  Optical diagnostics                       : unavailable",
            "  Reason                                    : platform channel mapping is unavailable",
        ])
        return "\n".join(lines)

    mapping = ifname_to_mux_optics_mapping(ifname)
    if not mapping:
        lines.extend([
            "  Optical diagnostics                       : unavailable",
            "  Reason                                    : interface has no mux optics mapping",
        ])
        return "\n".join(lines)

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        lines.extend([
            "  Optical diagnostics                       : unavailable",
            "  Reason                                    : mux telemetry RPC returned invalid XML",
        ])
        return "\n".join(lines)
    if root.attrib.get("error"):
        lines.extend([
            "  Optical diagnostics                       : unavailable",
            f"  Reason                                    : mux telemetry error {root.attrib.get('error')}",
        ])
        return "\n".join(lines)

    branch = _optics_mux_branch(root, mapping["mux-value"])
    if branch is None:
        lines.extend([
            "  Optical diagnostics                       : unavailable",
            f"  Reason                                    : mux branch 0x{mapping['mux-value']:02x} not returned",
        ])
        return "\n".join(lines)

    by_key = _optics_mux_addr_map(branch)
    module_eeprom = by_key.get((0x50, -1, 0), [])
    rx_eeprom = by_key.get((0x40, -1, 0), [])
    identity = _fci_identity(module_eeprom) or _standard_identity(module_eeprom)
    module_sensors = _module_sensor_values(module_eeprom)
    rx_sensors = _module_sensor_values(rx_eeprom)
    max_temp_c = _fci_max_temp_c(by_key, module_eeprom)
    rx_values = _fci_rx_power_vector_from_dumps(by_key)
    channels = [ch for ch in mapping["channels"] if 0 <= ch < len(rx_values)]
    if not rx_values or not channels:
        lines.extend([
            "  Optical diagnostics                       : unavailable",
            "  Reason                                    : mux channel RX power is unavailable",
            f"  Mux branch                                : 0x{mapping['mux-value']:02x}",
        ])
        return "\n".join(lines)

    selected_mw = [rx_values[ch] / 10000.0 for ch in channels]
    avg_mw = sum(selected_mw) / len(selected_mw)
    channel_text = ",".join(f"CH{ch:02d}" for ch in channels)

    lines.extend([
        "  Optical diagnostics source                : PE31625G24DIRA mux DOM",
        f"  Module                                    : {mapping['module-index']}",
        f"  Mux branch                                : 0x{mapping['mux-value']:02x}",
        f"  XCVR resource                             : {mapping['resource-id']}",
        f"  Optical channel(s)                        : {channel_text}",
        "  Channel mapping                           : "
        f"{_public_mux_mapping_status(mapping['mapping-status'])} "
        f"({mapping['calibration-status']})",
    ])
    calibration = _mux_module_calibration_context(mapping, channels)
    if calibration["total"]:
        lines.append(
            "  Module calibration coverage               : "
            f"{_mux_coverage_text(calibration)}")
    if calibration["selected_owners"]:
        lines.append(
            "  Selected channel mapping                  : "
            f"{', '.join(calibration['selected_owners'])}")
    if identity:
        lines.extend([
            f"  Vendor name                               : {identity.get('vendor-name') or '-'}",
            f"  Vendor PN                                 : {identity.get('vendor-pn') or '-'}",
            f"  Vendor SN                                 : {identity.get('vendor-sn') or '-'}",
        ])
    if module_sensors.get("temperature-c") is not None:
        temp_c = module_sensors["temperature-c"]
        lines.append(
            "  Module temperature                        : "
            f"{temp_c:.1f} degrees C / {temp_c * 9 / 5 + 32:.1f} degrees F")
    if module_sensors.get("voltage-v") is not None:
        lines.append(
            f"  Module voltage                            : {module_sensors['voltage-v']:.4f} V")
    if rx_sensors.get("voltage-v") is not None:
        lines.append(
            f"  RX-side module voltage                    : {rx_sensors['voltage-v']:.4f} V")
    if max_temp_c is not None:
        lines.append(f"  Module max temperature                    : {max_temp_c} degrees C")
    owners = {}
    ownership_warning = ""
    if not _mux_mapping_is_authoritative(mapping):
        owners = _mux_calibrated_channel_owners(ifname, mapping)
        ownership_warning = _mux_channel_ownership_warning(channels, owners)
    warning = _mux_mapping_warning(rx_values, channels)
    if warning:
        lines.append(f"  Optical channel mapping warning           : {warning}")
    if ownership_warning:
        lines.append(f"  Optical channel mapping warning           : {ownership_warning}")
    if ownership_warning:
        power_line = (
            "  Receiver signal average optical power     : "
            "unavailable (uncalibrated channel is already mapped to an accepted interface)"
        )
    else:
        power_line = (
            f"  Receiver signal average optical power     : "
            f"{avg_mw:.4f} mW / {_mw_to_dbm_text(avg_mw)}"
        )
    lines.extend([
        "  Laser output power                        : unavailable (mux DOM RX-only)",
        power_line,
        "",
        "  Mux channel diagnostics:",
        "    Channel  Raw    RX power",
    ])
    for ch in channels:
        raw = rx_values[ch]
        lines.append(f"    CH{ch:02d}     {raw:<5d}  {_format_rx_power(raw)}")
    if mapping["calibration-status"] == "inferred":
        lines.append("")
        lines.append(
            "  Note: CHxx-to-front-panel order is inferred from the accepted "
            "module sequence and not one-channel calibrated.")
    elif not _mux_mapping_is_authoritative(mapping):
        lines.append("")
        lines.append(
            "  Note: CHxx-to-front-panel order is configured and not one-channel calibrated.")
    return "\n".join(lines)


def format_interface_optics_mux_calibration(optics_xml: str,
                                            interfaces_xml: str = "") -> str:
    """Format a non-destructive mux channel calibration helper."""
    lines = ["Optics mux calibration helper:"]
    if ifname_to_mux_optics_mapping is None or physical_interface_names is None:
        lines.extend([
            "  Status : unavailable",
            "  Reason : platform channel mapping is unavailable",
        ])
        return "\n".join(lines)

    try:
        root = ET.fromstring(optics_xml)
    except ET.ParseError:
        lines.extend([
            "  Status : unavailable",
            "  Reason : mux telemetry RPC returned invalid XML",
        ])
        return "\n".join(lines)
    if root.attrib.get("error"):
        lines.extend([
            "  Status : unavailable",
            f"  Reason : mux telemetry error {root.attrib.get('error')}",
        ])
        return "\n".join(lines)

    link_states = _interface_link_states(interfaces_xml)
    names = physical_interface_names()
    module_ports = {}
    module_link_up = {}
    module_mapping_by_name = {}
    for name in names:
        mapping = ifname_to_mux_optics_mapping(name)
        if not mapping:
            continue
        module = mapping["module-index"]
        channel_text = ",".join(f"CH{ch:02d}" for ch in mapping["channels"])
        module_ports.setdefault(module, []).append(
            (name, channel_text, mapping["calibration-status"]))
        module_mapping_by_name.setdefault(module, {})[name] = mapping
        if link_states.get(name) == "up":
            module_link_up.setdefault(module, []).append(name)

    lines.extend([
        "  Mode   : read-only",
        "  Method : compare configured ports with live strong RX channels",
        "  Caveat : candidate maps are hints only; confirm by one known link at a time",
    ])

    for branch in root.findall("branch"):
        module, ports_hint = _optics_mux_branch_hint(_attr(branch, "value"))
        try:
            module_index = int(module)
        except (TypeError, ValueError):
            module_index = -1
        by_key = _optics_mux_addr_map(branch)
        rx_values = _fci_rx_power_vector_from_dumps(by_key)
        strong = _mux_strong_channels(rx_values)
        link_up = module_link_up.get(module_index, [])
        profile_rows = module_ports.get(module_index, [])
        module_mappings = module_mapping_by_name.get(module_index, {})
        calibrated_owners = _mux_calibrated_channel_owner_map(module_mappings)
        ownership_conflicts = _mux_uncalibrated_channel_conflicts(
            module_mappings, calibrated_owners)
        calibrated_rows = [
            name for name, _channels, status in profile_rows
            if _mux_status_is_authoritative(status)
        ]
        measured_rows = [
            name for name, _channels, status in profile_rows
            if status == "calibrated"
        ]
        inferred_rows = [
            name for name, _channels, status in profile_rows
            if status == "inferred"
        ]
        uncalibrated_rows = [
            name for name, _channels, status in profile_rows
            if not _mux_status_is_authoritative(status)
        ]
        coverage = {
            "calibrated": len(calibrated_rows),
            "measured": len(measured_rows),
            "inferred": len(inferred_rows),
            "total": len(profile_rows),
        }
        owner_label = (
            "Accepted channels" if inferred_rows else "Calibrated channels")

        lines.extend([
            "",
            f"Module {module} (mux {_attr(branch, 'value')}, ports {ports_hint})",
            f"  Calibration coverage: {_mux_coverage_text(coverage)}",
            "  Uncalibrated ports : " +
            (", ".join(uncalibrated_rows) if uncalibrated_rows else "none"),
            "  Strong RX channels : " +
            (", ".join(f"CH{ch:02d} {_format_rx_power(rx_values[ch])}"
                       for ch in strong) if strong else "none"),
            "  Link-up ports      : " +
            (", ".join(link_up) if link_up else "none"),
            "  Configured map     : " +
            (", ".join(f"{name}->{channels}"
                       f"{' ' + status if _mux_status_is_authoritative(status) else ''}"
                       for name, channels, status in profile_rows)
             if profile_rows else "-"),
            f"  {owner_label}: " +
            (", ".join(_mux_channel_owner_rows(calibrated_owners))
             if calibrated_owners else "none"),
            "  Mapping conflicts  : " +
            (", ".join(ownership_conflicts) if ownership_conflicts else "none"),
        ])
        profile_flat = []
        profile_pairs = []
        profile_all_calibrated = bool(link_up)
        for name in sorted(link_up):
            mapping = module_mappings.get(name)
            if not mapping or not _mux_mapping_is_authoritative(mapping):
                profile_all_calibrated = False
                break
            for channel in mapping.get("channels") or []:
                profile_flat.append(channel)
                profile_pairs.append((name, channel))
        profile_match = False
        uncalibrated_link_up = _mux_uncalibrated_link_up_ports(
            link_up, module_mappings)
        discoverable_strong = _mux_discoverable_strong_channels(
            strong, calibrated_owners)
        if (profile_all_calibrated and profile_flat and strong and
                sorted(profile_flat) == strong):
            profile_match = True
            detail = "live strong channels"
            if len(profile_flat) == len(strong):
                if profile_flat == strong:
                    detail = "candidate order"
                elif profile_flat == list(reversed(strong)):
                    detail = "reverse candidate order"
            match_label = (
                "accepted mappings" if inferred_rows else "calibrated overrides")
            lines.append(
                f"  Mapping match     : {match_label} match {detail}")
            calibrated = ", ".join(
                f"{name}->CH{channel:02d}" for name, channel in profile_pairs)
            map_label = "Accepted map" if inferred_rows else "Calibrated map"
            lines.append(f"  {map_label:<18}: {calibrated}")
            if inferred_rows:
                lines.append(
                    "  Candidate map     : not needed (configured mappings are accepted)")
            else:
                lines.append(
                    "  Candidate map     : not needed (calibrated mappings are active)")
        elif (discoverable_strong and uncalibrated_link_up and
              len(discoverable_strong) == len(uncalibrated_link_up)):
            forward = ", ".join(f"{name}->CH{ch:02d}"
                                for name, ch in zip(uncalibrated_link_up,
                                                    discoverable_strong))
            reverse = ", ".join(f"{name}->CH{ch:02d}"
                                for name, ch in zip(
                                    uncalibrated_link_up,
                                    reversed(discoverable_strong)))
            lines.append(f"  Candidate map     : {forward}")
            if len(discoverable_strong) > 1:
                lines.append(f"  Reverse candidate : {reverse}")
            else:
                name = uncalibrated_link_up[0]
                channel = discoverable_strong[0]
                mapping = module_mappings.get(name) or {}
                channel_owners = [
                    owner for owner in calibrated_owners.get(channel, [])
                    if owner != name
                ]
                if channel_owners:
                    lines.append(
                        "  Mapping update hint: blocked; "
                        f"CH{channel:02d} is already calibrated to "
                        f"{','.join(sorted(channel_owners))}")
                elif (not _mux_mapping_is_authoritative(mapping) or
                      mapping.get("channels") != [channel]):
                    lines.append(
                        f"  Mapping update hint: set {name} mux-channel={channel}")
        elif (strong and uncalibrated_link_up and len(strong) == 1 and
              len(uncalibrated_link_up) == 1 and
              calibrated_owners.get(strong[0])):
            name = uncalibrated_link_up[0]
            channel = strong[0]
            lines.append(f"  Candidate map     : {name}->CH{channel:02d}")
            channel_owners = [
                owner for owner in calibrated_owners.get(channel, [])
                if owner != name
            ]
            if channel_owners:
                lines.append(
                    "  Mapping update hint: blocked; "
                    f"CH{channel:02d} is already calibrated to "
                    f"{','.join(sorted(channel_owners))}")
        elif strong and link_up and len(strong) == len(link_up):
            forward = ", ".join(f"{name}->CH{ch:02d}"
                                for name, ch in zip(sorted(link_up), strong))
            reverse = ", ".join(f"{name}->CH{ch:02d}"
                                for name, ch in zip(sorted(link_up),
                                                    reversed(strong)))
            lines.append(f"  Candidate map     : {forward}")
            if len(strong) > 1:
                lines.append(f"  Reverse candidate : {reverse}")
        elif strong or link_up:
            lines.append(
                "  Candidate map     : unresolved (strong-channel count and link-up port count differ)")
        else:
            lines.append("  Candidate map     : no active optical signal")

    lines.extend([
        "",
        "Next step: leave exactly one known peer link up on the target module,",
        "rerun this command, then record the observed CHxx mapping in the platform channel mapping.",
    ])
    return "\n".join(lines)


def format_interface_optics_mux_mapping(optics_xml: str,
                                        interfaces_xml: str = "") -> str:
    """Format a compact profile-interface to mux-channel reconciliation table."""
    status = mux_calibration_status(optics_xml, interfaces_xml)
    lines = ["Optics mux interface mapping:"]
    if status.get("status") != "ok":
        lines.extend([
            "  Status : unavailable",
            f"  Reason : {status.get('reason') or 'calibration status unavailable'}",
        ])
        return "\n".join(lines)

    for module in status.get("modules", []):
        lines.extend([
            "",
            f"Module {module.get('module')} "
            f"(mux {module.get('mux')}, ports {module.get('ports_hint')})",
            "Interface       Link  Channels             Mapping        Selected map        RX power                  Use",
        ])
        for row in module.get("interface_map", []):
            ifname = row.get("interface") or "-"
            channel_text = ",".join(
                row.get("channel_names") or
                [f"CH{channel:02d}" for channel in row.get("channels") or []])
            mapping_text = row.get("calibration_status") or "-"
            owner_text = row.get("owner") or "-"
            rx_text = row.get("rx_power") or "-"
            use_text = row.get("use") or "-"
            lines.append(
                f"{_fit(ifname, 15)} "
                f"{_fit('up' if row.get('link') == 'up' else '-', 5)} "
                f"{_fit(channel_text, 20)} "
                f"{_fit(mapping_text, 14)} "
                f"{_fit(owner_text, 18)} "
                f"{_fit(rx_text, 25)} "
                f"{use_text}")

    lines.extend([
        "",
        "Use=authoritative means the interface has a calibrated or accepted inferred mux-channel mapping.",
        "Use=blocked-mapping means the configured channel belongs to another accepted mapped interface.",
    ])
    return "\n".join(lines)


def mux_calibration_check(status, mode):
    failures = []
    if status.get("status") != "ok":
        reason = status.get("reason") or "calibration status unavailable"
        return {"mode": mode, "passed": False, "failures": [reason]}

    for module in status.get("modules", []):
        module_id = module.get("module")
        prefix = f"module {module_id}"
        profile_by_name = {
            row.get("interface"): row
            for row in module.get("profile_map", [])
            if row.get("interface")
        }
        strong = {
            row.get("channel")
            for row in module.get("strong_rx_channels", [])
        }
        conflict_by_name = {}
        for conflict in module.get("ownership_conflicts", []):
            conflict_by_name.setdefault(
                conflict.get("interface"), []).append(conflict)

        for ifname in module.get("link_up_ports", []):
            row = profile_by_name.get(ifname)
            if not row:
                failures.append(f"{prefix}: link-up port {ifname} is missing from configured map")
                continue
            if not _mux_status_is_authoritative(row.get("calibration_status")):
                failures.append(f"{prefix}: link-up port {ifname} is not mux-calibrated")
            conflicts = conflict_by_name.get(ifname, [])
            for conflict in conflicts:
                failures.append(
                    f"{prefix}: link-up port {ifname} reuses "
                    f"{conflict.get('channel_name')} already mapped to "
                    f"{','.join(conflict.get('owners') or [])}")
            if strong:
                for channel in row.get("channels") or []:
                    if channel not in strong:
                        failures.append(
                            f"{prefix}: link-up port {ifname} mapped "
                            f"CH{channel:02d} is not a strong RX channel")

        if mode == "full":
            coverage = module.get("calibration_coverage") or {}
            uncalibrated = coverage.get("uncalibrated_ports") or []
            if uncalibrated:
                failures.append(
                    f"{prefix}: {len(uncalibrated)} uncalibrated ports: "
                    f"{', '.join(uncalibrated)}")
            conflicts = module.get("ownership_conflict_text") or []
            if conflicts:
                failures.append(
                    f"{prefix}: mapping conflicts: {', '.join(conflicts)}")
            if (coverage.get("total", 0) and
                    coverage.get("calibrated") != coverage.get("total")):
                failures.append(
                    f"{prefix}: calibration coverage "
                    f"{coverage.get('calibrated')}/{coverage.get('total')}")

    return {"mode": mode, "passed": not failures, "failures": failures}


def format_interface_optics_mux_calibration_check(optics_xml: str,
                                                  interfaces_xml: str,
                                                  mode: str) -> str:
    """Format active/full mux calibration check output."""
    status = mux_calibration_status(optics_xml, interfaces_xml)
    check = mux_calibration_check(status, mode)
    lines = [
        f"Optics mux calibration check ({mode}): "
        f"{'PASS' if check['passed'] else 'FAIL'}"
    ]
    if mode == "active":
        lines.append("  Scope : currently link-up ports")
    else:
        lines.append("  Scope : all configured mux optics ports")
    for module in status.get("modules", []):
        coverage = module.get("calibration_coverage") or {}
        strong = ", ".join(
            row.get("channel_name", f"CH{row.get('channel', 0):02d}")
            for row in module.get("strong_rx_channels", [])
        ) or "none"
        lines.append(
            f"  Module {module.get('module')} mux {module.get('mux')}: "
            f"coverage {_mux_coverage_text(coverage, unit='ports')}, "
            f"link-up {len(module.get('link_up_ports', []))}, "
            f"strong {strong}")
    if check["failures"]:
        lines.append("")
        lines.append("  Failures:")
        for failure in check["failures"]:
            lines.append(f"    - {failure}")
    return "\n".join(lines)


def _capacity_line(label, used, capacity, free, detail):
    if capacity >= 0:
        used_capacity = f"{used}/{capacity}"
        free_text = str(free if free >= 0 else "-")
    else:
        used_capacity = f"{used}/-"
        free_text = "-"
    return (
        f"  {label:<13} {_fit(used_capacity, 19)} "
        f"{_fit(free_text, 8)} {detail}"
    )


def _public_resource_purpose(name):
    mapping = {
        "acl-policer-owner": "acl-policer",
        "egress-acl-owner": "egress-acl",
        "control-plane-protection": "control-plane-protect",
    }
    if not name:
        return "-"
    return mapping.get(name, name[:-6] if name.endswith("-owner") else name)


def format_pfe_resources(xml: str) -> str:
    """Format show chassis forwarding resources output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if root.attrib.get("status", "0") != "0":
        return f"PFE resources: unavailable (status={root.attrib.get('status')})"

    mac = root.find("mac")
    events = root.find("events")
    event_last = root.find("event-last")
    fm10000_faults = root.find("fm10000-fault-counters")
    fm10000_interrupts = root.find("fm10000-interrupts")
    vlan = root.find("vlan")
    lag = root.find("lag")
    mcast = root.find("multicast")
    storm = root.find("storm-control")
    policer = root.find("policer")
    flow = root.find("flow")
    control = root.find("control-plane")
    flow_owners = root.findall("./flow-owners/owner")
    acl = root.find("acl")
    acl_owners = root.findall("./acl-owners/owner")
    ffu = root.find("ffu")
    l3 = root.find("l3")
    profile = root.find("profile")
    physical = root.find("physical-limits")
    l3_route_slices_disabled = (
        ffu is not None and
        _range_attr(ffu, "ipv4-uc-first", "ipv4-uc-last") == "-" and
        _range_attr(ffu, "ipv4-mc-first", "ipv4-mc-last") == "-" and
        _range_attr(ffu, "ipv6-uc-first", "ipv6-uc-last") == "-" and
        _range_attr(ffu, "ipv6-mc-first", "ipv6-mc-last") == "-"
    )
    l3_route_slices_enabled = ffu is not None and not l3_route_slices_disabled

    def _hex_attr(elem, key):
        value = _attr(elem, key)
        try:
            number = int(value, 0)
        except (TypeError, ValueError):
            return value
        if number < 0:
            return value
        return f"0x{number:x}"

    def _slice_count(first_key, last_key):
        first = _int_attr(ffu, first_key, -1) if ffu is not None else -1
        last = _int_attr(ffu, last_key, -1) if ffu is not None else -1
        return last - first + 1 if first >= 0 and last >= first else 0

    lines = ["PFE forwarding resources:"]
    source = root.attrib.get("source", "-") or "-"
    public_source = "forwarding-plane" if "sdk" in source.lower() else source
    model = root.attrib.get("model", "-") or "-"
    profile_path = root.attrib.get("profile", "-") or "-"
    platform_mode = "configured" if profile_path not in ("", "-") else "-"
    lines.extend([
        f"  Source : {public_source}",
        f"  Model         : {model}",
        f"  Platform mode : {platform_mode}",
    ])
    if profile is not None:
        lines.extend([
            "",
            "Inventory:",
            "  Ports  Switches  Lanes  XCVRs  Max AE",
            f"  {_attr(profile, 'ports'):<5}  {_attr(profile, 'switches'):<8}  "
            f"{_attr(profile, 'lanes'):<5}  {_attr(profile, 'xcvrs'):<5}  "
            f"{_attr(profile, 'max-ae')}",
        ])
    if physical is not None:
        lines.extend([
            "",
            "Physical ceilings:",
            f"  Board              : {_attr(physical, 'board')}",
            f"  Shared memory      : {_attr(physical, 'shared-memory-bytes')} bytes",
            f"  TCAM entries       : {_attr(physical, 'tcam-entries')} "
            f"({_attr(physical, 'tcam-capacity-status')})",
            f"  MAC/NextHop entries: {_attr(physical, 'mac-nexthop-entries')} "
            f"({_attr(physical, 'mac-capacity-status')})",
        ])

    telemetry_lines = []

    lines.extend([
        "",
        "L2 tables:",
        "  Resource             Used/Capacity       Util    Detail",
    ])
    if mac is not None:
        used, util = _capacity_cells(mac, "used", "capacity")
        lines.append(
            f"  {'MAC table':<20} {_fit(used, 19)} {_fit(util, 7)} "
            f"visible={_attr(mac, 'visible')} dynamic={_attr(mac, 'dynamic')} "
            f"static={_attr(mac, 'static')} reserved={_attr(mac, 'internal')} "
            f"multicast={_attr(mac, 'multicast')} aging={_attr(mac, 'aging-time')}s")
        if _attr(mac, "raw-bytes") != "-":
            lines.append(
                "  "
                f"{'':<20} {'':<19} {'':<7} "
                f"source=FM_MAC_TABLE_SIZE raw-bytes={_attr(mac, 'raw-bytes')} "
                f"entry-size={_attr(mac, 'entry-size')}")
        if _attr(mac, "truncated") == "1":
            lines.append(f"  {'':<20} {'':<19} {'':<7} warning=read-back truncated")
    if events is not None:
        telemetry_lines.append(
            f"  {'ASIC events':<20} {_fit(_attr(events, 'total'), 19)} "
            f"{_fit('-', 7)} port={_attr(events, 'port')} "
            f"mac-updates={_attr(events, 'table-updates')}/"
            f"{_attr(events, 'table-entries')} "
            f"learned={_attr(events, 'table-learned')} "
            f"aged={_attr(events, 'table-aged')} "
            f"errors={_attr(events, 'table-errors')} "
            f"security={_attr(events, 'security')} "
            f"platform={_attr(events, 'platform')} "
            f"parity={_attr(events, 'parity-errors')} "
            f"logical-port={_attr(events, 'logical-port')} "
            f"cable-mismatch={_attr(events, 'cable-mismatch')} "
            f"over-temp={_attr(events, 'over-temp')} "
            f"unsupported={_attr(events, 'unsupported')} "
            f"last={_attr(events, 'last-event')}/"
            f"{_attr(events, 'last-event-name')} "
            f"last-unsupported={_attr(events, 'last-unsupported-event')}/"
            f"{_attr(events, 'last-unsupported-event-name')} "
            f"drops={_attr(events, 'queue-drops')} "
            f"tcn={_attr(events, 'tcn-interrupts')}/"
            f"{_attr(events, 'tcn-pending')} "
            f"overflow={_attr(events, 'tcn-overflow')} "
            f"fifo-errors={_attr(events, 'tcn-fifo-errors')}")
        telemetry_lines.append(
            f"  {'MAC learning diag':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"tcn-learned={_attr(events, 'tcn-learned-events')} "
            f"tcn-moved={_attr(events, 'tcn-moved-events')} "
            f"learned={_attr(events, 'mac-learned-debug')} "
            f"aged={_attr(events, 'mac-aged-debug')} "
            f"port-changed={_attr(events, 'mac-port-changed')} "
            f"discarded={_attr(events, 'mac-learn-discarded')} "
            f"vlan-errors={_attr(events, 'mac-vlan-errors')} "
            f"security={_attr(events, 'mac-security')} "
            f"fifo-service={_attr(events, 'mac-work-service-fifo')} "
            f"fifo-events={_attr(events, 'mac-work-fifo-events')}")
        telemetry_lines.append(
            f"  {'ASIC event detail':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"switch={_attr(events, 'switch-events')} "
            f"frame={_attr(events, 'frame')} "
            f"software={_attr(events, 'software')} "
            f"sflow={_attr(events, 'sflow')} "
            f"fibm={_attr(events, 'fibm-threshold')} "
            f"crm={_attr(events, 'crm')} "
            f"arp={_attr(events, 'arp')} "
            f"purge={_attr(events, 'purge-scan-complete')} "
            f"egress-ts={_attr(events, 'egress-timestamp')} "
            f"enqueued={_attr(events, 'packet-enqueued')}")
    if event_last is not None:
        detail_keys = [
            ("port", "port"),
            ("vlan", "vlan"),
            ("lane", "lane"),
            ("mac", "mac"),
            ("status", "status"),
            ("temperature", "temp"),
            ("crm-id", "crm"),
            ("fibm-retries", "fibm-retries"),
            ("parity-type", "parity-type"),
            ("parity-severity", "parity-severity"),
            ("parity-area", "parity-area"),
            ("parity-status", "parity-status"),
            ("parity-sram", "parity-sram"),
            ("logical-first", "logical-first"),
            ("logical-count", "logical-count"),
            ("logical-pep-id", "pep-id"),
            ("logical-pep-port", "pep-port"),
            ("logical-created", "logical-created"),
            ("platform-type", "platform-type"),
            ("software-events", "software-events"),
            ("switch-slot", "switch-slot"),
            ("arp-sip", "arp-sip"),
            ("arp-dip", "arp-dip"),
            ("arp-ipv6", "arp-ipv6"),
            ("egress-port", "egress-port"),
        ]
        details = [
            f"{label}={_attr(event_last, key)}"
            for key, label in detail_keys
            if _attr(event_last, key) not in ("-", "-1")
        ]
        if details:
            telemetry_lines.append(
                f"  {'ASIC event source':<20} {_fit('-', 19)} {_fit('-', 7)} "
                + " ".join(details))
    if fm10000_faults is not None:
        telemetry_lines.append(
            f"  {'FM10000 faults':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"epl-int={_attr(fm10000_faults, 'epl-interrupts')} "
            f"link={_attr(fm10000_faults, 'link-change-events')} "
            f"link-lost={_attr(fm10000_faults, 'link-change-lost')} "
            f"egress-ts={_attr(fm10000_faults, 'egress-timestamp-events')}/"
            f"{_attr(fm10000_faults, 'egress-timestamp-lost')} "
            f"sram-c/u={_attr(fm10000_faults, 'sram-cerr-interrupts')}/"
            f"{_attr(fm10000_faults, 'sram-uerr-interrupts')} "
            f"parity-lost={_attr(fm10000_faults, 'parity-event-lost')} "
            f"repair-invalid={_attr(fm10000_faults, 'parity-repair-invalid')}")
        telemetry_lines.append(
            f"  {'FM10000 parity':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"area-epl={_attr(fm10000_faults, 'parity-area-epl')} "
            f"area-policer={_attr(fm10000_faults, 'parity-area-policer')} "
            f"policer-u/c={_attr(fm10000_faults, 'parity-area-policer-uerr')}/"
            f"{_attr(fm10000_faults, 'parity-area-policer-cerr')} "
            f"severity-t/r/c/f="
            f"{_attr(fm10000_faults, 'parity-severity-transient')}/"
            f"{_attr(fm10000_faults, 'parity-severity-repairable')}/"
            f"{_attr(fm10000_faults, 'parity-severity-cumulative')}/"
            f"{_attr(fm10000_faults, 'parity-severity-fatal')} "
            f"status-fixed/fail="
            f"{_attr(fm10000_faults, 'parity-status-fixed')}/"
            f"{_attr(fm10000_faults, 'parity-status-fix-failed')}")
    if fm10000_interrupts is not None:
        telemetry_lines.append(
            f"  {'FM10000 interrupts':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"crm-ip={_hex_attr(fm10000_interrupts, 'crm-ip0')}/"
            f"{_hex_attr(fm10000_interrupts, 'crm-ip1')}/"
            f"{_hex_attr(fm10000_interrupts, 'crm-ip2')} "
            f"crm-im={_hex_attr(fm10000_interrupts, 'crm-im0')}/"
            f"{_hex_attr(fm10000_interrupts, 'crm-im1')}/"
            f"{_hex_attr(fm10000_interrupts, 'crm-im2')} "
            f"fibm={_hex_attr(fm10000_interrupts, 'fibm-ip')}/"
            f"{_hex_attr(fm10000_interrupts, 'fibm-im')} "
            f"pcie-clk={_hex_attr(fm10000_interrupts, 'pcie-clk-ip')}/"
            f"{_hex_attr(fm10000_interrupts, 'pcie-clk-im')} "
            f"sbus-pcie={_hex_attr(fm10000_interrupts, 'sbus-pcie-ip')}/"
            f"{_hex_attr(fm10000_interrupts, 'sbus-pcie-im')} "
            f"sram-ip={_hex_attr(fm10000_interrupts, 'sram-err-ip0')}/"
            f"{_hex_attr(fm10000_interrupts, 'sram-err-ip1')} "
            f"trigger-ip={_hex_attr(fm10000_interrupts, 'trigger-ip0')}/"
            f"{_hex_attr(fm10000_interrupts, 'trigger-ip1')}")
        telemetry_lines.append(
            f"  {'FM10000 PCIe/SBUS':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"pcie-xref-hi/lo="
            f"{_hex_attr(fm10000_interrupts, 'pcie-clk-xref-high')}/"
            f"{_hex_attr(fm10000_interrupts, 'pcie-clk-xref-low')} "
            f"pcie-xpll-hi/lo="
            f"{_hex_attr(fm10000_interrupts, 'pcie-clk-xpll-high')}/"
            f"{_hex_attr(fm10000_interrupts, 'pcie-clk-xpll-low')} "
            f"sbus-detect-hi/lo="
            f"{_hex_attr(fm10000_interrupts, 'sbus-pcie-detect-high')}/"
            f"{_hex_attr(fm10000_interrupts, 'sbus-pcie-detect-low')} "
            f"trigger-count={_attr(fm10000_interrupts, 'trigger-pending-count')}")
        telemetry_lines.append(
            f"  {'FM10000 EPL pending':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"epl={_attr(fm10000_interrupts, 'epl-pending-count')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-pending-mask')} "
            f"error={_attr(fm10000_interrupts, 'epl-error-pending-count')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-error-pending-mask')} "
            f"fifo-error={_attr(fm10000_interrupts, 'epl-fifo-error-count')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-fifo-error-mask')}")
        telemetry_lines.append(
            f"  {'FM10000 EPL detail':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"an={_hex_attr(fm10000_interrupts, 'epl-an-pending-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-an-pending-high')} "
            f"link={_hex_attr(fm10000_interrupts, 'epl-link-pending-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-link-pending-high')} "
            f"serdes={_hex_attr(fm10000_interrupts, 'epl-serdes-pending-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-serdes-pending-high')} "
            f"error-int="
            f"{_hex_attr(fm10000_interrupts, 'epl-error-interrupt-mask')}")
        telemetry_lines.append(
            f"  {'FM10000 EPL fifo':<20} {_fit('-', 19)} {_fit('-', 7)} "
            f"jitter-u={_hex_attr(fm10000_interrupts, 'epl-jitter-uerr-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-jitter-uerr-high')} "
            f"jitter-c={_hex_attr(fm10000_interrupts, 'epl-jitter-cerr-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-jitter-cerr-high')} "
            f"rs-saf={_hex_attr(fm10000_interrupts, 'epl-rs-saf-uerr-mask')} "
            f"tx={_hex_attr(fm10000_interrupts, 'epl-fifo-tx-error-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-fifo-tx-error-high')} "
            f"rx={_hex_attr(fm10000_interrupts, 'epl-fifo-rx-error-low')}/"
            f"{_hex_attr(fm10000_interrupts, 'epl-fifo-rx-error-high')}")
    if vlan is not None:
        used, util = _capacity_cells(vlan, "used", "capacity")
        lines.append(
            f"  {'VLAN table':<20} {_fit(used, 19)} {_fit(util, 7)} "
            f"memberships={_attr(vlan, 'memberships')}")
    if lag is not None:
        used, util = _capacity_cells(lag, "used", "capacity")
        lines.append(
            f"  {'LAG groups':<20} {_fit(used, 19)} {_fit(util, 7)} "
            f"members={_attr(lag, 'members')} "
            f"member-capacity={_attr(lag, 'member-capacity')}")
    if mcast is not None:
        used, util = _capacity_cells(mcast, "used", "capacity")
        lines.append(
            f"  {'Multicast groups':<20} {_fit(used, 19)} {_fit(util, 7)} "
            f"listeners={_attr(mcast, 'listeners')} "
            f"listeners-free={_attr(mcast, 'listeners-free', 'unknown')}")
    if storm is not None:
        used, util = _capacity_cells(storm, "used", "capacity")
        lines.append(f"  {'Storm controllers':<20} {_fit(used, 19)} {_fit(util, 7)} -")
    if policer is not None:
        lines.append(f"  {'Policers':<20} {_fit(_attr(policer, 'used'), 19)} {'-':<7} -")

    if telemetry_lines:
        lines.extend([
            "",
            "Event and fault telemetry:",
            "  Counter group        Value               Gate    Detail",
        ])
        lines.extend(telemetry_lines)

    lines.extend([
        "",
        "TCAM and control plane:",
    ])
    if flow is not None:
        free = _attr(flow, "free")
        tables = _attr(flow, "tables")
        if tables in ("0", "-1"):
            lines.extend([
                "  Flow TCAM:",
                "    Tables allocated : 0",
                "    Entries used     : not allocated",
            ])
        else:
            usage, util = _capacity_cells(flow, "used", "capacity")
            lines.extend([
                "  Flow TCAM:",
                f"    Tables allocated : {tables}",
                f"    Entries used     : {usage} ({util})",
                f"    Entries free     : {free}",
            ])
    if flow_owners:
        lines.extend([
            "",
            "  Flow table allocations:",
            "    Table  Purpose               Used/Cap  Util    Detail",
        ])
        for owner in flow_owners:
            table = _attr(owner, "table")
            name = _public_resource_purpose(
                _attr(owner, "name", _attr(owner, "owner")))
            owner_type = _public_resource_purpose(_attr(owner, "owner"))
            usage, util = _capacity_text(_attr(owner, "used"),
                                         _attr(owner, "capacity"))
            detail = (
                f"class={owner_type} free={_attr(owner, 'free')} "
                f"max-actions={_attr(owner, 'max-actions')}")
            if control is not None and table == _attr(control, "table"):
                detail = (
                    f"rules={_attr(control, 'rules')} "
                    f"free={_attr(owner, 'free')}")
            lines.append(
                f"    {table:<6} {_fit(name, 21)} {_fit(usage, 9)} "
                f"{_fit(util, 7)} {detail}")
            if control is not None and table == _attr(control, "table"):
                lines.append(
                    f"    {'':<6} {'':<21} {'':<9} {'':<7} "
                    f"action=drop+count control-plane-protection "
                    f"drops={_attr(control, 'packets')}pkts/"
                    f"{_attr(control, 'octets')}B")
    elif control is not None:
        ctrl_used = _used_from_free(_attr(control, "capacity"),
                                   _attr(control, "free"))
        ctrl_usage, ctrl_util = _capacity_text(ctrl_used,
                                               _attr(control, "capacity"))
        lines.extend([
            "",
            "  Flow table allocations:",
            "    Table  Purpose               Used/Cap  Util    Detail",
            f"    {_attr(control, 'table'):<6} {'control-plane-protect':<21} "
            f"{_fit(ctrl_usage, 9)} {_fit(ctrl_util, 7)} "
            f"rules={_attr(control, 'rules')} free={_attr(control, 'free')}",
            f"    {'':<6} {'':<21} {'':<9} {'':<7} "
            f"action=drop+count control-plane-protection "
            f"drops={_attr(control, 'packets')}pkts/{_attr(control, 'octets')}B",
        ])
    if acl is not None:
        lines.extend([
            "",
            f"  ACL tables: count={_attr(acl, 'count')}",
        ])
    if acl_owners:
        lines.extend([
            "  ACL resource allocations:",
            "    ACL range  Purpose               Rules/ACL  Policers",
        ])
        for owner in acl_owners:
            acl_start = _attr(owner, "acl")
            acl_count = _attr(owner, "acl-count", "1")
            acl_range = acl_start
            try:
                start_i = int(acl_start)
                count_i = int(acl_count)
                if count_i > 1:
                    acl_range = f"{start_i}-{start_i + count_i - 1}"
            except ValueError:
                acl_range = acl_start
            first = _attr(owner, "first-policer")
            count = _attr(owner, "policer-count")
            policers = "-"
            if first not in ("", "-") and count not in ("", "-"):
                try:
                    first_i = int(first)
                    count_i = int(count)
                    last_i = first_i + count_i - 1
                    policers = f"{first_i}-{last_i}"
                except ValueError:
                    policers = f"{first}/{count}"
            purpose = _public_resource_purpose(
                _attr(owner, "name", _attr(owner, "owner")))
            lines.append(
                f"    {_fit(acl_range, 10)} "
                f"{_fit(purpose, 21)} "
                f"{_fit(_attr(owner, 'rules-per-acl', '-'), 9)} "
                f"{policers}")
    if ffu is not None:
        def ffu_route_range(first_name, last_name):
            text = _range_attr(ffu, first_name, last_name)
            if text == "-" and l3_route_slices_disabled:
                return "disabled (L2 mode)"
            return text

        ffu_title = "FFU slice allocation"
        if l3_route_slices_disabled:
            ffu_title += " (L2 mode)"

        lines.extend([
            "",
            f"  {ffu_title}:",
            "    Function        Slice range",
            f"    {'IPv4 unicast':<15} {ffu_route_range('ipv4-uc-first', 'ipv4-uc-last')}",
            f"    {'IPv4 multicast':<15} {ffu_route_range('ipv4-mc-first', 'ipv4-mc-last')}",
            f"    {'IPv6 unicast':<15} {ffu_route_range('ipv6-uc-first', 'ipv6-uc-last')}",
            f"    {'IPv6 multicast':<15} {ffu_route_range('ipv6-mc-first', 'ipv6-mc-last')}",
            f"    {'ACL/filter':<15} {_range_attr(ffu, 'acl-first', 'acl-last')}",
            "    Note: slice ranges describe hardware lookup allocation, not live entry usage.",
        ])
        if l3_route_slices_disabled:
            lines.append(
                "    Note: current platform mode disables L3 route lookups "
                "and reserves FFU for L2 safety/control-plane features.")
    if l3 is not None:
        routes = _int_attr(l3, "routes", 0)
        arp = _int_attr(l3, "arp", 0)
        ecmp = _int_attr(l3, "ecmp-groups", 0)
        route_slices = _int_attr(l3, "route-slices", -1)
        if route_slices < 0:
            route_slices = (
                _slice_count("ipv4-uc-first", "ipv4-uc-last") +
                _slice_count("ipv4-mc-first", "ipv4-mc-last") +
                _slice_count("ipv6-uc-first", "ipv6-uc-last") +
                _slice_count("ipv6-mc-first", "ipv6-mc-last"))
        route_capacity = _int_attr(l3, "route-capacity",
                                   route_slices * 1024)
        route_free = _int_attr(l3, "route-free",
                               max(route_capacity - routes, 0))
        arp_capacity = _int_attr(l3, "arp-capacity", 4096)
        arp_free = _int_attr(l3, "arp-free", max(arp_capacity - arp, 0))
        ecmp_capacity = _int_attr(l3, "ecmp-capacity", 1024)
        ecmp_free = _int_attr(l3, "ecmp-free",
                              max(ecmp_capacity - ecmp, 0))
        lines.extend(["", "L3/FIB:"])
        if l3_route_slices_disabled:
            lines.extend([
                "  State   : disabled by L2 platform mode",
                "  Scope   : route lookups are disabled; ARP/ECMP are ASIC inventory only",
                "  Resource      Used/Capacity       Free     Detail",
                _capacity_line("Routes", routes, route_capacity, route_free,
                               f"disabled route-slices={route_slices} delta={routes}"),
                _capacity_line("ARP entries", arp, arp_capacity, arp_free,
                               f"inventory-only delta={arp}"),
                _capacity_line("ECMP groups", ecmp, ecmp_capacity, ecmp_free,
                               f"inventory-only delta={ecmp}"),
                "  Note    : ARP/ECMP rows are not active L3 forwarding state in this platform mode.",
            ])
        else:
            lines.extend([
                "  Platform mode : L3 route slices enabled",
                "  Resource      Used/Capacity       Free     Detail",
                _capacity_line("Routes", routes, route_capacity, route_free,
                               f"route-slices={route_slices} delta={routes}"),
                _capacity_line("ARP entries", arp, arp_capacity, arp_free,
                               f"delta={arp} asic-inventory"),
                _capacity_line("ECMP groups", ecmp, ecmp_capacity, ecmp_free,
                               f"delta={ecmp} asic-inventory"),
            ])
            if routes == 0 and arp == 0 and ecmp == 0:
                if l3_route_slices_enabled:
                    lines.append(
                        "  State   : route resources reserved; L3 control "
                        "plane not initialized")
                else:
                    lines.append("  State   : not initialized")
    return "\n".join(lines)


def _runtime_mtime(value: str) -> str:
    try:
        ts = int(value)
        if ts <= 0:
            return "-"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (TypeError, ValueError, OSError):
        return "-"


def format_sdk_runtime(xml: str) -> str:
    """Format show chassis forwarding sdk output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if _local_name(root.tag) != "sdk-runtime":
        return xml
    if root.attrib.get("status", "0") != "0":
        return f"SDK runtime: unavailable (status={root.attrib.get('status')})"

    process = root.find("process")
    profile = root.find("profile")
    rdi = root.find("rdi")
    fields = {}
    if rdi is not None:
        for field in rdi.findall("field"):
            fields[field.get("name", "")] = field.get("value", "") or "-"

    lines = [
        "SDK runtime:",
        f"  Process : pid={_attr(process, 'pid')} executable={_attr(process, 'executable')}",
        f"  Profile : {_attr(profile, 'path')} (model={_attr(profile, 'model')})",
        f"  RDI     : {_attr(rdi, 'path')} present={_attr(rdi, 'present')}",
        "",
        "Loaded libraries:",
        "  Library                 Loaded  Path                                      Size        Modified",
    ]
    for lib in root.findall("library"):
        loaded = "yes" if lib.get("loaded") == "true" else "no"
        size = _attr(lib, "size")
        if size != "-":
            size = f"{size}B"
        lines.append(
            f"  {_attr(lib, 'name'):<23} {loaded:<6} "
            f"{_attr(lib, 'path'):<41} "
            f"{size:<11} {_runtime_mtime(_attr(lib, 'mtime'))}")

    lines.extend([
        "",
        "RDI platform fields:",
        "  Field                  Value",
    ])
    for name in ("platformName", "uioDevName", "sharedLibraryName",
                 "sharedLibrary.disable", "msiEnabled", "portIntrGpio",
                 "numPorts", "cpuPort", "mgmtPep"):
        lines.append(f"  {name:<22} {fields.get(name, '-')}")
    executor = root.find("executor")
    if executor is not None:
        lines.extend([
            "",
            "SDK executor queues:",
            "  Prio  Depth  High  Enqueued  Completed  Failed  Timeout  "
            "Wait p95/max (us)  Exec p95/max (us)",
        ])
        for queue in executor.findall("queue"):
            lines.append(
                f"  {_attr(queue, 'priority'):>4}  "
                f"{_attr(queue, 'depth'):>5}  "
                f"{_attr(queue, 'high-watermark'):>4}  "
                f"{_attr(queue, 'enqueued'):>8}  "
                f"{_attr(queue, 'completed'):>9}  "
                f"{_attr(queue, 'failed'):>6}  "
                f"{_attr(queue, 'timed-out'):>7}  "
                f"{_attr(queue, 'wait-p95-us'):>8}/"
                f"{_attr(queue, 'wait-max-us'):<8}  "
                f"{_attr(queue, 'exec-p95-us'):>8}/"
                f"{_attr(queue, 'exec-max-us')}")
    recovery = root.find("port-recovery")
    if recovery is not None:
        lines.extend([
            "",
            "Port recovery:",
            f"  Window  : enabled={_attr(recovery, 'enabled')} "
            f"duration={_attr(recovery, 'window-seconds')}s "
            f"last-poll-age={_attr(recovery, 'last-poll-age')}s "
            f"max-attempts={_attr(recovery, 'max-attempts')}",
            f"  Escalation: {_attr(recovery, 'full-pfe-escalation')}",
            "  Port  State       Attempts  Unknown polls  Last attempt age  "
            "Episode age  Window expired",
        ])
        for port in recovery.findall("port"):
            lines.append(
                f"  {_attr(port, 'id'):>4}  {_attr(port, 'state'):<11} "
                f"{_attr(port, 'attempts'):>8}  "
                f"{_attr(port, 'unknown-polls'):>13}  "
                f"{_attr(port, 'last-attempt-age'):>16}s  "
                f"{_attr(port, 'episode-elapsed-seconds'):>11}s  "
                f"{_attr(port, 'window-expired'):>14}")
    return "\n".join(lines)


def _public_runtime_component(name: str) -> str:
    mapping = {
        "libFocalpointSDK.so": "forwarding-api",
        "libLTPCManagedSwitch.so": "platform-switch",
    }
    return mapping.get(name, name.replace("SDK", "runtime"))


def format_forwarding_runtime(xml: str) -> str:
    """Format public forwarding runtime diagnostics without SDK-specific terms."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if _local_name(root.tag) != "sdk-runtime":
        return xml
    if root.attrib.get("status", "0") != "0":
        return f"Forwarding runtime: unavailable (status={root.attrib.get('status')})"

    process = root.find("process")
    profile = root.find("profile")
    rdi = root.find("rdi")
    fields = {}
    if rdi is not None:
        for field in rdi.findall("field"):
            fields[field.get("name", "")] = field.get("value", "") or "-"

    lines = [
        "Forwarding runtime:",
        f"  Process  : pid={_attr(process, 'pid')} executable={_attr(process, 'executable')}",
        f"  Platform mode: configured (model={_attr(profile, 'model')})",
        f"  Platform : present={_attr(rdi, 'present')}",
        "",
        "Loaded components:",
        "  Component             Loaded  Size        Modified",
    ]
    for lib in root.findall("library"):
        loaded = "yes" if lib.get("loaded") == "true" else "no"
        size = _attr(lib, "size")
        if size != "-":
            size = f"{size}B"
        lines.append(
            f"  {_public_runtime_component(_attr(lib, 'name')):<21} "
            f"{loaded:<6} {size:<11} {_runtime_mtime(_attr(lib, 'mtime'))}")

    lines.extend([
        "",
        "Platform fields:",
        f"  Platform name        : {fields.get('platformName', '-')}",
        f"  Interrupt mode       : msi={fields.get('msiEnabled', '-')}",
        f"  Port count           : {fields.get('numPorts', '-')}",
        f"  CPU port             : {fields.get('cpuPort', '-')}",
        f"  Management endpoint  : {fields.get('mgmtPep', '-')}",
    ])
    executor = root.find("executor")
    if executor is not None:
        lines.extend([
            "",
            "Forwarding executor:",
            "  Prio  Depth  High  Completed  Failed  Timeout  "
            "Wait p95 (us)  Exec p95 (us)",
        ])
        for queue in executor.findall("queue"):
            lines.append(
                f"  {_attr(queue, 'priority'):>4}  "
                f"{_attr(queue, 'depth'):>5}  "
                f"{_attr(queue, 'high-watermark'):>4}  "
                f"{_attr(queue, 'completed'):>9}  "
                f"{_attr(queue, 'failed'):>6}  "
                f"{_attr(queue, 'timed-out'):>7}  "
                f"{_attr(queue, 'wait-p95-us'):>13}  "
                f"{_attr(queue, 'exec-p95-us'):>13}")
    recovery = root.find("port-recovery")
    if recovery is not None:
        lines.extend([
            "",
            "Port recovery:",
            f"  Window  : enabled={_attr(recovery, 'enabled')} "
            f"duration={_attr(recovery, 'window-seconds')}s "
            f"last-poll-age={_attr(recovery, 'last-poll-age')}s "
            f"max-attempts={_attr(recovery, 'max-attempts')}",
            f"  Escalation: {_attr(recovery, 'full-pfe-escalation')}",
        ])
        for port in recovery.findall("port"):
            lines.append(
                f"  Port {_attr(port, 'id')}: {_attr(port, 'state')} "
                f"attempts={_attr(port, 'attempts')} "
                f"episode-age={_attr(port, 'episode-elapsed-seconds')}s "
                f"window-expired={_attr(port, 'window-expired')}")
    return "\n".join(lines)


def format_control_plane_protection(xml: str, punt_xml: str = "") -> str:
    """Format show control-plane protection output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if _local_name(root.tag) != "control-plane-protection":
        return xml
    if root.attrib.get("status", "0") != "0":
        return ("Control-plane protection: unavailable "
                f"(status={root.attrib.get('status')})")

    table = _attr(root, "table")
    capacity = _attr(root, "capacity")
    free = _attr(root, "free")
    used = _used_from_free(capacity, free)
    usage, util = _capacity_text(used, capacity)
    hardware_policers = _attr(root, "policers")
    if hardware_policers in ("", "-"):
        hardware_policers = "none"

    lines = [
        "Control-plane protection:",
        f"  Source : {_public_forwarding_text(_attr(root, 'source'))}",
        f"  TCAM   : table={table} entries={usage} util={util} free={free}",
        f"  Hardware policers: {hardware_policers}",
        "",
        "Classes:",
        "  Class            Protocol          Match                          "
        "Action        Enforcement                                  Counters        State",
    ]

    for cls in root.findall("class"):
        packets = _attr(cls, "packets")
        octets = _attr(cls, "octets")
        if packets == "-" or octets == "-":
            counters = "-"
        else:
            counters = f"{packets}pkts/{octets}B"
        lines.append(
            f"  {_fit(_attr(cls, 'name'), 16)} "
            f"{_fit(_attr(cls, 'protocol'), 17)} "
            f"{_fit(_attr(cls, 'match'), 30)} "
            f"{_fit(_attr(cls, 'action'), 13)} "
            f"{_fit(_attr(cls, 'enforcement'), 44)} "
            f"{_fit(counters, 15)} "
            f"{_attr(cls, 'state')}")

    punt_root = None
    if punt_xml:
        try:
            candidate = ET.fromstring(punt_xml)
            if _local_name(candidate.tag) == "packetd-stats":
                punt_root = candidate
        except ET.ParseError:
            punt_root = None

    lines.extend(["", "CPU punt policers:"])
    if punt_root is None:
        lines.append("  unavailable")
    else:
        policy = punt_root.find("punt-policy")
        classes = policy.findall("class") if policy is not None else []
        if not classes:
            lines.append("  no classes")
        else:
            lines.append(
                "  Class       Protocol  Match               Rate     Burst    Source      Delivered  Drops")
            for cls in classes:
                source = "config" if _attr(cls, "configured") == "true" else "default"
                lines.append(
                    f"  {_fit(_attr(cls, 'name'), 10)} "
                    f"{_fit(_attr(cls, 'protocol'), 9)} "
                    f"{_fit(_attr(cls, 'match'), 19)} "
                    f"{_fit(_attr(cls, 'rate-pps') + 'pps', 8)} "
                    f"{_fit(_attr(cls, 'burst-pkts'), 8)} "
                    f"{_fit(source, 10)} "
                    f"{_fit(_attr(cls, 'delivered'), 10)} "
                    f"{_attr(cls, 'drops')}")
        drops = _attr(punt_root, "rx-policy-drops")
        if drops != "-":
            lines.append(f"  Total policy drops: {drops}")
        tap = punt_root.find("l3-tap")
        if tap is not None:
            lines.extend([
                "",
                "L3 TAP shim:",
                f"  Status      : {_attr(tap, 'status')} "
                f"enabled={_attr(tap, 'enabled')} opened={_attr(tap, 'opened')}",
                f"  Interface   : {_attr(tap, 'ifname')} "
                f"egress-ports={_attr(tap, 'egress-ports')}",
                f"  ASIC->TAP   : rx={_attr(tap, 'rx-to-tap')} "
                f"write-fail={_attr(tap, 'rx-tap-write-fail')}",
                f"  TAP->ASIC   : rx={_attr(tap, 'tx-from-tap')} "
                f"tx={_attr(tap, 'tx-to-asic')} "
                f"no-egress-drop={_attr(tap, 'tx-no-egress-drop')} "
                f"fail={_attr(tap, 'tx-fail')}",
                f"  Reason      : {_attr(tap, 'last-error')}",
            ])

    lines.extend([
        "",
        "Note: IEEE RSTP/LLDP/LACP are trapped to protocol daemons; current "
        "hardware ACL policers protect standard punt classes, Flow TCAM "
        "DROP+COUNT covers non-IEEE private control MACs, and CPU punt "
        "policers limit packetd-to-daemon delivery.",
    ])
    return "\n".join(lines)


def _format_configd_public_capability_status(xml: str) -> str:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if _local_name(root.tag) != "configd-public-capability-status":
        return xml
    cleanup_required = root.attrib.get("cleanup-required", "-")
    replay = root.find("./active-replay")
    replay_admission = replay.attrib.get("admission", "-") if replay is not None else "-"
    replay_reason = replay.attrib.get("reason-code", "-") if replay is not None else "-"
    lines = [
        "Configuration authority:",
        f"  Active commit    : {root.attrib.get('active-commit-id', '-')}",
        f"  Cleanup required : {cleanup_required}",
        f"  Inspection       : {'complete' if root.attrib.get('inspection-complete') == 'true' else 'incomplete'}",
        f"  Active replay    : {replay_admission}",
        f"  Replay reason    : {replay_reason}",
    ]
    closed_roots = root.findall("./closed-roots/closed-root")
    if closed_roots:
        lines.extend(["", "Closed public capability intent:"])
        for closed_root in closed_roots:
            lines.extend([
                f"  Capability : {closed_root.attrib.get('capability-id', '-')}",
                f"  Root       : {closed_root.attrib.get('xpath', '-')}",
                f"  Cleanup    : {closed_root.attrib.get('cleanup-delete-command', '-')}",
            ])
    return "\n".join(lines)


def format_mgmtd_status(xml: str, configd_capability_xml: str = "") -> str:
    """Format show system management output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if _local_name(root.tag) != "mgmtd":
        return xml

    def public_desc(value):
        text = value or "-"
        return re.sub(r"\bhidden\b", "diagnostic", text, flags=re.IGNORECASE)

    lines = [
        "Management daemon:",
        f"  Sessions : total={root.attrib.get('total-sessions', '-')} "
        f"active={root.attrib.get('active-sessions', '-')}",
        f"  Requests : total={root.attrib.get('total-requests', '-')} "
        f"routed={root.attrib.get('routed-requests', '-')} "
        f"denied={root.attrib.get('denied-requests', '-')} "
        f"malformed={root.attrib.get('malformed-requests', '-')} "
        f"backend-errors={root.attrib.get('backend-errors', '-')}",
        f"  Handlers : max-concurrent={root.attrib.get('max-concurrent-handlers', '1')}",
        f"  Audit log: {root.attrib.get('audit-log', '-')}",
    ]

    updated, recovery, supervisor = _supervisor_state()
    if supervisor or recovery:
        try:
            age = int(time.time()) - int(updated)
        except (TypeError, ValueError):
            age = -1
        lines.extend([
            "",
            "Supervisor:",
            f"  State age : {age}s" if age >= 0 else "  State age : -",
        ])
        if recovery:
            lines.extend([
                f"  Recovery  : {recovery.get('status', '-')} "
                f"(generation={recovery.get('generation', '-')} "
                f"phase={recovery.get('phase', '-')})",
                f"  Replay    : {recovery.get('last-replay-status', '-')} "
                f"(generation={recovery.get('last-replay-generation', '-')} "
                f"attempts={recovery.get('replay-attempts', '-')})",
            ])
            if recovery.get("status") == "degraded":
                lines.append(
                    f"  Reason    : {recovery.get('degraded-reason', '-')}")
        lines.append("  Daemon      Status       PID      Restarts  Last restart")
        for entry in supervisor:
            name = entry.get("name", "-")
            status = entry.get("status", "-")
            pid = entry.get("pid", "-")
            restarts = entry.get("restarts", "-")
            last_restart = entry.get("last-restart", "0")
            try:
                last_text = "never" if int(last_restart) <= 0 else (
                    f"{int(time.time()) - int(last_restart)}s ago")
            except (TypeError, ValueError):
                last_text = "-"
            lines.append(
                f"  {name:<10} {status:<12} {pid:<8} {restarts:>8}  {last_text}")

    backends = root.findall("./backends/backend")
    if backends:
        lines.extend([
            "",
            "Backend routes:",
            "  Daemon      ID   Socket   Route    Req    Fail   Last result   Description",
        ])
        for backend in backends:
            name = backend.attrib.get("name", "-")
            daemon_id = backend.attrib.get("daemon", "-")
            socket = ("present" if backend.attrib.get("socket-present") == "true"
                      else "missing")
            route = ("virtual" if backend.attrib.get("virtual") == "true"
                     else "direct")
            requests = backend.attrib.get("requests", "-")
            failures = backend.attrib.get("failures", "-")
            last_result = backend.attrib.get("last-result", "-")
            last_elapsed = backend.attrib.get("last-elapsed-ms", "-")
            last_age = backend.attrib.get("last-age", "-")
            if last_age == "-1":
                last = "never"
            else:
                last = f"{last_result}/{last_elapsed}ms/{last_age}s"
            desc = public_desc(backend.attrib.get("desc", "-"))
            lines.append(
                f"  {name:<10} {daemon_id:<4} {socket:<8} {route:<8} "
                f"{requests:>5}  {failures:>5}  {last:<13} {desc}")

    sessions = root.findall("./recent-sessions/session")
    if sessions:
        lines.extend([
            "",
            "Recent requests:",
            "  ID     User   Daemon      Method Access   Result  Time",
        ])
        for session in sessions[:8]:
            sid = session.attrib.get("id", "-")
            uid = session.attrib.get("uid", "-")
            name = session.attrib.get("name", "-")
            method = session.attrib.get("method", "-")
            access = session.attrib.get("access", "-")
            result = session.attrib.get("result", "-")
            elapsed = session.attrib.get("elapsed-ms", "-")
            lines.append(
                f"  {sid:<6} {uid:<6} {name:<10} {method:<6} "
                f"{access:<8} {result:<7} {elapsed}ms")
    if configd_capability_xml:
        lines.extend([
            "",
            _format_configd_public_capability_status(
                configd_capability_xml),
        ])
    return "\n".join(lines)


def format_switch_config(xml: str) -> str:
    """Format show chassis forwarding config output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if root.attrib.get("status", "0") != "0":
        return f"ASIC switch runtime configuration: unavailable (status={root.attrib.get('status')})"

    lines = ["ASIC switch runtime configuration:"]
    lines.append(
        f"  Source              : {_public_forwarding_text(root.attrib.get('source', '-'))}")
    lines.append("")
    lines.append("Name                         Status  Value")
    for field in root.findall("field"):
        name = _public_forwarding_text(field.attrib.get("name", "-"))
        status = field.attrib.get("status", "ok")
        value = field.attrib.get("value", "-")
        lines.append(f"{name:<28} {status:<7} {value}")
    if len(lines) == 4:
        lines.append("(none)")
    return "\n".join(lines)


def format_pfe_status(json_str):
    try:
        import json
        data = json.loads(json_str)
    except Exception:
        return json_str
    def hard_status(key):
        return "OK" if data.get(key) else "FAIL"

    def optional_status(key):
        value = data.get(key)
        if value is True:
            return "OK"
        if value is False:
            return "N/A"
        return "N/A"

    lines = ["PFE capability status:",
             f"  PFE state      : {data.get('status', '?')}",
             f"  Runtime init   : {data.get('sdk_initialized', '?')}",
             f"  Switch enabled : {data.get('switch_enabled', '?')}",
             "", "  L2 capabilities:"]
    for key in ("port_inventory_ok", "port_programming_ok", "vlan_programming_ok",
                "pvid_programming_ok", "vlan_mode_programming_ok", "readback_verify_ok"):
        lines.append(f"    {key:<25s}: {hard_status(key)}")
    lines.append(""); lines.append("  Operational paths:")
    for key in ("counters_ok", "packet_io_ok"):
        lines.append(f"    {key:<25s}: {hard_status(key)}")
    lines.append(f"    {'transceiver_i2c_ok':<25s}: {optional_status('transceiver_i2c_ok')}")
    if data.get("hw_out_of_sync"):
        lines.extend([
            "",
            "  Warning: forwarding drift detected",
            "    Action: run request system reconcile",
        ])
    return "\n".join(lines)



def format_chassis_alarms(xml: str) -> str:
    try:
        root = ET.fromstring(xml)
    except Exception:
        return xml

    alarms = []
    if root.attrib.get("stale", "").lower() == "true":
        alarms.append(("chassis poll", "stale",
                       "environment inventory is older than its deadline"))

    for source in root.findall("./sources/source"):
        status = source.attrib.get("status", "unknown")
        if status == "ok":
            continue
        name = source.attrib.get("name", "unknown")
        alarms.append((name, status, "sensor source is not healthy"))

    for sensor in root.findall("./sensors/sensor"):
        status = sensor.attrib.get("status", "unknown")
        if status == "ok":
            continue
        if (sensor.attrib.get("class") == "none" and
                sensor.attrib.get("source") == "none"):
            continue
        label = sensor.attrib.get(
            "label", f"sensor-{sensor.attrib.get('id', '?')}")
        source = sensor.attrib.get("source", "unknown")
        sensor_class = sensor.attrib.get("class", "unknown")
        alarms.append((label, status,
                       f"{sensor_class} sensor from {source}"))

    lines = [
        "Chassis alarms:",
        f"  Active alarms : {len(alarms)}",
        "  Source        : chassis environment inventory",
        "  Detail        : show chassis environment",
    ]
    if not alarms:
        lines.extend(["", "No chassis alarms currently active."])
        return "\n".join(lines)

    lines.extend([
        "",
        "  Alarm source                   Status       Detail",
    ])
    for source, status, detail in alarms:
        lines.append(f"  {source:<30s} {status:<12s} {detail}")
    return "\n".join(lines)


def format_chassis_hardware(xml: str) -> str:
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception:
        return xml

    def text(tag):
        node = root.find(tag)
        return (node.text or "").strip() if node is not None and node.text else ""

    def sensor_value(sensor):
        sensor_class = sensor.attrib.get("class", "other")
        thresholds = []
        if sensor_class == "temperature" and sensor.attrib.get("temp"):
            value = f"{sensor.attrib['temp']} C"
            threshold_fields = (("temp-low", "C"), ("temp-high", "C"),
                                ("temp-crit", "C"))
        elif sensor_class == "voltage" and sensor.attrib.get("voltage"):
            value = f"{sensor.attrib['voltage']} V"
            threshold_fields = (("voltage-low", "V"), ("voltage-high", "V"))
        elif sensor_class == "current" and sensor.attrib.get("current"):
            value = f"{sensor.attrib['current']} A"
            threshold_fields = (("current-high", "A"),)
        elif sensor_class == "power" and sensor.attrib.get("power"):
            value = f"{sensor.attrib['power']} W"
            threshold_fields = (("power-cap", "W"), ("power-high", "W"))
        elif sensor_class == "fan" and sensor.attrib.get("fan-rpm"):
            value = f"{sensor.attrib['fan-rpm']} RPM"
            threshold_fields = ()
        elif sensor_class == "status" and sensor.attrib.get("state"):
            value = sensor.attrib["state"]
            threshold_fields = ()
        else:
            raw = sensor.attrib.get("raw", "")
            value = f"unavailable (raw {raw})" if raw else "unavailable"
            threshold_fields = ()
        for key, unit in threshold_fields:
            if sensor.attrib.get(key):
                thresholds.append(f"{key}={sensor.attrib[key]}{unit}")
        return value, thresholds

    def append_sensor_group(title, sensors):
        lines.extend(["", f"  {title}:"])
        if not sensors:
            lines.append("    (none)")
            return
        lines.append("    Sensor                         Source        Status       Value")
        for sensor in sensors:
            label = sensor.attrib.get("label", f"sensor-{sensor.attrib.get('id', '?')}")
            source = sensor.attrib.get("source", "-")
            status = sensor.attrib.get("status", "unknown")
            value, thresholds = sensor_value(sensor)
            lines.append(f"    {label:<30s} {source:<13s} {status:<12s} {value}")
            if thresholds:
                lines.append(f"      thresholds: {' '.join(thresholds)}")

    last_poll = _format_epoch_age(root.attrib.get("last-poll"))
    lines = [
        "Chassis hardware:",
        f"  Name   : {text('name') or '?'}",
        f"  Serial : {text('serial') or '?'}",
        f"  Poll   : {last_poll}",
        "",
        "  Sensor sources:",
    ]
    sources = root.findall("./sources/source")
    if not sources:
        lines.append("    (none)")
    else:
        lines.append("    Source         Status       Sensors")
    for source in sources:
        name = source.attrib.get("name", "?")
        status = source.attrib.get("status", "unknown")
        sensors = source.attrib.get("sensors", "0")
        lines.append(f"    {name:<14s} {status:<12s} {sensors}")

    sensors = root.findall("./sensors/sensor")
    grouped = {
        "temperature": [],
        "voltage": [],
        "current": [],
        "power": [],
        "fan": [],
        "status": [],
        "other": [],
    }
    for sensor in sensors:
        sensor_class = sensor.attrib.get("class", "other")
        if sensor_class not in grouped:
            sensor_class = "other"
        grouped[sensor_class].append(sensor)
    append_sensor_group("Temperature", grouped["temperature"])
    append_sensor_group("Voltage", grouped["voltage"])
    if grouped["current"]:
        append_sensor_group("Current", grouped["current"])
    if grouped["power"]:
        append_sensor_group("Power", grouped["power"])
    if grouped["fan"]:
        append_sensor_group("Fans", grouped["fan"])
    if grouped["status"]:
        append_sensor_group("Board status", grouped["status"])
    if grouped["other"]:
        append_sensor_group("Other sensors", grouped["other"])
    return "\n".join(lines)


def _format_epoch_age(value: str) -> str:
    try:
        ts = int(value)
    except (TypeError, ValueError):
        return "unknown"
    if ts <= 0:
        return "never"
    age = int(time.time()) - ts
    if age < 0:
        return f"{ts}"
    return f"{age}s ago"
