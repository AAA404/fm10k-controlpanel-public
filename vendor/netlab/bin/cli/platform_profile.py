import os
import shlex


DEFAULT_ROOT = os.environ.get(
    "NETLAB_ROOT",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
)
DEFAULT_PROFILE = os.path.join(DEFAULT_ROOT, "config", "platform",
                               "default.profile")
NETLAB_MAX_AE = 64
SKU_EXTERNAL_BANDWIDTH_LIMITS = {
    "FM10420": 400_000_000_000,
    "FM10840": 600_000_000_000,
}
PROFILE_CANDIDATES = (
    "/var/lib/netlab/platform.profile",
    "/etc/netlab/platform.profile",
    DEFAULT_PROFILE,
)
MUX_CHANNEL_SOURCES = ("calibrated", "inferred-order")


class PlatformProfileError(RuntimeError):
    pass


def _profile_path():
    env = os.environ.get("NETLAB_PLATFORM_PROFILE")
    if env:
        if not os.path.exists(env):
            raise PlatformProfileError(
                f"NETLAB_PLATFORM_PROFILE={env} does not exist")
        return env
    for path in PROFILE_CANDIDATES:
        if os.path.exists(path):
            return path
    raise PlatformProfileError("no platform profile found")


def _parse_kv(tokens):
    out = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key] = value
    return out


def load_profile():
    profile = {"platform": {}, "board": {}, "switches": [], "ports": [], "lanes": [],
               "xcvrs": [], "ffu": {}}
    path = _profile_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                tokens = shlex.split(line, comments=True)
                if not tokens:
                    continue
                if tokens[0] == "platform":
                    profile["platform"].update(_parse_kv(tokens[1:]))
                elif tokens[0] == "board":
                    if profile["board"]:
                        raise PlatformProfileError(
                            f"platform profile {path} has duplicate board records")
                    profile["board"].update(_parse_kv(tokens[1:]))
                elif tokens[0] == "switch":
                    profile["switches"].append(_parse_kv(tokens[1:]))
                elif tokens[0] == "port":
                    profile["ports"].append(_parse_kv(tokens[1:]))
                elif tokens[0] == "lane":
                    profile["lanes"].append(_parse_kv(tokens[1:]))
                elif tokens[0] == "xcvr":
                    profile["xcvrs"].append(_parse_kv(tokens[1:]))
                elif tokens[0] == "ffu":
                    profile["ffu"].update(_parse_kv(tokens[1:]))
    except (OSError, ValueError) as exc:
        raise PlatformProfileError(f"failed to load platform profile {path}: {exc}") from exc
    _validate_profile(profile, path)
    return profile


def _int_field(entry, field, path, context, required=False, default=None):
    value = entry.get(field)
    if value in (None, ""):
        if required:
            raise PlatformProfileError(
                f"platform profile {path} {context} missing {field}")
        return default
    try:
        return int(value, 0)
    except ValueError as exc:
        raise PlatformProfileError(
            f"platform profile {path} {context} has invalid {field} {value}") from exc


def _mux_channel_list(entry, field, path, context, allow_multiple):
    value = entry.get(field)
    if value is None:
        return None

    raw_items = value.split(",")
    if not allow_multiple and len(raw_items) != 1:
        raise PlatformProfileError(
            f"platform profile {path} {context} has invalid {field} {value}: "
            "use exactly one mux channel")

    channels = []
    for raw in raw_items:
        item = raw.strip()
        if not item:
            raise PlatformProfileError(
                f"platform profile {path} {context} has invalid {field} {value}: "
                "empty mux channel")
        try:
            channel = int(item, 0)
        except ValueError as exc:
            raise PlatformProfileError(
                f"platform profile {path} {context} has invalid {field} {item}") from exc
        if channel < 0 or channel > 11:
            raise PlatformProfileError(
                f"platform profile {path} {context} has invalid {field} {channel}: "
                "expected 0..11")
        if channel in channels:
            raise PlatformProfileError(
                f"platform profile {path} {context} has duplicate {field} {channel}")
        channels.append(channel)

    return channels


def _validate_mux_channel_override(entry, path, context):
    has_single = "mux-channel" in entry
    has_multi = "mux-channels" in entry
    source = (entry.get("mux-channel-source") or "").strip().lower()
    if has_single and has_multi:
        raise PlatformProfileError(
            f"platform profile {path} {context} sets both mux-channel and mux-channels")
    if source:
        if not has_single and not has_multi:
            raise PlatformProfileError(
                f"platform profile {path} {context} sets mux-channel-source without mux-channel")
        if source not in MUX_CHANNEL_SOURCES:
            allowed = ",".join(MUX_CHANNEL_SOURCES)
            raise PlatformProfileError(
                f"platform profile {path} {context} has invalid mux-channel-source "
                f"{source}: expected one of {allowed}")
    if has_single:
        _mux_channel_list(entry, "mux-channel", path, context,
                          allow_multiple=False)
    if has_multi:
        _mux_channel_list(entry, "mux-channels", path, context,
                          allow_multiple=True)


def _entry_flags(entry):
    return {flag.strip().lower() for flag in
            (entry.get("flags") or "").split(",") if flag.strip()}


def _entry_capabilities(entry):
    return {cap.strip().upper() for cap in
            (entry.get("capabilities") or "").split(",") if cap.strip()}


def _port_is_external(entry):
    role = (entry.get("role") or "").lower()
    return role == "external" or "external" in _entry_flags(entry)


def _port_budget_speed(entry, path):
    context = f"port {entry.get('name', '?')}"
    speeds = [
        _int_field(entry, "scheduler-speed", path, context, default=0),
        _int_field(entry, "line-rate", path, context, default=0),
        _int_field(entry, "default-speed", path, context, default=0),
    ]
    return max(speeds)


def _validate_bandwidth_budget(profile, path):
    model = (profile.get("platform", {}).get("model") or "").upper()
    limit = SKU_EXTERNAL_BANDWIDTH_LIMITS.get(model)
    if not limit:
        return

    used = sum(_port_budget_speed(entry, path)
               for entry in profile.get("ports", [])
               if _port_is_external(entry))
    if used > limit:
        raise PlatformProfileError(
            f"platform profile {path} external Ethernet bandwidth "
            f"{used} exceeds {model} limit {limit}")


def _slice_pair(profile, first_name, last_name, path):
    ffu = profile.get("ffu", {})
    first = _int_field(ffu, first_name, path, "ffu", default=-1)
    last = _int_field(ffu, last_name, path, "ffu", default=-1)
    return first, last


def _slice_pair_valid(first, last):
    if first == -1 and last == -1:
        return True
    if first < 0 or last < 0:
        return False
    return first <= last <= 31


def _slice_pair_enabled(first, last):
    return first >= 0 and last >= 0


def _slice_pair_overlap(a, b):
    a_first, a_last = a
    b_first, b_last = b
    if not _slice_pair_enabled(a_first, a_last):
        return False
    if not _slice_pair_enabled(b_first, b_last):
        return False
    return a_first <= b_last and b_first <= a_last


def _route_slices_enabled(profile, path):
    route_ranges = (
        _slice_pair(profile, "ipv4-uc-first", "ipv4-uc-last", path),
        _slice_pair(profile, "ipv4-mc-first", "ipv4-mc-last", path),
        _slice_pair(profile, "ipv6-uc-first", "ipv6-uc-last", path),
        _slice_pair(profile, "ipv6-mc-first", "ipv6-mc-last", path),
    )
    return any(_slice_pair_enabled(first, last)
               for first, last in route_ranges)


def _validate_ffu(profile, path):
    ffu = profile.get("ffu", {})
    if not ffu:
        return

    ranges = [
        ("ipv4-unicast", _slice_pair(profile, "ipv4-uc-first",
                                     "ipv4-uc-last", path)),
        ("ipv4-multicast", _slice_pair(profile, "ipv4-mc-first",
                                       "ipv4-mc-last", path)),
        ("ipv6-unicast", _slice_pair(profile, "ipv6-uc-first",
                                     "ipv6-uc-last", path)),
        ("ipv6-multicast", _slice_pair(profile, "ipv6-mc-first",
                                       "ipv6-mc-last", path)),
        ("acl", _slice_pair(profile, "acl-first", "acl-last", path)),
        ("cvlan", _slice_pair(profile, "cvlan-first", "cvlan-last", path)),
        ("bst-routing", _slice_pair(profile, "bst-routing-first",
                                    "bst-routing-last", path)),
    ]

    for name, pair in ranges:
        if not _slice_pair_valid(*pair):
            raise PlatformProfileError(
                f"platform profile {path} has invalid FFU {name} range "
                f"{pair[0]}-{pair[1]}")

    acl_first, acl_last = _slice_pair(profile, "acl-first", "acl-last", path)
    if not _slice_pair_enabled(acl_first, acl_last):
        raise PlatformProfileError(
            f"platform profile {path} FFU allocation must declare ACL range")

    for i, (left_name, left_pair) in enumerate(ranges):
        for right_name, right_pair in ranges[i + 1:]:
            if _slice_pair_overlap(left_pair, right_pair):
                raise PlatformProfileError(
                    f"platform profile {path} FFU {left_name} range "
                    f"{left_pair[0]}-{left_pair[1]} overlaps "
                    f"{right_name} range {right_pair[0]}-{right_pair[1]}")


def _validate_route_capability(profile, path):
    has_route_slices = _route_slices_enabled(profile, path)
    route_capable_ports = [
        entry for entry in profile.get("ports", [])
        if _port_is_external(entry) and
        "ROUTE" in _entry_capabilities(entry)
    ]

    if route_capable_ports and not has_route_slices:
        names = ", ".join(entry.get("name", "?")
                          for entry in route_capable_ports[:4])
        raise PlatformProfileError(
            f"platform profile {path} advertises ROUTE on {names} "
            "but disables all L3 FFU route slices")
    if has_route_slices and not route_capable_ports:
        raise PlatformProfileError(
            f"platform profile {path} enables L3 FFU route slices "
            "but has no external ROUTE-capable ports")


def _validate_board(profile, path):
    board = profile.get("board", {})
    if not board:
        return

    expected_text = {
        "model": "PE31625G24DiRA-MPS",
        "asic": "FM10840",
    }
    for field, expected in expected_text.items():
        if board.get(field) != expected:
            raise PlatformProfileError(
                f"platform profile {path} board {field} must be {expected}")
    if (profile.get("platform", {}).get("model") or "").upper() != "FM10840":
        raise PlatformProfileError(
            f"platform profile {path} board ASIC disagrees with platform model")

    expected_ints = {
        "fci-count": 2,
        "mux-address": 0x58,
        "cpld-ram-address": 0x59,
        "reset-gpio-address": 0x64,
        "fci0-mux": 0x01,
        "fci1-mux": 0x02,
        "environment-mux": 0x04,
        "power-mux": 0x08,
        "shared-memory-bytes": 4 * 1024 * 1024,
        "tcam-entries": 32768,
        "mac-nexthop-entries": 16384,
    }
    for field, expected in expected_ints.items():
        actual = _int_field(board, field, path, "board", required=True)
        if actual != expected:
            raise PlatformProfileError(
                f"platform profile {path} board {field} must be {expected}")
    bus = _int_field(board, "i2c-bus", path, "board", required=True)
    if bus < 0:
        raise PlatformProfileError(
            f"platform profile {path} board has invalid i2c-bus {bus}")
    mux_values = [
        _int_field(board, field, path, "board", required=True)
        for field in ("fci0-mux", "fci1-mux", "environment-mux", "power-mux")
    ]
    if len(set(mux_values)) != len(mux_values):
        raise PlatformProfileError(
            f"platform profile {path} board has duplicate mux branches")


def _validate_profile(profile, path):
    platform = profile.get("platform", {})
    required = ("model", "system-name", "system-mac")
    missing = [name for name in required if not platform.get(name)]
    if missing:
        raise PlatformProfileError(
            f"platform profile {path} missing {', '.join(missing)}")
    if not profile.get("ports"):
        raise PlatformProfileError(f"platform profile {path} has no ports")

    _validate_board(profile, path)

    seen_switch_indexes = set()
    seen_switch_numbers = set()
    cpu_ports = set()
    for entry in profile.get("switches", []):
        index = _int_field(entry, "index", path, "switch", required=True)
        number = _int_field(entry, "number", path, f"switch {index}",
                            default=index)
        cpu_port = _int_field(entry, "cpu-port", path, f"switch {index}",
                              default=-1)
        if index < 0 or number < 0:
            raise PlatformProfileError(
                f"platform profile {path} has invalid switch index/number")
        if index in seen_switch_indexes:
            raise PlatformProfileError(
                f"platform profile {path} duplicates switch index {index}")
        if number in seen_switch_numbers:
            raise PlatformProfileError(
                f"platform profile {path} duplicates switch number {number}")
        if cpu_port > 0:
            cpu_ports.add(cpu_port)
        seen_switch_indexes.add(index)
        seen_switch_numbers.add(number)

    seen_xcvrs = set()
    xcvr_mux_values = {}
    for entry in profile.get("xcvrs", []):
        rid = _int_field(entry, "resource-id", path, "xcvr", required=True)
        mux_value = _int_field(entry, "mux-value", path,
                               f"xcvr {rid}", default=-1)
        if rid < 0:
            raise PlatformProfileError(
                f"platform profile {path} has invalid xcvr resource-id {rid}")
        if rid in seen_xcvrs:
            raise PlatformProfileError(
                f"platform profile {path} duplicates xcvr resource-id {rid}")
        seen_xcvrs.add(rid)
        xcvr_mux_values[rid] = mux_value

    seen_names = set()
    seen_ports = set()
    seen_port_indexes = set()
    mux_channel_owners = {}
    for entry in profile["ports"]:
        name = entry.get("name")
        logical = entry.get("logical-port")
        if not name or not logical:
            raise PlatformProfileError(
                f"platform profile {path} has a port without name/logical-port")
        logical_int = _int_field(entry, "logical-port", path, f"port {name}",
                                 required=True)
        if logical_int <= 0:
            raise PlatformProfileError(
                f"platform profile {path} has invalid logical-port {logical}")
        switch_index = _int_field(entry, "switch-index", path, f"port {name}",
                                  default=_int_field(entry, "switch-id", path,
                                                     f"port {name}",
                                                     default=0))
        if seen_switch_indexes and switch_index not in seen_switch_indexes:
            raise PlatformProfileError(
                f"platform profile {path} port {name} references missing switch-index {switch_index}")
        port_index = _int_field(entry, "port-index", path, f"port {name}",
                                default=logical_int)
        if port_index < 0:
            raise PlatformProfileError(
                f"platform profile {path} has invalid port-index {port_index}")
        hw_resource_id = _int_field(entry, "hw-resource-id", path,
                                    f"port {name}", default=None)
        if hw_resource_id is not None and hw_resource_id not in seen_xcvrs:
            raise PlatformProfileError(
                f"platform profile {path} port {name} references missing xcvr resource-id {hw_resource_id}")
        _validate_mux_channel_override(entry, path, f"port {name}")
        override = _port_mux_channels_override(entry)
        mux_value = xcvr_mux_values.get(hw_resource_id, -1)
        if override and mux_value > 0:
            for channel in override:
                key = (mux_value, channel)
                owner = mux_channel_owners.get(key)
                if owner:
                    raise PlatformProfileError(
                        f"platform profile {path} port {name} duplicates "
                        f"mux 0x{mux_value:02x} channel {channel} already "
                        f"owned by {owner}")
                mux_channel_owners[key] = name
        xcvr_port = _int_field(entry, "xcvr-port", path,
                               f"port {name}", default=None)
        if xcvr_port is not None and xcvr_port <= 0:
            raise PlatformProfileError(
                f"platform profile {path} port {name} has invalid xcvr-port {xcvr_port}")
        for lane_field in ("dom-lane", "optical-lane", "xcvr-lane"):
            dom_lane = _int_field(entry, lane_field, path,
                                  f"port {name}", default=None)
            if dom_lane is not None and not 1 <= dom_lane <= 4:
                raise PlatformProfileError(
                    f"platform profile {path} port {name} has invalid {lane_field} {dom_lane}")
        if name in seen_names:
            raise PlatformProfileError(
                f"platform profile {path} duplicates interface {name}")
        if logical_int in seen_ports:
            raise PlatformProfileError(
                f"platform profile {path} duplicates logical-port {logical_int}")
        if (switch_index, port_index) in seen_port_indexes:
            raise PlatformProfileError(
                f"platform profile {path} duplicates switch {switch_index} port-index {port_index}")
        if logical_int in cpu_ports and not _port_is_hidden(entry):
            raise PlatformProfileError(
                f"platform profile {path} exposes cpu-port {logical_int} as user interface {name}")
        seen_names.add(name)
        seen_ports.add(logical_int)
        seen_port_indexes.add((switch_index, port_index))

    _validate_bandwidth_budget(profile, path)
    _validate_ffu(profile, path)
    _validate_route_capability(profile, path)

    seen_lanes = set()
    for entry in profile.get("lanes", []):
        ifname = entry.get("ifname") or entry.get("name") or entry.get("interface")
        if not ifname:
            raise PlatformProfileError(
                f"platform profile {path} has a lane without ifname")
        if ifname not in seen_names:
            raise PlatformProfileError(
                f"platform profile {path} lane references missing interface {ifname}")
        switch_index = _int_field(entry, "switch-index", path,
                                  f"lane {ifname}",
                                  default=_int_field(entry, "switch-id", path,
                                                     f"lane {ifname}",
                                                     default=0))
        if seen_switch_indexes and switch_index not in seen_switch_indexes:
            raise PlatformProfileError(
                f"platform profile {path} lane {ifname} references missing switch-index {switch_index}")
        port_index = _int_field(entry, "port-index", path, f"lane {ifname}",
                                default=None)
        if port_index is None:
            for p in profile["ports"]:
                if p.get("name") == ifname:
                    port_index = _int_field(p, "port-index", path,
                                            f"port {ifname}",
                                            default=_int_field(
                                                p, "logical-port", path,
                                                f"port {ifname}",
                                                required=True))
                    break
        lane_index = _int_field(entry, "index", path, f"lane {ifname}",
                                required=True)
        if lane_index < 0:
            raise PlatformProfileError(
                f"platform profile {path} has invalid lane index {lane_index}")
        key = (switch_index, port_index, lane_index)
        if key in seen_lanes:
            raise PlatformProfileError(
                f"platform profile {path} duplicates switch {switch_index} port-index {port_index} lane {lane_index}")
        seen_lanes.add(key)


def aggregate_names():
    profile = load_profile()
    try:
        max_ae = int(profile["platform"].get("max-ae", "0"))
    except ValueError:
        max_ae = 0
    max_ae = min(NETLAB_MAX_AE, max(0, max_ae))
    return [f"ae{i}" for i in range(max_ae)]


def _flags(entry):
    return _entry_flags(entry)


def _port_is_hidden(entry):
    role = (entry.get("role") or "").lower()
    flags = _flags(entry)
    return (role in ("cpu", "control", "cpu-control") or
            "hidden" in flags or "cpu" in flags or
            "control" in flags or "cpu-control" in flags)


def _visible_port_entry(profile, ifname):
    if not ifname:
        return None
    for entry in profile.get("ports", []):
        if _port_is_hidden(entry):
            continue
        if entry.get("name") == ifname:
            return entry
    return None


def _xcvr_resource_entry(profile, resource_id):
    for entry in profile.get("xcvrs", []):
        try:
            if int(entry.get("resource-id", "-1"), 0) == resource_id:
                return entry
        except ValueError:
            continue
    return None


def _resource_ids_for_mux(profile, mux_value):
    out = []
    for entry in profile.get("xcvrs", []):
        try:
            rid = int(entry.get("resource-id", "-1"), 0)
            value = int(entry.get("mux-value", "-1"), 0)
        except ValueError:
            continue
        if value == mux_value and rid >= 0:
            out.append(rid)
    return sorted(set(out))


def _port_mux_channels_override(port):
    text = port.get("mux-channels") or port.get("mux-channel") or ""
    if not text:
        return None
    channels = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            channel = int(item, 0)
        except ValueError:
            return None
        if channel < 0 or channel > 11:
            return None
        channels.append(channel)
    return channels or None


def ifname_to_mux_optics_mapping(ifname):
    """Return profile-derived PE31625G24DIRA mux channel mapping.

    The FCI LOBT module presents 12 optical channels per mux branch. RubyRapid
    profiles model those channels as three QSFP resources per branch, each with
    four lanes. Split 10G/25G ports select one channel; 40G/100G ports consume
    all four channels in their resource group.
    """
    profile = load_profile()
    port = _visible_port_entry(profile, ifname)
    if not port:
        return None

    try:
        resource_id = int(port.get("hw-resource-id", "-1"), 0)
    except ValueError:
        return None
    if resource_id < 0:
        return None

    xcvr = _xcvr_resource_entry(profile, resource_id)
    if not xcvr:
        return None
    try:
        mux_value = int(xcvr.get("mux-value", "-1"), 0)
    except ValueError:
        return None
    if mux_value <= 0:
        return None

    resources = _resource_ids_for_mux(profile, mux_value)
    if resource_id not in resources:
        return None
    resource_slot = resources.index(resource_id)
    channel_base = resource_slot * 4

    capabilities_text = (port.get("capabilities") or "").upper()
    mode_text = (port.get("ethernet-mode") or "").upper()
    is_multi_lane = (
        "100G" in capabilities_text or "40G" in capabilities_text or
        "100G" in mode_text or "40G" in mode_text
    )
    override = _port_mux_channels_override(port)
    if override:
        source = (port.get("mux-channel-source") or "calibrated").strip().lower()
        channels = override
        if source == "inferred-order":
            mapping_status = "profile-inferred"
            calibration_status = "inferred"
        else:
            mapping_status = "profile-override"
            calibration_status = "calibrated"
    elif is_multi_lane:
        source = "profile-derived"
        channels = list(range(channel_base, channel_base + 4))
        mapping_status = "profile-derived"
        calibration_status = "uncalibrated"
    else:
        source = "profile-derived"
        try:
            lane = int(port.get("lane", "0"), 0)
        except ValueError:
            lane = 0
        channels = [channel_base + max(0, min(lane, 3))]
        mapping_status = "profile-derived"
        calibration_status = "uncalibrated"

    mux_values = []
    for x in profile.get("xcvrs", []):
        try:
            value = int(x.get("mux-value", "-1"), 0)
        except ValueError:
            continue
        if value > 0 and value not in mux_values:
            mux_values.append(value)
    mux_values.sort()
    try:
        module_index = mux_values.index(mux_value)
    except ValueError:
        module_index = mux_value - 1

    return {
        "ifname": ifname,
        "module-index": module_index,
        "mux-value": mux_value,
        "resource-id": resource_id,
        "resource-slot": resource_slot,
        "channels": channels,
        "mapping-status": mapping_status,
        "calibration-status": calibration_status,
        "calibration-source": source,
    }


def _cpu_ports(profile):
    out = set()
    for switch in profile.get("switches", []):
        try:
            value = int(switch.get("cpu-port", "-1"), 0)
        except ValueError:
            continue
        if value > 0:
            out.add(value)
    return out


def physical_interface_names():
    profile = load_profile()
    return [p.get("name", "") for p in profile["ports"]
            if p.get("name") and not _port_is_hidden(p)]


def interface_names_with_flag(flag):
    wanted = (flag or "").lower()
    profile = load_profile()
    names = []
    for entry in profile["ports"]:
        if _port_is_hidden(entry):
            continue
        flags = _flags(entry)
        if wanted == "lldp" and "lldp-default" in flags:
            flags.add("lldp")
        if wanted in flags and entry.get("name"):
            names.append(entry.get("name"))
    return names


def port_to_ifname(port):
    try:
        logical = int(port)
    except (TypeError, ValueError):
        return port or "-"
    profile = load_profile()
    if logical in _cpu_ports(profile):
        return str(logical)
    for entry in profile["ports"]:
        if _port_is_hidden(entry):
            continue
        try:
            if int(entry.get("logical-port", "0")) == logical:
                return entry.get("name") or str(logical)
        except ValueError:
            continue
    if logical >= 4096:
        return f"logical-port-{logical}"
    return str(logical)


def ifname_to_port(ifname):
    if not ifname:
        return 0
    entry = _visible_port_entry(load_profile(), ifname)
    if entry:
        try:
            return int(entry.get("logical-port", "0"))
        except ValueError:
            return 0
    try:
        return int(ifname)
    except (TypeError, ValueError):
        return 0


def ifname_to_xcvr_resource(ifname):
    entry = _visible_port_entry(load_profile(), ifname)
    if not entry:
        return -1
    try:
        return int(entry.get("hw-resource-id", "-1"), 0)
    except ValueError:
        return -1


def ifname_to_xcvr_port(ifname):
    """Return the SDK transceiver query id for an interface.

    FM10000 platform XCVR APIs are addressed by SDK port-index in the active
    RDI. In split-port profiles several logical ports may share one XCVR
    resource, so optics must not query by logical-port or raw resource-id.
    """
    entry = _visible_port_entry(load_profile(), ifname)
    if not entry:
        try:
            return int(ifname)
        except (TypeError, ValueError):
            return 0
    try:
        explicit = int(entry.get("xcvr-port", "0"), 0)
        if explicit > 0:
            return explicit
    except ValueError:
        return 0
    try:
        port_index = int(entry.get("port-index", "0"), 0)
        if port_index > 0:
            return port_index
    except ValueError:
        return 0
    return ifname_to_port(ifname)


def ifname_to_optics_lane(ifname):
    entry = _visible_port_entry(load_profile(), ifname)
    if not entry:
        return None

    for field in ("dom-lane", "optical-lane", "xcvr-lane"):
        value = entry.get(field)
        if value in (None, ""):
            continue
        try:
            lane = int(value, 0)
        except ValueError:
            return None
        return lane if 1 <= lane <= 4 else None

    mode = (entry.get("ethernet-mode") or "").lower()
    capability = (entry.get("capabilities") or "").lower()
    if ("25g" not in mode and "25g" not in capability and
            "10g" not in mode and "10g" not in capability):
        return None

    interface_type = entry.get("interface-type") or ""
    if interface_type.startswith("QSFP_LANE"):
        try:
            return int(interface_type[len("QSFP_LANE"):]) + 1
        except ValueError:
            return None
    try:
        return int(entry.get("lane", "")) + 1
    except ValueError:
        return None
