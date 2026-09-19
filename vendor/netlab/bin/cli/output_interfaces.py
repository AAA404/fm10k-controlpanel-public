"""Output formatters for interface show commands."""
import xml.etree.ElementTree as ET

from output_common import (_float_text, _format_bps, _format_pps,
                           _format_rate, _format_speed, _local_name,
                           _mw_to_dbm, _text, _u64, _xcvr_type_name)

try:
    from platform_profile import (ifname_to_optics_lane, ifname_to_xcvr_port,
                                  ifname_to_xcvr_resource)
except Exception:
    ifname_to_optics_lane = None
    ifname_to_xcvr_port = None
    ifname_to_xcvr_resource = None


def format_interfaces_terse(xml: str) -> str:
    """Format show interfaces terse output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    rows = []
    for iface in root.findall("interface"):
        rows.append(
            {
                "Interface": _text(iface, "name") or "-",
                "Admin": _text(iface, "admin") or "-",
                "Link": _text(iface, "link") or "-",
                "Proto": _text(iface, "proto") or "-",
                "Description": _text(iface, "description") or "-",
            }
        )

    columns = ("Interface", "Admin", "Link", "Proto", "Description")
    widths = {}
    for column in columns:
        widths[column] = max([len(column)] + [len(row[column]) for row in rows])

    fmt = (
        f"{{Interface:<{widths['Interface']}}}  "
        f"{{Admin:<{widths['Admin']}}}  "
        f"{{Link:<{widths['Link']}}}  "
        f"{{Proto:<{widths['Proto']}}}  "
        f"{{Description:<{widths['Description']}}}"
    )
    lines = [fmt.format(**{column: column for column in columns}).rstrip()]
    lines.extend(fmt.format(**row).rstrip() for row in rows)
    return "\n".join(lines)


def format_interface_detail(xml: str) -> str:
    """Format show interfaces <if> detail output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    if _local_name(root.tag) == "interfaces":
        return "\n\n".join(_format_one_interface_detail(iface)
                           for iface in root.findall("interface"))
    return _format_one_interface_detail(root)


def _format_one_interface_detail(root) -> str:
    name = _text(root, "name")
    port_id = _text(root, "port-id")
    admin = _text(root, "admin-state")
    link = _text(root, "link-state")
    speed = _text(root, "speed")
    mtu = _text(root, "mtu") or "1514"
    default_speed = _text(root, "default-speed")
    line_rate = _text(root, "line-rate")
    scheduler_speed = _text(root, "scheduler-speed")
    media = _text(root, "media-type")
    role = _text(root, "role")
    interface_type = _text(root, "interface-type")
    ethernet_mode = _text(root, "ethernet-mode")
    capabilities = _text(root, "capabilities")
    fpc = _text(root, "fpc")
    pic = _text(root, "pic")
    port = _text(root, "port")
    switch_index = _text(root, "switch-index")
    port_index = _text(root, "port-index")
    pcie_port = _text(root, "pcie-port")
    epl_port = _text(root, "epl-port")
    hw_resource_id = _text(root, "hw-resource-id")
    front_panel = _text(root, "front-panel-port")
    supported_speeds = _text(root, "supported-speeds")
    l2mode = _text(root, "l2-mode")
    proto = _text(root, "proto")
    aggregate = _text(root, "aggregate")
    hwsync = _text(root, "hw-sync")
    if hwsync == "not-found":
        return f"error: interface {name or '-'} not found"
    enabled = "Enabled" if admin != "down" else "Disabled"
    link_title = link.capitalize() if link else "Unknown"
    flags = "Present"
    if link == "up":
        flags += " Running"
    lines = [
        f"Physical interface: {name}, {enabled}, Physical link is {link_title}",
        f"  Interface index: {port_id or '0'}, SNMP ifIndex: {port_id or '0'}",
        f"  Link-level type: Ethernet, MTU: {mtu}, Speed: {_format_speed(speed)}",
        f"  Device flags   : {flags}",
        f"  Interface flags: SNMP-Traps",
        f"  Link type      : Full-Duplex",
        f"  Port role      : {role or '-'}",
        f"  Media type     : {media or '-'}",
        f"  Front panel    : {front_panel or '-'}",
    ]
    if fpc or pic or port:
        lines.append(f"  Location       : FPC {fpc or '-'} PIC {pic or '-'} Port {port or '-'}")
    if switch_index or port_index:
        lines.append(f"  ASIC mapping   : switch {switch_index or '-'} port-index {port_index or '-'} logical-port {port_id or '-'}")
    if interface_type or ethernet_mode:
        lines.append(f"  Hardware mode  : {interface_type or '-'} / {ethernet_mode or '-'}")
    if ethernet_mode == "AUTODETECT":
        lines.append("  Speed selection: auto")
    if epl_port and epl_port != "-1":
        lines.append(f"  EPL port       : {epl_port}")
    if pcie_port and pcie_port != "-1":
        lines.append(f"  PCIe port      : {pcie_port}")
    if hw_resource_id and hw_resource_id != "-1":
        lines.append(f"  XCVR resource  : {hw_resource_id}")
    if default_speed:
        lines.append(f"  Default speed  : {_format_bps(default_speed)}")
    if line_rate and line_rate != default_speed:
        lines.append(f"  Line rate      : {_format_bps(line_rate)}")
    if scheduler_speed and scheduler_speed != default_speed:
        lines.append(f"  Scheduler speed: {_format_bps(scheduler_speed)}")
    if supported_speeds:
        rendered = ", ".join(_format_bps(x) for x in supported_speeds.split(",") if x)
        lines.append(f"  Supported speeds: {rendered or '-'}")
    if capabilities:
        lines.append(f"  Capabilities   : {capabilities}")
    if proto:
        lines.append(f"  Protocol        : {proto}")
    if aggregate:
        lines.append(f"  Aggregate       : {aggregate}")
    if l2mode and l2mode != "none":
        lines.append("")
        lines.append(f"  Logical interface {name}.0 (Index {port_id or '0'}) (SNMP ifIndex {port_id or '0'})")
        lines.append("    Flags: Up SNMP-Traps Encapsulation: Ethernet-Bridge")
        lines.append(f"    Protocol eth-switching, Interface mode: {l2mode}")
    lines.append(f"  Hardware state : {hwsync}")
    return "\n".join(lines)


def format_interface_optics(xml: str, ifname: str = "") -> str:
    """Format show interfaces diagnostics optics output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml

    port = root.attrib.get("port", "")
    name = ifname or f"port {port}"
    error = root.attrib.get("error")
    lines = [f"Physical interface: {name}"]

    if error is not None:
        lines.append(f"  Optical diagnostics                       : unavailable (error={error})")
        return "\n".join(lines)

    present = _text(root, "present")
    if present != "1":
        lines.append("  Optical diagnostics                       : transceiver not present")
        return "\n".join(lines)
    dom_valid = _text(root, "dom-valid")
    if dom_valid == "0":
        lines.append("  Optical diagnostics                       : unavailable (DOM read failed)")
        return "\n".join(lines)

    temp = _float_text(_text(root, "temp"))
    voltage = _float_text(_text(root, "voltage"))
    lanes = root.findall("lane")
    selected_lane = _selected_optics_lane(ifname)
    selected_lane_node = None
    if selected_lane is not None:
        for lane in lanes:
            if lane.attrib.get("id") == str(selected_lane):
                selected_lane_node = lane
                break

    module_tx_bias = _float_text(_text(root, "tx-bias"))
    module_tx_power = _float_text(_text(root, "tx-power"))
    module_rx_power = _float_text(_text(root, "rx-power"))
    selected_tx_bias = module_tx_bias
    selected_tx_power = module_tx_power
    selected_rx_power = module_rx_power
    if selected_lane_node is not None:
        selected_tx_bias = _float_text(_text(selected_lane_node, "tx-bias"))
        selected_tx_power = _float_text(_text(selected_lane_node, "tx-power"))
        selected_rx_power = _float_text(_text(selected_lane_node, "rx-power"))

    lines.append(f"  Module type                               : {_xcvr_type_name(_text(root, 'type'))}")
    resource = _profile_xcvr_resource(ifname)
    if resource is not None and resource >= 0:
        lines.append(f"  XCVR resource                             : {resource}")
    query_port = _profile_xcvr_query_port(ifname)
    if query_port is not None and query_port > 0:
        lines.append(f"  XCVR query port                           : {query_port}")
    if selected_lane is not None:
        lines.append(f"  Selected optical lane                     : {selected_lane}")
    lines.append(f"  Module temperature                        : {temp:.1f} degrees C / {temp * 9 / 5 + 32:.1f} degrees F")
    lines.append(f"  Module voltage                            : {voltage:.4f} V")
    lines.append(f"  Laser bias current                        : {module_tx_bias:.2f} mA")
    lines.append(f"  Laser output power                        : {_format_optical_power(module_tx_power, 'no light')}")
    lines.append(f"  Receiver signal average optical power     : {_format_optical_power(module_rx_power, 'no signal')}")
    if selected_lane_node is not None:
        lines.append(f"  Selected lane laser bias current          : {selected_tx_bias:.2f} mA")
        lines.append(f"  Selected lane laser output power          : {_format_optical_power(selected_tx_power, 'no light')}")
        lines.append(f"  Selected lane receiver optical power      : {_format_optical_power(selected_rx_power, 'no signal')}")
    if lanes:
        lines.append("")
        mismatch = _selected_lane_mapping_mismatch(selected_lane_node, lanes)
        visible_lanes = lanes if mismatch else (
            [selected_lane_node] if selected_lane_node is not None else lanes)
        if mismatch:
            lines.append(
                "  Optical lane mapping warning             : "
                "selected DOM lane is dark while another lane reports signal")
            lines.append("  Lane diagnostics:")
        elif selected_lane_node is not None:
            lines.append("  Selected lane diagnostics:")
        else:
            lines.append("  Lane diagnostics:")
        for lane in visible_lanes:
            if lane is None:
                continue
            lane_id = lane.attrib.get("id", "?")
            lane_bias = _float_text(_text(lane, "tx-bias"))
            lane_tx = _float_text(_text(lane, "tx-power"))
            lane_rx = _float_text(_text(lane, "rx-power"))
            lines.append(
                f"    Lane {lane_id}: bias {lane_bias:.2f} mA, "
                f"tx {_format_optical_power(lane_tx, 'no light')}, "
                f"rx {_format_optical_power(lane_rx, 'no signal')}")
    return "\n".join(lines)


def _format_optical_power(mw, zero_text):
    if mw <= 0:
        return f"{mw:.4f} mW / {zero_text}"
    return f"{mw:.4f} mW / {_mw_to_dbm(mw)} dBm"


def _selected_optics_lane(ifname):
    if not ifname or ifname_to_optics_lane is None:
        return None
    try:
        return ifname_to_optics_lane(ifname)
    except Exception:
        return None


def _profile_xcvr_resource(ifname):
    if not ifname or ifname_to_xcvr_resource is None:
        return None
    try:
        return ifname_to_xcvr_resource(ifname)
    except Exception:
        return None


def _profile_xcvr_query_port(ifname):
    if not ifname or ifname_to_xcvr_port is None:
        return None
    try:
        return ifname_to_xcvr_port(ifname)
    except Exception:
        return None


def _lane_has_signal(lane):
    if lane is None:
        return False
    return (_float_text(_text(lane, "tx-power")) > 0 or
            _float_text(_text(lane, "rx-power")) > 0)


def _selected_lane_mapping_mismatch(selected_lane_node, lanes):
    if selected_lane_node is None:
        return False
    if _lane_has_signal(selected_lane_node):
        return False
    for lane in lanes:
        if lane is selected_lane_node:
            continue
        if _lane_has_signal(lane):
            return True
    return False


def format_interface_statistics(xml: str) -> str:
    """Format show interfaces statistics output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        return f"Interface statistics unavailable: invalid counters data ({exc})"

    interfaces = root.findall("interface")
    if len(interfaces) == 1:
        return _format_one_interface_statistics(interfaces[0])

    lines = ["Interface               RX packets   TX packets   RX bps      TX bps      RX pps    TX pps    Errors  Drops"]
    for iface in interfaces:
        name = iface.attrib.get("name", "")
        rxp = _text(iface, "rx-packets")
        txp = _text(iface, "tx-packets")
        rxbps = _format_rate(_text(iface, "rx-bps"))
        txbps = _format_rate(_text(iface, "tx-bps"))
        rxpps = _format_pps(_text(iface, "rx-pps"))
        txpps = _format_pps(_text(iface, "tx-pps"))
        errors = _u64(_text(iface, "rx-errors")) + _u64(_text(iface, "tx-errors"))
        drops = _u64(_text(iface, "rx-drops")) + _u64(_text(iface, "tx-drops"))
        lines.append(f"{name:<23} {rxp:>10}   {txp:>10}   {rxbps:>9}   {txbps:>9}   {rxpps:>7}   {txpps:>7}   {errors:>6}  {drops:>5}")
        lines.extend(_format_interface_counter_detail(iface))
    return "\n".join(lines)


def _stat_value(iface, tag):
    return _text(iface, tag) or "0"


def _stat_line(label, value):
    return f"    {label:<18}: {value}"


def _nonzero_counter_lines(iface, fields):
    lines = []
    for label, tag in fields:
        value = _text(iface, tag)
        if value and value != "0":
            lines.append(f"    {label:<24}: {value}")
    return lines


def _format_one_interface_statistics(iface) -> str:
    name = iface.attrib.get("name", "-")
    rx_errors = _u64(_text(iface, "rx-errors"))
    tx_errors = _u64(_text(iface, "tx-errors"))
    rx_drops = _u64(_text(iface, "rx-drops"))
    tx_drops = _u64(_text(iface, "tx-drops"))

    lines = [
        f"Interface statistics: {name}",
        "  Traffic:",
        _stat_line("RX packets", _stat_value(iface, "rx-packets")),
        _stat_line("TX packets", _stat_value(iface, "tx-packets")),
        _stat_line("RX bytes", _stat_value(iface, "rx-bytes")),
        _stat_line("TX bytes", _stat_value(iface, "tx-bytes")),
        "  Rates:",
        _stat_line("RX bps", _format_rate(_text(iface, "rx-bps"))),
        _stat_line("TX bps", _format_rate(_text(iface, "tx-bps"))),
        _stat_line("RX pps", _format_pps(_text(iface, "rx-pps"))),
        _stat_line("TX pps", _format_pps(_text(iface, "tx-pps"))),
        "  Errors and drops:",
        _stat_line("RX errors", str(rx_errors)),
        _stat_line("TX errors", str(tx_errors)),
        _stat_line("RX drops", str(rx_drops)),
        _stat_line("TX drops", str(tx_drops)),
    ]

    packet_breakdown = _nonzero_counter_lines(iface, [
        ("RX unicast", "rx-ucast-packets"),
        ("RX multicast", "rx-mcast-packets"),
        ("RX broadcast", "rx-bcast-packets"),
        ("TX unicast", "tx-ucast-packets"),
        ("TX multicast", "tx-mcast-packets"),
        ("TX broadcast", "tx-bcast-packets"),
    ])
    if packet_breakdown:
        lines.append("  Packet breakdown:")
        lines.extend(packet_breakdown)

    exception_counters = _nonzero_counter_lines(iface, [
        ("RX FCS errors", "rx-fcs-errors"),
        ("RX symbol errors", "rx-symbol-errors"),
        ("RX frame errors", "rx-frame-size-errors"),
        ("RX pause", "rx-pause-packets"),
        ("TX pause", "tx-pause-packets"),
        ("STP drops", "stp-drops"),
        ("VLAN tag drops", "vlan-tag-drops"),
        ("Security violations", "security-violations"),
        ("Flood-control drops", "flood-control-drops"),
        ("Policer drops", "policer-drops"),
        ("TTL drops", "ttl-drops"),
    ])
    if exception_counters:
        lines.append("  Non-zero exception counters:")
        lines.extend(exception_counters)

    return "\n".join(lines)


def _format_interface_counter_detail(iface) -> list:
    name = iface.attrib.get("name", "")
    if not name:
        return []
    fields = [
        ("RX bytes", "rx-bytes"), ("TX bytes", "tx-bytes"),
        ("RX unicast", "rx-ucast-packets"), ("RX multicast", "rx-mcast-packets"),
        ("RX broadcast", "rx-bcast-packets"),
        ("TX unicast", "tx-ucast-packets"), ("TX multicast", "tx-mcast-packets"),
        ("TX broadcast", "tx-bcast-packets"),
        ("RX FCS errors", "rx-fcs-errors"),
        ("RX symbol errors", "rx-symbol-errors"),
        ("RX frame errors", "rx-frame-size-errors"),
        ("RX pause", "rx-pause-packets"), ("TX pause", "tx-pause-packets"),
        ("STP drops", "stp-drops"), ("VLAN tag drops", "vlan-tag-drops"),
        ("Security violations", "security-violations"),
        ("Flood-control drops", "flood-control-drops"),
        ("Policer drops", "policer-drops"), ("TTL drops", "ttl-drops"),
    ]
    chunks = []
    for label, tag in fields:
        value = _text(iface, tag)
        if value and value != "0":
            chunks.append(f"{label}={value}")
    if not chunks:
        return []
    return [f"  Non-zero counters: {', '.join(chunks)}"]
