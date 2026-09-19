"""Format L3 operational state."""
import xml.etree.ElementTree as ET

from output_common import _attr, _fit


def _parse(xml):
    try:
        return ET.fromstring(xml)
    except ET.ParseError:
        return None


def _public_l3_text(value):
    if value is None:
        return value
    text = str(value)
    replacements = (
        ("switchd-owner", "switchd forwarding state"),
        ("hardware-owner", "hardware forwarding state"),
        ("persistent SDK owner handle map", "persistent forwarding handle map"),
        ("persistent-owner", "persistent-forwarding-state"),
        ("persistent owner", "persistent forwarding state"),
        ("owner-handle-map", "forwarding-handle-map"),
        ("owner handle map", "forwarding handle map"),
        ("owner read-back", "forwarding read-back"),
        ("owner boundary", "forwarding boundary"),
        ("owner mode", "routing authority"),
        ("owner", "forwarding state"),
        ("Owner", "Forwarding state"),
        ("SDK L3 hardware read-back", "hardware read-back"),
        ("SDK", "hardware"),
        ("sdk", "hardware"),
        ("Hidden", "Diagnostic"),
        ("hidden", "diagnostic"),
        ("profile-open", "platform-open"),
        ("profile-gate", "platform-gate"),
        ("platform profile", "platform mode"),
        ("Platform profile", "Platform mode"),
        ("profile", "platform mode"),
        ("Profile", "Platform mode"),
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def _public_l3_state(value):
    state = _attr(value, "installed-state", None) if hasattr(value, "tag") else value
    return {
        "owner-applied": "installed",
        "pending-owner": "pending-install",
        "owner-pending": "pending-install",
    }.get(state, state if state is not None else "-")


def _public_l3_family(value):
    family = str(value) if value is not None else "-"
    if family == "traffic-owner":
        return "l3-forwarding"
    return _public_l3_text(family)


def _public_l3_gate(value):
    gate = str(value) if value is not None else "-"
    if gate == "NETLAB_ENABLE_L3_SDK_APPLY":
        return "hardware apply gate"
    return _public_l3_text(gate)


def format_rpd_state(xml, view="state"):
    root = _parse(xml)
    if root is None:
        return xml
    if root.tag != "rpd-state":
        return xml

    frr = root.find("frr")
    frr_intent = root.find("frr-intent")
    frr_runtime = root.find("frr-runtime")
    frr_vtysh = root.find("frr-vtysh")
    fpm_listener = root.find("fpm-listener")
    fpm_rif_map = root.find("fpm-rif-map")
    dyn = root.find("dynamic-routing")
    churn = root.find("churn-gate")
    periodic = root.find("periodic-reconcile")
    linux_arp = root.find("linux-arp")
    drift = root.find("drift")
    fib_sync = root.find("fib-sync")
    fib_live = root.find("fib-live")
    rib = root.find("rib")
    if view == "ospf":
        ospf_routes = _attr(rib, "ospf", "0")
        lines = [
            "OSPF neighbor information:",
            f"  State      : {_attr(frr_runtime, 'status', 'gated')}",
            f"  Interfaces : {_attr(frr_intent, 'ospf-interfaces', '0')}",
            f"  Neighbors  : {_attr(frr_vtysh, 'ospf-neighbors', '0')}",
            f"  Full       : {_attr(frr_vtysh, 'ospf-full', '0')}",
            "  Snapshot   : stored="
            + _attr(frr_vtysh, "ospf-neighbor-entries", "0")
            + " total="
            + _attr(frr_vtysh, "ospf-neighbor-total", "0")
            + " complete="
            + _attr(frr_vtysh, "ospf-neighbor-complete", "false")
            + " truncated="
            + _attr(frr_vtysh, "ospf-neighbor-truncated", "false"),
            f"  Routes     : {ospf_routes}",
            "  FRR        : runtime-present="
            + _attr(frr, "runtime-present", "false")
            + " fpm="
            + _attr(fpm_listener, "status", "disabled"),
            "  Source     : vtysh="
            + _attr(frr_vtysh, "status", "unavailable")
            + " queries="
            + _attr(frr_vtysh, "queries", "0")
            + " format="
            + _attr(frr_vtysh, "format", "unknown")
            + " parse-errors="
            + _attr(frr_vtysh, "parse-errors", "0"),
            "  Reason     : " + _attr(frr_vtysh, "reason",
                                      _attr(frr_runtime, "reason",
                                      _attr(dyn, "reason",
                                            "FRR runtime is not open"))),
        ]
        neighbors = (
            frr_vtysh.findall("ospf-neighbor")
            if frr_vtysh is not None else []
        )
        if neighbors:
            lines.extend([
                "",
                "  Neighbor detail:",
                "  Neighbor ID      State       Address         Interface  Dead Time",
            ])
            for nbr in neighbors:
                lines.append(
                    f"  {_attr(nbr, 'id', '-'):<16} "
                    f"{_attr(nbr, 'state', '-'):<11} "
                    f"{_attr(nbr, 'address', '-'):<15} "
                    f"{_attr(nbr, 'interface', '-'):<10} "
                    f"{_attr(nbr, 'dead-time', '-')}")
        return "\n".join(lines)
    if view == "bgp":
        bgp_routes = _attr(rib, "bgp", "0")
        lines = [
            "BGP summary:",
            f"  State      : {_attr(frr_runtime, 'status', 'gated')}",
            f"  Local AS   : {_attr(frr_intent, 'bgp-local-as', '0')}",
            f"  Groups     : {_attr(frr_intent, 'bgp-groups', '0')}",
            f"  Neighbors  : {_attr(frr_intent, 'bgp-neighbors', '0')}",
            f"  Sessions   : {_attr(frr_vtysh, 'bgp-established', '0')}/"
            f"{_attr(frr_vtysh, 'bgp-peers', '0')} established",
            "  Snapshot   : stored="
            + _attr(frr_vtysh, "bgp-peer-entries", "0")
            + " total="
            + _attr(frr_vtysh, "bgp-peer-total", "0")
            + " complete="
            + _attr(frr_vtysh, "bgp-peer-complete", "false")
            + " truncated="
            + _attr(frr_vtysh, "bgp-peer-truncated", "false"),
            f"  Routes     : {bgp_routes}",
            "  FPM        : status="
            + _attr(fpm_listener, "status", "disabled")
            + " updates="
            + _attr(fpm_listener, "route-updates", "0"),
            "  Source     : vtysh="
            + _attr(frr_vtysh, "status", "unavailable")
            + " queries="
            + _attr(frr_vtysh, "queries", "0")
            + " format="
            + _attr(frr_vtysh, "format", "unknown")
            + " parse-errors="
            + _attr(frr_vtysh, "parse-errors", "0"),
            "  Reason     : " + _attr(frr_vtysh, "reason",
                                      _attr(frr_runtime, "reason",
                                      _attr(dyn, "reason",
                                            "FRR runtime is not open"))),
        ]
        peers = (
            frr_vtysh.findall("bgp-peer")
            if frr_vtysh is not None else []
        )
        if peers:
            lines.extend([
                "",
                "  Peer detail:",
                "  Neighbor         AS       State        PfxRcd  Uptime",
            ])
            for peer in peers:
                lines.append(
                    f"  {_attr(peer, 'neighbor', '-'):<16} "
                    f"{_attr(peer, 'remote-as', '-'):<8} "
                    f"{_attr(peer, 'state', '-'):<12} "
                    f"{_attr(peer, 'prefixes', '-'):<6} "
                    f"{_attr(peer, 'uptime', '-')}")
        return "\n".join(lines)

    lines = [
        "RPD state:",
        f"  Table          : {_attr(root, 'table', 'inet.0')}",
        f"  Generation     : {_attr(root, 'generation', '0')}",
        f"  FIB update id  : {_attr(root, 'fib-update-id', '0')}",
        f"  Last tx-id     : {_attr(root, 'last-tx-id', '0')}",
        f"  FRR runtime    : {_attr(frr, 'runtime-present', 'false')}",
        f"  FRR run state  : {_attr(frr_runtime, 'status', 'gated')} "
        f"config={_attr(frr_runtime, 'config-written', 'false')} "
        f"procs={_attr(frr_runtime, 'running-processes', '0')} "
        f"restarts={_attr(frr_runtime, 'restart-events', '0')}",
        f"  FRR vtysh      : {_attr(frr_vtysh, 'status', 'unavailable')} "
        f"ospf={_attr(frr_vtysh, 'ospf-full', '0')}/"
        f"{_attr(frr_vtysh, 'ospf-neighbors', '0')} "
        f"bgp={_attr(frr_vtysh, 'bgp-established', '0')}/"
        f"{_attr(frr_vtysh, 'bgp-peers', '0')} "
        f"complete={_attr(frr_vtysh, 'ospf-neighbor-complete', 'false')}/"
        f"{_attr(frr_vtysh, 'bgp-peer-complete', 'false')} "
        f"format={_attr(frr_vtysh, 'format', 'unknown')} "
        f"parse-errors={_attr(frr_vtysh, 'parse-errors', '0')}",
        f"  FRR config open: {_attr(frr, 'dynamic-config-open', 'false')}",
        f"  FRR gates      : config={_attr(frr_runtime, 'config-gate', 'false')} "
        f"start={_attr(frr_runtime, 'start-gate', 'false')}",
        f"  zebra/ospfd/bgpd: {_attr(frr, 'zebra', 'false')}/"
        f"{_attr(frr, 'ospfd', 'false')}/{_attr(frr, 'bgpd', 'false')}",
        f"  FRR config path: {_attr(frr_runtime, 'config-path', '-')}",
        f"  FRR intent     : {_attr(frr_intent, 'status', 'idle')}",
        f"  OSPF intent    : areas={_attr(frr_intent, 'ospf-areas', '0')} "
        f"interfaces={_attr(frr_intent, 'ospf-interfaces', '0')} "
        f"ifname-maps={_attr(frr_intent, 'ospf-ifname-maps', '0')}",
        f"  BGP intent     : local-as={_attr(frr_intent, 'bgp-local-as', '0')} "
        f"groups={_attr(frr_intent, 'bgp-groups', '0')} "
        f"neighbors={_attr(frr_intent, 'bgp-neighbors', '0')} "
        f"exports={_attr(frr_intent, 'bgp-exports', '0')}",
        f"  Policy intent  : terms={_attr(frr_intent, 'policy-terms', '0')}",
        f"  FPM listener   : {_attr(fpm_listener, 'status', 'disabled')} "
        f"port={_attr(fpm_listener, 'port', '2620')}",
        f"  FPM counters   : frames={_attr(fpm_listener, 'frames', '0')} "
        f"routes={_attr(fpm_listener, 'route-updates', '0')} "
        f"errors={_attr(fpm_listener, 'decode-errors', '0')}/"
        f"{_attr(fpm_listener, 'apply-errors', '0')}",
        f"  FPM deferred   : ignored={_attr(fpm_listener, 'ignored-updates', '0')} "
        f"queued={_attr(fpm_listener, 'deferred-updates', '0')} "
        f"replayed={_attr(fpm_listener, 'deferred-replays', '0')} "
        f"dropped={_attr(fpm_listener, 'deferred-drops', '0')}",
        f"  FPM pending    : frames={_attr(fpm_listener, 'pending-frames', '0')} "
        f"bytes={_attr(fpm_listener, 'pending-bytes', '0')} "
        f"nh-cache={_attr(fpm_listener, 'nh-cache-updates', '0')}/"
        f"{_attr(fpm_listener, 'nh-cache-resets', '0')}/"
        f"{_attr(fpm_listener, 'nh-cache-hits', '0')}/"
        f"{_attr(fpm_listener, 'nh-cache-misses', '0')}",
        f"  FPM RIF map    : {_attr(fpm_rif_map, 'status', 'empty')} "
        f"entries={_attr(fpm_rif_map, 'entries', '0')} "
        f"hits={_attr(fpm_rif_map, 'hits', '0')} "
        f"reason={_public_l3_text(_attr(fpm_rif_map, 'reason', '-'))}",
        f"  Drift         : {_attr(drift, 'state', 'unknown')}",
        f"  Route authority: {_public_l3_text(_attr(drift, 'owner-mode', 'unknown'))}",
        f"  Forwarding state: {_public_l3_text(_attr(drift, 'switchd-owner', 'unknown'))}",
        f"  Last apply ec : {_attr(drift, 'last-owner-ec', '0')}",
        f"  Drift reason  : {_public_l3_text(_attr(drift, 'reason', 'no read-back has run'))}",
        f"  FIB sync      : {_attr(fib_sync, 'state', 'unknown')} "
        f"switchd={_attr(fib_sync, 'switchd-status', 'unknown')} "
        f"routes={_attr(fib_sync, 'routes', '0')}",
        f"  FIB methods   : apply={_attr(fib_sync, 'apply-method', '114')} "
        f"read={_attr(fib_sync, 'readback-method', '115')} "
        f"reconcile={_attr(fib_sync, 'reconcile-method', '116')} "
        f"rollback={_attr(fib_sync, 'rollback-method', '117')}",
        f"  FIB live      : {_attr(fib_live, 'status', 'unknown')} "
        f"gate={_public_l3_gate(_attr(fib_live, 'gate', 'unknown'))} "
        f"ready={_attr(fib_live, 'live-ready', 'false')} "
        f"dynamic={_attr(fib_live, 'dynamic-routes', '0')} "
        f"managed={_attr(fib_live, 'owner-routes', '0')}",
        f"  FIB live miss : {_public_l3_text(_attr(fib_live, 'missing', '-'))}",
        f"  FIB reason    : {_public_l3_text(_attr(fib_sync, 'reason', 'no FIB sync has run'))}",
        f"  FIB live reason: {_public_l3_text(_attr(fib_live, 'reason', '-'))}",
        f"  Dynamic routing: fpm={_attr(dyn, 'fpm', 'planned')} "
        f"ospf={_attr(dyn, 'ospf', 'planned')} "
        f"bgp={_attr(dyn, 'bgp', 'planned')}",
        f"  Linux ARP      : {_attr(linux_arp, 'status', 'disabled')} "
        f"entries={_attr(linux_arp, 'entries', '0')} "
        f"dev={_attr(linux_arp, 'ifname', '-')} "
        f"rif={_attr(linux_arp, 'rif', '-')}",
        f"  Linux ARP reason: {_public_l3_text(_attr(linux_arp, 'reason', '-'))}",
        f"  Churn gate     : {_attr(churn, 'state', 'unknown')} "
        f"used={_attr(churn, 'used', '0')}/"
        f"{_attr(churn, 'max-updates', '0')} "
        f"drops={_attr(churn, 'drops', '0')}",
        f"  Periodic check : runs={_attr(periodic, 'runs', '0')} "
        f"errors={_attr(periodic, 'errors', '0')} "
        f"interval={_attr(periodic, 'interval-ms', '0')}ms",
        f"  Boundary       : {_public_l3_text(_attr(dyn, 'reason', 'FRR FPM consumer is not open'))}",
        f"  FRR reason     : {_public_l3_text(_attr(frr_runtime, 'reason', '-'))}",
    ]
    if rib is not None:
        lines.extend([
            f"  RIB candidates : {_attr(rib, 'candidates', '0')}",
            f"  Best routes    : {_attr(rib, 'best', '0')}",
            f"  RIB protocols  : connected={_attr(rib, 'connected', '0')} "
            f"static={_attr(rib, 'static', '0')} "
            f"ospf={_attr(rib, 'ospf', '0')} bgp={_attr(rib, 'bgp', '0')}",
            f"  RIB ECMP       : routes={_attr(rib, 'ecmp-routes', '0')} "
            f"members={_attr(rib, 'ecmp-members', '0')}",
        ])
        selected = [r for r in rib.findall("route")
                    if _attr(r, "selected", "false") == "true"]
        if selected:
            lines.extend(["", "  Selected RIB routes:",
                          "  Prefix              Proto  Pref Metric NH  State"])
            for route in selected[:8]:
                lines.append(
                    f"  {_attr(route, 'prefix', '-'):<19} "
                    f"{_attr(route, 'protocol', '-'):<6} "
                    f"{_attr(route, 'preference', '0'):>4} "
                    f"{_attr(route, 'metric', '0'):>6} "
                    f"{_attr(route, 'nexthops', '0'):>2}  "
                    f"{_public_l3_state(route)}")
    log = root.find("op-log")
    entries = log.findall("entry") if log is not None else []
    lines.extend([
        f"  Op-log count   : {_attr(log, 'count', str(len(entries)))}",
    ])
    if entries:
        lines.extend(["", "  Recent FIB operations:",
                      "  Update  Age   Action                         Result      Routes"])
        for entry in entries[-8:]:
            lines.append(
                f"  {_attr(entry, 'update-id', '0'):>6}  "
                f"{_attr(entry, 'age', '-'):>4}s  "
                f"{_attr(entry, 'action', '-'):<30} "
                f"{_attr(entry, 'result', '-'):<11} "
                f"{_attr(entry, 'routes', '0'):>6}")
    return "\n".join(lines)


def _rpd_rib(root, table="inet.0"):
    if root is None:
        return None
    for rib in root.findall("rib"):
        if _attr(rib, "table", "inet.0") == table:
            return rib
    return None


def _rpd_arp_table(root):
    rib = _rpd_rib(root)
    return rib.find("arp-table") if rib is not None else None


def _rpd_selected_routes(rib, protocol=None):
    if rib is None:
        return []
    routes = []
    for route in rib.findall("route"):
        if protocol and _attr(route, "protocol") != protocol:
            continue
        if _attr(route, "selected", "false") != "true":
            continue
        routes.append(route)
    return routes


def _int_attr(elem, name, default=None):
    if elem is None:
        return default
    try:
        return int(_attr(elem, name))
    except (TypeError, ValueError):
        return default


def _rpd_fib_synced_route(root, route):
    fib = root.find("fib-sync") if root is not None else None
    if fib is None:
        return False
    if _attr(fib, "state", "unknown") != "ok":
        return False
    if _attr(fib, "switchd-status", "unknown") != "ok":
        return False
    fib_generation = _int_attr(fib, "generation")
    fib_update_id = _int_attr(fib, "fib-update-id")
    route_generation = _int_attr(route, "generation")
    route_update_id = _int_attr(route, "fib-update-id")
    if (fib_generation is None or fib_update_id is None or
            route_generation is None or route_update_id is None):
        return False
    return (route_generation <= fib_generation and
            route_update_id <= fib_update_id)


def _rpd_forwarding_routes(root):
    rib = _rpd_rib(root)
    routes = []
    for route in _rpd_selected_routes(rib):
        state = _attr(route, "installed-state", "")
        protocol = _attr(route, "protocol", "")
        if state == "pending-arp":
            continue
        if protocol in ("connected", "static") and state != "owner-applied":
            continue
        if protocol in ("ospf", "bgp") and state == "pending-fib":
            if not _rpd_fib_synced_route(root, route):
                continue
        routes.append(route)
    return routes


def _rpd_route_nexthop(route):
    nh_count = _attr(route, "nexthops", "0")
    children = route.findall("nexthop")

    if children:
        parts = [
            f"{_attr(nh, 'address', '-')}@{_attr(nh, 'egress-rif', '-')}"
            for nh in children
        ]
        if len(parts) == 1:
            return parts[0]
        return f"ECMP({len(parts)}) {','.join(parts)}"

    key = _attr(route, "ecmp-key", "-")

    if nh_count == "0":
        return "Direct"
    if nh_count == "1":
        return key
    return f"ECMP({nh_count}) {key}"


def format_rpd_route_table(xml, protocol=None, table="inet.0"):
    root = _parse(xml)
    if root is None:
        return xml
    if root.tag != "rpd-state":
        return xml
    rib = _rpd_rib(root, table)
    routes = _rpd_selected_routes(rib, protocol)
    title = table
    if protocol:
        title += f" protocol {protocol}"
    lines = [
        f"{title}:",
        f"  Routes: {len(routes)} active, "
        f"{_attr(rib, 'candidates', '0')} candidates",
    ]
    if not routes:
        lines.append("  No active routes.")
        return "\n".join(lines)
    lines.extend([
        "  Destination        Protocol   Pref  Metric  Next-hop              Interface  State",
    ])
    for route in routes:
        lines.append(
            f"  {_fit(_attr(route, 'prefix'), 18)} "
            f"{_fit(_attr(route, 'protocol'), 10)} "
            f"{_attr(route, 'preference', '0'):>4} "
            f"{_attr(route, 'metric', '0'):>7} "
            f"{_fit(_rpd_route_nexthop(route), 21)} "
            f"{_fit(_attr(route, 'egress-rif'), 10)} "
            f"{_public_l3_state(route)}"
        )
    if _attr(rib, "truncated", "false") == "true":
        lines.append("  Note: RIB route output truncated by emit limit.")
    return "\n".join(lines)


def format_rpd_arp_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    if root.tag != "rpd-state":
        return xml
    table = _rpd_arp_table(root)
    arps = table.findall("arp") if table is not None else []
    lines = [
        "ARP table:",
        "  Table: inet.0",
        f"  Entries: {_attr(table, 'entries', str(len(arps)))}",
    ]
    if not arps:
        lines.append("  No ARP entries.")
        return "\n".join(lines)
    lines.extend([
        "  IP address       MAC address        Interface  Egress       Source  State",
    ])
    for arp in arps:
        lines.append(
            f"  {_fit(_attr(arp, 'ip'), 16)} "
            f"{_fit(_attr(arp, 'mac'), 18)} "
            f"{_fit(_attr(arp, 'rif'), 10)} "
            f"{_fit(_attr(arp, 'egress-port', '-'), 11)} "
            f"{_fit(_attr(arp, 'source', '-'), 7)} "
            f"{_public_l3_state(arp)}"
        )
    if _attr(table, "truncated", "false") == "true":
        lines.append("  Note: ARP output truncated by emit limit.")
    return "\n".join(lines)


def format_rpd_forwarding_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    if root.tag != "rpd-state":
        return xml
    routes = _rpd_forwarding_routes(root)
    fib = root.find("fib-sync")
    lines = [
        "Forwarding table inet.0:",
        f"  FIB sync : {_attr(fib, 'state', 'unknown')} "
        f"switchd={_attr(fib, 'switchd-status', 'unknown')} "
        f"generation={_attr(fib, 'generation', '0')} "
        f"update-id={_attr(fib, 'fib-update-id', '0')}",
    ]
    if not routes:
        lines.append("  No installed forwarding routes.")
        return "\n".join(lines)
    lines.extend([
        "  Destination        Protocol   Next-hop              Interface  Generation  Update",
    ])
    for route in routes:
        lines.append(
            f"  {_fit(_attr(route, 'prefix'), 18)} "
            f"{_fit(_attr(route, 'protocol'), 10)} "
            f"{_fit(_rpd_route_nexthop(route), 21)} "
            f"{_fit(_attr(route, 'egress-rif'), 10)} "
            f"{_attr(route, 'generation', '0'):>10} "
            f"{_attr(route, 'fib-update-id', '0'):>7}"
        )
    return "\n".join(lines)


def format_rpd_route_summary(xml):
    root = _parse(xml)
    if root is None:
        return xml
    if root.tag != "rpd-state":
        return xml
    ribs = root.findall("rib")
    fib = root.find("fib-sync")
    live = root.find("fib-live")
    lines = [
        "L3 route summary:",
        "  RIB     Active  Candidates  Connected  Static  OSPF  BGP  ECMP members",
    ]
    for rib in ribs:
        lines.append(
            f"  {_fit(_attr(rib, 'table', 'inet.0'), 7)} "
            f"{_fit(_attr(rib, 'best', '0'), 6)} "
            f"{_fit(_attr(rib, 'candidates', '0'), 11)} "
            f"{_fit(_attr(rib, 'connected', '0'), 10)} "
            f"{_fit(_attr(rib, 'static', '0'), 6)} "
            f"{_fit(_attr(rib, 'ospf', '0'), 5)} "
            f"{_fit(_attr(rib, 'bgp', '0'), 4)} "
            f"{_attr(rib, 'ecmp-members', '0')}")
    lines.extend([
        "",
        f"  FIB sync : {_attr(fib, 'state', 'unknown')} "
        f"routes={_attr(fib, 'routes', '0')} "
        f"reason={_public_l3_text(_attr(fib, 'reason', '-'))}",
        f"  FIB live : {_attr(live, 'status', 'unknown')} "
        f"gate={_public_l3_gate(_attr(live, 'gate', 'unknown'))} "
        f"ready={_attr(live, 'live-ready', 'false')} "
        f"missing={_public_l3_text(_attr(live, 'missing', '-'))}",
    ])
    return "\n".join(lines)


def _header(root, title):
    state = _attr(root, "state", "unknown")
    mode = _public_l3_text(_attr(root, "mode", "diagnostic"))
    tx_state = _attr(root, "transaction-state", "unknown")
    tx_id = _attr(root, "tx-id", "0")
    rollback = _attr(root, "rollback-available", "false")
    profile = root.find("profile")
    boundary = root.find("boundary")
    reason = _public_l3_text(_attr(
        boundary, "reason", "hardware apply/read-back/rollback not enabled"))
    lines = [
        f"{title}:",
        f"  State          : {state} ({mode})",
        f"  Transaction    : {tx_state} tx-id={tx_id} rollback={rollback}",
        f"  Hardware apply : {_attr(root, 'hardware-apply', 'disabled')}",
        f"  Hardware read-back: {_attr(root, 'sdk-readback', 'disabled')}",
        f"  User config    : {_attr(boundary, 'user-config', 'rejected')}",
    ]
    if profile is not None:
        l3_ready = _attr(profile, "l3-ready", "false")
        route_ports = _attr(profile, "external-route-ports", "0")
        route_slices = _attr(profile, "enabled-route-slices", "0")
        mode = ("L3 route resources ready"
                if l3_ready == "true" else "L3 route resources unavailable")
        lines.append(
            f"  Platform mode  : {mode} "
            f"ports={route_ports} route-slices={route_slices}")
    lines.append(f"  Boundary       : {reason}")
    return lines


def _inventory(root):
    inv = root.find("inventory")
    if inv is None:
        return [], False
    objects = inv.findall("object")
    truncated = inv.find("truncated") is not None or _attr(inv, "complete") == "false"
    return objects, truncated


def _usage(root):
    usage = root.find("usage")
    return {
        "rifs": _attr(usage, "rifs", "0"),
        "arp": _attr(usage, "arp", "0"),
        "next-hops": _attr(usage, "next-hops", "0"),
        "routes": _attr(usage, "routes", "0"),
        "ecmp-groups": _attr(usage, "ecmp-groups", "0"),
        "ecmp-members": _attr(usage, "ecmp-members", "0"),
    }


def _capacity(root):
    cap = root.find("capacity")
    return {
        "rifs": _attr(cap, "rifs", "0"),
        "arp": _attr(cap, "arp", "0"),
        "next-hops": _attr(cap, "next-hops", "0"),
        "routes": _attr(cap, "routes", "0"),
        "route-slices": _attr(cap, "route-slices", "0"),
        "ecmp-groups": _attr(cap, "ecmp-groups", "0"),
        "ecmp-members": _attr(cap, "ecmp-members", "0"),
    }


def _plan(root):
    plan = root.find("plan")
    return {
        "rifs": _attr(plan, "rifs", "0"),
        "arp": _attr(plan, "arp", "0"),
        "next-hops": _attr(plan, "next-hops", "0"),
        "routes": _attr(plan, "routes", "0"),
        "ecmp-groups": _attr(plan, "ecmp-groups", "0"),
    }


def _objects_by_family(objects, family):
    return [obj for obj in objects if _attr(obj, "family") == family]


def _nh_index(objects):
    return {
        _attr(obj, "key"): obj
        for obj in _objects_by_family(objects, "next-hop")
    }


def _ecmp_index(objects):
    return {
        _attr(obj, "key"): obj
        for obj in _objects_by_family(objects, "ecmp")
    }


def _arp_index(objects):
    return {
        _attr(obj, "ip"): obj
        for obj in _objects_by_family(objects, "arp")
    }


def _format_route_target(route, nexthops, ecmp_groups):
    target_type = _attr(route, "target-type")
    target_id = _attr(route, "target-id")
    if target_type == "ecmp":
        ecmp = ecmp_groups.get(target_id)
        members = _attr(ecmp, "members", "-") if ecmp is not None else "-"
        return f"ecmp:{target_id}", members, "-"
    if target_type == "rif":
        return f"rif:{target_id}", "connected", _attr(route, "rif", target_id)
    nh = nexthops.get(target_id)
    if nh is None:
        return f"next-hop:{target_id}", "-", "-"
    return f"next-hop:{target_id}", _attr(nh, "arp"), _attr(nh, "rif")


def _format_public_route(route, nexthops, ecmp_groups):
    target_type = _attr(route, "target-type")
    target_id = _attr(route, "target-id")
    if target_type == "rif":
        return "connected", "Direct", _attr(route, "rif", target_id)
    if target_type == "ecmp":
        ecmp = ecmp_groups.get(target_id)
        members = _attr(ecmp, "members", "-") if ecmp is not None else "-"
        return "static", f"ECMP({members})", "-"
    nh = nexthops.get(target_id)
    if nh is None:
        return "static", "-", "-"
    return "static", _attr(nh, "arp"), _attr(nh, "rif")


def _format_ecmp_members(ecmp, nexthops):
    members = _attr(ecmp, "members")
    if members == "-":
        return "-"
    resolved = []
    for member in [item.strip() for item in members.split(",") if item.strip()]:
        nh = nexthops.get(member)
        if nh is None:
            resolved.append(f"{member}->missing")
        else:
            resolved.append(f"{member}->{_attr(nh, 'arp')}")
    return ",".join(resolved) if resolved else "-"


def format_l3_state(xml):
    root = _parse(xml)
    if root is None:
        return xml
    plan = _plan(root)
    boundary = root.find("boundary")
    lines = [
        "L3 control-plane state:",
        f"  State          : {_attr(root, 'state', 'unknown')} "
        f"({_public_l3_text(_attr(root, 'mode', 'diagnostic'))})",
        f"  Config open    : {_attr(root, 'config-open', 'false')}",
        f"  Hardware apply : {_attr(root, 'hardware-apply', 'disabled')}",
        f"  Hardware read-back: {_attr(root, 'sdk-readback', 'disabled')}",
        f"  Generation     : {_attr(root, 'generation', '0')}",
        f"  Last load      : {_attr(root, 'last-load', '0')}",
        f"  Transaction    : {_attr(root, 'transaction-state', 'unknown')} "
        f"tx-id={_attr(root, 'tx-id', '0')} "
        f"rollback={_attr(root, 'rollback-available', 'false')}",
        f"  User config    : {_attr(boundary, 'user-config', 'rejected')}",
        f"  Boundary       : {_public_l3_text(_attr(boundary, 'reason', 'hardware apply/read-back/rollback not enabled'))}",
        "",
        "  Candidate plan:",
        f"    rifs={plan['rifs']} arp={plan['arp']} "
        f"next-hops={plan['next-hops']} routes={plan['routes']} "
        f"ecmp-groups={plan['ecmp-groups']}",
    ]
    return "\n".join(lines)


def _shadow_transaction_root(root):
    if root.tag == "l3-transaction-readback":
        return root, None
    owner = root.find("switchd-owner")
    if owner is None:
        return None, None
    return owner.find("l3-transaction-readback"), owner


def _shadow_hardware_readback(tx, shadow):
    if shadow is not None:
        return _attr(shadow, "sdk-readback", "disabled")
    return _attr(tx, "sdk-readback", "disabled")


def _shadow_object_detail(obj):
    family = _attr(obj, "family")
    if family == "rif":
        return f"vlan={_attr(obj, 'vlan')} address={_attr(obj, 'address')}"
    if family == "arp":
        return (f"{_attr(obj, 'ip')} {_attr(obj, 'mac')} "
                f"rif={_attr(obj, 'rif')} "
                f"egress={_attr(obj, 'egress-port')}")
    if family == "next-hop":
        return f"arp={_attr(obj, 'arp')} rif={_attr(obj, 'rif')}"
    if family == "ecmp":
        return f"members={_attr(obj, 'members')}"
    if family == "route":
        target = _attr(obj, "target")
        if target == "-":
            target_type = _attr(obj, "target-type")
            target_id = _attr(obj, "target-id")
            target = f"{target_type}:{target_id}" if target_type != "-" else "-"
        return f"target={target}"
    return "-"


def _append_shadow_families(lines, shadow):
    families = shadow.findall("family") if shadow is not None else []
    lines.extend([
        "  Shadow read-back:",
        f"    Source        : {_public_l3_text(_attr(shadow, 'source', 'switchd-owner'))}",
        f"    Complete      : {_attr(shadow, 'complete', 'true')} "
        f"emit-limit={_attr(shadow, 'emit-limit', '-')}",
    ])
    if not families:
        lines.append("    Families      : none")
        return
    lines.extend([
        "    Family      Count  Emitted  Extra",
    ])
    for family in families:
        extra = "-"
        if _attr(family, "name") == "ecmp":
            extra = f"members={_attr(family, 'members', '0')}"
        lines.append(
            f"    {_fit(_attr(family, 'name'), 11)} "
            f"{_fit(_attr(family, 'count', '0'), 6)} "
            f"{_fit(_attr(family, 'emitted', '0'), 8)} {extra}")


def _append_shadow_objects(lines, shadow):
    objects = shadow.findall("object") if shadow is not None else []
    if not objects:
        return
    lines.extend([
        "",
        "  Shadow objects:",
        "    Family      Key                  Detail                         State",
    ])
    for obj in objects:
        key = _attr(obj, "key", _attr(obj, "ip", "-"))
        lines.append(
            f"    {_fit(_attr(obj, 'family'), 11)} "
            f"{_fit(key, 20)} "
            f"{_fit(_shadow_object_detail(obj), 30)} "
            f"{_public_l3_text(_attr(obj, 'state', 'shadow'))}")
    if shadow.find("truncated") is not None or _attr(shadow, "complete") == "false":
        lines.append("    Note: shadow inventory truncated by emit limit.")


def _append_shadow_verify(lines, verify):
    lines.extend([
        "",
        "  Shadow verifier:",
        f"    Status        : {_attr(verify, 'status', 'unknown')} "
        f"compared={_attr(verify, 'compared', '0')} "
        f"mismatches={_attr(verify, 'mismatches', '0')}",
    ])
    families = verify.findall("family") if verify is not None else []
    if not families:
        return
    lines.extend([
        "    Family      Expected  Actual  Mismatch",
    ])
    for family in families:
        lines.append(
            f"    {_fit(_attr(family, 'name'), 11)} "
            f"{_fit(_attr(family, 'expected', '0'), 9)} "
            f"{_fit(_attr(family, 'actual', '0'), 7)} "
            f"{_attr(family, 'mismatches', '0')}")


def _append_l3_intent(lines, title, intent):
    if intent is None:
        return
    lines.extend([
        "",
        f"  {title}:",
        f"    Forwarding writer: {_public_l3_text(_attr(intent, 'owner', 'switchd'))}",
        f"    Hardware write: {_attr(intent, 'sdk-write', 'disabled')}",
        f"    Order         : {_attr(intent, 'order', '-')}",
        f"    Total ops     : {_attr(intent, 'total-ops', '0')}",
    ])
    if intent.get("restore-ops") is not None:
        lines.append(f"    Restore ops   : {_attr(intent, 'restore-ops', '0')}")


def _append_hal_probe(lines, probe):
    if probe is None:
        return
    lines.extend([
        "",
        "  HAL intent probe:",
        f"    Status        : {_attr(probe, 'status', 'unknown')}",
        f"    Hardware write: {_attr(probe, 'sdk-write', 'disabled')}",
        f"    Hardware read-back: {_attr(probe, 'sdk-readback', 'disabled')}",
        f"    Fingerprint   : {_attr(probe, 'fingerprint', '-')}",
    ])
    objects = probe.findall("sdk-object")
    if not objects:
        return
    lines.extend([
        "    Hardware family     Count",
    ])
    for obj in objects:
        count = _attr(obj, "count", _attr(obj, "groups", "0"))
        if obj.get("members") is not None:
            count = f"{count} groups/{_attr(obj, 'members')} members"
        family = _public_l3_family(_attr(obj, "family"))
        lines.append(f"    {_fit(family, 19)} {count}")


def _append_sdk_preflight(lines, preflight):
    if preflight is None:
        return
    lines.extend([
        "",
        "  Hardware transaction preflight:",
        f"    Status        : {_attr(preflight, 'status', 'unknown')}",
        f"    Hardware apply: {_attr(preflight, 'hardware-apply', 'disabled')}",
        f"    Hardware write: {_attr(preflight, 'sdk-write', 'disabled')}",
        f"    Hardware read-back: {_attr(preflight, 'sdk-readback', 'disabled')}",
        f"    Rollback      : {_attr(preflight, 'rollback', 'planned')}",
        f"    Platform gate : {_public_l3_text(_attr(preflight, 'profile-gate', 'required'))}",
        f"    Operator gate : {_attr(preflight, 'gate-enabled', 'false')} "
        f"({_public_l3_gate(_attr(preflight, 'gate-env', '-'))})",
        f"    Total ops     : {_attr(preflight, 'total-ops', '0')}",
    ])
    families = preflight.findall("family")
    if not families:
        return
    lines.append("    Family             Apply  Rollback")
    for family in families:
        name = _public_l3_family(_attr(family, "name"))
        apply = _attr(family, "apply", "0")
        rollback = _attr(family, "rollback", "0")
        if family.get("members") is not None:
            apply = f"{apply}/{_attr(family, 'members')}"
        lines.append(f"    {_fit(name, 18)} {_fit(apply, 6)} {rollback}")


def _append_sdk_live_readback(lines, probe):
    if probe is None:
        return
    lines.extend([
        "",
        "  Hardware live inventory:",
        f"    Status        : {_attr(probe, 'status', 'unknown')}",
        f"    Hardware apply: {_attr(probe, 'hardware-apply', 'disabled')}",
        f"    Hardware write: {_attr(probe, 'sdk-write', 'disabled')}",
        f"    Hardware read-back: {_attr(probe, 'sdk-readback', 'disabled')}",
        f"    Mode          : {_attr(probe, 'mode', 'canary')}",
    ])
    router = probe.find("router")
    if router is not None:
        lines.append(
            f"    Router        : vrid={_attr(router, 'vrid', '-')} "
            f"state={_attr(router, 'state', '-')} "
            f"status={_attr(router, 'status', 'unknown')}"
        )
    families = probe.findall("family")
    if not families:
        return
    lines.append("    Family          Status     Count  Emitted")
    for family in families:
        lines.append(
            f"    {_fit(_public_l3_family(_attr(family, 'name')), 15)} "
            f"{_fit(_attr(family, 'status', 'unknown'), 10)} "
            f"{_fit(_attr(family, 'count', '0'), 6)} "
            f"{_attr(family, 'emitted', '0')}"
        )
    objects = probe.findall("object")
    if not objects:
        return
    lines.extend([
        "",
        "    Hardware actual objects:",
        "    Family      Key                  Detail",
    ])
    for obj in objects:
        raw_family = _attr(obj, "family", "-")
        family = _public_l3_family(raw_family)
        key = _attr(obj, "key", "-")
        detail = "-"
        if raw_family == "rif":
            detail = (
                f"vlan={_attr(obj, 'vlan')} "
                f"addr={_attr(obj, 'address')} "
                f"state={_attr(obj, 'state')}"
            )
        elif raw_family == "arp":
            detail = (
                f"{_attr(obj, 'ip')} {_attr(obj, 'mac')} "
                f"if={_attr(obj, 'interface')} vlan={_attr(obj, 'vlan')}"
            )
        elif raw_family == "ecmp":
            detail = (
                f"members={_attr(obj, 'members')} "
                f"status={_attr(obj, 'member-status')}"
            )
        elif raw_family == "route":
            if _attr(obj, "type") == "ecmp":
                detail = f"{_attr(obj, 'prefix')} ecmp={_attr(obj, 'ecmp')}"
            else:
                detail = (
                    f"{_attr(obj, 'prefix')} "
                    f"next-hop={_attr(obj, 'next-hop')}"
                )
        lines.append(
            f"    {_fit(family, 11)} {_fit(key, 20)} {_fit(detail, 36)}"
        )


def _append_sdk_owner_verify(lines, verify):
    if verify is None:
        return
    lines.extend([
        "",
        "  Hardware route verifier:",
        f"    Status        : {_attr(verify, 'status', 'unknown')}",
        f"    Hardware apply: {_attr(verify, 'hardware-apply', 'disabled')}",
        f"    Hardware write: {_attr(verify, 'sdk-write', 'disabled')}",
        f"    Hardware read-back: {_attr(verify, 'sdk-readback', 'disabled')}",
        f"    Forwarding map: {_public_l3_text(_attr(verify, 'owner-handle-map', 'missing'))}",
        f"    Compared      : {_attr(verify, 'compared', '0')}",
        f"    Mismatches    : {_attr(verify, 'mismatches', '0')}",
        f"    Reason        : {_public_l3_text(_attr(verify, 'reason', '-'))}",
    ])
    families = verify.findall("family")
    if not families:
        return
    lines.append("    Family      Expected  Actual          Status      Mismatch")
    for family in families:
        name = _public_l3_family(_attr(family, "name"))
        expected = _attr(family, "expected", "0")
        actual = _attr(family, "actual",
                       _attr(family, "actual-owned",
                             _attr(family, "actual-inventory", "0")))
        if name == "ecmp":
            actual = (
                f"managed={_attr(family, 'actual-owned', '0')}/"
                f"inv={_attr(family, 'actual-inventory', '0')}"
            )
        lines.append(
            f"    {_fit(name, 11)} {_fit(expected, 9)} "
            f"{_fit(actual, 15)} {_fit(_attr(family, 'status'), 11)} "
            f"{_attr(family, 'mismatches', '0')}"
        )


def _resource_delta(root):
    if root.tag == "l3-resource-delta":
        return root
    return root.find("l3-resource-delta")


def _resource_extra(res):
    if _attr(res, "name") == "route":
        return f"route-slices={_attr(res, 'route-slices', '0')}"
    return "-"


def format_l3_resource_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    delta = _resource_delta(root)
    lines = _header(root, "L3 route resources")
    lines.extend([
        "",
        f"  Resource model : {_public_l3_text(_attr(delta, 'mode', 'diagnostic'))}",
        f"  Hardware apply : {_attr(delta, 'hardware-apply', 'disabled')}",
        f"  Hardware read-back: {_attr(delta, 'sdk-readback', 'disabled')}",
        "",
    ])
    resources = delta.findall("resource") if delta is not None else []
    if not resources:
        lines.append("  No diagnostic L3 resource delta available.")
        return "\n".join(lines)
    lines.extend([
        "  Resource     Pre   Used  Delta  Capacity  Free    Extra",
    ])
    for res in resources:
        lines.append(
            f"  {_fit(_attr(res, 'name'), 12)} "
            f"{_fit(_attr(res, 'pre', '0'), 5)} "
            f"{_fit(_attr(res, 'used', '0'), 5)} "
            f"{_fit(_attr(res, 'delta', '0'), 6)} "
            f"{_fit(_attr(res, 'capacity', '0'), 9)} "
            f"{_fit(_attr(res, 'free', '0'), 7)} "
            f"{_resource_extra(res)}")
    return "\n".join(lines)


def format_l3_shadow_state(xml):
    root = _parse(xml)
    if root is None:
        return xml
    tx, owner = _shadow_transaction_root(root)
    lines = ["L3 shadow transaction state:"]
    if owner is not None:
        lines.append(
            f"  Route wrapper  : {_attr(owner, 'status', 'unknown')} "
            f"ec={_attr(owner, 'ec', '-')}")
    if tx is None:
        lines.extend([
            "  Forwarding state: unavailable",
            "  Hardware apply : disabled",
            "  Hardware read-back: disabled",
            "  User config    : rejected",
            "  Boundary       : switchd forwarding read-back unavailable",
        ])
        return "\n".join(lines)

    shadow = tx.find("shadow-readback")
    verify = tx.find("shadow-verify")
    apply_intent = tx.find("apply-intent")
    rollback_intent = tx.find("rollback-intent")
    boundary = tx.find("boundary")
    usage = tx.find("usage")
    pre = tx.find("pre-state")

    lines.extend([
        f"  Forwarding writer: switchd "
        f"({_public_l3_text(_attr(tx, 'mode', 'diagnostic'))})",
        f"  Transaction    : {_attr(tx, 'transaction-state', 'unknown')} "
        f"tx-id={_attr(tx, 'tx-id', '0')} "
        f"rollback={_attr(tx, 'rollback-available', 'false')}",
        f"  Hardware apply : {_attr(tx, 'hardware-apply', 'disabled')}",
        f"  Read-back      : {_attr(tx, 'read-back', 'synthetic')}",
        f"  Hardware write : {_attr(apply_intent, 'sdk-write', 'disabled')}",
        f"  Hardware read-back: {_shadow_hardware_readback(tx, shadow)}",
        f"  User config    : {_attr(boundary, 'user-config', 'rejected')}",
        f"  Boundary       : {_public_l3_text(_attr(boundary, 'reason', 'hardware read-back not enabled'))}",
        "",
        "  Current usage:",
        f"    rifs={_attr(usage, 'rifs', '0')} arp={_attr(usage, 'arp', '0')} "
        f"next-hops={_attr(usage, 'next-hops', '0')} "
        f"routes={_attr(usage, 'routes', '0')} "
        f"ecmp-groups={_attr(usage, 'ecmp-groups', '0')} "
        f"ecmp-members={_attr(usage, 'ecmp-members', '0')}",
        "  Pre-state:",
        f"    rifs={_attr(pre, 'rifs', '0')} arp={_attr(pre, 'arp', '0')} "
        f"next-hops={_attr(pre, 'next-hops', '0')} "
        f"routes={_attr(pre, 'routes', '0')} "
        f"ecmp-groups={_attr(pre, 'ecmp-groups', '0')} "
        f"ecmp-members={_attr(pre, 'ecmp-members', '0')}",
        "",
    ])
    _append_shadow_families(lines, shadow)
    _append_shadow_objects(lines, shadow)
    _append_shadow_verify(lines, verify)
    _append_l3_intent(lines, "Apply intent", apply_intent)
    _append_l3_intent(lines, "Rollback intent", rollback_intent)
    _append_hal_probe(lines, tx.find("hal-l3-intent-probe"))
    _append_sdk_preflight(lines, tx.find("hal-l3-sdk-preflight"))
    _append_sdk_owner_verify(lines, tx.find("l3-sdk-owner-verify"))
    _append_sdk_live_readback(lines, tx.find("l3-sdk-readback-probe"))
    return "\n".join(lines)


def format_l3_route_summary(xml):
    root = _parse(xml)
    if root is None:
        return xml
    usage = _usage(root)
    capacity = _capacity(root)
    lines = _header(root, "L3 route summary")
    lines.extend([
        "",
        "  RIB     Control-plane routes  Hardware routes  Next-hops  ARP  ECMP  RIFs",
        f"  inet.0  {_fit(usage['routes'], 13)}  {_fit('0', 15)} "
        f"{_fit(usage['next-hops'], 9)} {_fit(usage['arp'], 4)} "
        f"{_fit(usage['ecmp-groups'], 5)} {usage['rifs']}",
        "",
        "  Capacity:",
        f"    routes={usage['routes']}/{capacity['routes']} "
        f"route-slices={capacity['route-slices']} "
        f"arp={usage['arp']}/{capacity['arp']} "
        f"next-hops={usage['next-hops']}/{capacity['next-hops']} "
        f"ecmp-groups={usage['ecmp-groups']}/{capacity['ecmp-groups']} "
        f"ecmp-members={usage['ecmp-members']}/{capacity['ecmp-members']}",
    ])
    return "\n".join(lines)


def format_l3_route_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    objects, truncated = _inventory(root)
    routes = _objects_by_family(objects, "route")
    nexthops = _nh_index(objects)
    ecmp_groups = _ecmp_index(objects)
    usage = _usage(root)
    lines = [
        "inet.0:",
        f"  Routes: {usage['routes']}",
    ]
    if not routes:
        lines.append("  No routes learned or configured.")
    else:
        lines.extend([
            "  Destination        Protocol   Next-hop/Members  Interface",
        ])
        for route in routes:
            protocol, next_hop, rif = _format_public_route(route, nexthops,
                                                           ecmp_groups)
            lines.append(
                f"  {_fit(_attr(route, 'prefix', _attr(route, 'key')), 18)} "
                f"{_fit(protocol, 10)} {_fit(next_hop, 17)} "
                f"{_fit(rif, 10)}")
    if truncated:
        lines.append("  Note: route inventory truncated by emit limit.")
    return "\n".join(lines)


def format_l3_interface_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    objects, truncated = _inventory(root)
    rifs = _objects_by_family(objects, "rif")
    usage = _usage(root)
    lines = _header(root, "L3 interface table")
    lines.extend([
        "",
        f"Entries: {usage['rifs']} control-plane RIFs, 0 hardware RIFs",
    ])
    if not rifs:
        lines.append("  No control-plane L3 interfaces loaded.")
    else:
        lines.extend([
            "  Interface  VLAN    Address             State",
        ])
        for rif in rifs:
            lines.append(
                f"  {_fit(_attr(rif, 'key'), 10)} "
                f"{_fit(_attr(rif, 'vlan'), 7)} "
                f"{_fit(_attr(rif, 'address'), 19)} "
                f"{_public_l3_text(_attr(rif, 'state', 'diagnostic'))}")
    if truncated:
        lines.append("  Note: control-plane inventory truncated by emit limit.")
    return "\n".join(lines)


def format_l3_next_hop_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    objects, truncated = _inventory(root)
    nexthops = _objects_by_family(objects, "next-hop")
    arps = _arp_index(objects)
    usage = _usage(root)
    lines = _header(root, "L3 next-hop table")
    lines.extend([
        "",
        f"Entries: {usage['next-hops']} control-plane next-hops, "
        "0 hardware next-hops",
    ])
    if not nexthops:
        lines.append("  No control-plane next-hops loaded.")
    else:
        lines.extend([
            "  ID      ARP              MAC address        Interface  State",
        ])
        for nh in nexthops:
            arp_ip = _attr(nh, "arp")
            arp = arps.get(arp_ip)
            lines.append(
                f"  {_fit(_attr(nh, 'key'), 7)} "
                f"{_fit(arp_ip, 16)} "
                f"{_fit(_attr(arp, 'mac'), 18)} "
                f"{_fit(_attr(nh, 'rif'), 10)} "
                f"{_public_l3_text(_attr(nh, 'state', 'diagnostic'))}")
    if truncated:
        lines.append("  Note: control-plane inventory truncated by emit limit.")
    return "\n".join(lines)


def format_l3_ecmp_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    objects, truncated = _inventory(root)
    ecmp_groups = _objects_by_family(objects, "ecmp")
    nexthops = _nh_index(objects)
    usage = _usage(root)
    lines = _header(root, "L3 ECMP table")
    lines.extend([
        "",
        f"Entries: {usage['ecmp-groups']} control-plane ECMP groups, "
        f"{usage['ecmp-members']} control-plane members, 0 hardware groups",
    ])
    if not ecmp_groups:
        lines.append("  No control-plane ECMP groups loaded.")
    else:
        lines.extend([
            "  Group   Members           Resolved members                    State",
        ])
        for ecmp in ecmp_groups:
            lines.append(
                f"  {_fit(_attr(ecmp, 'key'), 7)} "
                f"{_fit(_attr(ecmp, 'members'), 17)} "
                f"{_fit(_format_ecmp_members(ecmp, nexthops), 36)} "
                f"{_public_l3_text(_attr(ecmp, 'state', 'diagnostic'))}")
    if truncated:
        lines.append("  Note: control-plane inventory truncated by emit limit.")
    return "\n".join(lines)


def format_l3_arp_table(xml):
    root = _parse(xml)
    if root is None:
        return xml
    if root.tag == "rpd-state":
        return format_rpd_arp_table(xml)
    objects, truncated = _inventory(root)
    arps = _objects_by_family(objects, "arp")
    usage = _usage(root)
    lines = [
        "ARP table:",
        f"  Entries: {usage['arp']}",
    ]
    if not arps:
        lines.append("  No ARP entries.")
    else:
        lines.extend([
            "  IP address       MAC address        Interface  Egress",
        ])
        for arp in arps:
            lines.append(
                f"  {_fit(_attr(arp, 'ip'), 16)} "
                f"{_fit(_attr(arp, 'mac'), 18)} "
                f"{_fit(_attr(arp, 'rif'), 10)} "
                f"{_fit(_attr(arp, 'egress-port'), 11)}")
    if truncated:
        lines.append("  Note: ARP inventory truncated by emit limit.")
    return "\n".join(lines)
