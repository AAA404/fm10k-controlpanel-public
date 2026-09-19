"""Output formatters for configuration text."""
import ipaddress
import xml.etree.ElementTree as ET


def format_diff(xml: str) -> str:
    """Format show | compare output."""
    return format_config_diff(xml)


def format_config_set(xml: str) -> str:
    """Format show configuration | display set output."""
    formatted = format_config_as_set(xml)
    return formatted if formatted else xml


def format_config_hierarchy(xml: str, path_tokens=None) -> str:
    """Format candidate config as Junos-style hierarchy."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception:
        return xml

    node, renderer = _select_config_node(root, path_tokens or [])
    if node is None:
        return "(empty)"
    lines = []
    if renderer:
        renderer(node, lines, 0)
    else:
        _render_generic_config_node(node, lines, 0, include_self=True)
    return "\n".join(lines) if lines else "(empty)"


def _xml_name(elem):
    return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag


def _xml_child(elem, tag):
    for child in list(elem):
        if _xml_name(child) == tag:
            return child
    return None


def _xml_child_text(elem, tag):
    child = _xml_child(elem, tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _xml_child_texts(elem, tag):
    values = []
    for child in list(elem):
        if _xml_name(child) != tag:
            continue
        value = (child.text or "").strip() if child.text else ""
        if value:
            values.append(value)
    return values


def _firewall_filter_term(term_name):
    if "." in term_name:
        filter_name, term = term_name.split(".", 1)
        if filter_name and term:
            return filter_name, term
    return "default", term_name


def _firewall_action(action):
    if action == "drop":
        return "discard"
    if action == "count":
        return "count"
    return action


def _firewall_compiler_set_prefix(term_name, mode):
    filter_name, term = _firewall_filter_term(term_name)
    return ("firewall family ethernet-switching "
            f"filter {filter_name} term {term} {mode}")


def _select_config_node(root, tokens):
    if _xml_name(root) != "netlab-config":
        return root, None
    if not tokens:
        return root, _render_netlab_root

    top_name = "netlab-config" if tokens[0] == "configuration" else tokens[0]
    if top_name == "netlab-config":
        return root, _render_netlab_root

    if top_name == "system":
        top = _xml_child(root, top_name)
        if top is None:
            return None, None
        return top, _render_system_contents

    if top_name == "vlans":
        top = _xml_child(root, top_name)
        if top is None:
            return None, None
        if len(tokens) == 1:
            return top, _render_vlans_contents
        vlan = _find_list_child(top, "vlan", "name", tokens[1])
        return vlan, _render_vlans_contents

    if top_name == "interfaces":
        top = _xml_child(root, top_name)
        if len(tokens) == 1:
            return root, _render_public_interfaces_contents
        if len(tokens) >= 2 and tokens[1] == "irb":
            return _select_irb_node(root, tokens[2:])
        ifname = tokens[1]
        physical = (_find_list_child(top, "interface", "name", ifname)
                    if top is not None else None)
        routing = _xml_child(root, "interfaces-routing")
        routed = None
        if routing is not None:
            routed = _find_list_child(routing, "interface", "name",
                                      ifname + ".0")
        if physical is None and routed is None:
            return None, None
        return root, lambda node, lines, indent: (
            _render_public_interfaces_contents(node, lines, indent, ifname))

    if top_name == "firewall":
        return root, _render_firewall_contents

    top = _xml_child(root, top_name)
    if top is None:
        return None, None

    if top_name == "protocols":
        return _select_protocols_node(top, tokens[1:])

    if top_name == "chassis":
        return top, _render_chassis_contents

    if top_name == "snmp":
        return top, _render_snmp_contents

    if top_name == "control-plane":
        return top, _render_control_plane_contents

    if top_name == "class-of-service":
        return top, _render_class_of_service_contents

    if top_name == "forwarding-options":
        return top, _render_forwarding_options_contents

    if top_name == "ethernet-switching-options":
        return top, _render_ethernet_switching_options_contents

    if top_name == "interfaces-routing":
        return None, None

    if top_name == "routing-options":
        return top, _render_routing_options_contents

    if top_name == "routing-instances":
        return top, _render_routing_instances_contents

    if top_name == "policy-options":
        return _select_policy_options_node(top, tokens[1:])

    return top, None


def _select_irb_node(root, tokens):
    routing = _xml_child(root, "interfaces-routing")
    if routing is None:
        return None, None
    if not tokens:
        return routing, lambda node, lines, indent: (
            _render_interfaces_routing_contents(node, lines, indent, root))
    if len(tokens) >= 2 and tokens[0] == "unit":
        unit = tokens[1]
        for iface in [child for child in list(routing)
                      if _xml_name(child) == "interface"]:
            rif = _xml_child_text(iface, "name")
            vlan = _xml_child_text(iface, "vlan")
            if _irb_unit_from_rif(rif, vlan) == unit:
                return iface, lambda node, lines, indent: (
                    _render_interfaces_routing_contents(node, lines, indent,
                                                       root))
    return None, None


def _select_protocols_node(protocols, tokens):
    if not tokens:
        return protocols, _render_protocols_contents
    if tokens[0] == "ospf":
        ospf = _xml_child(protocols, "ospf")
        if ospf is None:
            return None, None
        if len(tokens) == 1:
            return ospf, _render_ospf_contents
        if len(tokens) >= 3 and tokens[1] == "area":
            area = _find_list_child(ospf, "area", "name", tokens[2])
            if area is not None and len(tokens) >= 5 and tokens[3] == "interface":
                iface = _find_list_child(area, "interface", "name", tokens[4])
                return iface, _render_ospf_contents
            return area, _render_ospf_contents
        return None, None
    if tokens[0] == "bgp":
        bgp = _xml_child(protocols, "bgp")
        if bgp is None:
            return None, None
        if len(tokens) == 1:
            return bgp, _render_bgp_contents
        if len(tokens) >= 3 and tokens[1] == "group":
            group = _find_list_child(bgp, "group", "name", tokens[2])
            if group is not None and len(tokens) >= 5 and tokens[3] == "neighbor":
                neighbor = _find_list_child(group, "neighbor", "address", tokens[4])
                return neighbor, _render_bgp_contents
            return group, _render_bgp_contents
        return None, None
    if tokens[0] == "lldp":
        lldp = _xml_child(protocols, "lldp")
        if lldp is None:
            return None, None
        if len(tokens) == 1:
            return lldp, _render_lldp_contents
        if len(tokens) >= 3 and tokens[1] == "interface":
            iface = _find_list_child(lldp, "interface", "name", tokens[2])
            return iface, _render_lldp_contents
        return None, None
    if tokens[0] == "igmp-snooping":
        igmp = _xml_child(protocols, "igmp-snooping")
        if igmp is None:
            return None, None
        return igmp, _render_igmp_snooping_contents
    if tokens[0] == "lacp":
        lacp = _xml_child(protocols, "lacp")
        if lacp is None:
            return None, None
        return lacp, _render_lacp_contents
    if tokens[0] == "mstp":
        mstp = _xml_child(protocols, "mstp")
        if mstp is None:
            return None, None
        if len(tokens) == 1:
            return mstp, _render_mstp_contents
        if len(tokens) >= 3 and tokens[1] == "interface":
            iface = _find_list_child(mstp, "interface", "name", tokens[2])
            return iface, _render_mstp_contents
        if len(tokens) >= 3 and tokens[1] == "instance":
            inst = _find_list_child(mstp, "instance", "id", tokens[2])
            if (inst is not None and len(tokens) >= 5 and
                    tokens[3] == "interface"):
                iface = _find_list_child(inst, "interface", "name",
                                         tokens[4])
                return iface, _render_mstp_instance_interface
            return inst, _render_mstp_contents
        return None, None
    if tokens[0] != "rstp":
        return _xml_child(protocols, tokens[0]), None
    rstp = _xml_child(protocols, "rstp")
    if rstp is None:
        return None, None
    if len(tokens) == 1:
        return rstp, _render_rstp_contents
    if len(tokens) >= 3 and tokens[1] == "interface":
        iface = _find_list_child(rstp, "interface", "name", tokens[2])
        return iface, _render_rstp_contents
    return None, None


def _select_policy_options_node(policy_options, tokens):
    if not tokens:
        return policy_options, _render_policy_options_contents
    if len(tokens) >= 2 and tokens[0] == "policy-statement":
        policy = _find_list_child(policy_options, "policy-statement", "name",
                                  tokens[1])
        if policy is None:
            return None, None
        if len(tokens) == 2:
            return policy, _render_policy_options_contents
        if len(tokens) >= 4 and tokens[2] == "term":
            term = _find_list_child(policy, "term", "name", tokens[3])
            return term, _render_policy_options_contents
    return None, None


def _find_list_child(parent, list_name, key_name, key_value):
    for child in list(parent):
        if _xml_name(child) != list_name:
            continue
        if _xml_child_text(child, key_name) == key_value:
            return child
    return None


def _irb_unit_from_rif(rif, vlan=""):
    if vlan:
        return vlan
    if rif.startswith("vlan") and rif[4:].isdigit():
        return rif[4:]
    if rif.startswith("irb.") and rif[4:].isdigit():
        return rif[4:]
    return ""


def _physical_unit_from_rif(rif):
    if not rif or "." not in rif:
        return "", ""
    ifname, unit = rif.rsplit(".", 1)
    if not ifname or unit != "0" or "/" not in ifname:
        return "", ""
    return ifname, unit


def _rif_unit(rif):
    return _irb_unit_from_rif(rif or "")


def _rif_matches_unit(rif, unit):
    if not rif or not unit:
        return False
    return rif == f"vlan{unit}" or rif == f"irb.{unit}" or _rif_unit(rif) == unit


def _ipv4_in_prefix(ip, prefix):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix,
                                                                strict=False)
    except ValueError:
        return False


def _routing_static_node(root):
    routing = _xml_child(root, "routing-options") if root is not None else None
    return _xml_child(routing, "static") if routing is not None else None


def _routing_static_arps(root):
    static = _routing_static_node(root)
    if static is None:
        return []
    arps = []
    for arp in [child for child in list(static) if _xml_name(child) == "arp"]:
        ip = _xml_child_text(arp, "ip")
        if not ip:
            continue
        arps.append({
            "ip": ip,
            "mac": _xml_child_text(arp, "mac"),
            "interface": _xml_child_text(arp, "interface"),
            "egress-interface": _xml_child_text(arp, "egress-interface"),
        })
    return arps


def _static_arps_for_irb(root, rif, unit, address):
    matched = []
    for arp in _routing_static_arps(root):
        arp_rif = arp.get("interface", "")
        if arp_rif:
            if arp_rif == rif or _rif_matches_unit(arp_rif, unit):
                matched.append(arp)
            continue
        if address and _ipv4_in_prefix(arp.get("ip", ""), address):
            matched.append(arp)
    return matched


def _routing_next_hop_index(static):
    result = {}
    if static is None:
        return result
    for nh in [child for child in list(static) if _xml_name(child) == "next-hop"]:
        nhid = _xml_child_text(nh, "id")
        arp = _xml_child_text(nh, "arp-ip")
        if nhid and arp:
            result[nhid] = arp
    return result


def _routing_ecmp_index(static, next_hop_index):
    result = {}
    if static is None:
        return result
    for ecmp in [child for child in list(static) if _xml_name(child) == "ecmp"]:
        ecmp_id = _xml_child_text(ecmp, "id")
        if not ecmp_id:
            continue
        members = []
        for member in [child for child in list(ecmp)
                       if _xml_name(child) == "member"]:
            nhid = (member.text or "").strip()
            if nhid:
                members.append(next_hop_index.get(nhid, nhid))
        result[ecmp_id] = members
    return result


def _route_next_hop_displays(route, next_hop_index, ecmp_index=None):
    nh_ips = _xml_child_texts(route, "next-hop-address")
    if nh_ips:
        return nh_ips
    nhid = _xml_child_text(route, "next-hop-id")
    if nhid:
        return [next_hop_index.get(nhid, nhid)]
    ecmp_id = _xml_child_text(route, "ecmp-id")
    if ecmp_id and ecmp_index is not None:
        return ecmp_index.get(ecmp_id, [])
    return []


def _render_block(lines, indent, name, body_fn):
    pad = "    " * indent
    lines.append(f"{pad}{name} {{")
    body_fn(indent + 1)
    lines.append(f"{pad}}}")


def _render_block_if_nonempty(lines, indent, name, body_fn):
    start = len(lines)
    _render_block(lines, indent, name, body_fn)
    if len(lines) == start + 2:
        del lines[start:]


def _render_leaf(lines, indent, name, value=None):
    pad = "    " * indent
    if value is None or value == "":
        lines.append(f"{pad}{name};")
    else:
        lines.append(f"{pad}{name} {value};")


def _render_public_interfaces_contents(root, lines, indent,
                                       selected_ifname=None):
    physical = _xml_child(root, "interfaces")
    routing = _xml_child(root, "interfaces-routing")
    physical_entries = {}
    ordered_names = []
    if physical is not None:
        for iface in [child for child in list(physical)
                      if _xml_name(child) == "interface"]:
            ifname = _xml_child_text(iface, "name")
            if ifname:
                physical_entries[ifname] = iface
                ordered_names.append(ifname)
    routed_entries = {}
    if routing is not None:
        for iface in [child for child in list(routing)
                      if _xml_name(child) == "interface"]:
            ifname, unit = _physical_unit_from_rif(
                _xml_child_text(iface, "name"))
            if ifname and unit:
                routed_entries[ifname] = iface
                if ifname not in physical_entries:
                    ordered_names.append(ifname)
    for ifname in ordered_names:
        if selected_ifname and ifname != selected_ifname:
            continue
        iface = physical_entries.get(ifname)
        routed = routed_entries.get(ifname)

        def body(i, iface=iface, routed=routed):
            if iface is not None:
                _render_interface_body(iface, lines, i)
            if routed is not None:
                _render_physical_rif_unit(routed, lines, i, root)

        _render_block(lines, indent, ifname, body)
    if routing is not None and not selected_ifname:
        _render_interfaces_routing_contents(routing, lines, indent, root)


def _render_public_interfaces_block(root, lines, indent):
    body = []
    _render_public_interfaces_contents(root, body, indent + 1)
    if not body:
        return
    pad = "    " * indent
    lines.append(f"{pad}interfaces {{")
    lines.extend(body)
    lines.append(f"{pad}}}")


def _firewall_term_entries(root, family):
    eso = _xml_child(root, "ethernet-switching-options")
    if eso is None:
        return []
    node_names = (("user-filter", "ingress-acl")
                  if family == "ethernet-switching"
                  else ("ingress-ipv4-acl",))
    entries = []
    for node_name in node_names:
        acl_node = _xml_child(eso, node_name)
        if acl_node is None:
            continue
        for term in list(acl_node):
            if _xml_name(term) != "term":
                continue
            tname = _xml_child_text(term, "name")
            if not tname:
                continue
            filter_name, public_term = _firewall_filter_term(tname)
            entries.append((filter_name, public_term, term))
    return entries


def _firewall_compiler_entries(root):
    eso = _xml_child(root, "ethernet-switching-options")
    if eso is None:
        return []
    entries = []
    for node_name, mode in (("acl-policer", "policer"),
                            ("egress-acl", "egress")):
        acl_node = _xml_child(eso, node_name)
        if acl_node is None:
            continue
        for term in list(acl_node):
            if _xml_name(term) != "term":
                continue
            tname = _xml_child_text(term, "name")
            if not tname:
                continue
            filter_name, public_term = _firewall_filter_term(tname)
            entries.append((filter_name, public_term, mode, term))
    return entries


def _render_firewall_term(lines, indent, family, term):
    if family == "ethernet-switching":
        leaf_map = (
            ("vlan", "vlan"),
            ("interface", "interface"),
            ("source-mac", "source-mac"),
            ("destination-mac", "destination-mac"),
        )
    else:
        leaf_map = (
            ("vlan", "vlan"),
            ("interface", "interface"),
            ("source-ip", "source-address"),
            ("source-prefix", "source-address"),
            ("destination-ip", "destination-address"),
            ("destination-prefix", "destination-address"),
            ("dscp", "dscp"),
            ("ecn", "ecn"),
            ("protocol", "protocol"),
            ("source-port", "source-port"),
            ("source-port-range", "source-port-range"),
            ("destination-port", "destination-port"),
            ("destination-port-range", "destination-port-range"),
            ("tcp-flags", "tcp-flags"),
            ("tcp-flags-mask", "tcp-flags-mask"),
        )

    from_leaves = [
        (public_leaf, _xml_child_text(term, leaf))
        for leaf, public_leaf in leaf_map
        if _xml_child_text(term, leaf)
    ]
    if from_leaves:
        def from_body(i):
            for public_leaf, value in from_leaves:
                _render_leaf(lines, i, public_leaf, value)

        _render_block(lines, indent, "from", from_body)
    action = _firewall_action(_xml_child_text(term, "action"))
    if action:
        _render_leaf(lines, indent, "then", action)


def _render_firewall_compiler_term(lines, indent, mode, term):
    if mode == "policer":
        from_leaves = [
            (leaf, _xml_child_text(term, leaf))
            for leaf in ("interface", "destination-mac")
            if _xml_child_text(term, leaf)
        ]
        then_leaves = [
            (leaf, _xml_child_text(term, leaf))
            for leaf in ("bandwidth", "burst-size")
            if _xml_child_text(term, leaf)
        ]
    elif mode == "egress":
        from_leaves = [
            (leaf, _xml_child_text(term, leaf))
            for leaf in ("interface", "source-mac", "destination-mac")
            if _xml_child_text(term, leaf)
        ]
        action = _firewall_action(_xml_child_text(term, "action"))
        then_leaves = [("", action)] if action else []
    else:
        return

    def mode_body(i):
        if from_leaves:
            def from_body(j):
                for leaf, value in from_leaves:
                    _render_leaf(lines, j, leaf, value)

            _render_block(lines, i, "from", from_body)
        if then_leaves:
            if mode == "egress" and then_leaves[0][0] == "":
                _render_leaf(lines, i, "then", then_leaves[0][1])
            else:
                def then_body(j):
                    for leaf, value in then_leaves:
                        _render_leaf(lines, j, leaf, value)

                _render_block(lines, i, "then", then_body)

    _render_block(lines, indent, mode, mode_body)


def _render_firewall_contents(root, lines, indent):
    family_entries = []
    for family in ("ethernet-switching", "inet"):
        entries = [
            (filter_name, public_term, None, term)
            for filter_name, public_term, term
            in _firewall_term_entries(root, family)
        ]
        if family == "ethernet-switching":
            entries.extend(_firewall_compiler_entries(root))
        if entries:
            family_entries.append((family, entries))
    if not family_entries:
        return

    def family_root_body(i):
        for family, entries in family_entries:
            filters = {}
            for filter_name, public_term, mode, term in entries:
                filters.setdefault(filter_name, []).append(
                    (public_term, mode, term))

            def family_body(j, family=family, filters=filters):
                for filter_name, terms in filters.items():
                    def filter_body(k, family=family, terms=terms):
                        for public_term, mode, term in terms:
                            def term_body(m, family=family, mode=mode,
                                          term=term):
                                if mode:
                                    _render_firewall_compiler_term(
                                        lines, m, mode, term)
                                else:
                                    _render_firewall_term(
                                        lines, m, family, term)

                            _render_block(lines, k, f"term {public_term}",
                                          term_body)

                    _render_block(lines, j, f"filter {filter_name}",
                                  filter_body)

            _render_block(lines, i, family, family_body)

    _render_block(lines, indent, "family", family_root_body)


def _render_firewall_block(root, lines, indent):
    _render_block_if_nonempty(
        lines, indent, "firewall",
        lambda i: _render_firewall_contents(root, lines, i))


def _render_netlab_root(root, lines, indent):
    rendered_public_interfaces = False
    for child in list(root):
        name = _xml_name(child)
        if name == "system":
            _render_block(lines, indent, "system",
                          lambda i: _render_system_contents(child, lines, i))
        elif name == "vlans":
            _render_block(lines, indent, "vlans",
                          lambda i: _render_vlans_contents(child, lines, i))
        elif name == "interfaces":
            if not rendered_public_interfaces:
                _render_public_interfaces_block(root, lines, indent)
                rendered_public_interfaces = True
        elif name == "protocols":
            _render_block(lines, indent, "protocols",
                          lambda i: _render_protocols_contents(child, lines, i))
        elif name == "chassis":
            _render_block(lines, indent, "chassis",
                          lambda i: _render_chassis_contents(child, lines, i))
        elif name == "snmp":
            _render_block(lines, indent, "snmp",
                          lambda i: _render_snmp_contents(child, lines, i))
        elif name == "control-plane":
            _render_block(lines, indent, "control-plane",
                          lambda i: _render_control_plane_contents(child, lines, i))
        elif name == "class-of-service":
            _render_block(lines, indent, "class-of-service",
                          lambda i: _render_class_of_service_contents(child, lines, i))
        elif name == "forwarding-options":
            _render_block_if_nonempty(
                lines, indent, "forwarding-options",
                lambda i: _render_forwarding_options_contents(child, lines, i))
        elif name == "ethernet-switching-options":
            _render_firewall_block(root, lines, indent)
            _render_block_if_nonempty(
                lines, indent, "ethernet-switching-options",
                lambda i: _render_ethernet_switching_options_contents(child, lines, i))
        elif name == "interfaces-routing":
            if not rendered_public_interfaces:
                _render_public_interfaces_block(root, lines, indent)
                rendered_public_interfaces = True
        elif name == "routing-options":
            _render_block_if_nonempty(
                lines, indent, "routing-options",
                lambda i: _render_routing_options_contents(child, lines, i))
        elif name == "routing-instances":
            _render_block_if_nonempty(
                lines, indent, "routing-instances",
                lambda i: _render_routing_instances_contents(child, lines, i))
        elif name == "policy-options":
            _render_block(lines, indent, "policy-options",
                          lambda i: _render_policy_options_contents(child, lines, i))
        else:
            _render_generic_config_node(child, lines, indent, include_self=True)


def _render_vlans_contents(node, lines, indent):
    entries = [node] if _xml_name(node) == "vlan" else [
        child for child in list(node) if _xml_name(child) == "vlan"]
    for vlan in entries:
        vname = _xml_child_text(vlan, "name")
        if not vname:
            continue
        def body(i, vlan=vlan):
            vid = _xml_child_text(vlan, "vlan-id")
            desc = _xml_child_text(vlan, "description")
            if vid:
                _render_leaf(lines, i, "vlan-id", vid)
            if desc:
                _render_leaf(lines, i, "description", f'"{desc}"')
        _render_block(lines, indent, vname, body)


def _render_system_contents(node, lines, indent):
    host_name = _xml_child_text(node, "host-name")
    if host_name:
        _render_leaf(lines, indent, "host-name", host_name)
    domain_name = _xml_child_text(node, "domain-name")
    if domain_name:
        _render_leaf(lines, indent, "domain-name", domain_name)
    for resolver in [child for child in list(node)
                     if _xml_name(child) == "name-server"]:
        address = _xml_child_text(resolver, "address")
        if address:
            _render_leaf(lines, indent, "name-server", address)
    authentication_order = _xml_child(node, "authentication-order")
    if authentication_order is not None:
        _render_system_authentication_order_contents(
            authentication_order, lines, indent)
    for server in [child for child in list(node)
                   if _xml_name(child) == "radius-server"]:
        _render_system_auth_server("radius-server", server, lines, indent)
    for server in [child for child in list(node)
                   if _xml_name(child) == "tacplus-server"]:
        _render_system_auth_server("tacplus-server", server, lines, indent)
    services = _xml_child(node, "services")
    if services is not None:
        _render_system_services_contents(services, lines, indent)
    ntp = _xml_child(node, "ntp")
    if ntp is not None:
        _render_system_ntp_contents(ntp, lines, indent)
    syslog = _xml_child(node, "syslog")
    if syslog is not None:
        _render_system_syslog_contents(syslog, lines, indent)
    login = _xml_child(node, "login")
    if login is not None:
        _render_system_login_contents(login, lines, indent)
    accounting = _xml_child(node, "accounting")
    if accounting is not None:
        _render_system_accounting_contents(accounting, lines, indent)


def _render_system_services_contents(node, lines, indent):
    def services_body(i):
        ssh = _xml_child(node, "ssh")
        if ssh is not None:
            ssh_enabled = _xml_child_text(ssh, "enable")
            root_login = _xml_child_text(ssh, "root-login")
            if ssh_enabled == "true" or root_login:
                def ssh_body(j):
                    if root_login:
                        _render_leaf(lines, j, "root-login", root_login)
                _render_block_if_nonempty(lines, i, "ssh", ssh_body)
                if ssh_enabled == "true" and not root_login:
                    _render_leaf(lines, i, "ssh")
        netconf = _xml_child(node, "netconf")
        if netconf is not None and _xml_child_text(netconf, "ssh") == "true":
            _render_block(lines, i, "netconf",
                          lambda j: _render_leaf(lines, j, "ssh"))
        restconf = _xml_child(node, "restconf")
        if restconf is not None and _xml_child_text(restconf, "https") == "true":
            _render_block(lines, i, "restconf",
                          lambda j: _render_leaf(lines, j, "https"))
        gnmi = _xml_child(node, "gnmi")
        if gnmi is not None:
            grpc = _xml_child_text(gnmi, "grpc")
            port = _xml_child_text(gnmi, "port")
            if grpc == "true" or port:
                def gnmi_body(j):
                    if grpc == "true":
                        _render_leaf(lines, j, "grpc")
                    if port:
                        _render_leaf(lines, j, "port", port)
                _render_block_if_nonempty(lines, i, "gnmi", gnmi_body)

    _render_block_if_nonempty(lines, indent, "services", services_body)


def _render_system_authentication_order_contents(node, lines, indent):
    methods = []
    for method in [child for child in list(node) if _xml_name(child) == "method"]:
        value = _xml_child_text(method, "name")
        if value:
            methods.append(value)
    if methods:
        _render_leaf(lines, indent, "authentication-order",
                     "[ " + " ".join(methods) + " ]")


def _render_system_auth_server(command, node, lines, indent):
    address = _xml_child_text(node, "address")
    if not address:
        return

    def server_body(i):
        leaves = ["secret", "port", "source-address", "timeout"]
        if command == "radius-server":
            leaves.append("retry")
        for leaf in leaves:
            value = _xml_child_text(node, leaf)
            if value:
                _render_leaf(lines, i, leaf, value)
        if _xml_child_text(node, "single-connection") == "true":
            _render_leaf(lines, i, "single-connection")

    _render_block(lines, indent, f"{command} {address}", server_body)


def _render_snmp_contents(node, lines, indent):
    contact = _xml_child_text(node, "contact")
    if contact:
        _render_leaf(lines, indent, "contact", contact)
    location = _xml_child_text(node, "location")
    if location:
        _render_leaf(lines, indent, "location", location)

    for community in [child for child in list(node)
                      if _xml_name(child) == "community"]:
        name = _xml_child_text(community, "name")
        if not name:
            continue

        def community_body(i, community=community):
            authorization = _xml_child_text(community, "authorization")
            if authorization:
                _render_leaf(lines, i, "authorization", authorization)
            for client in [child for child in list(community)
                           if _xml_name(child) == "clients"]:
                address = _xml_child_text(client, "address")
                if address:
                    _render_leaf(lines, i, "clients", address)

        _render_block(lines, indent, f"community {name}", community_body)

    for group in [child for child in list(node)
                  if _xml_name(child) == "trap-group"]:
        name = _xml_child_text(group, "name")
        if not name:
            continue

        def group_body(i, group=group):
            version = _xml_child_text(group, "version")
            if version:
                _render_leaf(lines, i, "version", version)
            for target in [child for child in list(group)
                           if _xml_name(child) == "targets"]:
                address = _xml_child_text(target, "address")
                if address:
                    _render_leaf(lines, i, "targets", address)

        _render_block(lines, indent, f"trap-group {name}", group_body)


def _render_system_ntp_contents(node, lines, indent):
    servers = [child for child in list(node) if _xml_name(child) == "server"]

    def ntp_body(i):
        for server in servers:
            address = _xml_child_text(server, "address")
            if not address:
                continue
            if _xml_child_text(server, "prefer") == "true":
                _render_block(lines, i, f"server {address}",
                              lambda j: _render_leaf(lines, j, "prefer"))
            else:
                _render_leaf(lines, i, "server", address)

    _render_block_if_nonempty(lines, indent, "ntp", ntp_body)


def _render_system_syslog_contents(node, lines, indent):
    def syslog_body(i):
        for kind in ("host", "file"):
            for entry in [child for child in list(node) if _xml_name(child) == kind]:
                item_name = _xml_child_text(entry, "name")
                any_level = _xml_child_text(entry, "any")
                if item_name and any_level:
                    _render_block(lines, i, f"{kind} {item_name}",
                                  lambda j, any_level=any_level:
                                  _render_leaf(lines, j, "any", any_level))

    _render_block_if_nonempty(lines, indent, "syslog", syslog_body)


def _render_system_login_contents(node, lines, indent):
    users = [child for child in list(node) if _xml_name(child) == "user"]

    def login_body(i):
        for user in users:
            user_name = _xml_child_text(user, "name")
            if not user_name:
                continue

            def user_body(j, user=user):
                login_class = _xml_child_text(user, "class")
                if login_class:
                    _render_leaf(lines, j, "class", login_class)
                auth = _xml_child(user, "authentication")
                if auth is not None:
                    def auth_body(k, auth=auth):
                        encrypted = _xml_child_text(auth, "encrypted-password")
                        ssh_rsa = _xml_child_text(auth, "ssh-rsa")
                        if encrypted:
                            _render_leaf(lines, k, "encrypted-password",
                                         encrypted)
                        if ssh_rsa:
                            _render_leaf(lines, k, "ssh-rsa", ssh_rsa)

                    _render_block_if_nonempty(lines, j, "authentication",
                                              auth_body)

            _render_block(lines, i, f"user {user_name}", user_body)

    _render_block_if_nonempty(lines, indent, "login", login_body)


def _render_system_accounting_contents(node, lines, indent):
    events = []
    events_node = _xml_child(node, "events")
    if events_node is not None:
        for event in [child for child in list(events_node)
                      if _xml_name(child) == "event"]:
            name = _xml_child_text(event, "name")
            if name:
                events.append(name)

    def accounting_body(i):
        if events:
            _render_leaf(lines, i, "events", "[ " + " ".join(events) + " ]")

    _render_block_if_nonempty(lines, indent, "accounting", accounting_body)


def _render_chassis_contents(node, lines, indent):
    for leaf in ("port-mode", "network-services"):
        value = _xml_child_text(node, leaf)
        if value:
            _render_leaf(lines, indent, leaf, value)


def _render_interfaces_contents(node, lines, indent):
    entries = [node] if _xml_name(node) == "interface" else [
        child for child in list(node) if _xml_name(child) == "interface"]
    for iface in entries:
        ifname = _xml_child_text(iface, "name")
        if not ifname:
            continue
        _render_block(lines, indent, ifname,
                      lambda i, iface=iface: _render_interface_body(iface, lines, i))


def _render_interface_body(iface, lines, indent):
    desc = _xml_child_text(iface, "description")
    native = _xml_child_text(iface, "native-vlan-id")
    if desc:
        _render_leaf(lines, indent, "description", f'"{desc}"')
    if _xml_child_text(iface, "disable") == "true":
        _render_leaf(lines, indent, "disable")
    if native:
        _render_leaf(lines, indent, "native-vlan-id", native)
    ether = _xml_child(iface, "ether-options")
    if ether is not None:
        lag = _xml_child_text(ether, "ieee8023ad")
        lacp = _xml_child(ether, "lacp")
        member_priority = (_xml_child_text(lacp, "port-priority")
                           if lacp is not None else "")
        if lag or member_priority:
            _render_block(lines, indent, "ether-options",
                          lambda i: _render_ether_options_body(
                              lag, member_priority, lines, i))
    agg = _xml_child(iface, "aggregated-ether-options")
    if agg is not None:
        _render_aggregated_ether_options(agg, lines, indent)
    unit = _xml_child(iface, "unit")
    if unit is not None:
        _render_unit(unit, lines, indent)


def _render_aggregated_ether_options(agg, lines, indent):
    min_links = _xml_child_text(agg, "minimum-links")
    hash_policy = _xml_child(agg, "hash-policy")
    rotation = (_xml_child_text(hash_policy, "rotation")
                if hash_policy is not None else "")
    lacp = _xml_child(agg, "lacp")
    mode = _xml_child_text(lacp, "mode") if lacp is not None else ""
    actor_key = _xml_child_text(lacp, "actor-key") if lacp is not None else ""
    periodic = _xml_child_text(lacp, "periodic") if lacp is not None else ""
    if not min_links and not rotation and not mode and not actor_key and not periodic:
        return
    def body(i):
        if min_links:
            _render_leaf(lines, i, "minimum-links", min_links)
        if rotation:
            _render_block(lines, i, "hash-policy",
                          lambda j: _render_leaf(lines, j, "rotation",
                                                 rotation))
        if mode or actor_key or periodic:
            _render_block(lines, i, "lacp",
                          lambda j: _render_lacp_ae_contents(
                              mode, actor_key, periodic, lines, j))
    _render_block(lines, indent, "aggregated-ether-options", body)


def _render_ether_options_body(lag, member_priority, lines, indent):
    if lag:
        _render_leaf(lines, indent, "802.3ad", lag)
    if member_priority:
        _render_block(lines, indent, "lacp",
                      lambda i: _render_leaf(lines, i, "port-priority",
                                             member_priority))


def _render_lacp_ae_contents(mode, actor_key, periodic, lines, indent):
    if mode:
        _render_leaf(lines, indent, mode)
    if actor_key:
        _render_leaf(lines, indent, "actor-key", actor_key)
    if periodic:
        _render_leaf(lines, indent, "periodic", periodic)


def _render_unit(unit, lines, indent):
    logical_units = [child for child in list(unit)
                     if _xml_name(child) == "logical-unit"]
    if not logical_units:
        return
    for lu in logical_units:
        uid = _xml_child_text(lu, "unit-id") or "0"
        _render_block(lines, indent, f"unit {uid}",
                      lambda i, lu=lu: _render_logical_unit_body(lu, lines, i))


def _render_logical_unit_body(lu, lines, indent):
    family = _xml_child(lu, "family")
    if family is None:
        return
    esw = _xml_child(family, "ethernet-switching")
    if esw is None:
        return
    def family_body(i):
        _render_block(lines, i, "ethernet-switching",
                      lambda j: _render_ethernet_switching_body(esw, lines, j))
    _render_block(lines, indent, "family", family_body)


def _render_ethernet_switching_body(esw, lines, indent):
    mode = _xml_child_text(esw, "interface-mode")
    if mode:
        _render_leaf(lines, indent, "interface-mode", mode)
    members = [child for child in list(esw) if _xml_name(child) == "vlan-members"]
    if members:
        def vlan_body(i):
            for member in members:
                if member.text and member.text.strip():
                    _render_leaf(lines, i, "members", member.text.strip())
        _render_block(lines, indent, "vlan", vlan_body)


def _render_protocols_contents(protocols, lines, indent):
    lldp = _xml_child(protocols, "lldp")
    if lldp is not None:
        _render_block(lines, indent, "lldp",
                      lambda i: _render_lldp_contents(lldp, lines, i))
    lacp = _xml_child(protocols, "lacp")
    if lacp is not None:
        _render_block(lines, indent, "lacp",
                      lambda i: _render_lacp_contents(lacp, lines, i))
    igmp = _xml_child(protocols, "igmp-snooping")
    if igmp is not None:
        _render_block(lines, indent, "igmp-snooping",
                      lambda i: _render_igmp_snooping_contents(
                          igmp, lines, i))
    rstp = _xml_child(protocols, "rstp")
    if rstp is not None:
        _render_block(lines, indent, "rstp",
                      lambda i: _render_rstp_contents(rstp, lines, i))
    mstp = _xml_child(protocols, "mstp")
    if mstp is not None:
        _render_block(lines, indent, "mstp",
                      lambda i: _render_mstp_contents(mstp, lines, i))
    ospf = _xml_child(protocols, "ospf")
    if ospf is not None:
        _render_block(lines, indent, "ospf",
                      lambda i: _render_ospf_contents(ospf, lines, i))
    bgp = _xml_child(protocols, "bgp")
    if bgp is not None:
        _render_block(lines, indent, "bgp",
                      lambda i: _render_bgp_contents(bgp, lines, i))


def _render_ospf_contents(node, lines, indent):
    node_name = _xml_name(node)
    if node_name == "interface":
        ifname = _xml_child_text(node, "name")
        if ifname:
            _render_leaf(lines, indent, "interface", ifname)
        return
    areas = [node] if node_name == "area" else [
        child for child in list(node) if _xml_name(child) == "area"]
    for area in areas:
        area_name = _xml_child_text(area, "name")
        if not area_name:
            continue

        def area_body(i, area=area):
            for iface in [child for child in list(area)
                          if _xml_name(child) == "interface"]:
                ifname = _xml_child_text(iface, "name")
                if ifname:
                    _render_leaf(lines, i, "interface", ifname)

        _render_block(lines, indent, f"area {area_name}", area_body)


def _render_bgp_contents(node, lines, indent):
    node_name = _xml_name(node)
    if node_name == "neighbor":
        addr = _xml_child_text(node, "address")
        peer_as = _xml_child_text(node, "peer-as")
        if addr:
            _render_block(lines, indent, f"neighbor {addr}",
                          lambda i: _render_leaf(lines, i, "peer-as", peer_as)
                          if peer_as else None)
        return
    groups = [node] if node_name == "group" else [
        child for child in list(node) if _xml_name(child) == "group"]
    for group in groups:
        group_name = _xml_child_text(group, "name")
        if not group_name:
            continue

        def group_body(i, group=group):
            for leaf in ("type", "export", "hold-time"):
                value = _xml_child_text(group, leaf)
                if value:
                    _render_leaf(lines, i, leaf, value)
            for neighbor in [child for child in list(group)
                             if _xml_name(child) == "neighbor"]:
                addr = _xml_child_text(neighbor, "address")
                peer_as = _xml_child_text(neighbor, "peer-as")
                if not addr:
                    continue
                _render_block(lines, i, f"neighbor {addr}",
                              lambda j, peer_as=peer_as:
                              _render_leaf(lines, j, "peer-as", peer_as)
                              if peer_as else None)

        _render_block(lines, indent, f"group {group_name}", group_body)


def _render_lldp_contents(node, lines, indent):
    if _xml_name(node) == "lldp":
        if _xml_child_text(node, "disable") == "true":
            _render_leaf(lines, indent, "disable")
        for leaf in ("transmit-interval", "hold-multiplier",
                     "system-name", "system-description",
                     "management-address"):
            value = _xml_child_text(node, leaf)
            if value:
                _render_leaf(lines, indent, f"{leaf} {value}")
    entries = [node] if _xml_name(node) == "interface" else [
        child for child in list(node) if _xml_name(child) == "interface"]
    for iface in entries:
        ifname = _xml_child_text(iface, "name")
        if not ifname:
            continue
        def body(i, iface=iface):
            if _xml_child_text(iface, "disable") == "true":
                _render_leaf(lines, i, "disable")
        _render_block(lines, indent, f"interface {ifname}", body)


def _render_igmp_snooping_contents(node, lines, indent):
    timeout = _xml_child_text(node, "membership-timeout")
    if timeout:
        _render_leaf(lines, indent, "membership-timeout", timeout)
    for vlan in [child for child in list(node)
                 if _xml_name(child) == "vlan"]:
        vlan_name = _xml_child_text(vlan, "name")
        if not vlan_name:
            continue

        def vlan_body(i, vlan=vlan):
            for iface in [child for child in list(vlan)
                          if _xml_name(child) == "interface"]:
                ifname = _xml_child_text(iface, "name")
                if not ifname:
                    continue

                def iface_body(j, iface=iface):
                    for group in [child for child in list(iface)
                                  if _xml_name(child) == "static-group"]:
                        if group.text and group.text.strip():
                            _render_leaf(lines, j, "static-group",
                                         group.text.strip())

                _render_block(lines, i, f"interface {ifname}", iface_body)

        _render_block(lines, indent, f"vlan {vlan_name}", vlan_body)


def _render_rstp_contents(node, lines, indent):
    if _xml_name(node) != "interface":
        for leaf in ("bridge-priority", "hello-time", "max-age",
                     "forward-delay"):
            value = _xml_child_text(node, leaf)
            if value:
                _render_leaf(lines, indent, leaf, value)
    entries = [node] if _xml_name(node) == "interface" else [
        child for child in list(node) if _xml_name(child) == "interface"]
    for iface in entries:
        ifname = _xml_child_text(iface, "name")
        if not ifname:
            continue
        def body(i, iface=iface):
            if _xml_child_text(iface, "edge") == "true":
                _render_leaf(lines, i, "edge")
            if _xml_child_text(iface, "bpdu-block-on-edge") == "true":
                _render_leaf(lines, i, "bpdu-block-on-edge")
            if _xml_child_text(iface, "root-protection") == "true":
                _render_leaf(lines, i, "root-protection")
            if _xml_child_text(iface, "loop-protection") == "true":
                _render_leaf(lines, i, "loop-protection")
            for leaf in ("path-cost", "port-priority"):
                value = _xml_child_text(iface, leaf)
                if value:
                    _render_leaf(lines, i, f"{leaf} {value}")
        _render_block(lines, indent, f"interface {ifname}", body)


def _render_mstp_contents(node, lines, indent):
    node_name = _xml_name(node)
    if node_name == "instance":
        _render_mstp_instance(node, lines, indent)
        return
    if node_name != "interface":
        for leaf in ("configuration-name", "revision-level",
                     "bridge-priority", "hello-time", "max-age",
                     "forward-delay", "max-hops"):
            value = _xml_child_text(node, leaf)
            if value:
                _render_leaf(lines, indent, leaf, value)
        for inst in [child for child in list(node)
                     if _xml_name(child) == "instance"]:
            inst_id = _xml_child_text(inst, "id")
            if inst_id:
                _render_block(lines, indent, f"instance {inst_id}",
                              lambda i, inst=inst:
                              _render_mstp_instance(inst, lines, i))
    entries = [node] if node_name == "interface" else [
        child for child in list(node) if _xml_name(child) == "interface"]
    for iface in entries:
        ifname = _xml_child_text(iface, "name")
        if not ifname:
            continue
        def body(i, iface=iface):
            if _xml_child_text(iface, "edge") == "true":
                _render_leaf(lines, i, "edge")
            if _xml_child_text(iface, "bpdu-block-on-edge") == "true":
                _render_leaf(lines, i, "bpdu-block-on-edge")
            if _xml_child_text(iface, "root-protection") == "true":
                _render_leaf(lines, i, "root-protection")
            if _xml_child_text(iface, "loop-protection") == "true":
                _render_leaf(lines, i, "loop-protection")
            for leaf in ("path-cost", "port-priority"):
                value = _xml_child_text(iface, leaf)
                if value:
                    _render_leaf(lines, i, f"{leaf} {value}")
        _render_block(lines, indent, f"interface {ifname}", body)


def _render_mstp_instance(inst, lines, indent):
    bridge_priority = _xml_child_text(inst, "bridge-priority")
    if bridge_priority:
        _render_leaf(lines, indent, "bridge-priority", bridge_priority)
    for vlan in [child for child in list(inst) if _xml_name(child) == "vlan"]:
        vlan_id = _xml_child_text(vlan, "vlan-id")
        if vlan_id:
            _render_leaf(lines, indent, "vlan", vlan_id)
    for iface in [child for child in list(inst)
                  if _xml_name(child) == "interface"]:
        ifname = _xml_child_text(iface, "name")
        if ifname:
            _render_block(lines, indent, f"interface {ifname}",
                          lambda i, iface=iface:
                          _render_mstp_instance_interface(iface, lines, i))


def _render_mstp_instance_interface(iface, lines, indent):
    for leaf in ("path-cost", "port-priority"):
        value = _xml_child_text(iface, leaf)
        if value:
            _render_leaf(lines, indent, f"{leaf} {value}")


def _render_lacp_contents(node, lines, indent):
    for leaf in ("system-id", "system-priority", "port-priority"):
        value = _xml_child_text(node, leaf)
        if value:
            _render_leaf(lines, indent, leaf, value)


def _render_rif_unit_family(iface, lines, indent, root, unit):
    rif = _xml_child_text(iface, "name")
    address = _xml_child_text(iface, "address")
    if not rif or not address:
        return
    arps = _static_arps_for_irb(root, rif, unit, address)

    def family_body(i):
        def inet_body(j):
            if not arps:
                _render_leaf(lines, j, "address", address)
                return

            def address_body(k):
                for arp in arps:
                    ip = arp.get("ip", "")
                    if not ip:
                        continue

                    def arp_body(m, arp=arp):
                        mac = arp.get("mac", "")
                        egress = arp.get("egress-interface", "")
                        if mac:
                            _render_leaf(lines, m, "mac", mac)
                        if egress:
                            _render_leaf(lines, m, "egress-interface",
                                         egress)

                    _render_block(lines, k, f"arp {ip}", arp_body)

            _render_block(lines, j, f"address {address}", address_body)

        _render_block(lines, i, "inet", inet_body)

    _render_block(lines, indent, "family", family_body)


def _render_physical_rif_unit(iface, lines, indent, root):
    _, unit = _physical_unit_from_rif(_xml_child_text(iface, "name"))
    if not unit:
        return
    _render_block(lines, indent, f"unit {unit}",
                  lambda i: _render_rif_unit_family(
                      iface, lines, i, root, unit))


def _render_interfaces_routing_contents(node, lines, indent, root=None):
    entries = [node] if _xml_name(node) == "interface" else [
        child for child in list(node) if _xml_name(child) == "interface"]

    def irb_body(i):
        for iface in entries:
            rif = _xml_child_text(iface, "name")
            unit = _irb_unit_from_rif(rif,
                                      _xml_child_text(iface, "vlan"))
            if not unit:
                continue
            _render_block(lines, i, f"unit {unit}",
                          lambda j, iface=iface, unit=unit:
                          _render_rif_unit_family(
                              iface, lines, j, root, unit))

    _render_block_if_nonempty(lines, indent, "irb", irb_body)


def _render_routing_options_contents(node, lines, indent):
    autonomous_system = _xml_child_text(node, "autonomous-system")
    if autonomous_system:
        _render_leaf(lines, indent, "autonomous-system", autonomous_system)
    static = _xml_child(node, "static")
    if static is None:
        return
    next_hop_index = _routing_next_hop_index(static)
    ecmp_index = _routing_ecmp_index(static, next_hop_index)

    def static_body(i):
        for route in [child for child in list(static)
                      if _xml_name(child) == "route"]:
            prefix = _xml_child_text(route, "prefix")
            if not prefix:
                continue

            def route_body(j, route=route):
                next_hops = _route_next_hop_displays(route, next_hop_index,
                                                     ecmp_index)
                for nh in next_hops:
                    _render_leaf(lines, j, "next-hop", nh)

            _render_block(lines, i, f"route {prefix}", route_body)

    _render_block_if_nonempty(lines, indent, "static", static_body)


def _render_vrf_routing_options_contents(node, lines, indent):
    static = _xml_child(node, "static")
    if static is None:
        return

    def static_body(i):
        for arp in [child for child in list(static)
                    if _xml_name(child) == "arp"]:
            ip = _xml_child_text(arp, "ip")
            if not ip:
                continue

            def arp_body(j, arp=arp):
                for leaf in ("mac", "interface", "egress-interface"):
                    value = _xml_child_text(arp, leaf)
                    if value:
                        _render_leaf(lines, j, leaf, value)

            _render_block(lines, i, f"arp {ip}", arp_body)

        for next_hop in [child for child in list(static)
                         if _xml_name(child) == "next-hop"]:
            next_hop_id = _xml_child_text(next_hop, "id")
            if not next_hop_id:
                continue

            def next_hop_body(j, next_hop=next_hop):
                arp_ip = _xml_child_text(next_hop, "arp-ip")
                interface = _xml_child_text(next_hop, "interface")
                if arp_ip:
                    _render_leaf(lines, j, "arp", arp_ip)
                if interface:
                    _render_leaf(lines, j, "interface", interface)

            _render_block(lines, i, f"next-hop {next_hop_id}",
                          next_hop_body)

        for ecmp in [child for child in list(static)
                     if _xml_name(child) == "ecmp"]:
            ecmp_id = _xml_child_text(ecmp, "id")
            if not ecmp_id:
                continue

            def ecmp_body(j, ecmp=ecmp):
                for member in _xml_child_texts(ecmp, "member"):
                    _render_leaf(lines, j, "member", member)

            _render_block(lines, i, f"ecmp {ecmp_id}", ecmp_body)

        for route in [child for child in list(static)
                      if _xml_name(child) == "route"]:
            prefix = _xml_child_text(route, "prefix")
            if not prefix:
                continue

            def route_body(j, route=route):
                for next_hop in _xml_child_texts(route,
                                                  "next-hop-address"):
                    _render_leaf(lines, j, "next-hop", next_hop)
                next_hop_id = _xml_child_text(route, "next-hop-id")
                ecmp_id = _xml_child_text(route, "ecmp-id")
                if next_hop_id:
                    _render_leaf(lines, j, "next-hop", next_hop_id)
                elif ecmp_id:
                    _render_leaf(lines, j, "ecmp", ecmp_id)

            _render_block(lines, i, f"route {prefix}", route_body)

    _render_block_if_nonempty(lines, indent, "static", static_body)


def _render_routing_instances_contents(node, lines, indent):
    instances = [node] if _xml_name(node) == "instance" else [
        child for child in list(node) if _xml_name(child) == "instance"]
    for instance in instances:
        instance_name = _xml_child_text(instance, "name")
        if not instance_name:
            continue

        def instance_body(i, instance=instance):
            instance_type = _xml_child_text(instance, "instance-type")
            if instance_type:
                _render_leaf(lines, i, "instance-type", instance_type)
            for iface in [child for child in list(instance)
                          if _xml_name(child) == "interface"]:
                if iface.text and iface.text.strip():
                    _render_leaf(lines, i, "interface", iface.text.strip())
            routing = _xml_child(instance, "routing-options")
            if routing is not None:
                _render_block_if_nonempty(
                    lines, i, "routing-options",
                    lambda j: _render_vrf_routing_options_contents(
                        routing, lines, j))

        _render_block(lines, indent, instance_name, instance_body)


def _render_policy_options_contents(node, lines, indent):
    node_name = _xml_name(node)
    if node_name == "term":
        _render_policy_term(node, lines, indent)
        return
    policies = [node] if node_name == "policy-statement" else [
        child for child in list(node) if _xml_name(child) == "policy-statement"]
    for policy in policies:
        policy_name = _xml_child_text(policy, "name")
        if not policy_name:
            continue

        def policy_body(i, policy=policy):
            for term in [child for child in list(policy)
                         if _xml_name(child) == "term"]:
                term_name = _xml_child_text(term, "name")
                if not term_name:
                    continue
                _render_block(lines, i, f"term {term_name}",
                              lambda j, term=term:
                              _render_policy_term(term, lines, j))

        _render_block(lines, indent, f"policy-statement {policy_name}",
                      policy_body)


def _render_policy_term(term, lines, indent):
    from_node = _xml_child(term, "from")
    if from_node is not None:
        route_filters = [child for child in list(from_node)
                         if _xml_name(child) == "route-filter"]
        if route_filters:
            def from_body(i):
                for rf in route_filters:
                    prefix = _xml_child_text(rf, "prefix")
                    match_type = _xml_child_text(rf, "match-type")
                    if prefix and match_type:
                        _render_leaf(lines, i, f"route-filter {prefix}",
                                     match_type)
            _render_block(lines, indent, "from", from_body)
    then_node = _xml_child(term, "then")
    action = _xml_child_text(then_node, "action") if then_node is not None else ""
    if action:
        _render_leaf(lines, indent, "then", action)


def _render_control_plane_contents(node, lines, indent):
    protection = _xml_child(node, "protection")
    if protection is None:
        return

    classes = [child for child in list(protection)
               if _xml_name(child) == "class"]
    if not classes:
        return

    def protection_body(i):
        for cls in classes:
            name = _xml_child_text(cls, "name")
            if not name:
                continue

            def class_body(j, cls=cls):
                for leaf in ("rate-pps", "burst-pkts"):
                    value = _xml_child_text(cls, leaf)
                    if value:
                        _render_leaf(lines, j, leaf, value)

            _render_block(lines, i, f"class {name}", class_body)

    _render_block(lines, indent, "protection", protection_body)


def _render_class_of_service_contents(node, lines, indent):
    scheduler = _xml_child(node, "scheduler")
    template_entries = []
    scheduler_entries = []
    if scheduler is not None:
        template_entries = [child for child in list(scheduler)
                            if _xml_name(child) == "template"]
        scheduler_interfaces = _xml_child(scheduler, "interfaces")
        if scheduler_interfaces is not None:
            scheduler_entries = [
                child for child in list(scheduler_interfaces)
                if _xml_name(child) == "interface"
            ]

    def public_scheduler_leaves(tmpl):
        leaves = []
        for item in list(tmpl):
            if _xml_name(item) != "group":
                continue
            if _xml_child_text(item, "id") != "0":
                continue
            strict = _xml_child_text(item, "strict-priority")
            rate = _xml_child_text(item, "rate-bps")
            burst = _xml_child_text(item, "burst-bits")
            if strict:
                leaves.append(("priority",
                               "strict-high" if strict == "true" else "low"))
            if rate:
                leaves.append(("transmit-rate", rate))
            if burst:
                leaves.append(("buffer-size", burst))
        return leaves

    def public_scheduler_interface_template(iface):
        template = _xml_child_text(iface, "template")
        if not template:
            return ""
        if _xml_child_text(iface, "traffic-class-enable-mask"):
            return ""
        for child in list(iface):
            if _xml_name(child) in ("traffic-class", "group"):
                return ""
        return template

    public_templates = [
        (tmpl, public_scheduler_leaves(tmpl))
        for tmpl in template_entries
        if public_scheduler_leaves(tmpl)
    ]
    scheduler_map_by_if = {}
    for iface in scheduler_entries:
        ifname = _xml_child_text(iface, "name")
        template = public_scheduler_interface_template(iface)
        if ifname and template:
            scheduler_map_by_if[ifname] = template

    interfaces = _xml_child(node, "interfaces")
    iface_entries = []
    if interfaces is not None:
        iface_entries = [child for child in list(interfaces)
                         if _xml_name(child) == "interface"]

    if iface_entries or scheduler_map_by_if:
        iface_by_name = {}
        ordered_names = []
        for iface in iface_entries:
            ifname = _xml_child_text(iface, "name")
            if ifname and ifname not in iface_by_name:
                iface_by_name[ifname] = iface
                ordered_names.append(ifname)
        for ifname in scheduler_map_by_if:
            if ifname not in iface_by_name:
                ordered_names.append(ifname)

        def interfaces_body(i):
            for ifname in ordered_names:
                iface = iface_by_name.get(ifname)

                def iface_body(j, iface=iface):
                    if iface is not None:
                        trust = _xml_child_text(iface, "trust")
                        priority = _xml_child_text(iface, "default-priority")
                        pfc = _xml_child(iface, "priority-flow-control")
                        if trust:
                            _render_leaf(lines, j, "trust", trust)
                        if priority:
                            _render_leaf(lines, j, "default-priority",
                                         priority)
                        if pfc is not None:
                            def pfc_body(k, pfc=pfc):
                                for leaf in ("rx-class-mask", "tx-class-mask",
                                             "lossless-smp-mask",
                                             "shared-pause-mask"):
                                    value = _xml_child_text(pfc, leaf)
                                    if value:
                                        _render_leaf(lines, k, leaf, value)

                            _render_block(lines, j, "priority-flow-control",
                                          pfc_body)
                    template = scheduler_map_by_if.get(ifname)
                    if template:
                        _render_leaf(lines, j, "scheduler-map", template)

                _render_block(lines, i, ifname, iface_body)

        _render_block(lines, indent, "interfaces", interfaces_body)

    forwarding = _xml_child(node, "forwarding")
    if forwarding is not None:
        maps = [child for child in list(forwarding)
                if _xml_name(child) == "switch-priority"]

        def forwarding_body(i):
            for item in maps:
                priority = _xml_child_text(item, "priority")
                tc = _xml_child_text(item, "traffic-class")
                if priority and tc:
                    _render_block(lines, i, f"switch-priority {priority}",
                                  lambda j, tc=tc: _render_leaf(
                                      lines, j, "traffic-class", tc))

        if maps:
            _render_block(lines, indent, "forwarding", forwarding_body)

    if public_templates:
        def public_schedulers_body(i):
            for tmpl, leaves in public_templates:
                tmpl_name = _xml_child_text(tmpl, "name")
                if not tmpl_name:
                    continue

                def public_scheduler_body(j, leaves=leaves):
                    for leaf, value in leaves:
                        _render_leaf(lines, j, leaf, value)

                _render_block(lines, i, tmpl_name, public_scheduler_body)

        _render_block(lines, indent, "schedulers", public_schedulers_body)

    if scheduler is not None:
        entries = scheduler_entries

        def scheduler_body(i):
            def render_scheduler_policy(policy_node, k, include_template,
                                        strip_public_group0=False):
                if include_template:
                    template = _xml_child_text(policy_node, "template")
                    if template:
                        _render_leaf(lines, k, "template", template)
                tc_enable = _xml_child_text(policy_node,
                                            "traffic-class-enable-mask")
                if tc_enable:
                    _render_leaf(lines, k, "traffic-class-enable-mask",
                                 tc_enable)
                for item in list(policy_node):
                    item_name = _xml_name(item)
                    if item_name == "traffic-class":
                        tc = _xml_child_text(item, "class")
                        group = _xml_child_text(item, "shaping-group")
                        if tc and group:
                            _render_block(
                                lines, k, f"traffic-class {tc}",
                                lambda m, group=group: _render_leaf(
                                    lines, m, "shaping-group", group))
                    if item_name == "group":
                        group_id = _xml_child_text(item, "id")
                        strict = _xml_child_text(item, "strict-priority")
                        weight = _xml_child_text(item, "weight")
                        rate = _xml_child_text(item, "rate-bps")
                        burst = _xml_child_text(item, "burst-bits")
                        if not group_id:
                            continue
                        if strip_public_group0 and group_id == "0":
                            strict = ""
                            rate = ""
                            burst = ""
                        if not strict and not weight and not rate and not burst:
                            continue

                        def group_body(m, strict=strict, weight=weight,
                                       rate=rate, burst=burst):
                            if strict:
                                _render_leaf(lines, m, "strict-priority",
                                             strict)
                            if weight:
                                _render_leaf(lines, m, "weight", weight)
                            if rate:
                                _render_leaf(lines, m, "rate-bps", rate)
                            if burst:
                                _render_leaf(lines, m, "burst-bits", burst)

                        _render_block(lines, k, f"group {group_id}",
                                      group_body)

            def templates_body(j):
                for tmpl in template_entries:
                    tmpl_name = _xml_child_text(tmpl, "name")
                    if not tmpl_name:
                        continue
                    _render_block_if_nonempty(
                        lines, j, tmpl_name,
                        lambda k, tmpl=tmpl: render_scheduler_policy(
                            tmpl, k, False, strip_public_group0=True))

            def interfaces_body(j):
                for iface in entries:
                    ifname = _xml_child_text(iface, "name")
                    template = _xml_child_text(iface, "template")
                    tc_enable = _xml_child_text(iface,
                                                "traffic-class-enable-mask")
                    tc_entries = [child for child in list(iface)
                                  if _xml_name(child) == "traffic-class"]
                    group_entries = [child for child in list(iface)
                                     if _xml_name(child) == "group"]
                    if not ifname or (not template and not tc_enable and
                                      not tc_entries and not group_entries):
                        continue

                    def iface_body(k, iface=iface):
                        include_template = (
                            public_scheduler_interface_template(iface) == "")
                        render_scheduler_policy(iface, k, include_template)

                    _render_block_if_nonempty(lines, j, ifname, iface_body)

            if template_entries:
                _render_block_if_nonempty(lines, i, "template", templates_body)
            _render_block_if_nonempty(lines, i, "interfaces", interfaces_body)

        if entries or template_entries:
            _render_block_if_nonempty(lines, indent, "scheduler",
                                      scheduler_body)

    watermarks = _xml_child(node, "watermarks")
    if watermarks is not None:
        priority_entries = [child for child in list(watermarks)
                            if _xml_name(child) == "switch-priority"]
        iface_entries = [child for child in list(watermarks)
                         if _xml_name(child) == "interface"]

        def watermarks_body(i):
            for pri_node in priority_entries:
                pri = _xml_child_text(pri_node, "priority")
                if not pri:
                    continue
                soft_drop = _xml_child_text(pri_node, "soft-drop")
                jitter = _xml_child_text(pri_node, "soft-drop-jitter")
                hog = _xml_child_text(pri_node, "soft-drop-hog")
                if not soft_drop and not jitter and not hog:
                    continue

                def pri_body(j, soft_drop=soft_drop,
                             jitter=jitter, hog=hog):
                    if soft_drop:
                        _render_leaf(lines, j, "soft-drop", soft_drop)
                    if jitter:
                        _render_leaf(lines, j, "soft-drop-jitter", jitter)
                    if hog:
                        _render_leaf(lines, j, "soft-drop-hog", hog)

                _render_block(lines, i, f"switch-priority {pri}",
                              pri_body)

            def iface_body(j, iface):
                for tc_node in list(iface):
                    if _xml_name(tc_node) != "traffic-class":
                        continue
                    tc = _xml_child_text(tc_node, "class")
                    if not tc:
                        continue
                    tx_hog = _xml_child_text(tc_node, "tx-hog")
                    tx_private = _xml_child_text(tc_node, "tx-private")
                    if not tx_hog and not tx_private:
                        continue

                    def tc_body(k, tx_hog=tx_hog,
                                tx_private=tx_private):
                        if tx_hog:
                            _render_leaf(lines, k, "tx-hog", tx_hog)
                        if tx_private:
                            _render_leaf(lines, k, "tx-private",
                                         tx_private)

                    _render_block(lines, j, f"traffic-class {tc}", tc_body)

            for iface in iface_entries:
                ifname = _xml_child_text(iface, "name")
                if not ifname:
                    continue
                _render_block(lines, i, f"interface {ifname}",
                              lambda j, iface=iface: iface_body(j, iface))

        if priority_entries or iface_entries:
            _render_block(lines, indent, "watermarks", watermarks_body)


def _render_ethernet_switching_options_contents(node, lines, indent):
    aging = _xml_child_text(node, "mac-table-aging-time")
    if aging:
        _render_leaf(lines, indent, "mac-table-aging-time", aging)

    secure_node = _xml_child(node, "secure-access-port")
    if secure_node is not None:
        interfaces = [child for child in list(secure_node)
                      if _xml_name(child) == "interface"]

        def secure_body(i):
            for iface in interfaces:
                ifname = _xml_child_text(iface, "name")
                if not ifname:
                    continue

                def iface_body(j, iface=iface):
                    limit = _xml_child_text(iface, "mac-limit")
                    if limit:
                        _render_leaf(lines, j, "mac-limit", limit)
                    action = _xml_child_text(iface, "violation-action")
                    if action:
                        _render_leaf(lines, j, "action", action)

                _render_block(lines, i, f"interface {ifname}", iface_body)

        if interfaces:
            _render_block(lines, indent, "secure-access-port", secure_body)

    mac_move_node = _xml_child(node, "mac-move")
    dampening_node = (_xml_child(mac_move_node, "dampening")
                      if mac_move_node is not None else None)
    if dampening_node is not None:
        def dampening_body(i):
            for leaf in ("threshold", "window", "action"):
                value = _xml_child_text(dampening_node, leaf)
                if value:
                    _render_leaf(lines, i, leaf, value)

        _render_block(lines, indent, "mac-move", lambda i:
                      _render_block(lines, i, "dampening", dampening_body))

    for security_name in ("dhcp-snooping", "arp-inspection"):
        security_node = _xml_child(node, security_name)
        if security_node is None:
            continue

        vlans = [child for child in list(security_node)
                 if _xml_name(child) == "vlan"]
        interfaces = [child for child in list(security_node)
                      if _xml_name(child) == "interface"]
        bindings = [child for child in list(security_node)
                    if _xml_name(child) == "binding"]

        def security_body(i, vlans=vlans, interfaces=interfaces,
                          bindings=bindings, security_name=security_name):
            for vlan in vlans:
                vname = _xml_child_text(vlan, "name")
                if vname:
                    _render_leaf(lines, i, "vlan", vname)
            for iface in interfaces:
                ifname = _xml_child_text(iface, "name")
                trusted = _xml_child_text(iface, "trusted")
                if ifname and trusted == "true":
                    _render_leaf(lines, i, f"interface {ifname} trusted")
            if security_name == "dhcp-snooping":
                for binding in bindings:
                    mac = _xml_child_text(binding, "mac-address")
                    vlan = _xml_child_text(binding, "vlan")
                    ifname = _xml_child_text(binding, "interface")
                    ip = _xml_child_text(binding, "ip-address")
                    if mac and vlan and ifname:
                        _render_leaf(lines, i,
                                     f"binding {mac} vlan {vlan} "
                                     f"interface {ifname}")
                    if mac and vlan and ip:
                        _render_leaf(lines, i,
                                     f"binding {mac} vlan {vlan} "
                                     f"ip-address {ip}")

        if vlans or interfaces or bindings:
            _render_block(lines, indent, security_name, security_body)

    acl_independent_node = _xml_child(node, "acl-independent")
    if acl_independent_node is not None:
        groups = [child for child in list(acl_independent_node)
                  if _xml_name(child) == "group"]

        def acl_independent_body(i, groups=groups):
            def acl_body(j):
                for group in groups:
                    gname = _xml_child_text(group, "name")
                    if not gname:
                        continue
                    terms = [child for child in list(group)
                             if _xml_name(child) == "term"]

                    def group_body(k, terms=terms):
                        for term in terms:
                            tname = _xml_child_text(term, "name")
                            family = _xml_child_text(term, "family")
                            if not tname or not family:
                                continue

                            def term_body(m, term=term):
                                for leaf in (
                                        "vlan", "interface", "source-mac",
                                        "destination-mac", "source-ip",
                                        "source-prefix", "destination-ip",
                                        "destination-prefix", "dscp", "ecn",
                                        "protocol", "source-port",
                                        "source-port-range",
                                        "destination-port",
                                        "destination-port-range",
                                        "tcp-flags", "tcp-flags-mask",
                                        "action", "bandwidth",
                                        "burst-size"):
                                    value = _xml_child_text(term, leaf)
                                    if value:
                                        _render_leaf(lines, m, leaf, value)

                            _render_block(lines, k,
                                          f"term {tname} {family}",
                                          term_body)

                    _render_block(lines, j, f"independent-group {gname}",
                                  group_body)

            _render_block(lines, i, "acl", acl_body)

        if groups:
            acl_independent_body(indent)

    for rate_node_name in ("storm-control", "ingress-rate-limit",
                           "egress-rate-limit"):
        rate_node = _xml_child(node, rate_node_name)
        if rate_node is not None:
            interfaces = [child for child in list(rate_node)
                          if _xml_name(child) == "interface"]

            def rate_body(i, interfaces=interfaces):
                for iface in interfaces:
                    ifname = _xml_child_text(iface, "name")
                    if not ifname:
                        continue

                    def iface_body(j, iface=iface):
                        bandwidth = _xml_child_text(iface, "bandwidth")
                        burst = _xml_child_text(iface, "burst-size")
                        if bandwidth:
                            _render_leaf(lines, j, "bandwidth", bandwidth)
                        if burst:
                            _render_leaf(lines, j, "burst-size", burst)

                    _render_block(lines, i, f"interface {ifname}", iface_body)

            if interfaces:
                _render_block(lines, indent, rate_node_name, rate_body)

    static_node = _xml_child(node, "static")
    if static_node is None:
        return

    entries = [child for child in list(static_node)
               if _xml_name(child) == "mac-table-entry"]
    if not entries:
        return

    def static_body(i):
        for entry in entries:
            mac = _xml_child_text(entry, "mac-address")
            vlan = _xml_child_text(entry, "vlan")
            ifname = _xml_child_text(entry, "interface")
            if not mac:
                continue
            def entry_body(j, vlan=vlan, ifname=ifname):
                if vlan:
                    _render_leaf(lines, j, "vlan", vlan)
                if ifname:
                    _render_leaf(lines, j, "interface", ifname)
            _render_block(lines, i, f"mac-table-entry {mac}", entry_body)

    _render_block(lines, indent, "static", static_body)


def _render_generic_config_node(node, lines, indent, include_self=True):
    name = _xml_name(node)
    children = list(node)
    text = (node.text or "").strip()
    if not children:
        if text == "true":
            _render_leaf(lines, indent, name)
        elif text and text != "false":
            _render_leaf(lines, indent, name, text)
        return
    if include_self:
        _render_block(lines, indent, name,
                      lambda i: [_render_generic_config_node(c, lines, i)
                                 for c in children])
    else:
        for child in children:
            _render_generic_config_node(child, lines, indent)


def _render_forwarding_options_contents(node, lines, indent):
    mirroring = _xml_child(node, "port-mirroring")
    if mirroring is None:
        return

    def mirror_body(i):
        for instance in [child for child in list(mirroring)
                         if _xml_name(child) == "instance"]:
            instance_name = _xml_child_text(instance, "name")
            if not instance_name:
                continue

            def instance_body(j, instance=instance):
                output = _xml_child(instance, "output")
                destination = (_xml_child_text(output, "interface")
                               if output is not None else "")
                if destination:
                    _render_block(
                        lines, j, "output",
                        lambda k: _render_leaf(lines, k, "interface",
                                               destination))
                input_node = _xml_child(instance, "input")
                sources = ([child for child in list(input_node)
                            if _xml_name(child) == "interface"]
                           if input_node is not None else [])
                if sources:
                    def input_body(k):
                        for source in sources:
                            source_name = _xml_child_text(source, "name")
                            direction = (_xml_child_text(source, "direction")
                                         or "ingress")
                            if not source_name:
                                continue
                            _render_block(
                                lines, k, f"interface {source_name}",
                                lambda m, direction=direction: _render_leaf(
                                    lines, m, "direction", direction))
                    _render_block(lines, j, "input", input_body)

            _render_block(lines, i, f"instance {instance_name}",
                          instance_body)

    _render_block(lines, indent, "port-mirroring", mirror_body)


def format_config_as_set(xml: str, change_prefix: str = "",
                          include_edit: bool = False,
                          path_tokens=None) -> str:
    """Format XML config as set-command style output."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception:
        return xml
    specialized = _format_netlab_config_set(root, change_prefix, include_edit)
    if specialized:
        return _filter_set_output(specialized, path_tokens, change_prefix)
    lines = ["[edit]"] if include_edit else []
    _walk_for_set(root, "", lines, change_prefix)
    return _filter_set_output("\n".join(lines), path_tokens, change_prefix)


def _filter_set_output(text: str, path_tokens, change_prefix: str = "") -> str:
    """Filter set-command output to a config subtree."""
    if not path_tokens:
        return text
    prefix = f"{change_prefix}set {' '.join(path_tokens)}"
    matches = []
    for line in text.splitlines():
        if line == "[edit]":
            matches.append(line)
            continue
        if line == prefix or line.startswith(prefix + " "):
            matches.append(line)
    return "\n".join(matches) if matches else "(empty)"


def _format_netlab_config_set(root, change_prefix: str = "",
                              include_edit: bool = False) -> str:
    def name(elem):
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        return tag

    def child_text(elem, tag):
        for child in list(elem):
            if name(child) == tag:
                return (child.text or "").strip()
        return ""

    def child_texts(elem, tag):
        values = []
        for child in list(elem):
            if name(child) == tag and child.text:
                value = child.text.strip()
                if value:
                    values.append(value)
        return values

    def child_find(elem, tag):
        for child in list(elem):
            if name(child) == tag:
                return child
        return None

    if name(root) != "netlab-config":
        return ""

    lines = ["[edit]"] if include_edit else []

    def emit(command):
        lines.append(f"{change_prefix}set {command}")

    for top in list(root):
        if name(top) == "system":
            host_name = child_text(top, "host-name")
            if host_name:
                emit(f"system host-name {host_name}")
            domain_name = child_text(top, "domain-name")
            if domain_name:
                emit(f"system domain-name {domain_name}")
            for resolver in list(top):
                if name(resolver) != "name-server":
                    continue
                address = child_text(resolver, "address")
                if address:
                    emit(f"system name-server {address}")
            auth_order = child_find(top, "authentication-order")
            if auth_order is not None:
                for method in list(auth_order):
                    if name(method) != "method":
                        continue
                    method_name = child_text(method, "name")
                    if method_name:
                        emit(f"system authentication-order {method_name}")
            for server_type in ("radius-server", "tacplus-server"):
                for server in list(top):
                    if name(server) != server_type:
                        continue
                    address = child_text(server, "address")
                    if not address:
                        continue
                    emit(f"system {server_type} {address}")
                    leaves = ["secret", "port", "source-address", "timeout"]
                    if server_type == "radius-server":
                        leaves.append("retry")
                    for leaf in leaves:
                        value = child_text(server, leaf)
                        if value:
                            emit(f"system {server_type} {address} "
                                 f"{leaf} {value}")
                    if child_text(server, "single-connection") == "true":
                        emit(f"system {server_type} {address} "
                             "single-connection")
            services = child_find(top, "services")
            if services is not None:
                ssh = child_find(services, "ssh")
                if ssh is not None:
                    if child_text(ssh, "enable") == "true":
                        emit("system services ssh")
                    root_login = child_text(ssh, "root-login")
                    if root_login:
                        emit(f"system services ssh root-login {root_login}")
                netconf = child_find(services, "netconf")
                if netconf is not None and child_text(netconf, "ssh") == "true":
                    emit("system services netconf ssh")
                restconf = child_find(services, "restconf")
                if restconf is not None and child_text(restconf, "https") == "true":
                    emit("system services restconf https")
                gnmi = child_find(services, "gnmi")
                if gnmi is not None:
                    if child_text(gnmi, "grpc") == "true":
                        emit("system services gnmi grpc")
                    port = child_text(gnmi, "port")
                    if port:
                        emit(f"system services gnmi port {port}")
            ntp = child_find(top, "ntp")
            if ntp is not None:
                for server in list(ntp):
                    if name(server) != "server":
                        continue
                    address = child_text(server, "address")
                    if not address:
                        continue
                    if child_text(server, "prefer") == "true":
                        emit(f"system ntp server {address} prefer")
                    else:
                        emit(f"system ntp server {address}")
            syslog = child_find(top, "syslog")
            if syslog is not None:
                for kind in ("host", "file"):
                    for entry in list(syslog):
                        if name(entry) != kind:
                            continue
                        item_name = child_text(entry, "name")
                        any_level = child_text(entry, "any")
                        if item_name and any_level:
                            emit(f"system syslog {kind} {item_name} "
                                 f"any {any_level}")
            login = child_find(top, "login")
            if login is not None:
                for user in list(login):
                    if name(user) != "user":
                        continue
                    user_name = child_text(user, "name")
                    if not user_name:
                        continue
                    login_class = child_text(user, "class")
                    if login_class:
                        emit(f"system login user {user_name} class "
                             f"{login_class}")
                    auth = child_find(user, "authentication")
                    if auth is not None:
                        encrypted = child_text(auth, "encrypted-password")
                        ssh_rsa = child_text(auth, "ssh-rsa")
                        if encrypted:
                            emit("system login user "
                                 f"{user_name} authentication "
                                 f"encrypted-password {encrypted}")
                        if ssh_rsa:
                            emit("system login user "
                                 f"{user_name} authentication ssh-rsa "
                                 f"{ssh_rsa}")
            accounting = child_find(top, "accounting")
            if accounting is not None:
                events_node = child_find(accounting, "events")
                if events_node is not None:
                    for event in list(events_node):
                        if name(event) != "event":
                            continue
                        event_name = child_text(event, "name")
                        if event_name:
                            emit(f"system accounting events {event_name}")
        elif name(top) == "snmp":
            contact = child_text(top, "contact")
            if contact:
                emit(f"snmp contact {contact}")
            location = child_text(top, "location")
            if location:
                emit(f"snmp location {location}")
            for community in list(top):
                if name(community) != "community":
                    continue
                community_name = child_text(community, "name")
                if not community_name:
                    continue
                authorization = child_text(community, "authorization")
                if authorization:
                    emit("snmp community "
                         f"{community_name} authorization {authorization}")
                else:
                    emit(f"snmp community {community_name}")
                for client in list(community):
                    if name(client) != "clients":
                        continue
                    address = child_text(client, "address")
                    if address:
                        emit(f"snmp community {community_name} "
                             f"clients {address}")
            for group in list(top):
                if name(group) != "trap-group":
                    continue
                group_name = child_text(group, "name")
                if not group_name:
                    continue
                version = child_text(group, "version")
                if version:
                    emit(f"snmp trap-group {group_name} version {version}")
                else:
                    emit(f"snmp trap-group {group_name}")
                for target in list(group):
                    if name(target) != "targets":
                        continue
                    address = child_text(target, "address")
                    if address:
                        emit(f"snmp trap-group {group_name} "
                             f"targets {address}")
        elif name(top) == "vlans":
            for vlan in list(top):
                if name(vlan) != "vlan":
                    continue
                vname = child_text(vlan, "name")
                if not vname:
                    continue
                vid = child_text(vlan, "vlan-id")
                desc = child_text(vlan, "description")
                if vid:
                    emit(f"vlans {vname} vlan-id {vid}")
                if desc:
                    emit(f"vlans {vname} description \"{desc}\"")
        elif name(top) == "interfaces":
            for iface in list(top):
                if name(iface) != "interface":
                    continue
                ifname = child_text(iface, "name")
                if not ifname:
                    continue
                desc = child_text(iface, "description")
                disable = child_text(iface, "disable")
                native = child_text(iface, "native-vlan-id")
                if desc:
                    emit(f"interfaces {ifname} description \"{desc}\"")
                if disable == "true":
                    emit(f"interfaces {ifname} disable")
                if native:
                    emit(f"interfaces {ifname} native-vlan-id {native}")
                for child in list(iface):
                    if name(child) == "ether-options":
                        lag = child_text(child, "ieee8023ad")
                        if lag:
                            emit(f"interfaces {ifname} ether-options 802.3ad {lag}")
                        for ether_child in list(child):
                            if name(ether_child) == "lacp":
                                value = child_text(ether_child, "port-priority")
                                if value:
                                    emit(f"interfaces {ifname} ether-options lacp port-priority {value}")
                    if name(child) == "aggregated-ether-options":
                        min_links = child_text(child, "minimum-links")
                        if min_links:
                            emit(f"interfaces {ifname} aggregated-ether-options minimum-links {min_links}")
                        for agg_child in list(child):
                            if name(agg_child) == "hash-policy":
                                rotation = child_text(agg_child, "rotation")
                                if rotation:
                                    emit(f"interfaces {ifname} aggregated-ether-options hash-policy rotation {rotation}")
                            if name(agg_child) == "lacp":
                                mode = child_text(agg_child, "mode")
                                actor_key = child_text(agg_child, "actor-key")
                                periodic = child_text(agg_child, "periodic")
                                if mode:
                                    emit(f"interfaces {ifname} aggregated-ether-options lacp {mode}")
                                if actor_key:
                                    emit(f"interfaces {ifname} aggregated-ether-options lacp actor-key {actor_key}")
                                if periodic:
                                    emit(f"interfaces {ifname} aggregated-ether-options lacp periodic {periodic}")
                    if name(child) != "unit":
                        continue
                    for unit in list(child):
                        if name(unit) != "logical-unit":
                            continue
                        uid = child_text(unit, "unit-id") or "0"
                        for family in list(unit):
                            if name(family) != "family":
                                continue
                            for esw in list(family):
                                if name(esw) != "ethernet-switching":
                                    continue
                                mode = child_text(esw, "interface-mode")
                                if mode:
                                    emit(
                                        f"interfaces {ifname} unit {uid} family ethernet-switching interface-mode {mode}")
                                for member in list(esw):
                                    if name(member) == "vlan-members" and member.text:
                                        emit(
                                            f"interfaces {ifname} unit {uid} family ethernet-switching vlan members {member.text.strip()}")
        elif name(top) == "protocols":
            for proto in list(top):
                if name(proto) == "lldp":
                    if child_text(proto, "disable") == "true":
                        emit("protocols lldp disable")
                    for leaf in ("transmit-interval", "hold-multiplier",
                                 "system-name", "system-description",
                                 "management-address"):
                        value = child_text(proto, leaf)
                        if value:
                            emit(f"protocols lldp {leaf} {value}")
                    for iface in list(proto):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        if not ifname:
                            continue
                        emit(f"protocols lldp interface {ifname}")
                        if child_text(iface, "disable") == "true":
                            emit(f"protocols lldp interface {ifname} disable")
                if name(proto) == "rstp":
                    for leaf in ("bridge-priority", "hello-time", "max-age",
                                 "forward-delay"):
                        value = child_text(proto, leaf)
                        if value:
                            emit(f"protocols rstp {leaf} {value}")
                    for iface in list(proto):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        if not ifname:
                            continue
                        emit(f"protocols rstp interface {ifname}")
                        if child_text(iface, "edge") == "true":
                            emit(f"protocols rstp interface {ifname} edge")
                        if child_text(iface, "bpdu-block-on-edge") == "true":
                            emit(f"protocols rstp interface {ifname} bpdu-block-on-edge")
                        if child_text(iface, "root-protection") == "true":
                            emit(f"protocols rstp interface {ifname} root-protection")
                        if child_text(iface, "loop-protection") == "true":
                            emit(f"protocols rstp interface {ifname} loop-protection")
                        for leaf in ("path-cost", "port-priority"):
                            value = child_text(iface, leaf)
                            if value:
                                emit(f"protocols rstp interface {ifname} {leaf} {value}")
                if name(proto) == "igmp-snooping":
                    timeout = child_text(proto, "membership-timeout")
                    if timeout:
                        emit(f"protocols igmp-snooping membership-timeout {timeout}")
                    for vlan in list(proto):
                        if name(vlan) != "vlan":
                            continue
                        vlan_name = child_text(vlan, "name")
                        if not vlan_name:
                            continue
                        for iface in list(vlan):
                            if name(iface) != "interface":
                                continue
                            ifname = child_text(iface, "name")
                            if not ifname:
                                continue
                            for group in list(iface):
                                if name(group) == "static-group" and group.text:
                                    emit("protocols igmp-snooping vlan "
                                         f"{vlan_name} interface {ifname} "
                                         f"static-group {group.text.strip()}")
                if name(proto) == "mstp":
                    for leaf in ("configuration-name", "revision-level",
                                 "bridge-priority", "hello-time", "max-age",
                                 "forward-delay", "max-hops"):
                        value = child_text(proto, leaf)
                        if value:
                            emit(f"protocols mstp {leaf} {value}")
                    for inst in list(proto):
                        if name(inst) != "instance":
                            continue
                        inst_id = child_text(inst, "id")
                        if not inst_id:
                            continue
                        value = child_text(inst, "bridge-priority")
                        if value:
                            emit(f"protocols mstp instance {inst_id} bridge-priority {value}")
                        for vlan in list(inst):
                            if name(vlan) != "vlan":
                                continue
                            vlan_id = child_text(vlan, "vlan-id")
                            if vlan_id:
                                emit(f"protocols mstp instance {inst_id} vlan {vlan_id}")
                        for iface in list(inst):
                            if name(iface) != "interface":
                                continue
                            ifname = child_text(iface, "name")
                            if not ifname:
                                continue
                            emit(f"protocols mstp instance {inst_id} interface {ifname}")
                            for leaf in ("path-cost", "port-priority"):
                                value = child_text(iface, leaf)
                                if value:
                                    emit(f"protocols mstp instance {inst_id} interface {ifname} {leaf} {value}")
                    for iface in list(proto):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        if not ifname:
                            continue
                        emit(f"protocols mstp interface {ifname}")
                        if child_text(iface, "edge") == "true":
                            emit(f"protocols mstp interface {ifname} edge")
                        if child_text(iface, "bpdu-block-on-edge") == "true":
                            emit(f"protocols mstp interface {ifname} bpdu-block-on-edge")
                        if child_text(iface, "root-protection") == "true":
                            emit(f"protocols mstp interface {ifname} root-protection")
                        if child_text(iface, "loop-protection") == "true":
                            emit(f"protocols mstp interface {ifname} loop-protection")
                        for leaf in ("path-cost", "port-priority"):
                            value = child_text(iface, leaf)
                            if value:
                                emit(f"protocols mstp interface {ifname} {leaf} {value}")
                if name(proto) == "lacp":
                    for leaf in ("system-id", "system-priority", "port-priority"):
                        value = child_text(proto, leaf)
                        if value:
                            emit(f"protocols lacp {leaf} {value}")
                if name(proto) == "ospf":
                    for area in list(proto):
                        if name(area) != "area":
                            continue
                        area_name = child_text(area, "name")
                        if not area_name:
                            continue
                        for iface in list(area):
                            if name(iface) != "interface":
                                continue
                            ifname = child_text(iface, "name")
                            if ifname:
                                emit("protocols ospf area "
                                     f"{area_name} interface {ifname}")
                if name(proto) == "bgp":
                    for group in list(proto):
                        if name(group) != "group":
                            continue
                        group_name = child_text(group, "name")
                        if not group_name:
                            continue
                        for leaf in ("type", "export", "hold-time"):
                            value = child_text(group, leaf)
                            if value:
                                emit(f"protocols bgp group {group_name} {leaf} {value}")
                        for neighbor in list(group):
                            if name(neighbor) != "neighbor":
                                continue
                            addr = child_text(neighbor, "address")
                            peer_as = child_text(neighbor, "peer-as")
                            if addr and peer_as:
                                emit("protocols bgp group "
                                     f"{group_name} neighbor {addr} peer-as {peer_as}")
        elif name(top) == "control-plane":
            protection = next((x for x in list(top)
                               if name(x) == "protection"), None)
            if protection is not None:
                for cls in list(protection):
                    if name(cls) != "class":
                        continue
                    cname = child_text(cls, "name")
                    if not cname:
                        continue
                    for leaf in ("rate-pps", "burst-pkts"):
                        value = child_text(cls, leaf)
                        if value:
                            emit("control-plane protection class "
                                 f"{cname} {leaf} {value}")
        elif name(top) == "interfaces-routing":
            for iface in list(top):
                if name(iface) != "interface":
                    continue
                rif = child_text(iface, "name")
                if not rif:
                    continue
                vlan = child_text(iface, "vlan")
                address = child_text(iface, "address")
                unit = _irb_unit_from_rif(rif, vlan)
                physical_ifname, physical_unit = _physical_unit_from_rif(rif)
                if unit and address:
                    emit("interfaces irb unit "
                         f"{unit} family inet address {address}")
                    for arp in _static_arps_for_irb(root, rif, unit, address):
                        ip = arp.get("ip", "")
                        if not ip:
                            continue
                        base = ("interfaces irb unit "
                                f"{unit} family inet address {address} "
                                f"arp {ip}")
                        mac = arp.get("mac", "")
                        egress = arp.get("egress-interface", "")
                        if mac:
                            emit(f"{base} mac {mac}")
                        if egress:
                            emit(f"{base} egress-interface {egress}")
                elif unit:
                    emit(f"interfaces irb unit {unit}")
                elif physical_ifname and physical_unit and address:
                    base = (f"interfaces {physical_ifname} unit "
                            f"{physical_unit} family inet address {address}")
                    emit(base)
                    for arp in _static_arps_for_irb(
                            root, rif, physical_unit, address):
                        ip = arp.get("ip", "")
                        if not ip:
                            continue
                        arp_base = f"{base} arp {ip}"
                        mac = arp.get("mac", "")
                        egress = arp.get("egress-interface", "")
                        if mac:
                            emit(f"{arp_base} mac {mac}")
                        if egress:
                            emit(f"{arp_base} egress-interface {egress}")
        elif name(top) == "chassis":
            for leaf in ("port-mode", "network-services"):
                value = child_text(top, leaf)
                if value:
                    emit(f"chassis {leaf} {value}")
        elif name(top) == "forwarding-options":
            mirroring = child_find(top, "port-mirroring")
            if mirroring is None:
                continue
            for instance in list(mirroring):
                if name(instance) != "instance":
                    continue
                instance_name = child_text(instance, "name")
                if not instance_name:
                    continue
                base = ("forwarding-options port-mirroring instance "
                        f"{instance_name}")
                output = child_find(instance, "output")
                destination = (child_text(output, "interface")
                               if output is not None else "")
                if destination:
                    emit(f"{base} output interface {destination}")
                input_node = child_find(instance, "input")
                if input_node is None:
                    continue
                for source in list(input_node):
                    if name(source) != "interface":
                        continue
                    source_name = child_text(source, "name")
                    direction = child_text(source, "direction") or "ingress"
                    if source_name:
                        emit(f"{base} input interface {source_name} "
                             f"direction {direction}")
        elif name(top) == "routing-options":
            autonomous_system = child_text(top, "autonomous-system")
            if autonomous_system:
                emit(f"routing-options autonomous-system {autonomous_system}")
            static = child_find(top, "static")
            if static is None:
                continue
            next_hop_index = {}
            ecmp_index = {}
            for item in list(static):
                if name(item) == "next-hop":
                    nhid = child_text(item, "id")
                    arp = child_text(item, "arp-ip")
                    if nhid and arp:
                        next_hop_index[nhid] = arp
            for item in list(static):
                if name(item) != "ecmp":
                    continue
                ecmp_id = child_text(item, "id")
                if not ecmp_id:
                    continue
                members = []
                for member in list(item):
                    if name(member) != "member" or not member.text:
                        continue
                    nhid = member.text.strip()
                    members.append(next_hop_index.get(nhid, nhid))
                ecmp_index[ecmp_id] = members
            for item in list(static):
                if name(item) == "route":
                    prefix = child_text(item, "prefix")
                    next_hops = child_texts(item, "next-hop-address")
                    if not next_hops:
                        nhid = child_text(item, "next-hop-id")
                        nh = next_hop_index.get(nhid, nhid)
                        if nh:
                            next_hops = [nh]
                    ecmp = child_text(item, "ecmp-id")
                    if not next_hops and ecmp:
                        next_hops = ecmp_index.get(ecmp, [])
                    if prefix:
                        for nh in next_hops:
                            emit("routing-options static "
                                 f"route {prefix} next-hop {nh}")
        elif name(top) == "routing-instances":
            for instance in list(top):
                if name(instance) != "instance":
                    continue
                instance_name = child_text(instance, "name")
                if not instance_name:
                    continue
                instance_type = child_text(instance, "instance-type")
                if instance_type:
                    emit(f"routing-instances {instance_name} "
                         f"instance-type {instance_type}")
                for iface in child_texts(instance, "interface"):
                    emit(f"routing-instances {instance_name} "
                         f"interface {iface}")
                scoped = child_find(instance, "routing-options")
                static = child_find(scoped, "static") if scoped is not None else None
                if static is None:
                    continue
                for item in list(static):
                    item_name = name(item)
                    if item_name == "arp":
                        ip = child_text(item, "ip")
                        for leaf in ("mac", "interface",
                                     "egress-interface"):
                            value = child_text(item, leaf)
                            if ip and value:
                                emit(f"routing-instances {instance_name} "
                                     f"routing-options static arp {ip} "
                                     f"{leaf} {value}")
                    elif item_name == "next-hop":
                        nhid = child_text(item, "id")
                        arp = child_text(item, "arp-ip")
                        interface = child_text(item, "interface")
                        if nhid and arp:
                            emit(f"routing-instances {instance_name} "
                                 f"routing-options static next-hop {nhid} "
                                 f"arp {arp}")
                        if nhid and interface:
                            emit(f"routing-instances {instance_name} "
                                 f"routing-options static next-hop {nhid} "
                                 f"interface {interface}")
                    elif item_name == "ecmp":
                        ecmp_id = child_text(item, "id")
                        for member in child_texts(item, "member"):
                            if ecmp_id:
                                emit(f"routing-instances {instance_name} "
                                     f"routing-options static ecmp {ecmp_id} "
                                     f"member {member}")
                for item in list(static):
                    if name(item) != "route":
                        continue
                    prefix = child_text(item, "prefix")
                    for nh in child_texts(item, "next-hop-address"):
                        emit(f"routing-instances {instance_name} "
                             f"routing-options static route {prefix} "
                             f"next-hop {nh}")
                    nhid = child_text(item, "next-hop-id")
                    ecmp_id = child_text(item, "ecmp-id")
                    if prefix and nhid:
                        emit(f"routing-instances {instance_name} "
                             f"routing-options static route {prefix} "
                             f"next-hop {nhid}")
                    elif prefix and ecmp_id:
                        emit(f"routing-instances {instance_name} "
                             f"routing-options static route {prefix} "
                             f"ecmp {ecmp_id}")
        elif name(top) == "policy-options":
            for policy in list(top):
                if name(policy) != "policy-statement":
                    continue
                policy_name = child_text(policy, "name")
                if not policy_name:
                    continue
                for term in list(policy):
                    if name(term) != "term":
                        continue
                    term_name = child_text(term, "name")
                    if not term_name:
                        continue
                    from_node = child_find(term, "from")
                    if from_node is not None:
                        for rf in list(from_node):
                            if name(rf) != "route-filter":
                                continue
                            prefix = child_text(rf, "prefix")
                            match_type = child_text(rf, "match-type")
                            if prefix and match_type:
                                emit("policy-options policy-statement "
                                     f"{policy_name} term {term_name} "
                                     f"from route-filter {prefix} {match_type}")
                    then_node = child_find(term, "then")
                    action = child_text(then_node, "action") if then_node is not None else ""
                    if action:
                        emit("policy-options policy-statement "
                             f"{policy_name} term {term_name} then {action}")
        elif name(top) == "class-of-service":
            for child in list(top):
                if name(child) == "interfaces":
                    for iface in list(child):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        if not ifname:
                            continue
                        trust = child_text(iface, "trust")
                        priority = child_text(iface, "default-priority")
                        if trust:
                            emit("class-of-service interfaces "
                                 f"{ifname} trust {trust}")
                        if priority:
                            emit("class-of-service interfaces "
                                 f"{ifname} default-priority {priority}")
                        pfc = child_find(iface, "priority-flow-control")
                        if pfc is not None:
                            for leaf in ("rx-class-mask", "tx-class-mask",
                                         "lossless-smp-mask",
                                         "shared-pause-mask"):
                                value = child_text(pfc, leaf)
                                if value:
                                    emit("class-of-service interfaces "
                                         f"{ifname} priority-flow-control "
                                         f"{leaf} {value}")
                if name(child) == "forwarding":
                    for item in list(child):
                        if name(item) != "switch-priority":
                            continue
                        priority = child_text(item, "priority")
                        tc = child_text(item, "traffic-class")
                        if priority and tc:
                            emit("class-of-service forwarding "
                                 f"switch-priority {priority} "
                                 f"traffic-class {tc}")
                if name(child) == "scheduler":
                    def emit_scheduler_policy(prefix, policy_node,
                                              scheduler_name=None):
                        tc_enable = child_text(policy_node,
                                               "traffic-class-enable-mask")
                        if tc_enable:
                            emit(f"{prefix} traffic-class-enable-mask "
                                 f"{tc_enable}")
                        for item in list(policy_node):
                            if name(item) == "traffic-class":
                                tc = child_text(item, "class")
                                group = child_text(item, "shaping-group")
                                if tc and group:
                                    emit(f"{prefix} traffic-class {tc} "
                                         f"shaping-group {group}")
                            if name(item) == "group":
                                group_id = child_text(item, "id")
                                strict = child_text(item, "strict-priority")
                                weight = child_text(item, "weight")
                                rate = child_text(item, "rate-bps")
                                burst = child_text(item, "burst-bits")
                                if scheduler_name and group_id == "0":
                                    if strict:
                                        priority = ("strict-high"
                                                    if strict == "true"
                                                    else "low")
                                        emit("class-of-service schedulers "
                                             f"{scheduler_name} priority "
                                             f"{priority}")
                                    if rate:
                                        emit("class-of-service schedulers "
                                             f"{scheduler_name} "
                                             f"transmit-rate {rate}")
                                    if burst:
                                        emit("class-of-service schedulers "
                                             f"{scheduler_name} "
                                             f"buffer-size {burst}")
                                    strict = ""
                                    rate = ""
                                    burst = ""
                                if group_id and strict:
                                    emit(f"{prefix} group {group_id} "
                                         f"strict-priority {strict}")
                                if group_id and weight:
                                    emit(f"{prefix} group {group_id} "
                                         f"weight {weight}")
                                if group_id and rate:
                                    emit(f"{prefix} group {group_id} "
                                         f"rate-bps {rate}")
                                if group_id and burst:
                                    emit(f"{prefix} group {group_id} "
                                         f"burst-bits {burst}")

                    for tmpl in list(child):
                        if name(tmpl) != "template":
                            continue
                        tmpl_name = child_text(tmpl, "name")
                        if not tmpl_name:
                            continue
                        emit_scheduler_policy(
                            f"class-of-service scheduler template {tmpl_name}",
                            tmpl, scheduler_name=tmpl_name)

                    interfaces = child_find(child, "interfaces")
                    if interfaces is None:
                        continue
                    for iface in list(interfaces):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        if not ifname:
                            continue
                        template = child_text(iface, "template")
                        if template:
                            emit("class-of-service interfaces "
                                 f"{ifname} scheduler-map {template}")
                        emit_scheduler_policy(
                            f"class-of-service scheduler interfaces {ifname}",
                            iface)
                if name(child) == "watermarks":
                    for pri_node in list(child):
                        if name(pri_node) != "switch-priority":
                            continue
                        pri = child_text(pri_node, "priority")
                        if not pri:
                            continue
                        for leaf in ("soft-drop", "soft-drop-jitter",
                                     "soft-drop-hog"):
                            value = child_text(pri_node, leaf)
                            if value:
                                emit("class-of-service watermarks "
                                     f"switch-priority {pri} "
                                     f"{leaf} {value}")
                    for iface in list(child):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        if not ifname:
                            continue
                        for tc_node in list(iface):
                            if name(tc_node) != "traffic-class":
                                continue
                            tc = child_text(tc_node, "class")
                            if not tc:
                                continue
                            for leaf in ("tx-hog", "tx-private"):
                                value = child_text(tc_node, leaf)
                                if value:
                                    emit("class-of-service watermarks "
                                         f"interface {ifname} "
                                         f"traffic-class {tc} "
                                         f"{leaf} {value}")
        elif name(top) == "ethernet-switching-options":
            aging = child_text(top, "mac-table-aging-time")
            if aging:
                emit(f"ethernet-switching-options mac-table-aging-time {aging}")
            for child in list(top):
                if name(child) == "secure-access-port":
                    for iface in list(child):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        limit = child_text(iface, "mac-limit")
                        if ifname and limit:
                            emit("ethernet-switching-options secure-access-port "
                                 f"interface {ifname} mac-limit {limit}")
                        action = child_text(iface, "violation-action")
                        if ifname and action:
                            emit("ethernet-switching-options secure-access-port "
                                 f"interface {ifname} action {action}")
                if name(child) == "mac-move":
                    dampening = next((x for x in list(child)
                                      if name(x) == "dampening"), None)
                    if dampening is not None:
                        for leaf in ("threshold", "window", "action"):
                            value = child_text(dampening, leaf)
                            if value:
                                emit("ethernet-switching-options mac-move "
                                     f"dampening {leaf} {value}")
                if name(child) in ("dhcp-snooping", "arp-inspection"):
                    feature = name(child)
                    for item in list(child):
                        if name(item) == "vlan":
                            vname = child_text(item, "name")
                            if vname:
                                emit("ethernet-switching-options "
                                     f"{feature} vlan {vname}")
                        if name(item) == "interface":
                            ifname = child_text(item, "name")
                            trusted = child_text(item, "trusted")
                            if ifname and trusted == "true":
                                emit("ethernet-switching-options "
                                     f"{feature} interface {ifname} trusted")
                        if feature == "dhcp-snooping" and name(item) == "binding":
                            mac = child_text(item, "mac-address")
                            vlan = child_text(item, "vlan")
                            ifname = child_text(item, "interface")
                            ip = child_text(item, "ip-address")
                            if mac and vlan and ifname:
                                emit("ethernet-switching-options "
                                     "dhcp-snooping binding "
                                     f"{mac} vlan {vlan} interface {ifname}")
                            if mac and vlan and ip:
                                emit("ethernet-switching-options "
                                     "dhcp-snooping binding "
                                     f"{mac} vlan {vlan} ip-address {ip}")
                if name(child) in ("user-filter", "ingress-acl"):
                    for term in list(child):
                        if name(term) != "term":
                            continue
                        tname = child_text(term, "name")
                        if not tname:
                            continue
                        filter_name, public_term = _firewall_filter_term(tname)
                        prefix = ("firewall family ethernet-switching "
                                  f"filter {filter_name} "
                                  f"term {public_term}")
                        for leaf in ("vlan", "interface", "source-mac",
                                     "destination-mac"):
                            value = child_text(term, leaf)
                            if value:
                                emit(f"{prefix} from {leaf} {value}")
                        action = _firewall_action(child_text(term, "action"))
                        if action:
                            emit(f"{prefix} then {action}")
                if name(child) == "egress-acl":
                    for term in list(child):
                        if name(term) != "term":
                            continue
                        tname = child_text(term, "name")
                        if not tname:
                            continue
                        prefix = _firewall_compiler_set_prefix(tname, "egress")
                        for leaf in ("interface", "source-mac",
                                     "destination-mac"):
                            value = child_text(term, leaf)
                            if value:
                                emit(f"{prefix} from {leaf} {value}")
                        action = _firewall_action(child_text(term, "action"))
                        if action:
                            emit(f"{prefix} then {action}")
                if name(child) == "ingress-ipv4-acl":
                    for term in list(child):
                        if name(term) != "term":
                            continue
                        tname = child_text(term, "name")
                        if not tname:
                            continue
                        filter_name, public_term = _firewall_filter_term(tname)
                        prefix = ("firewall family inet "
                                  f"filter {filter_name} term {public_term}")
                        leaf_map = (
                            ("vlan", "vlan"),
                            ("interface", "interface"),
                            ("source-ip", "source-address"),
                            ("source-prefix", "source-address"),
                            ("destination-ip", "destination-address"),
                            ("destination-prefix", "destination-address"),
                            ("dscp", "dscp"),
                            ("ecn", "ecn"),
                            ("protocol", "protocol"),
                            ("source-port", "source-port"),
                            ("source-port-range", "source-port-range"),
                            ("destination-port", "destination-port"),
                            ("destination-port-range",
                             "destination-port-range"),
                            ("tcp-flags", "tcp-flags"),
                            ("tcp-flags-mask", "tcp-flags-mask"),
                        )
                        for leaf, public_leaf in leaf_map:
                            value = child_text(term, leaf)
                            if value:
                                emit(f"{prefix} from {public_leaf} {value}")
                        action = _firewall_action(child_text(term, "action"))
                        if action:
                            emit(f"{prefix} then {action}")
                if name(child) == "acl-policer":
                    for term in list(child):
                        if name(term) != "term":
                            continue
                        tname = child_text(term, "name")
                        if not tname:
                            continue
                        prefix = _firewall_compiler_set_prefix(tname,
                                                               "policer")
                        for leaf in ("interface", "destination-mac"):
                            value = child_text(term, leaf)
                            if value:
                                emit(f"{prefix} from {leaf} {value}")
                        for leaf in ("bandwidth", "burst-size"):
                            value = child_text(term, leaf)
                            if value:
                                emit(f"{prefix} then {leaf} {value}")
                if name(child) == "acl-independent":
                    for group in list(child):
                        if name(group) != "group":
                            continue
                        gname = child_text(group, "name")
                        if not gname:
                            continue
                        for term in list(group):
                            if name(term) != "term":
                                continue
                            tname = child_text(term, "name")
                            family = child_text(term, "family")
                            if not tname or not family:
                                continue
                            prefix = ("ethernet-switching-options acl "
                                      f"independent-group {gname} "
                                      f"term {tname} {family}")
                            emit(prefix)
                            for leaf in ("vlan", "interface", "source-mac",
                                         "destination-mac", "source-ip",
                                         "source-prefix", "destination-ip",
                                         "destination-prefix", "dscp", "ecn",
                                         "protocol", "source-port",
                                         "source-port-range",
                                         "destination-port",
                                         "destination-port-range",
                                         "tcp-flags", "tcp-flags-mask",
                                         "action", "bandwidth",
                                         "burst-size"):
                                value = child_text(term, leaf)
                                if value:
                                    emit(f"{prefix} {leaf} {value}")
                if name(child) in ("storm-control", "ingress-rate-limit",
                                   "egress-rate-limit"):
                    feature = name(child)
                    for iface in list(child):
                        if name(iface) != "interface":
                            continue
                        ifname = child_text(iface, "name")
                        bandwidth = child_text(iface, "bandwidth")
                        burst = child_text(iface, "burst-size")
                        if ifname and bandwidth:
                            emit(f"ethernet-switching-options {feature} "
                                 f"interface {ifname} bandwidth {bandwidth}")
                        if ifname and burst:
                            emit(f"ethernet-switching-options {feature} "
                                 f"interface {ifname} burst-size {burst}")
                if name(child) != "static":
                    continue
                for entry in list(child):
                    if name(entry) != "mac-table-entry":
                        continue
                    mac = child_text(entry, "mac-address")
                    vlan = child_text(entry, "vlan")
                    ifname = child_text(entry, "interface")
                    if mac and vlan and ifname:
                        emit("ethernet-switching-options static "
                             f"mac-table-entry {mac} vlan {vlan} interface {ifname}")

    if include_edit:
        return "\n".join(lines) if len(lines) > 1 else "[edit]"
    return "\n".join(lines)


def _walk_for_set(elem, path, lines, change_prefix=""):
    """Walk config tree and emit set-command format."""
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    # Skip namespace wrapper
    if tag == "netlab-config":
        for child in elem:
            _walk_for_set(child, "", lines, change_prefix)
        return
    current = f"{path} {tag}".strip()
    children = list(elem)
    txt = (elem.text or "").strip()
    if not children and txt:
        lines.append(f"{change_prefix}set {current} {txt}")
    elif not children and tag not in ("vlans", "interfaces", "ethernet-switching",
                                       "family", "unit"):
        lines.append(f"{change_prefix}set {current}")
    else:
        for child in children:
            _walk_for_set(child, current, lines, change_prefix)


def format_config_diff(xml: str) -> str:
    """Format candidate vs active diff XML into Junos-style comparison."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception:
        return xml

    lines = []
    _walk_diff(root, "", lines)
    return "\n".join(lines) if lines else "No changes between candidate and active config"


def _walk_diff(elem, path, lines):
    """Walk diff XML and emit [+] / [-] prefixed lines."""
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    current = f"{path} {tag}".strip()
    children = list(elem)
    txt = (elem.text or "").strip()
    if not children and txt:
        lines.append(f"+    {current} {txt};")
    elif not children:
        lines.append(f"+    {current};")
    else:
        for child in children:
            _walk_diff(child, current, lines)
