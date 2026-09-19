"""Translate Junos-like configuration commands to configd paths."""

from feature_policy import (unsupported_config_delete_leaf,
                            unsupported_config_leaf)

def cli_to_path(tokens):
    if not tokens:
        return None, ""
    if _is_legacy_rate_limit(tokens):
        return None, ""
    if tokens[0] == "system":
        return _path_system(tokens[1:])
    if tokens[0] == "snmp":
        return _path_snmp(tokens[1:])
    if tokens[0] == "vlans":
        return _path_vlans(tokens[1:])
    if tokens[0] == "interfaces" and len(tokens) >= 2 and tokens[1] == "irb":
        return _path_interfaces_irb(tokens[1:])
    if tokens[0] == "interfaces":
        return _path_interfaces(tokens[1:])
    if tokens[0] == "protocols":
        return _path_protocols(tokens[1:])
    if tokens[0] == "chassis":
        return _path_chassis(tokens[1:])
    if tokens[0] == "control-plane":
        return _path_control_plane(tokens[1:])
    if tokens[0] == "firewall":
        return _path_firewall(tokens[1:])
    if tokens[0] == "class-of-service":
        return _path_class_of_service(tokens[1:])
    if tokens[0] == "forwarding-options":
        return _path_forwarding_options(tokens[1:])
    if tokens[0] == "ethernet-switching-options":
        return _path_ethernet_switching_options(tokens[1:])
    if tokens[0] == "interfaces-routing":
        return None, ""
    if tokens[0] == "routing-options":
        return _path_routing_options(tokens[1:])
    if tokens[0] == "routing-instances":
        return _path_routing_instances(tokens[1:])
    if tokens[0] == "policy-options":
        return _path_policy_options(tokens[1:])
    return "/netlab:netlab-config/" + "/".join(tokens), ""

def cli_to_delete_path(tokens):
    if not tokens:
        return None
    if _is_legacy_rate_limit(tokens):
        return None
    if tokens[0] == "system":
        return _delete_path_system(tokens[1:])
    if tokens[0] == "snmp":
        return _delete_path_snmp(tokens[1:])
    if tokens[0] == "vlans" and len(tokens) == 2:
        return "/netlab:netlab-config/vlans/vlan[name='" + tokens[1] + "']"
    if tokens[0] == "interfaces" and len(tokens) >= 2 and tokens[1] == "irb":
        path = _delete_path_interfaces_irb(tokens[1:])
        if path:
            return path
    if tokens[0] == "interfaces":
        path = _delete_path_interfaces(tokens[1:])
        if path:
            return path
    if tokens[0] == "protocols":
        path = _delete_path_protocols(tokens[1:])
        if path:
            return path
    if tokens[0] == "chassis":
        path = _delete_path_chassis(tokens[1:])
        if path:
            return path
    if tokens[0] == "control-plane":
        path = _delete_path_control_plane(tokens[1:])
        if path:
            return path
    if tokens[0] == "firewall":
        path = _delete_path_firewall(tokens[1:])
        if path:
            return path
    if tokens[0] == "class-of-service":
        path = _delete_path_class_of_service(tokens[1:])
        if path:
            return path
    if tokens[0] == "forwarding-options":
        path = _delete_path_forwarding_options(tokens[1:])
        if path:
            return path
    if tokens[0] == "ethernet-switching-options":
        path = _delete_path_ethernet_switching_options(tokens[1:])
        if path:
            return path
    if tokens[0] == "interfaces-routing":
        return None
    if tokens[0] == "routing-options":
        path = _delete_path_routing_options(tokens[1:])
        if path:
            return path
    if tokens[0] == "routing-instances":
        path = _delete_path_routing_instances(tokens[1:])
        if path:
            return path
    if tokens[0] == "policy-options":
        path = _delete_path_policy_options(tokens[1:])
        if path:
            return path
    result = cli_to_path(tokens)
    if result is None:
        return None
    path, _ = result
    return path

def _is_legacy_rate_limit(tokens):
    return (len(tokens) >= 2 and
            tokens[0] == "ethernet-switching-options" and
            tokens[1] == "rate-limit")


def _path_forwarding_options(tokens):
    if len(tokens) < 3 or tokens[0] != "port-mirroring" or \
            tokens[1] != "instance":
        return "/netlab:netlab-config/forwarding-options/" + "/".join(tokens), ""
    instance = tokens[2]
    base = ("/netlab:netlab-config/forwarding-options/port-mirroring"
            "/instance[name='" + instance + "']")
    if len(tokens) == 3:
        return base + "/name", instance
    if len(tokens) == 6 and tokens[3:5] == ["output", "interface"]:
        return base + "/output/interface", tokens[5]
    if len(tokens) in (6, 8) and tokens[3:5] == ["input", "interface"]:
        source = tokens[5]
        source_base = base + "/input/interface[name='" + source + "']"
        if len(tokens) == 6:
            return source_base + "/name", source
        if tokens[6] == "direction":
            return source_base + "/direction", tokens[7]
    return base + "/" + "/".join(tokens[3:]), ""


def _delete_path_forwarding_options(tokens):
    root = "/netlab:netlab-config/forwarding-options"
    if not tokens:
        return root
    if tokens == ["port-mirroring"]:
        return root + "/port-mirroring"
    if len(tokens) < 3 or tokens[0] != "port-mirroring" or \
            tokens[1] != "instance":
        return None
    base = (root + "/port-mirroring/instance[name='" + tokens[2] + "']")
    if len(tokens) == 3:
        return base
    if tokens[3:] == ["output"]:
        return base + "/output"
    if tokens[3:] == ["output", "interface"]:
        return base + "/output/interface"
    if len(tokens) >= 6 and tokens[3:5] == ["input", "interface"]:
        source_base = base + "/input/interface[name='" + tokens[5] + "']"
        if len(tokens) == 6:
            return source_base
        if tokens[6:] == ["direction"]:
            return source_base + "/direction"
    return None


def _is_ipv4_address(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _irb_unit_to_rif(unit):
    return "vlan" + unit


def _physical_unit_to_rif(ifname, unit):
    if unit != "0":
        return ""
    return ifname + ".0"


def _path_physical_rif(ifname, rest):
    if len(rest) < 4 or tuple(rest[:3]) != ("unit", "0", "family") or \
            rest[3] != "inet":
        return None
    rif = _physical_unit_to_rif(ifname, rest[1])
    base = ("/netlab:netlab-config/interfaces-routing"
            "/interface[name='" + rif + "']")
    inet = rest[4:]
    if not inet:
        return base + "/name", rif
    if len(inet) >= 2 and inet[0] == "address":
        if len(inet) >= 4 and inet[2] == "arp":
            ip = inet[3]
            arp = ("/netlab:netlab-config/routing-options/static"
                   "/arp[ip='" + ip + "']")
            if len(inet) == 4:
                return arp + "/ip", ip
            if len(inet) >= 6 and inet[4] in (
                    "mac", "egress-interface", "interface"):
                return arp + "/" + inet[4], inet[5]
            return arp + "/" + "/".join(inet[4:]), ""
        return base + "/address", inet[1]
    return base + "/" + "/".join(inet), ""


def _delete_path_physical_rif(ifname, rest):
    if len(rest) < 4 or tuple(rest[:3]) != ("unit", "0", "family") or \
            rest[3] != "inet":
        return None
    rif = _physical_unit_to_rif(ifname, rest[1])
    base = ("/netlab:netlab-config/interfaces-routing"
            "/interface[name='" + rif + "']")
    inet = rest[4:]
    if not inet:
        return base
    if len(inet) >= 1 and inet[0] == "address":
        if len(inet) >= 4 and inet[2] == "arp":
            arp = ("/netlab:netlab-config/routing-options/static"
                   "/arp[ip='" + inet[3] + "']")
            if len(inet) == 4:
                return arp
            if inet[4] in ("mac", "egress-interface", "interface"):
                return arp + "/" + inet[4]
            return arp + "/" + "/".join(inet[4:])
        return base + "/address"
    return None


def _path_system(tokens):
    if len(tokens) >= 2 and tokens[0] == "host-name":
        return "/netlab:netlab-config/system/host-name", tokens[1]
    if len(tokens) >= 2 and tokens[0] == "domain-name":
        return "/netlab:netlab-config/system/domain-name", tokens[1]
    if len(tokens) >= 2 and tokens[0] == "name-server":
        addr = tokens[1]
        return ("/netlab:netlab-config/system/name-server"
                "[address='" + addr + "']/address"), addr
    if len(tokens) >= 2 and tokens[0] == "authentication-order":
        method = tokens[1]
        base = ("/netlab:netlab-config/system/authentication-order"
                "/method[name='" + method + "']")
        return base + "/name", method
    if len(tokens) >= 2 and tokens[0] in ("radius-server", "tacplus-server"):
        server_type = tokens[0]
        address = tokens[1]
        base = ("/netlab:netlab-config/system/" + server_type +
                "[address='" + address + "']")
        if len(tokens) == 2:
            return base + "/address", address
        leaves = ("secret", "port", "source-address", "timeout")
        if server_type == "radius-server":
            leaves = leaves + ("retry",)
        if len(tokens) >= 4 and tokens[2] in leaves:
            return base + "/" + tokens[2], " ".join(tokens[3:])
        if (server_type == "tacplus-server" and len(tokens) == 3 and
                tokens[2] == "single-connection"):
            return base + "/single-connection", "true"
    if len(tokens) >= 2 and tokens[0] == "services":
        if tokens[1] == "ssh":
            if len(tokens) == 2:
                return "/netlab:netlab-config/system/services/ssh/enable", "true"
            if len(tokens) >= 4 and tokens[2] == "root-login":
                return ("/netlab:netlab-config/system/services/ssh"
                        "/root-login"), tokens[3]
        if len(tokens) >= 3 and tokens[1] == "netconf" and tokens[2] == "ssh":
            return "/netlab:netlab-config/system/services/netconf/ssh", "true"
        if (len(tokens) >= 3 and tokens[1] in ("restconf", "rest") and
                tokens[2] == "https"):
            return "/netlab:netlab-config/system/services/restconf/https", "true"
        if len(tokens) >= 3 and tokens[1] == "gnmi":
            if tokens[2] == "grpc":
                return "/netlab:netlab-config/system/services/gnmi/grpc", "true"
            if len(tokens) >= 4 and tokens[2] == "port":
                return "/netlab:netlab-config/system/services/gnmi/port", tokens[3]
    if len(tokens) >= 3 and tokens[0] == "ntp" and tokens[1] == "server":
        addr = tokens[2]
        base = "/netlab:netlab-config/system/ntp/server[address='" + addr + "']"
        if len(tokens) == 3:
            return base + "/address", addr
        if len(tokens) >= 4 and tokens[3] == "prefer":
            return base + "/prefer", "true"
    if len(tokens) >= 5 and tokens[0] == "syslog" and tokens[1] in ("host", "file"):
        target = tokens[1]
        name = tokens[2]
        if tokens[3] == "any":
            return ("/netlab:netlab-config/system/syslog/" + target +
                    "[name='" + name + "']/any"), tokens[4]
    if len(tokens) >= 3 and tokens[0] == "login" and tokens[1] == "user":
        user = tokens[2]
        base = "/netlab:netlab-config/system/login/user[name='" + user + "']"
        if len(tokens) == 3:
            return base + "/name", user
        if len(tokens) >= 5 and tokens[3] == "class":
            return base + "/class", tokens[4]
        if len(tokens) >= 6 and tokens[3] == "authentication":
            if tokens[4] == "encrypted-password":
                return base + "/authentication/encrypted-password", tokens[5]
            if tokens[4] == "ssh-rsa":
                return base + "/authentication/ssh-rsa", " ".join(tokens[5:])
    if len(tokens) >= 3 and tokens[0] == "accounting" and tokens[1] == "events":
        event = tokens[2]
        base = ("/netlab:netlab-config/system/accounting/events"
                "/event[name='" + event + "']")
        return base + "/name", event
    return "/netlab:netlab-config/system/" + "/".join(tokens), ""


def _delete_path_system(tokens):
    if not tokens:
        return "/netlab:netlab-config/system"
    if tokens[0] == "host-name":
        return "/netlab:netlab-config/system/host-name"
    if tokens[0] == "domain-name":
        return "/netlab:netlab-config/system/domain-name"
    if len(tokens) >= 2 and tokens[0] == "name-server":
        return ("/netlab:netlab-config/system/name-server"
                "[address='" + tokens[1] + "']")
    if len(tokens) >= 1 and tokens[0] == "authentication-order":
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/authentication-order"
        return ("/netlab:netlab-config/system/authentication-order"
                "/method[name='" + tokens[1] + "']")
    if len(tokens) >= 1 and tokens[0] in ("radius-server", "tacplus-server"):
        server_type = tokens[0]
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/" + server_type
        base = ("/netlab:netlab-config/system/" + server_type +
                "[address='" + tokens[1] + "']")
        leaves = ("secret", "port", "source-address", "timeout")
        if server_type == "radius-server":
            leaves = leaves + ("retry",)
        if server_type == "tacplus-server":
            leaves = leaves + ("single-connection",)
        if len(tokens) >= 3 and tokens[2] in leaves:
            return base + "/" + tokens[2]
        return base
    if tokens[0] == "services":
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/services"
        if tokens[1] == "ssh":
            if len(tokens) == 2:
                return "/netlab:netlab-config/system/services/ssh"
            if len(tokens) >= 3 and tokens[2] == "root-login":
                return "/netlab:netlab-config/system/services/ssh/root-login"
        if len(tokens) >= 3 and tokens[1] == "netconf" and tokens[2] == "ssh":
            return "/netlab:netlab-config/system/services/netconf/ssh"
        if (len(tokens) >= 3 and tokens[1] in ("restconf", "rest") and
                tokens[2] == "https"):
            return "/netlab:netlab-config/system/services/restconf/https"
        if len(tokens) >= 3 and tokens[1] == "gnmi":
            if tokens[2] == "grpc":
                return "/netlab:netlab-config/system/services/gnmi/grpc"
            if tokens[2] == "port":
                return "/netlab:netlab-config/system/services/gnmi/port"
    if len(tokens) >= 1 and tokens[0] == "ntp":
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/ntp"
        if len(tokens) >= 3 and tokens[1] == "server":
            base = ("/netlab:netlab-config/system/ntp/server"
                    "[address='" + tokens[2] + "']")
            if len(tokens) >= 4 and tokens[3] == "prefer":
                return base + "/prefer"
            return base
    if len(tokens) >= 1 and tokens[0] == "syslog":
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/syslog"
        if len(tokens) >= 3 and tokens[1] in ("host", "file"):
            base = ("/netlab:netlab-config/system/syslog/" + tokens[1] +
                    "[name='" + tokens[2] + "']")
            if len(tokens) >= 4 and tokens[3] == "any":
                return base + "/any"
            return base
    if len(tokens) >= 1 and tokens[0] == "login":
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/login"
        if len(tokens) >= 3 and tokens[1] == "user":
            base = "/netlab:netlab-config/system/login/user[name='" + tokens[2] + "']"
            if len(tokens) == 3:
                return base
            if len(tokens) >= 4 and tokens[3] == "class":
                return base + "/class"
            if len(tokens) >= 5 and tokens[3] == "authentication":
                if tokens[4] in ("encrypted-password", "ssh-rsa"):
                    return base + "/authentication/" + tokens[4]
                return base + "/authentication"
    if len(tokens) >= 1 and tokens[0] == "accounting":
        if len(tokens) == 1:
            return "/netlab:netlab-config/system/accounting"
        if len(tokens) >= 2 and tokens[1] == "events":
            if len(tokens) == 2:
                return "/netlab:netlab-config/system/accounting/events"
            return ("/netlab:netlab-config/system/accounting/events"
                    "/event[name='" + tokens[2] + "']")
    return None


def _path_snmp(tokens):
    if len(tokens) >= 2 and tokens[0] == "contact":
        return "/netlab:netlab-config/snmp/contact", " ".join(tokens[1:])
    if len(tokens) >= 2 and tokens[0] == "location":
        return "/netlab:netlab-config/snmp/location", " ".join(tokens[1:])
    if len(tokens) >= 2 and tokens[0] == "community":
        community = tokens[1]
        base = "/netlab:netlab-config/snmp/community[name='" + community + "']"
        if len(tokens) == 2:
            return base + "/name", community
        if len(tokens) >= 4 and tokens[2] == "authorization":
            return base + "/authorization", tokens[3]
        if len(tokens) >= 4 and tokens[2] == "clients":
            client = tokens[3]
            return base + "/clients[address='" + client + "']/address", client
    if len(tokens) >= 2 and tokens[0] == "trap-group":
        group = tokens[1]
        base = "/netlab:netlab-config/snmp/trap-group[name='" + group + "']"
        if len(tokens) == 2:
            return base + "/name", group
        if len(tokens) >= 4 and tokens[2] == "version":
            return base + "/version", tokens[3]
        if len(tokens) >= 4 and tokens[2] == "targets":
            target = tokens[3]
            return base + "/targets[address='" + target + "']/address", target
    return "/netlab:netlab-config/snmp/" + "/".join(tokens), ""


def _delete_path_snmp(tokens):
    if not tokens:
        return "/netlab:netlab-config/snmp"
    if tokens[0] in ("contact", "location"):
        return "/netlab:netlab-config/snmp/" + tokens[0]
    if len(tokens) >= 2 and tokens[0] == "community":
        base = "/netlab:netlab-config/snmp/community[name='" + tokens[1] + "']"
        if len(tokens) == 2:
            return base
        if len(tokens) >= 3 and tokens[2] == "authorization":
            return base + "/authorization"
        if len(tokens) >= 4 and tokens[2] == "clients":
            return base + "/clients[address='" + tokens[3] + "']"
    if len(tokens) >= 2 and tokens[0] == "trap-group":
        base = "/netlab:netlab-config/snmp/trap-group[name='" + tokens[1] + "']"
        if len(tokens) == 2:
            return base
        if len(tokens) >= 3 and tokens[2] == "version":
            return base + "/version"
        if len(tokens) >= 4 and tokens[2] == "targets":
            return base + "/targets[address='" + tokens[3] + "']"
    return None


def _path_chassis(tokens):
    if len(tokens) == 2 and tokens[0] in ("port-mode", "network-services"):
        return "/netlab:netlab-config/chassis/" + tokens[0], tokens[1]
    return "/netlab:netlab-config/chassis/" + "/".join(tokens), ""

def _delete_path_chassis(tokens):
    if len(tokens) == 1 and tokens[0] in ("port-mode", "network-services"):
        return "/netlab:netlab-config/chassis/" + tokens[0]
    if len(tokens) == 2 and tokens[0] in ("port-mode", "network-services"):
        return "/netlab:netlab-config/chassis/" + tokens[0]
    if not tokens:
        return "/netlab:netlab-config/chassis"
    return None

def _acl_alias_target(family):
    if family in ("ethernet", "ethernet-switching", "l2", "mac"):
        return "ingress-acl"
    if family in ("inet", "ipv4"):
        return "ingress-ipv4-acl"
    if family == "policer":
        return "acl-policer"
    if family in ("egress", "egress-mac"):
        return "egress-acl"
    return None

def _acl_alias_allowed_leaves(target):
    common = ("vlan", "interface", "action")
    mac_leaves = ("source-mac", "destination-mac")
    ipv4_leaves = ("source-ip", "source-prefix", "destination-ip",
                   "destination-prefix", "dscp", "ecn", "protocol",
                   "source-port", "source-port-range",
                   "destination-port", "destination-port-range",
                   "tcp-flags", "tcp-flags-mask")
    if target == "ingress-acl":
        return common + mac_leaves
    if target == "ingress-ipv4-acl":
        return common + ipv4_leaves
    if target == "acl-policer":
        return ("interface", "destination-mac", "bandwidth", "burst-size")
    if target == "egress-acl":
        return ("interface", "source-mac", "destination-mac", "action")
    return ()

def _acl_independent_allowed_leaves(family):
    common = ("vlan", "interface", "action")
    policer = ("bandwidth", "burst-size")
    mac_leaves = ("source-mac", "destination-mac")
    ipv4_leaves = ("source-ip", "source-prefix", "destination-ip",
                   "destination-prefix", "dscp", "ecn", "protocol",
                   "source-port", "source-port-range",
                   "destination-port", "destination-port-range",
                   "tcp-flags", "tcp-flags-mask")
    if family in ("ethernet", "ethernet-switching", "l2", "mac"):
        return common + mac_leaves + policer
    if family in ("inet", "ipv4"):
        return common + ipv4_leaves + policer
    if family == "policer":
        return ("vlan", "interface") + mac_leaves + ipv4_leaves + policer
    return ()

def _acl_alias_value(leaf, value):
    if leaf in ("source-mac", "destination-mac"):
        return value.lower()
    return value

def _acl_group_term_name(group, term):
    return f"{group}.{term}"

def _firewall_term_name(filter_name, term):
    return _acl_group_term_name(filter_name, term)

def _firewall_acl_target(family):
    if family == "ethernet-switching":
        return "ingress-acl"
    if family == "inet":
        return "ingress-ipv4-acl"
    return None

def _firewall_from_leaf(family, leaf, value=""):
    if leaf in ("vlan", "interface"):
        return leaf
    if family == "ethernet-switching":
        if leaf in ("source-mac", "destination-mac"):
            return leaf
        return None
    if family == "inet":
        if leaf == "source-address":
            return "source-prefix" if "/" in value else "source-ip"
        if leaf == "destination-address":
            return "destination-prefix" if "/" in value else "destination-ip"
        if leaf in ("dscp", "ecn", "protocol", "source-port",
                    "source-port-range", "destination-port",
                    "destination-port-range", "tcp-flags",
                    "tcp-flags-mask"):
            return leaf
    return None

def _firewall_action_value(action):
    if action == "discard":
        return "drop"
    if action in ("accept", "count"):
        return "count"
    return None

def _acl_independent_base(group, term, family):
    return ("/netlab:netlab-config/ethernet-switching-options"
            "/acl-independent/group[name='" + group + "']"
            "/term[name='" + term + "'][family='" + family + "']")

def _delete_path_interfaces(tokens):
    if not tokens:
        return None
    ifn = tokens[0]; rest = tokens[1:]
    p = "/netlab:netlab-config/interfaces/interface[name='" + ifn + "']"
    if not rest:
        return p
    if rest[0] == "description":
        return p + "/description"
    if rest[0] == "disable":
        return p + "/disable"
    if rest[0] in ("mtu", "speed"):
        return p + "/" + rest[0]
    if rest[0] == "native-vlan-id":
        return p + "/native-vlan-id"
    if (rest[0] == "ether-options" and len(rest) >= 2 and
            rest[1] == "802.3ad"):
        return p + "/ether-options/ieee8023ad"
    if (rest[0] == "ether-options" and len(rest) >= 3 and
            rest[1] == "lacp" and rest[2] == "port-priority"):
        return p + "/ether-options/lacp/port-priority"
    if (rest[0] == "aggregated-ether-options" and len(rest) >= 2 and
            rest[1] == "minimum-links"):
        return p + "/aggregated-ether-options/minimum-links"
    if (rest[0] == "aggregated-ether-options" and len(rest) >= 3 and
            rest[1] == "hash-policy" and rest[2] == "rotation"):
        return p + "/aggregated-ether-options/hash-policy/rotation"
    if (rest[0] == "aggregated-ether-options" and len(rest) >= 2 and
            rest[1] == "lacp"):
        if len(rest) >= 3 and rest[2] == "periodic":
            return p + "/aggregated-ether-options/lacp/periodic"
        if len(rest) >= 3 and rest[2] == "actor-key":
            return p + "/aggregated-ether-options/lacp/actor-key"
        return p + "/aggregated-ether-options/lacp/mode"
    if rest[0] == "unit" and len(rest) >= 2:
        routed = _delete_path_physical_rif(ifn, rest)
        if routed:
            return routed
        base = p + "/unit/logical-unit[unit-id='" + rest[1] + "']"
        r2 = rest[2:]
        if r2[:2] == ["family", "ethernet-switching"]:
            base += "/family/ethernet-switching"
            r3 = r2[2:]
            if len(r3) >= 2 and r3[0] == "vlan" and r3[1] == "members":
                if len(r3) >= 3:
                    return base + "/vlan-members[.='" + r3[2] + "']"
                return base + "/vlan-members"
            if r3 and r3[0] == "vlan-members":
                if len(r3) >= 2:
                    return base + "/vlan-members[.='" + r3[1] + "']"
                return base + "/vlan-members"
            if r3 and r3[0] == "interface-mode":
                return base + "/interface-mode"
            if not r3:
                return base
    return None

def _path_vlans(tokens):
    if not tokens:
        return None, ""
    vn = tokens[0]; rest = tokens[1:]
    p = "/netlab:netlab-config/vlans/vlan[name='" + vn + "']"
    if not rest:
        return p + "/name", vn
    if rest[0] == "vlan-id" and len(rest) >= 2:
        return p + "/vlan-id", rest[1]
    if rest[0] == "description" and len(rest) >= 2:
        return p + "/description", " ".join(rest[1:])
    return p + "/" + "/".join(rest), ""

def _path_interfaces(tokens):
    if not tokens:
        return None, ""
    ifn = tokens[0]; rest = tokens[1:]
    p = "/netlab:netlab-config/interfaces/interface[name='" + ifn + "']"
    if not rest: return p, ""
    if rest[0] == "description" and len(rest) >= 2:
        return p + "/description", " ".join(rest[1:])
    if rest[0] == "disable": return p + "/disable", "true"
    if rest[0] in ("mtu", "speed") and len(rest) >= 2:
        return p + "/" + rest[0], rest[1]
    if rest[0] == "native-vlan-id" and len(rest) >= 2:
        return p + "/native-vlan-id", rest[1]
    if rest[0] == "ether-options" and len(rest) >= 2 and rest[1] == "802.3ad":
        return p + "/ether-options/ieee8023ad", rest[2] if len(rest) >= 3 else ""
    if (rest[0] == "ether-options" and len(rest) >= 4 and
            rest[1] == "lacp" and rest[2] == "port-priority"):
        return p + "/ether-options/lacp/port-priority", rest[3]
    if (rest[0] == "aggregated-ether-options" and len(rest) >= 2 and
            rest[1] == "minimum-links"):
        return p + "/aggregated-ether-options/minimum-links", rest[2] if len(rest) >= 3 else ""
    if (rest[0] == "aggregated-ether-options" and len(rest) >= 3 and
            rest[1] == "hash-policy" and rest[2] == "rotation"):
        return (p + "/aggregated-ether-options/hash-policy/rotation",
                rest[3] if len(rest) >= 4 else "")
    if (rest[0] == "aggregated-ether-options" and len(rest) >= 2 and
            rest[1] == "lacp"):
        if len(rest) >= 4 and rest[2] == "periodic":
            return (p + "/aggregated-ether-options/lacp/periodic",
                    rest[3])
        if len(rest) >= 4 and rest[2] == "actor-key":
            return (p + "/aggregated-ether-options/lacp/actor-key",
                    rest[3])
        return p + "/aggregated-ether-options/lacp/mode", rest[2] if len(rest) >= 3 else ""
    if rest[0] == "unit" and len(rest) >= 2:
        routed = _path_physical_rif(ifn, rest)
        if routed:
            return routed
        base = p + "/unit/logical-unit[unit-id='" + rest[1] + "']"
        r2 = rest[2:]
        if not r2: return base, ""
        if r2[0] == "family" and len(r2) >= 2 and r2[1] == "ethernet-switching":
            base += "/family/ethernet-switching"
            r3 = r2[2:]
            if not r3: return base, ""
            if r3[0] == "interface-mode" and len(r3) >= 2:
                return base + "/interface-mode", r3[1]
            if (r3[0] == "vlan" and len(r3) >= 3 and r3[1] == "members"):
                return base + "/vlan-members", r3[2]
            if (r3[0] == "vlan-members" and len(r3) >= 2):
                return base + "/vlan-members", r3[1]
    return p + "/" + "/".join(rest), ""


def _path_interfaces_irb(tokens):
    if len(tokens) >= 3 and tokens[0] == "irb" and tokens[1] == "unit":
        unit = tokens[2]
        rif = _irb_unit_to_rif(unit)
        base = ("/netlab:netlab-config/interfaces-routing"
                "/interface[name='" + rif + "']")
        rest = tokens[3:]
        if not rest:
            return base + "/name", rif
        if (len(rest) >= 4 and rest[0] == "family" and
                rest[1] == "inet" and rest[2] == "address"):
            if len(rest) >= 6 and rest[4] == "arp":
                ip = rest[5]
                p = ("/netlab:netlab-config/routing-options/static"
                     "/arp[ip='" + ip + "']")
                if len(rest) == 6:
                    return p + "/ip", ip
                if len(rest) >= 8 and rest[6] == "mac":
                    return p + "/mac", rest[7]
                if len(rest) >= 8 and rest[6] == "egress-interface":
                    return p + "/egress-interface", rest[7]
                if len(rest) >= 8 and rest[6] == "interface":
                    return p + "/interface", rest[7]
                return p + "/" + "/".join(rest[6:]), ""
            return base + "/address", rest[3]
        if len(rest) >= 2 and rest[0] == "family" and rest[1] == "inet":
            return base + "/name", rif
        return base + "/" + "/".join(rest), ""
    return None, ""


def _delete_path_interfaces_irb(tokens):
    if len(tokens) >= 3 and tokens[0] == "irb" and tokens[1] == "unit":
        unit = tokens[2]
        rif = _irb_unit_to_rif(unit)
        base = ("/netlab:netlab-config/interfaces-routing"
                "/interface[name='" + rif + "']")
        rest = tokens[3:]
        if not rest:
            return base
        if (len(rest) >= 3 and rest[0] == "family" and
                rest[1] == "inet" and rest[2] == "address"):
            if len(rest) >= 6 and rest[4] == "arp":
                p = ("/netlab:netlab-config/routing-options/static"
                     "/arp[ip='" + rest[5] + "']")
                if len(rest) == 6:
                    return p
                if rest[6] in ("mac", "egress-interface", "interface"):
                    return p + "/" + rest[6]
                return p + "/" + "/".join(rest[6:])
            return base + "/address"
        if len(rest) >= 2 and rest[0] == "family" and rest[1] == "inet":
            return base + "/address"
        return base + "/" + "/".join(rest)
    return None


def _path_interfaces_routing(tokens):
    if not tokens:
        return None, ""
    if len(tokens) >= 2 and tokens[0] == "interface":
        rif = tokens[1]
        rest = tokens[2:]
        p = "/netlab:netlab-config/interfaces-routing/interface[name='" + rif + "']"
        if not rest:
            return p + "/name", rif
        if rest[0] == "vlan" and len(rest) >= 2:
            return p + "/vlan", rest[1]
        if rest[0] == "address" and len(rest) >= 2:
            return p + "/address", rest[1]
        return p + "/" + "/".join(rest), ""
    return "/netlab:netlab-config/interfaces-routing/" + "/".join(tokens), ""


def _delete_path_interfaces_routing(tokens):
    if not tokens:
        return None
    if len(tokens) >= 2 and tokens[0] == "interface":
        rif = tokens[1]
        base = "/netlab:netlab-config/interfaces-routing/interface[name='" + rif + "']"
        if len(tokens) == 2:
            return base
        if tokens[2] in ("vlan", "address"):
            return base + "/" + tokens[2]
        return base + "/" + "/".join(tokens[2:])
    return None


def _path_routing_options(tokens):
    if len(tokens) >= 2 and tokens[0] == "autonomous-system":
        return "/netlab:netlab-config/routing-options/autonomous-system", tokens[1]
    if len(tokens) >= 2 and tokens[0] == "static":
        rest = tokens[1:]
        base = "/netlab:netlab-config/routing-options/static"
        if len(rest) >= 2 and rest[0] == "arp":
            ip = rest[1]
            p = base + "/arp[ip='" + ip + "']"
            if len(rest) == 2:
                return p + "/ip", ip
            if len(rest) >= 4 and rest[2] == "mac":
                return p + "/mac", rest[3]
            if len(rest) >= 4 and rest[2] == "interface":
                return p + "/interface", rest[3]
            if len(rest) >= 4 and rest[2] == "egress-interface":
                return p + "/egress-interface", rest[3]
            return p + "/" + "/".join(rest[2:]), ""
        if len(rest) >= 2 and rest[0] == "next-hop":
            nhid = rest[1]
            p = base + "/next-hop[id='" + nhid + "']"
            if len(rest) == 2:
                return p + "/id", nhid
            if len(rest) >= 4 and rest[2] == "arp":
                return p + "/arp-ip", rest[3]
            if len(rest) >= 4 and rest[2] == "interface":
                return p + "/interface", rest[3]
            return p + "/" + "/".join(rest[2:]), ""
        if len(rest) >= 2 and rest[0] == "ecmp":
            ecmp_id = rest[1]
            p = base + "/ecmp[id='" + ecmp_id + "']"
            if len(rest) == 2:
                return p + "/id", ecmp_id
            if len(rest) >= 4 and rest[2] == "member":
                return p + "/member", rest[3]
            return p + "/" + "/".join(rest[2:]), ""
        if len(rest) >= 2 and rest[0] == "route":
            prefix = rest[1]
            p = base + "/route[prefix='" + prefix + "']"
            if len(rest) == 2:
                return p + "/prefix", prefix
            if len(rest) >= 4 and rest[2] == "next-hop":
                if _is_ipv4_address(rest[3]):
                    return p + "/next-hop-address", rest[3]
                return p + "/next-hop-id", rest[3]
            if len(rest) >= 4 and rest[2] == "ecmp":
                return p + "/ecmp-id", rest[3]
            return p + "/" + "/".join(rest[2:]), ""
        return base + "/" + "/".join(rest), ""
    return "/netlab:netlab-config/routing-options/" + "/".join(tokens), ""


def _path_routing_instances(tokens):
    if not tokens:
        return None, ""
    name = tokens[0]
    base = ("/netlab:netlab-config/routing-instances"
            "/instance[name='" + name + "']")
    rest = tokens[1:]
    if not rest:
        return base + "/name", name
    if len(rest) >= 2 and rest[0] == "instance-type":
        return base + "/instance-type", rest[1]
    if len(rest) >= 2 and rest[0] == "interface":
        return base + "/interface", rest[1]
    if rest[0] == "routing-options":
        path, value = _path_routing_options(rest[1:])
        if not path:
            return None, ""
        global_root = "/netlab:netlab-config/routing-options"
        return base + "/routing-options" + path[len(global_root):], value
    return base + "/" + "/".join(rest), ""


def _delete_path_routing_options(tokens):
    if not tokens:
        return "/netlab:netlab-config/routing-options"
    if tokens[0] == "autonomous-system":
        return "/netlab:netlab-config/routing-options/autonomous-system"
    if tokens[0] == "static":
        base = "/netlab:netlab-config/routing-options/static"
        rest = tokens[1:]
        if not rest:
            return base
        if len(rest) >= 2 and rest[0] == "arp":
            p = base + "/arp[ip='" + rest[1] + "']"
            if len(rest) == 2:
                return p
            if rest[2] in ("mac", "interface", "egress-interface"):
                return p + "/" + rest[2]
            return p + "/" + "/".join(rest[2:])
        if len(rest) >= 2 and rest[0] == "next-hop":
            p = base + "/next-hop[id='" + rest[1] + "']"
            if len(rest) == 2:
                return p
            if rest[2] == "arp":
                return p + "/arp-ip"
            if rest[2] == "interface":
                return p + "/" + rest[2]
            return p + "/" + "/".join(rest[2:])
        if len(rest) >= 2 and rest[0] == "ecmp":
            p = base + "/ecmp[id='" + rest[1] + "']"
            if len(rest) == 2:
                return p
            if len(rest) >= 4 and rest[2] == "member":
                return p + "/member[.='" + rest[3] + "']"
            if rest[2] == "member":
                return p + "/member"
            return p + "/" + "/".join(rest[2:])
        if len(rest) >= 2 and rest[0] == "route":
            p = base + "/route[prefix='" + rest[1] + "']"
            if len(rest) == 2:
                return p
            if rest[2] == "next-hop":
                if len(rest) == 3:
                    return p + "/next-hop-address"
                if len(rest) >= 4 and _is_ipv4_address(rest[3]):
                    return p + "/next-hop-address[.='" + rest[3] + "']"
                return p + "/next-hop-id"
            if rest[2] == "ecmp":
                return p + "/ecmp-id"
            return p + "/" + "/".join(rest[2:])
    return None


def _delete_path_routing_instances(tokens):
    if not tokens:
        return "/netlab:netlab-config/routing-instances"
    name = tokens[0]
    base = ("/netlab:netlab-config/routing-instances"
            "/instance[name='" + name + "']")
    rest = tokens[1:]
    if not rest:
        return base
    if rest[0] in ("instance-type", "interface"):
        if rest[0] == "interface" and len(rest) >= 2:
            return base + "/interface[.='" + rest[1] + "']"
        return base + "/" + rest[0]
    if rest[0] == "routing-options":
        path = _delete_path_routing_options(rest[1:])
        if not path:
            return None
        global_root = "/netlab:netlab-config/routing-options"
        return base + "/routing-options" + path[len(global_root):]
    return base + "/" + "/".join(rest)

def _path_policy_options(tokens):
    if len(tokens) >= 2 and tokens[0] == "policy-statement":
        policy = tokens[1]
        base = ("/netlab:netlab-config/policy-options"
                "/policy-statement[name='" + policy + "']")
        if len(tokens) == 2:
            return base + "/name", policy
        if len(tokens) >= 4 and tokens[2] == "term":
            term = tokens[3]
            term_base = base + "/term[name='" + term + "']"
            if len(tokens) == 4:
                return term_base + "/name", term
            if (len(tokens) >= 8 and tokens[4] == "from" and
                    tokens[5] == "route-filter"):
                prefix = tokens[6]
                rf_base = term_base + "/from/route-filter[prefix='" + prefix + "']"
                if len(tokens) == 8 and tokens[7] == "exact":
                    return rf_base + "/match-type", "exact"
                return rf_base + "/" + "/".join(tokens[7:]), ""
            if (len(tokens) >= 6 and tokens[4] == "then" and
                    tokens[5] in ("accept", "reject")):
                return term_base + "/then/action", tokens[5]
            return term_base + "/" + "/".join(tokens[4:]), ""
        return base + "/" + "/".join(tokens[2:]), ""
    return "/netlab:netlab-config/policy-options/" + "/".join(tokens), ""


def _delete_path_policy_options(tokens):
    if len(tokens) >= 2 and tokens[0] == "policy-statement":
        base = ("/netlab:netlab-config/policy-options"
                "/policy-statement[name='" + tokens[1] + "']")
        if len(tokens) == 2:
            return base
        if len(tokens) >= 4 and tokens[2] == "term":
            term_base = base + "/term[name='" + tokens[3] + "']"
            if len(tokens) == 4:
                return term_base
            if len(tokens) >= 7 and tokens[4] == "from" and tokens[5] == "route-filter":
                return term_base + "/from/route-filter[prefix='" + tokens[6] + "']"
            if len(tokens) >= 5 and tokens[4] == "then":
                return term_base + "/then"
    return None


def _firewall_term_base(family, filter_name, term):
    target = _firewall_acl_target(family)
    if not target:
        return None
    term_name = _firewall_term_name(filter_name, term)
    return ("/netlab:netlab-config/ethernet-switching-options/"
            + target + "/term[name='" + term_name + "']")


def _firewall_compiler_base(family, filter_name, term, mode):
    if family != "ethernet-switching":
        return None
    target = _acl_alias_target(mode)
    if target not in ("acl-policer", "egress-acl"):
        return None
    term_name = _firewall_term_name(filter_name, term)
    return ("/netlab:netlab-config/ethernet-switching-options/"
            + target + "/term[name='" + term_name + "']")


def _path_firewall(tokens):
    if (len(tokens) < 7 or tokens[0] != "family" or
            tokens[2] != "filter" or tokens[4] != "term"):
        return None, ""
    family = tokens[1]
    filter_name = tokens[3]
    term = tokens[5]
    rest = tokens[6:]
    if rest and rest[0] in ("policer", "egress"):
        base = _firewall_compiler_base(family, filter_name, term, rest[0])
        if not base:
            return None, ""
        mode = rest[0]
        mode_rest = rest[1:]
        if not mode_rest:
            return base + "/name", _firewall_term_name(filter_name, term)
        if mode == "policer":
            if len(mode_rest) == 3 and mode_rest[0] == "from":
                leaf = mode_rest[1]
                if leaf in ("interface", "destination-mac"):
                    return base + "/" + leaf, _acl_alias_value(leaf, mode_rest[2])
            if len(mode_rest) == 3 and mode_rest[0] == "then":
                leaf = mode_rest[1]
                if leaf in ("bandwidth", "burst-size"):
                    return base + "/" + leaf, mode_rest[2]
        if mode == "egress":
            if len(mode_rest) == 3 and mode_rest[0] == "from":
                leaf = mode_rest[1]
                if leaf in ("interface", "source-mac", "destination-mac"):
                    return base + "/" + leaf, _acl_alias_value(leaf, mode_rest[2])
            if len(mode_rest) == 2 and mode_rest[0] == "then":
                action = _firewall_action_value(mode_rest[1])
                if action:
                    return base + "/action", action
        return None, ""

    base = _firewall_term_base(family, filter_name, term)
    if not base:
        return None, ""
    if not rest:
        return base + "/name", _firewall_term_name(filter_name, term)
    if len(rest) == 3 and rest[0] == "from":
        leaf = _firewall_from_leaf(family, rest[1], rest[2])
        if leaf:
            return base + "/" + leaf, _acl_alias_value(leaf, rest[2])
    if len(rest) == 2 and rest[0] == "then":
        action = _firewall_action_value(rest[1])
        if action:
            return base + "/action", action
    return None, ""


def _delete_path_firewall(tokens):
    if (len(tokens) < 6 or tokens[0] != "family" or
            tokens[2] != "filter" or tokens[4] != "term"):
        return None
    family = tokens[1]
    filter_name = tokens[3]
    term = tokens[5]
    rest = tokens[6:]
    if rest and rest[0] in ("policer", "egress"):
        base = _firewall_compiler_base(family, filter_name, term, rest[0])
        if not base:
            return None
        mode = rest[0]
        mode_rest = rest[1:]
        if not mode_rest:
            return base
        if mode == "policer":
            if len(mode_rest) >= 2 and mode_rest[0] == "from":
                leaf = mode_rest[1]
                if leaf in ("interface", "destination-mac"):
                    return base + "/" + leaf
            if len(mode_rest) >= 2 and mode_rest[0] == "then":
                leaf = mode_rest[1]
                if leaf in ("bandwidth", "burst-size"):
                    return base + "/" + leaf
        if mode == "egress":
            if len(mode_rest) >= 2 and mode_rest[0] == "from":
                leaf = mode_rest[1]
                if leaf in ("interface", "source-mac", "destination-mac"):
                    return base + "/" + leaf
            if mode_rest and mode_rest[0] == "then":
                return base + "/action"
        return None

    base = _firewall_term_base(family, filter_name, term)
    if not base:
        return None
    if not rest:
        return base
    if len(rest) >= 2 and rest[0] == "from":
        value = rest[2] if len(rest) >= 3 else ""
        leaf = _firewall_from_leaf(family, rest[1], value)
        if leaf:
            return base + "/" + leaf
    if rest and rest[0] == "then":
        return base + "/action"
    return None


def _path_protocols(tokens):
    if tokens and tokens[0] == "igmp-snooping":
        base = "/netlab:netlab-config/protocols/igmp-snooping"
        if len(tokens) == 1:
            return base, ""
        if len(tokens) == 3 and tokens[1] == "membership-timeout":
            return base + "/membership-timeout", tokens[2]
        if len(tokens) >= 3 and tokens[1] == "vlan":
            vlan = tokens[2]
            vlan_base = base + "/vlan[name='" + vlan + "']"
            if len(tokens) == 3:
                return vlan_base + "/name", vlan
            if len(tokens) >= 5 and tokens[3] == "interface":
                ifname = tokens[4]
                iface_base = vlan_base + "/interface[name='" + ifname + "']"
                if len(tokens) == 5:
                    return iface_base + "/name", ifname
                if (len(tokens) == 7 and tokens[5] == "static-group"):
                    group = tokens[6]
                    return (iface_base + "/static-group[.='" + group + "']",
                            group)
        return None
    if len(tokens) >= 3 and tokens[0] == "ospf" and tokens[1] == "area":
        area = tokens[2]
        base = "/netlab:netlab-config/protocols/ospf/area[name='" + area + "']"
        if len(tokens) == 3:
            return base + "/name", area
        if len(tokens) >= 5 and tokens[3] == "interface":
            ifn = tokens[4]
            iface = base + "/interface[name='" + ifn + "']"
            return iface + "/name", ifn
        return base + "/" + "/".join(tokens[3:]), ""
    if len(tokens) >= 3 and tokens[0] == "bgp" and tokens[1] == "group":
        group = tokens[2]
        base = "/netlab:netlab-config/protocols/bgp/group[name='" + group + "']"
        if len(tokens) == 3:
            return base + "/name", group
        if len(tokens) >= 5 and tokens[3] in (
                "type", "export", "hold-time"):
            return base + "/" + tokens[3], tokens[4]
        if len(tokens) >= 5 and tokens[3] == "neighbor":
            nbr = tokens[4]
            nbr_base = base + "/neighbor[address='" + nbr + "']"
            if len(tokens) == 5:
                return nbr_base + "/address", nbr
            if len(tokens) >= 7 and tokens[5] == "peer-as":
                return nbr_base + "/peer-as", tokens[6]
            return nbr_base + "/" + "/".join(tokens[5:]), ""
        return base + "/" + "/".join(tokens[3:]), ""
    if len(tokens) >= 3 and tokens[0] == "lacp":
        base = "/netlab:netlab-config/protocols/lacp"
        leaf = tokens[1]
        if leaf in ("system-id", "system-priority", "port-priority"):
            return base + "/" + leaf, tokens[2]
        return base + "/" + "/".join(tokens[1:]), ""
    if len(tokens) >= 3 and tokens[0] == "rstp":
        base = "/netlab:netlab-config/protocols/rstp"
        leaf = tokens[1]
        if leaf in ("bridge-priority", "hello-time", "max-age",
                    "forward-delay"):
            return base + "/" + leaf, tokens[2]
    if len(tokens) >= 3 and tokens[0] == "mstp":
        base = "/netlab:netlab-config/protocols/mstp"
        leaf = tokens[1]
        if leaf in ("configuration-name", "revision-level",
                    "bridge-priority", "hello-time", "max-age",
                    "forward-delay", "max-hops"):
            return base + "/" + leaf, tokens[2]
        if leaf == "instance" and len(tokens) >= 3:
            inst = tokens[2]
            inst_base = base + "/instance[id='" + inst + "']"
            if len(tokens) == 3:
                return inst_base + "/id", inst
            if len(tokens) >= 5 and tokens[3] == "interface":
                ifn = tokens[4]
                iface_base = inst_base + "/interface[name='" + ifn + "']"
                if len(tokens) == 5:
                    return iface_base + "/name", ifn
                if (len(tokens) >= 7 and
                        tokens[5] in ("path-cost", "port-priority")):
                    return iface_base + "/" + tokens[5], tokens[6]
                return iface_base + "/" + "/".join(tokens[5:]), ""
            if len(tokens) >= 5 and tokens[3] == "bridge-priority":
                return inst_base + "/bridge-priority", tokens[4]
            if len(tokens) >= 5 and tokens[3] == "vlan":
                vlan = tokens[4]
                return inst_base + "/vlan[vlan-id='" + vlan + "']/vlan-id", vlan
    if len(tokens) >= 2 and tokens[0] == "lldp" and tokens[1] != "interface":
        base = "/netlab:netlab-config/protocols/lldp"
        leaf = tokens[1]
        if leaf == "disable" and len(tokens) == 2:
            return base + "/disable", "true"
        if leaf in ("transmit-interval", "hold-multiplier",
                    "system-name", "system-description",
                    "management-address") and len(tokens) >= 3:
            return base + "/" + leaf, " ".join(tokens[2:])
        return base + "/" + "/".join(tokens[1:]), ""
    if len(tokens) == 3 and tokens[0] == "lldp" and tokens[1] == "interface":
        ifn = tokens[2]
        return ("/netlab:netlab-config/protocols/lldp"
                "/interface[name='" + ifn + "']/name"), ifn
    if len(tokens) >= 4 and tokens[0] == "lldp" and tokens[1] == "interface":
        ifn = tokens[2]
        leaf = tokens[3]
        base = ("/netlab:netlab-config/protocols/lldp"
                "/interface[name='" + ifn + "']")
        if leaf == "disable":
            return base + "/disable", "true"
        return base + "/" + "/".join(tokens[3:]), ""
    if len(tokens) == 3 and tokens[0] == "rstp" and tokens[1] == "interface":
        ifn = tokens[2]
        return ("/netlab:netlab-config/protocols/rstp"
                "/interface[name='" + ifn + "']/name"), ifn
    if len(tokens) >= 4 and tokens[0] == "rstp" and tokens[1] == "interface":
        ifn = tokens[2]
        leaf = tokens[3]
        base = ("/netlab:netlab-config/protocols/rstp"
                "/interface[name='" + ifn + "']")
        if leaf in ("edge", "bpdu-block-on-edge",
                    "root-protection", "loop-protection"):
            return base + "/" + leaf, "true"
        if leaf in ("path-cost", "port-priority") and len(tokens) >= 5:
            return base + "/" + leaf, tokens[4]
        return base + "/" + "/".join(tokens[3:]), ""
    if len(tokens) == 3 and tokens[0] == "mstp" and tokens[1] == "interface":
        ifn = tokens[2]
        return ("/netlab:netlab-config/protocols/mstp"
                "/interface[name='" + ifn + "']/name"), ifn
    if len(tokens) >= 4 and tokens[0] == "mstp" and tokens[1] == "interface":
        ifn = tokens[2]
        leaf = tokens[3]
        base = ("/netlab:netlab-config/protocols/mstp"
                "/interface[name='" + ifn + "']")
        if leaf in ("edge", "bpdu-block-on-edge",
                    "root-protection", "loop-protection"):
            return base + "/" + leaf, "true"
        if leaf in ("path-cost", "port-priority") and len(tokens) >= 5:
            return base + "/" + leaf, tokens[4]
        return base + "/" + "/".join(tokens[3:]), ""
    return "/netlab:netlab-config/protocols/" + "/".join(tokens), ""

def _delete_path_protocols(tokens):
    if tokens and tokens[0] == "igmp-snooping":
        base = "/netlab:netlab-config/protocols/igmp-snooping"
        if len(tokens) == 1:
            return base
        if len(tokens) == 2 and tokens[1] == "membership-timeout":
            return base + "/membership-timeout"
        if len(tokens) >= 3 and tokens[1] == "vlan":
            vlan_base = base + "/vlan[name='" + tokens[2] + "']"
            if len(tokens) == 3:
                return vlan_base
            if len(tokens) >= 5 and tokens[3] == "interface":
                iface_base = (vlan_base + "/interface[name='" +
                              tokens[4] + "']")
                if len(tokens) == 5:
                    return iface_base
                if len(tokens) == 7 and tokens[5] == "static-group":
                    return iface_base + "/static-group[.='" + tokens[6] + "']"
        return None
    if len(tokens) >= 1 and tokens[0] == "ospf":
        base = "/netlab:netlab-config/protocols/ospf"
        if len(tokens) == 1:
            return base
        if len(tokens) >= 3 and tokens[1] == "area":
            area_base = base + "/area[name='" + tokens[2] + "']"
            if len(tokens) == 3:
                return area_base
            if len(tokens) >= 5 and tokens[3] == "interface":
                return area_base + "/interface[name='" + tokens[4] + "']"
    if len(tokens) >= 1 and tokens[0] == "bgp":
        base = "/netlab:netlab-config/protocols/bgp"
        if len(tokens) == 1:
            return base
        if len(tokens) >= 3 and tokens[1] == "group":
            group_base = base + "/group[name='" + tokens[2] + "']"
            if len(tokens) == 3:
                return group_base
            if len(tokens) >= 4 and tokens[3] in (
                    "type", "export", "hold-time"):
                return group_base + "/" + tokens[3]
            if len(tokens) >= 5 and tokens[3] == "neighbor":
                nbr_base = group_base + "/neighbor[address='" + tokens[4] + "']"
                if len(tokens) == 5:
                    return nbr_base
                if len(tokens) >= 6 and tokens[5] == "peer-as":
                    return nbr_base + "/peer-as"
    if len(tokens) == 1 and tokens[0] == "lacp":
        return "/netlab:netlab-config/protocols/lacp"
    if len(tokens) >= 2 and tokens[0] == "lacp":
        base = "/netlab:netlab-config/protocols/lacp"
        if tokens[1] in ("system-id", "system-priority", "port-priority"):
            return base + "/" + tokens[1]
    if len(tokens) >= 2 and tokens[0] == "rstp" and tokens[1] != "interface":
        base = "/netlab:netlab-config/protocols/rstp"
        if tokens[1] in ("bridge-priority", "hello-time", "max-age",
                         "forward-delay"):
            return base + "/" + tokens[1]
    if len(tokens) >= 2 and tokens[0] == "mstp" and tokens[1] != "interface":
        base = "/netlab:netlab-config/protocols/mstp"
        if tokens[1] in ("configuration-name", "revision-level",
                         "bridge-priority", "hello-time", "max-age",
                         "forward-delay", "max-hops"):
            return base + "/" + tokens[1]
        if tokens[1] == "instance" and len(tokens) >= 3:
            inst_base = base + "/instance[id='" + tokens[2] + "']"
            if len(tokens) == 3:
                return inst_base
            if len(tokens) >= 5 and tokens[3] == "interface":
                iface_base = (inst_base + "/interface[name='" +
                              tokens[4] + "']")
                if len(tokens) == 5:
                    return iface_base
                if (len(tokens) >= 6 and
                        tokens[5] in ("path-cost", "port-priority")):
                    return iface_base + "/" + tokens[5]
            if len(tokens) >= 4 and tokens[3] == "bridge-priority":
                return inst_base + "/bridge-priority"
            if len(tokens) >= 5 and tokens[3] == "vlan":
                return inst_base + "/vlan[vlan-id='" + tokens[4] + "']"
    if len(tokens) == 1 and tokens[0] == "lldp":
        return "/netlab:netlab-config/protocols/lldp"
    if len(tokens) >= 2 and tokens[0] == "lldp" and tokens[1] != "interface":
        base = "/netlab:netlab-config/protocols/lldp"
        if tokens[1] in ("disable", "transmit-interval",
                         "hold-multiplier", "system-name",
                         "system-description", "management-address"):
            return base + "/" + tokens[1]
    if len(tokens) >= 3 and tokens[0] == "lldp" and tokens[1] == "interface":
        ifn = tokens[2]
        base = ("/netlab:netlab-config/protocols/lldp"
                "/interface[name='" + ifn + "']")
        if len(tokens) == 3:
            return base
        if tokens[3] == "disable":
            return base + "/disable"
    if len(tokens) >= 3 and tokens[0] == "rstp" and tokens[1] == "interface":
        ifn = tokens[2]
        base = ("/netlab:netlab-config/protocols/rstp"
                "/interface[name='" + ifn + "']")
        if len(tokens) == 3:
            return base
        if tokens[3] in ("edge", "bpdu-block-on-edge",
                         "root-protection", "loop-protection",
                         "path-cost", "port-priority"):
            return base + "/" + tokens[3]
    if len(tokens) >= 3 and tokens[0] == "mstp" and tokens[1] == "interface":
        ifn = tokens[2]
        base = ("/netlab:netlab-config/protocols/mstp"
                "/interface[name='" + ifn + "']")
        if len(tokens) == 3:
            return base
        if tokens[3] in ("edge", "bpdu-block-on-edge",
                         "root-protection", "loop-protection",
                         "path-cost", "port-priority"):
            return base + "/" + tokens[3]
    return None

def _path_control_plane(tokens):
    base = "/netlab:netlab-config/control-plane"
    if len(tokens) >= 5 and tokens[0] == "protection" and tokens[1] == "class":
        cls = tokens[2]
        if tokens[3] in ("rate-pps", "burst-pkts"):
            return (base + "/protection/class"
                    "[name='" + cls + "']/" + tokens[3]), tokens[4]
    return base + "/" + "/".join(tokens), ""

def _delete_path_control_plane(tokens):
    base = "/netlab:netlab-config/control-plane"
    if not tokens:
        return base
    if tokens[0] == "protection":
        if len(tokens) == 1:
            return base + "/protection"
        if len(tokens) >= 3 and tokens[1] == "class":
            path = base + "/protection/class[name='" + tokens[2] + "']"
            if len(tokens) == 3:
                return path
            if len(tokens) == 4 and tokens[3] in ("rate-pps", "burst-pkts"):
                return path + "/" + tokens[3]
    return None

def _path_class_of_service(tokens):
    base = "/netlab:netlab-config/class-of-service"
    if len(tokens) >= 2 and tokens[0] == "schedulers":
        name = tokens[1]
        if len(tokens) == 2:
            return (base + "/scheduler/template"
                    "[name='" + name + "']/name"), name
        if len(tokens) == 4 and tokens[2] in ("transmit-rate",
                                               "buffer-size"):
            leaf = "rate-bps" if tokens[2] == "transmit-rate" else "burst-bits"
            return (base + "/scheduler/template"
                    "[name='" + name + "']/group[id='0']/" + leaf), tokens[3]
        if len(tokens) == 4 and tokens[2] == "priority":
            if tokens[3] == "strict-high":
                return (base + "/scheduler/template"
                        "[name='" + name + "']/group[id='0']"
                        "/strict-priority"), "true"
            if tokens[3] == "low":
                return (base + "/scheduler/template"
                        "[name='" + name + "']/group[id='0']"
                        "/strict-priority"), "false"
        return None, ""
    if len(tokens) >= 2 and tokens[0] == "ets":
        if len(tokens) >= 3 and tokens[1] == "policy":
            return _path_class_of_service(
                ["scheduler", "template", tokens[2]] + tokens[3:])
        if len(tokens) >= 3 and tokens[1] == "interfaces":
            if len(tokens) == 5 and tokens[3] == "policy":
                return _path_class_of_service(
                    ["scheduler", "interfaces", tokens[2],
                     "template", tokens[4]])
            return _path_class_of_service(
                ["scheduler", "interfaces", tokens[2]] + tokens[3:])
    if (len(tokens) >= 4 and tokens[0] == "interfaces" and
            tokens[2] in ("trust", "default-priority")):
        ifname = tokens[1]
        return (base + "/interfaces/interface"
                "[name='" + ifname + "']/" + tokens[2]), tokens[3]
    if (len(tokens) == 4 and tokens[0] == "interfaces" and
            tokens[2] == "scheduler-map"):
        return (base + "/scheduler/interfaces/interface"
                "[name='" + tokens[1] + "']/template"), tokens[3]
    if (len(tokens) >= 5 and tokens[0] == "interfaces" and
            tokens[2] == "priority-flow-control" and
            tokens[3] in ("rx-class-mask", "tx-class-mask",
                          "lossless-smp-mask", "shared-pause-mask")):
        ifname = tokens[1]
        return (base + "/interfaces/interface"
                "[name='" + ifname + "']/priority-flow-control/" +
                tokens[3]), tokens[4]
    if (len(tokens) >= 5 and tokens[0] == "forwarding" and
            tokens[1] == "switch-priority" and
            tokens[3] == "traffic-class"):
        return (base + "/forwarding/switch-priority"
                "[priority='" + tokens[2] + "']/traffic-class"), tokens[4]
    if (len(tokens) == 3 and tokens[0] == "scheduler" and
            tokens[1] in ("template", "policy")):
        return (base + "/scheduler/template"
                "[name='" + tokens[2] + "']/name"), tokens[2]
    if (len(tokens) == 5 and tokens[0] == "scheduler" and
            tokens[1] in ("template", "policy") and
            tokens[3] == "traffic-class-enable-mask"):
        return (base + "/scheduler/template"
                "[name='" + tokens[2] + "']/traffic-class-enable-mask",
                tokens[4])
    if (len(tokens) >= 7 and tokens[0] == "scheduler" and
            tokens[1] in ("template", "policy") and
            tokens[3] == "traffic-class" and
            tokens[5] == "shaping-group"):
        return (base + "/scheduler/template"
                "[name='" + tokens[2] + "']/traffic-class"
                "[class='" + tokens[4] + "']/shaping-group"), tokens[6]
    if (len(tokens) >= 7 and tokens[0] == "scheduler" and
            tokens[1] in ("template", "policy") and
            tokens[3] == "group" and
            tokens[5] in ("strict-priority", "weight", "rate-bps",
                          "burst-bits")):
        return (base + "/scheduler/template"
                "[name='" + tokens[2] + "']/group"
                "[id='" + tokens[4] + "']/" + tokens[5]), tokens[6]
    if (len(tokens) == 5 and tokens[0] == "scheduler" and
            tokens[1] == "interfaces" and
            tokens[3] in ("template", "policy")):
        return (base + "/scheduler/interfaces/interface"
                "[name='" + tokens[2] + "']/template"), tokens[4]
    if (len(tokens) >= 7 and tokens[0] == "scheduler" and
            tokens[1] == "interfaces" and tokens[3] == "traffic-class" and
            tokens[5] == "shaping-group"):
        return (base + "/scheduler/interfaces/interface"
                "[name='" + tokens[2] + "']/traffic-class"
                "[class='" + tokens[4] + "']/shaping-group"), tokens[6]
    if (len(tokens) == 5 and tokens[0] == "scheduler" and
            tokens[1] == "interfaces" and
            tokens[3] == "traffic-class-enable-mask"):
        return (base + "/scheduler/interfaces/interface"
                "[name='" + tokens[2] + "']/traffic-class-enable-mask",
                tokens[4])
    if (len(tokens) >= 7 and tokens[0] == "scheduler" and
            tokens[1] == "interfaces" and tokens[3] == "group" and
            tokens[5] in ("strict-priority", "weight", "rate-bps",
                          "burst-bits")):
        return (base + "/scheduler/interfaces/interface"
                "[name='" + tokens[2] + "']/group"
                "[id='" + tokens[4] + "']/" + tokens[5]), tokens[6]
    if (len(tokens) == 7 and tokens[0] == "watermarks" and
            tokens[1] == "interface" and tokens[3] == "traffic-class" and
            tokens[5] in ("tx-hog", "tx-private")):
        return (base + "/watermarks/interface"
                "[name='" + tokens[2] + "']/traffic-class"
                "[class='" + tokens[4] + "']/" + tokens[5]), tokens[6]
    if (len(tokens) == 5 and tokens[0] == "watermarks" and
            tokens[1] == "switch-priority" and
            tokens[3] in ("soft-drop", "soft-drop-jitter",
                          "soft-drop-hog")):
        return (base + "/watermarks/switch-priority"
                "[priority='" + tokens[2] + "']/" + tokens[3]), tokens[4]
    if tokens[0] == "watermarks":
        return None
    return base + "/" + "/".join(tokens), ""

def _delete_path_class_of_service(tokens):
    base = "/netlab:netlab-config/class-of-service"
    if not tokens:
        return base
    if tokens[0] == "schedulers":
        if len(tokens) == 1:
            return base + "/scheduler/template"
        path = (base + "/scheduler/template"
                "[name='" + tokens[1] + "']")
        if len(tokens) == 2:
            return path
        if len(tokens) == 3 and tokens[2] in ("transmit-rate",
                                              "buffer-size", "priority"):
            leaf = {
                "transmit-rate": "rate-bps",
                "buffer-size": "burst-bits",
                "priority": "strict-priority",
            }[tokens[2]]
            return path + "/group[id='0']/" + leaf
    if tokens[0] == "ets":
        if len(tokens) == 1:
            return base + "/scheduler"
        if len(tokens) >= 2 and tokens[1] == "policy":
            if len(tokens) == 2:
                return base + "/scheduler/template"
            return _delete_path_class_of_service(
                ["scheduler", "template", tokens[2]] + tokens[3:])
        if len(tokens) >= 2 and tokens[1] == "interfaces":
            if len(tokens) == 2:
                return base + "/scheduler/interfaces"
            if len(tokens) == 5 and tokens[3] == "policy":
                return _delete_path_class_of_service(
                    ["scheduler", "interfaces", tokens[2], "template"])
            return _delete_path_class_of_service(
                ["scheduler", "interfaces", tokens[2]] + tokens[3:])
    if tokens[0] == "interfaces":
        if len(tokens) == 1:
            return base + "/interfaces"
        path = (base + "/interfaces/interface"
                "[name='" + tokens[1] + "']")
        if len(tokens) == 2:
            return path
        if len(tokens) == 3 and tokens[2] in ("trust", "default-priority"):
            return path + "/" + tokens[2]
        if len(tokens) == 3 and tokens[2] == "scheduler-map":
            return (base + "/scheduler/interfaces/interface"
                    "[name='" + tokens[1] + "']/template")
        if len(tokens) == 3 and tokens[2] == "priority-flow-control":
            return path + "/priority-flow-control"
        if (len(tokens) == 4 and tokens[2] == "priority-flow-control" and
                tokens[3] in ("rx-class-mask", "tx-class-mask",
                              "lossless-smp-mask", "shared-pause-mask")):
            return path + "/priority-flow-control/" + tokens[3]
    if tokens[0] == "forwarding":
        if len(tokens) == 1:
            return base + "/forwarding"
        if len(tokens) >= 3 and tokens[1] == "switch-priority":
            path = (base + "/forwarding/switch-priority"
                    "[priority='" + tokens[2] + "']")
            if len(tokens) == 3:
                return path
            if len(tokens) == 4 and tokens[3] == "traffic-class":
                return path + "/traffic-class"
    if tokens[0] == "scheduler":
        if len(tokens) == 1:
            return base + "/scheduler"
        if len(tokens) >= 2 and tokens[1] in ("template", "policy"):
            if len(tokens) == 2:
                return base + "/scheduler/template"
            path = (base + "/scheduler/template"
                    "[name='" + tokens[2] + "']")
            if len(tokens) == 3:
                return path
            if (len(tokens) == 4 and
                    tokens[3] == "traffic-class-enable-mask"):
                return path + "/traffic-class-enable-mask"
            if len(tokens) >= 5 and tokens[3] == "traffic-class":
                tc_path = path + "/traffic-class[class='" + tokens[4] + "']"
                if len(tokens) == 5:
                    return tc_path
                if len(tokens) == 6 and tokens[5] == "shaping-group":
                    return tc_path + "/shaping-group"
            if len(tokens) >= 5 and tokens[3] == "group":
                group_path = path + "/group[id='" + tokens[4] + "']"
                if len(tokens) == 5:
                    return group_path
                if (len(tokens) == 6 and
                        tokens[5] in ("strict-priority", "weight",
                                      "rate-bps", "burst-bits")):
                    return group_path + "/" + tokens[5]
        if len(tokens) == 2 and tokens[1] == "interfaces":
            return base + "/scheduler/interfaces"
        if len(tokens) >= 3 and tokens[1] == "interfaces":
            path = (base + "/scheduler/interfaces/interface"
                    "[name='" + tokens[2] + "']")
            if len(tokens) == 3:
                return path
            if len(tokens) == 4 and tokens[3] in ("template", "policy"):
                return path + "/template"
            if (len(tokens) == 4 and
                    tokens[3] == "traffic-class-enable-mask"):
                return path + "/traffic-class-enable-mask"
            if len(tokens) >= 5 and tokens[3] == "traffic-class":
                tc_path = path + "/traffic-class[class='" + tokens[4] + "']"
                if len(tokens) == 5:
                    return tc_path
                if len(tokens) == 6 and tokens[5] == "shaping-group":
                    return tc_path + "/shaping-group"
            if len(tokens) >= 5 and tokens[3] == "group":
                group_path = path + "/group[id='" + tokens[4] + "']"
                if len(tokens) == 5:
                    return group_path
                if (len(tokens) == 6 and
                        tokens[5] in ("strict-priority", "weight",
                                      "rate-bps", "burst-bits")):
                    return group_path + "/" + tokens[5]
    if tokens[0] == "watermarks":
        if len(tokens) == 1:
            return base + "/watermarks"
        if len(tokens) >= 3 and tokens[1] == "switch-priority":
            path = (base + "/watermarks/switch-priority"
                    "[priority='" + tokens[2] + "']")
            if len(tokens) == 3:
                return path
            if (len(tokens) == 4 and
                    tokens[3] in ("soft-drop", "soft-drop-jitter",
                                  "soft-drop-hog")):
                return path + "/" + tokens[3]
        if len(tokens) >= 3 and tokens[1] == "interface":
            path = (base + "/watermarks/interface"
                    "[name='" + tokens[2] + "']")
            if len(tokens) == 3:
                return path
            if len(tokens) >= 5 and tokens[3] == "traffic-class":
                tc_path = path + "/traffic-class[class='" + tokens[4] + "']"
                if len(tokens) == 5:
                    return tc_path
                if len(tokens) == 6 and tokens[5] in ("tx-hog",
                                                       "tx-private"):
                    return tc_path + "/" + tokens[5]
    return None

def _path_ethernet_switching_options(tokens):
    base = "/netlab:netlab-config/ethernet-switching-options"
    def rate_feature(token):
        if token in ("storm-control", "ingress-rate-limit",
                     "egress-rate-limit"):
            return token
        return None

    if len(tokens) == 2 and tokens[0] == "mac-table-aging-time":
        return base + "/mac-table-aging-time", tokens[1]
    if (len(tokens) == 5 and tokens[0] == "secure-access-port" and
            tokens[1] == "interface" and tokens[3] == "mac-limit"):
        ifname = tokens[2]
        return (base + "/secure-access-port/interface"
                "[name='" + ifname + "']/mac-limit"), tokens[4]
    if (len(tokens) == 5 and tokens[0] == "secure-access-port" and
            tokens[1] == "interface" and tokens[3] == "action"):
        ifname = tokens[2]
        return (base + "/secure-access-port/interface"
                "[name='" + ifname + "']/violation-action"), tokens[4]
    feature = rate_feature(tokens[0]) if tokens else None
    if (len(tokens) == 5 and feature and
            tokens[1] == "interface" and
            tokens[3] in ("bandwidth", "burst-size")):
        ifname = tokens[2]
        path = (base + "/" + feature + "/interface"
                "[name='" + ifname + "']")
        return path + "/" + tokens[3], tokens[4]
    if (len(tokens) == 4 and tokens[0] == "mac-move" and
            tokens[1] == "dampening" and
            tokens[2] in ("threshold", "window", "action")):
        return base + "/mac-move/dampening/" + tokens[2], tokens[3]
    if len(tokens) == 3 and tokens[0] == "dhcp-snooping" and tokens[1] == "vlan":
        return (base + "/dhcp-snooping/vlan"
                "[name='" + tokens[2] + "']/name"), tokens[2]
    if (len(tokens) == 4 and tokens[0] == "dhcp-snooping" and
            tokens[1] == "interface" and tokens[3] == "trusted"):
        return (base + "/dhcp-snooping/interface"
                "[name='" + tokens[2] + "']/trusted"), "true"
    if (len(tokens) == 7 and tokens[0] == "dhcp-snooping" and
            tokens[1] == "binding" and tokens[3] == "vlan" and
            tokens[5] == "interface"):
        mac = tokens[2].lower()
        vlan = tokens[4]
        ifname = tokens[6]
        return (base + "/dhcp-snooping/binding"
                "[mac-address='" + mac + "']"
                "[vlan='" + vlan + "']/interface"), ifname
    if (len(tokens) == 7 and tokens[0] == "dhcp-snooping" and
            tokens[1] == "binding" and tokens[3] == "vlan" and
            tokens[5] == "ip-address"):
        mac = tokens[2].lower()
        vlan = tokens[4]
        ip = tokens[6]
        return (base + "/dhcp-snooping/binding"
                "[mac-address='" + mac + "']"
                "[vlan='" + vlan + "']/ip-address"), ip
    if len(tokens) == 3 and tokens[0] == "arp-inspection" and tokens[1] == "vlan":
        return (base + "/arp-inspection/vlan"
                "[name='" + tokens[2] + "']/name"), tokens[2]
    if (len(tokens) == 4 and tokens[0] == "arp-inspection" and
            tokens[1] == "interface" and tokens[3] == "trusted"):
        return (base + "/arp-inspection/interface"
                "[name='" + tokens[2] + "']/trusted"), "true"
    if (len(tokens) == 5 and tokens[0] in ("user-filter", "ingress-acl") and
            tokens[1] == "term" and
            tokens[3] in ("vlan", "interface", "source-mac",
                           "destination-mac", "action")):
        feature = tokens[0]
        leaf = tokens[3]
        if leaf in ("source-mac", "destination-mac"):
            value = tokens[4].lower()
        else:
            value = tokens[4]
        return (base + "/" + feature + "/term"
                "[name='" + tokens[2] + "']/" + leaf), value
    if (len(tokens) == 4 and tokens[0] == "acl" and
            tokens[1] == "term" and _acl_alias_target(tokens[3])):
        return None, ""
    if (len(tokens) == 6 and tokens[0] == "acl" and
            tokens[1] == "term"):
        feature = _acl_alias_target(tokens[3])
        leaf = tokens[4]
        if feature and leaf in _acl_alias_allowed_leaves(feature):
            return (base + "/" + feature + "/term"
                    "[name='" + tokens[2] + "']/" + leaf), \
                   _acl_alias_value(leaf, tokens[5])
    if (len(tokens) == 6 and tokens[0] == "acl" and
            tokens[1] == "group" and tokens[3] == "term" and
            _acl_alias_target(tokens[5])):
        return None, ""
    if (len(tokens) == 8 and tokens[0] == "acl" and
            tokens[1] == "group" and tokens[3] == "term"):
        feature = _acl_alias_target(tokens[5])
        leaf = tokens[6]
        term_name = _acl_group_term_name(tokens[2], tokens[4])
        if feature and leaf in _acl_alias_allowed_leaves(feature):
            return (base + "/" + feature + "/term"
                    "[name='" + term_name + "']/" + leaf), \
                   _acl_alias_value(leaf, tokens[7])
    if (len(tokens) == 6 and tokens[0] == "acl" and
            tokens[1] == "independent-group" and tokens[3] == "term" and
            _acl_alias_target(tokens[5])):
        return None, ""
    if (len(tokens) == 8 and tokens[0] == "acl" and
            tokens[1] == "independent-group" and tokens[3] == "term"):
        feature = _acl_alias_target(tokens[5])
        leaf = tokens[6]
        if feature and leaf in _acl_independent_allowed_leaves(tokens[5]):
            return (_acl_independent_base(tokens[2], tokens[4], tokens[5]) +
                    "/" + leaf), _acl_alias_value(leaf, tokens[7])
        if tokens[5] in ("egress", "egress-mac"):
            return None, ""
    if (len(tokens) == 5 and tokens[0] == "ingress-ipv4-acl" and
            tokens[1] == "term" and
            tokens[3] in ("vlan", "interface", "source-ip",
                          "source-prefix", "destination-ip",
                          "destination-prefix", "dscp", "ecn", "protocol",
                          "source-port", "source-port-range",
                          "destination-port", "destination-port-range",
                          "tcp-flags",
                          "tcp-flags-mask", "action")):
        return (base + "/ingress-ipv4-acl/term"
                "[name='" + tokens[2] + "']/" + tokens[3]), tokens[4]
    if (len(tokens) == 5 and tokens[0] == "acl-policer" and
            tokens[1] == "term" and
            tokens[3] in ("interface", "destination-mac",
                          "bandwidth", "burst-size")):
        value = tokens[4].lower() if tokens[3] == "destination-mac" else tokens[4]
        return (base + "/acl-policer/term"
                "[name='" + tokens[2] + "']/" + tokens[3]), value
    if (len(tokens) == 5 and tokens[0] == "egress-acl" and
            tokens[1] == "term" and
            tokens[3] in ("interface", "source-mac", "destination-mac",
                          "action")):
        value = tokens[4].lower() if tokens[3] in ("source-mac", "destination-mac") else tokens[4]
        return (base + "/egress-acl/term"
                "[name='" + tokens[2] + "']/" + tokens[3]), value
    if (len(tokens) == 7 and tokens[0] == "static" and
            tokens[1] == "mac-table-entry" and tokens[3] == "vlan" and
            tokens[5] == "interface"):
        mac = tokens[2].lower()
        vlan = tokens[4]
        ifname = tokens[6]
        return (base + "/static/mac-table-entry"
                "[mac-address='" + mac + "']"
                "[vlan='" + vlan + "']/interface"), ifname
    return base + "/" + "/".join(tokens), ""

def _delete_path_ethernet_switching_options(tokens):
    base = "/netlab:netlab-config/ethernet-switching-options"
    def rate_feature(token):
        if token in ("storm-control", "ingress-rate-limit",
                     "egress-rate-limit"):
            return token
        return None

    if tokens == ["mac-table-aging-time"]:
        return base + "/mac-table-aging-time"
    if (len(tokens) >= 3 and tokens[0] == "secure-access-port" and
            tokens[1] == "interface"):
        path = (base + "/secure-access-port/interface"
                "[name='" + tokens[2] + "']")
        if len(tokens) == 3:
            return path
        if len(tokens) == 4 and tokens[3] == "mac-limit":
            return path + "/mac-limit"
        if len(tokens) == 4 and tokens[3] == "action":
            return path + "/violation-action"
    feature = rate_feature(tokens[0]) if tokens else None
    if (len(tokens) >= 3 and feature and
            tokens[1] == "interface"):
        path = (base + "/" + feature + "/interface"
                "[name='" + tokens[2] + "']")
        if len(tokens) == 3:
            return path
        if len(tokens) == 4 and tokens[3] in ("bandwidth", "burst-size"):
            return path + "/" + tokens[3]
    if (len(tokens) >= 2 and tokens[0] == "mac-move" and
            tokens[1] == "dampening"):
        path = base + "/mac-move/dampening"
        if len(tokens) == 2:
            return path
        if len(tokens) == 3 and tokens[2] in ("threshold", "window", "action"):
            return path + "/" + tokens[2]
    if len(tokens) == 1 and tokens[0] in ("dhcp-snooping", "arp-inspection"):
        return base + "/" + tokens[0]
    if len(tokens) >= 2 and tokens[0] in ("dhcp-snooping", "arp-inspection"):
        feature = tokens[0]
        if tokens[1] == "vlan":
            if len(tokens) == 2:
                return base + "/" + feature + "/vlan"
            if len(tokens) == 3:
                return (base + "/" + feature + "/vlan"
                        "[name='" + tokens[2] + "']")
        if tokens[1] == "interface":
            if len(tokens) == 2:
                return base + "/" + feature + "/interface"
            if len(tokens) >= 3:
                path = (base + "/" + feature + "/interface"
                        "[name='" + tokens[2] + "']")
                if len(tokens) == 3:
                    return path
                if len(tokens) == 4 and tokens[3] == "trusted":
                    return path + "/trusted"
        if feature == "dhcp-snooping" and tokens[1] == "binding":
            if len(tokens) == 2:
                return base + "/dhcp-snooping/binding"
            if len(tokens) >= 5 and tokens[3] == "vlan":
                mac = tokens[2].lower()
                vlan = tokens[4]
                path = (base + "/dhcp-snooping/binding"
                        "[mac-address='" + mac + "']"
                        "[vlan='" + vlan + "']")
                if len(tokens) == 5:
                    return path
                if len(tokens) == 6 and tokens[5] in ("interface", "ip-address"):
                    return path + "/" + tokens[5]
    if len(tokens) == 1 and tokens[0] in ("user-filter", "ingress-acl",
                                          "ingress-ipv4-acl",
                                          "acl-policer", "egress-acl"):
        return base + "/" + tokens[0]
    if (len(tokens) >= 4 and tokens[0] == "acl" and tokens[1] == "term"):
        feature = _acl_alias_target(tokens[3])
        if feature:
            path = (base + "/" + feature + "/term"
                    "[name='" + tokens[2] + "']")
            if len(tokens) == 4:
                return path
            if (len(tokens) == 5 and
                    tokens[4] in _acl_alias_allowed_leaves(feature)):
                return path + "/" + tokens[4]
    if (len(tokens) >= 6 and tokens[0] == "acl" and
            tokens[1] == "group" and tokens[3] == "term"):
        feature = _acl_alias_target(tokens[5])
        if feature:
            term_name = _acl_group_term_name(tokens[2], tokens[4])
            path = (base + "/" + feature + "/term"
                    "[name='" + term_name + "']")
            if len(tokens) == 6:
                return path
            if (len(tokens) == 7 and
                    tokens[6] in _acl_alias_allowed_leaves(feature)):
                return path + "/" + tokens[6]
    if (len(tokens) >= 2 and tokens[0] == "acl" and
            tokens[1] == "independent-group"):
        if len(tokens) == 2:
            return base + "/acl-independent"
        if len(tokens) == 3:
            return (base + "/acl-independent/group"
                    "[name='" + tokens[2] + "']")
        if len(tokens) >= 6 and tokens[3] == "term":
            feature = _acl_alias_target(tokens[5])
            if feature and tokens[5] not in ("egress", "egress-mac"):
                path = _acl_independent_base(tokens[2], tokens[4], tokens[5])
                if len(tokens) == 6:
                    return path
                if (len(tokens) == 7 and
                        tokens[6] in _acl_independent_allowed_leaves(tokens[5])):
                    return path + "/" + tokens[6]
    if (len(tokens) >= 2 and tokens[0] in ("user-filter", "ingress-acl",
                                           "ingress-ipv4-acl",
                                           "acl-policer", "egress-acl") and
            tokens[1] == "term"):
        if len(tokens) == 2:
            return base + "/" + tokens[0] + "/term"
        path = (base + "/" + tokens[0] + "/term"
                "[name='" + tokens[2] + "']")
        if len(tokens) == 3:
            return path
        mac_leaves = ("source-mac", "destination-mac")
        ipv4_leaves = ("source-ip", "source-prefix", "destination-ip",
                       "destination-prefix", "dscp", "ecn", "protocol",
                       "source-port", "source-port-range",
                       "destination-port", "destination-port-range",
                       "tcp-flags",
                       "tcp-flags-mask")
        common_leaves = ("vlan", "interface", "action")
        if tokens[0] == "acl-policer":
            allowed = ("interface", "destination-mac",
                       "bandwidth", "burst-size")
        elif tokens[0] == "egress-acl":
            allowed = ("interface", "source-mac", "destination-mac",
                       "action")
        else:
            allowed = common_leaves + (
                ipv4_leaves if tokens[0] == "ingress-ipv4-acl" else mac_leaves)
        if len(tokens) == 4 and tokens[3] in allowed:
            return path + "/" + tokens[3]
    if (len(tokens) >= 5 and tokens[0] == "static" and
            tokens[1] == "mac-table-entry" and tokens[3] == "vlan"):
        mac = tokens[2].lower()
        vlan = tokens[4]
        path = (base + "/static/mac-table-entry"
                "[mac-address='" + mac + "']"
                "[vlan='" + vlan + "']")
        if len(tokens) == 5:
            return path
        if len(tokens) == 6 and tokens[5] == "interface":
            return path + "/interface"
    return None
