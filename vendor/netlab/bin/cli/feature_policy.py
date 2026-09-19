"""Configuration feature gates for the CLI.

The CLI uses these gates for early, user-friendly rejection. Backend daemons
must still validate the candidate and fail closed before touching hardware.
"""

from public_capabilities import (GENERAL_ACL_INDEPENDENT,
                                 MANAGEMENT_SERVICES,
                                 public_capability_enabled)


class UnsupportedConfigPolicy:
    def __init__(self, name, predicate, reason):
        self.name = name
        self.predicate = predicate
        self.reason = reason

    def matches(self, tokens):
        return self.predicate(tokens)

    def message(self, tokens):
        reason = self.reason(tokens) if callable(self.reason) else self.reason
        return "error: unsupported configuration\nreason: " + reason


def _pvst(tokens):
    return (len(tokens) >= 2 and tokens[0] == "protocols" and
            tokens[1] in ("pvst", "rapid-pvst"))


def _internal_interfaces_routing(tokens):
    return bool(tokens) and tokens[0] == "interfaces-routing"


def _is_ipv4_address(value):
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(part, 10) for part in parts]
    except ValueError:
        return False
    return all(0 <= octet <= 255 for octet in octets)


def _internal_static_route_handles(tokens):
    if not (len(tokens) >= 3 and tokens[0] == "routing-options" and
            tokens[1] == "static"):
        return False
    if tokens[2] in ("arp", "next-hop", "ecmp"):
        return True
    if not (len(tokens) >= 5 and tokens[2] == "route"):
        return False
    if tokens[4] in ("ecmp", "ecmp-id", "next-hop-id"):
        return True
    return (tokens[4] == "next-hop" and len(tokens) >= 6 and
            not _is_ipv4_address(tokens[5]))


def _l3_profile_required(tokens):
    return _is_l3_config_root(tokens) and not _active_profile_has_l3()


def _parse_ipv4_prefix(value):
    if not value or "/" not in value:
        return None
    ip_text, plen_text = value.rsplit("/", 1)
    parts = ip_text.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(part, 10) for part in parts]
        plen = int(plen_text, 10)
    except ValueError:
        return None
    if any(octet < 0 or octet > 255 for octet in octets):
        return None
    if plen < 0 or plen > 32:
        return None
    value_u32 = ((octets[0] << 24) | (octets[1] << 16) |
                 (octets[2] << 8) | octets[3])
    return value_u32, plen


def _ipv4_prefix_is_deferred(value):
    parsed = _parse_ipv4_prefix(value)
    if parsed is None:
        return False
    value_u32, plen = parsed
    if plen == 0:
        return False
    return (value_u32 >> 28) >= 14


def _physical_routed_interface_supported(tokens):
    if len(tokens) < 8 or tokens[0] != "interfaces" or \
            tokens[1] == "irb" or tuple(tokens[2:6]) != (
                "unit", "0", "family", "inet"):
        return False
    rest = tokens[6:]
    if len(rest) < 2 or rest[0] != "address" or \
            _parse_ipv4_prefix(rest[1]) is None:
        return False
    if len(rest) == 2:
        return not _ipv4_prefix_is_deferred(rest[1])
    if len(rest) != 6 or rest[2] != "arp" or \
            not _is_ipv4_address(rest[3]):
        return False
    if rest[4] == "mac":
        parts = rest[5].split(":")
        return (len(parts) == 6 and
                all(len(part) == 2 and
                    all(ch in "0123456789abcdefABCDEF" for ch in part)
                    for part in parts))
    return rest[4] in ("egress-interface", "interface") and bool(rest[5])


def _physical_routed_interface_delete_supported(tokens):
    if len(tokens) < 6 or tokens[0] != "interfaces" or \
            tokens[1] == "irb" or tuple(tokens[2:6]) != (
                "unit", "0", "family", "inet"):
        return False
    rest = tuple(tokens[6:])
    if not rest:
        return True
    if rest[0] != "address":
        return False
    if len(rest) == 1:
        return True
    if _parse_ipv4_prefix(rest[1]) is None:
        return False
    if len(rest) == 2:
        return True
    if len(rest) < 4 or rest[2] != "arp" or \
            not _is_ipv4_address(rest[3]):
        return False
    if len(rest) == 4:
        return True
    if rest[4] not in ("mac", "egress-interface", "interface"):
        return False
    return len(rest) == 5 or (len(rest) == 6 and bool(rest[5]))


def _l3_v1_deferred(tokens):
    if not tokens:
        return False
    if tokens[0] == "firewall":
        return not _firewall_filter_facade_supported(tokens)
    if tokens[0] == "forwarding-options":
        return not _port_mirroring_supported(tokens)
    if tokens[0] == "routing-instances":
        return not _vrf_v1_supported(tokens)
    if tokens[0] == "tunnels":
        return True
    if tokens[0] == "interfaces" and len(tokens) >= 2:
        if tokens[1] in ("tunnel", "vxlan", "vtep"):
            return True
        if tokens[1] == "irb":
            return (len(tokens) >= 6 and tokens[4] == "family" and
                    tokens[5] != "inet")
        for idx, token in enumerate(tokens[:-1]):
            if (token == "family" and
                    tokens[idx + 1] in ("inet", "inet6", "iso", "mpls")):
                return not _physical_routed_interface_supported(tokens)
    if tokens[0] == "routing-options" and len(tokens) >= 2:
        if tokens[1] in ("multicast", "rib-groups", "forwarding-table"):
            return True
        if (len(tokens) >= 4 and tokens[1] == "static" and
                tokens[2] == "route" and
                _ipv4_prefix_is_deferred(tokens[3])):
            return True
    if tokens[0] == "protocols" and len(tokens) >= 2:
        if tokens[1] in ("ospf3", "pim", "igmp", "mld", "msdp",
                         "isis", "rip", "evpn", "ldp", "mpls"):
            return True
        if tokens[1] == "bgp" and any(token == "family" for token in tokens):
            return True
    if any(token in ("vxlan", "evpn") for token in tokens):
        return True
    return False


def _port_mirroring_supported(tokens):
    if len(tokens) < 2 or tuple(tokens[:2]) != ("forwarding-options",
                                                "port-mirroring"):
        return False
    if len(tokens) <= 4:
        return len(tokens) < 3 or tokens[2] == "instance"
    if tokens[2] != "instance":
        return False
    rest = tokens[4:]
    if len(rest) == 3 and tuple(rest[:2]) == ("output", "interface"):
        return True
    if len(rest) == 3 and tuple(rest[:2]) == ("input", "interface"):
        return True
    return (len(rest) == 5 and tuple(rest[:2]) == ("input", "interface") and
            rest[3] == "direction" and
            rest[4] in ("ingress", "egress", "both"))


def _l3_v1_deferred_reason(tokens):
    if tokens and tokens[0] == "firewall":
        return ("firewall configuration is limited to hardware-backed "
                "firewall family ethernet-switching|inet filter <name> "
                "term <term> from ... then discard|accept|count. PBR, "
                "redirect, and VRF actions remain deferred")
    if len(tokens) >= 6 and tokens[0] == "interfaces" and tokens[1] == "irb":
        if tokens[4] == "family" and tokens[5] == "inet6":
            return ("IPv6 routing is deferred; L3 V1 supports only "
                    "interfaces irb unit <unit> family inet address <prefix>")
    if len(tokens) >= 6 and tokens[0] == "interfaces" and \
            tokens[1] != "irb" and tokens[2] == "unit":
        return ("physical routed interface V1 supports only unit 0 family "
                "inet address <IPv4-prefix> with optional static ARP")
    if tokens and tokens[0] == "routing-instances":
        return ("VRF V1 supports one instance-type vrf, existing routed "
                "interface assignment, and IPv4 static routing only")
    if (len(tokens) >= 4 and tokens[0] == "routing-options" and
            tokens[1] == "static" and tokens[2] == "route"):
        return ("L3 V1 supports IPv4 unicast routes only; multicast and "
                "Class-E route prefixes are deferred")
    if tokens and tokens[0] == "forwarding-options":
        return ("forwarding-options supports only local port-mirroring "
                "instance <name> output interface <physical-interface> and "
                "input interface <physical-interface> direction "
                "ingress|egress|both")
    if tokens and tokens[0] == "firewall":
        return "policy routing is deferred; PBR is outside L3 V1"
    if tokens and (tokens[0] in ("tunnels",) or
                   any(token in ("tunnel", "vxlan", "evpn")
                       for token in tokens)):
        return "tunnel/VXLAN/EVPN routing is deferred outside L3 V1"
    return ("L3 supports IPv4 inet.0 connected/static/OSPF/BGP and one "
            "additional static-only VRF; IPv6, VRF dynamic protocols, "
            "multicast routing, PBR, and tunnel/VXLAN remain deferred")


def _vrf_v1_supported(tokens):
    if not tokens or tokens[0] != "routing-instances":
        return False
    if len(tokens) <= 2:
        return True
    rest = tokens[2:]
    if rest[0] == "instance-type":
        return len(rest) == 1 or (len(rest) == 2 and rest[1] == "vrf")
    if rest[0] == "interface":
        return len(rest) <= 2
    if tuple(rest[:2]) != ("routing-options", "static"):
        return False
    if len(rest) <= 2:
        return True
    if rest[2] not in ("arp", "next-hop", "ecmp", "route"):
        return False
    if rest[2] == "route" and len(rest) >= 4 and \
            _ipv4_prefix_is_deferred(rest[3]):
        return False
    return True


def _firewall_filter_facade_supported(tokens):
    if (len(tokens) < 7 or tokens[0] != "firewall" or
            tokens[1] != "family" or tokens[3] != "filter" or
            tokens[5] != "term"):
        return False
    family = tokens[2]
    if family not in ("ethernet-switching", "inet"):
        return False
    rest = tokens[7:]
    if not rest:
        return True
    if family == "ethernet-switching" and rest[0] in ("policer", "egress"):
        mode = rest[0]
        mode_rest = rest[1:]
        if not mode_rest:
            return True
        if mode == "policer":
            if len(mode_rest) == 3 and mode_rest[0] == "from":
                return mode_rest[1] in ("interface", "destination-mac")
            if len(mode_rest) == 3 and mode_rest[0] == "then":
                return mode_rest[1] in ("bandwidth", "burst-size")
        if mode == "egress":
            if len(mode_rest) == 3 and mode_rest[0] == "from":
                return mode_rest[1] in (
                    "interface", "source-mac", "destination-mac")
            if len(mode_rest) == 2 and mode_rest[0] == "then":
                return mode_rest[1] == "discard"
        return False
    if len(rest) == 3 and rest[0] == "from":
        common = ("vlan", "interface")
        ethernet = common + ("source-mac", "destination-mac")
        inet = common + (
            "source-address", "destination-address", "dscp", "ecn",
            "protocol", "source-port", "source-port-range",
            "destination-port", "destination-port-range", "tcp-flags",
            "tcp-flags-mask")
        return rest[1] in (ethernet if family == "ethernet-switching" else inet)
    if len(rest) == 2 and rest[0] == "then":
        return rest[1] in ("discard", "accept", "count")
    return False


def _is_l3_config_root(tokens):
    if not tokens:
        return False
    if tokens[0] in ("routing-options", "routing-instances",
                     "interfaces-routing", "policy-options"):
        return True
    if len(tokens) >= 2 and tokens[0] == "protocols" and tokens[1] in ("ospf", "bgp"):
        return True
    if len(tokens) >= 2 and tokens[0] == "interfaces" and \
            tokens[1] == "irb":
        return True
    return (len(tokens) >= 6 and tokens[0] == "interfaces" and
            tokens[2] == "unit" and tokens[4] == "family" and
            tokens[5] in ("inet", "inet6"))


def _active_profile_has_l3():
    try:
        from platform_profile import load_profile

        profile = load_profile()
    except Exception:
        return False

    ffu = profile.get("ffu", {})

    def enabled(first_name, last_name):
        try:
            first = int(ffu.get(first_name, "-1"), 0)
            last = int(ffu.get(last_name, "-1"), 0)
        except (TypeError, ValueError):
            return False
        return first >= 0 and last >= first

    has_route_slice = (
        enabled("ipv4-uc-first", "ipv4-uc-last") or
        enabled("ipv4-mc-first", "ipv4-mc-last") or
        enabled("ipv6-uc-first", "ipv6-uc-last") or
        enabled("ipv6-mc-first", "ipv6-mc-last")
    )
    has_route_port = False
    for entry in profile.get("ports", []):
        caps = {cap.strip().upper() for cap in
                (entry.get("capabilities") or "").split(",") if cap.strip()}
        role = (entry.get("role") or "").lower()
        flags = {flag.strip().lower() for flag in
                 (entry.get("flags") or "").split(",") if flag.strip()}
        if "ROUTE" in caps and (role == "external" or "external" in flags):
            has_route_port = True
            break
    return has_route_slice and has_route_port


def _cos_scheduler_policy_leaf(tokens):
    if len(tokens) in (1, 2) and tokens[0] == "traffic-class-enable-mask":
        return True
    if len(tokens) >= 2 and tokens[0] == "traffic-class":
        if len(tokens) == 2:
            return True
        if len(tokens) >= 4 and tokens[2] == "shaping-group":
            return True
        return False
    if len(tokens) >= 2 and tokens[0] == "group":
        if len(tokens) == 2:
            return True
        if (len(tokens) >= 4 and
                tokens[2] in ("strict-priority", "weight", "rate-bps",
                              "burst-bits")):
            return True
        return False
    return False


def _cos_scheduler_interface_leaf(tokens):
    if len(tokens) in (1, 2) and tokens[0] == "template":
        return True
    if len(tokens) in (1, 2) and tokens[0] == "policy":
        return True
    return _cos_scheduler_policy_leaf(tokens)


def _cos_scheduler_policy(tokens):
    if not (len(tokens) >= 2 and tokens[0] == "class-of-service" and
            tokens[1] == "scheduler"):
        return False
    if len(tokens) >= 3 and tokens[2] in ("template", "interfaces"):
        return False
    if len(tokens) >= 3 and tokens[2] == "policy":
        if len(tokens) == 4:
            return False
        return not _cos_scheduler_policy_leaf(tokens[4:])
    return True


def _cos_ets_policy(tokens):
    if not (len(tokens) >= 2 and tokens[0] == "class-of-service" and
            tokens[1] == "ets"):
        return False
    if len(tokens) >= 3 and tokens[2] == "policy":
        if len(tokens) == 4:
            return False
        return not _cos_scheduler_policy_leaf(tokens[4:])
    if len(tokens) >= 3 and tokens[2] == "interfaces":
        if len(tokens) == 4:
            return False
        if len(tokens) == 6 and tokens[4] == "policy":
            return False
        return not _cos_scheduler_interface_leaf(tokens[4:])
    return True


def _cos_schedulers_facade(tokens):
    if not (len(tokens) >= 2 and tokens[0] == "class-of-service" and
            tokens[1] == "schedulers"):
        return False
    if len(tokens) <= 3:
        return False
    rest = tokens[3:]
    if len(rest) == 1 and rest[0] in ("transmit-rate", "buffer-size",
                                      "priority"):
        return False
    if len(rest) == 2 and rest[0] in ("transmit-rate", "buffer-size"):
        return False
    if len(rest) == 2 and rest[0] == "priority":
        return rest[1] not in ("strict-high", "low")
    return True


def _cos_queue_policy(tokens):
    return (len(tokens) >= 2 and tokens[0] == "class-of-service" and
            tokens[1] in ("queues", "queue", "queue-policy", "drop-profile"))


def _cos_watermarks(tokens):
    if not (len(tokens) >= 2 and tokens[0] == "class-of-service" and
            tokens[1] in ("watermark", "watermarks")):
        return False
    if tokens[1] != "watermarks":
        return True
    if len(tokens) == 2:
        return False
    if len(tokens) >= 4 and tokens[2] == "switch-priority":
        if len(tokens) == 4:
            return False
        if tokens[4] not in ("soft-drop", "soft-drop-jitter",
                             "soft-drop-hog"):
            return True
        if len(tokens) in (5, 6):
            return False
        return True
    if not (len(tokens) >= 4 and tokens[2] == "interface"):
        return True
    if len(tokens) == 4:
        return False
    if not (len(tokens) >= 6 and tokens[4] == "traffic-class"):
        return True
    if len(tokens) == 6:
        return False
    if tokens[6] not in ("tx-hog", "tx-private"):
        return True
    if len(tokens) in (7, 8):
        return False
    return True


def _cos_ecn(tokens):
    return (len(tokens) >= 2 and tokens[0] == "class-of-service" and
            tokens[1] == "ecn")


def _legacy_rate_limit(tokens):
    return (len(tokens) >= 2 and tokens[0] == "ethernet-switching-options" and
            tokens[1] == "rate-limit")


def _general_acl_supported_family(tokens):
    if not (len(tokens) >= 3 and
            tokens[0] == "ethernet-switching-options" and
            tokens[1] == "acl"):
        return False
    if tokens[2] == "term":
        if len(tokens) < 5:
            return False
        family = tokens[4]
        family_index = 4
    elif (tokens[2] == "group" and len(tokens) >= 7 and
          tokens[4] == "term"):
        family = tokens[6]
        family_index = 6
    elif tokens[2] == "independent-group":
        if len(tokens) in (4, 6) and (len(tokens) == 4 or tokens[4] == "term"):
            return True
        if not (len(tokens) >= 7 and tokens[4] == "term"):
            return False
        family = tokens[6]
        family_index = 6
    else:
        return False
    common = ("vlan", "interface", "action")
    mac_leaves = ("source-mac", "destination-mac")
    ipv4_leaves = ("source-ip", "source-prefix", "destination-ip",
                   "destination-prefix", "dscp", "ecn", "protocol",
                   "source-port", "source-port-range",
                   "destination-port", "destination-port-range",
                   "tcp-flags", "tcp-flags-mask")
    policer_leaves = ("bandwidth", "burst-size")
    if tokens[2] == "independent-group":
        if family in ("ethernet", "ethernet-switching", "l2", "mac"):
            allowed = common + mac_leaves + policer_leaves
        elif family in ("inet", "ipv4"):
            allowed = common + ipv4_leaves + policer_leaves
        elif family == "policer":
            allowed = ("vlan", "interface") + mac_leaves + ipv4_leaves + \
                      policer_leaves
        else:
            return False
    else:
        if family in ("ethernet", "ethernet-switching", "l2", "mac"):
            allowed = common + mac_leaves
        elif family in ("inet", "ipv4"):
            allowed = common + ipv4_leaves
        elif family == "policer":
            allowed = ("interface", "destination-mac", "bandwidth",
                       "burst-size")
        elif family in ("egress", "egress-mac"):
            allowed = ("interface", "source-mac", "destination-mac",
                       "action")
        else:
            return False
    if len(tokens) == family_index + 1:
        return True
    return (len(tokens) == family_index + 3 and
            tokens[family_index + 1] in allowed)


def _general_acl(tokens):
    if not (len(tokens) >= 2 and
            tokens[0] == "ethernet-switching-options"):
        return False
    if tokens[1] in ("filter", "egress-filter"):
        return True
    if tokens[1] != "acl":
        return False
    if not public_capability_enabled(GENERAL_ACL_INDEPENDENT):
        return True
    return not _general_acl_supported_family(tokens)


def _general_acl_reason(tokens):
    if (len(tokens) >= 2 and tokens[1] == "acl" and
            not public_capability_enabled(GENERAL_ACL_INDEPENDENT)):
        return (
            "independent General ACL is closed by the immutable public "
            "capability authority until allocator, read-back, rollback, "
            "restart/replay, counter, cleanup, and traffic evidence is promoted")
    return (
        "general ACL requires an explicit supported family: ethernet, inet, "
        "policer, or egress. Use firewall family ethernet-switching|inet "
        "filter <filter> term <term> from ... then discard|accept|count, or "
        "the firewall policer/egress facade for scoped ethernet-switching terms")


def _management_services(tokens):
    if public_capability_enabled(MANAGEMENT_SERVICES):
        return False
    return ((len(tokens) >= 2 and tokens[0] == "system" and
             tokens[1] == "services") or
            (bool(tokens) and tokens[0] == "snmp"))


def _ipv4_acl_policer_action(tokens):
    return (len(tokens) >= 5 and
            tokens[0] == "ethernet-switching-options" and
            tokens[1] == "ingress-ipv4-acl" and
            tokens[2] == "term" and
            (tokens[4] in ("policer", "policer-action") or
             (tokens[4] == "action" and len(tokens) >= 6 and
              tokens[5] == "policer")))


def _independent_egress_acl(tokens):
    return (public_capability_enabled(GENERAL_ACL_INDEPENDENT) and
            len(tokens) >= 7 and
            tokens[0] == "ethernet-switching-options" and
            tokens[1] == "acl" and
            tokens[2] == "independent-group" and
            tokens[4] == "term" and
            tokens[6] in ("egress", "egress-mac"))


def _legacy_acl_owner_config(tokens):
    return (len(tokens) >= 2 and
            tokens[0] == "ethernet-switching-options" and
            tokens[1] in ("user-filter", "ingress-acl", "ingress-ipv4-acl",
                          "acl-policer", "egress-acl"))


def _legacy_acl_owner_config_reason(tokens):
    root = tokens[1] if len(tokens) > 1 else ""
    if root == "user-filter":
        return ("ethernet-switching-options user-filter is unsupported "
                "legacy syntax; use firewall family ethernet-switching "
                "filter <filter> term <term> from ... then discard")
    if root == "ingress-acl":
        return ("ethernet-switching-options ingress-acl is unsupported "
                "legacy syntax; use firewall family ethernet-switching filter "
                "<filter> term <term> from ... then accept|discard|count")
    if root == "ingress-ipv4-acl":
        return ("ethernet-switching-options ingress-ipv4-acl is unsupported "
                "legacy syntax; use firewall family inet filter <filter> "
                "term <term> from ... then accept|discard|count")
    if root == "acl-policer":
        return ("ethernet-switching-options acl-policer is unsupported "
                "legacy syntax; use firewall family ethernet-switching filter "
                "<filter> term <term> policer from interface|"
                "destination-mac ... then bandwidth|burst-size ...")
    if root == "egress-acl":
        return ("ethernet-switching-options egress-acl is unsupported "
                "legacy syntax; use firewall family ethernet-switching filter "
                "<filter> term <term> egress from interface|source-mac|"
                "destination-mac ... then discard")
    return "legacy ACL configuration syntax is not public"


UNSUPPORTED_CONFIG_POLICIES = (
    UnsupportedConfigPolicy(
        "pvst",
        _pvst,
        ("PVST protocol state is not hardware-backed; use protocols rstp or "
         "protocols mstp"),
    ),
    UnsupportedConfigPolicy(
        "internal-interfaces-routing",
        _internal_interfaces_routing,
        ("direct routed-interface syntax is unsupported; use interfaces irb "
         "unit <unit> or interfaces <physical> unit 0 family inet"),
    ),
    UnsupportedConfigPolicy(
        "internal-static-route-handles",
        _internal_static_route_handles,
        ("direct static routing syntax is unsupported; use interfaces "
         "irb unit <unit> family inet address <prefix> arp <neighbor-ip> "
         "mac|egress-interface ... and routing-options static route "
         "<prefix> next-hop <ip>"),
    ),
    UnsupportedConfigPolicy(
        "l3-v1-deferred",
        _l3_v1_deferred,
        _l3_v1_deferred_reason,
    ),
    UnsupportedConfigPolicy(
        "l3-profile-required",
        _l3_profile_required,
        ("L3 routing requires an active L3 chassis mode with route slices "
         "and ROUTE-capable external ports"),
    ),
    UnsupportedConfigPolicy(
        "cos-scheduler-policy",
        _cos_scheduler_policy,
        ("unsupported scheduler policy path; use scheduler policy <name> ... "
         "or scheduler template <name> ... or scheduler interfaces <if> "
         "policy|template <name>, scheduler interfaces "
         "<if> traffic-class <0-7> shaping-group <0-7> or scheduler "
         "interfaces <if> traffic-class-enable-mask <1-255> or scheduler "
         "interfaces <if> group <0-7> "
         "strict-priority|weight|rate-bps|burst-bits"),
    ),
    UnsupportedConfigPolicy(
        "cos-ets-policy",
        _cos_ets_policy,
        ("unsupported ETS policy path; current FM10000 ETS support is the "
         "scheduler-backed subset: class-of-service ets policy <name> "
         "traffic-class-enable-mask|traffic-class|group ... and "
         "class-of-service ets interfaces <if> policy|traffic-class-enable-mask|"
         "traffic-class|group ..."),
    ),
    UnsupportedConfigPolicy(
        "cos-schedulers-facade",
        _cos_schedulers_facade,
        ("class-of-service schedulers supports only the Junos facade "
         "schedulers <name> transmit-rate <bps>, buffer-size <bits>, "
         "or priority strict-high|low; advanced queue/drop/ECN policy "
         "remains deferred"),
    ),
    UnsupportedConfigPolicy(
        "cos-queue-policy",
        _cos_queue_policy,
        ("FM10000 queue profile/drop policy is not hardware-backed yet; "
         "current FM10000 support is the scheduler template/interfaces subset"),
    ),
    UnsupportedConfigPolicy(
        "cos-watermarks",
        _cos_watermarks,
        ("FM10000 public watermarks support "
         "class-of-service watermarks interface <if> traffic-class <0-7> "
         "tx-hog|tx-private <value> or class-of-service watermarks "
         "switch-priority <0-7> soft-drop|soft-drop-jitter|soft-drop-hog "
         "<value>. RX/pause watermarks and TX soft-drop enable bits remain "
         "platform controlled"),
    ),
    UnsupportedConfigPolicy(
        "cos-ecn",
        _cos_ecn,
        ("FM10000 ECN/CN policy is not hardware-backed on this platform; "
         "CN mode symbols are documented for FM3000/FM4000/FM6000 only"),
    ),
    UnsupportedConfigPolicy(
        "legacy-rate-limit",
        _legacy_rate_limit,
        "rate-limit was renamed to ingress-rate-limit",
    ),
    UnsupportedConfigPolicy(
        "ipv4-acl-policer-action",
        _ipv4_acl_policer_action,
        ("ingress-ipv4-acl action policer is not available on the Flow "
         "TCAM path; use firewall family ethernet-switching filter <filter> "
         "term <term> policer ... for the hardware-backed ACL compiler "
         "policer"),
    ),
    UnsupportedConfigPolicy(
        "legacy-acl-owner-config",
        _legacy_acl_owner_config,
        _legacy_acl_owner_config_reason,
    ),
    UnsupportedConfigPolicy(
        "independent-egress-acl",
        _independent_egress_acl,
        ("acl independent-group egress is not hardware-backed yet; use "
         "firewall family ethernet-switching filter <filter> term <term> "
         "egress ... for the scoped egress pipeline"),
    ),
    UnsupportedConfigPolicy(
        "general-acl",
        _general_acl,
        _general_acl_reason,
    ),
    UnsupportedConfigPolicy(
        "management-services",
        _management_services,
        ("management protocol services have no runtime owner; configuration "
         "is closed by the immutable public capability authority until "
         "listener read-back, rollback, replay, and operational evidence exist"),
    ),
)


def unsupported_config_policy(tokens):
    tokens = tuple(tokens or ())
    for policy in UNSUPPORTED_CONFIG_POLICIES:
        if policy.matches(tokens):
            return policy
    return None


def unsupported_config_leaf(tokens):
    policy = unsupported_config_policy(tokens)
    if not policy:
        return None
    return policy.message(tuple(tokens or ()))


def unsupported_config_delete_leaf(tokens):
    if _physical_routed_interface_delete_supported(tokens):
        return None
    policy = unsupported_config_policy(tokens)
    if not policy:
        return None
    if (policy.name == "general-acl" and
            not public_capability_enabled(GENERAL_ACL_INDEPENDENT)):
        return None
    if (policy.name == "management-services" and
            not public_capability_enabled(MANAGEMENT_SERVICES)):
        return None
    return policy.message(tuple(tokens or ()))
