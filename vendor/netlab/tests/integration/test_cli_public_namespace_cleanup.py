#!/usr/bin/env python3.11
"""Public CLI namespace checks for Junos-style facades."""

import hashlib
import os
import re
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bin", "cli"))

import cli as cli_module  # noqa: E402
import completion_dynamic  # noqa: E402
import feature_policy  # noqa: E402
import output_chassis  # noqa: E402
import session as session_module  # noqa: E402
from cli import NetLabCLI  # noqa: E402
from completion_engine import get_context_candidates  # noqa: E402
from completion_schema import CFG_SCHEMA, OP_SCHEMA  # noqa: E402
from config_paths import cli_to_delete_path, cli_to_path  # noqa: E402
from errors import format_error  # noqa: E402
from feature_policy import unsupported_config_leaf  # noqa: E402
from output_chassis import format_pfe_resources  # noqa: E402
from output_config import format_config_as_set, format_config_hierarchy  # noqa: E402
from session import (DAEMON_CHASSISD, DAEMON_CONFIGD, DAEMON_IFD,
                     DAEMON_LACPD, DAEMON_L2D, DAEMON_LLDPD, DAEMON_MGMTD,
                     DAEMON_PACKETD, DAEMON_RPD, DAEMON_STATSD, DAEMON_STPD,
                     DAEMON_SWITCHD)  # noqa: E402


class NoLiveRpcCLI(NetLabCLI):
    """CLI fixture that makes an accidental production IPC call fatal."""

    def __init__(self, responses=None):
        super().__init__()
        self.responses = dict(responses or {})
        self.rpc_calls = []

    def _rpc(self, daemon, method, payload, timeout_ms=0):
        call = (daemon, method, payload, timeout_ms)
        self.rpc_calls.append(call)
        key = (daemon, method, payload)
        if key not in self.responses:
            raise AssertionError(
                "unexpected live RPC boundary: "
                f"daemon={daemon} method={method} payload={payload!r}")
        return self.responses[key]


def words(text, mode="operational"):
    return {item["word"] for item in get_context_candidates(text, mode)}


def check(name, condition, detail=""):
    if condition:
        print(f"PASS: {name}")
        return 0
    print(f"FAIL: {name} -- {detail}")
    return 1


def visible_help_leaks(schema):
    patterns = [
        re.compile(r"\bprofile\b", re.IGNORECASE),
        re.compile(r"\bRDI\b"),
        re.compile(r"\bSDK\b"),
        re.compile(r"\bowner\b", re.IGNORECASE),
        re.compile(r"\bhidden\b", re.IGNORECASE),
    ]
    leaks = []

    def walk(node, path):
        if not isinstance(node, dict) or node.get("_hidden"):
            return
        help_text = node.get("_help") or ""
        if any(pattern.search(help_text) for pattern in patterns):
            leaks.append("%s :: %s" % (" ".join(path) or "<root>",
                                       help_text))
        for key, child in node.items():
            if key.startswith("_") or key == "<[Enter]>":
                continue
            walk(child, path + [key])

    walk(schema, [])
    return leaks


def main():
    failed = 0

    help_leaks = visible_help_leaks(OP_SCHEMA) + visible_help_leaks(CFG_SCHEMA)
    failed += check("visible completion help hides internal wording",
                    not help_leaks,
                    "\n".join(help_leaks))

    set_top = words("set ", "config")
    failed += check("public set advertises system",
                    "system" in set_top, str(set_top))
    failed += check(
        "set system host-name maps to system host-name leaf",
        cli_to_path(["system", "host-name", "leaf-1"]) == (
            "/netlab:netlab-config/system/host-name", "leaf-1"),
    )
    failed += check(
        "delete system host-name maps to system leaf",
        cli_to_delete_path(["system", "host-name"]) ==
        "/netlab:netlab-config/system/host-name",
    )
    system_words = words("set system ", "config")
    failed += check(
        "system exposes implemented management configuration facade",
        {"domain-name", "name-server", "ntp", "syslog",
         "login", "authentication-order", "radius-server",
         "tacplus-server", "accounting"}.issubset(system_words) and
        "services" not in system_words,
        str(system_words),
    )
    failed += check("public set hides SNMP without a runtime owner",
                    "snmp" not in set_top, str(set_top))
    services_words = words("set system services ", "config")
    failed += check("system services set namespace is closed",
                    not services_words, str(services_words))
    snmp_words = words("set snmp ", "config")
    failed += check("SNMP set namespace is closed",
                    not snmp_words,
                    str(snmp_words))
    failed += check(
        "system services ssh maps to management service enable",
        cli_to_path(["system", "services", "ssh"]) == (
            "/netlab:netlab-config/system/services/ssh/enable", "true"),
    )
    failed += check(
        "system services gnmi grpc maps to management service enable",
        cli_to_path(["system", "services", "gnmi", "grpc"]) == (
            "/netlab:netlab-config/system/services/gnmi/grpc", "true"),
    )
    failed += check(
        "system services gnmi port maps to port leaf",
        cli_to_path(["system", "services", "gnmi", "port", "57400"]) == (
            "/netlab:netlab-config/system/services/gnmi/port", "57400"),
    )
    failed += check(
        "snmp community authorization maps to keyed community",
        cli_to_path(["snmp", "community", "public",
                     "authorization", "read-only"]) == (
            "/netlab:netlab-config/snmp/community[name='public']"
            "/authorization", "read-only"),
    )
    failed += check(
        "snmp community clients maps to keyed client",
        cli_to_path(["snmp", "community", "public",
                     "clients", "192.0.2.0/24"]) == (
            "/netlab:netlab-config/snmp/community[name='public']"
            "/clients[address='192.0.2.0/24']/address",
            "192.0.2.0/24"),
    )
    failed += check(
        "system ntp server prefer maps to keyed server",
        cli_to_path(["system", "ntp", "server", "192.0.2.10", "prefer"]) == (
            "/netlab:netlab-config/system/ntp/server"
            "[address='192.0.2.10']/prefer", "true"),
    )
    failed += check(
        "system syslog host any maps to keyed host",
        cli_to_path(["system", "syslog", "host", "192.0.2.20",
                     "any", "notice"]) == (
            "/netlab:netlab-config/system/syslog/host"
            "[name='192.0.2.20']/any", "notice"),
    )
    failed += check(
        "system login user class maps to keyed user",
        cli_to_path(["system", "login", "user", "ops",
                     "class", "operator"]) == (
            "/netlab:netlab-config/system/login/user[name='ops']/class",
            "operator"),
    )
    failed += check(
        "system authentication-order maps to keyed method",
        cli_to_path(["system", "authentication-order", "radius"]) == (
            "/netlab:netlab-config/system/authentication-order"
            "/method[name='radius']/name", "radius"),
    )
    failed += check(
        "system radius-server secret maps to keyed server",
        cli_to_path(["system", "radius-server", "192.0.2.30",
                     "secret", "$9$radius"]) == (
            "/netlab:netlab-config/system/radius-server"
            "[address='192.0.2.30']/secret", "$9$radius"),
    )
    failed += check(
        "system tacplus-server single-connection maps to keyed server",
        cli_to_path(["system", "tacplus-server", "192.0.2.40",
                     "single-connection"]) == (
            "/netlab:netlab-config/system/tacplus-server"
            "[address='192.0.2.40']/single-connection", "true"),
    )
    failed += check(
        "system accounting events maps to keyed event",
        cli_to_path(["system", "accounting", "events",
                     "interactive-commands"]) == (
            "/netlab:netlab-config/system/accounting/events"
            "/event[name='interactive-commands']/name",
            "interactive-commands"),
    )
    failed += check(
        "delete system ntp server maps to keyed server",
        cli_to_delete_path(["system", "ntp", "server", "192.0.2.10"]) ==
        "/netlab:netlab-config/system/ntp/server[address='192.0.2.10']",
    )
    failed += check(
        "delete system radius-server leaf maps to keyed server leaf",
        cli_to_delete_path(["system", "radius-server", "192.0.2.30",
                            "source-address"]) ==
        "/netlab:netlab-config/system/radius-server"
        "[address='192.0.2.30']/source-address",
    )
    failed += check(
        "delete system accounting events maps to keyed event",
        cli_to_delete_path(["system", "accounting", "events",
                            "interactive-commands"]) ==
        "/netlab:netlab-config/system/accounting/events"
        "/event[name='interactive-commands']",
    )
    failed += check(
        "delete snmp community client maps to keyed client",
        cli_to_delete_path(["snmp", "community", "public",
                            "clients", "192.0.2.0/24"]) ==
        "/netlab:netlab-config/snmp/community[name='public']"
        "/clients[address='192.0.2.0/24']",
    )
    failed += check("public set advertises firewall facade",
                    "firewall" in set_top, str(set_top))

    esw = words("set ethernet-switching-options ", "config")
    leaked_config = {
        "user-filter", "ingress-acl", "ingress-ipv4-acl",
        "acl-policer", "egress-acl",
    }
    failed += check("public ethernet-switching-options hides direct ACL owners",
                    esw.isdisjoint(leaked_config), str(esw))
    general_acl = words("set ethernet-switching-options acl ", "config")
    failed += check("public ACL facade is closed before promotion",
                    not general_acl, str(general_acl))

    cos = words("set class-of-service ", "config")
    failed += check("public CoS hides ETS/watermark owner controls",
                    cos.isdisjoint({"ets", "watermarks"}), str(cos))
    failed += check("public CoS hides scheduler owner root",
                    "scheduler" not in cos, str(cos))
    failed += check("public CoS exposes Junos schedulers facade",
                    "schedulers" in cos, str(cos))
    cos_if = words("set class-of-service interfaces et-0/0/0 ", "config")
    failed += check("public CoS interface exposes scheduler-map facade",
                    "scheduler-map" in cos_if, str(cos_if))

    static = words("set routing-options static ", "config")
    failed += check("public static routing hides next-hop/ECMP handles",
                    "route" in static and
                    static.isdisjoint({"arp", "next-hop", "ecmp"}),
                    str(static))
    static_route = words(
        "set routing-options static route 198.51.100.0/24 ", "config")
    failed += check("public static route exposes next-hop IP facade",
                    "next-hop" in static_route and "ecmp" not in static_route,
                    str(static_route))
    policy_cli = NoLiveRpcCLI({
        (DAEMON_CONFIGD, 4, b"0"): b"rollback fixture loaded",
    })
    policy_cli.mode = "config"
    l3_internal_cases = {
        "set interfaces-routing interface vlan200 address 198.51.100.1/24":
            "direct routed-interface syntax is unsupported",
        "delete interfaces-routing interface vlan200":
            "direct routed-interface syntax is unsupported",
        "set routing-options static arp 198.51.100.2 mac 02:00:00:00:02:02":
            "direct static routing syntax is unsupported",
        "set routing-options static next-hop 1 arp 198.51.100.2":
            "direct static routing syntax is unsupported",
        "set routing-options static ecmp 10 member 1":
            "direct static routing syntax is unsupported",
        "set routing-options static route 203.0.113.0/24 ecmp 10":
            "direct static routing syntax is unsupported",
        "set routing-options static route 203.0.113.0/24 next-hop 1":
            "direct static routing syntax is unsupported",
        "delete routing-options static route 203.0.113.0/24 next-hop 1":
            "direct static routing syntax is unsupported",
    }
    for command, expected in l3_internal_cases.items():
        result = policy_cli.dispatch(command) or ""
        failed += check(
            f"{command} is blocked by public L3 facade",
            expected in result and
            "interfaces-routing" not in result and
            "next-hop-id" not in result and
            "ecmp-id" not in result and
            "internal" not in result.lower() and
            "owner" not in result.lower() and
            "sdk" not in result.lower() and
            "hidden" not in result.lower(),
            result,
        )
    old_active_profile_has_l3 = feature_policy._active_profile_has_l3
    try:
        feature_policy._active_profile_has_l3 = lambda: False
        l3_gate_result = policy_cli.dispatch(
            "set routing-options static route 203.0.113.0/24 "
            "next-hop 192.0.2.2") or ""
    finally:
        feature_policy._active_profile_has_l3 = old_active_profile_has_l3
    failed += check(
        "L3 chassis-mode rejection hides profile wording",
        "unsupported configuration" in l3_gate_result and
        "active L3 chassis mode" in l3_gate_result and
        "profile" not in l3_gate_result.lower(),
        l3_gate_result,
    )
    old_authority_token = os.environ.pop(
        "NETLAB_CONFIG_AUTHORITY_TOKEN", None)
    policy_cli._config_writable_error = lambda: None
    try:
        rollback_result = policy_cli.dispatch("rollback 0")
    finally:
        if old_authority_token is not None:
            os.environ["NETLAB_CONFIG_AUTHORITY_TOKEN"] = old_authority_token
    failed += check(
        "public rollback test stays behind the isolated RPC fixture",
        rollback_result == "rollback fixture loaded" and
        [(daemon, method, payload)
         for daemon, method, payload, _ in policy_cli.rpc_calls] == [
             (DAEMON_CONFIGD, 4, b"0"),
         ],
        str(policy_cli.rpc_calls),
    )
    irb_arp = words("set interfaces irb unit 200 family inet address "
                    "198.51.100.1/24 arp 198.51.100.2 ", "config")
    failed += check("IRB address exposes static ARP facade",
                    {"mac", "egress-interface"}.issubset(irb_arp),
                    str(irb_arp))
    failed += check(
        "IRB static ARP facade maps to compatibility static ARP leaf",
        cli_to_path(["interfaces", "irb", "unit", "200", "family", "inet",
                     "address", "198.51.100.1/24", "arp", "198.51.100.2",
                     "mac", "02:00:00:00:02:02"]) == (
            "/netlab:netlab-config/routing-options/static"
            "/arp[ip='198.51.100.2']/mac", "02:00:00:00:02:02"),
    )

    route = words("show route ")
    failed += check("public show route hides diagnostic owner views",
                    route.isdisjoint({"state", "next-hop", "ecmp",
                                      "resources", "shadow"}),
                    str(route))

    show_top = words("show ")
    failed += check("public show advertises firewall facade",
                    "firewall" in show_top, str(show_top))
    failed += check("public show advertises diagnostics namespace",
                    "diagnostics" in show_top, str(show_top))

    request_system = get_context_candidates("request system ", "operational")
    reconcile_help = " ".join(
        item.get("help", "") for item in request_system
        if item.get("word") == "reconcile")
    failed += check("request system reconcile help hides internal state",
                    "forwarding drift" in reconcile_help and
                    "HW_OUT_OF_SYNC" not in reconcile_help and
                    "owner" not in reconcile_help.lower() and
                    "sdk" not in reconcile_help.lower() and
                    "hidden" not in reconcile_help.lower(),
                    reconcile_help)
    port_mode_actions = get_context_candidates(
        "request chassis port-mode ", "operational")
    port_mode_help = " ".join(
        item.get("help", "") for item in port_mode_actions
        if item.get("word") in ("apply", "rollback"))
    failed += check("request chassis port-mode help hides RDI/profile internals",
                    "chassis port mode" in port_mode_help and
                    "RDI" not in port_mode_help and
                    "profile" not in port_mode_help.lower() and
                    "owner" not in port_mode_help.lower() and
                    "sdk" not in port_mode_help.lower(),
                    port_mode_help)

    diag_l3 = words("show diagnostics l3 ")
    failed += check("diagnostics keeps L3 owner views discoverable",
                    {"state", "next-hop", "ecmp", "resources",
                     "shadow"}.issubset(diag_l3),
                    str(diag_l3))

    diag_fwd = words("show diagnostics forwarding ")
    failed += check("diagnostics exposes public forwarding runtime view",
                    "runtime" in diag_fwd, str(diag_fwd))
    failed += check("diagnostics hides legacy SDK view",
                    "sdk" not in diag_fwd, str(diag_fwd))
    forwarding_cli = NoLiveRpcCLI({
        (DAEMON_SWITCHD, 34, b"pfe_status"): b'''{
            "status": "ok",
            "sdk_initialized": true,
            "switch_enabled": true,
            "port_inventory_ok": true,
            "port_programming_ok": true,
            "vlan_programming_ok": true,
            "pvid_programming_ok": true,
            "vlan_mode_programming_ok": true,
            "readback_verify_ok": true,
            "counters_ok": true,
            "packet_io_ok": true
        }''',
    })
    forwarding_status = forwarding_cli.dispatch(
        "show chassis forwarding") or ""
    failed += check("show chassis forwarding hides SDK wording",
                    "SDK" not in forwarding_status and
                    "sdk" not in forwarding_status and
                    "Runtime init" in forwarding_status and
                    [(daemon, method, payload)
                     for daemon, method, payload, _
                     in forwarding_cli.rpc_calls] == [
                         (DAEMON_SWITCHD, 34, b"pfe_status"),
                     ],
                    forwarding_status[:400])

    class ForwardingDriftCLI(NetLabCLI):
        def __init__(self):
            super().__init__()
            self.mode = "operational"

        def _rpc(self, daemon, method, payload, timeout_ms=0):
            if daemon == DAEMON_SWITCHD and method == 34:
                return b"""{
                    "status": "degraded",
                    "sdk_initialized": true,
                    "switch_enabled": true,
                    "port_inventory_ok": true,
                    "port_programming_ok": true,
                    "vlan_programming_ok": true,
                    "pvid_programming_ok": true,
                    "vlan_mode_programming_ok": true,
                    "readback_verify_ok": true,
                    "counters_ok": true,
                    "packet_io_ok": true,
                    "hw_out_of_sync": true
                }"""
            return b"error: unexpected rpc"

    drift_forwarding = ForwardingDriftCLI().dispatch(
        "show chassis forwarding") or ""
    failed += check("show chassis forwarding drift hides internal state",
                    "forwarding drift detected" in drift_forwarding and
                    "request system reconcile" in drift_forwarding and
                    "HW_OUT_OF_SYNC" not in drift_forwarding and
                    "sdk" not in drift_forwarding.lower() and
                    "owner" not in drift_forwarding.lower(),
                    drift_forwarding)

    resources_text = format_pfe_resources("""
    <resources status="0" source="sdk" model="FM10840"
               profile="/var/lib/netlab/platform.profile">
      <profile ports="27" switches="1" lanes="0" xcvrs="6" max-ae="8"/>
      <ffu ipv4-uc-first="0" ipv4-uc-last="3" acl-first="4" acl-last="31"/>
      <l3 routes="0" arp="0" ecmp-groups="0"/>
      <mac used="4" capacity="16384" visible="1" dynamic="1"
           static="3" internal="3" multicast="2" aging-time="60"/>
    </resources>
    """)
    resources_lower = resources_text.lower()
    failed += check("show chassis forwarding resources hides profile/internal wording",
                    "Platform mode : configured" in resources_text and
                    "Platform mode : L3 route slices enabled" in resources_text and
                    "reserved=3" in resources_text and
                    "profile" not in resources_lower and
                    "RDI" not in resources_text and
                    "/etc/rdi" not in resources_lower and
                    "platform.profile" not in resources_text and
                    "internal=" not in resources_text and
                    "sdk" not in resources_lower and
                    "owner" not in resources_lower,
                    resources_text)
    old_runtime_timeout = os.environ.get("NETLAB_CLI_RUNTIME_TIMEOUT_MS")
    os.environ["NETLAB_CLI_RUNTIME_TIMEOUT_MS"] = "321"

    class RuntimeTimeoutCLI(NetLabCLI):
        def __init__(self):
            super().__init__()
            self.mode = "operational"
            self.calls = []

        def _rpc(self, daemon, method, payload, timeout_ms=0):
            self.calls.append((daemon, method, payload, timeout_ms))
            return b"error: SDK owner hidden request timed out"

        def _resolve_vlan_id(self, value):
            if value == "100":
                return 100
            return super()._resolve_vlan_id(value)

    try:
        runtime_timeout_cli = RuntimeTimeoutCLI()
        runtime_forwarding = runtime_timeout_cli.dispatch(
            "show chassis forwarding")
        runtime_copp = runtime_timeout_cli.dispatch(
            "show control-plane protection")
        runtime_view_outputs = {
            command: runtime_timeout_cli.dispatch(command) or ""
            for command in (
                "show interfaces terse",
                "show interfaces detail",
                "show interfaces extensive",
                "show interfaces statistics",
                "show interfaces et-0/0/0 detail",
                "show interfaces et-0/0/0 extensive",
                "show interfaces et-0/0/0 statistics",
                "show vlans",
                "show firewall",
                "show firewall family ethernet-switching",
                "show firewall family inet",
                "show ethernet-switching",
                "show ethernet-switching interfaces",
                "show ethernet-switching table",
                "show ethernet-switching mac-move",
                "show ethernet-switching secure-access-port",
                "show ethernet-switching dhcp-snooping",
                "show ethernet-switching arp-inspection",
                "show ethernet-switching acl",
                "show ethernet-switching storm-control",
                "show ethernet-switching ingress-rate-limit",
                "show ethernet-switching egress-rate-limit",
                "show class-of-service",
                "show class-of-service interfaces",
                "show class-of-service forwarding",
                "show class-of-service flow-control",
                "show class-of-service scheduler",
                "show diagnostics forwarding runtime",
                "show system management",
                "show chassis forwarding resources",
                "show diagnostics forwarding config",
                "show chassis hardware",
                "show chassis environment",
                "show lldp interfaces",
                "show lldp local-information",
                "show lldp neighbors",
                "show lldp neighbors detail",
                "show lldp statistics",
                "show lacp interfaces",
                "show spanning-tree",
                "show spanning-tree bridge",
                "show spanning-tree statistics",
                "show spanning-tree interface et-0/0/0",
                "show route",
                "show route protocol static",
                "show route forwarding-table",
                "show route summary",
                "show arp",
                "show rpd state",
                "show ospf neighbor",
                "show bgp summary",
            )
        }
        show_call_count = len(runtime_timeout_cli.calls)
        clear_action_outputs = {
            command: runtime_timeout_cli.dispatch(command) or ""
            for command in (
                "clear interfaces statistics",
                "clear interfaces statistics et-0/0/0",
                "clear ethernet-switching table",
                "clear ethernet-switching table vlan 100",
                "clear ethernet-switching table interface et-0/0/0",
                "clear ethernet-switching table vlan 100 interface et-0/0/0",
                "clear ethernet-switching mac-move",
                "clear ethernet-switching mac-move interface et-0/0/0",
                "clear ethernet-switching secure-access-port interface et-0/0/0",
                "clear spanning-tree bpdu-guard interface et-0/0/0",
            )
        }
        clear_action_calls = runtime_timeout_cli.calls[show_call_count:]
    finally:
        if old_runtime_timeout is None:
            os.environ.pop("NETLAB_CLI_RUNTIME_TIMEOUT_MS", None)
        else:
            os.environ["NETLAB_CLI_RUNTIME_TIMEOUT_MS"] = old_runtime_timeout

    failed += check("public runtime show uses bounded RPC timeout",
                    runtime_timeout_cli.calls and
                    all(call[3] == 321 for call in runtime_timeout_cli.calls),
                    str(runtime_timeout_cli.calls))
    failed += check("public runtime show wraps timeout as unavailable",
                    "PFE capability status:" in runtime_forwarding and
                    "Runtime init   : unavailable" in runtime_forwarding and
                    "Control-plane protection: unavailable" in runtime_copp and
                    "Source : forwarding-plane" in runtime_copp and
                    "SDK" not in runtime_forwarding + runtime_copp and
                    "sdk" not in runtime_forwarding + runtime_copp and
                    "profile" not in (runtime_forwarding + runtime_copp).lower() and
                    "RDI" not in runtime_forwarding + runtime_copp and
                    "platform.profile" not in runtime_forwarding + runtime_copp and
                    "/etc/rdi" not in (runtime_forwarding + runtime_copp).lower() and
                    "owner" not in runtime_copp.lower(),
                    runtime_forwarding + "\n---\n" + runtime_copp)
    runtime_public_calls = [
        call for call in runtime_timeout_cli.calls
        if call[0] in (DAEMON_CHASSISD, DAEMON_IFD, DAEMON_LACPD,
                       DAEMON_L2D, DAEMON_LLDPD, DAEMON_MGMTD,
                       DAEMON_RPD, DAEMON_STATSD, DAEMON_STPD,
                       DAEMON_SWITCHD)
    ]
    failed += check("public L2/L3/CoS show uses bounded runtime timeout",
                    runtime_public_calls and
                    all(call[3] == 321 for call in runtime_public_calls),
                    str(runtime_timeout_cli.calls))
    failed += check("public L2/L3/CoS show wraps runtime timeout",
                    runtime_view_outputs and
                    all("unavailable" in output and
                        "request timed out" in output
                        for output in runtime_view_outputs.values()),
                    "\n---\n".join(
                        f"{cmd}\n{text}" for cmd, text
                        in runtime_view_outputs.items()))
    failed += check("public L2/L3/CoS timeout output hides owner/SDK",
                    all("sdk" not in output.lower() and
                        "owner" not in output.lower() and
                        "hidden" not in output.lower()
                        for output in runtime_view_outputs.values()),
                    "\n---\n".join(runtime_view_outputs.values()))
    failed += check("public clear uses bounded runtime timeout",
                    clear_action_calls and
                    all(call[3] == 321 for call in clear_action_calls),
                    str(clear_action_calls))
    failed += check("public clear wraps runtime timeout as failed action",
                    clear_action_outputs and
                    all("failed" in output and
                        "request timed out" in output
                        for output in clear_action_outputs.values()),
                    "\n---\n".join(
                        f"{cmd}\n{text}" for cmd, text
                        in clear_action_outputs.items()))
    failed += check("public clear timeout output hides owner/SDK",
                    all("sdk" not in output.lower() and
                        "owner" not in output.lower() and
                        "hidden" not in output.lower()
                        for output in clear_action_outputs.values()),
                    "\n---\n".join(clear_action_outputs.values()))
    for code in (2003, 2004, 2005):
        formatted_error = format_error(code)
        failed += check(f"public PFE error {code} hides SDK wording",
                        "SDK" not in formatted_error and
                        "sdk" not in formatted_error and
                        "forwarding runtime" in formatted_error,
                        formatted_error)
    copp_cli = NoLiveRpcCLI({
        (DAEMON_SWITCHD, 65, b""): (
            b'<control-plane-protection status="0" source="ies-sdk" '
            b'table="0" capacity="0" free="0" policers="0"/>'),
        (DAEMON_PACKETD, 1, b""): b'<packetd-stats/>',
    })
    copp_status = copp_cli.dispatch("show control-plane protection") or ""
    failed += check("show control-plane protection hides owner/SDK wording",
                    "SDK" not in copp_status and
                    "sdk" not in copp_status and
                    "owner" not in copp_status.lower() and
                    "Source : forwarding-plane" in copp_status and
                    [(daemon, method, payload)
                     for daemon, method, payload, _ in copp_cli.rpc_calls] == [
                         (DAEMON_SWITCHD, 65, b""),
                         (DAEMON_PACKETD, 1, b""),
                     ],
                    copp_status[:400])

    cli = NoLiveRpcCLI()
    redirected = {
        "show route state": "show diagnostics l3 state",
        "show route next-hop": "show diagnostics l3 next-hop",
        "show route ecmp": "show diagnostics l3 ecmp",
        "show route resources": "show diagnostics l3 resources",
        "show route shadow": "show diagnostics l3 shadow",
        "show ethernet-switching acl-capabilities": (
            "show diagnostics ethernet-switching acl-capabilities"),
        "show ethernet-switching user-filter": (
            "show diagnostics ethernet-switching user-filter"),
        "show ethernet-switching ingress-acl": (
            "show diagnostics ethernet-switching ingress-acl"),
        "show ethernet-switching ingress-ipv4-acl": (
            "show diagnostics ethernet-switching ingress-ipv4-acl"),
        "show ethernet-switching acl-policer": (
            "show diagnostics ethernet-switching acl-policer"),
        "show ethernet-switching egress-acl": (
            "show diagnostics ethernet-switching egress-acl"),
        "show class-of-service queues": (
            "show diagnostics class-of-service queues"),
        "show class-of-service watermarks": (
            "show diagnostics class-of-service watermarks"),
        "show class-of-service ets": (
            "show diagnostics class-of-service ets"),
        "show chassis forwarding config": (
            "show diagnostics forwarding config"),
        "show chassis forwarding sdk": (
            "show diagnostics forwarding runtime"),
        "show diagnostics forwarding sdk": (
            "show diagnostics forwarding runtime"),
    }
    for old, new in redirected.items():
        result = cli.dispatch(old) or ""
        failed += check(f"{old} redirects to diagnostics",
                        result.startswith("error: use ") and new in result,
                        result)
        if " sdk" in old:
            failed += check(f"{old} redirect hides legacy runtime wording",
                            "sdk" not in result.lower(),
                            result)
    route_rejects = {
        "show route summary detail":
            "unknown route summary target",
        "show route interfaces detail":
            "unknown route interfaces target",
        "show route forwarding-table detail":
            "unknown route forwarding-table target",
        "show route protocol connected detail":
            "unknown route protocol connected target",
        "show route state detail":
            "unknown route state target",
        "show route next-hop detail":
            "unknown route next-hop target",
        "show diagnostics l3 state detail":
            "unknown diagnostics l3 state target",
        "show diagnostics l3 interfaces detail":
            "unknown diagnostics l3 interfaces target",
        "show diagnostics l3 next-hop detail":
            "unknown diagnostics l3 next-hop target",
        "show diagnostics l3 ecmp detail":
            "unknown diagnostics l3 ecmp target",
        "show diagnostics l3 resources detail":
            "unknown diagnostics l3 resources target",
        "show diagnostics l3 shadow detail":
            "unknown diagnostics l3 shadow target",
        "show rpd state detail":
            "unknown rpd state target",
    }
    for command, expected in route_rejects.items():
        result = cli.dispatch(command) or ""
        failed += check(f"{command} rejects unknown suffix",
                        expected in result, result)
    ethernet_rejects = {
        "show ethernet-switching interfaces detail":
            "unknown ethernet-switching interfaces target",
        "show ethernet-switching table detail":
            "unknown ethernet-switching table target",
        "show ethernet-switching mac-move detail":
            "unknown ethernet-switching mac-move target",
        "show ethernet-switching secure-access-port detail":
            "unknown ethernet-switching secure-access-port target",
        "show ethernet-switching dhcp-snooping detail":
            "unknown ethernet-switching dhcp-snooping target",
        "show ethernet-switching arp-inspection detail":
            "unknown ethernet-switching arp-inspection target",
        "show ethernet-switching storm-control detail":
            "unknown ethernet-switching storm-control target",
        "show ethernet-switching ingress-rate-limit detail":
            "unknown ethernet-switching ingress-rate-limit target",
        "show ethernet-switching egress-rate-limit detail":
            "unknown ethernet-switching egress-rate-limit target",
        "show ethernet-switching acl detail":
            "unknown ethernet-switching acl target",
        "show ethernet-switching user-filter detail":
            "unknown ethernet-switching user-filter target",
        "show diagnostics ethernet-switching user-filter detail":
            "unknown diagnostics ethernet-switching user-filter target",
    }
    for command, expected in ethernet_rejects.items():
        result = cli.dispatch(command) or ""
        failed += check(f"{command} rejects unknown suffix",
                        expected in result, result)
    cos_rejects = {
        "show class-of-service interfaces detail":
            "unknown class-of-service interfaces target",
        "show class-of-service forwarding detail":
            "unknown class-of-service forwarding target",
        "show class-of-service flow-control detail":
            "unknown class-of-service flow-control target",
        "show class-of-service scheduler detail":
            "unknown class-of-service scheduler target",
        "show class-of-service capabilities detail":
            "unknown class-of-service capabilities target",
        "show class-of-service queues detail":
            "unknown class-of-service queues target",
        "show diagnostics class-of-service queues detail":
            "unknown diagnostics class-of-service queues target",
        "show diagnostics class-of-service watermarks detail":
            "unknown diagnostics class-of-service watermarks target",
        "show diagnostics class-of-service ets detail":
            "unknown diagnostics class-of-service ets target",
        "show diagnostics class-of-service capabilities detail":
            "unknown diagnostics class-of-service capabilities target",
    }
    for command, expected in cos_rejects.items():
        result = cli.dispatch(command) or ""
        failed += check(f"{command} rejects unknown suffix",
                        expected in result, result)
    cos_watermark_reject = unsupported_config_leaf([
        "class-of-service", "watermarks", "interface", "et-0/0/0",
        "traffic-class", "0", "rx-hog", "1024",
    ]) or ""
    failed += check("CoS watermark rejection hides profile wording",
                    "profile controlled" not in cos_watermark_reject and
                    "platform controlled" in cos_watermark_reject,
                    cos_watermark_reject)
    public_cos = cli.dispatch("show class-of-service capabilities") or ""
    failed += check("public CoS capabilities hide method-level gates",
                    "methods 95/96/97" not in public_cos and
                    "hidden transaction" not in public_cos and
                    "profile controlled" not in public_cos and
                    "platform controlled" in public_cos and
                    "implementation probes live under diagnostics"
                    in public_cos,
                    public_cos)
    diag_cos = cli.dispatch(
        "show diagnostics class-of-service capabilities") or ""
    failed += check("diagnostic CoS capabilities keep method-level gates",
                    "methods 95/96/97" in diag_cos and
                    "QoS queue transaction" in diag_cos and
                    "diagnostic transaction" in diag_cos and
                    "hidden transaction" not in diag_cos,
                    diag_cos)

    fw_family = words("set firewall family ", "config")
    failed += check("firewall facade exposes supported families",
                    {"ethernet-switching", "inet"}.issubset(fw_family),
                    str(fw_family))

    failed += check(
        "firewall ethernet-switching source maps to ingress ACL",
        cli_to_path([
            "firewall", "family", "ethernet-switching", "filter", "EDGE",
            "term", "block", "from", "destination-mac",
            "02:00:00:00:00:01",
        ]) == (
            "/netlab:netlab-config/ethernet-switching-options"
            "/ingress-acl/term[name='EDGE.block']/destination-mac",
            "02:00:00:00:00:01",
        ),
    )

    failed += check(
        "firewall inet prefix maps to ingress IPv4 ACL",
        cli_to_path([
            "firewall", "family", "inet", "filter", "EDGE",
            "term", "web", "from", "destination-address",
            "203.0.113.0/24",
        ]) == (
            "/netlab:netlab-config/ethernet-switching-options"
            "/ingress-ipv4-acl/term[name='EDGE.web']/destination-prefix",
            "203.0.113.0/24",
        ),
    )

    failed += check(
        "firewall then discard maps to drop action",
        cli_to_path([
            "firewall", "family", "inet", "filter", "EDGE",
            "term", "web", "then", "discard",
        ]) == (
            "/netlab:netlab-config/ethernet-switching-options"
            "/ingress-ipv4-acl/term[name='EDGE.web']/action",
            "drop",
        ),
    )
    failed += check(
        "CoS scheduler facade transmit-rate maps to template group rate",
        cli_to_path([
            "class-of-service", "schedulers", "WAN", "transmit-rate",
            "1000000000",
        ]) == (
            "/netlab:netlab-config/class-of-service"
            "/scheduler/template[name='WAN']/group[id='0']/rate-bps",
            "1000000000",
        ),
    )
    failed += check(
        "CoS scheduler facade priority maps to strict-priority",
        cli_to_path([
            "class-of-service", "schedulers", "WAN", "priority",
            "strict-high",
        ]) == (
            "/netlab:netlab-config/class-of-service"
            "/scheduler/template[name='WAN']/group[id='0']/strict-priority",
            "true",
        ),
    )
    failed += check(
        "CoS interface scheduler-map maps to scheduler template attach",
        cli_to_path([
            "class-of-service", "interfaces", "et-0/0/0",
            "scheduler-map", "WAN",
        ]) == (
            "/netlab:netlab-config/class-of-service"
            "/scheduler/interfaces/interface[name='et-0/0/0']/template",
            "WAN",
        ),
    )
    failed += check(
        "delete CoS scheduler facade maps to template leaf",
        cli_to_delete_path([
            "class-of-service", "schedulers", "WAN", "transmit-rate",
        ]) == (
            "/netlab:netlab-config/class-of-service"
            "/scheduler/template[name='WAN']/group[id='0']/rate-bps"
        ),
    )

    failed += check(
        "delete firewall term maps to owner term delete",
        cli_to_delete_path([
            "firewall", "family", "inet", "filter", "EDGE",
            "term", "web",
        ]) == (
            "/netlab:netlab-config/ethernet-switching-options"
            "/ingress-ipv4-acl/term[name='EDGE.web']"
        ),
    )

    failed += check(
        "supported firewall facade is not policy-blocked",
        unsupported_config_leaf([
            "firewall", "family", "inet", "filter", "EDGE",
            "term", "web", "then", "discard",
        ]) is None,
    )
    failed += check(
        "PBR firewall action remains blocked",
        unsupported_config_leaf([
            "firewall", "family", "inet", "filter", "PBR",
            "term", "t", "then", "routing-instance", "blue",
        ]) is not None,
    )
    result = unsupported_config_leaf([
        "ethernet-switching-options", "acl", "term", "block-any",
        "action", "drop",
    ]) or ""
    failed += check(
        "general ACL rejection names the closed promotion authority",
        "independent General ACL is closed" in result,
        result)
    result = unsupported_config_leaf([
        "ethernet-switching-options", "egress-filter", "term",
        "block-any", "action", "drop",
    ]) or ""
    failed += check(
        "legacy egress filter rejection points to firewall facade",
        "firewall family" in result and
        "ingress-acl" not in result and
        "ingress-ipv4-acl" not in result and
        "acl-policer" not in result and
        "egress-acl" not in result,
        result)
    legacy_owner_cases = {
        "user-filter": [
            "ethernet-switching-options", "user-filter", "term",
            "block", "source-mac", "02:00:00:00:aa:01",
        ],
        "ingress-acl": [
            "ethernet-switching-options", "ingress-acl", "term",
            "block", "source-mac", "02:00:00:00:cc:01",
        ],
        "ingress-ipv4-acl": [
            "ethernet-switching-options", "ingress-ipv4-acl", "term",
            "web", "destination-ip", "203.0.113.10",
        ],
        "acl-policer": [
            "ethernet-switching-options", "acl-policer", "term",
            "police", "bandwidth", "1000",
        ],
        "egress-acl": [
            "ethernet-switching-options", "egress-acl", "term",
            "egress", "action", "drop",
        ],
    }
    for root, tokens in legacy_owner_cases.items():
        result = unsupported_config_leaf(tokens) or ""
        failed += check(f"legacy {root} config root is blocked",
                        "unsupported legacy syntax" in result and
                        "firewall family" in result and
                        "internal" not in result.lower() and
                        "owner" not in result.lower(),
                        result)
    ipv4_policer_result = unsupported_config_leaf([
        "ethernet-switching-options", "ingress-ipv4-acl", "term", "web",
        "policer", "limit1m",
    ]) or ""
    failed += check(
        "ingress IPv4 ACL policer action rejection is public-safe",
        "action policer is not available" in ipv4_policer_result and
        "firewall family ethernet-switching" in ipv4_policer_result and
        "internal" not in ipv4_policer_result.lower() and
        "owner" not in ipv4_policer_result.lower(),
        ipv4_policer_result)
    failed += check(
        "firewall policer facade is not policy-blocked",
        unsupported_config_leaf([
            "firewall", "family", "ethernet-switching", "filter", "EDGE",
            "term", "police", "policer", "then", "bandwidth", "1000",
        ]) is None,
    )
    failed += check(
        "firewall egress facade is not policy-blocked",
        unsupported_config_leaf([
            "firewall", "family", "ethernet-switching", "filter", "EDGE",
            "term", "egress", "egress", "then", "discard",
        ]) is None,
    )

    xml = """
    <netlab-config>
      <system>
        <host-name>leaf-1</host-name>
        <domain-name>example.net</domain-name>
        <name-server>
          <address>192.0.2.53</address>
        </name-server>
        <authentication-order>
          <method>
            <name>radius</name>
          </method>
          <method>
            <name>password</name>
          </method>
        </authentication-order>
        <radius-server>
          <address>192.0.2.30</address>
          <secret>$9$radius</secret>
          <port>1812</port>
          <source-address>192.0.2.1</source-address>
          <timeout>3</timeout>
          <retry>2</retry>
        </radius-server>
        <tacplus-server>
          <address>192.0.2.40</address>
          <secret>$9$tacplus</secret>
          <port>49</port>
          <source-address>192.0.2.1</source-address>
          <timeout>5</timeout>
          <single-connection>true</single-connection>
        </tacplus-server>
        <services>
          <ssh>
            <enable>true</enable>
            <root-login>deny-password</root-login>
          </ssh>
          <netconf>
            <ssh>true</ssh>
          </netconf>
          <restconf>
            <https>true</https>
          </restconf>
          <gnmi>
            <grpc>true</grpc>
            <port>57400</port>
          </gnmi>
        </services>
        <ntp>
          <server>
            <address>192.0.2.10</address>
            <prefer>true</prefer>
          </server>
        </ntp>
        <syslog>
          <host>
            <name>192.0.2.20</name>
            <any>notice</any>
          </host>
          <file>
            <name>messages</name>
            <any>info</any>
          </file>
        </syslog>
        <login>
          <user>
            <name>ops</name>
            <class>operator</class>
            <authentication>
              <encrypted-password>$6$hash</encrypted-password>
              <ssh-rsa>ssh-rsa AAAATEST</ssh-rsa>
            </authentication>
          </user>
        </login>
        <accounting>
          <events>
            <event>
              <name>login</name>
            </event>
            <event>
              <name>change-log</name>
            </event>
            <event>
              <name>interactive-commands</name>
            </event>
          </events>
        </accounting>
      </system>
      <snmp>
        <contact>NOC Team</contact>
        <location>DC1 Row 7</location>
        <community>
          <name>public</name>
          <authorization>read-only</authorization>
          <clients>
            <address>192.0.2.0/24</address>
          </clients>
        </community>
        <trap-group>
          <name>noc</name>
          <version>v2</version>
          <targets>
            <address>192.0.2.200</address>
          </targets>
        </trap-group>
      </snmp>
      <interfaces-routing>
        <interface>
          <name>vlan200</name>
          <vlan>200</vlan>
          <address>198.51.100.1/24</address>
        </interface>
      </interfaces-routing>
      <ethernet-switching-options>
        <ingress-acl>
          <term>
            <name>EDGE.block</name>
            <destination-mac>02:00:00:00:00:01</destination-mac>
            <action>drop</action>
          </term>
        </ingress-acl>
	        <ingress-ipv4-acl>
	          <term>
	            <name>EDGE.web</name>
	            <destination-prefix>203.0.113.0/24</destination-prefix>
	            <action>drop</action>
	          </term>
	        </ingress-ipv4-acl>
	        <acl-policer>
	          <term>
	            <name>EDGE.police</name>
	            <interface>et-0/0/0</interface>
	            <destination-mac>02:00:00:00:00:02</destination-mac>
	            <bandwidth>1000</bandwidth>
	            <burst-size>65536</burst-size>
	          </term>
	        </acl-policer>
	        <egress-acl>
	          <term>
	            <name>EDGE.out</name>
	            <interface>et-0/0/1</interface>
	            <source-mac>02:00:00:00:00:03</source-mac>
	            <action>drop</action>
	          </term>
	        </egress-acl>
	      </ethernet-switching-options>
      <routing-options>
        <static>
          <arp>
            <ip>198.51.100.2</ip>
            <mac>02:00:00:00:02:02</mac>
            <interface>vlan200</interface>
            <egress-interface>et-0/0/1</egress-interface>
          </arp>
          <arp>
            <ip>198.51.100.3</ip>
            <mac>02:00:00:00:02:03</mac>
            <interface>vlan200</interface>
            <egress-interface>et-0/0/2</egress-interface>
          </arp>
          <next-hop>
            <id>1</id>
            <arp-ip>198.51.100.2</arp-ip>
            <interface>vlan200</interface>
          </next-hop>
          <next-hop>
            <id>2</id>
            <arp-ip>198.51.100.3</arp-ip>
            <interface>vlan200</interface>
          </next-hop>
          <ecmp>
            <id>10</id>
            <member>1</member>
            <member>2</member>
          </ecmp>
          <route>
            <prefix>203.0.113.0/24</prefix>
            <ecmp-id>10</ecmp-id>
          </route>
        </static>
      </routing-options>
      <class-of-service>
        <scheduler>
          <template>
            <name>WAN</name>
            <group>
              <id>0</id>
              <strict-priority>true</strict-priority>
              <rate-bps>1000000000</rate-bps>
              <burst-bits>1048576</burst-bits>
            </group>
          </template>
          <interfaces>
            <interface>
              <name>et-0/0/0</name>
              <template>WAN</template>
            </interface>
          </interfaces>
        </scheduler>
      </class-of-service>
    </netlab-config>
    """
    text = format_config_as_set(xml)
    hierarchy = format_config_hierarchy(xml)
    failed += check("display set emits system host-name",
                    "set system host-name leaf-1" in text,
                    text)
    failed += check("display set emits system management facade",
                    "set system domain-name example.net" in text and
                    "set system name-server 192.0.2.53" in text and
                    "set system authentication-order radius" in text and
                    "set system authentication-order password" in text and
                    "set system radius-server 192.0.2.30" in text and
                    "set system radius-server 192.0.2.30 secret $9$radius"
                    in text and
                    "set system radius-server 192.0.2.30 "
                    "source-address 192.0.2.1" in text and
                    "set system radius-server 192.0.2.30 retry 2" in text and
                    "set system tacplus-server 192.0.2.40" in text and
                    "set system tacplus-server 192.0.2.40 "
                    "single-connection" in text and
                    "set system services ssh" in text and
                    "set system services ssh root-login deny-password" in text and
                    "set system services netconf ssh" in text and
                    "set system services restconf https" in text and
                    "set system services gnmi grpc" in text and
                    "set system services gnmi port 57400" in text and
                    "set system ntp server 192.0.2.10 prefer" in text and
                    "set system syslog host 192.0.2.20 any notice" in text and
                    "set system syslog file messages any info" in text and
                    "set system login user ops class operator" in text and
                    "set system login user ops authentication "
                    "encrypted-password $6$hash" in text and
                    "set system login user ops authentication ssh-rsa "
                    "ssh-rsa AAAATEST" in text and
                    "set system accounting events login" in text and
                    "set system accounting events change-log" in text and
                    "set system accounting events interactive-commands"
                    in text,
                    text)
    failed += check("hierarchy renders system management facade",
                    "system {" in hierarchy and
                    "host-name leaf-1;" in hierarchy and
                    "domain-name example.net;" in hierarchy and
                    "name-server 192.0.2.53;" in hierarchy and
                    "authentication-order [ radius password ];" in hierarchy and
                    "radius-server 192.0.2.30 {" in hierarchy and
                    "source-address 192.0.2.1;" in hierarchy and
                    "retry 2;" in hierarchy and
                    "tacplus-server 192.0.2.40 {" in hierarchy and
                    "single-connection;" in hierarchy and
                    "services {" in hierarchy and
                    "root-login deny-password;" in hierarchy and
                    "netconf {" in hierarchy and
                    "restconf {" in hierarchy and
                    "gnmi {" in hierarchy and
                    "port 57400;" in hierarchy and
                    "ntp {" in hierarchy and
                    "server 192.0.2.10 {" in hierarchy and
                    "syslog {" in hierarchy and
                    "host 192.0.2.20 {" in hierarchy and
                    "login {" in hierarchy and
                    "user ops {" in hierarchy and
                    "accounting {" in hierarchy and
                    "events [ login change-log interactive-commands ];"
                    in hierarchy,
                    hierarchy)
    failed += check("display set emits snmp facade",
                    "set snmp contact NOC Team" in text and
                    "set snmp location DC1 Row 7" in text and
                    "set snmp community public authorization read-only" in text and
                    "set snmp community public clients 192.0.2.0/24" in text and
                    "set snmp trap-group noc version v2" in text and
                    "set snmp trap-group noc targets 192.0.2.200" in text,
                    text)
    failed += check("hierarchy renders snmp management facade",
                    "snmp {" in hierarchy and
                    "contact NOC Team;" in hierarchy and
                    "location DC1 Row 7;" in hierarchy and
                    "community public {" in hierarchy and
                    "authorization read-only;" in hierarchy and
                    "clients 192.0.2.0/24;" in hierarchy and
                    "trap-group noc {" in hierarchy and
                    "targets 192.0.2.200;" in hierarchy,
                    hierarchy)
    failed += check(
        "display set emits ethernet-switching firewall facade",
        "set firewall family ethernet-switching filter EDGE term block "
        "from destination-mac 02:00:00:00:00:01" in text and
        "set firewall family ethernet-switching filter EDGE term block "
        "then discard" in text,
        text,
    )
    failed += check(
        "display set emits inet firewall facade",
        "set firewall family inet filter EDGE term web "
        "from destination-address 203.0.113.0/24" in text and
        "set firewall family inet filter EDGE term web then discard" in text,
        text,
    )
    failed += check(
        "hierarchy emits firewall filter facade",
        "firewall {" in hierarchy and
        "family {" in hierarchy and
        "ethernet-switching {" in hierarchy and
        "filter EDGE {" in hierarchy and
        "term block {" in hierarchy and
        "destination-mac 02:00:00:00:00:01;" in hierarchy and
        "then discard;" in hierarchy and
        "inet {" in hierarchy and
        "term web {" in hierarchy and
        "destination-address 203.0.113.0/24;" in hierarchy,
        hierarchy,
    )
    failed += check("display set hides ingress ACL owner paths",
                    "ingress-acl" not in text and
                    "ingress-ipv4-acl" not in text,
                    text)
    failed += check("hierarchy hides ingress ACL owner paths",
                    "ingress-acl" not in hierarchy and
                    "ingress-ipv4-acl" not in hierarchy,
                    hierarchy)
    failed += check(
        "display set emits firewall policer and egress facade",
        "set firewall family ethernet-switching filter EDGE term police "
        "policer from destination-mac 02:00:00:00:00:02" in text and
        "set firewall family ethernet-switching filter EDGE term police "
        "policer then bandwidth 1000" in text and
        "set firewall family ethernet-switching filter EDGE term out "
        "egress from source-mac 02:00:00:00:00:03" in text and
        "set firewall family ethernet-switching filter EDGE term out "
        "egress then discard" in text,
        text,
    )
    failed += check("display set hides ACL compiler aliases",
                    "ethernet-switching-options acl group EDGE term police"
                    not in text and
                    "ethernet-switching-options acl group EDGE term out"
                    not in text,
                    text)
    failed += check("display set hides ACL policer/egress owner paths",
                    "acl-policer" not in text and
                    "egress-acl" not in text,
                    text)
    failed += check(
        "hierarchy emits firewall policer and egress facade",
        "firewall {" in hierarchy and
        "filter EDGE {" in hierarchy and
        "term police {" in hierarchy and
        "policer {" in hierarchy and
        "from {" in hierarchy and
        "destination-mac 02:00:00:00:00:02;" in hierarchy and
        "then {" in hierarchy and
        "bandwidth 1000;" in hierarchy and
        "term out {" in hierarchy and
        "egress {" in hierarchy and
        "source-mac 02:00:00:00:00:03;" in hierarchy and
        "then discard;" in hierarchy,
        hierarchy,
    )
    failed += check("hierarchy hides ACL compiler alias block",
                    "term EDGE.police {" not in hierarchy and
                    "term EDGE.out {" not in hierarchy,
                    hierarchy)
    failed += check("hierarchy hides ACL policer/egress owner paths",
                    "acl-policer" not in hierarchy and
                    "egress-acl" not in hierarchy,
                    hierarchy)
    failed += check(
        "display set emits IRB static ARP facade",
        "set interfaces irb unit 200 family inet address "
        "198.51.100.1/24 arp 198.51.100.2 mac 02:00:00:00:02:02"
        in text and
        "set interfaces irb unit 200 family inet address "
        "198.51.100.1/24 arp 198.51.100.2 egress-interface et-0/0/1"
        in text and
        "set interfaces irb unit 200 family inet address "
        "198.51.100.1/24 arp 198.51.100.3 mac 02:00:00:00:02:03"
        in text,
        text,
    )
    failed += check(
        "display set hides static ARP/next-hop/ECMP handles",
        "set routing-options static route 203.0.113.0/24 "
        "next-hop 198.51.100.2" in text and
        "set routing-options static route 203.0.113.0/24 "
        "next-hop 198.51.100.3" in text and
        "routing-options static arp" not in text and
        "routing-options static next-hop 1" not in text and
        "routing-options static ecmp 10" not in text and
        "routing-options static route 203.0.113.0/24 ecmp 10" not in text,
        text,
    )
    failed += check(
        "hierarchy emits IRB static ARP facade",
        "address 198.51.100.1/24 {" in hierarchy and
        "arp 198.51.100.2 {" in hierarchy and
        "mac 02:00:00:00:02:02;" in hierarchy and
        "egress-interface et-0/0/1;" in hierarchy,
        hierarchy,
    )
    failed += check(
        "hierarchy hides static ARP/next-hop and ECMP handles",
        "route 203.0.113.0/24 {" in hierarchy and
        "next-hop 198.51.100.2;" in hierarchy and
        "next-hop 198.51.100.3;" in hierarchy and
        "\n        arp 198.51.100.2 {" not in hierarchy and
        "\n        next-hop 1 {" not in hierarchy and
        "\n        ecmp 10 {" not in hierarchy and
        "ecmp 10;" not in hierarchy,
        hierarchy,
    )

    class CompareCLI(NetLabCLI):
        def __init__(self):
            super().__init__()
            self.mode = "config"

        def _get_config_xml(self, active):
            return "<netlab-config/>" if active else xml

    compare_text = CompareCLI().dispatch("show | compare") or ""
    failed += check(
        "show compare emits public IRB/static route facade",
        "[edit interfaces irb unit 200 family inet]" in compare_text and
        "+   address 198.51.100.1/24;" in compare_text and
        "[edit interfaces irb unit 200 family inet address "
        "198.51.100.1/24 arp 198.51.100.2]" in compare_text and
        "+   mac 02:00:00:00:02:02;" in compare_text and
        "+   egress-interface et-0/0/1;" in compare_text and
        "[edit routing-options static route 203.0.113.0/24]" in
        compare_text and
        "+   next-hop 198.51.100.2;" in compare_text and
        "+   next-hop 198.51.100.3;" in compare_text,
        compare_text,
    )
    failed += check(
        "show compare hides internal L3 owner paths",
        "interfaces-routing" not in compare_text and
        "routing-options static arp" not in compare_text and
        "routing-options static next-hop" not in compare_text and
        "routing-options static ecmp" not in compare_text and
        "ecmp-id" not in compare_text and
        "next-hop-id" not in compare_text,
        compare_text,
    )
    failed += check(
        "display set emits CoS scheduler facade",
        "set class-of-service schedulers WAN priority strict-high" in text and
        "set class-of-service schedulers WAN transmit-rate 1000000000"
        in text and
        "set class-of-service schedulers WAN buffer-size 1048576" in text and
        "set class-of-service interfaces et-0/0/0 scheduler-map WAN" in text,
        text,
    )
    failed += check("display set hides simple scheduler owner path",
                    "class-of-service scheduler template WAN" not in text and
                    "class-of-service scheduler interfaces et-0/0/0"
                    not in text,
                    text)
    failed += check(
        "hierarchy emits CoS scheduler facade",
        "schedulers {" in hierarchy and
        "WAN {" in hierarchy and
        "priority strict-high;" in hierarchy and
        "transmit-rate 1000000000;" in hierarchy and
        "buffer-size 1048576;" in hierarchy and
        "scheduler-map WAN;" in hierarchy,
        hierarchy,
    )
    failed += check(
        "hierarchy hides simple scheduler owner path",
        "\n    scheduler {" not in hierarchy and
        "template WAN" not in hierarchy,
        hierarchy,
    )

    cfg_top = words("", "config")
    failed += check("config top-level advertises save",
                    "save" in cfg_top, str(cfg_top))
    failed += check("config top-level advertises load",
                    "load" in cfg_top, str(cfg_top))
    failed += check("load completion exposes display-set loaders",
                    words("load ", "config") == {
                        "factory-default", "merge", "override",
                        "set"},
                    str(words("load ", "config")))
    commit_words = words("commit ", "config")
    failed += check("commit completion exposes check",
                    "check" in commit_words, str(commit_words))
    failed += check("commit completion exposes comment",
                    "comment" in commit_words, str(commit_words))
    failed += check("commit completion exposes confirmed",
                    "confirmed" in commit_words, str(commit_words))

    old_config_read_timeout = os.environ.get("NETLAB_CLI_CONFIG_READ_TIMEOUT_MS")
    os.environ["NETLAB_CLI_CONFIG_READ_TIMEOUT_MS"] = "432"

    class ConfigReadCLI(NetLabCLI):
        def __init__(self, fail=False):
            super().__init__()
            self.calls = []
            self.fail = fail

        def _rpc(self, daemon, method, payload, timeout_ms=0):
            self.calls.append((daemon, method, payload, timeout_ms))
            if self.fail:
                return b"error: request timed out"
            if daemon == DAEMON_CONFIGD and method == 5:
                return b"""
                <netlab-config>
                  <system><host-name>candidate-host</host-name></system>
                </netlab-config>
                """
            if daemon == DAEMON_CONFIGD and method == 8:
                return b"""
                <netlab-config>
                  <system><host-name>active-host</host-name></system>
                </netlab-config>
                """
            if daemon == DAEMON_CONFIGD and method == 11:
                return b"0\tactive\n1\tprevious\n"
            if daemon == DAEMON_CONFIGD and method == 13:
                return b"Commit confirmed: none pending\n"
            return b""

    try:
        read_cli = ConfigReadCLI()
        read_cli.mode = "operational"
        read_outputs = [
            read_cli.dispatch("show configuration | display set"),
            read_cli.dispatch("show system commit"),
            read_cli.dispatch("show system commit confirmed"),
            read_cli.dispatch("show system rollback"),
            read_cli.dispatch("show system rollback 0"),
        ]
        cfg_read_cli = ConfigReadCLI()
        cfg_read_cli.mode = "config"
        cfg_outputs = [
            cfg_read_cli.dispatch("show"),
            cfg_read_cli.dispatch("show | compare"),
        ]
        fail_cli = ConfigReadCLI(fail=True)
        fail_cli.mode = "operational"
        fail_outputs = [
            fail_cli.dispatch("show configuration"),
            fail_cli.dispatch("show system commit"),
            fail_cli.dispatch("show system commit confirmed"),
            fail_cli.dispatch("show system rollback"),
            fail_cli.dispatch("show system rollback 0"),
        ]
        cfg_fail_cli = ConfigReadCLI(fail=True)
        cfg_fail_cli.mode = "config"
        cfg_fail_outputs = [
            cfg_fail_cli.dispatch("show"),
            cfg_fail_cli.dispatch("show | compare"),
        ]
    finally:
        if old_config_read_timeout is None:
            os.environ.pop("NETLAB_CLI_CONFIG_READ_TIMEOUT_MS", None)
        else:
            os.environ["NETLAB_CLI_CONFIG_READ_TIMEOUT_MS"] = (
                old_config_read_timeout)

    config_read_calls = (
        read_cli.calls + cfg_read_cli.calls + fail_cli.calls +
        cfg_fail_cli.calls)
    failed += check("config lifecycle show uses bounded read timeout",
                    config_read_calls and
                    all(call[3] == 432 for call in config_read_calls
                        if call[0] == DAEMON_CONFIGD and
                        call[1] in (5, 8, 11, 13)),
                    str(config_read_calls))
    failed += check("config lifecycle show renders public data",
                    "set system host-name active-host" in read_outputs[0] and
                    "Commit history:" in read_outputs[1] and
                    "Commit confirmed:" in read_outputs[2] and
                    "Rollback history:" in read_outputs[3] and
                    "Rollback configuration 0:" in read_outputs[4] and
                    "candidate-host" in cfg_outputs[0] and
                    "[edit" in cfg_outputs[1],
                    "\n---\n".join(read_outputs + cfg_outputs))
    failed += check("config lifecycle show wraps read timeout",
                    "cannot read active configuration: request timed out"
                    in fail_outputs[0] and
                    "cannot read commit history: request timed out"
                    in fail_outputs[1] and
                    "cannot read commit confirmation state: request timed out"
                    in fail_outputs[2] and
                    "cannot read rollback history: request timed out"
                    in fail_outputs[3] and
                    "cannot read active configuration: request timed out"
                    in fail_outputs[4] and
                    "cannot read candidate configuration: request timed out"
                    in cfg_fail_outputs[0] and
                    "cannot read candidate configuration: request timed out"
                    in cfg_fail_outputs[1],
                    "\n---\n".join(fail_outputs + cfg_fail_outputs))

    old_config_write_timeout = os.environ.get(
        "NETLAB_CLI_CONFIG_WRITE_TIMEOUT_MS")
    old_config_commit_timeout = os.environ.get(
        "NETLAB_CLI_CONFIG_COMMIT_TIMEOUT_MS")
    old_config_lock_path = os.environ.get("NETLAB_LAB_ONLY_CONFIG_LOCK_PATH")
    old_config_authority_token = os.environ.get(
        "NETLAB_CONFIG_AUTHORITY_TOKEN")
    os.environ["NETLAB_CLI_CONFIG_WRITE_TIMEOUT_MS"] = "543"
    os.environ["NETLAB_CLI_CONFIG_COMMIT_TIMEOUT_MS"] = "654"

    class ConfigWriteCLI(NetLabCLI):
        def __init__(self, fail=False):
            super().__init__()
            self.mode = "config"
            self.calls = []
            self.fail = fail

        def _rpc(self, daemon, method, payload, timeout_ms=0):
            self.calls.append((daemon, method, payload, timeout_ms))
            if self.fail:
                return b"error: SDK owner hidden request timed out"
            return b""

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["NETLAB_LAB_ONLY_CONFIG_LOCK_PATH"] = os.path.join(
                tmpdir, "cli-config.lock")
            write_cli = ConfigWriteCLI()
            write_outputs = [
                write_cli.dispatch("set system host-name write-host"),
                write_cli.dispatch("delete system host-name"),
                write_cli.dispatch("commit check"),
                write_cli.dispatch('commit comment "write audit"'),
                write_cli.dispatch(
                    'commit confirmed 2 comment "write safety"'),
                write_cli.dispatch("commit"),
                write_cli.dispatch("rollback 0"),
            ]
            reconcile_cli = ConfigWriteCLI()
            reconcile_cli.mode = "operational"
            reconcile_output = reconcile_cli.dispatch(
                "request system reconcile")

            fail_write_cli = ConfigWriteCLI(fail=True)
            fail_outputs = [
                fail_write_cli.dispatch("set system host-name fail-host"),
                fail_write_cli.dispatch("delete system host-name"),
                fail_write_cli.dispatch("commit check"),
                fail_write_cli.dispatch("commit"),
                fail_write_cli.dispatch("rollback 0"),
            ]
            fail_reconcile_cli = ConfigWriteCLI(fail=True)
            fail_reconcile_cli.mode = "operational"
            fail_reconcile_output = fail_reconcile_cli.dispatch(
                "request system reconcile")
            guard_token = "ab" * 32
            guard_envelope = (
                b"netlab-config-authority-v1 " +
                guard_token.encode("ascii") + b"\n")
            os.environ["NETLAB_CONFIG_AUTHORITY_TOKEN"] = guard_token
            guarded_cli = ConfigWriteCLI()
            guarded_outputs = [
                guarded_cli.dispatch("set system host-name guarded-host"),
                guarded_cli.dispatch("delete system host-name"),
                guarded_cli.dispatch("commit"),
                guarded_cli.dispatch("rollback 0"),
            ]
            guarded_replay = guarded_cli._configd_mutation_rpc(
                10, b"", timeout_ms=765)
            os.environ["NETLAB_CONFIG_AUTHORITY_TOKEN"] = "invalid"
            invalid_guard_cli = ConfigWriteCLI()
            invalid_guard_output = invalid_guard_cli.dispatch(
                "set system host-name rejected-host")
    finally:
        if old_config_write_timeout is None:
            os.environ.pop("NETLAB_CLI_CONFIG_WRITE_TIMEOUT_MS", None)
        else:
            os.environ["NETLAB_CLI_CONFIG_WRITE_TIMEOUT_MS"] = (
                old_config_write_timeout)
        if old_config_commit_timeout is None:
            os.environ.pop("NETLAB_CLI_CONFIG_COMMIT_TIMEOUT_MS", None)
        else:
            os.environ["NETLAB_CLI_CONFIG_COMMIT_TIMEOUT_MS"] = (
                old_config_commit_timeout)
        if old_config_lock_path is None:
            os.environ.pop("NETLAB_LAB_ONLY_CONFIG_LOCK_PATH", None)
        else:
            os.environ["NETLAB_LAB_ONLY_CONFIG_LOCK_PATH"] = (
                old_config_lock_path)
        if old_config_authority_token is None:
            os.environ.pop("NETLAB_CONFIG_AUTHORITY_TOKEN", None)
        else:
            os.environ["NETLAB_CONFIG_AUTHORITY_TOKEN"] = (
                old_config_authority_token)

    write_calls = (
        write_cli.calls + reconcile_cli.calls + fail_write_cli.calls +
        fail_reconcile_cli.calls)
    write_methods = {1, 2, 4}
    commit_methods = {3, 6, 12}
    failed += check("config lifecycle write uses bounded timeout",
                    write_calls and
                    all(call[3] == 543 for call in write_calls
                        if call[0] == DAEMON_CONFIGD and
                        call[1] in write_methods) and
                    all(call[3] == 654 for call in write_calls
                        if call[0] == DAEMON_CONFIGD and
                        call[1] in commit_methods),
                    str(write_calls))
    failed += check("config lifecycle write preserves success responses",
                    write_outputs[0] is None and
                    write_outputs[1] is None and
                    write_outputs[2] == "commit check passed" and
                    write_outputs[3] == "commit complete" and
                    "commit confirmed" in write_outputs[4] and
                    write_outputs[5] == "commit complete" and
                    write_outputs[6] == "rollback complete" and
                    reconcile_output == "",
                    "\n---\n".join(str(item) for item in
                                    write_outputs + [reconcile_output]))
    failed += check(
        "production guard token envelopes every candidate/commit mutation",
        all(output in (None, "commit complete", "rollback complete")
            for output in guarded_outputs) and
        guarded_replay == b"" and
        len(guarded_cli.calls) == 5 and
        all(call[2].startswith(guard_envelope)
            for call in guarded_cli.calls) and
        any(call[1] == 10 and call[2] == guard_envelope and
            call[3] == 765 for call in guarded_cli.calls),
        str(guarded_cli.calls),
    )
    failed += check(
        "invalid production guard token fails before IPC",
        "invalid production configuration authority token"
        in invalid_guard_output and not invalid_guard_cli.calls,
        invalid_guard_output,
    )
    failed += check("config lifecycle write wraps backend wording",
                    all("request timed out" in (output or "")
                        for output in fail_outputs + [fail_reconcile_output]) and
                    all("sdk" not in (output or "").lower() and
                        "owner" not in (output or "").lower() and
                        "hidden" not in (output or "").lower()
                        for output in fail_outputs + [fail_reconcile_output]),
                    "\n---\n".join(
                        output or "" for output in
                        fail_outputs + [fail_reconcile_output]))

    old_socket = os.environ.get("NETLAB_MGMTD_SOCKET")
    old_timeout = os.environ.get("NETLAB_CLI_COMPLETION_TIMEOUT_MS")
    old_store = os.environ.get("NETLAB_CONFIG_STORE_DIR")
    old_session = session_module.CliSession
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "mgmtd.sock")
        open(socket_path, "w", encoding="utf-8").close()
        os.environ["NETLAB_MGMTD_SOCKET"] = socket_path
        os.environ["NETLAB_CLI_COMPLETION_TIMEOUT_MS"] = "250"
        os.environ["NETLAB_CONFIG_STORE_DIR"] = tmpdir
        os.makedirs(os.path.join(tmpdir, "rescue.conf"))

        class FakeCompletionSession:
            calls = []

            def connect(self):
                return True

            def close(self):
                pass

            def send_request(self, daemon, method, payload, timeout_ms=0):
                self.calls.append((daemon, method, payload, timeout_ms))
                if daemon == session_module.DAEMON_IFD:
                    return (0, 0, b"""
                    <interfaces>
                      <interface><name>et-0/0/0</name></interface>
                    </interfaces>
                    """)
                if daemon == session_module.DAEMON_L2D:
                    return (0, 0, b"""
                    <vlans>
                      <vlan><name>v100</name></vlan>
                    </vlans>
                    """)
                if daemon == session_module.DAEMON_CONFIGD:
                    return (0, 0, b"0\tactive\n1\tprevious\n")
                return (-1, 0, b"")

        session_module.CliSession = FakeCompletionSession
        try:
            iface_words = completion_dynamic.dynamic_candidates(
                "operational-interfaces", "et")
            vlan_words = completion_dynamic.dynamic_candidates("vlans", "v")
            rollback_words = completion_dynamic.dynamic_candidates(
                "rollback", "")
        finally:
            session_module.CliSession = old_session
            if old_socket is None:
                os.environ.pop("NETLAB_MGMTD_SOCKET", None)
            else:
                os.environ["NETLAB_MGMTD_SOCKET"] = old_socket
            if old_timeout is None:
                os.environ.pop("NETLAB_CLI_COMPLETION_TIMEOUT_MS", None)
            else:
                os.environ["NETLAB_CLI_COMPLETION_TIMEOUT_MS"] = old_timeout
            if old_store is None:
                os.environ.pop("NETLAB_CONFIG_STORE_DIR", None)
            else:
                os.environ["NETLAB_CONFIG_STORE_DIR"] = old_store

        failed += check("dynamic completion uses bounded RPC timeout",
                        FakeCompletionSession.calls and
                        all(call[3] == 250
                            for call in FakeCompletionSession.calls),
                        str(FakeCompletionSession.calls))
        failed += check("dynamic interface completion keeps runtime names",
                        any(item["word"] == "et-0/0/0"
                            for item in iface_words),
                        str(iface_words))
        failed += check("dynamic VLAN completion keeps runtime names",
                        any(item["word"] == "v100" for item in vlan_words),
                        str(vlan_words))
        failed += check("rollback completion hides non-regular rescue file",
                        any(item["word"] == "0" for item in rollback_words) and
                        not any(item["word"] == "rescue"
                                for item in rollback_words),
                        str(rollback_words))

    class FakeCLI(NetLabCLI):
        def __init__(self):
            super().__init__()
            self.mode = "config"
            self.loaded = []
            self.cleared = 0
            self.commit_payloads = []
            self.rpc_calls = []

        def _get_config_xml(self, active):
            return xml

        def _cfg_set(self, tokens):
            self.loaded.append(tokens)
            return None

        def _cfg_clear_candidate(self):
            self.cleared += 1
            return None

        def _rpc(self, daemon, method, payload, timeout_ms=0):
            self.rpc_calls.append((daemon, method, payload))
            if daemon == DAEMON_CHASSISD and method == 1:
                return b"""<chassis last-poll="1785311617" generation="12"
                    age-seconds="2" stale="false" duration-ms="20">
                  <name>RubyRapid-24x10G-L3</name>
                  <serial>fixture</serial>
                  <sources>
                    <source name="switchd-sbus" status="ok" sensors="1"/>
                    <source name="sysfs-hwmon" status="ok" sensors="0"/>
                  </sources>
                  <sensors>
                    <sensor id="0" label="MAIN TEMP SENSOR"
                      source="switchd-sbus" class="temperature" status="ok"
                      temp="35.4" temp-high="90.0" temp-crit="100.0"/>
                  </sensors>
                </chassis>"""
            if daemon == DAEMON_CONFIGD and method == 3:
                self.commit_payloads.append(payload)
                return b""
            if daemon == DAEMON_CONFIGD and method == 6:
                return b""
            if daemon == DAEMON_CONFIGD and method == 11:
                return (b"0\t2026-07-02 12:00:00 HKT by root "
                        b"via cli comment \"ticket-42\"\n")
            if daemon == DAEMON_CONFIGD and method == 13:
                return (b"Commit confirmed: awaiting confirmation\n"
                        b"  rollback in     : 599 seconds\n")
            return b"error: unexpected rpc"

    class ClearRootsCLI(NetLabCLI):
        def __init__(self):
            super().__init__()
            self.mode = "config"
            self.deleted = []

        def _configd_delete_raw(self, path):
            self.deleted.append(path)
            return 0, b""

    clear_roots_cli = ClearRootsCLI()
    clear_result = clear_roots_cli._cfg_clear_candidate()
    failed += check("override clear includes VRF and forwarding roots",
                    clear_result is None and
                    "/netlab:netlab-config/routing-instances" in
                    clear_roots_cli.deleted and
                    "/netlab:netlab-config/forwarding-options" in
                    clear_roots_cli.deleted,
                    str(clear_roots_cli.deleted))

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "candidate.set")
        cli = FakeCLI()
        failed += check("save writes display-set file",
                        cli.dispatch(f"save {path}") == f"Wrote {path}" and
                        os.path.exists(path),
                        path)
        saved = open(path, encoding="utf-8").read()
        failed += check("saved file uses firewall facade",
                        "set firewall family inet filter EDGE term web "
                        "then discard" in saved,
                        saved)
        failed += check("saved file preserves management services facade",
                        "set system services gnmi grpc" in saved and
                        "set snmp community public authorization read-only"
                        in saved,
                        saved)
        save_dir = cli.dispatch(f"save {tmpdir}")
        failed += check("save rejects directory target cleanly",
                        save_dir ==
                        f"error: cannot save configuration to directory: {tmpdir}",
                        save_dir)
        cli2 = FakeCLI()
        load_merge = cli2.dispatch(f"load merge {path}")
        failed += check("load merge rejects unowned service intent atomically",
                        "management protocol services have no runtime owner" in
                        load_merge and
                        cli2.cleared == 0 and
                        cli2.loaded == [],
                        f"result={load_merge} loaded={cli2.loaded}")
        load_dir = cli2.dispatch(f"load merge {tmpdir}")
        failed += check("load rejects directory source cleanly",
                        load_dir ==
                        f"error: cannot load configuration from directory: {tmpdir}",
                        load_dir)
        cli_set = FakeCLI()
        load_set = cli_set.dispatch(f"load set {path}")
        failed += check("load set rejects unowned service intent atomically",
                        "management protocol services have no runtime owner" in
                        load_set and
                        cli_set.cleared == 0 and
                        cli_set.loaded == [],
                        f"result={load_set} loaded={cli_set.loaded}")
        cli_factory = FakeCLI()
        failed += check("load factory-default clears candidate",
                        cli_factory.dispatch("load factory-default") ==
                        "load factory-default complete" and
                        cli_factory.cleared == 1 and
                        cli_factory.loaded == [],
                        f"cleared={cli_factory.cleared} "
                        f"loaded={cli_factory.loaded}")
        nav_cli = FakeCLI()
        nav_cli.edit_path = ["interfaces", "et-0/0/0", "unit", "0"]
        result = nav_cli.dispatch("up extra")
        failed += check("config up rejects suffix without changing edit path",
                        result == "error: unknown up option: extra" and
                        nav_cli.edit_path ==
                        ["interfaces", "et-0/0/0", "unit", "0"],
                        f"{result} path={nav_cli.edit_path}")
        result = nav_cli.dispatch("top extra")
        failed += check("config top rejects suffix without changing edit path",
                        result == "error: unknown top option: extra" and
                        nav_cli.edit_path ==
                        ["interfaces", "et-0/0/0", "unit", "0"],
                        f"{result} path={nav_cli.edit_path}")
        failed += check("config run without command is fail-closed",
                        nav_cli.dispatch("run") ==
                        "error: incomplete run command",
                        "run returned unexpected result")
        info = FakeCLI()
        info.mode = "operational"
        system_text = info.dispatch("show system")
        failed += check("show system displays active host-name",
                        "Hostname: leaf-1" in system_text,
                        system_text)
        show_top = words("show ")
        failed += check("show advertises version",
                        "version" in show_top, str(show_top))
        failed += check("show advertises NTP and SNMP management views",
                        {"ntp", "snmp"}.issubset(show_top),
                        str(show_top))
        version_text = info.dispatch("show version")
        failed += check("show version renders public platform view",
                        "NetLab Switch OS" in version_text and
                        "Build revision" in version_text and
                        "Chassis mode" in version_text and
                        "Network services" in version_text,
                        version_text)
        failed += check("show version hides profile wording",
                        "profile" not in version_text.lower() and
                        "rdi" not in version_text.lower(),
                        version_text)

        class LocalCommandCLI(NetLabCLI):
            def __init__(self):
                super().__init__()
                self.commands = []

            def _run_local_command(self, args, timeout=10):
                self.commands.append((args, timeout))
                return "local command fixture output"

        local = LocalCommandCLI()
        ping_text = local.dispatch("ping 192.0.2.1 count 3")
        failed += check("ping uses bounded public wrapper",
                        "Host reachability test:" in ping_text and
                        "target : 192.0.2.1" in ping_text and
                        "count  : 3" in ping_text and
                        "local command fixture output" in ping_text and
                        local.commands == [
                            (["ping", "-c", "3", "-W", "2",
                              "192.0.2.1"], 9)
                        ],
                        f"{ping_text} commands={local.commands}")
        failed += check("ping rejects unknown options",
                        "unknown ping option" in local.dispatch(
                            "ping 192.0.2.1 rapid"),
                        str(local.commands))
        failed += check("ping rejects option-like target",
                        "invalid ping target" in local.dispatch("ping -c"),
                        str(local.commands))
        failed += check("ping validates count bounds",
                        "ping count must be 1..20" in local.dispatch(
                            "ping 192.0.2.1 count 0"),
                        str(local.commands))
        local.commands.clear()
        traceroute_text = local.dispatch("traceroute 198.51.100.1")
        failed += check("traceroute uses bounded public wrapper",
                        "Path trace:" in traceroute_text and
                        "target : 198.51.100.1" in traceroute_text and
                        local.commands == [
                            (["traceroute", "-n", "-w", "2", "-q", "1",
                              "198.51.100.1"], 30)
                        ],
                        f"{traceroute_text} commands={local.commands}")
        failed += check("traceroute rejects unknown options",
                        "unknown traceroute option" in local.dispatch(
                            "traceroute 198.51.100.1 detail"),
                        str(local.commands))
        failed += check("show interfaces terse rejects unknown suffix",
                        "unknown interfaces terse target" in info.dispatch(
                            "show interfaces terse detail"))
        failed += check("show interfaces detail rejects unknown suffix",
                        "unknown interfaces detail target" in info.dispatch(
                            "show interfaces detail extra"))
        failed += check("show interfaces statistics rejects unknown suffix",
                        "unknown interfaces statistics target" in
                        info.dispatch(
                            "show interfaces statistics et-0/0/0 extra"))
        failed += check("show interface detail rejects unknown suffix",
                        "unknown interface detail target" in info.dispatch(
                            "show interfaces et-0/0/0 detail extra"))
        failed += check("show interface statistics rejects unknown suffix",
                        "unknown interface statistics target" in
                        info.dispatch(
                            "show interfaces et-0/0/0 statistics extra"))
        failed += check("show interfaces diagnostics optics rejects unknown suffix",
                        "unknown interfaces diagnostics optics target" in
                        info.dispatch(
                            "show interfaces diagnostics optics et-0/0/0 extra"))
        failed += check("show interfaces diagnostics optics mapping rejects unknown suffix",
                        "unknown interfaces diagnostics optics mapping target"
                        in info.dispatch(
                            "show interfaces diagnostics optics mapping extra"))
        old_optics_timeout = os.environ.get("NETLAB_CLI_OPTICS_TIMEOUT_MS")
        os.environ["NETLAB_CLI_OPTICS_TIMEOUT_MS"] = "333"

        class OpticsTimeoutCLI(NetLabCLI):
            def __init__(self):
                super().__init__()
                self.mode = "operational"
                self.calls = []

            def _rpc(self, daemon, method, payload, timeout_ms=0):
                self.calls.append((daemon, method, payload, timeout_ms))
                if daemon == DAEMON_SWITCHD and method == 90:
                    return b"<mux error='timeout'/>"
                if daemon == DAEMON_IFD and method == 1:
                    return b"<interfaces/>"
                return b""

        try:
            optics_cli = OpticsTimeoutCLI()
            optics_outputs = [
                optics_cli.dispatch("show chassis optics mux"),
                optics_cli.dispatch(
                    "show interfaces diagnostics optics et-0/0/0"),
                optics_cli.dispatch("show interfaces diagnostics optics"),
                optics_cli.dispatch(
                    "show interfaces diagnostics optics calibration"),
                optics_cli.dispatch(
                    "show interfaces diagnostics optics calibration check active"),
                optics_cli.dispatch(
                    "show interfaces diagnostics optics mapping"),
            ]
        finally:
            if old_optics_timeout is None:
                os.environ.pop("NETLAB_CLI_OPTICS_TIMEOUT_MS", None)
            else:
                os.environ["NETLAB_CLI_OPTICS_TIMEOUT_MS"] = old_optics_timeout

        failed += check("optics diagnostics use bounded RPC timeout",
                        optics_cli.calls and
                        all(call[3] == 333 for call in optics_cli.calls
                            if (call[0], call[1]) in (
                                (DAEMON_SWITCHD, 90), (DAEMON_IFD, 1))),
                        str(optics_cli.calls))
        failed += check("optics unavailable skips interface RPC",
                        not any(call[0] == DAEMON_IFD
                                for call in optics_cli.calls),
                        str(optics_cli.calls))
        failed += check("optics diagnostics return unavailable boundary",
                        all(("unavailable" in (text or "") or
                             "Optics mux calibration check" in (text or ""))
                            for text in optics_outputs),
                        "\n---\n".join(optics_outputs))

        class OpticsRetryCLI(NetLabCLI):
            def __init__(self):
                super().__init__()
                self.mode = "operational"
                self.calls = 0

            def _rpc(self, daemon, method, payload, timeout_ms=0):
                if daemon == DAEMON_SWITCHD and method == 90:
                    self.calls += 1
                    if self.calls == 1:
                        return b"error: daemon is unreachable"
                    return (
                        b'<optics-mux-probe bus="0" mux="0x58" '
                        b'control-before="0x31" restore-status="0"/>'
                    )
                return b""

        old_retry_delay = cli_module.OPTICS_MUX_RPC_RETRY_DELAY_SEC
        cli_module.OPTICS_MUX_RPC_RETRY_DELAY_SEC = 0
        try:
            retry_cli = OpticsRetryCLI()
            retry_text = retry_cli.dispatch("show chassis optics mux")
        finally:
            cli_module.OPTICS_MUX_RPC_RETRY_DELAY_SEC = old_retry_delay

        failed += check("optics mux RPC retries transient unreachable",
                        retry_cli.calls == 2 and
                        "Chassis optics mux:" in retry_text and
                        "unavailable" not in retry_text,
                        f"calls={retry_cli.calls} text={retry_text}")
        old_physical_interface_names = cli_module.physical_interface_names
        try:
            cli_module.physical_interface_names = lambda: []
            optics_no_ports = optics_cli.dispatch(
                "show interfaces diagnostics optics") or ""
        finally:
            cli_module.physical_interface_names = old_physical_interface_names
        failed += check("optics unavailable reason hides RDI/profile wording",
                        "unavailable" in optics_no_ports and
                        "RDI" not in optics_no_ports and
                        "profile" not in optics_no_ports.lower(),
                        optics_no_ports)
        clear_cli = FakeCLI()
        clear_cli.mode = "operational"
        clear_cli.rpc_calls.clear()
        clear_stats_extra = clear_cli.dispatch(
            "clear interfaces statistics et-0/0/0 extra")
        failed += check("clear interfaces statistics rejects unknown suffix",
                        "unknown clear interfaces statistics target"
                        in clear_stats_extra and not clear_cli.rpc_calls,
                        f"{clear_stats_extra} calls={clear_cli.rpc_calls}")
        clear_bpdu_extra = clear_cli.dispatch(
            "clear spanning-tree bpdu-guard interface et-0/0/0 extra")
        failed += check("clear bpdu guard rejects unknown suffix",
                        "unknown clear spanning-tree bpdu-guard interface target"
                        in clear_bpdu_extra and not clear_cli.rpc_calls,
                        f"{clear_bpdu_extra} calls={clear_cli.rpc_calls}")
        show_system_words = words("show system ")
        failed += check("show system advertises commit history",
                        "commit" in show_system_words,
                        str(show_system_words))
        failed += check("show system advertises rollback history",
                        "rollback" in show_system_words,
                        str(show_system_words))
        failed += check("show system management rejects unknown suffix",
                        "unknown system management target" in info.dispatch(
                            "show system management detail"))
        failed += check("show system advertises uptime/boot/memory/buffers/queues/vm/processes/storage",
                        {"uptime", "boot-messages", "memory", "buffers", "queues",
                         "virtual-memory", "processes", "storage"}.issubset(
                            show_system_words),
                        str(show_system_words))
        failed += check("show system advertises core dump inventory",
                        "core-dumps" in show_system_words,
                        str(show_system_words))
        failed += check("show system advertises host runtime inventory",
                        {"connections", "statistics"}.issubset(
                            show_system_words),
                        str(show_system_words))
        failed += check("show system advertises users/login/accounting",
                        {"users", "login", "accounting"}.issubset(
                            show_system_words),
                        str(show_system_words))
        failed += check("show system advertises AAA views",
                        {"authentication", "radius-server",
                         "tacplus-server"}.issubset(show_system_words),
                        str(show_system_words))
        failed += check("show system advertises services",
                        "services" in show_system_words,
                        str(show_system_words))
        failed += check("show system advertises NTP and syslog views",
                        {"ntp", "syslog"}.issubset(show_system_words),
                        str(show_system_words))
        failed += check("show system advertises software inventory",
                        "software" in show_system_words,
                        str(show_system_words))
        failed += check("show system advertises license inventory",
                        "license" in show_system_words,
                        str(show_system_words))
        software_inventory = info.dispatch("show system software")
        failed += check("show system software renders inventory boundary",
                        "System software:" in software_inventory and
                        "NetLab Switch OS" in software_inventory and
                        "Build revision" in software_inventory and
                        "Runtime mode" in software_inventory and
                        "Image validation : request system software validate"
                        in software_inventory and
                        "Image install    : request system software add"
                        in software_inventory and
                        "Image signing    : trust anchor not configured"
                        in software_inventory and
                        "A/B upgrade      : not configured"
                        in software_inventory and
                        "Rollback command : request system software rollback"
                        in software_inventory,
                        software_inventory)
        failed += check("show system software hides profile wording",
                        "profile" not in software_inventory.lower() and
                        "rdi" not in software_inventory.lower(),
                        software_inventory)
        license_inventory = info.dispatch("show system license")
        failed += check("show system license renders inventory boundary",
                        "System license:" in license_inventory and
                        "State            : not configured" in license_inventory and
                        "License store    : unavailable" in license_inventory and
                        "Enforcement      : not active" in license_inventory and
                        "Runtime boundary : features are governed by build/platform gates"
                        in license_inventory,
                        license_inventory)
        failed += check("show system license hides profile wording",
                        "profile" not in license_inventory.lower() and
                        "rdi" not in license_inventory.lower(),
                        license_inventory)
        services_text = info.dispatch("show system services")
        failed += check("show system services renders management intent",
                        "System services:" in services_text and
                        "gnmi" in services_text and
                        "configured/not-implemented" in services_text and
                        "port=57400" in services_text and
                        "snmp" in services_text and
                        "communities=1" in services_text,
                        services_text)
        service_words = words("show system services ")
        failed += check("show system services advertises service details",
                        {"ssh", "netconf", "restconf", "gnmi",
                         "snmp"}.issubset(service_words),
                        str(service_words))
        gnmi_text = info.dispatch("show system services gnmi")
        failed += check("show system services gnmi renders detail",
                        "System service: gnmi" in gnmi_text and
                        "State  : configured/not-implemented" in gnmi_text and
                        "gRPC intent    : configured" in gnmi_text and
                        "TCP port       : 57400" in gnmi_text,
                        gnmi_text)
        snmp_text = info.dispatch("show system services snmp")
        failed += check("show system services snmp renders communities",
                        "System service: snmp" in snmp_text and
                        "Contact     : NOC Team" in snmp_text and
                        "public" in snmp_text and
                        "192.0.2.0/24" in snmp_text and
                        "noc" in snmp_text and
                        "192.0.2.200" in snmp_text,
                        snmp_text)
        show_snmp_text = info.dispatch("show snmp")
        failed += check("show snmp renders management facade",
                        "SNMP:" in show_snmp_text and
                        "Contact     : NOC Team" in show_snmp_text and
                        "Communities : 1" in show_snmp_text and
                        "Trap groups : 1" in show_snmp_text and
                        "Runtime SNMP state: configuration intent only"
                        in show_snmp_text,
                        show_snmp_text)
        snmp_stats_text = info.dispatch("show snmp statistics")
        failed += check("show snmp statistics renders runtime boundary",
                        "SNMP statistics:" in snmp_stats_text and
                        "Input packets   : not reported" in snmp_stats_text and
                        "Communities     : 1" in snmp_stats_text and
                        "packet counters are not reported here"
                        in snmp_stats_text,
                        snmp_stats_text)
        empty_snmp = NoLiveRpcCLI()
        empty_snmp._get_config_xml = lambda active=True: "<netlab-config/>"
        empty_snmp_text = empty_snmp.dispatch("show snmp")
        failed += check("show snmp handles unconfigured baseline",
                        "SNMP:" in empty_snmp_text and
                        "State       : disabled" in empty_snmp_text and
                        "Communities : 0" in empty_snmp_text and
                        "Trap groups : 0" in empty_snmp_text,
                        empty_snmp_text)
        empty_snmp_stats = empty_snmp.dispatch("show snmp statistics subagents")
        failed += check("show snmp statistics handles unconfigured baseline",
                        "SNMP statistics:" in empty_snmp_stats and
                        "Communities     : 0" in empty_snmp_stats and
                        "Trap groups     : 0" in empty_snmp_stats and
                        "Subagents       : not reported" in empty_snmp_stats,
                        empty_snmp_stats)
        login_text = info.dispatch("show system login")
        failed += check("show system login renders configured local users",
                        "System login:" in login_text and
                        "ops" in login_text and
                        "operator" in login_text and
                        "encrypted-password, ssh-rsa" in login_text,
                        login_text)
        login_user_text = info.dispatch("show system login user ops")
        failed += check("show system login user filters local user",
                        "System login:" in login_user_text and
                        "ops" in login_user_text and
                        "operator" in login_user_text,
                        login_user_text)
        accounting_text = info.dispatch("show system accounting")
        failed += check("show system accounting renders audit intent",
                        "System accounting:" in accounting_text and
                        "login change-log interactive-commands"
                        in accounting_text and
                        "Change audit      : intent configured; see show system commit"
                        in accounting_text and
                        "Remote accounting : not configured"
                        in accounting_text,
                        accounting_text)
        auth_text = info.dispatch("show system authentication")
        failed += check("show system authentication renders AAA intent",
                        "System authentication:" in auth_text and
                        "Authentication order : radius password"
                        in auth_text and
                        "RADIUS servers       : 1" in auth_text and
                        "TACACS+ servers      : 1" in auth_text and
                        "Remote AAA state     : configuration intent only"
                        in auth_text,
                        auth_text)
        radius_text = info.dispatch("show system radius-server")
        failed += check("show system radius-server renders configured server",
                        "System RADIUS servers:" in radius_text and
                        "192.0.2.30" in radius_text and
                        "1812" in radius_text and
                        "configured" in radius_text and
                        "configuration intent only" in radius_text,
                        radius_text)
        tacplus_text = info.dispatch("show system tacplus-server")
        failed += check("show system tacplus-server renders configured server",
                        "System TACACS+ servers:" in tacplus_text and
                        "192.0.2.40" in tacplus_text and
                        "49" in tacplus_text and
                        "configured" in tacplus_text and
                        "yes" in tacplus_text,
                        tacplus_text)
        ntp_text = info.dispatch("show system ntp")
        failed += check("show system ntp renders configured servers",
                        "System NTP:" in ntp_text and
                        "192.0.2.10" in ntp_text and
                        "yes" in ntp_text and
                        "configuration intent only" in ntp_text,
                        ntp_text)
        ntp_associations_text = info.dispatch("show ntp associations")
        failed += check("show ntp associations renders runtime boundary",
                        "NTP associations:" in ntp_associations_text and
                        "192.0.2.10" in ntp_associations_text and
                        "daemon peer state is not reported here"
                        in ntp_associations_text,
                        ntp_associations_text)
        ntp_status_text = info.dispatch("show ntp status")
        failed += check("show ntp status renders sync boundary",
                        "NTP status:" in ntp_status_text and
                        "Synchronization : not reported" in ntp_status_text and
                        "Configured peers: 1" in ntp_status_text and
                        "Preferred peers : 192.0.2.10" in ntp_status_text,
                        ntp_status_text)
        syslog_text = info.dispatch("show system syslog")
        failed += check("show system syslog renders configured outputs",
                        "System syslog:" in syslog_text and
                        "192.0.2.20" in syslog_text and
                        "notice" in syslog_text and
                        "messages" in syslog_text and
                        "info" in syslog_text and
                        "configuration intent only" in syslog_text,
                        syslog_text)
        users_text = info.dispatch("show system users")
        failed += check("show system users renders session table",
                        "System users:" in users_text and
                        "User" in users_text and
                        "Terminal" in users_text,
                        users_text)
        alarms_text = info.dispatch("show system alarms")
        failed += check("show system alarms renders public alarm facade",
                        "System alarms:" in alarms_text and
                        "No active system alarms" in alarms_text and
                        "show chassis alarms" in alarms_text,
                        alarms_text)
        failed += check("show system alarms rejects unknown suffix",
                        "unknown system alarms target" in info.dispatch(
                            "show system alarms detail"))
        uptime_text = info.dispatch("show system uptime")
        failed += check("show system uptime renders host uptime",
                        "System uptime:" in uptime_text and
                        "host uptime inventory only" in uptime_text,
                        uptime_text)
        failed += check("show system uptime rejects unknown suffix",
                        "unknown system uptime target" in info.dispatch(
                            "show system uptime detail"))
        boot_log = os.path.join(tmpdir, "boot.log")
        with open(boot_log, "w", encoding="utf-8") as handle:
            handle.write("netlab boot start\nnetlab routing ready\n")
        old_boot_log = os.environ.get("NETLAB_BOOT_MESSAGES_FILE")
        os.environ["NETLAB_BOOT_MESSAGES_FILE"] = boot_log
        try:
            boot_text = info.dispatch("show system boot-messages")
            failed += check("show system boot-messages renders boot log",
                            "System boot messages:" in boot_text and
                            "netlab routing ready" in boot_text and
                            "read-only boot message inventory" in boot_text,
                            boot_text)
        finally:
            if old_boot_log is None:
                os.environ.pop("NETLAB_BOOT_MESSAGES_FILE", None)
            else:
                os.environ["NETLAB_BOOT_MESSAGES_FILE"] = old_boot_log
        memory_text = info.dispatch("show system memory")
        failed += check("show system memory renders host memory inventory",
                        "System memory:" in memory_text and
                        "Available" in memory_text and
                        "host memory inventory only" in memory_text,
                        memory_text)
        buffers_text = info.dispatch("show system buffers")
        failed += check("show system buffers renders host buffer counters",
                        "System buffers:" in buffers_text and
                        "Memory buffers:" in buffers_text and
                        "Socket buffers:" in buffers_text and
                        "host buffer counters only" in buffers_text,
                        buffers_text)
        queues_text = info.dispatch("show system queues")
        failed += check("show system queues renders host queue inventory",
                        "System queues:" in queues_text and
                        "System V message queues:" in queues_text and
                        "POSIX message queues:" in queues_text and
                        "host queue inventory only" in queues_text,
                        queues_text)
        virtual_memory_text = info.dispatch("show system virtual-memory")
        failed += check("show system virtual-memory renders host VM counters",
                        "System virtual memory:" in virtual_memory_text and
                        "VM counters:" in virtual_memory_text and
                        "host virtual memory counters only" in
                        virtual_memory_text,
                        virtual_memory_text)
        storage_text = info.dispatch("show system storage")
        failed += check("show system storage renders filesystem usage",
                        "System storage:" in storage_text and
                        "host filesystem usage only" in storage_text,
                        storage_text)
        failed += check("show system storage rejects unknown suffix",
                        "unknown system storage target" in info.dispatch(
                            "show system storage detail"))
        core_dir = os.path.join(tmpdir, "cores")
        os.makedirs(core_dir, exist_ok=True)
        core_name = "core.netlab.1234"
        core_path = os.path.join(core_dir, core_name)
        with open(core_path, "wb") as handle:
            handle.write(b"fake core bytes\n")
        old_core_dir = os.environ.get("NETLAB_CORE_DUMP_DIR")
        os.environ["NETLAB_CORE_DUMP_DIR"] = core_dir
        try:
            core_text = info.dispatch("show system core-dumps")
            failed += check("show system core-dumps renders inventory",
                            "System core dumps:" in core_text and
                            core_name in core_text and
                            "read-only core file inventory" in core_text,
                            core_text)
        finally:
            if old_core_dir is None:
                os.environ.pop("NETLAB_CORE_DUMP_DIR", None)
            else:
                os.environ["NETLAB_CORE_DUMP_DIR"] = old_core_dir
        processes_text = info.dispatch("show system processes")
        failed += check("show system processes renders process table",
                        "System processes:" in processes_text and
                        "host process inventory only" in processes_text,
                        processes_text)
        processes_extensive = info.dispatch("show system processes extensive")
        failed += check("show system processes extensive renders extended table",
                        "System processes:" in processes_extensive and
                        "View: extensive" in processes_extensive and
                        "host process inventory only" in processes_extensive,
                        processes_extensive)
        failed += check("show system processes rejects unknown suffix",
                        "unknown system processes target" in info.dispatch(
                            "show system processes detail"))
        connections_text = info.dispatch("show system connections")
        failed += check("show system connections renders socket inventory",
                        "System connections:" in connections_text and
                        "host socket inventory only" in connections_text,
                        connections_text)
        statistics_text = info.dispatch("show system statistics")
        failed += check("show system statistics renders kernel counters",
                        "System statistics:" in statistics_text and
                        "Protocol" in statistics_text and
                        "host kernel counters only" in statistics_text,
                        statistics_text)
        failed += check("show chassis advertises alarms/environment/RE",
                        {"alarms", "environment", "routing-engine"}.issubset(
                            words("show chassis ")),
                        str(words("show chassis ")))
        chassis_alarms = info.dispatch("show chassis alarms")
        failed += check("show chassis alarms is accepted",
                        "Chassis alarms:" in chassis_alarms and
                        "Active alarms : 0" in chassis_alarms and
                        "No chassis alarms currently active" in chassis_alarms,
                        chassis_alarms)

        class AlarmCLI(FakeCLI):
            def _rpc(self, daemon, method, payload, timeout_ms=0):
                if daemon == DAEMON_CHASSISD and method == 1:
                    return b"""<chassis last-poll="1785311617"
                        generation="13" age-seconds="20" stale="true"
                        duration-ms="20">
                      <name>RubyRapid-24x10G-L3</name>
                      <serial>fixture</serial>
                      <sources>
                        <source name="switchd-sbus" status="ok" sensors="1"/>
                        <source name="sysfs-hwmon" status="down" sensors="0"/>
                      </sources>
                      <sensors>
                        <sensor id="0" label="MAIN TEMP SENSOR"
                          source="switchd-sbus" class="temperature"
                          status="critical" temp="101.0" temp-crit="100.0"/>
                      </sensors>
                    </chassis>"""
                return super()._rpc(daemon, method, payload, timeout_ms)

        alarm_cli = AlarmCLI()
        alarm_cli.mode = "operational"
        active_chassis_alarms = alarm_cli.dispatch("show chassis alarms")
        failed += check(
            "show chassis alarms renders chassisd alarm state",
            "Active alarms : 3" in active_chassis_alarms and
            "chassis poll" in active_chassis_alarms and
            "sysfs-hwmon" in active_chassis_alarms and
            "MAIN TEMP SENSOR" in active_chassis_alarms and
            "critical" in active_chassis_alarms,
            active_chassis_alarms,
        )
        old_load_profile = output_chassis.load_profile
        old_port_mode_status = output_chassis.port_mode_status
        try:
            def fake_load_profile():
                return {
                    "platform": {
                        "port-mode": "24x10g",
                        "network-services": "l3",
                        "chassis-name": "RubyRapid-24x10G-L3",
                    },
                    "ffu": {
                        "ipv4-uc-first": "0",
                        "ipv4-uc-last": "3",
                        "acl-first": "4",
                        "acl-last": "31",
                    },
                    "ports": [
                        {
                            "role": "external",
                            "default-speed": "10000000000",
                            "capabilities": "ROUTE",
                        }
                        for _ in range(24)
                    ],
                }

            def fake_port_mode_status():
                return {
                    "configured": {
                        "port-mode": "24x10g",
                        "network-services": "l3",
                        "source": "active config with active profile fallback",
                    },
                    "applied": {
                        "port-mode": "24x10g",
                        "network-services": "l3",
                        "chassis-profile": "RubyRapid-24x10G-L3",
                        "path": "/var/lib/netlab/platform.profile",
                        "sha256": "a" * 64,
                    },
                    "rdi": {
                        "path": "/etc/rdi/fm_platform_attributes.cfg",
                        "sha256": "b" * 64,
                    },
                    "transaction": {
                        "state": "applied",
                        "tx-id": "20260703-110341",
                        "action": "apply",
                        "last-error": (
                            "profile/RDI audit failed: "
                            "/etc/rdi/fm_platform_attributes.cfg"),
                    },
                    "drift": False,
                }

            output_chassis.load_profile = fake_load_profile
            output_chassis.port_mode_status = fake_port_mode_status
            port_mode_text = output_chassis.format_chassis_port_mode()
        finally:
            output_chassis.load_profile = old_load_profile
            output_chassis.port_mode_status = old_port_mode_status
        lower_port_mode = port_mode_text.lower()
        failed += check(
            "show chassis port-mode hides profile/RDI internals",
            "Chassis mode           : RubyRapid-24x10G-L3" in port_mode_text and
            ("Apply model            : restart-time chassis port-mode selection"
             in port_mode_text) and
            "Applied chassis mode  : RubyRapid-24x10G-L3" in port_mode_text and
            "Platform attributes   : present" in port_mode_text and
            "profile" not in lower_port_mode and
            "rdi" not in lower_port_mode and
            "/var/lib/netlab/platform.profile" not in port_mode_text and
            "/etc/rdi" not in lower_port_mode,
            port_mode_text)
        failed += check("show chassis forwarding rejects unknown suffix",
                        "unknown chassis forwarding target" in info.dispatch(
                            "show chassis forwarding detail"))
        failed += check("show chassis forwarding resources rejects unknown suffix",
                        "unknown chassis forwarding target" in info.dispatch(
                            "show chassis forwarding resources detail"))
        info.rpc_calls.clear()
        diag_runtime_extra = info.dispatch(
            "show diagnostics forwarding runtime detail")
        failed += check("show diagnostics forwarding runtime rejects unknown suffix",
                        "unknown diagnostics forwarding runtime target"
                        in diag_runtime_extra and not info.rpc_calls,
                        f"{diag_runtime_extra} calls={info.rpc_calls}")
        info.rpc_calls.clear()
        diag_sdk_extra = info.dispatch(
            "show diagnostics forwarding sdk detail")
        failed += check("show diagnostics forwarding legacy runtime rejects unknown suffix",
                        "unknown diagnostics forwarding runtime target"
                        in diag_sdk_extra and "sdk" not in
                        diag_sdk_extra.lower() and not info.rpc_calls,
                        f"{diag_sdk_extra} calls={info.rpc_calls}")
        strict_show_rejects = {
            "show diagnostics forwarding":
                "incomplete diagnostics forwarding command",
            "show diagnostics l3":
                "incomplete diagnostics l3 command",
            "show diagnostics ethernet-switching":
                "incomplete diagnostics ethernet-switching command",
            "show diagnostics class-of-service":
                "incomplete diagnostics class-of-service command",
            "show control-plane protection detail":
                "unknown control-plane target",
            "show lldp":
                "incomplete lldp command",
            "show lldp interfaces detail":
                "unknown lldp interfaces target",
            "show lldp local-information detail":
                "unknown lldp local-information target",
            "show lldp neighbors detail extra":
                "unknown lldp neighbors detail target",
            "show lldp statistics detail":
                "unknown lldp statistics target",
            "show lacp":
                "incomplete lacp command",
            "show lacp interfaces detail":
                "unknown lacp interfaces target",
            "show spanning-tree bridge detail":
                "unknown spanning-tree bridge target",
            "show spanning-tree capabilities detail":
                "unknown spanning-tree capabilities target",
            "show spanning-tree statistics detail":
                "unknown spanning-tree statistics target",
            "show spanning-tree interface et-0/0/0 detail":
                "unknown spanning-tree interface target",
        }
        for command, expected in strict_show_rejects.items():
            info.rpc_calls.clear()
            result = info.dispatch(command) or ""
            failed += check(f"{command} rejects unknown suffix",
                            expected in result and not info.rpc_calls,
                            f"{result} calls={info.rpc_calls}")
        failed += check("show chassis hardware rejects unknown suffix",
                        "unknown chassis hardware target" in info.dispatch(
                            "show chassis hardware detail"))
        failed += check("show chassis environment is accepted",
                        "error: unknown chassis target" not in info.dispatch(
                            "show chassis environment"))
        failed += check("show chassis environment rejects unknown suffix",
                        "unknown chassis environment target" in info.dispatch(
                            "show chassis environment detail"))
        failed += check("show chassis port-mode rejects unknown suffix",
                        "unknown chassis port-mode target" in info.dispatch(
                            "show chassis port-mode detail"))
        chassis_re = info.dispatch("show chassis routing-engine")
        failed += check("show chassis routing-engine renders host RE inventory",
                        "Routing Engine status:" in chassis_re and
                        "Current state : Master" in chassis_re and
                        "read-only routing-engine inventory" in chassis_re,
                        chassis_re)
        failed += check("request advertises support information",
                        "support" in words("request ") and
                        "information" in words("request support "),
                        str(words("request ")))
        request_system = words("request system ")
        failed += check("request system advertises software validation",
                        "software" in request_system,
                        str(request_system))
        failed += check("request system advertises storage maintenance",
                        "storage" in request_system,
                        str(request_system))
        failed += check("request system advertises service operations",
                        "services" in request_system,
                        str(request_system))
        failed += check("request system advertises core dump operations",
                        "core-dumps" in request_system,
                        str(request_system))
        failed += check("request system advertises safe power lifecycle",
                        {"reboot", "halt", "power-off"}.issubset(
                            request_system),
                        str(request_system))
        failed += check("request system advertises snapshot and zeroize",
                        {"snapshot", "zeroize"}.issubset(request_system),
                        str(request_system))
        core_dump_delete_words = words("request system core-dumps delete ")
        failed += check("request system core-dumps delete exposes all/file",
                        "all" in core_dump_delete_words and
                        "<core-file>" in core_dump_delete_words,
                        str(core_dump_delete_words))
        failed += check("request system storage exposes cleanup",
                        "cleanup" in words("request system storage "),
                        str(words("request system storage ")))
        service_restart_words = words("request system services restart ")
        failed += check("request system services restart exposes services",
                        {"ssh", "netconf", "restconf", "gnmi",
                         "snmp"}.issubset(service_restart_words),
                        str(service_restart_words))
        failed += check("request system software exposes add/rollback/validate",
                        {"add", "rollback", "validate"}.issubset(
                            words("request system software ")),
                        str(words("request system software ")))
        port_mode_calls = []
        original_port_mode_start = cli_module.start_background_action

        def capture_port_mode_start(*args):
            port_mode_calls.append(args)
            return 4242, "/var/log/netlab/port-mode-apply.log"

        cli_module.start_background_action = capture_port_mode_start
        try:
            port_mode_apply = info.dispatch(
                "request chassis port-mode apply")
        finally:
            cli_module.start_background_action = original_port_mode_start
        failed += check(
            "request chassis port-mode delegates only the requested action",
            port_mode_calls == [("apply",)] and
            "port-mode apply started in background" in port_mode_apply,
            f"calls={port_mode_calls!r} output={port_mode_apply}")
        storage_cleanup = info.dispatch("request system storage cleanup")
        failed += check("request system storage cleanup is fail-closed",
                        "System storage cleanup:" in storage_cleanup and
                        "candidate paths:" in storage_cleanup and
                        "execution    : blocked" in storage_cleanup and
                        "state        : no changes made" in storage_cleanup,
                        storage_cleanup)
        old_core_dir = os.environ.get("NETLAB_CORE_DUMP_DIR")
        os.environ["NETLAB_CORE_DUMP_DIR"] = core_dir
        try:
            core_delete = info.dispatch(
                f"request system core-dumps delete {core_name}")
            failed += check("request system core-dumps delete is fail-closed",
                            "System core dump delete:" in core_delete and
                            f"target       : {core_name}" in core_delete and
                            "matched files: 1" in core_delete and
                            "execution    : blocked" in core_delete and
                            "state        : no changes made" in core_delete and
                            os.path.exists(core_path),
                            core_delete)
        finally:
            if old_core_dir is None:
                os.environ.pop("NETLAB_CORE_DUMP_DIR", None)
            else:
                os.environ["NETLAB_CORE_DUMP_DIR"] = old_core_dir
        service_restart = info.dispatch("request system services restart gnmi")
        failed += check("request system services restart is fail-closed",
                        "System service restart:" in service_restart and
                        "service      : gnmi" in service_restart and
                        "execution    : blocked" in service_restart and
                        "state        : no changes made" in service_restart,
                        service_restart)
        reboot_text = info.dispatch("request system reboot")
        failed += check("request system reboot is fail-closed",
                        "System reboot request:" in reboot_text and
                        "execution    : blocked" in reboot_text and
                        "state        : no changes made" in reboot_text,
                        reboot_text)
        halt_text = info.dispatch("request system halt")
        failed += check("request system halt is fail-closed",
                        "System halt request:" in halt_text and
                        "execution    : blocked" in halt_text and
                        "state        : no changes made" in halt_text,
                        halt_text)
        power_off_text = info.dispatch("request system power-off")
        failed += check("request system power-off is fail-closed",
                        "System power-off request:" in power_off_text and
                        "execution    : blocked" in power_off_text and
                        "state        : no changes made" in power_off_text,
                        power_off_text)
        snapshot_text = info.dispatch("request system snapshot")
        failed += check("request system snapshot is fail-closed",
                        "System snapshot request:" in snapshot_text and
                        "execution    : blocked" in snapshot_text and
                        "state        : no changes made" in snapshot_text,
                        snapshot_text)
        zeroize_text = info.dispatch("request system zeroize")
        failed += check("request system zeroize is fail-closed",
                        "System zeroize request:" in zeroize_text and
                        "execution    : blocked" in zeroize_text and
                        "state        : no changes made" in zeroize_text,
                        zeroize_text)
        commit_text = info.dispatch("show system commit")
        failed += check("show system commit formats configd history",
                        "Commit history:" in commit_text and
                        "Revision" in commit_text and
                        "2026-07-02 12:00:00 HKT by root via cli"
                        in commit_text and
                        'comment "ticket-42"' in commit_text,
                        commit_text)
        rollback_text = info.dispatch("show system rollback")
        failed += check("show system rollback formats rollback history",
                        "Rollback history:" in rollback_text and
                        "Rollback" in rollback_text and
                        "2026-07-02 12:00:00 HKT by root via cli"
                        in rollback_text and
                        'comment "ticket-42"' in rollback_text,
                        rollback_text)
        rollback_active = info.dispatch("show system rollback 0")
        failed += check("show system rollback 0 displays active config",
                        "Rollback configuration 0:" in rollback_active and
                        "host-name leaf-1;" in rollback_active,
                        rollback_active)
        rollback_bad = info.dispatch("show system rollback rescue")
        failed += check("show system rollback rejects non-numeric target",
                        "non-negative integer" in rollback_bad,
                        rollback_bad)
        confirmed_text = info.dispatch("show system commit confirmed")
        failed += check("show system commit confirmed reports pending state",
                        "Commit confirmed: awaiting" in confirmed_text and
                        "rollback in" in confirmed_text,
                        confirmed_text)
        comment_cli = FakeCLI()
        result = comment_cli.dispatch('commit comment "ticket 42 deploy"')
        failed += check("commit comment sends configd audit payload",
                        result == "commit complete" and
                        comment_cli.commit_payloads ==
                        [b"comment=ticket 42 deploy"],
                        f"{result} {comment_cli.commit_payloads}")
        check_cli = FakeCLI()
        result = check_cli.dispatch("commit check")
        failed += check("commit check sends configd validation RPC",
                        result == "commit check passed" and
                        check_cli.rpc_calls ==
                        [(DAEMON_CONFIGD, 6, b"")],
                        f"{result} {check_cli.rpc_calls}")
        bad_check_cli = FakeCLI()
        result = bad_check_cli.dispatch("commit check extra")
        failed += check("commit check rejects unknown suffix before RPC",
                        result == "error: usage: commit check" and
                        bad_check_cli.rpc_calls == [],
                        f"{result} {bad_check_cli.rpc_calls}")
        confirmed_cli = FakeCLI()
        result = confirmed_cli.dispatch(
            'commit confirmed 3 comment "ticket 42 safety"')
        failed += check("commit confirmed sends timeout and audit payload",
                        "commit confirmed" in result and
                        "use 'commit' to confirm" in result and
                        confirmed_cli.commit_payloads ==
                        [b"confirmed=180\ncomment=ticket 42 safety"],
                        f"{result} {confirmed_cli.commit_payloads}")
        file_words = words("file ")
        failed += check("operational file facade exposes checksum/compare/copy/delete/list/rename/show",
                        {"checksum", "compare", "copy", "delete", "list",
                         "rename", "show"}.issubset(file_words),
                        str(file_words))
        checksum_words = words("file checksum ")
        failed += check("file checksum exposes expected algorithms",
                        {"md5", "sha1", "sha256"}.issubset(checksum_words),
                        str(checksum_words))
        compare_words = words("file compare ")
        failed += check("file compare exposes files",
                        "files" in compare_words,
                        str(compare_words))
        show_log_words = words("show log ")
        failed += check("show log exposes system and daemon logs",
                        {"messages", "configd", "switchd"}.issubset(
                            show_log_words),
                        str(show_log_words))
        note_path = os.path.join(tmpdir, "note.txt")
        with open(note_path, "w", encoding="utf-8") as handle:
            handle.write("hello from file show\n")
        list_text = info.dispatch(f"file list {tmpdir}")
        failed += check("file list shows directory entries",
                        "Directory:" in list_text and "note.txt" in list_text,
                        list_text)
        file_text = info.dispatch(f"file show {note_path}")
        failed += check("file show reads file contents",
                        "File:" in file_text and
                        "hello from file show" in file_text,
                        file_text)
        changed_path = os.path.join(tmpdir, "note-changed.txt")
        with open(changed_path, "w", encoding="utf-8") as handle:
            handle.write("hello from file compare\n")
        compare_text = info.dispatch(
            f"file compare files {note_path} {changed_path} unified")
        failed += check("file compare unified shows text diff",
                        f"--- {note_path}" in compare_text and
                        f"+++ {changed_path}" in compare_text and
                        "-hello from file show" in compare_text and
                        "+hello from file compare" in compare_text,
                        compare_text)
        same_text = info.dispatch(f"file compare files {note_path} {note_path}")
        failed += check("file compare identical reports no difference",
                        same_text == "Files are identical",
                        same_text)
        whitespace_path = os.path.join(tmpdir, "note-whitespace.txt")
        with open(whitespace_path, "w", encoding="utf-8") as handle:
            handle.write("hello   from   file show\n")
        whitespace_text = info.dispatch(
            f"file compare files {note_path} {whitespace_path} "
            "ignore-white-space")
        failed += check("file compare can ignore whitespace",
                        whitespace_text == "Files are identical",
                        whitespace_text)
        compare_dir = info.dispatch(f"file compare files {note_path} {tmpdir}")
        failed += check("file compare rejects directories",
                        "cannot compare directory" in compare_dir,
                        compare_dir)
        expected_sha256 = hashlib.sha256(
            b"hello from file show\n").hexdigest()
        checksum_text = info.dispatch(f"file checksum sha256 {note_path}")
        failed += check("file checksum sha256 reads file digest",
                        "File checksum:" in checksum_text and
                        "algorithm : sha256" in checksum_text and
                        expected_sha256 in checksum_text,
                        checksum_text)
        failed += check("file checksum rejects unsupported algorithm",
                        "unsupported checksum algorithm" in info.dispatch(
                            f"file checksum crc32 {note_path}"))
        image_path = os.path.join(tmpdir, "netlab-install.tgz")
        image_bytes = b"fake image bytes\n"
        with open(image_path, "wb") as handle:
            handle.write(image_bytes)
        image_sha256 = hashlib.sha256(image_bytes).hexdigest()
        software_text = info.dispatch(
            f"request system software validate {image_path}")
        failed += check("request software validate performs read-only image preflight",
                        "Software image validation:" in software_text and
                        f"image        : {image_path}" in software_text and
                        image_sha256 in software_text and
                        "signature    : missing" in software_text and
                        "verification : not performed" in software_text and
                        "install      : not requested" in software_text,
                        software_text)
        software_add = info.dispatch(
            f"request system software add {image_path} no-copy reboot")
        failed += check("request software add is fail-closed after preflight",
                        "Software image add:" in software_add and
                        f"image        : {image_path}" in software_add and
                        image_sha256 in software_add and
                        "options      : no-copy reboot" in software_add and
                        "install      : blocked" in software_add and
                        "reboot       : blocked" in software_add and
                        "state        : no changes made" in software_add,
                        software_add)
        software_add_bad = info.dispatch(
            f"request system software add {image_path} validate no-validate")
        failed += check("request software add rejects conflicting validation flags",
                        "validate and no-validate cannot be used together"
                        in software_add_bad,
                        software_add_bad)
        software_rollback = info.dispatch("request system software rollback")
        failed += check("request software rollback is fail-closed",
                        "Software rollback:" in software_rollback and
                        "rollback image      : unavailable" in software_rollback and
                        "A/B upgrade         : not configured"
                        in software_rollback and
                        "action              : blocked"
                        in software_rollback and
                        "state               : no changes made"
                        in software_rollback,
                        software_rollback)
        software_dir = info.dispatch(
            f"request system software validate {tmpdir}")
        failed += check("request software validate rejects directories",
                        "software image must be a regular file" in software_dir,
                        software_dir)
        copy_path = os.path.join(tmpdir, "note-copy.txt")
        copy_text = info.dispatch(f"file copy {note_path} {copy_path}")
        failed += check("file copy writes destination file",
                        "file copied" in copy_text and
                        os.path.exists(copy_path) and
                        open(copy_path, encoding="utf-8").read() ==
                        "hello from file show\n",
                        copy_text)
        missing_parent = os.path.join(tmpdir, "missing", "note-copy.txt")
        copy_missing_parent = info.dispatch(
            f"file copy {note_path} {missing_parent}")
        failed += check("file copy rejects missing destination parent",
                        "destination directory not found" in
                        copy_missing_parent and
                        not os.path.exists(os.path.dirname(missing_parent)),
                        copy_missing_parent)
        copy_unsafe = info.dispatch(
            f"file copy {note_path} /etc/netlab-copy-denied")
        failed += check("file copy rejects unsafe destination root",
                        "outside allowed mutable paths" in copy_unsafe,
                        copy_unsafe)
        delete_text = info.dispatch(f"file delete {copy_path}")
        failed += check("file delete removes regular file",
                        "file deleted" in delete_text and
                        not os.path.exists(copy_path),
                        delete_text)
        symlink_path = os.path.join(tmpdir, "note-link.txt")
        try:
            os.symlink(note_path, symlink_path)
            delete_symlink = info.dispatch(f"file delete {symlink_path}")
            failed += check("file delete rejects symbolic links",
                            "symbolic link" in delete_symlink and
                            os.path.islink(symlink_path),
                            delete_symlink)
        except (AttributeError, NotImplementedError, OSError):
            pass
        rename_source = os.path.join(tmpdir, "note-rename-src.txt")
        rename_destination = os.path.join(tmpdir, "note-rename-dst.txt")
        with open(rename_source, "w", encoding="utf-8") as handle:
            handle.write("hello from file rename\n")
        rename_text = info.dispatch(
            f"file rename {rename_source} {rename_destination}")
        failed += check("file rename moves regular file",
                        "file renamed" in rename_text and
                        not os.path.exists(rename_source) and
                        os.path.exists(rename_destination) and
                        open(rename_destination, encoding="utf-8").read() ==
                        "hello from file rename\n",
                        rename_text)
        rename_missing_parent_src = os.path.join(
            tmpdir, "note-rename-missing-parent.txt")
        with open(rename_missing_parent_src, "w", encoding="utf-8") as handle:
            handle.write("rename parent boundary\n")
        rename_missing_parent_dst = os.path.join(
            tmpdir, "missing-rename", "note.txt")
        rename_missing_parent = info.dispatch(
            f"file rename {rename_missing_parent_src} "
            f"{rename_missing_parent_dst}")
        failed += check("file rename rejects missing destination parent",
                        "destination directory not found" in
                        rename_missing_parent and
                        os.path.exists(rename_missing_parent_src) and
                        not os.path.exists(os.path.dirname(
                            rename_missing_parent_dst)),
                        rename_missing_parent)
        rename_parent_file = os.path.join(tmpdir, "rename-parent-file")
        with open(rename_parent_file, "w", encoding="utf-8") as handle:
            handle.write("not a directory\n")
        rename_bad_parent = info.dispatch(
            f"file rename {rename_missing_parent_src} "
            f"{rename_parent_file}/note.txt")
        failed += check("file rename rejects non-directory parent cleanly",
                        "destination parent is not a directory" in
                        rename_bad_parent and
                        "Errno" not in rename_bad_parent and
                        os.path.exists(rename_missing_parent_src),
                        rename_bad_parent)
        rename_dir = info.dispatch(f"file rename {tmpdir} {rename_source}")
        failed += check("file rename rejects directories",
                        "cannot rename directory" in rename_dir,
                        rename_dir)
        old_log_dir = os.environ.get("NETLAB_LOG_DIR")
        old_system_log_dir = os.environ.get("NETLAB_SYSTEM_LOG_DIR")
        netlab_log_dir = os.path.join(tmpdir, "netlab-log")
        system_log_dir = os.path.join(tmpdir, "system-log")
        os.makedirs(netlab_log_dir)
        os.makedirs(system_log_dir)
        with open(os.path.join(netlab_log_dir, "configd.log"),
                  "w", encoding="utf-8") as handle:
            handle.write("configd ready\n")
        with open(os.path.join(netlab_log_dir, "rpd.log"),
                  "w", encoding="utf-8") as handle:
            handle.write("rpd ready (persistent SDK owner)\n")
        with open(os.path.join(system_log_dir, "messages"),
                  "w", encoding="utf-8") as handle:
            handle.write("system message\n")
        try:
            os.environ["NETLAB_LOG_DIR"] = netlab_log_dir
            os.environ["NETLAB_SYSTEM_LOG_DIR"] = system_log_dir
            log_index = info.dispatch("show log")
            failed += check("show log lists available log files",
                            "Log files:" in log_index and
                            "configd" in log_index and
                            "messages" in log_index,
                            log_index)
            configd_log = info.dispatch("show log configd")
            failed += check("show log configd reads daemon log tail",
                            "Log file: configd" in configd_log and
                            "configd ready" in configd_log,
                            configd_log)
            rpd_log = info.dispatch("show log rpd")
            failed += check("show log rpd hides owner/SDK wording",
                            "Log file: rpd" in rpd_log and
                            "persistent forwarding runtime role" in rpd_log and
                            "owner" not in rpd_log.lower() and
                            "sdk" not in rpd_log.lower(),
                            rpd_log)
            messages_log = info.dispatch("show log messages")
            failed += check("show log messages reads system log tail",
                            "Log file: messages" in messages_log and
                            "system message" in messages_log,
                            messages_log)
            old_support_dir = os.environ.get("NETLAB_SUPPORT_DIR")
            support_dir = os.path.join(tmpdir, "support")
            os.environ["NETLAB_SUPPORT_DIR"] = support_dir
            old_strftime = cli_module.time.strftime

            def fixed_support_strftime(fmt, *args):
                if fmt == "%Y%m%d-%H%M%S":
                    return "20260703-131500"
                return old_strftime(fmt, *args)

            cli_module.time.strftime = fixed_support_strftime
            try:
                support = info.dispatch("request support information")
                support_again = info.dispatch("request support information")
                support_files = sorted(os.listdir(support_dir))
                failed += check("request support information writes bundle",
                                "Support information written" in support and
                                "Support information written" in support_again and
                                any(name.startswith("support-info-")
                                    for name in support_files),
                                support + "\n" + support_again)
                failed += check("request support keeps same-second bundles",
                                "support-info-20260703-131500.txt"
                                in support_files and
                                "support-info-20260703-131500-01.txt"
                                in support_files,
                                str(support_files))
                if support_files:
                    bundle_path = os.path.join(support_dir, support_files[0])
                    bundle = open(bundle_path, encoding="utf-8").read()
                    failed += check("support bundle captures public commands",
                                    "## show version" in bundle and
                                    "## show system software" in bundle and
                                    "## show system license" in bundle and
                                    "## show system boot-messages" in bundle and
                                    "## show system memory" in bundle and
                                    "## show system buffers" in bundle and
                                    "## show system queues" in bundle and
                                    "## show system virtual-memory" in bundle and
                                    "## show system core-dumps" in bundle and
                                    "## show system processes extensive"
                                    in bundle and
                                    "## show system rollback" in bundle and
                                    "## show system configuration" in bundle and
                                    "## show chassis alarms" in bundle and
                                    "## show chassis routing-engine" in bundle and
                                    "## show configuration | display set"
                                    in bundle,
                                    bundle[:400])
                else:
                    failed += check("support bundle captures public commands",
                                    False, support)
            finally:
                cli_module.time.strftime = old_strftime
                if old_support_dir is None:
                    os.environ.pop("NETLAB_SUPPORT_DIR", None)
                else:
                    os.environ["NETLAB_SUPPORT_DIR"] = old_support_dir
        finally:
            if old_log_dir is None:
                os.environ.pop("NETLAB_LOG_DIR", None)
            else:
                os.environ["NETLAB_LOG_DIR"] = old_log_dir
            if old_system_log_dir is None:
                os.environ.pop("NETLAB_SYSTEM_LOG_DIR", None)
            else:
                os.environ["NETLAB_SYSTEM_LOG_DIR"] = old_system_log_dir
        cli3 = FakeCLI()
        load_override = cli3.dispatch(f"load override {path}")
        failed += check("load override rejects unowned service intent before clear",
                        "management protocol services have no runtime owner" in
                        load_override and
                        cli3.cleared == 0 and cli3.loaded == [],
                        f"result={load_override} cleared={cli3.cleared} "
                        f"loaded={cli3.loaded}")

        old_store = os.environ.get("NETLAB_CONFIG_STORE_DIR")
        os.environ["NETLAB_CONFIG_STORE_DIR"] = tmpdir
        try:
            rollback_dir = os.path.join(tmpdir, "rollback")
            os.makedirs(rollback_dir)
            rollback_old_xml = """
            <netlab-config>
              <system>
                <host-name>rollback-1</host-name>
              </system>
            </netlab-config>
            """
            rollback_current_xml = """
            <netlab-config>
              <system>
                <host-name>rollback-current</host-name>
              </system>
            </netlab-config>
            """
            with open(os.path.join(rollback_dir, "0000000000000001.conf"),
                      "w", encoding="utf-8") as handle:
                handle.write(rollback_old_xml)
            with open(os.path.join(rollback_dir, "0000000000000002.conf"),
                      "w", encoding="utf-8") as handle:
                handle.write(rollback_current_xml)
            ops = FakeCLI()
            ops.mode = "operational"
            request_top = words("request system configuration ")
            failed += check("request exposes configuration rescue/archive",
                            {"rescue", "archive"}.issubset(request_top),
                            str(request_top))
            show_cfg = words("show system configuration ")
            failed += check("show exposes configuration rescue/archive",
                            {"rescue", "archive"}.issubset(show_cfg),
                            str(show_cfg))
            rescue = ops.dispatch("request system configuration rescue save")
            rescue_path = os.path.join(tmpdir, "rescue.conf")
            failed += check("request rescue save writes active config",
                            "rescue configuration saved" in rescue and
                            os.path.exists(rescue_path),
                            rescue)
            rescue_show = ops.dispatch("show system configuration rescue")
            failed += check("show rescue displays saved public config",
                            "Rescue configuration:" in rescue_show and
                            "set system host-name" in rescue_show and
                            "interfaces-routing" not in rescue_show and
                            "next-hop-id" not in rescue_show and
                            "ecmp-id" not in rescue_show and
                            "owner" not in rescue_show.lower() and
                            "sdk" not in rescue_show.lower() and
                            "hidden" not in rescue_show.lower(),
                            rescue_show)
            os.unlink(rescue_path)
            os.makedirs(rescue_path)
            rescue_dir_show = ops.dispatch("show system configuration rescue")
            failed += check("show rescue rejects non-regular rescue file",
                            rescue_dir_show ==
                            "error: rescue configuration must be a regular file",
                            rescue_dir_show)
            rescue_summary = ops.dispatch("show system configuration")
            failed += check("show configuration summary rejects non-regular rescue file",
                            "error: rescue configuration must be a regular file"
                            in rescue_summary,
                            rescue_summary)
            rescue_dir_delete = ops.dispatch(
                "request system configuration rescue delete")
            failed += check("request rescue delete rejects non-regular rescue file",
                            rescue_dir_delete ==
                            "error: rescue configuration must be a regular file"
                            and os.path.isdir(rescue_path),
                            rescue_dir_delete)
            rescue_dir_save = ops.dispatch(
                "request system configuration rescue save")
            failed += check("request rescue save rejects non-regular rescue file",
                            rescue_dir_save ==
                            "error: rescue configuration must be a regular file"
                            and os.path.isdir(rescue_path),
                            rescue_dir_save)
            os.rmdir(rescue_path)
            rescue_restore = ops.dispatch(
                "request system configuration rescue save")
            failed += check("request rescue save restores regular rescue file",
                            "rescue configuration saved" in rescue_restore and
                            os.path.isfile(rescue_path),
                            rescue_restore)
            old_strftime = cli_module.time.strftime

            def fixed_archive_strftime(fmt, *args):
                if fmt == "%Y%m%d-%H%M%S":
                    return "20260703-130000"
                return old_strftime(fmt, *args)

            cli_module.time.strftime = fixed_archive_strftime
            try:
                archive = ops.dispatch("request system configuration archive")
                archive_again = ops.dispatch(
                    "request system configuration archive")
            finally:
                cli_module.time.strftime = old_strftime
            archive_dir = os.path.join(tmpdir, "archive")
            failed += check("request archive writes active config",
                            "configuration archived" in archive and
                            "configuration archived" in archive_again and
                            os.path.isdir(archive_dir) and
                            any(name.endswith(".set")
                                for name in os.listdir(archive_dir)),
                            archive + "\n" + archive_again)
            archive_names = sorted(
                name for name in os.listdir(archive_dir)
                if name.endswith(".set"))
            failed += check("request archive keeps same-second snapshots",
                            "configuration-20260703-130000.set"
                            in archive_names and
                            "configuration-20260703-130000-01.set"
                            in archive_names,
                            str(archive_names))
            archive_name = archive_names[-1] if archive_names else ""
            archive_dir_entry = os.path.join(archive_dir, "directory.set")
            os.makedirs(archive_dir_entry)
            archive_show = ops.dispatch("show system configuration archive")
            failed += check("show archive lists archived config",
                            "Configuration archive:" in archive_show and
                            "configuration-" in archive_show and
                            "directory.set" not in archive_show,
                            archive_show)
            archive_file = ops.dispatch(
                f"show system configuration archive {archive_name}")
            failed += check("show archive file displays archived config",
                            archive_name and
                            f"Configuration archive: {archive_name}"
                            in archive_file and
                            "set system host-name" in archive_file,
                            archive_file)
            archive_dir_show = ops.dispatch(
                "show system configuration archive directory.set")
            failed += check("show archive rejects non-regular archive file",
                            "configuration archive must be a regular file"
                            in archive_dir_show,
                            archive_dir_show)
            archive_dir_delete = ops.dispatch(
                "request system configuration archive delete directory.set")
            failed += check("request archive delete rejects non-regular archive file",
                            "configuration archive must be a regular file"
                            in archive_dir_delete and
                            os.path.isdir(archive_dir_entry),
                            archive_dir_delete)
            archive_delete = ops.dispatch(
                f"request system configuration archive delete {archive_name}")
            failed += check("request archive delete removes archived config",
                            archive_delete == "configuration archive deleted" and
                            not os.path.exists(
                                os.path.join(archive_dir, archive_name)),
                            archive_delete)
            archive_escape = ops.dispatch(
                "request system configuration archive delete ../active.set")
            failed += check("request archive delete rejects path escape",
                            "archive file must be a file name" in archive_escape,
                            archive_escape)
            rollback_snapshot = ops.dispatch("show system rollback 1")
            failed += check("show system rollback 1 displays snapshot config",
                            "Rollback configuration 1:" in rollback_snapshot and
                            "host-name rollback-1;" in rollback_snapshot,
                            rollback_snapshot)
            rollback_compare = ops.dispatch("show system rollback 1 compare 0")
            failed += check("show system rollback compare diffs snapshots",
                            "[edit]" in rollback_compare and
                            "-   set system host-name leaf-1"
                            in rollback_compare and
                            "+   set system host-name rollback-1"
                            in rollback_compare,
                            rollback_compare)
            rollback_compare_same = ops.dispatch(
                "show system rollback 1 compare 1")
            failed += check("show system rollback compare reports no diff",
                            rollback_compare_same ==
                            "No differences between rollback 1 and rollback 1",
                            rollback_compare_same)
            rollback_compare_bad = ops.dispatch(
                "show system rollback 1 compare rescue")
            failed += check("show system rollback compare rejects bad target",
                            "non-negative integer" in rollback_compare_bad,
                            rollback_compare_bad)
            active_compare = ops.dispatch(
                "show configuration | compare rollback 1")
            failed += check("show configuration compare rollback uses active config",
                            "[edit]" in active_compare and
                            "-   set system host-name rollback-1"
                            in active_compare and
                            "+   set system host-name leaf-1"
                            in active_compare,
                            active_compare)
            candidate_cli = FakeCLI()
            candidate_cli.mode = "config"
            candidate_compare = candidate_cli.dispatch(
                "show | compare rollback 1")
            failed += check("show pipe compare rollback uses candidate config",
                            "[edit]" in candidate_compare and
                            "-   set system host-name rollback-1"
                            in candidate_compare and
                            "+   set system host-name leaf-1"
                            in candidate_compare,
                            candidate_compare)
            bare_display = candidate_cli.dispatch("show | display")
            failed += check("show pipe display requires explicit format",
                            "incomplete display pipe" in bare_display,
                            bare_display)
            active_bare_display = ops.dispatch("show configuration | display")
            failed += check("show configuration display requires explicit format",
                            "incomplete display pipe" in active_bare_display,
                            active_bare_display)
            generic_bare_display = ops.dispatch("show version | display")
            failed += check("generic display pipe requires explicit format",
                            "incomplete display pipe" in generic_bare_display,
                            generic_bare_display)
            deleted = ops.dispatch("request system configuration rescue delete")
            failed += check("request rescue delete removes file",
                            deleted == "rescue configuration deleted" and
                            not os.path.exists(rescue_path),
                            deleted)
            ops.dispatch("request system configuration rescue save")
            rollback_words = words("rollback ", "config")
            failed += check("rollback completion exposes existing rescue",
                            "rescue" in rollback_words,
                            str(rollback_words))
            rescue_cli = FakeCLI()
            rescue_cli.mode = "config"
            result = rescue_cli.dispatch("rollback rescue")
            failed += check("rollback rescue rejects unowned service intent",
                            "management protocol services have no runtime owner"
                            in result and
                            rescue_cli.cleared == 0 and
                            rescue_cli.loaded == [],
                            f"result={result} cleared={rescue_cli.cleared} "
                            f"loaded={rescue_cli.loaded}")
        finally:
            if old_store is None:
                os.environ.pop("NETLAB_CONFIG_STORE_DIR", None)
            else:
                os.environ["NETLAB_CONFIG_STORE_DIR"] = old_store

        old_lock = os.environ.get("NETLAB_LAB_ONLY_CONFIG_LOCK_PATH")
        lock_path = os.path.join(tmpdir, "cli-config.lock")
        os.environ["NETLAB_LAB_ONLY_CONFIG_LOCK_PATH"] = lock_path
        try:
            configure_words = words("configure ")
            failed += check("configure completion exposes implemented lifecycle mode",
                            "exclusive" in configure_words,
                            str(configure_words))
            failed += check("configure completion hides unimplemented private mode",
                            "private" not in configure_words,
                            str(configure_words))
            private_cli = NoLiveRpcCLI()
            private_result = private_cli.dispatch("configure private")
            failed += check("configure private fails closed",
                            private_result.startswith(
                                "error: configure private") and
                            private_cli.mode == "operational",
                            private_result)
            op_exit = NoLiveRpcCLI()
            failed += check("operational exit rejects unknown suffix",
                            (op_exit.dispatch("exit now") ==
                             "error: unknown exit option: now") and
                            op_exit.mode == "operational",
                            repr(op_exit.mode))
            op_quit = NoLiveRpcCLI()
            failed += check("operational quit rejects unknown suffix",
                            (op_quit.dispatch("quit now") ==
                             "error: unknown quit option: now") and
                            op_quit.mode == "operational",
                            repr(op_quit.mode))
            exclusive_cli = NoLiveRpcCLI()
            exclusive_result = exclusive_cli.dispatch("configure exclusive")
            failed += check("configure exclusive acquires lock",
                            "exclusive" in exclusive_result and
                            exclusive_cli.mode == "config" and
                            os.path.exists(lock_path),
                            exclusive_result)
            blocked_cli = NoLiveRpcCLI()
            blocked_cli.mode = "config"
            blocked = blocked_cli.dispatch("set system host-name blocked")
            failed += check("exclusive lock blocks other writers",
                            "configuration database is locked" in blocked,
                            blocked)
            bad_exit = exclusive_cli.dispatch("exit now")
            failed += check("config exit rejects suffix without releasing lock",
                            bad_exit == "error: unknown exit option: now" and
                            exclusive_cli.mode == "config" and
                            os.path.exists(lock_path),
                            f"{bad_exit} mode={exclusive_cli.mode}")
            exclusive_cli.dispatch("exit")
            failed += check("configuration lock is released on exit",
                            not os.path.exists(lock_path),
                            lock_path)
            quit_cli = NoLiveRpcCLI()
            quit_result = quit_cli.dispatch("configure exclusive")
            bad_quit = quit_cli.dispatch("quit now")
            failed += check("config quit rejects suffix without releasing lock",
                            bad_quit == "error: unknown quit option: now" and
                            quit_cli.mode == "config" and
                            os.path.exists(lock_path),
                            f"{bad_quit} mode={quit_cli.mode}")
            quit_cli.dispatch("quit")
            failed += check("configuration lock is released on quit",
                            "exclusive" in quit_result and
                            not os.path.exists(lock_path),
                            lock_path)
        finally:
            if old_lock is None:
                os.environ.pop("NETLAB_LAB_ONLY_CONFIG_LOCK_PATH", None)
            else:
                os.environ["NETLAB_LAB_ONLY_CONFIG_LOCK_PATH"] = old_lock

    if failed:
        print(f"FAILED: {failed} public namespace checks")
        return 1
    print("OK: public CLI namespace cleanup checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
