#!/usr/bin/env python3.11
"""Unit-check configd public L3 XML to rpd plan compilation."""
import os
import subprocess
import tempfile
from pathlib import Path

from build_support import libyang_flags


ROOT = Path(__file__).resolve().parents[2]


C_SOURCE = r'''
#include "l3_client.h"
#include "netlab/interface_id.h"
#include "netlab/yang_config.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACTIVE_SESSION ((nl_yang_session *)0x1)
#define CANDIDATE_SESSION ((nl_yang_session *)0x2)

static const char *g_active_xml = "<netlab-config/>";
static const char *g_candidate_xml = "<netlab-config/>";

char *nl_yang_to_xml(nl_yang_session *s) {
    const char *src = s == ACTIVE_SESSION ? g_active_xml : g_candidate_xml;
    char *copy = strdup(src ? src : "");
    return copy;
}

bool nl_platform_system_mac(u8 mac[NL_MAC_ADDR_LEN]) {
    mac[0] = 0x02;
    mac[1] = 0x00;
    mac[2] = 0x00;
    mac[3] = 0x00;
    mac[4] = 0x00;
    mac[5] = 0x01;
    return true;
}

bool nl_ifid_get_by_name(const char *name, nl_port_entry *out) {
    if (!name || !out)
        return false;
    memset(out, 0, sizeof(*out));
    if (strcmp(name, "et-0/0/0") == 0) {
        snprintf(out->canonical_name, sizeof(out->canonical_name), "%s", name);
        snprintf(out->role, sizeof(out->role), "external");
        snprintf(out->capabilities, sizeof(out->capabilities), "L2,ROUTE");
        out->flags = NL_PORT_FLAG_EXTERNAL;
        out->logical_port = 1;
        return true;
    }
    if (strcmp(name, "et-0/0/1") == 0) {
        snprintf(out->canonical_name, sizeof(out->canonical_name), "%s", name);
        snprintf(out->role, sizeof(out->role), "external");
        snprintf(out->capabilities, sizeof(out->capabilities), "L2");
        out->flags = NL_PORT_FLAG_EXTERNAL;
        out->logical_port = 2;
        return true;
    }
    return false;
}

static int check(const char *name, int ok, const char *detail) {
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok && detail && detail[0])
        printf("%s\n", detail);
    return ok ? 0 : 1;
}

static int plan_contains(const char *plan, const char *needle) {
    return strstr(plan, needle) != NULL;
}

static int plan_ordered(const char *plan, const char *first,
                        const char *second) {
    const char *first_pos = strstr(plan, first);
    const char *second_pos = strstr(plan, second);

    return first_pos && second_pos && first_pos < second_pos;
}

static int compile_plan(char *plan, size_t plan_size, int *plan_len,
                        bool *has_l3, char *err, size_t err_size) {
    return configd_l3_build_plan(ACTIVE_SESSION, CANDIDATE_SESSION,
                                 plan, plan_size, plan_len, has_l3,
                                 err, err_size);
}

static char *build_route_scale_xml(int routes) {
    size_t capacity = 512U + (size_t)routes * 192U;
    char *xml = calloc(1, capacity);
    size_t off;

    if (!xml)
        return NULL;
    off = (size_t)snprintf(
        xml, capacity,
        "<netlab-config><interfaces-routing><interface>"
        "<name>irb.100</name><address>192.0.2.1/24</address>"
        "</interface></interfaces-routing><routing-options><static>");
    for (int i = 0; i < routes; i++) {
        int n = snprintf(
            xml + off, capacity - off,
            "<route><prefix>10.%d.%d.0/24</prefix>"
            "<next-hop-address>192.0.2.254</next-hop-address></route>",
            i / 256, i % 256);

        if (n < 0 || (size_t)n >= capacity - off) {
            free(xml);
            return NULL;
        }
        off += (size_t)n;
    }
    if ((size_t)snprintf(xml + off, capacity - off,
                         "</static></routing-options></netlab-config>") >=
        capacity - off) {
        free(xml);
        return NULL;
    }
    return xml;
}

static int count_plan_lines(const char *plan, const char *prefix) {
    int count = 0;
    size_t prefix_len = strlen(prefix);

    for (const char *line = plan; line && *line; ) {
        if (strncmp(line, prefix, prefix_len) == 0)
            count++;
        line = strchr(line, '\n');
        if (line)
            line++;
    }
    return count;
}

int main(void) {
    const char *public_l3_xml =
        "<netlab-config>"
        "  <interfaces-routing>"
        "    <interface>"
        "      <name>irb.100</name>"
        "      <address>192.0.2.1/24</address>"
        "    </interface>"
        "    <interface>"
        "      <name>irb.101</name>"
        "      <address>192.0.3.1/24</address>"
        "    </interface>"
        "  </interfaces-routing>"
        "  <routing-options>"
        "    <autonomous-system>65001</autonomous-system>"
        "    <static>"
        "      <arp>"
        "        <ip>192.0.2.2</ip>"
        "        <mac>02:00:00:00:02:02</mac>"
        "      </arp>"
        "      <arp>"
        "        <ip>192.0.2.3</ip>"
        "        <mac>02:00:00:00:02:03</mac>"
        "      </arp>"
        "      <route>"
        "        <prefix>203.0.113.0/24</prefix>"
        "        <next-hop-address>192.0.2.2</next-hop-address>"
        "        <next-hop-address>192.0.2.3</next-hop-address>"
        "      </route>"
        "    </static>"
        "  </routing-options>"
        "  <policy-options>"
        "    <policy-statement>"
        "      <name>EXPORT</name>"
        "      <term>"
        "        <name>t1</name>"
        "        <from>"
        "          <route-filter>"
        "            <prefix>203.0.113.0/24</prefix>"
        "            <match-type>exact</match-type>"
        "          </route-filter>"
        "        </from>"
        "        <then><action>accept</action></then>"
        "      </term>"
        "      <term>"
        "        <name>t2</name>"
        "        <from>"
        "          <route-filter>"
        "            <prefix>198.51.100.0/24</prefix>"
        "            <match-type>exact</match-type>"
        "          </route-filter>"
        "        </from>"
        "        <then><action>reject</action></then>"
        "      </term>"
        "    </policy-statement>"
        "  </policy-options>"
        "  <protocols>"
        "    <ospf>"
        "      <area>"
        "        <name>0.0.0.0</name>"
        "        <interface><name>irb.100</name></interface>"
        "      </area>"
        "      <area>"
        "        <name>0.0.0.1</name>"
        "        <interface><name>irb.101</name></interface>"
        "      </area>"
        "    </ospf>"
        "    <bgp>"
        "      <group>"
        "        <name>underlay</name>"
        "        <type>external</type>"
        "        <hold-time>900</hold-time>"
        "        <export>EXPORT</export>"
        "        <neighbor>"
        "          <address>192.0.2.2</address>"
        "          <peer-as>65002</peer-as>"
        "        </neighbor>"
        "      </group>"
        "      <group>"
        "        <name>overlay</name>"
        "        <type>internal</type>"
        "        <neighbor>"
        "          <address>192.0.2.3</address>"
        "          <peer-as>65001</peer-as>"
        "        </neighbor>"
        "      </group>"
        "    </bgp>"
        "  </protocols>"
        "</netlab-config>";
    char plan[32768] = {0};
    char err[1024] = {0};
    int plan_len = 0;
    bool has_l3 = false;
    int failed = 0;

    g_candidate_xml = public_l3_xml;
    failed += check("public L3 XML compiles to rpd plan",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) == 0,
                    err);
    failed += check("compiled public L3 plan is marked L3",
                    has_l3 && plan_len == (int)strlen(plan), plan);
    failed += check("interfaces irb becomes routed interface intent",
                    plan_contains(plan,
                                  "rif name irb.100 vlan 100 "
                                  "address 192.0.2.1/24 table inet.0\n"),
                    plan);
    failed += check("routing-options autonomous-system becomes BGP local AS",
                    plan_contains(plan,
                                  "protocol bgp local-as 65001 "
                                  "table inet.0\n"),
                    plan);
    failed += check("public static ARP facade infers connected RIF",
                    plan_contains(plan,
                                  "arp ip 192.0.2.2 mac 02:00:00:00:02:02 "
                                  "interface irb.100 table inet.0\n") &&
                    plan_contains(plan,
                                  "arp ip 192.0.2.3 mac 02:00:00:00:02:03 "
                                  "interface irb.100 table inet.0\n"),
                    plan);
    failed += check("public static route next-hop addresses auto-compile to ECMP",
                    plan_contains(plan,
                                  "next-hop id 60000 arp 192.0.2.2 "
                                  "interface irb.100 table inet.0\n") &&
                    plan_contains(plan,
                                  "next-hop id 60001 arp 192.0.2.3 "
                                  "interface irb.100 table inet.0\n") &&
                    plan_contains(plan,
                                  "ecmp id 60000 members 60000,60001 "
                                  "table inet.0\n") &&
                    plan_contains(plan,
                                  "route prefix 203.0.113.0/24 ecmp 60000 "
                                  "table inet.0\n"),
                    plan);
    failed += check("policy-options route-filter becomes export policy",
                    plan_contains(plan,
                                  "policy statement EXPORT term t1 "
                                  "route-filter 203.0.113.0/24 exact "
                                  "then accept\n") &&
                    plan_contains(plan,
                                  "policy statement EXPORT term t2 "
                                  "route-filter 198.51.100.0/24 exact "
                                  "then reject\n"),
                    plan);
    failed += check("protocols ospf area interface becomes FRR intent",
                    plan_contains(plan,
                                  "protocol ospf area 0.0.0.0 "
                                  "interface irb.100 table inet.0\n") &&
                    plan_contains(plan,
                                  "protocol ospf area 0.0.0.1 "
                                  "interface irb.101 table inet.0\n"),
                    plan);
    failed += check("protocols bgp group neighbor export becomes FRR intent",
                    plan_contains(plan,
                                  "protocol bgp group underlay type external "
                                  "table inet.0\n") &&
                    plan_contains(plan,
                                  "protocol bgp group underlay hold-time 900 "
                                  "table inet.0\n") &&
                    plan_contains(plan,
                                  "protocol bgp group underlay export EXPORT "
                                  "table inet.0\n") &&
                    plan_contains(plan,
                                  "protocol bgp group underlay neighbor "
                                  "192.0.2.2 peer-as 65002 table inet.0\n"),
                    plan);
    failed += check("protocols bgp internal group compiles to FRR intent",
                    plan_contains(plan,
                                  "protocol bgp group overlay type internal "
                                  "table inet.0\n") &&
                    plan_contains(plan,
                                  "protocol bgp group overlay neighbor "
                                  "192.0.2.3 peer-as 65001 table inet.0\n"),
                    plan);
    failed += check("compiled L3 plan carries platform router MAC",
                    plan_contains(plan,
                                  "router-mac 02:00:00:00:00:01\n"),
                    plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <interfaces-routing>"
        "    <interface>"
        "      <name>irb.100</name>"
        "      <address>192.0.2.1/24</address>"
        "    </interface>"
        "  </interfaces-routing>"
        "  <routing-options>"
        "    <static>"
        "      <route>"
        "        <prefix>203.0.113.0/24</prefix>"
        "        <next-hop-address>192.0.2.254</next-hop-address>"
        "      </route>"
        "    </static>"
        "  </routing-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("static route next-hop without ARP becomes pending RIB intent",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) == 0 &&
                    plan_contains(plan,
                                  "rif name irb.100 vlan 100 "
                                  "address 192.0.2.1/24 table inet.0\n") &&
                    plan_contains(plan,
                                  "rib-static-route prefix 203.0.113.0/24 "
                                  "nexthops 192.0.2.254@irb.100 "
                                  "table inet.0\n") &&
                    !plan_contains(plan,
                                   "\nroute prefix 203.0.113.0/24"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <interfaces-routing>"
        "    <interface>"
        "      <name>irb.100</name>"
        "      <address>192.0.2.1/24</address>"
        "    </interface>"
        "  </interfaces-routing>"
        "  <routing-options>"
        "    <static>"
        "      <route>"
        "        <prefix>203.0.113.0/24</prefix>"
        "        <next-hop-address>198.51.100.254</next-hop-address>"
        "      </route>"
        "    </static>"
        "  </routing-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("off-link static route next-hop remains fail-closed",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err,
                           "static route next-hop 198.51.100.254 has no connected routed interface"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <policy-options>"
        "    <policy-statement><name>EXPORT</name>"
        "      <term><name>bad</name>"
        "        <from><route-filter><prefix>203.0.113.0/24</prefix>"
        "          <match-type>longer</match-type></route-filter></from>"
        "        <then><action>accept</action></then>"
        "      </term>"
        "    </policy-statement>"
        "  </policy-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("policy route-filter match-type is fail-closed",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err, "unsupported policy route-filter match-type"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <policy-options>"
        "    <policy-statement><name>EXPORT</name>"
        "      <term><name>bad</name>"
        "        <from><route-filter><prefix>203.0.113.0/24</prefix>"
        "          <match-type>exact</match-type></route-filter></from>"
        "        <then><action>next-policy</action></then>"
        "      </term>"
        "    </policy-statement>"
        "  </policy-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("policy action is fail-closed to accept or reject",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err, "unsupported policy action"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <policy-options>"
        "    <policy-statement><name>EXPORT</name>"
        "      <term><name>bad</name>"
        "        <from></from>"
        "        <then><action>accept</action></then>"
        "      </term>"
        "    </policy-statement>"
        "  </policy-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("policy without route-filter is fail-closed",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err,
                           "incomplete policy term; from route-filter is required"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <interfaces-routing>"
        "    <interface>"
        "      <name>irb.100</name>"
        "      <address>192.0.2.1/24</address>"
        "    </interface>"
        "    <interface>"
        "      <name>irb.101</name>"
        "      <address>192.0.2.129/24</address>"
        "    </interface>"
        "  </interfaces-routing>"
        "  <routing-options>"
        "    <static>"
        "      <arp>"
        "        <ip>192.0.2.2</ip>"
        "        <mac>02:00:00:00:02:02</mac>"
        "      </arp>"
        "    </static>"
        "  </routing-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("ambiguous static ARP RIF inference is rejected",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err, "matches multiple routed interfaces"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <interfaces>"
        "    <interface><name>et-0/0/0</name>"
        "      <description>routed uplink</description>"
        "    </interface>"
        "  </interfaces>"
        "  <interfaces-routing>"
        "    <interface>"
        "      <name>et-0/0/0.0</name>"
        "      <address>198.51.100.1/31</address>"
        "    </interface>"
        "  </interfaces-routing>"
        "  <routing-options><static>"
        "    <arp><ip>198.51.100.0</ip>"
        "      <mac>02:00:00:00:03:02</mac>"
        "      <egress-interface>et-0/0/0</egress-interface>"
        "    </arp>"
        "    <route><prefix>203.0.113.0/24</prefix>"
        "      <next-hop-address>198.51.100.0</next-hop-address>"
        "    </route>"
        "  </static></routing-options>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("physical routed interface compiles with stable internal VLAN",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) == 0 &&
                    plan_contains(plan,
                                  "rif name et-0/0/0.0 vlan 4094 "
                                  "port et-0/0/0 address 198.51.100.1/31 "
                                  "table inet.0\n") &&
                    plan_contains(plan,
                                  "arp ip 198.51.100.0 "
                                  "mac 02:00:00:00:03:02 "
                                  "interface et-0/0/0.0 "
                                  "egress-port et-0/0/0 table inet.0\n") &&
                    plan_contains(plan,
                                  "next-hop id 60000 arp 198.51.100.0 "
                                  "interface et-0/0/0.0 table inet.0\n") &&
                    plan_contains(plan,
                                  "route prefix 203.0.113.0/24 "
                                  "next-hop 60000 table inet.0\n"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <vlans><vlan><name>reserved</name><vlan-id>4094</vlan-id>"
        "  </vlan></vlans>"
        "  <interfaces-routing><interface>"
        "    <name>et-0/0/0.0</name><address>198.51.100.1/31</address>"
        "  </interface></interfaces-routing>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    failed += check("physical routed interface rejects configured VLAN collision",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err, "internal VLAN 4094 conflicts"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <interfaces><interface><name>et-0/0/0</name>"
        "    <unit><logical-unit><unit-id>0</unit-id><family>"
        "      <ethernet-switching><interface-mode>access</interface-mode>"
        "      </ethernet-switching>"
        "    </family></logical-unit></unit>"
        "  </interface></interfaces>"
        "  <interfaces-routing><interface>"
        "    <name>et-0/0/0.0</name><address>198.51.100.1/31</address>"
        "  </interface></interfaces-routing>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    failed += check("physical routed interface rejects same-port L2 intent",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err, "conflicts with Layer-2 intent"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config><interfaces-routing><interface>"
        "  <name>et-0/0/1.0</name><address>198.51.100.1/31</address>"
        "</interface></interfaces-routing></netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    failed += check("physical routed interface requires ROUTE capability",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) != 0 &&
                    strstr(err, "not an external ROUTE-capable"),
                    err[0] ? err : plan);

    g_candidate_xml =
        "<netlab-config>"
        "  <interfaces-routing><interface>"
        "    <name>et-0/0/0.0</name><address>198.51.100.1/31</address>"
        "  </interface></interfaces-routing>"
        "  <routing-instances><instance>"
        "    <name>blue</name><instance-type>vrf</instance-type>"
        "    <virtual-router-id>1</virtual-router-id>"
        "    <kernel-table>1001</kernel-table>"
        "    <interface>et-0/0/0.0</interface>"
        "    <routing-options><static>"
        "      <arp><ip>198.51.100.0</ip>"
        "        <mac>02:00:00:00:03:02</mac>"
        "        <interface>et-0/0/0.0</interface>"
        "        <egress-interface>et-0/0/0</egress-interface>"
        "      </arp>"
        "      <route><prefix>203.0.113.0/24</prefix>"
        "        <next-hop-address>198.51.100.0</next-hop-address>"
        "      </route>"
        "    </static></routing-options>"
        "  </instance></routing-instances>"
        "</netlab-config>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("single VRF V1 compiles table-scoped RIF and static route",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) == 0 &&
                    plan_contains(plan, "l3-plan version=2\n") &&
                    plan_contains(plan,
                                  "virtual-router name blue "
                                  "table blue.inet.0 vrid 1 "
                                  "kernel-table 1001\n") &&
                    plan_contains(plan,
                                  "rif name et-0/0/0.0 vlan 4094 "
                                  "port et-0/0/0 address 198.51.100.1/31 "
                                  "table blue.inet.0\n") &&
                    plan_contains(plan,
                                  "arp ip 198.51.100.0 "
                                  "mac 02:00:00:00:03:02 "
                                  "interface et-0/0/0.0 "
                                  "egress-port et-0/0/0 "
                                  "table blue.inet.0\n") &&
                    plan_contains(plan,
                                  "route prefix 203.0.113.0/24 "
                                  "next-hop 60000 table blue.inet.0\n") &&
                    plan_ordered(plan, "virtual-router name blue ",
                                 "rif name et-0/0/0.0 ") &&
                    plan_ordered(plan, "rif name et-0/0/0.0 ",
                                 "arp ip 198.51.100.0 ") &&
                    plan_ordered(plan, "arp ip 198.51.100.0 ",
                                 "next-hop id 60000 ") &&
                    plan_ordered(plan, "next-hop id 60000 ",
                                 "route prefix 203.0.113.0/24 "),
                    err[0] ? err : plan);

    g_active_xml = public_l3_xml;
    g_candidate_xml = "<netlab-config/>";
    memset(plan, 0, sizeof(plan));
    err[0] = '\0';
    plan_len = 0;
    has_l3 = false;
    failed += check("active L3 deletion compiles an owner-clearing plan",
                    compile_plan(plan, sizeof(plan), &plan_len,
                                 &has_l3, err, sizeof(err)) == 0 &&
                    has_l3 &&
                    plan_contains(plan, "l3-plan version=1\n") &&
                    plan_contains(plan,
                                  "router-mac 02:00:00:00:00:01\n"),
                    err[0] ? err : plan);

    {
        static const int scales[] = {1, 128, 512, 1024};
        char *scale_plan = calloc(1, NL_L3_PLAN_MAX_BYTES);

        if (!scale_plan) {
            failed += check("L3 route scale plan workspace allocates", 0,
                            "out of memory");
        } else {
            for (size_t i = 0; i < sizeof(scales) / sizeof(scales[0]); i++) {
                char *scale_xml = build_route_scale_xml(scales[i]);
                char name[128];
                int scale_len = 0;
                bool scale_has_l3 = false;

                memset(scale_plan, 0, NL_L3_PLAN_MAX_BYTES);
                err[0] = '\0';
                g_active_xml = "<netlab-config/>";
                g_candidate_xml = scale_xml;
                snprintf(name, sizeof(name),
                         "%d-route public L3 plan fits bounded IPC workspace",
                         scales[i]);
                failed += check(
                    name,
                    scale_xml &&
                    compile_plan(scale_plan, NL_L3_PLAN_MAX_BYTES,
                                 &scale_len, &scale_has_l3,
                                 err, sizeof(err)) == 0 &&
                    scale_has_l3 && scale_len > 0 &&
                    scale_len < (int)NL_L3_PLAN_MAX_BYTES &&
                    count_plan_lines(scale_plan,
                                     "rib-static-route ") == scales[i],
                    err[0] ? err : scale_plan);
                if (scales[i] == 1024)
                    failed += check(
                        "1024-route legal plan exceeds the removed 16 KiB cap",
                        scale_len > 16384,
                        scale_plan);
                if (scales[i] == 1024) {
                    int small_len = 0;
                    bool small_has_l3 = false;
                    char small_plan[4096];

                    err[0] = '\0';
                    failed += check(
                        "undersized L3 workspace fails explicitly",
                        compile_plan(small_plan, sizeof(small_plan),
                                     &small_len, &small_has_l3,
                                     err, sizeof(err)) != 0 &&
                        strstr(err, "L3 plan exceeds buffer"),
                        err);
                }
                free(scale_xml);
            }
            free(scale_plan);
        }
    }

    return failed ? 1 : 0;
}
'''


def main():
    env = os.environ.copy()
    libyang_cflags, _, _ = libyang_flags()
    with tempfile.TemporaryDirectory(prefix="configd-l3-build-plan-") as td:
        stack_frames: list[tuple[str, int]] = []
        for source_name in ("main.c", "l3_client.c"):
            source = ROOT / "sbin" / "configd" / source_name
            stack_obj = Path(td) / (source.stem + "_stack.o")
            stack_build = subprocess.run(
                [
                    "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                    "-pedantic", "-Wno-format-truncation", "-O2",
                    "-D_GNU_SOURCE",
                    "-Wframe-larger-than=262144", "-fstack-usage",
                    "-I", str(ROOT / "include"),
                    "-I", str(ROOT / "sbin" / "configd"),
                    *libyang_cflags,
                    "-c", str(source), "-o", str(stack_obj),
                ],
                cwd=str(ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                check=False,
            )
            print(stack_build.stdout, end="")
            if stack_build.returncode != 0:
                return 1
            usage = stack_obj.with_suffix(".su").read_text(
                encoding="utf-8")
            for line in usage.splitlines():
                fields = line.split("\t")
                if len(fields) >= 2:
                    stack_frames.append((fields[0], int(fields[1])))
        largest = max((frame for _, frame in stack_frames), default=-1)
        if largest < 0 or largest > 262144:
            print("FAIL: configd L3 plan paths stay below 256 KiB frames")
            print(f"largest={largest}")
            return 1
        print(
            "PASS: configd L3 plan paths stay below 256 KiB frames "
            f"(largest={largest} bytes)"
        )

        src = Path(td) / "test_configd_l3_build_plan.c"
        binary = Path(td) / "test_configd_l3_build_plan"
        src.write_text(C_SOURCE)
        build = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-g", "-O0", "-D_GNU_SOURCE",
                "-ffunction-sections", "-fdata-sections",
                "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin" / "configd"),
                *libyang_cflags,
                str(src),
                str(ROOT / "sbin" / "configd" / "l3_client.c"),
                "-Wl,--gc-sections",
                "-o", str(binary),
            ],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        print(build.stdout, end="")
        if build.returncode != 0:
            return 1
        run = subprocess.run(
            [str(binary)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        print(run.stdout, end="")
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
