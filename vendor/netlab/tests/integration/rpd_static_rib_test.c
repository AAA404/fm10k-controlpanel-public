#include "rib.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, int ok) {
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    return ok ? 0 : 1;
}

static const rpd_rib_arp *find_arp(const rpd_rib *rib, const char *ip,
                                   const char *rif) {
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++) {
        const rpd_rib_arp *arp = &rib->arps[i];

        if (arp->active && strcmp(arp->ip, ip) == 0 &&
            strcmp(arp->rif, rif) == 0)
            return arp;
    }
    return NULL;
}

static const rpd_rib_route *find_route(const rpd_rib *rib, const char *prefix,
                                       const char *protocol) {
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        const rpd_rib_route *route = &rib->routes[i];

        if (route->active && strcmp(route->prefix, prefix) == 0 &&
            strcmp(route->protocol, protocol) == 0)
            return route;
    }
    return NULL;
}

int main(void) {
    const char *valid_plan =
        "rif name irb.100 vlan 100 address 192.0.2.1/24\n"
        "next-hop id 1 arp 192.0.2.2 interface irb.100\n"
        "arp ip 192.0.2.2 mac 02:00:00:00:02:02 interface irb.100 "
        "egress-port et-0/0/1\n"
        "route prefix 203.0.113.0/24 next-hop 1\n";
    const char *replacement_plan =
        "rif name irb.200 vlan 200 address 192.0.3.1/24\n"
        "next-hop id 2 arp 192.0.3.2 interface irb.200\n"
        "arp ip 192.0.3.2 mac 02:00:00:00:03:02 interface irb.200 "
        "egress-port et-0/0/2\n"
        "route prefix 203.0.114.0/24 next-hop 2\n";
    const char *physical_plan =
        "rif name et-0/0/0.0 vlan 4094 port et-0/0/0 "
        "address 198.51.100.1/31\n"
        "arp ip 198.51.100.0 mac 02:00:00:00:03:02 "
        "interface et-0/0/0.0 egress-port et-0/0/0\n"
        "next-hop id 1 arp 198.51.100.0 interface et-0/0/0.0\n"
        "route prefix 203.0.113.0/24 next-hop 1\n";
    const char *missing_arp_plan =
        "rif name irb.100 vlan 100 address 192.0.2.1/24\n"
        "next-hop id 1 arp 192.0.2.2 interface irb.100\n"
        "route prefix 203.0.113.0/24 next-hop 1\n";
    const char *pending_static_plan =
        "rif name irb.100 vlan 100 address 192.0.2.1/24\n"
        "rib-static-route prefix 203.0.113.0/24 "
        "nexthops 192.0.2.2@irb.100\n";
    const char *static_ecmp_plan =
        "rif name irb.100 vlan 100 address 192.0.2.1/24\n"
        "arp ip 192.0.2.2 mac 02:00:00:00:02:02 interface irb.100\n"
        "arp ip 192.0.2.3 mac 02:00:00:00:02:03 interface irb.100\n"
        "next-hop id 1 arp 192.0.2.2 interface irb.100\n"
        "next-hop id 2 arp 192.0.2.3 interface irb.100\n"
        "ecmp id 10 members 1,2\n"
        "route prefix 203.0.113.0/24 ecmp 10\n";
    const char *multicast_static_plan =
        "rif name irb.100 vlan 100 address 192.0.2.1/24\n"
        "arp ip 192.0.2.2 mac 02:00:00:00:02:02 interface irb.100\n"
        "next-hop id 1 arp 192.0.2.2 interface irb.100\n"
        "route prefix 224.0.0.0/4 next-hop 1\n";
    const char *resolved_update =
        "op=replace protocol=bgp prefix=198.51.100.0/24 "
        "nexthop=192.0.2.2 rif=irb.100 key=bgp-resolved\n";
    const char *ospf_over_static =
        "op=replace protocol=ospf prefix=203.0.113.0/24 "
        "metric=10 nexthop=192.0.2.2 rif=irb.100 "
        "key=ospf-over-static\n";
    const char *unresolved_update =
        "op=replace protocol=bgp prefix=198.51.100.0/24 "
        "nexthop=192.0.2.2 rif=irb.100 key=bgp-unresolved\n";
    const char *linux_arp =
        "arp ip 192.0.2.2 mac 02:00:00:00:02:22 "
        "interface irb.100 egress-port et-0/0/2\n";
    const char *table_scoped_plan =
        "rif name irb.100 vlan 100 address 192.0.2.1/24 table inet.0\n"
        "rif name vlan200 vlan 200 address 198.18.0.1/24 "
        "table blue.inet.0\n"
        "arp ip 198.18.0.2 mac 02:00:00:00:20:02 interface vlan200 "
        "table blue.inet.0\n"
        "next-hop id 200 arp 198.18.0.2 interface vlan200 "
        "table blue.inet.0\n"
        "route prefix 203.0.113.0/24 next-hop 200 "
        "table blue.inet.0\n";
    const char *vrf_fpm_update =
        "op=replace protocol=bgp prefix=198.51.100.0/24 "
        "table-id=1001 nexthop=198.18.0.2 rif=vlan200 key=vrf-bgp\n";
    static rpd_rib rib;
    static rpd_rib physical_rib;
    static rpd_rib rollback_rib;
    static rpd_rib vrf_rib;
    static rpd_rib scoped_global_rib;
    rpd_rib_stats stats;
    rpd_rib_update_result result;
    const rpd_rib_arp *arp;
    char err[192];
    char xml[8192];
    char fib[8192];
    size_t off = 0;
    int failed = 0;
    int routes_out = -1;
    int rc;

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, valid_plan, (int)strlen(valid_plan),
                                  7, 3, &result, err, sizeof(err));
    failed += check("static plan with ARP syncs", rc == 0);
    rpd_rib_get_stats(&rib, &stats);
    failed += check("static plan creates connected static and ARP entries",
                    stats.connected == 1 && stats.static_routes == 1 &&
                    stats.arp_entries == 1);
    arp = find_arp(&rib, "192.0.2.2", "irb.100");
    failed += check("ARP intent preserves MAC egress and generation",
                    arp && strcmp(arp->mac, "02:00:00:00:02:02") == 0 &&
                    strcmp(arp->egress_port, "et-0/0/1") == 0 &&
                    strcmp(arp->source, "static") == 0 &&
                    strcmp(arp->installed_state, "owner-applied") == 0 &&
                    arp->generation == 7 && arp->fib_update_id == 3);

    rpd_rib_init(&physical_rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(
        &physical_rib, physical_plan, (int)strlen(physical_plan),
        8, 4, &result, err, sizeof(err));
    rpd_rib_get_stats(&physical_rib, &stats);
    failed += check("physical RIF plan syncs through static RIB parser",
                    rc == 0 && stats.connected == 1 &&
                    stats.static_routes == 1 && stats.arp_entries == 1);

    rpd_rib_init(&scoped_global_rib);
    failed += check("VRF RIB scope initializes with fixed kernel table",
                    rpd_rib_init_scope(&vrf_rib, "blue.inet.0", 1001) == 0);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&scoped_global_rib, table_scoped_plan,
                                  (int)strlen(table_scoped_plan),
                                  8, 4, &result, err, sizeof(err));
    rpd_rib_get_stats(&scoped_global_rib, &stats);
    failed += check("global RIB ignores VRF-scoped static records",
                    rc == 0 && stats.connected == 1 &&
                    stats.static_routes == 0 && stats.arp_entries == 0);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&vrf_rib, table_scoped_plan,
                                  (int)strlen(table_scoped_plan),
                                  8, 4, &result, err, sizeof(err));
    rpd_rib_get_stats(&vrf_rib, &stats);
    failed += check("VRF RIB imports only its table-scoped owner objects",
                    rc == 0 && stats.connected == 1 &&
                    stats.static_routes == 1 && stats.arp_entries == 1);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_apply_fpm_text(&vrf_rib, vrf_fpm_update,
                                (int)strlen(vrf_fpm_update),
                                9, 5, &result, err, sizeof(err));
    failed += check("VRF FPM table id selects the VRF RIB",
                    rc == 0 && find_route(&vrf_rib,
                                          "198.51.100.0/24", "bgp"));
    memset(err, 0, sizeof(err));
    rc = rpd_rib_apply_fpm_text(&scoped_global_rib, vrf_fpm_update,
                                (int)strlen(vrf_fpm_update),
                                9, 5, &result, err, sizeof(err));
    failed += check("VRF FPM update cannot cross into global RIB",
                    rc != 0 && strstr(err, "does not match RIB"));
    fib[0] = '\0';
    routes_out = -1;
    failed += check("VRF RIB compiles a table-scoped FIB batch",
                    rpd_rib_compile_fib_batch(&vrf_rib, 9, 5, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    strstr(fib, "fib-batch table=blue.inet.0") &&
                    strstr(fib, "prefix=198.51.100.0/24"));

    xml[0] = '\0';
    failed += check("RIB XML appends with ARP table",
                    rpd_rib_append_xml(&rib, xml, sizeof(xml), &off) == 0 &&
                    strstr(xml, "<arp-table entries=\"1\"") &&
                    strstr(xml, "ip=\"192.0.2.2\"") &&
                    strstr(xml, "source=\"static\"") &&
                    strstr(xml, "fib-update-id=\"3\""));

    rc = rpd_rib_apply_fpm_text(&rib, resolved_update,
                                (int)strlen(resolved_update),
                                8, 4, &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "198.51.100.0/24", "bgp");
        failed += check("resolved dynamic route stays pending-fib",
                        rc == 0 && route &&
                        strcmp(route->installed_state, "pending-fib") == 0);
    }
    fib[0] = '\0';
    routes_out = -1;
    failed += check("resolved dynamic route enters FIB batch",
                    rpd_rib_compile_fib_batch(&rib, 8, 4, fib, sizeof(fib),
                                              &routes_out) > 0 &&
                    routes_out >= 3 &&
                    strstr(fib, "prefix=198.51.100.0/24"));
    fib[0] = '\0';
    routes_out = -1;
    failed += check("resolved dynamic route compiles as FIB delta replace",
                    rpd_rib_compile_fib_delta(&rib, &result, 8, 4, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    routes_out == 1 &&
                    strstr(fib, "mode=delta") &&
                    strstr(fib, "fib-route op=replace "
                           "prefix=198.51.100.0/24") &&
                    strstr(fib, "owner-role=dynamic-fib"));

    memcpy(&rollback_rib, &rib, sizeof(rollback_rib));
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, replacement_plan,
                                  (int)strlen(replacement_plan),
                                  12, 9, &result, err, sizeof(err));
    {
        const rpd_rib_route *old_static =
            find_route(&rib, "203.0.113.0/24", "static");
        const rpd_rib_route *new_static =
            find_route(&rib, "203.0.114.0/24", "static");
        const rpd_rib_route *dynamic =
            find_route(&rib, "198.51.100.0/24", "bgp");

        failed += check("static replacement swaps static owner RIB only",
                        rc == 0 && !old_static && new_static &&
                        !find_arp(&rib, "192.0.2.2", "irb.100") &&
                        find_arp(&rib, "192.0.3.2", "irb.200") &&
                        dynamic &&
                        strcmp(dynamic->installed_state,
                               "pending-arp") == 0);
    }
    memcpy(&rib, &rollback_rib, sizeof(rib));
    {
        const rpd_rib_route *old_static =
            find_route(&rib, "203.0.113.0/24", "static");
        const rpd_rib_route *new_static =
            find_route(&rib, "203.0.114.0/24", "static");
        const rpd_rib_route *dynamic =
            find_route(&rib, "198.51.100.0/24", "bgp");

        failed += check("static rollback snapshot restores RIB and ARP state",
                        old_static && !new_static &&
                        find_arp(&rib, "192.0.2.2", "irb.100") &&
                        !find_arp(&rib, "192.0.3.2", "irb.200") &&
                        dynamic &&
                        strcmp(dynamic->installed_state,
                               "pending-fib") == 0);
    }
    fib[0] = '\0';
    routes_out = -1;
    failed += check("static rollback snapshot restores FIB batch contents",
                    rpd_rib_compile_fib_batch(&rib, 13, 10, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    routes_out >= 3 &&
                    strstr(fib, "prefix=203.0.113.0/24") &&
                    strstr(fib, "prefix=198.51.100.0/24") &&
                    !strstr(fib, "prefix=203.0.114.0/24"));

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, static_ecmp_plan,
                                  (int)strlen(static_ecmp_plan),
                                  14, 11, &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "203.0.113.0/24", "static");
        failed += check("static ECMP route keeps both nexthops in RIB",
                        rc == 0 && route &&
                        route->n_nexthops == 2 &&
                        strcmp(route->nexthops[0].address,
                               "192.0.2.2") == 0 &&
                        strcmp(route->nexthops[1].address,
                               "192.0.2.3") == 0 &&
                        strcmp(route->installed_state,
                               "owner-applied") == 0);
    }
    rpd_rib_get_stats(&rib, &stats);
    failed += check("static ECMP route contributes ECMP counters",
                    stats.static_routes == 1 && stats.ecmp_routes == 1 &&
                    stats.ecmp_members == 2 && stats.arp_entries == 2);
    fib[0] = '\0';
    routes_out = -1;
    failed += check("static ECMP route enters FIB batch with stable key",
                    rpd_rib_compile_fib_batch(&rib, 14, 11, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    routes_out == 2 &&
                    strstr(fib, "prefix=203.0.113.0/24") &&
                    strstr(fib, "protocol=static") &&
                    strstr(fib,
                           "nexthops=192.0.2.2@irb.100,192.0.2.3@irb.100") &&
                    strstr(fib, "owner-role=persistent-owner"));
    {
        const char *scale_add =
            "op=add protocol=bgp prefix=198.51.101.0/24 metric=100 "
            "nexthops=192.0.2.3@irb.100,192.0.2.2@irb.100 "
            "key=scale-add\n";
        const char *scale_shrink =
            "op=replace protocol=bgp prefix=198.51.101.0/24 metric=200 "
            "nexthop=192.0.2.2 rif=irb.100 key=scale-shrink\n";
        const char *scale_expand =
            "op=replace protocol=bgp prefix=198.51.101.0/24 metric=300 "
            "nexthops=192.0.2.2@irb.100,192.0.2.3@irb.100 "
            "key=scale-expand\n";
        const char *scale_withdraw =
            "op=withdraw protocol=bgp prefix=198.51.101.0/24 "
            "key=scale-withdraw\n";
        const char *scale_readd =
            "op=add protocol=bgp prefix=198.51.101.0/24 metric=400 "
            "nexthop=192.0.2.2 rif=irb.100 key=scale-readd\n";
        const char *scale_delete =
            "op=delete protocol=bgp prefix=198.51.101.0/24 "
            "key=scale-delete\n";
        u64 last_generation = 0;
        u64 last_fib_update_id = 0;

        memset(err, 0, sizeof(err));
        rc = rpd_rib_apply_fpm_text(&rib, scale_add,
                                    (int)strlen(scale_add),
                                    20, 20, &result, err, sizeof(err));
        fib[0] = '\0';
        routes_out = -1;
        failed += check("route-scale dynamic add compiles stable ECMP delta",
                        rc == 0 &&
                        result.generation == 20 &&
                        result.fib_update_id == 20 &&
                        result.generation > last_generation &&
                        result.fib_update_id > last_fib_update_id &&
                        rpd_rib_compile_fib_delta(&rib, &result, 20, 20,
                                                  fib, sizeof(fib),
                                                  &routes_out) > 0 &&
                        routes_out == 1 &&
                        strstr(fib, "mode=delta") &&
                        strstr(fib, "generation=20 fib-update-id=20") &&
                        strstr(fib, "fib-route op=replace "
                               "prefix=198.51.101.0/24") &&
                        strstr(fib,
                               "nexthops=192.0.2.2@irb.100,192.0.2.3@irb.100") &&
                        strstr(fib, "metric=100"));
        last_generation = result.generation;
        last_fib_update_id = result.fib_update_id;

        memset(err, 0, sizeof(err));
        rc = rpd_rib_apply_fpm_text(&rib, scale_shrink,
                                    (int)strlen(scale_shrink),
                                    21, 21, &result, err, sizeof(err));
        fib[0] = '\0';
        routes_out = -1;
        failed += check("route-scale ECMP shrink compiles single-member delta",
                        rc == 0 &&
                        result.generation > last_generation &&
                        result.fib_update_id > last_fib_update_id &&
                        rpd_rib_compile_fib_delta(&rib, &result, 21, 21,
                                                  fib, sizeof(fib),
                                                  &routes_out) > 0 &&
                        routes_out == 1 &&
                        strstr(fib, "fib-route op=replace "
                               "prefix=198.51.101.0/24") &&
                        strstr(fib, "nexthops=192.0.2.2@irb.100") &&
                        !strstr(fib, "192.0.2.3@irb.100") &&
                        strstr(fib, "metric=200"));
        last_generation = result.generation;
        last_fib_update_id = result.fib_update_id;

        memset(err, 0, sizeof(err));
        rc = rpd_rib_apply_fpm_text(&rib, scale_expand,
                                    (int)strlen(scale_expand),
                                    22, 22, &result, err, sizeof(err));
        fib[0] = '\0';
        routes_out = -1;
        failed += check("route-scale ECMP expand compiles two-member delta",
                        rc == 0 &&
                        result.generation > last_generation &&
                        result.fib_update_id > last_fib_update_id &&
                        rpd_rib_compile_fib_delta(&rib, &result, 22, 22,
                                                  fib, sizeof(fib),
                                                  &routes_out) > 0 &&
                        routes_out == 1 &&
                        strstr(fib,
                               "nexthops=192.0.2.2@irb.100,192.0.2.3@irb.100") &&
                        strstr(fib, "metric=300"));
        last_generation = result.generation;
        last_fib_update_id = result.fib_update_id;

        memset(err, 0, sizeof(err));
        rc = rpd_rib_apply_fpm_text(&rib, scale_withdraw,
                                    (int)strlen(scale_withdraw),
                                    23, 23, &result, err, sizeof(err));
        fib[0] = '\0';
        routes_out = -1;
        failed += check("route-scale withdraw compiles FIB delete delta",
                        rc == 0 &&
                        result.generation > last_generation &&
                        result.fib_update_id > last_fib_update_id &&
                        rpd_rib_compile_fib_delta(&rib, &result, 23, 23,
                                                  fib, sizeof(fib),
                                                  &routes_out) > 0 &&
                        routes_out == 1 &&
                        strstr(fib, "fib-route op=delete "
                               "prefix=198.51.101.0/24"));
        last_generation = result.generation;
        last_fib_update_id = result.fib_update_id;

        memset(err, 0, sizeof(err));
        rc = rpd_rib_apply_fpm_text(&rib, scale_readd,
                                    (int)strlen(scale_readd),
                                    24, 24, &result, err, sizeof(err));
        failed += check("route-scale re-add after withdraw advances IDs",
                        rc == 0 &&
                        result.generation > last_generation &&
                        result.fib_update_id > last_fib_update_id);
        last_generation = result.generation;
        last_fib_update_id = result.fib_update_id;

        memset(err, 0, sizeof(err));
        rc = rpd_rib_apply_fpm_text(&rib, scale_delete,
                                    (int)strlen(scale_delete),
                                    25, 25, &result, err, sizeof(err));
        fib[0] = '\0';
        routes_out = -1;
        failed += check("route-scale explicit delete compiles FIB delete delta",
                        rc == 0 &&
                        result.generation > last_generation &&
                        result.fib_update_id > last_fib_update_id &&
                        rpd_rib_compile_fib_delta(&rib, &result, 25, 25,
                                                  fib, sizeof(fib),
                                                  &routes_out) > 0 &&
                        routes_out == 1 &&
                        strstr(fib, "fib-route op=delete "
                               "prefix=198.51.101.0/24"));
    }

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, valid_plan, (int)strlen(valid_plan),
                                  15, 12, &result, err, sizeof(err));
    failed += check("static preference fixture syncs", rc == 0);
    rc = rpd_rib_apply_fpm_text(&rib, ospf_over_static,
                                (int)strlen(ospf_over_static),
                                16, 13, &result, err, sizeof(err));
    fib[0] = '\0';
    routes_out = -1;
    {
        const rpd_rib_route *static_route =
            find_route(&rib, "203.0.113.0/24", "static");
        const rpd_rib_route *ospf_route =
            find_route(&rib, "203.0.113.0/24", "ospf");

        failed += check("static wins over OSPF by preference",
                        rc == 0 && static_route && ospf_route &&
                        static_route->preference == 5 &&
                        ospf_route->preference == 10 &&
                        rpd_rib_compile_fib_batch(&rib, 16, 13, fib,
                                                  sizeof(fib),
                                                  &routes_out) > 0 &&
                        strstr(fib,
                               "prefix=203.0.113.0/24 protocol=static") &&
                        !strstr(fib,
                                "prefix=203.0.113.0/24 protocol=ospf"));
    }

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_apply_fpm_text(&rib, unresolved_update,
                                (int)strlen(unresolved_update),
                                9, 5, &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "198.51.100.0/24", "bgp");
        failed += check("unresolved dynamic route is pending-arp",
                        rc == 0 && route &&
                        strcmp(route->installed_state, "pending-arp") == 0);
    }
    fib[0] = '\0';
    routes_out = -1;
    failed += check("unresolved dynamic route is held from FIB batch",
                    rpd_rib_compile_fib_batch(&rib, 9, 5, fib, sizeof(fib),
                                              &routes_out) > 0 &&
                    routes_out == 0 &&
                    !strstr(fib, "prefix=198.51.100.0/24"));
    fib[0] = '\0';
    routes_out = -1;
    failed += check("unresolved dynamic route compiles as FIB delta delete",
                    rpd_rib_compile_fib_delta(&rib, &result, 9, 5, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    routes_out == 1 &&
                    strstr(fib, "mode=delta") &&
                    strstr(fib, "fib-route op=delete "
                           "prefix=198.51.100.0/24"));
    rc = rpd_rib_sync_dynamic_arp_text(&rib, linux_arp,
                                       (int)strlen(linux_arp),
                                       10, 6, &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "198.51.100.0/24", "bgp");
        arp = find_arp(&rib, "192.0.2.2", "irb.100");
        failed += check("linux ARP resolves dynamic route",
                        rc == 0 && route && arp &&
                        strcmp(arp->source, "linux") == 0 &&
                        strcmp(route->installed_state, "pending-fib") == 0);
    }
    fib[0] = '\0';
    routes_out = -1;
    failed += check("linux-resolved route enters FIB batch",
                    rpd_rib_compile_fib_batch(&rib, 10, 6, fib, sizeof(fib),
                                              &routes_out) > 0 &&
                    routes_out == 1 &&
                    strstr(fib, "prefix=198.51.100.0/24") &&
                    strstr(fib, "owner-role=dynamic-fib"));
    rc = rpd_rib_sync_dynamic_arp_text(&rib, "", 0, 11, 7,
                                       &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "198.51.100.0/24", "bgp");
        failed += check("linux ARP removal returns route to pending-arp",
                        rc == 0 && route &&
                        !find_arp(&rib, "192.0.2.2", "irb.100") &&
                        strcmp(route->installed_state, "pending-arp") == 0);
    }

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, pending_static_plan,
                                  (int)strlen(pending_static_plan),
                                  15, 12, &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "203.0.113.0/24", "static");
        failed += check("static route without ARP enters RIB pending ARP",
                        rc == 0 && route &&
                        strcmp(route->installed_state, "pending-arp") == 0 &&
                        strcmp(route->nexthops[0].address,
                               "192.0.2.2") == 0 &&
                        strcmp(route->nexthops[0].egress_rif,
                               "irb.100") == 0);
    }
    fib[0] = '\0';
    routes_out = -1;
    failed += check("pending static ARP route is held from FIB batch",
                    rpd_rib_compile_fib_batch(&rib, 15, 12, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    routes_out == 1 &&
                    !strstr(fib, "prefix=203.0.113.0/24"));
    rc = rpd_rib_sync_dynamic_arp_text(&rib, linux_arp,
                                       (int)strlen(linux_arp),
                                       16, 13, &result, err, sizeof(err));
    {
        const rpd_rib_route *route =
            find_route(&rib, "203.0.113.0/24", "static");
        failed += check("Linux ARP resolves pending static route to owner gate",
                        rc == 0 && route &&
                        strcmp(route->installed_state, "pending-owner") == 0);
    }
    fib[0] = '\0';
    routes_out = -1;
    failed += check("pending-owner static route is held from dynamic FIB",
                    rpd_rib_compile_fib_batch(&rib, 16, 13, fib,
                                              sizeof(fib), &routes_out) > 0 &&
                    routes_out == 1 &&
                    !strstr(fib, "prefix=203.0.113.0/24"));

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, missing_arp_plan,
                                  (int)strlen(missing_arp_plan),
                                  8, 4, &result, err, sizeof(err));
    failed += check("next-hop without ARP is rejected",
                    rc != 0 && strstr(err, "next-hop"));

    rpd_rib_init(&rib);
    memset(err, 0, sizeof(err));
    rc = rpd_rib_sync_static_plan(&rib, multicast_static_plan,
                                  (int)strlen(multicast_static_plan),
                                  12, 8, &result, err, sizeof(err));
    failed += check("multicast static route is rejected",
                    rc != 0 && strstr(err, "invalid static route"));

    rpd_rib_init(&rib);
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        rpd_rib_route *route = &rib.routes[i];

        route->active = true;
        snprintf(route->prefix, sizeof(route->prefix), "10.%d.%d.%d/32",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        snprintf(route->protocol, sizeof(route->protocol), "connected");
        snprintf(route->installed_state, sizeof(route->installed_state),
                 "owner-applied");
    }
    {
        char undersized[128];
        int serialized_routes = -1;

        failed += check(
            "4096-route FIB count is independent of serialization buffer",
            rpd_rib_compile_fib_batch(&rib, 20, 20, undersized,
                                      sizeof(undersized),
                                      &serialized_routes) < 0 &&
            rpd_rib_fib_route_count(&rib) == RPD_RIB_MAX_ROUTES);
    }
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        snprintf(rib.routes[i].protocol, sizeof(rib.routes[i].protocol),
                 "bgp");
        snprintf(rib.routes[i].installed_state,
                 sizeof(rib.routes[i].installed_state), "pending-fib");
    }
    rpd_rib_mark_dynamic_fib_installed(&rib);
    failed += check(
        "4096 dynamic routes are marked installed through best-route index",
        strcmp(rib.routes[0].installed_state, "owner-applied") == 0 &&
        strcmp(rib.routes[RPD_RIB_MAX_ROUTES - 1].installed_state,
               "owner-applied") == 0);

    return failed ? 1 : 0;
}
