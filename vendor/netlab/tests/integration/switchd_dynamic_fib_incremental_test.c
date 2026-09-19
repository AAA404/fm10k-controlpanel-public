#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../sbin/switchd/hal_l3.c"

enum { SDK_TEST_MAX_ROUTES = NL_L3_PERSISTENT_MAX_ROUTES };

static fm_routeEntry sdk_routes[SDK_TEST_MAX_ROUTES];
static int sdk_route_count;
static int sdk_add_calls;
static int sdk_delete_calls;
static int sdk_fail_next_add;
static int sdk_fail_next_delete;
static int sdk_fail_add_attempts;
static int sdk_fail_delete_attempts;
static bool sdk_vlan_exists;
static fm_bool sdk_vlan_routable;
static bool sdk_interface_exists;
static bool sdk_interface_addr_exists;
static fm_int sdk_interface_id = 100;
static fm_uint16 sdk_interface_vlan;
static fm_interfaceState sdk_interface_state;
static fm_ipAddr sdk_interface_addr;
static bool sdk_arp_exists;
static fm_arpEntry sdk_arp;

fm_status fmAddRoute(fm_int sw, fm_routeEntry *route, fm_routeState state)
{
    (void)sw;
    if (sdk_fail_next_add || sdk_fail_add_attempts > 0) {
        sdk_fail_next_add = 0;
        if (sdk_fail_add_attempts > 0)
            sdk_fail_add_attempts--;
        return (fm_status)-1;
    }
    if (!route || state != FM_ROUTE_STATE_UP ||
        sdk_route_count >= SDK_TEST_MAX_ROUTES)
        return (fm_status)-1;
    for (int i = 0; i < sdk_route_count; i++)
        if (route_entry_equal(&sdk_routes[i], route))
            return (fm_status)-1;
    sdk_routes[sdk_route_count++] = *route;
    sdk_add_calls++;
    return FM_OK;
}

fm_status fmDeleteRoute(fm_int sw, fm_routeEntry *route)
{
    (void)sw;
    if (sdk_fail_next_delete || sdk_fail_delete_attempts > 0) {
        sdk_fail_next_delete = 0;
        if (sdk_fail_delete_attempts > 0)
            sdk_fail_delete_attempts--;
        return (fm_status)-1;
    }
    if (!route)
        return (fm_status)-1;
    for (int i = 0; i < sdk_route_count; i++) {
        if (!route_entry_equal(&sdk_routes[i], route))
            continue;
        sdk_routes[i] = sdk_routes[sdk_route_count - 1];
        sdk_route_count--;
        sdk_delete_calls++;
        return FM_OK;
    }
    return FM_ERR_NOT_FOUND;
}

fm_status fmGetRouteList(fm_int sw, fm_int *num_routes,
                         fm_routeEntry *routes, fm_int max)
{
    int emitted;

    (void)sw;
    if (!num_routes || max < 0 || (max > 0 && !routes))
        return (fm_status)-1;
    *num_routes = sdk_route_count;
    emitted = sdk_route_count < max ? sdk_route_count : max;
    for (int i = 0; i < emitted; i++)
        routes[i] = sdk_routes[i];
    return FM_OK;
}

fm_status fmGetECMPGroupList(fm_int sw, fm_int *num_groups,
                             fm_int *groups, fm_int max)
{
    (void)sw;
    (void)groups;
    (void)max;
    if (!num_groups)
        return (fm_status)-1;
    *num_groups = 0;
    return FM_OK;
}

fm_status fmGetECMPGroupNextHopList(fm_int sw, fm_int group_id,
                                    fm_int *num_nexthops,
                                    fm_nextHop *nexthops, fm_int max)
{
    (void)sw;
    (void)group_id;
    (void)nexthops;
    (void)max;
    if (!num_nexthops)
        return (fm_status)-1;
    *num_nexthops = 0;
    return FM_ERR_NOT_FOUND;
}

fm_status fmCreateECMPGroup(fm_int sw, fm_int *group_id,
                            fm_int num_nexthops, fm_nextHop *nexthops)
{
    (void)sw;
    (void)num_nexthops;
    (void)nexthops;
    if (!group_id)
        return (fm_status)-1;
    *group_id = 100;
    return FM_OK;
}

fm_status fmDeleteECMPGroup(fm_int sw, fm_int group_id)
{
    (void)sw;
    (void)group_id;
    return FM_OK;
}

fm_status fmGetRouteState(fm_int sw, fm_routeEntry *route,
                          fm_routeState *state)
{
    (void)sw;
    for (int i = 0; route && i < sdk_route_count; i++) {
        if (!route_entry_equal(&sdk_routes[i], route))
            continue;
        if (state)
            *state = FM_ROUTE_STATE_UP;
        return FM_OK;
    }
    return FM_ERR_NOT_FOUND;
}

fm_status fmGetVirtualRouterList(fm_int sw, fm_int *num_vrids,
                                 fm_int *vrids, fm_int max)
{
    (void)sw;
    (void)vrids;
    (void)max;
    if (!num_vrids)
        return FM_ERR_INVALID_ARGUMENT;
    *num_vrids = 0;
    return FM_OK;
}

fm_status fmCreateVlan(fm_int sw, fm_uint16 vlan)
{
    (void)sw;
    (void)vlan;
    if (sdk_vlan_exists)
        return FM_ERR_ALREADY_EXISTS;
    sdk_vlan_exists = true;
    sdk_vlan_routable = FM_DISABLED;
    return FM_OK;
}

fm_status fmDeleteVlan(fm_int sw, fm_uint16 vlan)
{
    (void)sw;
    (void)vlan;
    if (!sdk_vlan_exists)
        return FM_ERR_NOT_FOUND;
    sdk_vlan_exists = false;
    sdk_vlan_routable = FM_DISABLED;
    return FM_OK;
}

fm_status fmGetVlanAttribute(fm_int sw, fm_uint16 vlan, fm_int attr,
                             void *value)
{
    (void)sw;
    (void)vlan;
    if (!sdk_vlan_exists || attr != FM_VLAN_ROUTABLE || !value)
        return FM_ERR_NOT_FOUND;
    *(fm_bool *)value = sdk_vlan_routable;
    return FM_OK;
}

fm_status fmSetVlanAttribute(fm_int sw, fm_uint16 vlan, fm_int attr,
                             void *value)
{
    (void)sw;
    (void)vlan;
    if (!sdk_vlan_exists || attr != FM_VLAN_ROUTABLE || !value)
        return FM_ERR_NOT_FOUND;
    sdk_vlan_routable = *(fm_bool *)value;
    return FM_OK;
}

fm_status fmGetVlanPortList(fm_int sw, fm_uint16 vlan, fm_int *n_ports,
                            fm_int *ports, fm_int max)
{
    (void)sw;
    (void)vlan;
    (void)ports;
    (void)max;
    if (!n_ports)
        return FM_ERR_INVALID_ARGUMENT;
    *n_ports = 0;
    return FM_OK;
}

fm_status fmCreateInterface(fm_int sw, fm_int *interface)
{
    (void)sw;
    if (!interface || sdk_interface_exists)
        return FM_ERR_ALREADY_EXISTS;
    sdk_interface_exists = true;
    sdk_interface_id++;
    *interface = sdk_interface_id;
    sdk_interface_state = FM_INTERFACE_STATE_ADMIN_DOWN;
    sdk_interface_vlan = 0;
    return FM_OK;
}

fm_status fmDeleteInterface(fm_int sw, fm_int interface)
{
    (void)sw;
    if (!sdk_interface_exists || interface != sdk_interface_id)
        return FM_ERR_NOT_FOUND;
    sdk_interface_exists = false;
    return FM_OK;
}

fm_status fmGetInterfaceList(fm_int sw, fm_int *count, fm_int *interfaces,
                             fm_int max)
{
    (void)sw;
    if (!count || max < 0)
        return FM_ERR_INVALID_ARGUMENT;
    *count = sdk_interface_exists ? 1 : 0;
    if (sdk_interface_exists && max > 0 && interfaces)
        interfaces[0] = sdk_interface_id;
    return FM_OK;
}

fm_status fmSetInterfaceAttribute(fm_int sw, fm_int interface, fm_int attr,
                                  void *value)
{
    (void)sw;
    if (!sdk_interface_exists || interface != sdk_interface_id || !value)
        return FM_ERR_NOT_FOUND;
    if (attr == FM_INTERFACE_VLAN)
        sdk_interface_vlan = *(fm_uint16 *)value;
    else if (attr == FM_INTERFACE_STATE)
        sdk_interface_state = *(fm_interfaceState *)value;
    else
        return FM_ERR_INVALID_ARGUMENT;
    return FM_OK;
}

fm_status fmGetInterfaceAttribute(fm_int sw, fm_int interface, fm_int attr,
                                  void *value)
{
    (void)sw;
    if (!sdk_interface_exists || interface != sdk_interface_id || !value)
        return FM_ERR_NOT_FOUND;
    if (attr == FM_INTERFACE_VLAN)
        *(fm_uint16 *)value = sdk_interface_vlan;
    else if (attr == FM_INTERFACE_STATE)
        *(fm_interfaceState *)value = sdk_interface_state;
    else
        return FM_ERR_INVALID_ARGUMENT;
    return FM_OK;
}

fm_status fmAddInterfaceAddr(fm_int sw, fm_int interface, fm_ipAddr *addr)
{
    (void)sw;
    if (!sdk_interface_exists || interface != sdk_interface_id || !addr)
        return FM_ERR_NOT_FOUND;
    sdk_interface_addr = *addr;
    sdk_interface_addr_exists = true;
    return FM_OK;
}

fm_status fmDeleteInterfaceAddr(fm_int sw, fm_int interface,
                                fm_ipAddr *addr)
{
    (void)sw;
    if (!sdk_interface_exists || interface != sdk_interface_id || !addr ||
        !sdk_interface_addr_exists ||
        !ipaddr_equal(addr, &sdk_interface_addr))
        return FM_ERR_NOT_FOUND;
    sdk_interface_addr_exists = false;
    return FM_OK;
}

fm_status fmGetInterfaceAddrList(fm_int sw, fm_int interface, fm_int *count,
                                 fm_ipAddr *addresses, fm_int max)
{
    (void)sw;
    if (!sdk_interface_exists || interface != sdk_interface_id || !count)
        return FM_ERR_NOT_FOUND;
    *count = sdk_interface_addr_exists ? 1 : 0;
    if (sdk_interface_addr_exists && max > 0 && addresses)
        addresses[0] = sdk_interface_addr;
    return FM_OK;
}

fm_status fmAddARPEntry(fm_int sw, fm_arpEntry *arp)
{
    (void)sw;
    if (!arp || sdk_arp_exists)
        return FM_ERR_ALREADY_EXISTS;
    sdk_arp = *arp;
    sdk_arp_exists = true;
    return FM_OK;
}

fm_status fmDeleteARPEntry(fm_int sw, fm_arpEntry *arp)
{
    (void)sw;
    if (!arp || !sdk_arp_exists || !arp_entry_equal(arp, &sdk_arp))
        return FM_ERR_NOT_FOUND;
    sdk_arp_exists = false;
    return FM_OK;
}

fm_status fmGetARPEntryList(fm_int sw, fm_int *count, fm_arpEntry *arps,
                            fm_int max)
{
    (void)sw;
    if (!count)
        return FM_ERR_INVALID_ARGUMENT;
    *count = sdk_arp_exists ? 1 : 0;
    if (sdk_arp_exists && max > 0 && arps)
        arps[0] = sdk_arp;
    return FM_OK;
}

fm_status fmGetARPEntryInfo(fm_int sw, fm_arpEntry *arp,
                            fm_arpEntryInfo *info)
{
    (void)sw;
    if (!arp || !info || !sdk_arp_exists ||
        !arp_entry_equal(arp, &sdk_arp))
        return FM_ERR_NOT_FOUND;
    memset(info, 0, sizeof(*info));
    info->arp = sdk_arp;
    return FM_OK;
}

fm_status fmGetAddress(fm_int sw, fm_macaddr address, fm_int vlan,
                       fm_macAddressEntry *entry)
{
    (void)sw;
    (void)address;
    (void)vlan;
    (void)entry;
    return FM_ERR_NOT_FOUND;
}

int nl_ifid_get_all(nl_port_entry *entries, int max)
{
    (void)entries;
    (void)max;
    return 0;
}

bool nl_ifid_logical_port_to_name(int logical_port, char *buf,
                                  size_t buf_size)
{
    (void)logical_port;
    if (buf && buf_size > 0)
        buf[0] = '\0';
    return false;
}

bool nl_ifid_get_by_name(const char *name, nl_port_entry *entry)
{
    (void)name;
    (void)entry;
    return false;
}

int nl_ifid_name_to_logical_port(const char *name)
{
    (void)name;
    return -1;
}

bool nl_ifid_is_user_port(int logical_port)
{
    (void)logical_port;
    return false;
}

bool nl_ifid_name_is_user_port(const char *name)
{
    (void)name;
    return false;
}

fm_status fmGetRouterAttribute(fm_int sw, fm_int attr, void *value)
{
    (void)sw;
    (void)attr;
    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    *(fm_macaddr *)value = 0;
    return FM_OK;
}

fm_status fmSetRouterAttribute(fm_int sw, fm_int attr, void *value)
{
    (void)sw;
    (void)attr;
    (void)value;
    return FM_OK;
}

fm_status fmGetRouterState(fm_int sw, fm_int vrid, fm_routerState *state)
{
    (void)sw;
    (void)vrid;
    if (!state)
        return FM_ERR_INVALID_ARGUMENT;
    *state = FM_ROUTER_STATE_ADMIN_DOWN;
    return FM_OK;
}

fm_status fmSetRouterState(fm_int sw, fm_int vrid, fm_routerState state)
{
    (void)sw;
    (void)vrid;
    (void)state;
    return FM_OK;
}

fm_status fmCreateVirtualRouter(fm_int sw, fm_int vrid)
{
    (void)sw;
    (void)vrid;
    return FM_OK;
}

fm_status fmDeleteVirtualRouter(fm_int sw, fm_int vrid)
{
    (void)sw;
    (void)vrid;
    return FM_OK;
}

fm_status fmGetVlanPortTag(fm_int sw, fm_int vlan, fm_int port,
                           fm_bool *tag)
{
    (void)sw;
    (void)vlan;
    (void)port;
    (void)tag;
    return FM_ERR_NOT_FOUND;
}

fm_status fmGetVlanPortState(fm_int sw, fm_uint16 vlan, fm_int port,
                             fm_int *state)
{
    (void)sw;
    (void)vlan;
    (void)port;
    (void)state;
    return FM_ERR_NOT_FOUND;
}

fm_status fmAddVlanPort(fm_int sw, fm_uint16 vlan, fm_int port, fm_bool tag)
{
    (void)sw;
    (void)vlan;
    (void)port;
    (void)tag;
    return FM_OK;
}

fm_status fmDeleteVlanPort(fm_int sw, fm_uint16 vlan, fm_int port)
{
    (void)sw;
    (void)vlan;
    (void)port;
    return FM_OK;
}

fm_status fmSetVlanPortState(fm_int sw, fm_uint16 vlan, fm_int port,
                             fm_int state)
{
    (void)sw;
    (void)vlan;
    (void)port;
    (void)state;
    return FM_OK;
}

fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr,
                             void *value)
{
    (void)sw;
    (void)port;
    (void)attr;
    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    *(fm_uint32 *)value = 0;
    return FM_OK;
}

fm_status fmSetPortAttribute(fm_int sw, fm_int port, fm_int attr,
                             void *value)
{
    (void)sw;
    (void)port;
    (void)attr;
    (void)value;
    return FM_OK;
}

fm_status fmAddAddress(fm_int sw, fm_macAddressEntry *entry)
{
    (void)sw;
    (void)entry;
    return FM_OK;
}

fm_status fmDeleteAddress(fm_int sw, fm_macAddressEntry *entry)
{
    (void)sw;
    (void)entry;
    return FM_OK;
}

const char *fmErrorMsg(fm_int err)
{
    (void)err;
    return "fake-sdk-error";
}

static void fill_route(hal_l3_dynamic_fib_route *route,
                       hal_l3_dynamic_fib_nexthop *nexthop,
                       const char *prefix)
{
    memset(route, 0, sizeof(*route));
    memset(nexthop, 0, sizeof(*nexthop));
    snprintf(route->prefix, sizeof(route->prefix), "%s", prefix);
    snprintf(route->protocol, sizeof(route->protocol), "bgp");
    route->nexthops = nexthop;
    route->n_nexthops = 1;
    snprintf(nexthop->address, sizeof(nexthop->address), "198.51.100.2");
    snprintf(nexthop->interface_addr, sizeof(nexthop->interface_addr),
             "198.51.100.1/24");
}

static void fill_plan(hal_l3_dynamic_fib_plan *plan,
                      hal_l3_dynamic_fib_route *routes, int route_count,
                      u64 generation)
{
    memset(plan, 0, sizeof(*plan));
    snprintf(plan->table, sizeof(plan->table), "inet.0");
    plan->vrid = 0;
    plan->generation = generation;
    plan->fib_update_id = generation + 1;
    plan->routes = routes;
    plan->n_routes = route_count;
}

static void reset_dynamic_owner_fixture(void)
{
    for (int slot = 0; slot < HAL_L3_DYNAMIC_OWNER_SLOTS; slot++) {
        free(g_l3_dynamic_fib_owner[slot].state);
        g_l3_dynamic_fib_owner[slot].state = NULL;
    }
    memset(sdk_routes, 0, sizeof(sdk_routes));
    sdk_route_count = 0;
    sdk_add_calls = 0;
    sdk_delete_calls = 0;
    sdk_fail_next_add = 0;
    sdk_fail_next_delete = 0;
    sdk_fail_add_attempts = 0;
    sdk_fail_delete_attempts = 0;
}

static void reset_persistent_sdk_fixture(void)
{
    free(g_l3_persistent_owner);
    g_l3_persistent_owner = NULL;
    memset(sdk_routes, 0, sizeof(sdk_routes));
    sdk_route_count = 0;
    sdk_vlan_exists = false;
    sdk_vlan_routable = FM_DISABLED;
    sdk_interface_exists = false;
    sdk_interface_addr_exists = false;
    sdk_interface_vlan = 0;
    sdk_interface_state = FM_INTERFACE_STATE_ADMIN_DOWN;
    memset(&sdk_interface_addr, 0, sizeof(sdk_interface_addr));
    sdk_arp_exists = false;
    memset(&sdk_arp, 0, sizeof(sdk_arp));
}

static int build_persistent_route_plan(hal_l3_intent_plan *plan,
                                       hal_l3_intent_rif *rif,
                                       hal_l3_intent_arp *arp,
                                       hal_l3_intent_next_hop *nexthop,
                                       hal_l3_intent_route *routes,
                                       int route_count)
{
    if (!plan || !rif || !arp || !nexthop || !routes || route_count < 0)
        return -1;
    memset(plan, 0, sizeof(*plan));
    memset(rif, 0, sizeof(*rif));
    memset(arp, 0, sizeof(*arp));
    memset(nexthop, 0, sizeof(*nexthop));
    memset(routes, 0, sizeof(*routes) * (size_t)route_count);

    snprintf(rif->name, sizeof(rif->name), "irb.100");
    snprintf(rif->table, sizeof(rif->table), "inet.0");
    snprintf(rif->address, sizeof(rif->address), "192.0.2.1/24");
    rif->vlan = 100;
    snprintf(arp->ip, sizeof(arp->ip), "192.0.2.2");
    snprintf(arp->table, sizeof(arp->table), "inet.0");
    snprintf(arp->mac, sizeof(arp->mac), "02:00:00:00:00:02");
    snprintf(arp->rif, sizeof(arp->rif), "%s", rif->name);
    nexthop->id = 1;
    snprintf(nexthop->table, sizeof(nexthop->table), "inet.0");
    snprintf(nexthop->arp, sizeof(nexthop->arp), "%s", arp->ip);
    snprintf(nexthop->rif, sizeof(nexthop->rif), "%s", rif->name);
    for (int i = 0; i < route_count; i++) {
        snprintf(routes[i].prefix, sizeof(routes[i].prefix),
                 "10.%d.%d.0/24", i / 256, i % 256);
        snprintf(routes[i].table, sizeof(routes[i].table), "inet.0");
        routes[i].target_type = HAL_L3_ROUTE_TARGET_NEXTHOP;
        routes[i].target_id = nexthop->id;
    }
    plan->rifs = rif;
    plan->n_rifs = 1;
    plan->arps = arp;
    plan->n_arps = 1;
    plan->nexthops = nexthop;
    plan->n_nexthops = 1;
    plan->routes = routes;
    plan->n_routes = route_count;
    return 0;
}

static int run_persistent_route_scale(int route_count, u64 tx_id)
{
    hal_l3_intent_plan plan;
    hal_l3_intent_rif rif;
    hal_l3_intent_arp arp;
    hal_l3_intent_next_hop nexthop;
    hal_l3_intent_route *routes = NULL;
    char *resp = NULL;
    char expected[64];
    int rc = 1;

    reset_persistent_sdk_fixture();
    routes = calloc((size_t)route_count, sizeof(*routes));
    resp = calloc(1, NETLAB_L3_RUNTIME_RESPONSE_MAX);
    if (!routes || !resp ||
        build_persistent_route_plan(&plan, &rif, &arp, &nexthop,
                                    routes, route_count) != 0)
        goto out;
    if (hal_l3_persistent_owner_apply(
            0, &plan, true, tx_id, resp,
            NETLAB_L3_RUNTIME_RESPONSE_MAX) != 0 ||
        !g_l3_persistent_owner || !g_l3_persistent_owner->applied ||
        g_l3_persistent_owner->n_routes != route_count ||
        g_l3_persistent_owner->n_fib_routes != route_count ||
        sdk_route_count != route_count || !strstr(resp, "status=\"ok\""))
        goto out;
    snprintf(expected, sizeof(expected), "fib-routes=\"%d\"", route_count);
    if (hal_l3_persistent_owner_readback(
            0, resp, NETLAB_L3_RUNTIME_RESPONSE_MAX) != 0 ||
        !strstr(resp, "status=\"ok\"") || !strstr(resp, expected))
        goto out;
    if (hal_l3_persistent_owner_rollback(
            0, true, tx_id, resp,
            NETLAB_L3_RUNTIME_RESPONSE_MAX) != 0 ||
        g_l3_persistent_owner || sdk_route_count != 0 ||
        sdk_interface_exists || sdk_arp_exists || sdk_vlan_exists ||
        !strstr(resp, "status=\"ok\""))
        goto out;
    rc = 0;
out:
    if (rc != 0)
        fprintf(stderr, "%d-route persistent scale failed: %s\n",
                route_count, resp ? resp : "allocation failed");
    free(routes);
    free(resp);
    reset_persistent_sdk_fixture();
    return rc;
}

static int run_persistent_rollback_retry(void)
{
    hal_l3_intent_plan plan;
    hal_l3_intent_rif rif;
    hal_l3_intent_arp arp;
    hal_l3_intent_next_hop nexthop;
    hal_l3_intent_route routes[9];
    char resp[NETLAB_L3_RUNTIME_RESPONSE_MAX];
    int rc = 1;

    reset_persistent_sdk_fixture();
    if (build_persistent_route_plan(&plan, &rif, &arp, &nexthop,
                                    routes, 9) != 0 ||
        hal_l3_persistent_owner_apply(
            0, &plan, true, 901, resp, sizeof(resp)) != 0)
        goto out;
    sdk_fail_delete_attempts = 1;
    if (hal_l3_persistent_owner_rollback(
            0, true, 901, resp, sizeof(resp)) == 0 ||
        !strstr(resp, "status=\"out-of-sync\"") ||
        !g_l3_persistent_owner ||
        !g_l3_persistent_owner->hw_out_of_sync || sdk_route_count != 1)
        goto out;
    if (hal_l3_persistent_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "status=\"out-of-sync\""))
        goto out;
    if (hal_l3_persistent_owner_rollback(
            0, true, 901, resp, sizeof(resp)) != 0 ||
        g_l3_persistent_owner || sdk_route_count != 0 ||
        !strstr(resp, "status=\"ok\""))
        goto out;
    rc = 0;
out:
    if (rc != 0)
        fprintf(stderr, "persistent rollback retry failed: %s\n", resp);
    reset_persistent_sdk_fixture();
    return rc;
}

static int run_persistent_capacity_contract(void)
{
    hal_l3_intent_plan plan;
    hal_l3_intent_rif rif;
    hal_l3_intent_arp arp;
    hal_l3_intent_next_hop nexthop;
    hal_l3_intent_route *routes;
    char resp[4096];
    int over = NL_L3_PERSISTENT_MAX_ROUTES + 1;
    int rc = 1;

    if (run_persistent_route_scale(8, 800) != 0 ||
        run_persistent_route_scale(9, 900) != 0 ||
        run_persistent_route_scale(NL_L3_PERSISTENT_MAX_ROUTES, 102400) != 0 ||
        run_persistent_rollback_retry() != 0)
        return 1;

    reset_persistent_sdk_fixture();
    routes = calloc((size_t)over, sizeof(*routes));
    if (!routes ||
        build_persistent_route_plan(&plan, &rif, &arp, &nexthop,
                                    routes, over) != 0)
        goto out;
    if (hal_l3_persistent_owner_apply(
            0, &plan, true, 102500, resp, sizeof(resp)) == 0 ||
        !strstr(resp, "status=\"invalid\"") ||
        g_l3_persistent_owner || sdk_route_count != 0)
        goto out;
    rc = 0;
out:
    if (rc != 0)
        fprintf(stderr, "persistent max+1 contract failed: %s\n", resp);
    free(routes);
    reset_persistent_sdk_fixture();
    return rc;
}

static int run_owner_slot_contract(void)
{
    hal_l3_dynamic_fib_route routes[2];
    hal_l3_dynamic_fib_nexthop nexthops[2];
    hal_l3_dynamic_fib_plan plan;
    hal_l3_dynamic_fib_owner *committed;
    char resp[16384];
    int rc = 1;

    reset_dynamic_owner_fixture();
    fill_route(&routes[0], &nexthops[0], "10.70.0.0/24");
    fill_route(&routes[1], &nexthops[1], "10.70.1.0/24");

    fill_plan(&plan, routes, 1, 10);
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 100, resp, sizeof(resp)) != 0 ||
        !g_l3_dynamic_fib_owner[0].state ||
        !g_l3_dynamic_fib_owner[0].state->applied ||
        g_l3_dynamic_fib_owner[0].state->n_routes != 1 ||
        sdk_route_count != 1 || !strstr(resp, "status=\"ok\""))
        goto out;
    if (hal_l3_dynamic_fib_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "status=\"ok\"") ||
        !strstr(resp, "prefix=\"10.70.0.0/24\""))
        goto out;

    committed = g_l3_dynamic_fib_owner[0].state;
    fill_route(&routes[0], &nexthops[0], "10.71.0.0/24");
    fill_plan(&plan, routes, 1, 11);
    sdk_fail_add_attempts = 1;
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 101, resp, sizeof(resp)) == 0 ||
        !strstr(resp, "status=\"rollback\"") ||
        g_l3_dynamic_fib_owner[0].state != committed ||
        !committed->applied || committed->hw_out_of_sync ||
        strcmp(committed->route_prefix[0], "10.70.0.0/24") != 0 ||
        sdk_route_count != 1)
        goto out;
    if (hal_l3_dynamic_fib_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "prefix=\"10.70.0.0/24\""))
        goto out;

    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 101, resp, sizeof(resp)) != 0 ||
        g_l3_dynamic_fib_owner[0].state == committed ||
        strcmp(g_l3_dynamic_fib_owner[0].state->route_prefix[0],
               "10.71.0.0/24") != 0 || sdk_route_count != 1)
        goto out;

    committed = g_l3_dynamic_fib_owner[0].state;
    fill_route(&routes[1], &nexthops[1], "10.71.1.0/24");
    fill_plan(&plan, routes, 2, 12);
    sdk_fail_next_add = 1;
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 102, resp, sizeof(resp)) == 0 ||
        !strstr(resp, "status=\"rollback\"") ||
        g_l3_dynamic_fib_owner[0].state != committed ||
        committed->n_routes != 1 || sdk_route_count != 1)
        goto out;
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 102, resp, sizeof(resp)) != 0 ||
        g_l3_dynamic_fib_owner[0].state == committed ||
        g_l3_dynamic_fib_owner[0].state->n_routes != 2 ||
        sdk_route_count != 2)
        goto out;

    committed = g_l3_dynamic_fib_owner[0].state;
    if (hal_l3_dynamic_fib_owner_rollback(
            0, true, 999, resp, sizeof(resp)) == 0 ||
        g_l3_dynamic_fib_owner[0].state != committed ||
        sdk_route_count != 2)
        goto out;
    sdk_fail_delete_attempts = 1;
    if (hal_l3_dynamic_fib_owner_rollback(
            0, true, 102, resp, sizeof(resp)) == 0 ||
        !strstr(resp, "status=\"out-of-sync\"") ||
        !committed->applied || !committed->hw_out_of_sync ||
        sdk_route_count != 1)
        goto out;
    if (hal_l3_dynamic_fib_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "status=\"out-of-sync\""))
        goto out;
    if (hal_l3_dynamic_fib_owner_rollback(
            0, true, 102, resp, sizeof(resp)) != 0 ||
        g_l3_dynamic_fib_owner[0].state != committed ||
        committed->applied || committed->hw_out_of_sync ||
        sdk_route_count != 0)
        goto out;
    if (hal_l3_dynamic_fib_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "status=\"empty\""))
        goto out;
    if (hal_l3_dynamic_fib_owner_rollback(
            0, true, 102, resp, sizeof(resp)) == 0)
        goto out;

    fill_route(&routes[0], &nexthops[0], "10.72.0.0/24");
    fill_plan(&plan, routes, 1, 20);
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 200, resp, sizeof(resp)) != 0)
        goto out;
    fill_route(&routes[0], &nexthops[0], "10.73.0.0/24");
    fill_plan(&plan, routes, 1, 21);
    sdk_fail_add_attempts = 2;
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 201, resp, sizeof(resp)) == 0 ||
        !strstr(resp, "status=\"out-of-sync\"") ||
        !g_l3_dynamic_fib_owner[0].state->hw_out_of_sync ||
        g_l3_dynamic_fib_owner[0].state->applied ||
        sdk_route_count != 0)
        goto out;
    if (hal_l3_dynamic_fib_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "status=\"out-of-sync\""))
        goto out;
    if (hal_l3_dynamic_fib_owner_apply(
            0, &plan, true, 202, resp, sizeof(resp)) != 0 ||
        !g_l3_dynamic_fib_owner[0].state->applied ||
        g_l3_dynamic_fib_owner[0].state->hw_out_of_sync ||
        strcmp(g_l3_dynamic_fib_owner[0].state->route_prefix[0],
               "10.73.0.0/24") != 0 || sdk_route_count != 1)
        goto out;
    if (hal_l3_dynamic_fib_owner_readback(
            0, resp, sizeof(resp)) != 0 ||
        !strstr(resp, "status=\"ok\""))
        goto out;

    rc = 0;
out:
    if (rc != 0)
        fprintf(stderr, "owner-slot contract failed: %s\n", resp);
    reset_dynamic_owner_fixture();
    return rc;
}

static int run_incremental_contract(void)
{
    hal_l3_dynamic_fib_owner *owner = calloc(1, sizeof(*owner));
    hal_l3_dynamic_fib_owner *next = calloc(1, sizeof(*next));
    hal_l3_dynamic_fib_route routes[2];
    hal_l3_dynamic_fib_nexthop nexthops[2];
    hal_l3_dynamic_fib_plan plan;
    char resp[2048];
    bool handled = false;
    int add_before;
    int delete_before;
    int rc = 1;

    if (!owner || !next)
        goto out;
    fill_route(&routes[0], &nexthops[0], "10.64.0.0/24");
    fill_route(&routes[1], &nexthops[1], "10.64.1.0/24");

    fill_plan(&plan, routes, 1, 1);
    dynamic_owner_prepare(owner, 0, &plan, 2);
    if (dynamic_prepare_unicast_plan(&plan, owner) != 0)
        goto out;
    owner->applied = true;
    owner->route_added[0] = true;
    sdk_routes[0] = owner->route_entry[0];
    sdk_route_count = 1;

    fill_plan(&plan, routes, 2, 2);
    dynamic_owner_prepare(next, 0, &plan, 3);
    sdk_fail_next_add = 1;
    if (dynamic_try_incremental_unicast(
            0, owner, &plan, 3, next, &handled, resp, sizeof(resp)) != -1 ||
        !handled || owner->n_routes != 1 || sdk_route_count != 1 ||
        owner->hw_out_of_sync || !strstr(resp, "status=\"rollback\""))
        goto out;

    dynamic_owner_prepare(next, 0, &plan, 3);
    if (dynamic_try_incremental_unicast(
            0, owner, &plan, 3, next, &handled, resp, sizeof(resp)) != 0 ||
        !handled || owner->n_routes != 1 || next->n_routes != 2 ||
        sdk_route_count != 2 ||
        sdk_add_calls != 1 || sdk_delete_calls != 0 ||
        !strstr(resp, "update-mode=\"incremental-unicast\"") ||
        !strstr(resp, "changed-compared=\"1\""))
        goto out;
    free(owner);
    owner = next;
    next = calloc(1, sizeof(*next));
    if (!next)
        goto out;

    routes[0] = routes[1];
    nexthops[0] = nexthops[1];
    routes[0].nexthops = &nexthops[0];
    fill_plan(&plan, routes, 1, 3);
    dynamic_owner_prepare(next, 0, &plan, 4);
    sdk_fail_next_delete = 1;
    if (dynamic_try_incremental_unicast(
            0, owner, &plan, 4, next, &handled, resp, sizeof(resp)) != -1 ||
        !handled || owner->n_routes != 2 || sdk_route_count != 2 ||
        owner->hw_out_of_sync || !strstr(resp, "status=\"rollback\""))
        goto out;

    dynamic_owner_prepare(next, 0, &plan, 4);
    if (dynamic_try_incremental_unicast(
            0, owner, &plan, 4, next, &handled, resp, sizeof(resp)) != 0 ||
        !handled || owner->n_routes != 2 || next->n_routes != 1 ||
        sdk_route_count != 1 ||
        sdk_add_calls != 1 || sdk_delete_calls != 1)
        goto out;
    free(owner);
    owner = next;
    next = calloc(1, sizeof(*next));
    if (!next)
        goto out;

    add_before = sdk_add_calls;
    delete_before = sdk_delete_calls;
    fill_route(&routes[0], &nexthops[0], "10.65.0.0/24");
    fill_plan(&plan, routes, 1, 4);
    dynamic_owner_prepare(next, 0, &plan, 5);
    handled = true;
    if (dynamic_try_incremental_unicast(
            0, owner, &plan, 5, next, &handled, resp, sizeof(resp)) != -1 ||
        handled || sdk_add_calls != add_before ||
        sdk_delete_calls != delete_before)
        goto out;

    rc = 0;
out:
    free(next);
    free(owner);
    return rc;
}

int main(void)
{
    if (run_incremental_contract() != 0) {
        fprintf(stderr, "incremental dynamic FIB contract failed\n");
        return 1;
    }
    if (run_owner_slot_contract() != 0)
        return 1;
    if (run_persistent_capacity_contract() != 0)
        return 1;
    puts("PASS: switchd applies single-path dynamic FIB deltas incrementally");
    puts("PASS: dynamic FIB owner-slot preserves readback, rollback, and retry");
    puts("PASS: persistent L3 owner supports 8, 9, and 1024 routes");
    puts("PASS: persistent L3 owner rejects the 1025th route explicitly");
    puts("PASS: persistent L3 rollback preserves failed handles for retry");
    return 0;
}
