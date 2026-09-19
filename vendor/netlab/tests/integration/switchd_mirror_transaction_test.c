#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/hal_mirror.c"

#define TEST_GROUP NETLAB_MIRROR_V1_GROUP
#define TEST_DESTINATION 24
#define TEST_MAX_PORTS 8
#define TEST_MAX_VLANS 8

typedef struct {
    fm_uint16 vlan;
    fm_mirrorVlanType direction;
} simulated_vlan_source;

typedef struct {
    bool exists;
    bool ignore_delete;
    fm_int destination;
    fm_mirrorType type;
    fm_int ports[TEST_MAX_PORTS];
    fm_mirrorType port_types[TEST_MAX_PORTS];
    int n_ports;
    simulated_vlan_source vlans[2][TEST_MAX_VLANS];
    int n_vlans[2];
    fm_bool truncate;
    fm_bool acl_filter;
    fm_int sample_rate;
    fm_int encapsulation_vlan;
    fm_byte vlan_priority;
    fm_int trapcode_id;
    fm_status v2_first_status;
    fm_status legacy_first_status;
    fm_int fail_attribute;
    fm_vlanSelect fail_vlan_selector;
    fm_status fail_vlan_status;
    int writes;
} mirror_simulator;

static mirror_simulator g_sim;
static int g_failures;

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failures++;
}

static void reset_simulator(void) {
    memset(&g_sim, 0, sizeof(g_sim));
    g_sim.destination = TEST_DESTINATION;
    g_sim.type = FM_MIRROR_TYPE_INGRESS;
    g_sim.sample_rate = FM_MIRROR_SAMPLE_RATE_DISABLED;
    g_sim.encapsulation_vlan = FM_MIRROR_NO_VLAN_ENCAP;
    g_sim.v2_first_status = FM_OK;
    g_sim.legacy_first_status = FM_OK;
    g_sim.fail_attribute = -1;
    g_sim.fail_vlan_selector = (fm_vlanSelect)-1;
    g_sim.fail_vlan_status = FM_OK;
}

static void seed_default_group(void) {
    g_sim.exists = true;
    g_sim.n_ports = 1;
    g_sim.ports[0] = 2;
    g_sim.port_types[0] = FM_MIRROR_TYPE_INGRESS;
}

bool nl_ifid_is_user_port(int logical_port) {
    return logical_port > 0 && logical_port <= 64;
}

fm_status fmGetMirror(fm_int sw, fm_int group, fm_int *destination,
                      fm_mirrorType *type) {
    (void)sw;
    if (group != TEST_GROUP || !destination || !type)
        return FM_ERR_INVALID_ARGUMENT;
    if (!g_sim.exists)
        return FM_ERR_INVALID_PORT_MIRROR_GROUP;
    *destination = g_sim.destination;
    *type = g_sim.type;
    return FM_OK;
}

fm_status fmCreateMirror(fm_int sw, fm_int group, fm_int destination,
                         fm_mirrorType type) {
    (void)sw;
    if (group != TEST_GROUP || g_sim.exists)
        return FM_ERR_INVALID_PORT_MIRROR_GROUP;
    g_sim.exists = true;
    g_sim.destination = destination;
    g_sim.type = type;
    g_sim.n_ports = 0;
    memset(g_sim.n_vlans, 0, sizeof(g_sim.n_vlans));
    g_sim.truncate = FALSE;
    g_sim.acl_filter = FALSE;
    g_sim.sample_rate = FM_MIRROR_SAMPLE_RATE_DISABLED;
    g_sim.encapsulation_vlan = FM_MIRROR_NO_VLAN_ENCAP;
    g_sim.vlan_priority = 0;
    g_sim.trapcode_id = 0;
    g_sim.writes++;
    return FM_OK;
}

fm_status fmDeleteMirror(fm_int sw, fm_int group) {
    (void)sw;
    if (group != TEST_GROUP)
        return FM_ERR_INVALID_PORT_MIRROR_GROUP;
    if (!g_sim.exists)
        return FM_ERR_INVALID_PORT_MIRROR_GROUP;
    g_sim.writes++;
    if (!g_sim.ignore_delete)
        g_sim.exists = false;
    return FM_OK;
}

fm_status fmGetMirrorPortFirstV2(fm_int sw, fm_int group,
                                 fm_int *port, fm_mirrorType *type) {
    (void)sw;
    if (group != TEST_GROUP || !port || !type)
        return FM_ERR_INVALID_ARGUMENT;
    if (g_sim.v2_first_status != FM_OK)
        return g_sim.v2_first_status;
    if (g_sim.n_ports == 0)
        return FM_ERR_NO_PORTS_IN_MIRROR_GROUP;
    *port = g_sim.ports[0];
    *type = g_sim.port_types[0];
    return FM_OK;
}

fm_status fmGetMirrorPortNextV2(fm_int sw, fm_int group, fm_int current,
                                fm_int *next, fm_mirrorType *type) {
    (void)sw;
    if (group != TEST_GROUP || !next || !type)
        return FM_ERR_INVALID_ARGUMENT;
    for (int i = 0; i < g_sim.n_ports; i++) {
        if (g_sim.ports[i] != current)
            continue;
        if (i + 1 >= g_sim.n_ports)
            return FM_ERR_NO_PORTS_IN_MIRROR_GROUP;
        *next = g_sim.ports[i + 1];
        *type = g_sim.port_types[i + 1];
        return FM_OK;
    }
    return FM_ERR_INVALID_PORT;
}

fm_status fmGetMirrorPortFirst(fm_int sw, fm_int group, fm_int *port) {
    fm_mirrorType type;

    if (g_sim.legacy_first_status != FM_OK)
        return g_sim.legacy_first_status;
    return fmGetMirrorPortFirstV2(sw, group, port, &type);
}

fm_status fmGetMirrorPortNext(fm_int sw, fm_int group, fm_int current,
                              fm_int *next) {
    fm_mirrorType type;

    return fmGetMirrorPortNextV2(sw, group, current, next, &type);
}

fm_status fmGetMirrorAttribute(fm_int sw, fm_int group, fm_int attr,
                               void *value) {
    (void)sw;
    if (group != TEST_GROUP || !g_sim.exists || !value)
        return FM_ERR_INVALID_ARGUMENT;
    if (attr == g_sim.fail_attribute)
        return FM_FAIL;
    switch (attr) {
    case FM_MIRROR_TRUNCATE:
        *(fm_bool *)value = g_sim.truncate;
        return FM_OK;
    case FM_MIRROR_SAMPLE_RATE:
        *(fm_int *)value = g_sim.sample_rate;
        return FM_OK;
    case FM_MIRROR_ACL:
        *(fm_bool *)value = g_sim.acl_filter;
        return FM_OK;
    case FM_MIRROR_VLAN:
        *(fm_int *)value = g_sim.encapsulation_vlan;
        return FM_OK;
    case FM_MIRROR_VLAN_PRI:
        *(fm_byte *)value = g_sim.vlan_priority;
        return FM_OK;
    case FM_MIRROR_TRAPCODE_ID:
        *(fm_int *)value = g_sim.trapcode_id;
        return FM_OK;
    default:
        return FM_ERR_UNSUPPORTED;
    }
}

fm_status fmSetMirrorAttribute(fm_int sw, fm_int group, fm_int attr,
                               void *value) {
    (void)sw;
    if (group != TEST_GROUP || !g_sim.exists || !value)
        return FM_ERR_INVALID_ARGUMENT;
    g_sim.writes++;
    switch (attr) {
    case FM_MIRROR_TRUNCATE:
        g_sim.truncate = *(fm_bool *)value;
        return FM_OK;
    case FM_MIRROR_SAMPLE_RATE:
        g_sim.sample_rate = *(fm_int *)value;
        return FM_OK;
    case FM_MIRROR_ACL:
        g_sim.acl_filter = *(fm_bool *)value;
        return FM_OK;
    case FM_MIRROR_VLAN:
        g_sim.encapsulation_vlan = *(fm_int *)value;
        return FM_OK;
    case FM_MIRROR_VLAN_PRI:
        g_sim.vlan_priority = *(fm_byte *)value;
        return FM_OK;
    case FM_MIRROR_TRAPCODE_ID:
        g_sim.trapcode_id = *(fm_int *)value;
        return FM_OK;
    default:
        return FM_ERR_UNSUPPORTED;
    }
}

fm_status fmAddMirrorPortExt(fm_int sw, fm_int group, fm_int port,
                             fm_mirrorType type) {
    (void)sw;
    if (group != TEST_GROUP || !g_sim.exists ||
        g_sim.n_ports >= TEST_MAX_PORTS)
        return FM_ERR_INVALID_ARGUMENT;
    g_sim.ports[g_sim.n_ports] = port;
    g_sim.port_types[g_sim.n_ports] = type;
    g_sim.n_ports++;
    g_sim.writes++;
    return FM_OK;
}

fm_status fmGetMirrorVlanFirstExt(fm_int sw, fm_int group,
                                  fm_vlanSelect selector,
                                  fm_uint16 *vlan,
                                  fm_mirrorVlanType *direction) {
    (void)sw;
    if (group != TEST_GROUP || selector < FM_VLAN_SELECT_VLAN1 ||
        selector > FM_VLAN_SELECT_VLAN2 || !vlan || !direction)
        return FM_ERR_INVALID_ARGUMENT;
    if (selector == g_sim.fail_vlan_selector &&
        g_sim.fail_vlan_status != FM_OK)
        return g_sim.fail_vlan_status;
    if (g_sim.n_vlans[selector] == 0)
        return FM_ERR_NO_VLANS_IN_MIRROR_GROUP;
    *vlan = g_sim.vlans[selector][0].vlan;
    *direction = g_sim.vlans[selector][0].direction;
    return FM_OK;
}

fm_status fmGetMirrorVlanNextExt(fm_int sw, fm_int group,
                                 fm_vlanSelect selector,
                                 fm_uint16 current, fm_uint16 *next,
                                 fm_mirrorVlanType *direction) {
    (void)sw;
    if (group != TEST_GROUP || selector < FM_VLAN_SELECT_VLAN1 ||
        selector > FM_VLAN_SELECT_VLAN2 || !next || !direction)
        return FM_ERR_INVALID_ARGUMENT;
    for (int i = 0; i < g_sim.n_vlans[selector]; i++) {
        if (g_sim.vlans[selector][i].vlan != current)
            continue;
        if (i + 1 >= g_sim.n_vlans[selector])
            return FM_ERR_NO_VLANS_IN_MIRROR_GROUP;
        *next = g_sim.vlans[selector][i + 1].vlan;
        *direction = g_sim.vlans[selector][i + 1].direction;
        return FM_OK;
    }
    return FM_ERR_INVALID_VLAN;
}

fm_status fmAddMirrorVlanExt(fm_int sw, fm_int group,
                             fm_vlanSelect selector, fm_uint16 vlan,
                             fm_mirrorVlanType direction) {
    int slot;

    (void)sw;
    if (group != TEST_GROUP || !g_sim.exists ||
        selector < FM_VLAN_SELECT_VLAN1 ||
        selector > FM_VLAN_SELECT_VLAN2)
        return FM_ERR_INVALID_ARGUMENT;
    slot = g_sim.n_vlans[selector];
    if (slot >= TEST_MAX_VLANS)
        return FM_ERR_BUFFER_FULL;
    g_sim.vlans[selector][slot].vlan = vlan;
    g_sim.vlans[selector][slot].direction = direction;
    g_sim.n_vlans[selector]++;
    g_sim.writes++;
    return FM_OK;
}

const char *fmErrorMsg(fm_int status) {
    (void)status;
    return "mock FM status";
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

static void test_enumeration_errors_fail_closed(void) {
    hal_mirror_state state;

    reset_simulator();
    seed_default_group();
    g_sim.v2_first_status = FM_FAIL;
    expect("V2 first-port error is fail-closed",
           hal_mirror_state_get(0, TEST_GROUP, &state) != 0 &&
           g_sim.writes == 0);

    reset_simulator();
    seed_default_group();
    g_sim.v2_first_status = FM_ERR_UNSUPPORTED;
    g_sim.legacy_first_status = FM_FAIL;
    expect("legacy first-port error is fail-closed",
           hal_mirror_state_get(0, TEST_GROUP, &state) != 0 &&
           g_sim.writes == 0);

    reset_simulator();
    g_sim.exists = true;
    expect("an empty existing mirror is captured exactly",
           hal_mirror_state_get(0, TEST_GROUP, &state) == 0 &&
           state.exists && state.exact_snapshot &&
           state.n_sources == 0 && state.n_vlan_sources == 0);
}

static void seed_extended_group(void) {
    seed_default_group();
    g_sim.type = FM_MIRROR_TYPE_BIDIRECTIONAL;
    g_sim.n_ports = 2;
    g_sim.ports[0] = 7;
    g_sim.port_types[0] = FM_MIRROR_TYPE_EGRESS;
    g_sim.ports[1] = 2;
    g_sim.port_types[1] = FM_MIRROR_TYPE_INGRESS;
    g_sim.truncate = TRUE;
    g_sim.sample_rate = 17;
    g_sim.encapsulation_vlan = 300;
    g_sim.vlan_priority = 5;
    g_sim.trapcode_id = 7;
    g_sim.n_vlans[FM_VLAN_SELECT_VLAN1] = 1;
    g_sim.vlans[FM_VLAN_SELECT_VLAN1][0].vlan = 100;
    g_sim.vlans[FM_VLAN_SELECT_VLAN1][0].direction =
        FM_MIRROR_VLAN_EGRESS;
    g_sim.n_vlans[FM_VLAN_SELECT_VLAN2] = 1;
    g_sim.vlans[FM_VLAN_SELECT_VLAN2][0].vlan = 200;
    g_sim.vlans[FM_VLAN_SELECT_VLAN2][0].direction =
        FM_MIRROR_VLAN_INGRESS;
}

static void test_complete_snapshot_and_failures(void) {
    hal_mirror_state state;

    reset_simulator();
    seed_extended_group();
    expect("mirror snapshot preserves ports, VLAN1/VLAN2, and attributes",
           hal_mirror_state_get(0, TEST_GROUP, &state) == 0 &&
           state.attributes_valid && state.truncate &&
           state.sample_rate == 17 &&
           state.encapsulation_vlan == 300 &&
           state.vlan_priority == 5 && state.trapcode_id == 7 &&
           state.source_ports[0] == 2 &&
           state.source_ports[1] == 7 &&
           state.n_vlan_sources == 2 &&
           state.source_vlan_selectors[0] == FM_VLAN_SELECT_VLAN1 &&
           state.source_vlans[0] == 100 &&
           state.source_vlan_selectors[1] == FM_VLAN_SELECT_VLAN2 &&
           state.source_vlans[1] == 200);

    reset_simulator();
    seed_default_group();
    g_sim.fail_attribute = FM_MIRROR_SAMPLE_RATE;
    expect("attribute read error is fail-closed",
           hal_mirror_state_get(0, TEST_GROUP, &state) != 0);

    reset_simulator();
    seed_default_group();
    g_sim.fail_vlan_selector = FM_VLAN_SELECT_VLAN2;
    g_sim.fail_vlan_status = FM_FAIL;
    expect("VLAN source read error is fail-closed",
           hal_mirror_state_get(0, TEST_GROUP, &state) != 0);

    reset_simulator();
    seed_default_group();
    g_sim.acl_filter = TRUE;
    expect("ACL-bound foreign mirror is rejected before mutation",
           hal_mirror_state_get(0, TEST_GROUP, &state) != 0 &&
           g_sim.writes == 0);
}

static void test_exact_restore_and_delete_proof(void) {
    hal_mirror_state wanted;
    hal_mirror_state actual;

    reset_simulator();
    seed_extended_group();
    expect("extended before-image capture succeeds",
           hal_mirror_state_get(0, TEST_GROUP, &wanted) == 0);
    g_sim.type = FM_MIRROR_TYPE_INGRESS;
    g_sim.n_ports = 1;
    g_sim.ports[0] = 9;
    g_sim.port_types[0] = FM_MIRROR_TYPE_INGRESS;
    memset(g_sim.n_vlans, 0, sizeof(g_sim.n_vlans));
    g_sim.truncate = FALSE;
    g_sim.sample_rate = FM_MIRROR_SAMPLE_RATE_DISABLED;
    g_sim.encapsulation_vlan = FM_MIRROR_NO_VLAN_ENCAP;
    g_sim.vlan_priority = 0;
    g_sim.trapcode_id = 0;
    expect("replace restores and proves the full mirror before-image",
           hal_mirror_session_replace(0, &wanted) == 0 &&
           hal_mirror_state_get(0, TEST_GROUP, &actual) == 0 &&
           hal_mirror_state_equal(&wanted, &actual));

    reset_simulator();
    seed_default_group();
    expect("delete is accepted only after absent readback",
           hal_mirror_session_delete(0, TEST_GROUP) == 0 &&
           !g_sim.exists);

    reset_simulator();
    seed_default_group();
    g_sim.ignore_delete = true;
    expect("successful delete call with live group fails readback",
           hal_mirror_session_delete(0, TEST_GROUP) != 0 &&
           g_sim.exists);
}

int main(void) {
    test_enumeration_errors_fail_closed();
    test_complete_snapshot_and_failures();
    test_exact_restore_and_delete_proof();
    if (g_failures != 0) {
        fprintf(stderr, "%d mirror transaction checks failed\n", g_failures);
        return 1;
    }
    puts("PASS: mirror transaction state is exact and fail-closed");
    return 0;
}
