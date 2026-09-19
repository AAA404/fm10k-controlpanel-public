/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define LAG_DELETE_READBACK_ATTEMPTS 3
#define LAG_DELETE_READBACK_INTERVAL_US 1

#include "../../sbin/switchd/hal_vlan.c"
#include "../../sbin/switchd/hal_lag.c"
#include "../../sbin/switchd/l2_plan_storage.c"
#include "../../sbin/switchd/read_back_verifier.c"

bool fm10k_native_profile(void) { return false; }
int hal_fm10k_lag_member_set(int sw, int lag, int port, bool attached) {
    (void)sw; (void)lag; (void)port; (void)attached; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_members_status(int lag, const int *members, int count) {
    (void)lag; (void)members; (void)count; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_restore_port(int sw, int lag, int port, uint64_t tx) {
    (void)sw; (void)lag; (void)port; (void)tx; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_transaction_check(uint64_t tx, bool committed) {
    (void)tx; (void)committed; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
void hal_fm10k_lag_transaction_retire(uint64_t tx) { (void)tx; }
int hal_fm10k_lag_del_port_transaction(int sw, int lag, int port, uint64_t tx) {
    (void)sw; (void)lag; (void)port; (void)tx; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_attributes_capture(int sw, int lag, fm10k_lag_attributes *out) {
    (void)sw; (void)lag; (void)out; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_attributes_restore(int sw, int lag, const fm10k_lag_attributes *before) {
    (void)sw; (void)lag; (void)before; return NL_ERR_CAPABILITY_INSUFFICIENT;
}

typedef struct {
    bool vlan_exists;
    int vlan_id;
    bool vlan_member;
    bool vlan_member_iterated;
    bool vlan_tagged;
    int vlan_port;
    int vlan_first_override;
    int vlan_port_first_override;
    fm_status vlan_first_status;
    fm_status vlan_next_status;
    fm_status vlan_port_first_status;
    fm_status vlan_port_next_status;
    fm_status vlan_tag_status;
    fm_status vlan_delete_status;
    fm_status vlan_remove_status;
    bool vlan_delete_changes_state;
    bool vlan_remove_changes_state;
    int vlan_first_calls;
    int vlan_next_calls;
    int vlan_port_first_calls;
    int vlan_port_next_calls;
    int vlan_tag_calls;

    bool lag_exists;
    int lag_id;
    bool lag_member;
    int lag_port;
    int lag_first_override;
    int lag_next_override;
    int lag_port_first_override;
    int lag_port_next_override;
    bool lag_unbounded, lag_port_unbounded;
    fm_status lag_first_status;
    fm_status lag_next_status;
    fm_status lag_port_first_status;
    fm_status lag_port_next_status;
    fm_status lag_delete_status;
    fm_status lag_remove_status;
    bool lag_delete_changes_state;
    bool lag_remove_changes_state;
    int lag_first_calls;
    int lag_next_calls;
    int lag_port_first_calls;
    int lag_port_next_calls;
} presence_simulator;

static presence_simulator g_sim;
static l2_apply_plan g_last_writer_plan;
static int g_failed;

static void reset_simulator(void) {
    memset(&g_sim, 0, sizeof(g_sim));
    g_sim.vlan_exists = true;
    g_sim.vlan_id = 100;
    g_sim.vlan_member = true;
    g_sim.vlan_member_iterated = true;
    g_sim.vlan_tagged = true;
    g_sim.vlan_port = 7;
    g_sim.vlan_first_override = INT_MIN;
    g_sim.vlan_port_first_override = INT_MIN;
    g_sim.vlan_first_status = FM_OK;
    g_sim.vlan_next_status = FM_OK;
    g_sim.vlan_port_first_status = FM_OK;
    g_sim.vlan_port_next_status = FM_OK;
    g_sim.vlan_tag_status = FM_OK;
    g_sim.vlan_delete_status = FM_OK;
    g_sim.vlan_remove_status = FM_OK;
    g_sim.vlan_delete_changes_state = true;
    g_sim.vlan_remove_changes_state = true;

    g_sim.lag_exists = true;
    g_sim.lag_id = 42;
    g_sim.lag_member = true;
    g_sim.lag_port = 7;
    g_sim.lag_first_override = INT_MIN;
    g_sim.lag_next_override = INT_MIN;
    g_sim.lag_port_first_override = INT_MIN;
    g_sim.lag_port_next_override = INT_MIN;
    g_sim.lag_first_status = FM_OK;
    g_sim.lag_next_status = FM_ERR_NO_LAGS;
    g_sim.lag_port_first_status = FM_OK;
    g_sim.lag_port_next_status = FM_ERR_NO_PORTS_IN_LAG;
    g_sim.lag_delete_status = FM_OK;
    g_sim.lag_remove_status = FM_OK;
    g_sim.lag_delete_changes_state = true;
    g_sim.lag_remove_changes_state = true;
}

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failed++;
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

const char *fmErrorMsg(fm_int err) {
    (void)err;
    return "injected SDK status";
}

fm_status fmGetVlanFirst(fm_int sw, fm_int *first_id) {
    (void)sw;
    g_sim.vlan_first_calls++;
    if (g_sim.vlan_first_status != FM_OK)
        return g_sim.vlan_first_status;
    *first_id = g_sim.vlan_first_override != INT_MIN ?
        g_sim.vlan_first_override :
        (g_sim.vlan_exists ? g_sim.vlan_id : -1);
    return FM_OK;
}

fm_status fmGetVlanNext(fm_int sw, fm_int start_id, fm_int *next_id) {
    (void)sw;
    g_sim.vlan_next_calls++;
    if (g_sim.vlan_next_status != FM_OK)
        return g_sim.vlan_next_status;
    *next_id = g_sim.vlan_exists && start_id < g_sim.vlan_id ?
        g_sim.vlan_id : -1;
    return FM_OK;
}

fm_status fmGetVlanPortFirst(fm_int sw, fm_int vlan_id,
                             fm_int *first_port) {
    (void)sw;
    g_sim.vlan_port_first_calls++;
    if (g_sim.vlan_port_first_status != FM_OK)
        return g_sim.vlan_port_first_status;
    if (!g_sim.vlan_exists || vlan_id != g_sim.vlan_id)
        return FM_ERR_INVALID_VLAN;
    *first_port = g_sim.vlan_port_first_override != INT_MIN ?
        g_sim.vlan_port_first_override :
        (g_sim.vlan_member && g_sim.vlan_member_iterated ?
         g_sim.vlan_port : -1);
    return FM_OK;
}

fm_status fmGetVlanPortNext(fm_int sw, fm_int vlan_id,
                            fm_int start_port, fm_int *next_port) {
    (void)sw;
    (void)vlan_id;
    g_sim.vlan_port_next_calls++;
    if (g_sim.vlan_port_next_status != FM_OK)
        return g_sim.vlan_port_next_status;
    *next_port =
        g_sim.vlan_member && g_sim.vlan_member_iterated &&
        start_port < g_sim.vlan_port ? g_sim.vlan_port : -1;
    return FM_OK;
}

fm_status fmGetVlanPortTag(fm_int sw, fm_int vlan_id, fm_int port,
                           fm_bool *tagged) {
    (void)sw;
    g_sim.vlan_tag_calls++;
    if (g_sim.vlan_tag_status != FM_OK)
        return g_sim.vlan_tag_status;
    if (!g_sim.vlan_exists || vlan_id != g_sim.vlan_id)
        return FM_ERR_INVALID_VLAN;
    if (!g_sim.vlan_member || port != g_sim.vlan_port)
        return FM_ERR_INVALID_PORT;
    *tagged = g_sim.vlan_tagged ? TRUE : FALSE;
    return FM_OK;
}

fm_status fmDeleteVlan(fm_int sw, fm_uint16 vlan_id) {
    (void)sw;
    (void)vlan_id;
    if (g_sim.vlan_delete_status == FM_OK &&
        g_sim.vlan_delete_changes_state) {
        g_sim.vlan_exists = false;
        g_sim.vlan_member = false;
    }
    return g_sim.vlan_delete_status;
}

fm_status fmDeleteVlanPort(fm_int sw, fm_uint16 vlan_id, fm_int port) {
    (void)sw;
    (void)vlan_id;
    (void)port;
    if (g_sim.vlan_remove_status == FM_OK &&
        g_sim.vlan_remove_changes_state)
        g_sim.vlan_member = false;
    return g_sim.vlan_remove_status;
}

fm_status fmGetLAGFirst(fm_int sw, fm_int *first_lag) {
    (void)sw;
    g_sim.lag_first_calls++;
    if (g_sim.lag_first_status != FM_OK)
        return g_sim.lag_first_status;
    if (!g_sim.lag_exists) {
        *first_lag = -1;
        return FM_ERR_NO_LAGS;
    }
    *first_lag = g_sim.lag_first_override != INT_MIN ?
        g_sim.lag_first_override : g_sim.lag_id;
    return FM_OK;
}

fm_status fmGetLAGNext(fm_int sw, fm_int current_lag,
                       fm_int *next_lag) {
    (void)sw;
    g_sim.lag_next_calls++;
    if (g_sim.lag_next_status != FM_OK)
        return g_sim.lag_next_status;
    *next_lag = g_sim.lag_next_override != INT_MIN ? g_sim.lag_next_override :
        g_sim.lag_unbounded ? current_lag + 1 :
        g_sim.lag_exists && current_lag < g_sim.lag_id ? g_sim.lag_id : -1;
    return FM_OK;
}

fm_status fmGetLAGPortFirst(fm_int sw, fm_int lag_id,
                            fm_int *first_port) {
    (void)sw;
    g_sim.lag_port_first_calls++;
    if (g_sim.lag_port_first_status != FM_OK)
        return g_sim.lag_port_first_status;
    if (!g_sim.lag_exists || lag_id != g_sim.lag_id)
        return FM_ERR_INVALID_LAG;
    if (!g_sim.lag_member)
        return FM_ERR_NO_PORTS_IN_LAG;
    *first_port = g_sim.lag_port_first_override != INT_MIN ?
        g_sim.lag_port_first_override : g_sim.lag_port;
    return FM_OK;
}

fm_status fmGetLAGPortNext(fm_int sw, fm_int lag_id,
                           fm_int current_port, fm_int *next_port) {
    (void)sw;
    (void)lag_id;
    g_sim.lag_port_next_calls++;
    if (g_sim.lag_port_next_status != FM_OK)
        return g_sim.lag_port_next_status;
    *next_port = g_sim.lag_port_next_override != INT_MIN ? g_sim.lag_port_next_override :
        g_sim.lag_port_unbounded ? current_port + 1 :
        g_sim.lag_member && current_port < g_sim.lag_port ?
        g_sim.lag_port : -1;
    return FM_OK;
}

fm_status fmDeleteLAG(fm_int sw, fm_int lag_id) {
    (void)sw;
    (void)lag_id;
    if (g_sim.lag_delete_status == FM_OK &&
        g_sim.lag_delete_changes_state) {
        g_sim.lag_exists = false;
        g_sim.lag_member = false;
    }
    return g_sim.lag_delete_status;
}

fm_status fmDeleteLAGPort(fm_int sw, fm_int lag_id, fm_int port) {
    (void)sw;
    (void)lag_id;
    (void)port;
    if (g_sim.lag_remove_status == FM_OK &&
        g_sim.lag_remove_changes_state)
        g_sim.lag_member = false;
    return g_sim.lag_remove_status;
}

static void test_vlan_presence(void) {
    hal_presence_snapshot snapshot;
    struct verify_result result;

    reset_simulator();
    snapshot = hal_vlan_presence_snapshot(0, 100);
    expect("VLAN presence reports PRESENT after a successful read",
           snapshot.state == HAL_PRESENCE_PRESENT &&
           snapshot.sdk_status == FM_OK);

    reset_simulator();
    g_sim.vlan_exists = false;
    snapshot = hal_vlan_presence_snapshot(0, 100);
    expect("VLAN negative iterator sentinel is explicit ABSENT",
           snapshot.state == HAL_PRESENCE_ABSENT &&
           g_sim.vlan_next_calls == 0);

    reset_simulator();
    g_sim.vlan_first_status = FM_FAIL;
    snapshot = hal_vlan_presence_snapshot(0, 100);
    expect("VLAN first read failure remains READ_ERROR",
           snapshot.state == HAL_PRESENCE_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    g_sim.vlan_first_override = 50;
    g_sim.vlan_next_status = FM_FAIL;
    snapshot = hal_vlan_presence_snapshot(0, 100);
    expect("VLAN iterator read failure is not absence",
           snapshot.state == HAL_PRESENCE_READ_ERROR &&
           g_sim.vlan_next_calls == 1);

    reset_simulator();
    g_sim.vlan_tagged = false;
    snapshot = hal_vlan_member_snapshot(0, 100, 7);
    expect("VLAN tag mismatch preserves PRESENT membership",
           snapshot.state == HAL_PRESENCE_PRESENT && !snapshot.tagged);
    memset(&result, 0, sizeof(result));
    expect("VLAN remove verifier rejects a present untagged member",
           verify_vlan_member_presence(
               0, 100, 7, false, false, false, &result) != 0 &&
           !result.readback_ok && result.sdk_status == 0);
    memset(&result, 0, sizeof(result));
    expect("VLAN add verifier reports tag mismatch, not absence",
           verify_vlan_port_member(0, 100, 7, true, &result) != 0 &&
           strstr(result.detail, "tag mismatch") != NULL);

    reset_simulator();
    g_sim.vlan_tag_status = FM_FAIL;
    snapshot = hal_vlan_member_snapshot(0, 100, 7);
    expect("VLAN tag read failure remains READ_ERROR",
           snapshot.state == HAL_PRESENCE_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);
    memset(&result, 0, sizeof(result));
    expect("VLAN remove verifier fails closed on tag read error",
           verify_vlan_member_presence(
               0, 100, 7, false, false, false, &result) != 0 &&
           result.sdk_status == FM_FAIL);
}

static void test_vlan_mutation_readback(void) {
    reset_simulator();
    expect("VLAN delete succeeds only after explicit ABSENT",
           hal_vlan_delete(0, 100) == 0);

    reset_simulator();
    g_sim.vlan_delete_changes_state = false;
    expect("VLAN delete rejects a successful write that remains PRESENT",
           hal_vlan_delete(0, 100) != 0);

    reset_simulator();
    g_sim.vlan_first_status = FM_FAIL;
    expect("VLAN delete fails closed when post-write read fails",
           hal_vlan_delete(0, 100) != 0);

    reset_simulator();
    expect("VLAN member removal succeeds only after explicit ABSENT",
           hal_vlan_remove_port(0, 100, 7) == 0);

    reset_simulator();
    g_sim.vlan_remove_changes_state = false;
    expect("VLAN member removal rejects a member that remains PRESENT",
           hal_vlan_remove_port(0, 100, 7) != 0);

    reset_simulator();
    g_sim.vlan_tag_status = FM_FAIL;
    expect("VLAN member removal fails closed on post-write read error",
           hal_vlan_remove_port(0, 100, 7) != 0);
}

static void test_lag_presence(void) {
    hal_presence_snapshot snapshot;
    struct verify_result result;

    reset_simulator();
    snapshot = hal_lag_presence_snapshot(0, 42);
    expect("LAG presence reports PRESENT after a successful read",
           snapshot.state == HAL_PRESENCE_PRESENT);

    reset_simulator();
    g_sim.lag_exists = false;
    snapshot = hal_lag_presence_snapshot(0, 42);
    expect("FM_ERR_NO_LAGS is explicit ABSENT",
           snapshot.state == HAL_PRESENCE_ABSENT &&
           g_sim.lag_next_calls == 0);

    reset_simulator();
    g_sim.lag_first_status = FM_FAIL;
    snapshot = hal_lag_presence_snapshot(0, 42);
    expect("LAG first read failure remains READ_ERROR",
           snapshot.state == HAL_PRESENCE_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    g_sim.lag_first_override = 41;
    g_sim.lag_next_status = FM_FAIL;
    snapshot = hal_lag_presence_snapshot(0, 42);
    expect("LAG iterator read failure is not absence",
           snapshot.state == HAL_PRESENCE_READ_ERROR &&
           g_sim.lag_next_calls == 1);

    reset_simulator();
    g_sim.lag_port_first_override = 6;
    g_sim.lag_port_next_status = FM_FAIL;
    snapshot = hal_lag_member_snapshot(0, 42, 7);
    expect("LAG member iterator failure remains READ_ERROR",
           snapshot.state == HAL_PRESENCE_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    g_sim.lag_first_status = FM_FAIL;
    memset(&result, 0, sizeof(result));
    expect("LAG delete barrier fails immediately on read error",
           verify_lag_presence(0, 42, false, &result) != 0 &&
           result.sdk_status == FM_FAIL &&
           g_sim.lag_first_calls == 1);

    reset_simulator();
    snapshot = hal_lag_wait_absent(0, 42);
    expect("LAG delete barrier never turns a bounded timeout into ABSENT",
           snapshot.state == HAL_PRESENCE_PRESENT &&
           g_sim.lag_first_calls == LAG_DELETE_READBACK_ATTEMPTS);
}

static void test_lag_mutation_readback(void) {
    reset_simulator();
    expect("LAG delete succeeds only after explicit ABSENT",
           hal_lag_delete(0, 42) == 0);

    reset_simulator();
    g_sim.lag_delete_changes_state = false;
    expect("LAG delete rejects a successful write that remains PRESENT",
           hal_lag_delete(0, 42) != 0 &&
           g_sim.lag_first_calls == LAG_DELETE_READBACK_ATTEMPTS);

    reset_simulator();
    g_sim.lag_first_status = FM_FAIL;
    expect("LAG delete fails closed on barrier read error",
           hal_lag_delete(0, 42) != 0 &&
           g_sim.lag_first_calls == 1);

    reset_simulator();
    expect("LAG member removal succeeds only after explicit ABSENT",
           hal_lag_del_port(0, 42, 7) == 0);

    reset_simulator();
    g_sim.lag_remove_changes_state = false;
    expect("LAG member removal rejects a member that remains PRESENT",
           hal_lag_del_port(0, 42, 7) != 0);

    reset_simulator();
    g_sim.lag_port_first_status = FM_FAIL;
    expect("LAG member removal fails closed on post-write read error",
           hal_lag_del_port(0, 42, 7) != 0);
}

static void test_lag_malformed_iterators(void) {
    hal_presence_snapshot snapshot;
    const int malformed[] = {0, -1};
    for (unsigned i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        reset_simulator(); g_sim.lag_first_override = malformed[i];
        snapshot = hal_lag_presence_snapshot(0, 42);
        expect("LAG successful first read with an invalid handle is READ_ERROR",
               snapshot.state == HAL_PRESENCE_READ_ERROR && !g_sim.lag_next_calls);

        reset_simulator(); g_sim.lag_next_status = FM_OK;
        g_sim.lag_first_override = 41; g_sim.lag_next_override = malformed[i];
        snapshot = hal_lag_presence_snapshot(0, 42);
        expect("LAG successful next read with an invalid handle is READ_ERROR",
               snapshot.state == HAL_PRESENCE_READ_ERROR && g_sim.lag_next_calls == 1);

        reset_simulator(); g_sim.lag_port_first_override = malformed[i];
        snapshot = hal_lag_member_snapshot(0, 42, 7);
        expect("LAG successful first member read with an invalid port is READ_ERROR",
               snapshot.state == HAL_PRESENCE_READ_ERROR && !g_sim.lag_port_next_calls);

        reset_simulator(); g_sim.lag_port_next_status = FM_OK;
        g_sim.lag_port_first_override = 6; g_sim.lag_port_next_override = malformed[i];
        snapshot = hal_lag_member_snapshot(0, 42, 7);
        expect("LAG successful next member read with an invalid port is READ_ERROR",
               snapshot.state == HAL_PRESENCE_READ_ERROR && g_sim.lag_port_next_calls == 1);
    }
    reset_simulator(); g_sim.lag_next_status = FM_OK;
    g_sim.lag_first_override = g_sim.lag_next_override = 41;
    snapshot = hal_lag_presence_snapshot(0, 42);
    expect("LAG enumeration cycle is rejected without blocking the SDK owner",
           snapshot.state == HAL_PRESENCE_READ_ERROR && g_sim.lag_next_calls == 1);

    reset_simulator(); g_sim.lag_port_next_status = FM_OK;
    g_sim.lag_port_first_override = g_sim.lag_port_next_override = 6;
    snapshot = hal_lag_member_snapshot(0, 42, 7);
    expect("LAG member enumeration cycle is rejected without blocking the SDK owner",
           snapshot.state == HAL_PRESENCE_READ_ERROR && g_sim.lag_port_next_calls == 1);

    reset_simulator(); g_sim.lag_next_status = FM_OK; g_sim.lag_unbounded = true;
    snapshot = hal_lag_presence_snapshot(0, 1000);
    expect("LAG enumeration is bounded by the supported inventory capacity",
           snapshot.state == HAL_PRESENCE_READ_ERROR && g_sim.lag_next_calls == NETLAB_MAX_AE);

    reset_simulator(); g_sim.lag_port_next_status = FM_OK; g_sim.lag_port_unbounded = true;
    snapshot = hal_lag_member_snapshot(0, 42, 1000);
    expect("LAG member enumeration is bounded by the supported member capacity",
           snapshot.state == HAL_PRESENCE_READ_ERROR && g_sim.lag_port_next_calls == NETLAB_MAX_LAG_MEMBERS);

    reset_simulator(); g_sim.lag_delete_changes_state = false; g_sim.lag_first_override = 0;
    expect("LAG deletion cannot succeed on an invalid post-write handle",
           hal_lag_delete(0, 42) != 0 && g_sim.lag_exists && g_sim.lag_first_calls == 1);

    reset_simulator(); g_sim.lag_remove_changes_state = false; g_sim.lag_port_first_override = 0;
    expect("LAG member removal cannot succeed on an invalid post-write port",
           hal_lag_del_port(0, 42, 7) != 0 && g_sim.lag_member);
}

static void reset_last_writer_pair(l2_step_type first,
                                   l2_step_type second) {
    l2_apply_plan_reset(&g_last_writer_plan);
    if (l2_apply_plan_allocate_steps(&g_last_writer_plan, 2) != 0) {
        fputs("failed to allocate last-writer fixture\n", stderr);
        exit(2);
    }
    g_last_writer_plan.n_steps = 2;
    g_last_writer_plan.steps[0].type = first;
    g_last_writer_plan.steps[1].type = second;
    g_last_writer_plan.steps[0].ae_id = -1;
    g_last_writer_plan.steps[1].ae_id = -1;
}

static bool first_step_is_superseded(void) {
    return readback_superseding_step_index(
        &g_last_writer_plan, 0, g_last_writer_plan.n_steps) == 1;
}

static void test_final_readback_last_writer(void) {
    l2_apply_step *first;
    l2_apply_step *last;

    reset_last_writer_pair(L2_STEP_STORM_CONTROL_DEL,
                           L2_STEP_STORM_CONTROL_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 7;
    last->storm_rate_kbps = 2000;
    expect("storm DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_INGRESS_RATE_LIMIT_DEL,
                           L2_STEP_INGRESS_RATE_LIMIT_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 8;
    expect("ingress-rate DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_EGRESS_RATE_LIMIT_DEL,
                           L2_STEP_EGRESS_RATE_LIMIT_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 9;
    expect("egress-rate DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_INTERFACE_DEL,
                           L2_STEP_QOS_INTERFACE_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 10;
    expect("QoS interface DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_PFC_DEL,
                           L2_STEP_QOS_PFC_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 11;
    expect("QoS PFC DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_PRIORITY_MAP_DEL,
                           L2_STEP_QOS_PRIORITY_MAP_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->qos_switch_priority = last->qos_switch_priority = 12;
    expect("QoS priority DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_SCHEDULER_TC_MAP_DEL,
                           L2_STEP_QOS_SCHEDULER_TC_MAP_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 12;
    first->qos_scheduler_traffic_class =
        last->qos_scheduler_traffic_class = 3;
    expect("scheduler TC-map DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_SCHEDULER_GROUP_DEL,
                           L2_STEP_QOS_SCHEDULER_GROUP_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 12;
    first->qos_scheduler_group = last->qos_scheduler_group = 4;
    expect("scheduler group DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(
        L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL,
        L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 12;
    first->qos_scheduler_group = last->qos_scheduler_group = 4;
    expect("scheduler shaping DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_SCHEDULER_PORT_DEL,
                           L2_STEP_QOS_SCHEDULER_PORT_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 12;
    expect("scheduler port DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_WATERMARK_DEL,
                           L2_STEP_QOS_WATERMARK_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 13;
    first->qos_watermark_attr = last->qos_watermark_attr =
        HAL_QOS_WATERMARK_ATTR_TX_HOG;
    first->qos_watermark_index = last->qos_watermark_index = 2;
    expect("per-port watermark DEL->SET verifies only the final writer",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_WATERMARK_DEL,
                           L2_STEP_QOS_WATERMARK_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = 0;
    last->port = 17;
    first->qos_watermark_attr = last->qos_watermark_attr =
        HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP;
    first->qos_watermark_index = last->qos_watermark_index = 0;
    expect("switch watermark scope ignores incidental port fields",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_ACL_POLICER_DEL,
                           L2_STEP_ACL_POLICER_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->acl_policer.port = last->acl_policer.port = 14;
    first->acl_policer.dst_mac = last->acl_policer.dst_mac =
        UINT64_C(0x001122334455);
    first->acl_policer.rate_kbps = 1000;
    last->acl_policer.rate_kbps = 2000;
    expect("ACL policer rate update keeps one semantic read-back key",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_EGRESS_ACL_DEL,
                           L2_STEP_EGRESS_ACL_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->egress_acl.port = last->egress_acl.port = 15;
    first->egress_acl.src_mac = last->egress_acl.src_mac =
        UINT64_C(0x001122334455);
    first->egress_acl.dst_mac = last->egress_acl.dst_mac =
        UINT64_C(0x006655443322);
    expect("egress ACL DEL->SET verifies only the final owner",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_ACL_INDEPENDENT_DEL,
                           L2_STEP_ACL_INDEPENDENT_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->acl_independent.slot = last->acl_independent.slot = 5;
    expect("independent ACL slot update verifies only the final owner",
           first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_INGRESS_IPV4_ACL_DEL,
                           L2_STEP_INGRESS_IPV4_ACL_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->ingress_ipv4_acl.vid = last->ingress_ipv4_acl.vid = 100;
    first->ingress_ipv4_acl.port = last->ingress_ipv4_acl.port = 16;
    first->ingress_ipv4_acl.has_protocol =
        last->ingress_ipv4_acl.has_protocol = true;
    first->ingress_ipv4_acl.protocol =
        last->ingress_ipv4_acl.protocol = 6;
    first->ingress_ipv4_acl.count_only = false;
    last->ingress_ipv4_acl.count_only = true;
    expect("ingress ACL action update shares the live rule identity",
           first_step_is_superseded());
}

static void test_final_readback_distinct_keys(void) {
    l2_apply_step *first;
    l2_apply_step *last;

    reset_last_writer_pair(L2_STEP_STORM_CONTROL_DEL,
                           L2_STEP_STORM_CONTROL_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = 7;
    last->port = 8;
    expect("storm writes on different ports both remain verifiable",
           !first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_INGRESS_RATE_LIMIT_SET,
                           L2_STEP_EGRESS_RATE_LIMIT_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 7;
    expect("independent ingress and egress limit keys do not collide",
           !first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_SCHEDULER_GROUP_SET,
                           L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 9;
    first->qos_scheduler_group = last->qos_scheduler_group = 2;
    expect("scheduler topology and shaping remain separately verified",
           !first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_PFC_SET,
                           L2_STEP_QOS_WATERMARK_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 10;
    last->qos_watermark_attr = HAL_QOS_WATERMARK_ATTR_TX_HOG;
    last->qos_watermark_index = 0;
    expect("PFC input and direct watermark remain separately verified",
           !first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_ACL_POLICER_SET,
                           L2_STEP_ACL_INDEPENDENT_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->acl_policer.port = last->acl_independent.port = 11;
    last->acl_independent.slot = 0;
    expect("owners sharing an ACL parent keep distinct read-back keys",
           !first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_QOS_WATERMARK_DEL,
                           L2_STEP_QOS_WATERMARK_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->port = last->port = 12;
    first->qos_watermark_attr = last->qos_watermark_attr =
        HAL_QOS_WATERMARK_ATTR_TX_HOG;
    first->qos_watermark_index = 1;
    last->qos_watermark_index = 2;
    expect("different watermark indices both remain verifiable",
           !first_step_is_superseded());

    reset_last_writer_pair(L2_STEP_ACL_POLICER_DEL,
                           L2_STEP_ACL_POLICER_SET);
    first = &g_last_writer_plan.steps[0];
    last = &g_last_writer_plan.steps[1];
    first->acl_policer.port = last->acl_policer.port = 13;
    first->acl_policer.dst_mac = UINT64_C(0x001122334455);
    last->acl_policer.dst_mac = UINT64_C(0x001122334456);
    expect("different ACL policer identities both remain verifiable",
           !first_step_is_superseded());

    l2_apply_plan_reset(&g_last_writer_plan);
    if (l2_apply_plan_allocate_steps(&g_last_writer_plan, 3) != 0) {
        fputs("failed to allocate distinct-key fixture\n", stderr);
        exit(2);
    }
    g_last_writer_plan.n_steps = 3;
    for (int i = 0; i < 3; i++) {
        g_last_writer_plan.steps[i].type =
            i == 1 ? L2_STEP_STORM_CONTROL_SET :
                     L2_STEP_STORM_CONTROL_DEL;
        g_last_writer_plan.steps[i].ae_id = -1;
        g_last_writer_plan.steps[i].port = 14;
    }
    expect("multiple writes leave only the last semantic writer",
           readback_superseding_step_index(
               &g_last_writer_plan, 0, 3) == 1 &&
           readback_superseding_step_index(
               &g_last_writer_plan, 1, 3) == 2 &&
           readback_superseding_step_index(
               &g_last_writer_plan, 2, 3) == -1);
}

int main(void) {
    test_vlan_presence();
    test_vlan_mutation_readback();
    test_lag_presence();
    test_lag_mutation_readback();
    test_lag_malformed_iterators();
    test_final_readback_last_writer();
    test_final_readback_distinct_keys();
    l2_apply_plan_reset(&g_last_writer_plan);
    if (g_failed != 0) {
        fprintf(stderr, "%d presence/read-back checks failed\n", g_failed);
        return 1;
    }
    puts("PASS: VLAN/LAG presence and mutation read-back are fail closed");
    return 0;
}
