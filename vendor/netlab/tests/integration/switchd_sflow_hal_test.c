#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

static unsigned int g_fixture_settle_calls;
static bool g_arm_delayed_capture;
static bool g_deliver_delayed_capture;
static void sflow_fixture_settle(void);
#define SFLOW_PROBE_SETTLE() sflow_fixture_settle()
#include "../../sbin/switchd/hal_sflow.c"

typedef enum {
    API_GET_SFLOW_TYPE = 0,
    API_GET_SFLOW_ATTRIBUTE,
    API_GET_MIRROR_ATTRIBUTE,
    API_GET_SFLOW_PORT_LIST,
    API_GET_MIRROR,
    API_DELETE_SFLOW,
    API_CREATE_SFLOW,
    API_SET_SFLOW_RATE,
    API_ADD_SFLOW_PORT,
    API_GET_PORT_STATE,
    API_GET_PORT_COUNTERS,
    API_GET_SPAN_STATE,
    API_KIND_COUNT,
} api_kind;

typedef struct {
    bool sflow_exists;
    bool foreign_group31;
    fm_sFlowType sflow_type;
    fm_uint requested_rate;
    fm_uint16 vlan;
    fm_uint64 sample_count;
    fm_int trap_code;
    fm_int mirror_trap_code;
    fm_int effective_rate;
    fm_int port_count;
    fm_int ports[NL_SFLOW_V1_MAX_PORTS];
    fm_int port_modes[3];
    fm_int port_states[3];
    fm_portCounters port_counters[3];
    unsigned int port_guard_index;
    hal_mirror_state span;
    nl_sflow_capture_counters_v1 capture;
} sdk_simulator;

static sdk_simulator g_sim;
static unsigned int g_api_calls[API_KIND_COUNT];
static api_kind g_fail_api = API_KIND_COUNT;
static unsigned int g_fail_nth;
static fm_status g_fail_status = FM_FAIL;
static char g_mutations[128];
static size_t g_mutation_len;
static unsigned int g_span_changed_on_call;
static unsigned int g_capture_snapshot_calls;
static unsigned int g_capture_change_on_call;
static u64 g_capture_callback_delta;
static u64 g_capture_disabled_delta;
static u64 g_capture_free_failure_delta;

static void sflow_fixture_settle(void)
{
    g_fixture_settle_calls++;
    if (g_arm_delayed_capture && g_fixture_settle_calls == 2U)
        g_deliver_delayed_capture = true;
}

static int require_true(bool condition, const char *message)
{
    if (condition)
        return 0;
    fprintf(stderr, "%s\n", message);
    return 1;
}

static bool api_enter(api_kind kind, char mutation)
{
    g_api_calls[kind]++;
    if (mutation != '\0' && g_mutation_len + 1U < sizeof(g_mutations)) {
        g_mutations[g_mutation_len++] = mutation;
        g_mutations[g_mutation_len] = '\0';
    }
    return g_fail_api == kind && g_api_calls[kind] == g_fail_nth;
}

static void reset_observations(void)
{
    memset(g_api_calls, 0, sizeof(g_api_calls));
    memset(g_mutations, 0, sizeof(g_mutations));
    g_mutation_len = 0;
    g_fail_api = API_KIND_COUNT;
    g_fail_nth = 0;
    g_fail_status = FM_FAIL;
    g_span_changed_on_call = 0;
    g_capture_snapshot_calls = 0;
    g_capture_change_on_call = 0;
    g_capture_callback_delta = 0;
    g_capture_disabled_delta = 0;
    g_capture_free_failure_delta = 0;
    g_fixture_settle_calls = 0;
    g_arm_delayed_capture = false;
    g_deliver_delayed_capture = false;
    g_sim.port_guard_index = 0;
}

static void simulator_reset(void)
{
    fm_portCounters base;

    memset(&g_sim, 0, sizeof(g_sim));
    g_sim.sflow_type = FM_SFLOW_TYPE_INGRESS;
    g_sim.requested_rate = 1U;
    g_sim.effective_rate = 1;
    g_sim.vlan = FM_SFLOW_VLAN_ANY;
    g_sim.trap_code = SFLOW_V1_TRAP_CODE_ID;
    g_sim.mirror_trap_code = SFLOW_V1_MIRROR_TRAP_CODE_ID;

    memset(&base, 0, sizeof(base));
    base.cntRxUcstPkts = 10U;
    base.cntRxBcstPkts = 20U;
    base.cntRxMcstPkts = 30U;
    base.cntRxGoodOctets = 4096U;
    base.cntRxBadOctets = 2U;
    base.cntRxFCSErrors = 1U;
    base.cntRxFramingErrorPkts = 2U;
    base.cntRxHogDropPkts = 3U;
    base.cntRxCMDropPkts = 4U;
    for (size_t i = 0; i < 3U; i++) {
        /*
         * The deployed probe port is intentionally admin-up/link-down.
         * Quiescence is proven from operational state plus RX projections.
         */
        g_sim.port_modes[i] = FM_PORT_MODE_UP;
        g_sim.port_states[i] = FM_PORT_STATE_DOWN;
        g_sim.port_counters[i] = base;
    }

    g_sim.span.exists = true;
    g_sim.span.group = NETLAB_MIRROR_V1_GROUP;
    g_sim.span.destination_port = 17;
    g_sim.span.direction = HAL_MIRROR_DIRECTION_INGRESS;
    g_sim.span.n_sources = 2;
    g_sim.span.source_ports[0] = 2;
    g_sim.span.source_ports[1] = 9;
    g_sim.span.source_directions[0] = HAL_MIRROR_DIRECTION_INGRESS;
    g_sim.span.source_directions[1] = HAL_MIRROR_DIRECTION_INGRESS;
    reset_observations();
}

static void simulator_set_sflow(u32 requested_rate,
                                const int *ports, int port_count)
{
    g_sim.sflow_exists = true;
    g_sim.foreign_group31 = false;
    g_sim.sflow_type = FM_SFLOW_TYPE_INGRESS;
    g_sim.requested_rate = (fm_uint)requested_rate;
    g_sim.effective_rate = (fm_int)nl_sflow_effective_rate(requested_rate);
    g_sim.vlan = FM_SFLOW_VLAN_ANY;
    g_sim.sample_count = 77U;
    g_sim.trap_code = SFLOW_V1_TRAP_CODE_ID;
    g_sim.mirror_trap_code = SFLOW_V1_MIRROR_TRAP_CODE_ID;
    g_sim.port_count = (fm_int)port_count;
    memset(g_sim.ports, 0, sizeof(g_sim.ports));
    for (int i = 0; i < port_count; i++)
        g_sim.ports[i] = (fm_int)ports[i];
}

static void simulator_remove_sflow(void)
{
    g_sim.sflow_exists = false;
    g_sim.port_count = 0;
    memset(g_sim.ports, 0, sizeof(g_sim.ports));
}

static int capture_expected_state(nl_sflow_hw_state_v1 *expected)
{
    int rc;

    memset(expected, 0, sizeof(*expected));
    rc = hal_sflow_state_get(0, expected);
    reset_observations();
    return rc;
}

static int current_matches(const nl_sflow_hw_state_v1 *expected)
{
    nl_sflow_hw_state_v1 current;

    g_fail_api = API_KIND_COUNT;
    memset(&current, 0, sizeof(current));
    if (hal_sflow_state_get(0, &current) != 0)
        return 0;
    return sflow_config_equal(&current, expected);
}

fm_status fmGetSFlowType(fm_int sw, fm_int sflow_id,
                         fm_sFlowType *type)
{
    (void)sw;
    if (api_enter(API_GET_SFLOW_TYPE, '\0'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID || !type)
        return FM_FAIL;
    if (!g_sim.sflow_exists)
        return FM_ERR_INVALID_SFLOW_INSTANCE;
    *type = g_sim.sflow_type;
    return FM_OK;
}

fm_status fmGetSFlowAttribute(fm_int sw, fm_int sflow_id,
                              fm_int attr, void *value)
{
    (void)sw;
    if (api_enter(API_GET_SFLOW_ATTRIBUTE, '\0'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID ||
        !g_sim.sflow_exists || !value)
        return FM_FAIL;
    switch (attr) {
    case FM_SFLOW_SAMPLE_RATE:
        *(fm_uint *)value = g_sim.requested_rate;
        return FM_OK;
    case FM_SFLOW_VLAN:
        *(fm_uint16 *)value = g_sim.vlan;
        return FM_OK;
    case FM_SFLOW_TRAP_CODE:
        *(fm_int *)value = g_sim.trap_code;
        return FM_OK;
    case FM_SFLOW_COUNT:
        *(fm_uint64 *)value = g_sim.sample_count;
        return FM_OK;
    default:
        return FM_FAIL;
    }
}

fm_status fmGetMirrorAttribute(fm_int sw, fm_int group,
                               fm_int attr, void *value)
{
    (void)sw;
    if (api_enter(API_GET_MIRROR_ATTRIBUTE, '\0'))
        return g_fail_status;
    if (group != (fm_int)NL_SFLOW_V1_MIRROR_GROUP ||
        !g_sim.sflow_exists || !value)
        return FM_FAIL;
    switch (attr) {
    case FM_MIRROR_SAMPLE_RATE:
        *(fm_int *)value = g_sim.effective_rate;
        return FM_OK;
    case FM_MIRROR_TRAPCODE_ID:
        *(fm_int *)value = g_sim.mirror_trap_code;
        return FM_OK;
    default:
        return FM_FAIL;
    }
}

fm_status fmGetSFlowPortList(fm_int sw, fm_int sflow_id,
                             fm_int *num_ports, fm_int *ports,
                             fm_int max)
{
    (void)sw;
    if (api_enter(API_GET_SFLOW_PORT_LIST, '\0'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID ||
        !g_sim.sflow_exists || !num_ports || !ports ||
        max < g_sim.port_count)
        return FM_FAIL;
    if (g_sim.port_count == 0)
        return FM_ERR_NO_SFLOW_PORT;
    *num_ports = g_sim.port_count;
    for (fm_int i = 0; i < g_sim.port_count; i++)
        ports[i] = g_sim.ports[i];
    return FM_OK;
}

fm_status fmGetMirror(fm_int sw, fm_int group, fm_int *destination,
                      fm_mirrorType *type)
{
    (void)sw;
    if (api_enter(API_GET_MIRROR, '\0'))
        return g_fail_status;
    if (group != (fm_int)NL_SFLOW_V1_MIRROR_GROUP ||
        !destination || !type)
        return FM_FAIL;
    if (!g_sim.sflow_exists && !g_sim.foreign_group31)
        return FM_ERR_INVALID_PORT_MIRROR_GROUP;
    *destination = 1;
    *type = FM_MIRROR_TYPE_INGRESS;
    return FM_OK;
}

fm_status fmDeleteSFlow(fm_int sw, fm_int sflow_id)
{
    (void)sw;
    if (api_enter(API_DELETE_SFLOW, 'D'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID)
        return FM_FAIL;
    if (!g_sim.sflow_exists)
        return FM_ERR_INVALID_SFLOW_INSTANCE;
    simulator_remove_sflow();
    return FM_OK;
}

fm_status fmCreateSFlow(fm_int sw, fm_int sflow_id,
                        fm_sFlowType type)
{
    (void)sw;
    if (api_enter(API_CREATE_SFLOW, 'C'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID ||
        g_sim.sflow_exists || g_sim.foreign_group31)
        return FM_FAIL;
    g_sim.sflow_exists = true;
    g_sim.sflow_type = type;
    g_sim.requested_rate = 1U;
    g_sim.effective_rate = 1;
    g_sim.vlan = FM_SFLOW_VLAN_ANY;
    g_sim.sample_count = 0U;
    g_sim.trap_code = SFLOW_V1_TRAP_CODE_ID;
    g_sim.mirror_trap_code = SFLOW_V1_MIRROR_TRAP_CODE_ID;
    g_sim.port_count = 0;
    memset(g_sim.ports, 0, sizeof(g_sim.ports));
    return FM_OK;
}

fm_status fmSetSFlowAttribute(fm_int sw, fm_int sflow_id,
                              fm_int attr, void *value)
{
    fm_uint requested;

    (void)sw;
    if (api_enter(API_SET_SFLOW_RATE, 'R'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID ||
        !g_sim.sflow_exists || attr != FM_SFLOW_SAMPLE_RATE || !value)
        return FM_FAIL;
    requested = *(fm_uint *)value;
    g_sim.requested_rate = requested;
    g_sim.effective_rate =
        (fm_int)nl_sflow_effective_rate((u32)requested);
    return FM_OK;
}

fm_status fmAddSFlowPort(fm_int sw, fm_int sflow_id, fm_int port)
{
    (void)sw;
    if (api_enter(API_ADD_SFLOW_PORT, 'A'))
        return g_fail_status;
    if (sflow_id != (fm_int)NL_SFLOW_V1_SAMPLER_ID ||
        !g_sim.sflow_exists || port <= 0 ||
        g_sim.port_count >= (fm_int)NL_SFLOW_V1_MAX_PORTS)
        return FM_FAIL;
    g_sim.ports[g_sim.port_count++] = port;
    return FM_OK;
}

fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode,
                         fm_int *state, fm_int *info)
{
    unsigned int index = g_sim.port_guard_index;

    (void)sw;
    (void)port;
    (void)info;
    if (api_enter(API_GET_PORT_STATE, '\0'))
        return g_fail_status;
    if (!mode || !state)
        return FM_FAIL;
    if (index > 2U)
        index = 2U;
    *mode = g_sim.port_modes[index];
    *state = g_sim.port_states[index];
    return FM_OK;
}

fm_status fmGetPortCounters(fm_int sw, fm_int port,
                            fm_portCounters *counters)
{
    unsigned int index = g_sim.port_guard_index;

    (void)sw;
    (void)port;
    if (api_enter(API_GET_PORT_COUNTERS, '\0'))
        return g_fail_status;
    if (!counters)
        return FM_FAIL;
    if (index > 2U)
        index = 2U;
    *counters = g_sim.port_counters[index];
    g_sim.port_guard_index++;
    return FM_OK;
}

bool nl_ifid_get_by_logical_port(int logical_port, nl_port_entry *out)
{
    if (!out || logical_port <= 0)
        return false;
    memset(out, 0, sizeof(*out));
    out->logical_port = logical_port;
    out->front_panel_port = logical_port;
    out->flags = NL_PORT_FLAG_EXTERNAL;
    (void)snprintf(out->role, sizeof(out->role), "external");
    return true;
}

bool nl_ifid_is_user_port(int logical_port)
{
    return logical_port > 0 && logical_port <= 24;
}

int hal_mirror_state_get(int sw, int group, hal_mirror_state *state)
{
    (void)sw;
    if (api_enter(API_GET_SPAN_STATE, '\0'))
        return (int)g_fail_status;
    if (!state || group != NETLAB_MIRROR_V1_GROUP)
        return -1;
    *state = g_sim.span;
    if (g_span_changed_on_call != 0U &&
        g_api_calls[API_GET_SPAN_STATE] == g_span_changed_on_call)
        state->destination_port++;
    return 0;
}

bool hal_mirror_state_equal(const hal_mirror_state *left,
                            const hal_mirror_state *right)
{
    if (!left || !right || left->exists != right->exists)
        return false;
    if (!left->exists)
        return true;
    if (left->group != right->group ||
        left->destination_port != right->destination_port ||
        left->direction != right->direction ||
        left->n_sources != right->n_sources)
        return false;
    for (int i = 0; i < left->n_sources; i++) {
        if (left->source_ports[i] != right->source_ports[i] ||
            left->source_directions[i] != right->source_directions[i])
            return false;
    }
    return true;
}

void sflow_capture_snapshot(nl_sflow_capture_counters_v1 *out)
{
    if (g_deliver_delayed_capture) {
        g_sim.capture.callback_events++;
        g_sim.capture.disabled_drops++;
        g_deliver_delayed_capture = false;
    }
    g_capture_snapshot_calls++;
    if (g_capture_change_on_call != 0U &&
        g_capture_snapshot_calls == g_capture_change_on_call) {
        g_sim.capture.callback_events += g_capture_callback_delta;
        g_sim.capture.disabled_drops += g_capture_disabled_delta;
        g_sim.capture.buffer_free_failures +=
            g_capture_free_failure_delta;
    }
    if (out)
        *out = g_sim.capture;
}

static int test_state_absent_and_existing(void)
{
    static const int ports[] = {9, 2, 5};
    nl_sflow_hw_state_v1 state;

    simulator_reset();
    memset(&state, 0, sizeof(state));
    if (hal_sflow_state_get(3, &state) != 0 ||
        state.exists != 0U ||
        state.version != NL_SFLOW_V1_VERSION ||
        state.size != sizeof(state) ||
        state.sampler_id != NL_SFLOW_V1_SAMPLER_ID ||
        state.mirror_group != NL_SFLOW_V1_MIRROR_GROUP) {
        fprintf(stderr, "absent sFlow state is not canonical\n");
        return 1;
    }

    simulator_set_sflow(NL_SFLOW_V1_MAX_SAMPLE_RATE, ports, 3);
    memset(&state, 0, sizeof(state));
    if (hal_sflow_state_get(3, &state) != 0 ||
        !state.exists ||
        state.requested_rate != NL_SFLOW_V1_MAX_SAMPLE_RATE ||
        state.effective_rate != NL_SFLOW_V1_RATE_MODULUS ||
        state.requested_rate == state.effective_rate ||
        state.port_count != 3U ||
        state.ports[0] != 2U ||
        state.ports[1] != 5U ||
        state.ports[2] != 9U ||
        state.vlan != FM_SFLOW_VLAN_ANY ||
        state.trap_code != SFLOW_V1_TRAP_CODE_ID ||
        state.mirror_trap_code != SFLOW_V1_MIRROR_TRAP_CODE_ID) {
        fprintf(stderr,
                "existing sFlow requested/effective/ports readback mismatch\n");
        return 1;
    }
    return 0;
}

static int test_prewrite_fail_closed(void)
{
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    g_sim.foreign_group31 = true;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || g_mutation_len != 0U ||
        strstr(response, "reason=\"group31-foreign-owner\"") == NULL) {
        fprintf(stderr, "foreign group31 was not rejected before writes\n");
        return 1;
    }

    simulator_reset();
    g_sim.port_states[0] = FM_PORT_STATE_UP;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || g_mutation_len != 0U ||
        strstr(response, "reason=\"port-has-ingress-risk\"") == NULL) {
        fprintf(stderr, "link-up port was not rejected before writes\n");
        return 1;
    }

    simulator_reset();
    g_sim.port_states[0] = FM_PORT_STATE_PARTIALLY_UP;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || g_mutation_len != 0U ||
        strstr(response, "reason=\"port-has-ingress-risk\"") == NULL) {
        fprintf(stderr, "partially-up port was not rejected before writes\n");
        return 1;
    }

    simulator_reset();
    g_sim.port_counters[1].cntRxUcstPkts++;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || g_mutation_len != 0U ||
        strstr(response, "reason=\"port-not-quiescent\"") == NULL) {
        fprintf(stderr, "moving RX projection was not rejected before writes\n");
        return 1;
    }
    return 0;
}

static int test_probe_absent_exact_sequence(void)
{
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc != 0 ||
        strcmp(g_mutations, "DCRAD") != 0 ||
        g_sim.sflow_exists ||
        g_api_calls[API_CREATE_SFLOW] != 1U ||
        g_api_calls[API_SET_SFLOW_RATE] != 1U ||
        g_api_calls[API_ADD_SFLOW_PORT] != 1U ||
        g_api_calls[API_DELETE_SFLOW] != 2U ||
        strstr(response, "status=\"ok\"") == NULL ||
        strstr(response, "requested-rate=\"16777215\"") == NULL ||
        strstr(response, "effective-rate=\"16777216\"") == NULL ||
        strstr(response, "tx-id=\"42\"") == NULL ||
        strstr(response, "admin-mode=\"0\"") == NULL ||
        strstr(response, "callback-before=\"0\"") == NULL ||
        strstr(response, "callback-after=\"0\"") == NULL ||
        strstr(response, "disabled-drops-before=\"0\"") == NULL ||
        strstr(response, "disabled-drops-after=\"0\"") == NULL ||
        strstr(response, "free-failures-before=\"0\"") == NULL ||
        strstr(response, "free-failures-after=\"0\"") == NULL ||
        strstr(response, "span-group0-unchanged=\"true\"") == NULL) {
        fprintf(stderr, "absent-state probe sequence mismatch: %s\n",
                g_mutations);
        return 1;
    }
    return 0;
}

static int test_probe_restore_existing(void)
{
    static const int prior_ports[] = {8, 3};
    nl_sflow_hw_state_v1 expected;
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    simulator_set_sflow(1000U, prior_ports, 2);
    if (capture_expected_state(&expected) != 0)
        return require_true(false, "capture prior sFlow state failed");

    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc != 0 ||
        strcmp(g_mutations, "DCRADCRAA") != 0 ||
        !current_matches(&expected) ||
        g_api_calls[API_CREATE_SFLOW] != 2U ||
        g_api_calls[API_SET_SFLOW_RATE] != 2U ||
        g_api_calls[API_ADD_SFLOW_PORT] != 3U ||
        g_api_calls[API_DELETE_SFLOW] != 2U ||
        strstr(response, "status=\"ok\"") == NULL ||
        strstr(response, "prior-exists=\"true\"") == NULL ||
        strstr(response, "span-group0-unchanged=\"true\"") == NULL) {
        fprintf(stderr, "existing-state exact restore mismatch: %s\n",
                g_mutations);
        return 1;
    }
    return 0;
}

static int run_recoverable_failure(const char *name, bool prior_exists,
                                   api_kind fail_api,
                                   unsigned int fail_nth)
{
    static const int prior_ports[] = {8, 3};
    nl_sflow_hw_state_v1 expected;
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    if (prior_exists)
        simulator_set_sflow(1000U, prior_ports, 2);
    if (capture_expected_state(&expected) != 0) {
        fprintf(stderr, "%s: capture expected state failed\n", name);
        return 1;
    }
    g_fail_api = fail_api;
    g_fail_nth = fail_nth;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    g_fail_api = API_KIND_COUNT;
    if (rc == 0 ||
        !current_matches(&expected) ||
        strstr(response, "status=\"blocked\"") == NULL) {
        fprintf(stderr,
                "%s: failure did not return blocked with exact cleanup: %s\n",
                name, response);
        return 1;
    }
    return 0;
}

static int run_restore_failure(const char *name, api_kind fail_api,
                               unsigned int fail_nth)
{
    static const int prior_ports[] = {8, 3};
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    simulator_set_sflow(1000U, prior_ports, 2);
    g_fail_api = fail_api;
    g_fail_nth = fail_nth;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    g_fail_api = API_KIND_COUNT;
    if (rc == 0 ||
        strstr(response, "status=\"out-of-sync\"") == NULL ||
        strstr(response, "reason=\"cleanup-out-of-sync\"") == NULL) {
        fprintf(stderr, "%s: restore failure was not fail-closed: %s\n",
                name, response);
        return 1;
    }
    return 0;
}

static int test_failure_cleanup_matrix(void)
{
    if (run_recoverable_failure(
            "delete", false, API_DELETE_SFLOW, 1U) != 0)
        return 1;
    if (run_recoverable_failure(
            "create", false, API_CREATE_SFLOW, 1U) != 0)
        return 1;
    if (run_recoverable_failure(
            "rate", false, API_SET_SFLOW_RATE, 1U) != 0)
        return 1;
    if (run_recoverable_failure(
            "add", false, API_ADD_SFLOW_PORT, 1U) != 0)
        return 1;
    if (run_recoverable_failure(
            "probe-readback", false, API_GET_SFLOW_TYPE, 3U) != 0)
        return 1;
    if (run_recoverable_failure(
            "post-delete-readback", true, API_GET_SFLOW_TYPE, 2U) != 0)
        return 1;
    if (run_recoverable_failure(
            "span-readback", false, API_GET_SPAN_STATE, 2U) != 0)
        return 1;

    if (run_restore_failure(
            "restore-delete", API_DELETE_SFLOW, 2U) != 0)
        return 1;
    if (run_restore_failure(
            "restore-create", API_CREATE_SFLOW, 2U) != 0)
        return 1;
    if (run_restore_failure(
            "restore-rate", API_SET_SFLOW_RATE, 2U) != 0)
        return 1;
    if (run_restore_failure(
            "restore-add", API_ADD_SFLOW_PORT, 2U) != 0)
        return 1;
    if (run_restore_failure(
            "restore-readback", API_GET_SFLOW_TYPE, 5U) != 0)
        return 1;
    return 0;
}

static int test_span_change_detected_and_restored(void)
{
    nl_sflow_hw_state_v1 expected;
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    if (capture_expected_state(&expected) != 0)
        return 1;
    g_span_changed_on_call = 2U;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 ||
        !current_matches(&expected) ||
        strstr(response, "reason=\"span-changed-during-probe\"") == NULL) {
        fprintf(stderr, "SPAN group0 change was not detected and cleaned up\n");
        return 1;
    }
    return 0;
}

static int test_runtime_guard_deltas(void)
{
    nl_sflow_hw_state_v1 expected;
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
    int rc;

    simulator_reset();
    if (capture_expected_state(&expected) != 0)
        return 1;
    g_sim.port_counters[2].cntRxUcstPkts++;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || !current_matches(&expected) ||
        strstr(response, "reason=\"port-changed-during-probe\"") == NULL) {
        fprintf(stderr, "postwrite RX change was not blocked: %s\n", response);
        return 1;
    }

    simulator_reset();
    if (capture_expected_state(&expected) != 0)
        return 1;
    g_arm_delayed_capture = true;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || !current_matches(&expected) ||
        strstr(response, "reason=\"unexpected-sflow-callback\"") == NULL ||
        strstr(response, "callback-after=\"1\"") == NULL ||
        g_fixture_settle_calls != 2U) {
        fprintf(stderr,
                "delayed post-cleanup callback was not blocked: %s\n",
                response);
        return 1;
    }

    simulator_reset();
    if (capture_expected_state(&expected) != 0)
        return 1;
    g_capture_change_on_call = 2U;
    g_capture_callback_delta = 1U;
    g_capture_disabled_delta = 1U;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || !current_matches(&expected) ||
        strstr(response, "reason=\"unexpected-sflow-callback\"") == NULL ||
        strstr(response, "callback-before=\"0\"") == NULL ||
        strstr(response, "callback-after=\"1\"") == NULL ||
        strstr(response, "disabled-drops-after=\"1\"") == NULL) {
        fprintf(stderr, "callback delta was not blocked: %s\n", response);
        return 1;
    }

    simulator_reset();
    if (capture_expected_state(&expected) != 0)
        return 1;
    g_capture_change_on_call = 2U;
    g_capture_free_failure_delta = 1U;
    rc = hal_sflow_live_probe(
        0, 5, true, 42U, response, sizeof(response));
    if (rc == 0 || !current_matches(&expected) ||
        strstr(response, "reason=\"unexpected-sflow-callback\"") == NULL ||
        strstr(response, "free-failures-before=\"0\"") == NULL ||
        strstr(response, "free-failures-after=\"1\"") == NULL) {
        fprintf(stderr, "free-failure delta was not blocked: %s\n", response);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_state_absent_and_existing() != 0)
        return 1;
    if (test_prewrite_fail_closed() != 0)
        return 1;
    if (test_probe_absent_exact_sequence() != 0)
        return 1;
    if (test_probe_restore_existing() != 0)
        return 1;
    if (test_failure_cleanup_matrix() != 0)
        return 1;
    if (test_span_change_detected_and_restored() != 0)
        return 1;
    if (test_runtime_guard_deltas() != 0)
        return 1;
    puts("PASS: switchd sFlow HAL readback, probe guards, and cleanup");
    return 0;
}
