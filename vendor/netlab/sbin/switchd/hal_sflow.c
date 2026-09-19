#include "hal_sflow.h"

#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "sflow_capture.h"

#include <fm_sdk.h>
#include <api/fm_api_mirror.h>
#include <api/fm_api_port.h>
#include <api/fm_api_sflow.h>
#include <api/fm_api_stats.h>
#include <common/fm_errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef SFLOW_PROBE_COUNTER_SETTLE_US
#define SFLOW_PROBE_COUNTER_SETTLE_US 50000U
#endif
#ifndef SFLOW_PROBE_SETTLE
#define SFLOW_PROBE_SETTLE() \
    ((void)usleep(SFLOW_PROBE_COUNTER_SETTLE_US))
#endif
#define SFLOW_V1_TRAP_CODE_ID 0
#define SFLOW_V1_MIRROR_TRAP_CODE_ID 12

typedef struct {
    u64 packets;
    u64 good_octets;
    u64 bad_octets;
    u64 errors;
} sflow_rx_projection;

static bool sflow_absent_status(fm_status status) {
    return status == FM_ERR_INVALID_SFLOW_INSTANCE;
}

static bool mirror_absent_status(fm_status status) {
    return status == FM_ERR_INVALID_PORT_MIRROR_GROUP ||
           status == FM_ERR_NO_MIRROR_GROUPS_EXIST;
}

static void sort_ports(nl_sflow_hw_state_v1 *state) {
    if (!state)
        return;
    for (u32 i = 1; i < state->port_count; i++) {
        u32 port = state->ports[i];
        u32 j = i;

        while (j > 0 && state->ports[j - 1] > port) {
            state->ports[j] = state->ports[j - 1];
            j--;
        }
        state->ports[j] = port;
    }
}

static bool sflow_config_equal(const nl_sflow_hw_state_v1 *left,
                               const nl_sflow_hw_state_v1 *right) {
    if (!left || !right || left->exists != right->exists)
        return false;
    if (!left->exists)
        return true;
    if (left->version != NL_SFLOW_V1_VERSION ||
        right->version != NL_SFLOW_V1_VERSION ||
        left->size != sizeof(*left) || right->size != sizeof(*right) ||
        left->sampler_id != right->sampler_id ||
        left->mirror_group != right->mirror_group ||
        left->type != right->type ||
        left->vlan != right->vlan ||
        left->requested_rate != right->requested_rate ||
        left->effective_rate != right->effective_rate ||
        left->trap_code != right->trap_code ||
        left->mirror_trap_code != right->mirror_trap_code ||
        left->port_count != right->port_count)
        return false;
    for (u32 i = 0; i < left->port_count; i++) {
        if (left->ports[i] != right->ports[i])
            return false;
    }
    return true;
}

static int mirror_group_exists(int sw, int group, bool *exists) {
    fm_int destination = 0;
    fm_mirrorType type = FM_MIRROR_TYPE_INGRESS;
    fm_status status;

    if (!exists)
        return -1;
    status = fmGetMirror((fm_int)sw, (fm_int)group,
                         &destination, &type);
    if (status == FM_OK) {
        *exists = true;
        return 0;
    }
    if (mirror_absent_status(status)) {
        *exists = false;
        return 0;
    }
    return (int)status;
}

int hal_sflow_state_get(int sw, nl_sflow_hw_state_v1 *state) {
    fm_sFlowType type = FM_SFLOW_TYPE_INGRESS;
    fm_uint requested = 0;
    fm_uint16 vlan = FM_SFLOW_VLAN_ANY;
    fm_uint64 count = 0;
    fm_int trap_code = -1;
    fm_int mirror_trap_code = -1;
    fm_int effective = 0;
    fm_int port_count = 0;
    fm_int ports[NL_SFLOW_V1_MAX_PORTS + 1U];
    fm_status status;

    if (!state)
        return -1;
    memset(state, 0, sizeof(*state));
    state->version = NL_SFLOW_V1_VERSION;
    state->size = sizeof(*state);
    state->sampler_id = NL_SFLOW_V1_SAMPLER_ID;
    state->mirror_group = NL_SFLOW_V1_MIRROR_GROUP;

    status = fmGetSFlowType((fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
                            &type);
    if (sflow_absent_status(status))
        return 0;
    if (status != FM_OK)
        return (int)status;

    state->exists = 1U;
    state->type = (u8)type;
    status = fmGetSFlowAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        FM_SFLOW_SAMPLE_RATE, &requested);
    if (status != FM_OK)
        return (int)status;
    status = fmGetSFlowAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        FM_SFLOW_VLAN, &vlan);
    if (status != FM_OK)
        return (int)status;
    status = fmGetSFlowAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        FM_SFLOW_TRAP_CODE, &trap_code);
    if (status != FM_OK)
        return (int)status;
    status = fmGetSFlowAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        FM_SFLOW_COUNT, &count);
    if (status != FM_OK)
        return (int)status;
    status = fmGetMirrorAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_MIRROR_GROUP,
        FM_MIRROR_SAMPLE_RATE, &effective);
    if (status != FM_OK)
        return (int)status;
    status = fmGetMirrorAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_MIRROR_GROUP,
        FM_MIRROR_TRAPCODE_ID, &mirror_trap_code);
    if (status != FM_OK)
        return (int)status;

    memset(ports, 0, sizeof(ports));
    status = fmGetSFlowPortList(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        &port_count, ports,
        (fm_int)(NL_SFLOW_V1_MAX_PORTS + 1U));
    if (status == FM_ERR_NO_SFLOW_PORT)
        port_count = 0;
    else if (status != FM_OK)
        return (int)status;
    if (port_count < 0 ||
        port_count > (fm_int)NL_SFLOW_V1_MAX_PORTS)
        return -1;

    state->sample_count = (u64)count;
    state->requested_rate = (u32)requested;
    state->effective_rate = (u32)effective;
    state->trap_code = (s32)trap_code;
    state->mirror_trap_code = (s32)mirror_trap_code;
    state->vlan = (u16)vlan;
    state->port_count = (u32)port_count;
    for (fm_int i = 0; i < port_count; i++) {
        if (ports[i] <= 0)
            return -1;
        state->ports[i] = (u32)ports[i];
    }
    sort_ports(state);
    for (u32 i = 1; i < state->port_count; i++) {
        if (state->ports[i - 1] == state->ports[i])
            return -1;
    }
    return 0;
}

static int sflow_delete(int sw) {
    fm_status status = fmDeleteSFlow(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID);

    if (status == FM_OK || sflow_absent_status(status))
        return 0;
    return (int)status;
}

static bool sflow_state_restorable(const nl_sflow_hw_state_v1 *state) {
    if (!state || !state->exists)
        return true;
    if (state->version != NL_SFLOW_V1_VERSION ||
        state->size != sizeof(*state) ||
        state->sampler_id != NL_SFLOW_V1_SAMPLER_ID ||
        state->mirror_group != NL_SFLOW_V1_MIRROR_GROUP ||
        state->type != FM_SFLOW_TYPE_INGRESS ||
        state->vlan != FM_SFLOW_VLAN_ANY ||
        state->requested_rate < NL_SFLOW_V1_MIN_SAMPLE_RATE ||
        state->requested_rate > NL_SFLOW_V1_MAX_SAMPLE_RATE ||
        state->effective_rate !=
            nl_sflow_effective_rate(state->requested_rate) ||
        state->trap_code != SFLOW_V1_TRAP_CODE_ID ||
        state->mirror_trap_code != SFLOW_V1_MIRROR_TRAP_CODE_ID ||
        state->port_count > NL_SFLOW_V1_MAX_PORTS)
        return false;
    for (u32 i = 0; i < state->port_count; i++) {
        if (state->ports[i] == 0 ||
            (i > 0 && state->ports[i - 1] >= state->ports[i]))
            return false;
    }
    return true;
}

static int sflow_create_exact(int sw,
                              const nl_sflow_hw_state_v1 *desired) {
    nl_sflow_hw_state_v1 readback;
    fm_uint requested;
    fm_status status;
    int rc;

    if (!desired || !desired->exists ||
        !sflow_state_restorable(desired))
        return -1;
    status = fmCreateSFlow(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        (fm_sFlowType)desired->type);
    if (status != FM_OK)
        return (int)status;

    requested = (fm_uint)desired->requested_rate;
    status = fmSetSFlowAttribute(
        (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
        FM_SFLOW_SAMPLE_RATE, &requested);
    if (status != FM_OK)
        goto fail;
    for (u32 i = 0; i < desired->port_count; i++) {
        status = fmAddSFlowPort(
            (fm_int)sw, (fm_int)NL_SFLOW_V1_SAMPLER_ID,
            (fm_int)desired->ports[i]);
        if (status != FM_OK)
            goto fail;
    }
    rc = hal_sflow_state_get(sw, &readback);
    if (rc != 0 || !sflow_config_equal(&readback, desired)) {
        status = rc != 0 ? (fm_status)rc : FM_FAIL;
        goto fail;
    }
    return 0;

fail:
    (void)sflow_delete(sw);
    return (int)status;
}

static int sflow_restore(int sw,
                         const nl_sflow_hw_state_v1 *desired) {
    nl_sflow_hw_state_v1 readback;
    bool group31_exists = false;
    int rc;

    rc = sflow_delete(sw);
    if (rc != 0)
        return rc;
    if (desired && desired->exists) {
        rc = sflow_create_exact(sw, desired);
        if (rc != 0)
            return rc;
    }
    rc = hal_sflow_state_get(sw, &readback);
    if (rc != 0 || !sflow_config_equal(
            &readback, desired ? desired : &readback))
        return rc != 0 ? rc : -1;
    if (!desired || !desired->exists) {
        rc = mirror_group_exists(
            sw, (int)NL_SFLOW_V1_MIRROR_GROUP, &group31_exists);
        if (rc != 0 || group31_exists)
            return rc != 0 ? rc : -1;
    }
    return 0;
}

static int read_port_guard(int sw, int port, int *mode, int *state,
                           sflow_rx_projection *rx) {
    fm_portCounters counters;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    fm_int read_mode = 0;
    fm_int read_state = 0;
    fm_status status;

    if (!mode || !state || !rx)
        return -1;
    status = fmGetPortState((fm_int)sw, (fm_int)port,
                            &read_mode, &read_state, info);
    if (status != FM_OK)
        return (int)status;
    memset(&counters, 0, sizeof(counters));
    status = fmGetPortCounters((fm_int)sw, (fm_int)port, &counters);
    if (status != FM_OK)
        return (int)status;

    *mode = (int)read_mode;
    *state = (int)read_state;
    rx->packets = (u64)counters.cntRxUcstPkts +
                  (u64)counters.cntRxBcstPkts +
                  (u64)counters.cntRxMcstPkts;
    rx->good_octets = (u64)counters.cntRxGoodOctets;
    rx->bad_octets = (u64)counters.cntRxBadOctets;
    rx->errors = (u64)counters.cntRxFCSErrors +
                 (u64)counters.cntRxFramingErrorPkts +
                 (u64)counters.cntRxHogDropPkts +
                 (u64)counters.cntRxCMDropPkts;
    return 0;
}

static bool rx_projection_equal(const sflow_rx_projection *left,
                                const sflow_rx_projection *right) {
    return left && right &&
        left->packets == right->packets &&
        left->good_octets == right->good_octets &&
        left->bad_octets == right->bad_octets &&
        left->errors == right->errors;
}

static bool capture_probe_unchanged(
    const nl_sflow_capture_counters_v1 *before,
    const nl_sflow_capture_counters_v1 *after) {
    return before && after &&
        before->callback_events == after->callback_events &&
        before->disabled_drops == after->disabled_drops &&
        before->buffer_free_failures == after->buffer_free_failures;
}

static bool probe_port_valid(int port, nl_port_entry *entry) {
    if (!entry || !nl_ifid_get_by_logical_port(port, entry))
        return false;
    return nl_ifid_is_user_port(port) &&
        (entry->flags & NL_PORT_FLAG_EXTERNAL) != 0 &&
        (entry->flags &
         (NL_PORT_FLAG_HIDDEN | NL_PORT_FLAG_CPU_CONTROL)) == 0 &&
        strcmp(entry->role, "external") == 0 &&
        entry->front_panel_port > 0;
}

static void format_probe_response(
    char *response, size_t response_size, const char *status,
    const char *reason, u64 tx_id, int port, int mode, int link_state,
    const sflow_rx_projection *rx_before,
    const sflow_rx_projection *rx_after,
    const nl_sflow_hw_state_v1 *prior,
    const nl_sflow_hw_state_v1 *tested,
    const nl_sflow_capture_counters_v1 *capture_before,
    const nl_sflow_capture_counters_v1 *capture_after,
    bool span_unchanged, int primary_status, int cleanup_status) {
    if (!response || response_size == 0)
        return;
    (void)snprintf(
        response, response_size,
        "<sflow-live-probe schema-version=\"1\" status=\"%s\" "
        "reason=\"%s\" tx-id=\"%llu\" port=\"%d\" admin-mode=\"%d\" "
        "link-state=\"%d\" requested-rate=\"%u\" "
        "effective-rate=\"%u\" prior-exists=\"%s\" "
        "prior-requested-rate=\"%u\" prior-effective-rate=\"%u\" "
        "rx-packets-before=\"%llu\" rx-packets-after=\"%llu\" "
        "rx-octets-before=\"%llu\" rx-octets-after=\"%llu\" "
        "callback-before=\"%llu\" callback-after=\"%llu\" "
        "disabled-drops-before=\"%llu\" "
        "disabled-drops-after=\"%llu\" "
        "free-failures-before=\"%llu\" "
        "free-failures-after=\"%llu\" "
        "span-group0-unchanged=\"%s\" primary-status=\"%d\" "
        "cleanup-status=\"%d\"/>\n",
        status ? status : "invalid", reason ? reason : "unknown",
        (unsigned long long)tx_id, port, mode, link_state,
        tested ? tested->requested_rate : 0U,
        tested ? tested->effective_rate : 0U,
        prior && prior->exists ? "true" : "false",
        prior ? prior->requested_rate : 0U,
        prior ? prior->effective_rate : 0U,
        (unsigned long long)(rx_before ? rx_before->packets : 0U),
        (unsigned long long)(rx_after ? rx_after->packets : 0U),
        (unsigned long long)(rx_before ? rx_before->good_octets : 0U),
        (unsigned long long)(rx_after ? rx_after->good_octets : 0U),
        (unsigned long long)(capture_before ?
                             capture_before->callback_events : 0U),
        (unsigned long long)(capture_after ?
                             capture_after->callback_events : 0U),
        (unsigned long long)(capture_before ?
                             capture_before->disabled_drops : 0U),
        (unsigned long long)(capture_after ?
                             capture_after->disabled_drops : 0U),
        (unsigned long long)(capture_before ?
                             capture_before->buffer_free_failures : 0U),
        (unsigned long long)(capture_after ?
                             capture_after->buffer_free_failures : 0U),
        span_unchanged ? "true" : "false",
        primary_status, cleanup_status);
}

int hal_sflow_live_probe(int sw, int port, bool acknowledged, u64 tx_id,
                         char *response, size_t response_size) {
    nl_port_entry entry;
    nl_sflow_hw_state_v1 prior;
    nl_sflow_hw_state_v1 probe;
    nl_sflow_hw_state_v1 tested;
    nl_sflow_hw_state_v1 final_state;
    nl_sflow_capture_counters_v1 capture_before;
    nl_sflow_capture_counters_v1 capture_after;
    hal_mirror_state span_before;
    hal_mirror_state span_after;
    sflow_rx_projection rx_before;
    sflow_rx_projection rx_stable;
    sflow_rx_projection rx_after;
    bool group31_exists = false;
    bool writes_started = false;
    bool span_unchanged = false;
    const char *reason = "ok";
    int mode = -1;
    int link_state = -1;
    int final_mode = -1;
    int final_link_state = -1;
    int primary_status = 0;
    int cleanup_status = 0;
    int rc;

    memset(&entry, 0, sizeof(entry));
    memset(&prior, 0, sizeof(prior));
    memset(&probe, 0, sizeof(probe));
    memset(&tested, 0, sizeof(tested));
    memset(&final_state, 0, sizeof(final_state));
    memset(&capture_before, 0, sizeof(capture_before));
    memset(&capture_after, 0, sizeof(capture_after));
    memset(&span_before, 0, sizeof(span_before));
    memset(&span_after, 0, sizeof(span_after));
    memset(&rx_before, 0, sizeof(rx_before));
    memset(&rx_stable, 0, sizeof(rx_stable));
    memset(&rx_after, 0, sizeof(rx_after));
    if (response && response_size > 0)
        response[0] = '\0';

    if (!acknowledged) {
        reason = "ack-required";
        primary_status = -1;
        goto out;
    }
    if (!probe_port_valid(port, &entry)) {
        reason = "port-not-external-physical";
        primary_status = -1;
        goto out;
    }
    rc = read_port_guard(sw, port, &mode, &link_state, &rx_before);
    if (rc != 0) {
        reason = "port-preflight-read-failed";
        primary_status = rc;
        goto out;
    }
    if (link_state == FM_PORT_STATE_UP ||
        link_state == FM_PORT_STATE_PARTIALLY_UP) {
        reason = "port-has-ingress-risk";
        primary_status = -1;
        goto out;
    }
    SFLOW_PROBE_SETTLE();
    rc = read_port_guard(
        sw, port, &final_mode, &final_link_state, &rx_stable);
    if (rc != 0 || final_link_state == FM_PORT_STATE_UP ||
        final_link_state == FM_PORT_STATE_PARTIALLY_UP ||
        !rx_projection_equal(&rx_before, &rx_stable)) {
        reason = "port-not-quiescent";
        primary_status = rc != 0 ? rc : -1;
        goto out;
    }

    sflow_capture_snapshot(&capture_before);
    rc = hal_mirror_state_get(sw, NETLAB_MIRROR_V1_GROUP, &span_before);
    if (rc != 0) {
        reason = "span-prestate-read-failed";
        primary_status = rc;
        goto out;
    }
    rc = hal_sflow_state_get(sw, &prior);
    if (rc != 0) {
        reason = "sflow-prestate-read-failed";
        primary_status = rc;
        goto out;
    }
    if (!sflow_state_restorable(&prior)) {
        reason = "sflow-prestate-not-restorable";
        primary_status = -1;
        goto out;
    }
    if (!prior.exists) {
        rc = mirror_group_exists(
            sw, (int)NL_SFLOW_V1_MIRROR_GROUP, &group31_exists);
        if (rc != 0 || group31_exists) {
            reason = rc != 0 ? "group31-read-failed" :
                               "group31-foreign-owner";
            primary_status = rc != 0 ? rc : -1;
            goto out;
        }
    }

    writes_started = true;
    rc = sflow_delete(sw);
    if (rc != 0) {
        reason = "prior-delete-failed";
        primary_status = rc;
        goto cleanup;
    }
    rc = hal_sflow_state_get(sw, &final_state);
    if (rc != 0 || final_state.exists) {
        reason = "prior-delete-readback-failed";
        primary_status = rc != 0 ? rc : -1;
        goto cleanup;
    }
    rc = mirror_group_exists(
        sw, (int)NL_SFLOW_V1_MIRROR_GROUP, &group31_exists);
    if (rc != 0 || group31_exists) {
        reason = "group31-delete-readback-failed";
        primary_status = rc != 0 ? rc : -1;
        goto cleanup;
    }

    probe.version = NL_SFLOW_V1_VERSION;
    probe.size = sizeof(probe);
    probe.exists = 1U;
    probe.type = FM_SFLOW_TYPE_INGRESS;
    probe.vlan = FM_SFLOW_VLAN_ANY;
    probe.sampler_id = NL_SFLOW_V1_SAMPLER_ID;
    probe.mirror_group = NL_SFLOW_V1_MIRROR_GROUP;
    probe.requested_rate = NL_SFLOW_V1_MAX_SAMPLE_RATE;
    probe.effective_rate =
        nl_sflow_effective_rate(probe.requested_rate);
    probe.trap_code = SFLOW_V1_TRAP_CODE_ID;
    probe.mirror_trap_code = SFLOW_V1_MIRROR_TRAP_CODE_ID;
    probe.port_count = 1U;
    probe.ports[0] = (u32)port;
    rc = sflow_create_exact(sw, &probe);
    if (rc != 0) {
        reason = "probe-create-failed";
        primary_status = rc;
        goto cleanup;
    }
    rc = hal_sflow_state_get(sw, &tested);
    if (rc != 0 || !sflow_config_equal(&tested, &probe)) {
        reason = "probe-readback-mismatch";
        primary_status = rc != 0 ? rc : -1;
        goto cleanup;
    }
    rc = hal_mirror_state_get(sw, NETLAB_MIRROR_V1_GROUP, &span_after);
    if (rc != 0 || !hal_mirror_state_equal(&span_before, &span_after)) {
        reason = "span-changed-during-probe";
        primary_status = rc != 0 ? rc : -1;
        goto cleanup;
    }

cleanup:
    if (writes_started) {
        cleanup_status = sflow_restore(sw, &prior);
        if (hal_sflow_state_get(sw, &final_state) != 0 ||
            !sflow_config_equal(&final_state, &prior))
            cleanup_status = cleanup_status != 0 ? cleanup_status : -1;
        if (hal_mirror_state_get(
                sw, NETLAB_MIRROR_V1_GROUP, &span_after) != 0 ||
            !hal_mirror_state_equal(&span_before, &span_after))
            cleanup_status = cleanup_status != 0 ? cleanup_status : -1;
    }
    span_unchanged =
        hal_mirror_state_equal(&span_before, &span_after);
    /*
     * fmDeleteSFlow() does not establish an event-delivery barrier.  Give any
     * packet already classified by the sampler a bounded interval to reach
     * the callback before accepting the final RX/capture projections.
     */
    SFLOW_PROBE_SETTLE();
    rc = read_port_guard(
        sw, port, &final_mode, &final_link_state, &rx_after);
    if (rc != 0 || final_link_state == FM_PORT_STATE_UP ||
        final_link_state == FM_PORT_STATE_PARTIALLY_UP ||
        !rx_projection_equal(&rx_stable, &rx_after)) {
        if (primary_status == 0) {
            reason = "port-changed-during-probe";
            primary_status = rc != 0 ? rc : -1;
        }
    }
    sflow_capture_snapshot(&capture_after);
    if (!capture_probe_unchanged(&capture_before, &capture_after) &&
        primary_status == 0) {
        reason = "unexpected-sflow-callback";
        primary_status = -1;
    }
    if (cleanup_status != 0) {
        reason = "cleanup-out-of-sync";
        primary_status = primary_status != 0 ? primary_status : -1;
    }

out:
    if (capture_after.callback_events == 0 &&
        capture_after.disabled_drops == 0 &&
        capture_after.buffer_free_failures == 0)
        sflow_capture_snapshot(&capture_after);
    format_probe_response(
        response, response_size,
        primary_status == 0 && cleanup_status == 0 ? "ok" :
        cleanup_status != 0 ? "out-of-sync" : "blocked",
        reason, tx_id, port, mode, link_state, &rx_before, &rx_after,
        &prior, &tested, &capture_before, &capture_after,
        span_unchanged, primary_status, cleanup_status);
    return primary_status == 0 && cleanup_status == 0 ? 0 : -1;
}
