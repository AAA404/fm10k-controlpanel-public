#include "hal_cpu_protection.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_port.h>
#include <api/fm_api_qos.h>
#include <string.h>

/* CPU egress shaping is independent of the single winning Trigger rate
 * limiter used by storm control. It never changes the external destination
 * mask or the priority/DSCP of a transit frame. FM10000 datasheet 5.6.4.2,
 * 5.7.8.6 and 5.7.9.3.2; pinned SDK fm10000SetPortQOS(). */
int hal_cpu_protection_read(int sw, hal_cpu_protection_state *out) {
    fm_int port = -1;
    fm_uint64 value;
    fm_status st;
    if (!out) return FM_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->port = -1;
    st = fmGetCpuPort(sw, &port);
    if (st != FM_OK) return st;
    if (port <= 0 || !nl_ifid_is_cpu_port(port) || nl_ifid_is_user_port(port))
        return FM_ERR_INVALID_PORT;
    out->port = port;
    st = fmGetPortQOS(sw, port, FM_QOS_SHAPING_GROUP_RATE, 0, &value);
    if (st != FM_OK) return st;
    out->rate_bps = value;
    st = fmGetPortQOS(sw, port, FM_QOS_SHAPING_GROUP_MAX_BURST, 0, &value);
    if (st != FM_OK) return st;
    out->burst_bits = value;
    for (int tc = 0; tc < HAL_CPU_PROTECTION_TC_COUNT; ++tc) {
        st = fmGetPortQOS(sw, port, FM_QOS_TC_SHAPING_GROUP_MAP, tc,
                          &out->tc_group[tc]);
        if (st != FM_OK) return st;
        if (out->tc_group[tc] >= HAL_CPU_PROTECTION_TC_COUNT)
            return FM_ERR_INVALID_STATE;
    }
    return FM_OK;
}

bool hal_cpu_protection_matches(const hal_cpu_protection_state *state) {
    if (!state || state->port <= 0 ||
        /* Pinned SDK rounds to a fraction of a byte per 48 fabric clocks.
         * Bound the accepted quantization and publish the actual rate. */
        state->rate_bps < HAL_CPU_PROTECTION_RATE_BPS - 500000ULL ||
        state->rate_bps > HAL_CPU_PROTECTION_RATE_BPS + 500000ULL ||
        state->burst_bits != HAL_CPU_PROTECTION_BURST_BITS)
        return false;
    for (int tc = 0; tc < HAL_CPU_PROTECTION_TC_COUNT; ++tc)
        if (state->tc_group[tc] != 0) return false;
    return true;
}

static int restore(int sw, const hal_cpu_protection_state *before) {
    hal_cpu_protection_state current, actual;
    fm_uint64 value;
    int failed = 0;
    /* Do not restore into a different CPU owner if the live mapping drifted. */
    if (hal_cpu_protection_read(sw, &current) != FM_OK ||
        current.port != before->port)
        return FM_ERR_INVALID_STATE;
    value = before->burst_bits;
    failed |= fmSetPortQOS(sw, before->port, FM_QOS_SHAPING_GROUP_MAX_BURST,
                           0, &value) != FM_OK;
    for (int tc = 0; tc < HAL_CPU_PROTECTION_TC_COUNT; ++tc) {
        fm_uint32 group = before->tc_group[tc];
        failed |= fmSetPortQOS(sw, before->port, FM_QOS_TC_SHAPING_GROUP_MAP,
                               tc, &group) != FM_OK;
    }
    value = before->rate_bps;
    failed |= fmSetPortQOS(sw, before->port, FM_QOS_SHAPING_GROUP_RATE,
                           0, &value) != FM_OK;
    if (hal_cpu_protection_read(sw, &actual) != FM_OK ||
        memcmp(before, &actual, sizeof(actual)) != 0)
        failed = 1;
    return failed ? FM_ERR_INVALID_STATE : FM_OK;
}

int hal_cpu_protection_init(int sw) {
    hal_cpu_protection_state before, actual;
    fm_uint64 value;
    fm_status st = hal_cpu_protection_read(sw, &before);
    if (st != FM_OK) return st;
    if (hal_cpu_protection_matches(&before)) return FM_OK;

    value = HAL_CPU_PROTECTION_BURST_BITS;
    st = fmSetPortQOS(sw, before.port, FM_QOS_SHAPING_GROUP_MAX_BURST, 0, &value);
    if (st != FM_OK) goto rollback;
    value = HAL_CPU_PROTECTION_RATE_BPS;
    st = fmSetPortQOS(sw, before.port, FM_QOS_SHAPING_GROUP_RATE, 0, &value);
    if (st != FM_OK) goto rollback;
    for (int tc = 0; tc < HAL_CPU_PROTECTION_TC_COUNT; ++tc) {
        fm_uint32 group = 0;
        if (before.tc_group[tc] == group) continue;
        st = fmSetPortQOS(sw, before.port, FM_QOS_TC_SHAPING_GROUP_MAP, tc, &group);
        if (st != FM_OK) goto rollback;
    }
    st = hal_cpu_protection_read(sw, &actual);
    if (st != FM_OK) goto rollback;
    if (actual.port != before.port || !hal_cpu_protection_matches(&actual)) {
        st = FM_ERR_INVALID_STATE;
        goto rollback;
    }
    NL_LOG_INFO("CPU egress protection port=%d rate=%llu bps burst=%llu bits",
                actual.port, (unsigned long long)actual.rate_bps,
                (unsigned long long)actual.burst_bits);
    return FM_OK;

rollback:
    if (restore(sw, &before) != FM_OK)
        NL_LOG_CRIT("CPU egress protection failed and restoration is unproven; startup rejected");
    return st;
}
