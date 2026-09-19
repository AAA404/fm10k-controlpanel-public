#include "netlab/hal.h"
#include "netlab/hal_transaction_snapshot.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_qos.h>
#include <string.h>

#define NETLAB_EGRESS_RATE_LIMIT_SG 0
#define NETLAB_EGRESS_RATE_LIMIT_TC_COUNT 8
#define NETLAB_EGRESS_RATE_LIMIT_DEFAULT_BURST_BYTES 65536

static hal_egress_rate_transaction_snapshot
egress_rate_transaction_read_error(fm_status status) {
    hal_egress_rate_transaction_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = (int)status;
    return snapshot;
}

hal_egress_rate_transaction_snapshot
hal_egress_rate_limit_transaction_snapshot(int sw, int port) {
    hal_egress_rate_transaction_snapshot snapshot;
    fm_uint64 raw_rate = 0;
    fm_uint64 raw_burst = 0;
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    if (port <= 0 || !nl_ifid_is_user_port(port))
        return snapshot;

    st = fmGetPortQOS(
        (fm_int)sw, (fm_int)port, FM_QOS_SHAPING_GROUP_RATE,
        NETLAB_EGRESS_RATE_LIMIT_SG, &raw_rate);
    if (st != FM_OK)
        return egress_rate_transaction_read_error(st);
    st = fmGetPortQOS(
        (fm_int)sw, (fm_int)port, FM_QOS_SHAPING_GROUP_MAX_BURST,
        NETLAB_EGRESS_RATE_LIMIT_SG, &raw_burst);
    if (st != FM_OK)
        return egress_rate_transaction_read_error(st);
    snapshot.raw_rate_bps = (u64)raw_rate;
    snapshot.raw_burst_bits = (u64)raw_burst;
    for (int tc = 0; tc < HAL_TRANSACTION_EGRESS_RATE_TC_COUNT; tc++) {
        st = fmGetPortQOS(
            (fm_int)sw, (fm_int)port,
            FM_QOS_TC_SHAPING_GROUP_MAP, (fm_int)tc,
            &snapshot.tc_shaping_group_map[tc]);
        if (st != FM_OK)
            return egress_rate_transaction_read_error(st);
    }

    snapshot.state =
        snapshot.raw_rate_bps == (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT ?
        HAL_TRANSACTION_SNAPSHOT_ABSENT :
        HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

static bool egress_rate_transaction_snapshots_equal(
    const hal_egress_rate_transaction_snapshot *left,
    const hal_egress_rate_transaction_snapshot *right) {
    return left && right &&
           left->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           right->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           left->state == right->state &&
           left->raw_rate_bps == right->raw_rate_bps &&
           left->raw_burst_bits == right->raw_burst_bits &&
           memcmp(left->tc_shaping_group_map,
                  right->tc_shaping_group_map,
                  sizeof(left->tc_shaping_group_map)) == 0;
}

int hal_egress_rate_limit_transaction_restore(
    int sw, int port,
    const hal_egress_rate_transaction_snapshot *snapshot) {
    hal_egress_rate_transaction_snapshot readback;
    fm_uint64 value64;
    fm_uint32 value32;
    fm_status st;

    if (!snapshot ||
        snapshot->state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
        port <= 0 || !nl_ifid_is_user_port(port))
        return FM_ERR_INVALID_ARGUMENT;
    if ((snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT) !=
        (snapshot->raw_rate_bps ==
         (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT))
        return FM_ERR_INVALID_ARGUMENT;
    for (int tc = 0; tc < HAL_TRANSACTION_EGRESS_RATE_TC_COUNT; tc++)
        if (snapshot->tc_shaping_group_map[tc] >=
            HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;

    /*
     * Disable group-0 shaping while rebuilding its exact before-image, then
     * restore the original rate last.  This avoids forwarding through a
     * partially restored TC map with the old limiter still active.
     */
    value64 = FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &value64);
    if (st != FM_OK)
        return (int)st;
    value64 = (fm_uint64)snapshot->raw_burst_bits;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &value64);
    if (st != FM_OK)
        return (int)st;
    for (int tc = 0; tc < HAL_TRANSACTION_EGRESS_RATE_TC_COUNT; tc++) {
        value32 = (fm_uint32)snapshot->tc_shaping_group_map[tc];
        st = fmSetPortQOS(
            (fm_int)sw, (fm_int)port,
            FM_QOS_TC_SHAPING_GROUP_MAP, (fm_int)tc, &value32);
        if (st != FM_OK)
            return (int)st;
    }
    value64 = (fm_uint64)snapshot->raw_rate_bps;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &value64);
    if (st != FM_OK)
        return (int)st;

    readback = hal_egress_rate_limit_transaction_snapshot(sw, port);
    if (readback.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;
    return egress_rate_transaction_snapshots_equal(snapshot, &readback) ?
           0 : FM_ERR_INVALID_STATE;
}

static int map_all_tcs_to_group(int sw, int port, int group) {
    fm_uint32 sg = (fm_uint32)group;

    for (int tc = 0; tc < NETLAB_EGRESS_RATE_LIMIT_TC_COUNT; tc++) {
        fm_status st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                                    FM_QOS_TC_SHAPING_GROUP_MAP,
                                    (fm_int)tc, &sg);
        if (st != FM_OK) {
            NL_LOG_ERR("egress-rate-limit port=%d tc=%d map sg=%d failed: %s",
                       port, tc, group, fmErrorMsg(st));
            return (int)st;
        }
    }
    return 0;
}

int hal_egress_rate_limit_set(int sw, int port, int rate_kbps,
                              int burst_bytes) {
    fm_uint64 rate_bps;
    fm_uint64 burst_bits;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) || rate_kbps <= 0)
        return -1;
    if (burst_bytes <= 0)
        burst_bytes = NETLAB_EGRESS_RATE_LIMIT_DEFAULT_BURST_BYTES;

    if (map_all_tcs_to_group(sw, port, NETLAB_EGRESS_RATE_LIMIT_SG) != 0)
        return -1;

    burst_bits = (fm_uint64)burst_bytes * 8ULL;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &burst_bits);
    if (st != FM_OK) {
        NL_LOG_ERR("egress-rate-limit port=%d set burst=%llu bits failed: %s",
                   port, (unsigned long long)burst_bits, fmErrorMsg(st));
        return (int)st;
    }

    rate_bps = (fm_uint64)rate_kbps * 1000ULL;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &rate_bps);
    if (st != FM_OK) {
        NL_LOG_ERR("egress-rate-limit port=%d set rate=%llu bps failed: %s",
                   port, (unsigned long long)rate_bps, fmErrorMsg(st));
        return (int)st;
    }

    NL_LOG_INFO("egress-rate-limit port=%d sg=%d rate=%dKbps burst=%d",
                port, NETLAB_EGRESS_RATE_LIMIT_SG, rate_kbps, burst_bytes);
    return 0;
}

int hal_egress_rate_limit_delete(int sw, int port) {
    fm_uint64 rate_bps = FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    (void)map_all_tcs_to_group(sw, port, NETLAB_EGRESS_RATE_LIMIT_SG);
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &rate_bps);
    if (st != FM_OK) {
        NL_LOG_ERR("egress-rate-limit port=%d delete failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }
    return 0;
}

int hal_egress_rate_limit_get(int sw, int port,
                              hal_egress_rate_limit_entry *entry) {
    bool present = false;
    int rc = hal_egress_rate_limit_snapshot(
        sw, port, &present, entry);

    return rc == 0 && present ? 0 : -1;
}

int hal_egress_rate_limit_snapshot(
    int sw, int port, bool *present,
    hal_egress_rate_limit_entry *entry) {
    fm_uint64 rate_bps = 0;
    fm_uint64 burst_bits = 0;
    fm_status st;

    if (!present || !entry || port <= 0 || !nl_ifid_is_user_port(port))
        return -1;
    *present = false;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &rate_bps);
    if (st != FM_OK)
        return (int)st;
    if (rate_bps == FM_QOS_SHAPING_GROUP_RATE_DEFAULT)
        return 0;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      NETLAB_EGRESS_RATE_LIMIT_SG, &burst_bits);
    if (st != FM_OK)
        return (int)st;

    memset(entry, 0, sizeof(*entry));
    entry->port = port;
    entry->shaping_group = NETLAB_EGRESS_RATE_LIMIT_SG;
    entry->rate_kbps = (int)((rate_bps + 999ULL) / 1000ULL);
    entry->burst_bytes = (int)((burst_bits + 7ULL) / 8ULL);
    *present = true;
    return 0;
}

int hal_egress_rate_limit_list(int sw,
                               hal_egress_rate_limit_entry *entries,
                               int max_entries) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n_ports;
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports && n < max_entries; i++) {
        hal_egress_rate_limit_entry entry;

        if (!nl_ifid_is_user_port(ports[i].logical_port))
            continue;
        if (hal_egress_rate_limit_get(sw, ports[i].logical_port,
                                      &entry) != 0)
            continue;
        entries[n++] = entry;
    }
    return n;
}
