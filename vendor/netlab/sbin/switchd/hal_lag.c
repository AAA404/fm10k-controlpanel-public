/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/error.h"
#include "netlab/hal_presence.h"
#include "fm10k_lag.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_lag.h>
#include <string.h>
#include <unistd.h>

bool fm10k_native_profile(void);

#ifndef LAG_DELETE_READBACK_ATTEMPTS
#define LAG_DELETE_READBACK_ATTEMPTS 20
#endif
#ifndef LAG_DELETE_READBACK_INTERVAL_US
#define LAG_DELETE_READBACK_INTERVAL_US 100000
#endif

static hal_presence_snapshot lag_snapshot(hal_presence_state state,
                                          fm_status sdk_status) {
    hal_presence_snapshot snapshot;

    snapshot.state = state;
    snapshot.sdk_status = (int)sdk_status;
    snapshot.tagged = false;
    return snapshot;
}

hal_presence_snapshot hal_lag_first_snapshot(int sw, int *lag_id) {
    fm_int cur = -1;
    fm_status st = fmGetLAGFirst((fm_int)sw, &cur);

    if (lag_id)
        *lag_id = -1;
    if (st == FM_ERR_NO_LAGS)
        return lag_snapshot(HAL_PRESENCE_ABSENT, st);
    if (st != FM_OK)
        return lag_snapshot(HAL_PRESENCE_READ_ERROR, st);
    if (cur <= 0)
        return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_FAIL);
    if (lag_id)
        *lag_id = (int)cur;
    return lag_snapshot(HAL_PRESENCE_PRESENT, FM_OK);
}

hal_presence_snapshot hal_lag_presence_snapshot(int sw, int lag_id) {
    int first_lag = -1;
    fm_int cur, seen[NETLAB_MAX_AE];
    fm_status st;
    hal_presence_snapshot first;

    if (lag_id <= 0)
        return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_ERR_INVALID_LAG);

    first = hal_lag_first_snapshot(sw, &first_lag);
    if (first.state != HAL_PRESENCE_PRESENT)
        return first;
    cur = (fm_int)first_lag;
    for (int count = 0; count < NETLAB_MAX_AE; ++count) {
        fm_int next = -1;
        for (int i = 0; i < count; ++i)
            if (seen[i] == cur)
                return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_FAIL);
        seen[count] = cur;
        if ((int)cur == lag_id)
            return lag_snapshot(HAL_PRESENCE_PRESENT, FM_OK);
        st = fmGetLAGNext((fm_int)sw, cur, &next);
        if (st == FM_ERR_NO_LAGS)
            return lag_snapshot(HAL_PRESENCE_ABSENT, st);
        if (st != FM_OK || next <= 0)
            return lag_snapshot(HAL_PRESENCE_READ_ERROR, st != FM_OK ? st : FM_FAIL);
        cur = next;
    }
    return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_ERR_BUFFER_FULL);
}

hal_presence_snapshot hal_lag_member_snapshot(int sw, int lag_id, int port) {
    fm_int cur = -1, seen[NETLAB_MAX_LAG_MEMBERS];
    fm_status st;

    if (lag_id <= 0 || port <= 0)
        return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_ERR_INVALID_PORT);

    st = fmGetLAGPortFirst(
        (fm_int)sw, (fm_int)lag_id, &cur);
    if (st == FM_ERR_INVALID_LAG || st == FM_ERR_NO_PORTS_IN_LAG)
        return lag_snapshot(HAL_PRESENCE_ABSENT, st);
    if (st != FM_OK || cur <= 0)
        return lag_snapshot(HAL_PRESENCE_READ_ERROR, st != FM_OK ? st : FM_FAIL);

    for (int count = 0; count < NETLAB_MAX_LAG_MEMBERS; ++count) {
        fm_int next = -1;
        for (int i = 0; i < count; ++i)
            if (seen[i] == cur)
                return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_FAIL);
        seen[count] = cur;
        if ((int)cur == port)
            return lag_snapshot(HAL_PRESENCE_PRESENT, FM_OK);
        st = fmGetLAGPortNext(
            (fm_int)sw, (fm_int)lag_id, cur, &next);
        if (st == FM_ERR_NO_PORTS_IN_LAG)
            return lag_snapshot(HAL_PRESENCE_ABSENT, st);
        if (st != FM_OK || next <= 0)
            return lag_snapshot(HAL_PRESENCE_READ_ERROR, st != FM_OK ? st : FM_FAIL);
        cur = next;
    }
    return lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_ERR_BUFFER_FULL);
}

hal_presence_snapshot hal_lag_wait_absent(int sw, int lag_id) {
    hal_presence_snapshot snapshot =
        lag_snapshot(HAL_PRESENCE_READ_ERROR, FM_FAIL);

    for (int i = 0; i < LAG_DELETE_READBACK_ATTEMPTS; i++) {
        snapshot = hal_lag_presence_snapshot(sw, lag_id);
        if (snapshot.state != HAL_PRESENCE_PRESENT)
            return snapshot;
        if (i + 1 < LAG_DELETE_READBACK_ATTEMPTS)
            usleep(LAG_DELETE_READBACK_INTERVAL_US);
    }
    return snapshot;
}

static bool lag_handle_set_snapshot_valid(
    const hal_lag_handle_set_snapshot *set) {
    if (!set || set->state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
        set->count < 0 || set->count > NETLAB_MAX_AE)
        return false;
    return (set->state == HAL_TRANSACTION_SNAPSHOT_ABSENT &&
            set->count == 0) ||
           (set->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
            set->count > 0);
}

static bool lag_handle_set_contains(
    const hal_lag_handle_set_snapshot *set, int lag_id) {
    if (!set || lag_id <= 0)
        return false;
    for (int i = 0; i < set->count; i++)
        if (set->lag_ids[i] == lag_id)
            return true;
    return false;
}

hal_lag_handle_set_snapshot hal_lag_handle_set_snapshot_get(int sw) {
    hal_lag_handle_set_snapshot set;
    fm_int current = -1;
    fm_status st;

    memset(&set, 0, sizeof(set));
    set.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    set.sdk_status = (int)FM_FAIL;

    st = fmGetLAGFirst((fm_int)sw, &current);
    if (st == FM_ERR_NO_LAGS) {
        set.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
        set.sdk_status = (int)FM_OK;
        return set;
    }
    if (st != FM_OK || current <= 0) {
        set.sdk_status = st != FM_OK ? (int)st : (int)FM_FAIL;
        return set;
    }

    for (;;) {
        fm_int next = -1;

        if (set.count >= NETLAB_MAX_AE ||
            lag_handle_set_contains(&set, (int)current)) {
            set.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
            set.sdk_status = (int)FM_ERR_BUFFER_FULL;
            return set;
        }
        set.lag_ids[set.count++] = (int)current;

        st = fmGetLAGNext((fm_int)sw, current, &next);
        if (st == FM_ERR_NO_LAGS) {
            set.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
            set.sdk_status = (int)FM_OK;
            return set;
        }
        if (st != FM_OK || next <= 0) {
            set.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
            set.sdk_status = st != FM_OK ? (int)st : (int)FM_FAIL;
            return set;
        }
        current = next;
    }
}

bool hal_lag_handle_set_snapshot_equal(
    const hal_lag_handle_set_snapshot *left,
    const hal_lag_handle_set_snapshot *right) {
    if (!lag_handle_set_snapshot_valid(left) ||
        !lag_handle_set_snapshot_valid(right) ||
        left->count != right->count)
        return false;
    for (int i = 0; i < left->count; i++)
        if (!lag_handle_set_contains(right, left->lag_ids[i]))
            return false;
    return true;
}

static void lag_handle_set_delta(
    const hal_lag_handle_set_snapshot *before,
    const hal_lag_handle_set_snapshot *after,
    int *added_count, int *added_lag_id, int *removed_count) {
    *added_count = 0;
    *added_lag_id = -1;
    *removed_count = 0;
    for (int i = 0; i < after->count; i++) {
        if (lag_handle_set_contains(before, after->lag_ids[i]))
            continue;
        *added_lag_id = after->lag_ids[i];
        (*added_count)++;
    }
    for (int i = 0; i < before->count; i++)
        if (!lag_handle_set_contains(after, before->lag_ids[i]))
            (*removed_count)++;
}

int hal_lag_handle_set_single_addition(
    const hal_lag_handle_set_snapshot *before,
    const hal_lag_handle_set_snapshot *after,
    int *lag_id) {
    int added_count;
    int added_lag_id;
    int removed_count;

    if (lag_id)
        *lag_id = -1;
    if (!lag_handle_set_snapshot_valid(before) ||
        !lag_handle_set_snapshot_valid(after))
        return -1;
    lag_handle_set_delta(
        before, after, &added_count, &added_lag_id, &removed_count);
    if (removed_count != 0 || added_count > 1)
        return -1;
    if (added_count == 0)
        return 0;
    if (lag_id)
        *lag_id = added_lag_id;
    return 1;
}

int hal_lag_handle_set_restore_after_create(
    int sw, const hal_lag_handle_set_snapshot *before) {
    hal_lag_handle_set_snapshot current;
    hal_lag_handle_set_snapshot after;
    bool missing_before = false;
    int delete_failures = 0;

    if (!lag_handle_set_snapshot_valid(before))
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    current = hal_lag_handle_set_snapshot_get(sw);
    if (!lag_handle_set_snapshot_valid(&current))
        return NL_ERR_HW_STATE_OUT_OF_SYNC;

    for (int i = 0; i < before->count; i++)
        if (!lag_handle_set_contains(&current, before->lag_ids[i]))
            missing_before = true;
    for (int i = 0; i < current.count; i++) {
        if (lag_handle_set_contains(before, current.lag_ids[i]))
            continue;
        if (hal_lag_delete(sw, current.lag_ids[i]) != 0)
            delete_failures++;
    }

    after = hal_lag_handle_set_snapshot_get(sw);
    if (missing_before || delete_failures != 0 ||
        !hal_lag_handle_set_snapshot_equal(before, &after)) {
        NL_LOG_CRIT(
            "LAG create compensation did not restore global handle set: "
            "missing-before=%d delete-failures=%d before=%d after-state=%d "
            "after=%d sdk=%d",
            missing_before ? 1 : 0, delete_failures,
            before->count, (int)after.state, after.count,
            after.sdk_status);
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    return 0;
}

int hal_lag_create_classified(
    int sw, const hal_lag_handle_set_snapshot *before,
    int *lag_id, bool *created, int *sdk_status) {
    hal_lag_handle_set_snapshot after;
    fm_int raw_lag_id = -1;
    fm_status create_status;
    int added_count = 0;
    int removed_count = 0;
    int added_lag_id = -1;

    if (lag_id)
        *lag_id = -1;
    if (created)
        *created = false;
    if (sdk_status)
        *sdk_status = (int)FM_OK;

    if (!lag_handle_set_snapshot_valid(before)) {
        if (sdk_status)
            *sdk_status = before ? before->sdk_status : (int)FM_FAIL;
        NL_LOG_CRIT("LAG create pre-image enumeration failed: sdk=%d",
                    before ? before->sdk_status : (int)FM_FAIL);
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    create_status = fmCreateLAG((fm_int)sw, &raw_lag_id);
    if (sdk_status)
        *sdk_status = (int)create_status;

    after = hal_lag_handle_set_snapshot_get(sw);
    if (!lag_handle_set_snapshot_valid(&after)) {
        NL_LOG_CRIT(
            "LAG create post-image enumeration failed: create-sdk=%d "
            "read-sdk=%d",
            (int)create_status, after.sdk_status);
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    lag_handle_set_delta(
        before, &after, &added_count, &added_lag_id, &removed_count);

    if (added_count == 1) {
        if (lag_id)
            *lag_id = added_lag_id;
        if (created)
            *created = true;
    }

    if (removed_count != 0 || added_count != 1) {
        if (create_status != FM_OK &&
            removed_count == 0 && added_count == 0) {
            NL_LOG_ERR("fmCreateLAG made no live mutation: %s",
                       fmErrorMsg(create_status));
            return NL_ERR_SDK_CALL_FAILED;
        }
        NL_LOG_CRIT(
            "LAG create delta is ambiguous: create-sdk=%d added=%d "
            "removed=%d",
            (int)create_status, added_count, removed_count);
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    if (create_status != FM_OK) {
        NL_LOG_ERR(
            "fmCreateLAG returned %s after creating live LAG %d",
            fmErrorMsg(create_status), added_lag_id);
        return NL_ERR_SDK_CALL_FAILED;
    }
    if ((int)raw_lag_id != added_lag_id) {
        NL_LOG_CRIT(
            "fmCreateLAG returned handle %d but live delta is LAG %d",
            (int)raw_lag_id, added_lag_id);
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    return 0;
}

int hal_lag_delete(int sw, int lag_id) {
    fm_status st = fmDeleteLAG((fm_int)sw, (fm_int)lag_id);
    hal_presence_snapshot snapshot;

    snapshot = hal_lag_wait_absent(sw, lag_id);
    if (snapshot.state == HAL_PRESENCE_ABSENT) {
        if (st != FM_OK)
            NL_LOG_WARN(
                "LAG %d delete returned %s but authoritative "
                "read-back is absent",
                lag_id, fmErrorMsg(st));
        NL_LOG_INFO("LAG %d deleted", lag_id);
        return 0;
    }
    NL_LOG_ERR(
        "LAG %d delete read-back not absent: delete-sdk=%d "
        "state=%d read-sdk=%d",
        lag_id, (int)st, (int)snapshot.state,
        snapshot.sdk_status);
    return snapshot.state == HAL_PRESENCE_READ_ERROR ?
        NL_ERR_HW_STATE_OUT_OF_SYNC :
        (st != FM_OK ?
         NL_ERR_SDK_CALL_FAILED : NL_ERR_READBACK_MISMATCH);
}

int hal_lag_add_port(int sw, int lag_id, int port) {
    if (fm10k_native_profile()) return hal_fm10k_lag_member_set(sw, lag_id, port, true);
    fm_status st = fmAddLAGPort((fm_int)sw, (fm_int)lag_id, (fm_int)port);
    if (st != FM_OK) {
        NL_LOG_ERR("fmAddLAGPort lag=%d port=%d: %s", lag_id, port, fmErrorMsg(st));
        return -1;
    }
    NL_LOG_INFO("LAG %d: added port %d", lag_id, port);
    return 0;
}

int hal_lag_del_port(int sw, int lag_id, int port) {
    if (fm10k_native_profile()) return hal_fm10k_lag_member_set(sw, lag_id, port, false);
    fm_status st = fmDeleteLAGPort((fm_int)sw, (fm_int)lag_id, (fm_int)port);
    hal_presence_snapshot snapshot;

    if (st != FM_OK) {
        NL_LOG_ERR("fmDeleteLAGPort lag=%d port=%d: %s", lag_id, port, fmErrorMsg(st));
        return -1;
    }
    snapshot = hal_lag_member_snapshot(sw, lag_id, port);
    if (snapshot.state != HAL_PRESENCE_ABSENT) {
        NL_LOG_ERR(
            "LAG %d port %d remove read-back not absent: state=%d sdk=%d",
            lag_id, port, (int)snapshot.state, snapshot.sdk_status);
        return -1;
    }
    NL_LOG_INFO("LAG %d: removed port %d", lag_id, port);
    return 0;
}

int hal_lag_restore_port(int sw, int lag_id, int port, u64 tx_id) {
    return fm10k_native_profile() ? hal_fm10k_lag_restore_port(sw, lag_id, port, tx_id) :
        hal_lag_add_port(sw, lag_id, port);
}
int hal_lag_del_port_transaction(int sw, int lag_id, int port, u64 tx_id) {
    return fm10k_native_profile() ? hal_fm10k_lag_del_port_transaction(sw, lag_id, port, tx_id) :
        hal_lag_del_port(sw, lag_id, port);
}
int hal_lag_transaction_check(u64 tx_id, bool committed) {
    return fm10k_native_profile() ? hal_fm10k_lag_transaction_check(tx_id, committed) : 0;
}
void hal_lag_transaction_retire(u64 tx_id) {
    if (fm10k_native_profile()) hal_fm10k_lag_transaction_retire(tx_id);
}
int hal_lag_attributes_capture(int sw, int lag_id, fm10k_lag_attributes *out) {
    if (!out) return NL_ERR_INVALID_VALUE;
    memset(out, 0, sizeof(*out));
    return fm10k_native_profile() ? hal_fm10k_lag_attributes_capture(sw, lag_id, out) : 0;
}
int hal_lag_attributes_restore(int sw, int lag_id, const fm10k_lag_attributes *before) {
    return fm10k_native_profile() ? hal_fm10k_lag_attributes_restore(sw, lag_id, before) : 0;
}
hal_qos_interface_transaction_snapshot hal_lag_qos_snapshot(int sw, int lag_id) {
    if (fm10k_native_profile()) return hal_fm10k_lag_qos_snapshot(sw, lag_id);
    return (hal_qos_interface_transaction_snapshot){.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR,
                                                   .sdk_status = NL_ERR_CAPABILITY_INSUFFICIENT};
}
int hal_lag_qos_restore(int sw, int lag_id, const hal_qos_interface_transaction_snapshot *before) {
    return fm10k_native_profile() ? hal_fm10k_lag_qos_restore(sw, lag_id, before) : NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_lag_qos_set(int sw, int lag_id, int trust, int priority) {
    return fm10k_native_profile() ? hal_fm10k_lag_qos_set(sw, lag_id, trust, priority) : NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_lag_qos_get(int sw, int lag_id, hal_qos_interface_entry *out) {
    return fm10k_native_profile() ? hal_fm10k_lag_qos_get(sw, lag_id, out) : NL_ERR_CAPABILITY_INSUFFICIENT;
}

int hal_lag_set_hash_rotation(int sw, int lag_id, int rotation) {
    fm_uint32 value = (fm_uint32)rotation;
    fm_status st;

    if (lag_id <= 0 || (rotation != 0 && rotation != 1))
        return -1;

    st = fmSetLAGAttribute((fm_int)sw, FM_LAG_HASH_ROTATION,
                           (fm_int)lag_id, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("fmSetLAGAttribute HASH_ROTATION lag=%d rotation=%d: %s",
                   lag_id, rotation, fmErrorMsg(st));
        return (int)st;
    }
    NL_LOG_INFO("LAG %d: hash rotation=%s", lag_id,
                rotation == 0 ? "A" : "B");
    return 0;
}

int hal_lag_get_hash_rotation(int sw, int lag_id, int *rotation) {
    fm_uint32 value = 0;
    fm_status st;

    if (rotation)
        *rotation = -1;
    if (lag_id <= 0)
        return -1;

    st = fmGetLAGAttribute((fm_int)sw, FM_LAG_HASH_ROTATION,
                           (fm_int)lag_id, &value);
    if (st != FM_OK)
        return (int)st;
    if (rotation)
        *rotation = (int)value;
    return 0;
}

int hal_lag_get_all(int sw, struct sdk_result *result) {
    if (!result)
        return -1;
    memset(&result->data.lag_list, 0, sizeof(result->data.lag_list));

    fm_int curLag;
    fm_status st = fmGetLAGFirst((fm_int)sw, &curLag);
    if (st == FM_ERR_NO_LAGS) return 0;
    if (st != FM_OK) return -1;
    if (curLag <= 0) return NL_ERR_PRE_STATE_MISSING;

    while (curLag > 0) {
        int idx = result->data.lag_list.n_lags;
        hal_lag_readback_entry *entry;
        fm_int logical_port = -1;
        fm_int members[NETLAB_MAX_LAG_MEMBERS];
        fm_int n_members = 0;

        if (idx >= NETLAB_MAX_AE)
            return NL_ERR_CAPABILITY_INSUFFICIENT;
        for (int i = 0; i < idx; ++i)
            if (result->data.lag_list.lag[i].lag_id == curLag)
                return NL_ERR_HW_STATE_OUT_OF_SYNC;
        entry = &result->data.lag_list.lag[idx];
        memset(entry, 0, sizeof(*entry));
        memset(members, 0, sizeof(members));
        entry->lag_id = (int)curLag;
        entry->ae_id = hal_lag_ae_for_id((int)curLag);
        entry->logical_port = -1;
        entry->logical_port_status = (int)fmLAGNumberToLogicalPort(
            (fm_int)sw, curLag, &logical_port);
        if (entry->logical_port_status == FM_OK && logical_port > 0)
            entry->logical_port = (int)logical_port;
        else if (entry->logical_port_status == FM_OK)
            entry->logical_port_status = NL_ERR_PRE_STATE_MISSING;
        entry->member_status = (int)fmGetLAGPortList(
            (fm_int)sw, curLag, &n_members, members,
            NETLAB_MAX_LAG_MEMBERS);
        if (entry->member_status == FM_OK && (n_members < 0 || n_members > NETLAB_MAX_LAG_MEMBERS))
            entry->member_status = NL_ERR_PRE_STATE_MISSING;
        if (entry->member_status == FM_OK) {
            entry->n_members = (int)n_members;
            for (int i = 0; i < entry->n_members; i++)
                entry->members[i] = (int)members[i];
            if (fm10k_native_profile() &&
                (entry->ae_id < 0 || hal_fm10k_lag_members_status(curLag, entry->members, entry->n_members)))
                entry->member_status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        }
        entry->qos_status = NL_ERR_CAPABILITY_INSUFFICIENT;
        entry->qos_trust = entry->qos_default_priority = -1;
        if (fm10k_native_profile()) {
            hal_qos_interface_entry qos;
            entry->qos_status = hal_lag_qos_get(sw, curLag, &qos);
            if (!entry->qos_status) {
                entry->qos_trust = qos.trust_mode;
                entry->qos_default_priority = qos.default_priority;
            }
        }
        result->data.lag_list.n_lags = idx + 1;
        st = fmGetLAGNext((fm_int)sw, curLag, &curLag);
        if (st == FM_ERR_NO_LAGS)
            break;
        if (st != FM_OK)
            return -1;
        if (curLag <= 0)
            return NL_ERR_PRE_STATE_MISSING;
    }

    return 0;
}
