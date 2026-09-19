/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "hal_pfc_watchdog.h"
#include "netlab/hal_l2_flow_snapshot.h"
#include "netlab/hal_presence.h"
#include "netlab/error.h"
#include "hal_acl_owner_transaction_api.h"
#include "hal_flow_table.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_addr.h>
#include <api/fm_api_lag.h>

static int lag_lacp_to_cpu(int sw, int lag_id) {
    fm_uint32 disposition = FM_PDU_TOCPU;
    fm_status st = fmSetLAGAttribute((fm_int)sw, FM_LAG_LACP_DISPOSITION,
                                     (fm_int)lag_id, &disposition);
    if (st == FM_OK) {
        NL_LOG_INFO("lag %d: LACP disposition=TOCPU", lag_id);
        return 0;
    }
    if (st == FM_ERR_UNSUPPORTED || st == FM_ERR_INVALID_ATTRIB) {
        NL_LOG_INFO("lag %d: LACP disposition controlled by switch LAG mode",
                    lag_id);
        return 0;
    }
    NL_LOG_ERR("lag %d: LACP disposition TOCPU failed: %s",
               lag_id, fmErrorMsg(st));
    return (int)st;
}

static int g_ae_lag_id[NETLAB_MAX_AE];

static bool valid_ae_id(int ae_id) {
    return ae_id >= 0 && ae_id < NETLAB_MAX_AE;
}

static void remember_ae_lag(int ae_id, int lag_id) {
    if (valid_ae_id(ae_id) && lag_id > 0)
        g_ae_lag_id[ae_id] = lag_id;
}

static void forget_ae_lag(int ae_id, int lag_id) {
    if (valid_ae_id(ae_id) &&
        (lag_id <= 0 || g_ae_lag_id[ae_id] == lag_id))
        g_ae_lag_id[ae_id] = 0;
}

int hal_lag_id_for_ae(int ae_id) {
    return valid_ae_id(ae_id) ? g_ae_lag_id[ae_id] : 0;
}

int hal_lag_ae_for_id(int lag_id) {
    if (lag_id <= 0)
        return -1;
    for (int i = 0; i < NETLAB_MAX_AE; i++)
        if (g_ae_lag_id[i] == lag_id)
            return i;
    return -1;
}

// ===== Typed Apply Plan Executor =====

enum {
    HW_CAPTURE_ERROR = HAL_PRESENCE_READ_ERROR,
    HW_CAPTURE_ABSENT = HAL_PRESENCE_ABSENT,
    HW_CAPTURE_PRESENT = HAL_PRESENCE_PRESENT,
};

static int hw_vlan_exists_state(int sw, u16 vid) {
    return (int)hal_vlan_presence_snapshot(sw, vid).state;
}

static int hw_vlan_member_state(int sw, u16 vid, int port, bool *tagged) {
    hal_presence_snapshot snapshot =
        hal_vlan_member_snapshot(sw, vid, port);

    if (tagged)
        *tagged = snapshot.state == HAL_PRESENCE_PRESENT ?
            snapshot.tagged : false;
    return (int)snapshot.state;
}

static int hw_lag_exists_state(int sw, int lag_id) {
    if (lag_id <= 0)
        return HW_CAPTURE_ABSENT;
    return (int)hal_lag_presence_snapshot(sw, lag_id).state;
}

static int hw_lag_member_state(int sw, int lag_id, int port) {
    if (lag_id <= 0 || port <= 0)
        return HW_CAPTURE_ABSENT;
    return (int)hal_lag_member_snapshot(sw, lag_id, port).state;
}

static int resolve_lag_id(int sw, l2_apply_step *step) {
    int present;

    if (!step)
        return 0;
    /*
     * ae_id is the persistent identity.  SDK LAG IDs are allocator-owned
     * handles and may change after delete/recreate, so a cached handle must
     * never override the live semantic mapping.
     */
    if (valid_ae_id(step->ae_id)) {
        step->lag_id = g_ae_lag_id[step->ae_id];
        if (step->lag_id <= 0)
            return 0;
        present = hw_lag_exists_state(sw, step->lag_id);
        if (present == HW_CAPTURE_PRESENT)
            return step->lag_id;
        if (present == HW_CAPTURE_ABSENT) {
            forget_ae_lag(step->ae_id, step->lag_id);
            step->lag_id = 0;
            return 0;
        }
        step->lag_id = 0;
        return -1;
    }

    if (step->lag_id > 0) {
        present = hw_lag_exists_state(sw, step->lag_id);
        if (present == HW_CAPTURE_PRESENT)
            return step->lag_id;
        step->lag_id = 0;
        if (present == HW_CAPTURE_ERROR)
            return -1;
    }
    return 0;
}

static int resolve_target_port_state(int sw, l2_apply_step *step) {
    fm_int lport = 0;
    fm_status st;
    int lag;

    if (!step)
        return HW_CAPTURE_ERROR;
    if (!valid_ae_id(step->ae_id))
        return step->port > 0 ?
            HW_CAPTURE_PRESENT : HW_CAPTURE_ERROR;

    lag = resolve_lag_id(sw, step);
    if (lag < 0)
        return HW_CAPTURE_ERROR;
    if (lag == 0) {
        step->port = 0;
        return HW_CAPTURE_ABSENT;
    }
    st = fmLAGNumberToLogicalPort((fm_int)sw, (fm_int)lag, &lport);
    if (st != FM_OK || lport <= 0) {
        NL_LOG_ERR("resolve ae%d logical port failed: %s",
                   step->ae_id, fmErrorMsg(st));
        return HW_CAPTURE_ERROR;
    }
    step->lag_id = lag;
    step->port = (int)lport;
    return HW_CAPTURE_PRESENT;
}

static int resolve_target_port(int sw, l2_apply_step *step) {
    int state = resolve_target_port_state(sw, step);

    if (state == HW_CAPTURE_PRESENT)
        return step->port;
    return state == HW_CAPTURE_ABSENT ? 0 : -1;
}

static int pre_static_mac_cmp(const void *left, const void *right) {
    const l2_pre_static_mac_entry *a = left;
    const l2_pre_static_mac_entry *b = right;
    int cmp = memcmp(a->mac, b->mac, sizeof(a->mac));

    if (cmp != 0)
        return cmp;
    if (a->ae_id != b->ae_id)
        return a->ae_id < b->ae_id ? -1 : 1;
    if (a->port != b->port)
        return a->port < b->port ? -1 : 1;
    if (a->entry_type != b->entry_type)
        return a->entry_type < b->entry_type ? -1 : 1;
    return 0;
}

static bool pre_static_mac_sets_equal(
    const l2_pre_static_mac_entry *left, int n_left,
    const l2_pre_static_mac_entry *right, int n_right) {
    if (n_left != n_right)
        return false;
    for (int i = 0; i < n_left; i++) {
        if (memcmp(left[i].mac, right[i].mac,
                   sizeof(left[i].mac)) != 0 ||
            left[i].ae_id != right[i].ae_id ||
            left[i].entry_type != right[i].entry_type ||
            (!valid_ae_id(left[i].ae_id) &&
             left[i].port != right[i].port))
            return false;
    }
    return true;
}

static int static_mac_semantic_target(
    int sw, int port, int *ae_id) {
    fm_int lag = -1;
    fm_status st;
    int ae;

    if (!ae_id || port <= 0)
        return -1;
    *ae_id = -1;
    st = fmLogicalPortToLAGNumber(
        (fm_int)sw, (fm_int)port, &lag);
    if (st == FM_ERR_INVALID_PORT)
        return 0;
    if (st != FM_OK || lag <= 0)
        return -1;
    ae = hal_lag_ae_for_id((int)lag);
    if (!valid_ae_id(ae))
        return -1;
    *ae_id = ae;
    return 0;
}

static int read_vlan_static_macs_once(
    int sw, u16 vid, l2_pre_static_mac_entry *snapshot,
    int *n_snapshot) {
    fm_macAddressEntry *entries = NULL;
    fm_int total = 0;
    fm_int received = 0;
    fm_status st;
    int n = 0;

    if (!snapshot || !n_snapshot)
        return -1;
    *n_snapshot = 0;
    st = fmGetAddressTableExt(
        (fm_int)sw, &total, NULL, 0);
    if (st != FM_OK || total < 0 || total > 131072)
        return -1;
    if (total > 0) {
        entries = calloc((size_t)total, sizeof(*entries));
        if (!entries)
            return -1;
        received = total;
        st = fmGetAddressTableExt(
            (fm_int)sw, &received, entries, total);
        if (st != FM_OK || received < 0 || received > total) {
            free(entries);
            return -1;
        }
    }

    for (fm_int i = 0; i < received; i++) {
        l2_pre_static_mac_entry *out;
        fm_uint64 mac;

        if ((u16)entries[i].vlanID != vid ||
            (entries[i].type != FM_ADDRESS_STATIC &&
             entries[i].type != FM_ADDRESS_SECURE_STATIC))
            continue;
        if (n >= L2_PRE_STATIC_MAC_MAX) {
            free(entries);
            return -1;
        }
        out = &snapshot[n];
        memset(out, 0, sizeof(*out));
        mac = (fm_uint64)entries[i].macAddress;
        out->mac[0] = (u8)((mac >> 40) & 0xff);
        out->mac[1] = (u8)((mac >> 32) & 0xff);
        out->mac[2] = (u8)((mac >> 24) & 0xff);
        out->mac[3] = (u8)((mac >> 16) & 0xff);
        out->mac[4] = (u8)((mac >> 8) & 0xff);
        out->mac[5] = (u8)(mac & 0xff);
        out->port = (int)entries[i].port;
        out->entry_type = (int)entries[i].type;
        if (static_mac_semantic_target(
                sw, out->port, &out->ae_id) != 0) {
            free(entries);
            return -1;
        }
        n++;
    }
    free(entries);
    qsort(snapshot, (size_t)n, sizeof(*snapshot),
          pre_static_mac_cmp);
    *n_snapshot = n;
    return 0;
}

static int capture_vlan_static_macs(
    int sw, u16 vid, l2_apply_step *step) {
    l2_pre_static_mac_entry first[L2_PRE_STATIC_MAC_MAX];
    l2_pre_static_mac_entry second[L2_PRE_STATIC_MAC_MAX];
    int n_first = 0;
    int n_second = 0;

    if (!step)
        return -1;
    if (!step->pre_static_macs) {
        step->pre_static_macs = calloc(
            L2_PRE_STATIC_MAC_MAX, sizeof(*step->pre_static_macs));
        if (!step->pre_static_macs)
            return -1;
    }
    for (int attempt = 0; attempt < 3; attempt++) {
        if (read_vlan_static_macs_once(
                sw, vid, first, &n_first) != 0 ||
            read_vlan_static_macs_once(
                sw, vid, second, &n_second) != 0)
            return -1;
        if (!pre_static_mac_sets_equal(
                first, n_first, second, n_second))
            continue;
        step->pre_static_mac_count = n_second;
        if (n_second > 0) {
            memcpy(step->pre_static_macs, second,
                   (size_t)n_second * sizeof(second[0]));
        }
        return 0;
    }
    return -1;
}

static int resolve_static_mac_snapshot_port(
    int sw, const l2_pre_static_mac_entry *entry) {
    l2_apply_step target;

    if (!entry)
        return -1;
    if (!valid_ae_id(entry->ae_id))
        return entry->port > 0 ? entry->port : -1;
    memset(&target, 0, sizeof(target));
    target.ae_id = entry->ae_id;
    target.port = entry->port;
    return resolve_target_port(sw, &target);
}

static int restore_vlan_static_macs(
    int sw, u16 vid, const l2_apply_step *step) {
    if (!step || step->pre_static_mac_count < 0 ||
        step->pre_static_mac_count > L2_PRE_STATIC_MAC_MAX)
        return -1;
    for (int i = 0; i < step->pre_static_mac_count; i++) {
        const l2_pre_static_mac_entry *saved =
            &step->pre_static_macs[i];
        fm_macAddressEntry entry;
        int port = resolve_static_mac_snapshot_port(sw, saved);
        int current_port = 0;
        int current_type = 0;
        bool current_static = false;
        bool current_valid = false;
        fm_status st;

        if (port <= 0)
            return -1;
        if (hal_mac_entry_snapshot(
                sw, vid, saved->mac, &current_valid,
                &current_port, &current_static,
                &current_type) != 0)
            return -1;
        if (current_valid) {
            if (current_static &&
                current_port == port &&
                current_type == saved->entry_type)
                continue;
            /*
             * Rollback owns only the static/secure-static entries captured
             * before apply.  Never replace a foreign dynamic or protocol
             * entry that appeared while the transaction was in flight.
             */
            if (!current_static)
                return -1;
            if (hal_static_mac_delete(
                    sw, vid, saved->mac) != 0)
                return -1;
        }
        memset(&entry, 0, sizeof(entry));
        entry.macAddress =
            ((fm_macaddr)saved->mac[0] << 40) |
            ((fm_macaddr)saved->mac[1] << 32) |
            ((fm_macaddr)saved->mac[2] << 24) |
            ((fm_macaddr)saved->mac[3] << 16) |
            ((fm_macaddr)saved->mac[4] << 8) |
            (fm_macaddr)saved->mac[5];
        entry.vlanID = (fm_uint16)vid;
        entry.type = (fm_int)saved->entry_type;
        entry.destMask = FM_DESTMASK_UNUSED;
        entry.port = (fm_int)port;
        st = fmAddAddress((fm_int)sw, &entry);
        if (st != FM_OK)
            return (int)st;
    }
    return 0;
}

static int pre_vlan_member_cmp(const void *left, const void *right) {
    const l2_pre_vlan_member_entry *a = left;
    const l2_pre_vlan_member_entry *b = right;

    if (a->ae_id != b->ae_id)
        return a->ae_id < b->ae_id ? -1 : 1;
    if (a->port != b->port)
        return a->port < b->port ? -1 : 1;
    if (a->tagged != b->tagged)
        return a->tagged ? 1 : -1;
    if (a->stp_state != b->stp_state)
        return a->stp_state < b->stp_state ? -1 : 1;
    return 0;
}

static bool pre_vlan_member_sets_equal(
    const l2_pre_vlan_member_entry *left, int n_left,
    const l2_pre_vlan_member_entry *right, int n_right) {
    if (n_left != n_right)
        return false;
    for (int i = 0; i < n_left; i++) {
        if (left[i].ae_id != right[i].ae_id ||
            left[i].tagged != right[i].tagged ||
            left[i].stp_state != right[i].stp_state ||
            (!valid_ae_id(left[i].ae_id) &&
             left[i].port != right[i].port))
            return false;
    }
    return true;
}

static int append_vlan_member_snapshot(
    int sw, u16 vid, int port, l2_apply_step *step) {
    l2_pre_vlan_member_entry entry;
    fm_int stp = 0;
    fm_bool tagged = FALSE;
    fm_status st;

    if (!step || port <= 0)
        return -1;
    memset(&entry, 0, sizeof(entry));
    entry.port = port;
    if (static_mac_semantic_target(
            sw, port, &entry.ae_id) != 0)
        return -1;
    for (int i = 0; i < step->pre_vlan_member_count; i++) {
        const l2_pre_vlan_member_entry *existing =
            &step->pre_vlan_members[i];
        if (entry.ae_id >= 0 ?
            existing->ae_id == entry.ae_id :
            (existing->ae_id < 0 && existing->port == port))
            return 0;
    }
    if (step->pre_vlan_member_count >=
        L2_PRE_VLAN_MEMBER_MAX)
        return -1;
    st = fmGetVlanPortTag(
        (fm_int)sw, (fm_int)vid, (fm_int)port, &tagged);
    if (st != FM_OK)
        return -1;
    st = fmGetVlanPortState(
        (fm_int)sw, (fm_int)vid, (fm_int)port, &stp);
    if (st != FM_OK)
        return -1;
    entry.tagged = tagged ? true : false;
    entry.stp_state = (int)stp;
    step->pre_vlan_members[
        step->pre_vlan_member_count++] = entry;
    return 0;
}

static int capture_vlan_members(
    int sw, u16 vid, l2_apply_step *step) {
    fm_int current = -1;
    fm_status st;

    if (!step)
        return -1;
    if (!step->pre_vlan_members) {
        step->pre_vlan_members = calloc(
            L2_PRE_VLAN_MEMBER_MAX, sizeof(*step->pre_vlan_members));
        if (!step->pre_vlan_members)
            return -1;
    }
    step->pre_vlan_member_count = 0;
    st = fmGetVlanPortFirst(
        (fm_int)sw, (fm_int)vid, &current);
    if (st != FM_OK)
        return -1;
    unsigned visited = 0;
    while (current != -1) {
        if (current < 0 || ++visited > 65536) return -1;
        fm_int next = -1;

        /* CPU/TE membership is managed by the SDK and mirror owner, not by
         * data-port VLAN intents. Keep the mirror's own full before-image. */
        if (current != 0 && !fm10k_native_aux_port(sw, current) && append_vlan_member_snapshot(
                sw, vid, (int)current, step) != 0)
            return -1;
        st = fmGetVlanPortNext(
            (fm_int)sw, (fm_int)vid, current, &next);
        if (st != FM_OK)
            return -1;
        current = next;
    }

    /*
     * This pinned SDK omits LAG logical ports from the VLAN iterator.  Probe
     * every owned AE through its semantic mapping and merge direct tag/state
     * observations into the same bounded snapshot.
     */
    for (int ae = 0; ae < NETLAB_MAX_AE; ae++) {
        l2_apply_step target;
        int member;

        if (g_ae_lag_id[ae] <= 0)
            continue;
        memset(&target, 0, sizeof(target));
        target.ae_id = ae;
        if (resolve_target_port_state(
                sw, &target) != HW_CAPTURE_PRESENT)
            return -1;
        member = hw_vlan_member_state(
            sw, vid, target.port, NULL);
        if (member == HW_CAPTURE_ERROR)
            return -1;
        if (member == HW_CAPTURE_PRESENT &&
            append_vlan_member_snapshot(
                sw, vid, target.port, step) != 0)
            return -1;
    }
    qsort(step->pre_vlan_members,
          (size_t)step->pre_vlan_member_count,
          sizeof(step->pre_vlan_members[0]),
          pre_vlan_member_cmp);
    return 0;
}

static int int_cmp(const void *left, const void *right) {
    int a = *(const int *)left;
    int b = *(const int *)right;

    return a < b ? -1 : a > b ? 1 : 0;
}

static int capture_lag_composite(
    int sw, int lag_id, l2_apply_step *step) {
    fm_int members[NETLAB_MAX_LAG_MEMBERS];
    fm_int n_members = 0;
    fm_uint32 lacp = 0;
    fm_status st;

    if (!step || lag_id <= 0)
        return -1;
    memset(members, 0, sizeof(members));
    st = fmGetLAGPortList(
        (fm_int)sw, (fm_int)lag_id, &n_members, members,
        NETLAB_MAX_LAG_MEMBERS);
    if (st != FM_OK || n_members < 0 ||
        n_members > NETLAB_MAX_LAG_MEMBERS)
        return -1;
    step->pre_lag_member_count = (int)n_members;
    for (int i = 0; i < step->pre_lag_member_count; i++)
        step->pre_lag_members[i] = (int)members[i];
    qsort(step->pre_lag_members,
          (size_t)step->pre_lag_member_count,
          sizeof(step->pre_lag_members[0]), int_cmp);

    if (hal_lag_get_hash_rotation(
            sw, lag_id, &step->pre_lag_hash_rotation) != 0)
        return -1;
    step->pre_lag_hash_rotation_valid = true;
    st = fmGetLAGAttribute(
        (fm_int)sw, FM_LAG_LACP_DISPOSITION,
        (fm_int)lag_id, &lacp);
    if (st == FM_OK) {
        step->pre_lag_lacp_disposition_valid = true;
        step->pre_lag_lacp_disposition = (int)lacp;
    } else if (st != FM_ERR_UNSUPPORTED &&
               st != FM_ERR_INVALID_ATTRIB) {
        return -1;
    }
    return hal_lag_attributes_capture(sw, lag_id, &step->pre_lag_attributes);
}

static int lag_vlan_membership_count(int sw, int lag_id) {
    fm_int logical = -1;
    fm_int vlan = -1;
    fm_status st;
    int count = 0;

    st = fmLAGNumberToLogicalPort(
        (fm_int)sw, (fm_int)lag_id, &logical);
    if (st != FM_OK || logical <= 0)
        return -1;
    st = fmGetVlanFirst((fm_int)sw, &vlan);
    if (st != FM_OK)
        return -1;
    unsigned visited = 0;
    while (vlan != -1) {
        if (vlan < 1 || vlan > 4094 || ++visited > 4094) return -1;
        fm_int next = -1;
        int member = hw_vlan_member_state(
            sw, (u16)vlan, (int)logical, NULL);

        if (member == HW_CAPTURE_ERROR)
            return -1;
        if (member == HW_CAPTURE_PRESENT)
            count++;
        st = fmGetVlanNext(
            (fm_int)sw, vlan, &next);
        if (st != FM_OK)
            return -1;
        vlan = next;
    }
    return count;
}

static int capture_vlan_member_pre_state(
    int sw, l2_apply_step *step) {
    int target_state;
    int vlan_state;
    int member_state;

    if (!step)
        return -1;
    target_state = resolve_target_port_state(sw, step);
    if (target_state == HW_CAPTURE_ERROR)
        return -1;
    vlan_state = hw_vlan_exists_state(sw, step->vid);
    if (vlan_state == HW_CAPTURE_ERROR)
        return -1;
    if (target_state == HW_CAPTURE_ABSENT ||
        vlan_state == HW_CAPTURE_ABSENT)
        return 0;

    member_state = hw_vlan_member_state(
        sw, step->vid, step->port, &step->pre_member_tagged);
    if (member_state == HW_CAPTURE_ERROR)
        return -1;
    step->pre_member_existed =
        member_state == HW_CAPTURE_PRESENT;
    if (step->pre_member_existed) {
        fm_int stp = 0;
        fm_status st = fmGetVlanPortState(
            (fm_int)sw, (fm_int)step->vid,
            (fm_int)step->port, &stp);

        if (st != FM_OK)
            return -1;
        step->pre_member_stp_valid = true;
        step->pre_member_stp_state = (int)stp;
    }
    if (step->type == L2_STEP_VLAN_ADD_PORT ||
        step->pre_member_existed) {
        if (capture_vlan_static_macs(sw, step->vid, step) != 0)
            return -1;
    }
    return 0;
}

static int capture_exact_flow_rule_state(
    int sw, const hal_flow_presence_snapshot *rule,
    bool *table_present, bool *rule_present) {
    hal_flow_presence_snapshot table;

    if (!rule || !table_present || !rule_present)
        return -1;
    table = hal_l2_security_table_snapshot(sw);
    if (table.state == HAL_PRESENCE_READ_ERROR ||
        (table.state == HAL_PRESENCE_PRESENT && !table.exact) ||
        rule->state == HAL_PRESENCE_READ_ERROR ||
        (rule->state == HAL_PRESENCE_PRESENT && !rule->exact))
        return -1;
    *table_present = table.state == HAL_PRESENCE_PRESENT;
    *rule_present = rule->state == HAL_PRESENCE_PRESENT;
    return 0;
}

static int capture_step_pre_state(int sw, l2_apply_step *step,
                                  bool apply_capture) {
    fm_status st;
    int present;

    switch (step->type) {
        case L2_STEP_FM10K_GROUP_SET: {
            int rc = hal_fm10k_group_capture(sw, step->fm10k_group.epl, &step->pre_fm10k_group);
            step->pre_fm10k_group_valid = rc == 0;
            return rc;
        }
        case L2_STEP_FM10K_FAN_SET:
            return hal_fm10k_fan_capture(sw, &step->pre_fm10k_fan);
        case L2_STEP_VLAN_CREATE:
        case L2_STEP_VLAN_DELETE:
            present = hw_vlan_exists_state(sw, step->vid);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            step->pre_vlan_existed =
                present == HW_CAPTURE_PRESENT;
            if (step->type == L2_STEP_VLAN_DELETE &&
                step->pre_vlan_existed) {
                if (capture_vlan_static_macs(
                        sw, step->vid, step) != 0 ||
                    capture_vlan_members(
                        sw, step->vid, step) != 0)
                    return -1;
            }
            return 0;
        case L2_STEP_VLAN_ADD_PORT:
        case L2_STEP_VLAN_REM_PORT:
            return capture_vlan_member_pre_state(sw, step);
        case L2_STEP_PVID_SET: {
            fm_uint32 pvid = 0;
            present = resolve_target_port_state(sw, step);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT)
                return 0;
            st = fmGetPortAttribute((fm_int)sw, (fm_int)step->port,
                                    FM_PORT_DEF_VLAN, &pvid);
            if (st != FM_OK)
                return -1;
            step->pre_pvid_valid = true;
            step->pre_pvid = (u16)pvid;
            return 0;
        }
        case L2_STEP_VLAN_STP_SET: {
            fm_int stp_state = 0;
            int vlan_state;
            int member_state;

            present = resolve_target_port_state(sw, step);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            vlan_state = hw_vlan_exists_state(sw, step->vid);
            if (vlan_state == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT ||
                vlan_state == HW_CAPTURE_ABSENT)
                return 0;
            member_state = hw_vlan_member_state(
                sw, step->vid, step->port, NULL);
            if (member_state == HW_CAPTURE_ERROR)
                return -1;
            if (member_state == HW_CAPTURE_ABSENT)
                return 0;
            st = fmGetVlanPortState((fm_int)sw, (fm_int)step->vid,
                                    (fm_int)step->port, &stp_state);
            if (st != FM_OK)
                return -1;
            step->pre_stp_valid = true;
            step->pre_stp_state = (int)stp_state;
            return 0;
        }
        case L2_STEP_PORT_SET_ADMIN:
            step->pre_admin =
                hal_port_admin_transaction_snapshot_get(
                    sw, step->port);
            return step->pre_admin.state ==
                HAL_TRANSACTION_SNAPSHOT_PRESENT ? 0 : -1;
        case L2_STEP_PORT_SET_MTU: {
            int mtu = 0;
            present = resolve_target_port_state(sw, step);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT)
                return 0;
            if (hal_port_get_mtu(sw, step->port, &mtu, NULL) != 0)
                return -1;
            step->pre_mtu_valid = true;
            step->pre_mtu = mtu;
            return 0;
        }
        case L2_STEP_PORT_SET_SPEED: {
            int speed = 0;
            int ethernet_mode = 0;
            present = resolve_target_port_state(sw, step);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT)
                return 0;
            if (hal_port_get_speed_mode(sw, step->port, &speed,
                                        &ethernet_mode) != 0)
                return -1;
            if (!hal_port_ethernet_mode_restorable(ethernet_mode))
                return -1;
            step->pre_admin =
                hal_port_admin_transaction_snapshot_get(
                    sw, step->port);
            if (step->pre_admin.state !=
                    HAL_TRANSACTION_SNAPSHOT_PRESENT)
                return -1;
            step->pre_speed_valid = true;
            step->pre_speed = speed;
            step->pre_ethernet_mode = ethernet_mode;
            return 0;
        }
        case L2_STEP_PORT_INGRESS_FILTER_SET: {
            fm_bool enabled = FALSE;
            present = resolve_target_port_state(sw, step);
            if (present == HW_CAPTURE_ERROR) return -1;
            if (present == HW_CAPTURE_ABSENT) return 0;
            st = fmGetPortAttribute(sw, step->port, FM_PORT_DROP_BV, &enabled);
            if (st != FM_OK || (enabled != TRUE && enabled != FALSE)) return -1;
            step->pre_ingress_filter_valid = true;
            step->pre_ingress_filter = enabled == TRUE;
            return 0;
        }
        case L2_STEP_PORT_PARSER_SET: {
            fm_int parser = 0;
            present = resolve_target_port_state(sw, step);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT)
                return 0;
            st = fmGetPortAttribute((fm_int)sw, (fm_int)step->port,
                                    FM_PORT_PARSER, &parser);
            if (st != FM_OK)
                return -1;
            step->pre_parser_valid = true;
            step->pre_parser_mode = (int)parser;
            return 0;
        }
        case L2_STEP_MAC_AGING_SET: {
            int aging = 0;
            if (hal_mac_aging_get(sw, &aging) != 0)
                return -1;
            step->pre_aging_valid = true;
            step->pre_aging_time = aging;
            return 0;
        }
        case L2_STEP_STATIC_MAC_ADD:
            present = hw_vlan_exists_state(sw, step->vid);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT)
                return 0;
            if (hal_mac_entry_snapshot(
                    sw, step->vid, step->mac,
                    &step->pre_mac_valid, &step->pre_mac_port,
                    &step->pre_mac_static,
                    &step->pre_mac_type) != 0)
                return -1;
            if (step->pre_mac_valid &&
                static_mac_semantic_target(
                    sw, step->pre_mac_port,
                    &step->pre_mac_ae_id) != 0)
                return -1;
            return 0;
        case L2_STEP_STATIC_MAC_DEL:
            present = hw_vlan_exists_state(sw, step->vid);
            if (present == HW_CAPTURE_ERROR)
                return -1;
            if (present == HW_CAPTURE_ABSENT)
                return 0;
            if (hal_mac_entry_snapshot(
                    sw, step->vid, step->mac,
                    &step->pre_mac_valid, &step->pre_mac_port,
                    &step->pre_mac_static,
                    &step->pre_mac_type) != 0)
                return -1;
            if (step->pre_mac_valid &&
                static_mac_semantic_target(
                    sw, step->pre_mac_port,
                    &step->pre_mac_ae_id) != 0)
                return -1;
            return 0;
        case L2_STEP_LAG_CREATE:
        case L2_STEP_LAG_DELETE:
            step->pre_lag_handles =
                hal_lag_handle_set_snapshot_get(sw);
            if (step->pre_lag_handles.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
                return -1;
            step->pre_lag_id = resolve_lag_id(sw, step);
            if (step->pre_lag_id < 0)
                return -1;
            step->pre_lag_existed = step->pre_lag_id > 0;
            step->lag_id = step->pre_lag_id;
            if (step->type == L2_STEP_LAG_DELETE &&
                step->pre_lag_existed &&
                capture_lag_composite(
                    sw, step->pre_lag_id, step) != 0)
                return -1;
            return 0;
        case L2_STEP_LAG_ADD_PORT:
        case L2_STEP_LAG_DEL_PORT:
            step->pre_lag_id = resolve_lag_id(sw, step);
            if (step->pre_lag_id < 0)
                return -1;
            step->pre_lag_existed = step->pre_lag_id > 0;
            step->lag_id = step->pre_lag_id;
            present = step->pre_lag_existed ?
                hw_lag_member_state(
                    sw, step->pre_lag_id, step->port) :
                HW_CAPTURE_ABSENT;
            if (present == HW_CAPTURE_ERROR)
                return -1;
            step->pre_lag_member_existed =
                present == HW_CAPTURE_PRESENT;
            return 0;
        case L2_STEP_LAG_HASH_ROTATION_SET:
            step->pre_lag_id = resolve_lag_id(sw, step);
            if (step->pre_lag_id < 0)
                return -1;
            step->pre_lag_existed = step->pre_lag_id > 0;
            step->lag_id = step->pre_lag_id;
            if (step->pre_lag_id <= 0)
                return 0;
            if (hal_lag_get_hash_rotation(sw, step->pre_lag_id,
                                          &step->pre_lag_hash_rotation) != 0)
                return -1;
            step->pre_lag_hash_rotation_valid = true;
            return 0;
        case L2_STEP_DHCP_SNOOPING_SET:
        case L2_STEP_DHCP_SNOOPING_DEL: {
            hal_flow_presence_snapshot snapshot =
                hal_l2_security_rule_snapshot(
                    sw, "dhcp-snooping",
                    (u16)step->security_vid,
                    step->security_port);
            return capture_exact_flow_rule_state(
                sw, &snapshot,
                &step->pre_security_table_present,
                &step->pre_security_present);
        }
        case L2_STEP_ARP_INSPECTION_SET:
        case L2_STEP_ARP_INSPECTION_DEL: {
            hal_flow_presence_snapshot snapshot =
                hal_l2_security_rule_snapshot(
                    sw, "arp-inspection",
                    (u16)step->security_vid,
                    step->security_port);
            return capture_exact_flow_rule_state(
                sw, &snapshot,
                &step->pre_security_table_present,
                &step->pre_security_present);
        }
        case L2_STEP_ARP_INSPECTION_BINDING_SET:
        case L2_STEP_ARP_INSPECTION_BINDING_DEL: {
            hal_flow_presence_snapshot snapshot =
                hal_l2_security_arp_binding_snapshot(
                    sw, (u16)step->security_vid,
                    step->security_port, step->security_mac,
                    step->security_ip);
            return capture_exact_flow_rule_state(
                sw, &snapshot,
                &step->pre_security_table_present,
                &step->pre_security_present);
        }
        case L2_STEP_USER_FILTER_SET:
        case L2_STEP_USER_FILTER_DEL: {
            hal_flow_presence_snapshot snapshot =
                hal_l2_security_user_filter_snapshot(
                    sw, (u16)step->security_vid,
                    step->security_port, step->security_mac,
                    step->security_mac_kind);
            return capture_exact_flow_rule_state(
                sw, &snapshot,
                &step->pre_security_table_present,
                &step->pre_security_present);
        }
        case L2_STEP_INGRESS_IPV4_ACL_SET:
        case L2_STEP_INGRESS_IPV4_ACL_DEL: {
            hal_flow_presence_snapshot snapshot =
                hal_ingress_ipv4_acl_snapshot(
                    sw, &step->ingress_ipv4_acl);
            return capture_exact_flow_rule_state(
                sw, &snapshot,
                &step->pre_security_table_present,
                &step->pre_ingress_ipv4_acl_present);
        }
        case L2_STEP_ACL_POLICER_SET:
        case L2_STEP_ACL_POLICER_DEL: {
            hal_acl_owner_transaction_query query =
                step->type == L2_STEP_ACL_POLICER_SET ?
                HAL_ACL_OWNER_QUERY_SET_SEMANTIC :
                HAL_ACL_OWNER_QUERY_DELETE_EXACT;

            step->pre_acl_policer =
                hal_acl_policer_owner_transaction_snapshot_get(
                    sw, &step->acl_policer, query);
            return step->pre_acl_policer.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        }
        case L2_STEP_EGRESS_ACL_SET:
        case L2_STEP_EGRESS_ACL_DEL: {
            hal_acl_owner_transaction_query query =
                step->type == L2_STEP_EGRESS_ACL_SET ?
                HAL_ACL_OWNER_QUERY_SET_SEMANTIC :
                HAL_ACL_OWNER_QUERY_DELETE_EXACT;

            step->pre_egress_acl =
                hal_acl_egress_owner_transaction_snapshot_get(
                    sw, &step->egress_acl, query);
            return step->pre_egress_acl.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        }
        case L2_STEP_ACL_INDEPENDENT_SET:
        case L2_STEP_ACL_INDEPENDENT_DEL: {
            hal_acl_owner_transaction_query query =
                step->type == L2_STEP_ACL_INDEPENDENT_SET ?
                HAL_ACL_OWNER_QUERY_SET_SEMANTIC :
                HAL_ACL_OWNER_QUERY_DELETE_EXACT;

            step->pre_acl_independent =
                hal_acl_independent_transaction_snapshot_get(
                    sw, &step->acl_independent, query);
            return step->pre_acl_independent.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        }
        case L2_STEP_COPP_CLASS_SET:
            step->pre_copp =
                hal_control_plane_copp_transaction_snapshot(
                    sw, step->copp_class);
            return step->pre_copp.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        case L2_STEP_STORM_CONTROL_SET:
        case L2_STEP_STORM_CONTROL_DEL:
            if (step->port <= 0)
                return -1;
            step->pre_storm =
                hal_storm_control_transaction_snapshot_kind(
                    sw, step->port, step->storm_kind);
            return step->pre_storm.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            if (step->port <= 0)
                return -1;
            step->pre_ingress_rate_limit =
                hal_ingress_rate_limit_transaction_snapshot(
                    sw, step->port);
            return step->pre_ingress_rate_limit.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            if (step->port <= 0)
                return -1;
            step->pre_egress_rate_limit =
                hal_egress_rate_limit_transaction_snapshot(
                    sw, step->port);
            return step->pre_egress_rate_limit.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        case L2_STEP_QOS_INTERFACE_SET:
        case L2_STEP_QOS_INTERFACE_DEL: {
            int state = resolve_target_port_state(sw, step);
            if (state == HW_CAPTURE_ERROR) return -1;
            if (state == HW_CAPTURE_ABSENT) {
                step->pre_qos_interface = (hal_qos_interface_transaction_snapshot){
                    .state = HAL_TRANSACTION_SNAPSHOT_ABSENT};
                return 0;
            }
            step->pre_qos_interface = valid_ae_id(step->ae_id) ?
                hal_lag_qos_snapshot(sw, step->lag_id) :
                hal_qos_interface_transaction_snapshot_get(sw, step->port);
            return step->pre_qos_interface.state ==
                HAL_TRANSACTION_SNAPSHOT_PRESENT ? 0 : -1;
        }
        case L2_STEP_QOS_TC_SMP_SET:
            if (hal_qos_tc_smp_get(sw, step->qos_traffic_class, &step->pre_qos_smp)) return -1;
            step->pre_qos_smp_valid = true;
            return 0;
        case L2_STEP_QOS_DSCP_SET:
            if (hal_qos_dscp_get(sw, step->qos_dscp, &step->pre_qos_dscp_priority)) return -1;
            step->pre_qos_dscp_valid = true;
            return 0;
        case L2_STEP_QOS_PFC_SET:
        case L2_STEP_QOS_PFC_DEL: {
            hal_qos_flow_control_entry entry;
            if (step->port <= 0)
                return -1;
            if (hal_qos_flow_control_get(sw, step->port, &entry) != 0 ||
                entry.rx_class_pause_mask < 0 ||
                entry.tx_pause_mode < 0 ||
                entry.tx_class_pause_mask < 0 ||
                entry.smp_lossless_pause_mask < 0 ||
                entry.shared_pause_enable_mask < 0 ||
                entry.pc3_smp < 0 || entry.pc3_smp > 2)
                return -1;
            step->pre_qos_pfc_valid = true;
            step->pre_qos_pfc_rx_class_mask =
                entry.rx_class_pause_mask;
            step->pre_qos_pfc_tx_pause_mode = entry.tx_pause_mode;
            step->pre_qos_pfc_tx_class_mask =
                entry.tx_class_pause_mask;
            step->pre_qos_pfc_lossless_smp_mask =
                entry.smp_lossless_pause_mask;
            step->pre_qos_pfc_shared_pause_mask =
                entry.shared_pause_enable_mask;
            step->pre_qos_pfc_pc3_smp = entry.pc3_smp;
            if (entry.watchdog.saved_rx_mask >= 0) return -1;
            step->pre_qos_pfc_watchdog = entry.watchdog.policy;
            return 0;
        }
        case L2_STEP_QOS_PRIORITY_MAP_SET:
        case L2_STEP_QOS_PRIORITY_MAP_DEL: {
            hal_qos_priority_map_entry entry;
            if (step->qos_switch_priority < 0)
                return -1;
            if (hal_qos_priority_map_get(
                    sw, step->qos_switch_priority, &entry) != 0)
                return -1;
            step->pre_qos_priority_map_valid = true;
            step->pre_qos_traffic_class = entry.traffic_class;
            return 0;
        }
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL: {
            int group = 0;
            if (step->port <= 0 || step->qos_scheduler_traffic_class < 0)
                return -1;
            if (hal_qos_scheduler_tc_map_get(
                    sw, step->port, step->qos_scheduler_traffic_class,
                    &group) != 0)
                return -1;
            step->pre_qos_scheduler_tc_map_valid = true;
            step->pre_qos_scheduler_shaping_group = group;
            return 0;
        }
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            if (step->port <= 0 || step->qos_scheduler_group < 0)
                return -1;
            step->pre_qos_scheduler_topology =
                hal_qos_scheduler_topology_transaction_snapshot_get(
                    sw, step->port);
            return step->pre_qos_scheduler_topology.state ==
                       HAL_TRANSACTION_SNAPSHOT_PRESENT &&
                   (u32)step->qos_scheduler_group <
                       step->pre_qos_scheduler_topology.num_groups ?
                   0 : -1;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            if (step->port <= 0 || step->qos_scheduler_group < 0)
                return -1;
            step->pre_qos_scheduler_group_shaping =
                hal_qos_scheduler_group_shaping_transaction_snapshot_get(
                    sw, step->port, step->qos_scheduler_group);
            return step->pre_qos_scheduler_group_shaping.state ==
                HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? -1 : 0;
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
        case L2_STEP_QOS_SCHEDULER_PORT_DEL: {
            int mask = 0xff;
            if (step->port <= 0)
                return -1;
            if (hal_qos_scheduler_port_get(
                    sw, step->port, &mask) != 0)
                return -1;
            step->pre_qos_scheduler_port_valid = true;
            step->pre_qos_scheduler_traffic_class_enable_mask = mask;
            return 0;
        }
        case L2_STEP_QOS_WATERMARK_SET:
        case L2_STEP_QOS_WATERMARK_DEL: {
            bool switch_attr =
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
            if ((!switch_attr && step->port <= 0) ||
                step->qos_watermark_index < 0)
                return -1;
            step->pre_qos_watermark =
                hal_qos_watermark_transaction_snapshot_get(
                    sw, step->port, step->qos_watermark_attr,
                    step->qos_watermark_index);
            if (step->pre_qos_watermark.state !=
                HAL_TRANSACTION_SNAPSHOT_PRESENT)
                return -1;
            if (step->type == L2_STEP_QOS_WATERMARK_DEL &&
                apply_capture) {
                if (step->qos_watermark_reconcile) {
                    memset(&step->qos_watermark_delete_target, 0,
                           sizeof(step->qos_watermark_delete_target));
                    step->qos_watermark_delete_target.state =
                        HAL_TRANSACTION_SNAPSHOT_PRESENT;
                    step->qos_watermark_delete_target.sdk_status = FM_OK;
                    step->qos_watermark_delete_target.value =
                        step->pre_qos_watermark.value;
                    step->qos_watermark_delete_target.owner_baseline =
                        -1;
                    step->qos_watermark_delete_target.owner_value = -1;
                } else {
                    step->qos_watermark_delete_target =
                        hal_qos_watermark_delete_target_get(
                            sw, step->port,
                            step->qos_watermark_attr,
                            step->qos_watermark_index);
                }
                if (step->qos_watermark_delete_target.state !=
                    HAL_TRANSACTION_SNAPSHOT_PRESENT)
                    return -1;
            }
            return 0;
        }
        case L2_STEP_MIRROR_SESSION_SET:
        case L2_STEP_MIRROR_SESSION_DEL:
            return hal_mirror_state_get(sw, step->mirror.group,
                                        &step->pre_mirror);
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL: {
            int present = hal_l2_mcast_listener_present(
                sw, step->vid, step->mac, step->port);
            if (present < 0)
                return -1;
            step->pre_igmp_listener_present = present != 0;
            return 0;
        }
        default:
            return -1;
    }
}

static void clear_step_pre_state(l2_apply_step *step) {
    l2_apply_step_pre_state_reset(step);
}

static void clear_security_table_creation_token(l2_apply_step *step) {
    if (!step)
        return;
    memset(&step->security_table_creation_token, 0,
           sizeof(step->security_table_creation_token));
    step->security_table_creation_token.sw = -1;
    step->security_table_creation_token.table = -1;
}

static int security_set_result_with_creation_token(
    l2_apply_step *step, int apply_status) {
    hal_flow_table_creation_token token;
    int take_status;

    if (!step)
        return NL_ERR_SDK_CALL_FAILED;
    memset(&token, 0, sizeof(token));
    token.sw = -1;
    token.table = -1;
    take_status = hal_l2_security_take_created_table_token(&token);
    if (take_status < 0) {
        NL_LOG_CRIT(
            "security table creation-token transfer failed type=%d",
            step->type);
        return NL_ERR_SDK_CALL_FAILED;
    }
    if (take_status > 0) {
        if (!token.valid ||
            step->security_table_creation_token.valid) {
            NL_LOG_CRIT(
                "security table creation-token ownership conflict "
                "type=%d",
                step->type);
            return NL_ERR_SDK_CALL_FAILED;
        }
        step->security_table_creation_token = token;
    }
    return apply_status;
}

static int release_security_table_created_by_step(l2_apply_step *step) {
    if (!step || !step->security_table_creation_token.valid)
        return 0;
    if (hal_l2_security_release_created_table_empty(
            &step->security_table_creation_token) != 0) {
        NL_LOG_CRIT(
            "security table rollback release failed type=%d "
            "table=%d generation=%llu",
            step->type,
            step->security_table_creation_token.table,
            (unsigned long long)
                step->security_table_creation_token.generation);
        return -1;
    }
    clear_security_table_creation_token(step);
    return 0;
}

static bool storm_transaction_state_equal(
    const hal_storm_rate_transaction_snapshot *left,
    const hal_storm_rate_transaction_snapshot *right) {
    if (!left || !right ||
        left->state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
        right->state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
        left->state != right->state)
        return false;
    /*
     * controller is an allocator-owned handle.  The semantic before-image is
     * absence or the owned per-port rate/capacity pair.
     */
    return left->state == HAL_TRANSACTION_SNAPSHOT_ABSENT ||
        (left->rate_kbps == right->rate_kbps &&
         left->capacity_bytes == right->capacity_bytes);
}

static bool qos_interface_transaction_state_equal(
    const hal_qos_interface_transaction_snapshot *left,
    const hal_qos_interface_transaction_snapshot *right) {
    if (!left || !right || left->state != right->state) return false;
    if (left->state == HAL_TRANSACTION_SNAPSHOT_ABSENT) return true;
    return left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT && left->source == right->source &&
        left->dscp_preference == right->dscp_preference &&
        left->default_priority == right->default_priority &&
        left->default_switch_priority ==
            right->default_switch_priority;
}

static bool qos_scheduler_transaction_state_equal(
    const hal_qos_scheduler_topology_transaction_snapshot *left,
    const hal_qos_scheduler_topology_transaction_snapshot *right) {
    return left && right &&
        left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        left->num_groups == right->num_groups &&
        left->num_groups <=
            HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS &&
        memcmp(left->groups, right->groups,
               (size_t)left->num_groups *
               sizeof(left->groups[0])) == 0;
}

static bool qos_scheduler_group_shaping_transaction_state_equal(
    const hal_qos_scheduler_group_shaping_transaction_snapshot *left,
    const hal_qos_scheduler_group_shaping_transaction_snapshot *right) {
    return left && right &&
        left->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
        right->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
        left->state == right->state &&
        left->raw_rate_bps == right->raw_rate_bps &&
        left->raw_burst_bits == right->raw_burst_bits;
}

static bool egress_rate_transaction_state_equal(
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

static bool copp_policer_transaction_state_equal(
    const hal_copp_policer_transaction_snapshot *left,
    const hal_copp_policer_transaction_snapshot *right) {
    return left && right &&
        left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        left->acl == right->acl &&
        left->acl_scenarios == right->acl_scenarios &&
        left->acl_precedence == right->acl_precedence &&
        left->rule_count == right->rule_count &&
        left->rule_count >= 0 &&
        left->rule_count <= HAL_COPP_TRANSACTION_MAX_RULES &&
        memcmp(left->rules, right->rules,
               sizeof(left->rules)) == 0 &&
        left->policer == right->policer &&
        left->color_source == right->color_source &&
        left->cir_action == right->cir_action &&
        left->cir_capacity == right->cir_capacity &&
        left->cir_rate == right->cir_rate;
}

static bool acl_policer_transaction_state_equal(
    const hal_acl_policer_owner_transaction_snapshot *left,
    const hal_acl_policer_owner_transaction_snapshot *right) {
    return left && right &&
        left->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
        left->state == right->state &&
        left->sdk_status == right->sdk_status &&
        left->slot == right->slot &&
        left->shared_acl_present == right->shared_acl_present &&
        !left->shared_acl_creation.valid &&
        !right->shared_acl_creation.valid &&
        left->before.port == right->before.port &&
        left->before.dst_mac == right->before.dst_mac &&
        left->before.rate_kbps == right->before.rate_kbps &&
        left->before.burst_bytes == right->before.burst_bytes;
}

static bool acl_egress_transaction_state_equal(
    const hal_acl_egress_owner_transaction_snapshot *left,
    const hal_acl_egress_owner_transaction_snapshot *right) {
    return left && right &&
        left->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
        left->state == right->state &&
        left->sdk_status == right->sdk_status &&
        left->slot == right->slot &&
        left->acl_present == right->acl_present &&
        left->before.port == right->before.port &&
        left->before.src_mac == right->before.src_mac &&
        left->before.dst_mac == right->before.dst_mac;
}

static bool acl_independent_transaction_state_equal(
    const hal_acl_independent_transaction_snapshot *left,
    const hal_acl_independent_transaction_snapshot *right) {
    return left && right &&
        left->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
        left->state == right->state &&
        left->sdk_status == right->sdk_status &&
        left->slot == right->slot &&
        left->shared_acl_present == right->shared_acl_present &&
        !left->shared_acl_creation.valid &&
        !right->shared_acl_creation.valid &&
        memcmp(&left->before, &right->before,
               sizeof(left->before)) == 0;
}

static bool step_pre_state_equal(const l2_apply_step *expected,
                                 const l2_apply_step *actual) {
#define PRE_EQ(field) (expected->field == actual->field)
#define PRE_OPTIONAL_EQ(valid, field) \
    (PRE_EQ(valid) && (!expected->valid || PRE_EQ(field)))
#define PRE_OPTIONAL2_EQ(valid, field1, field2) \
    (PRE_EQ(valid) && (!expected->valid || \
     (PRE_EQ(field1) && PRE_EQ(field2))))

    if (!expected || !actual || expected->type != actual->type)
        return false;
    switch (expected->type) {
        case L2_STEP_FM10K_GROUP_SET:
            return expected->pre_fm10k_group_valid && actual->pre_fm10k_group_valid &&
                nl_fm10k_group_equal(&expected->pre_fm10k_group, &actual->pre_fm10k_group);
        case L2_STEP_FM10K_FAN_SET:
            return fm10k_fan_snapshot_equal(&expected->pre_fm10k_fan, &actual->pre_fm10k_fan);
        case L2_STEP_VLAN_CREATE:
            return PRE_EQ(pre_vlan_existed);
        case L2_STEP_VLAN_DELETE:
            return PRE_EQ(pre_vlan_existed) &&
                pre_static_mac_sets_equal(
                    expected->pre_static_macs,
                    expected->pre_static_mac_count,
                    actual->pre_static_macs,
                    actual->pre_static_mac_count) &&
                pre_vlan_member_sets_equal(
                    expected->pre_vlan_members,
                    expected->pre_vlan_member_count,
                    actual->pre_vlan_members,
                    actual->pre_vlan_member_count);
        case L2_STEP_VLAN_ADD_PORT:
        case L2_STEP_VLAN_REM_PORT:
            return PRE_EQ(pre_member_existed) &&
                (!expected->pre_member_existed ||
                 (PRE_EQ(pre_member_tagged) &&
                  PRE_OPTIONAL_EQ(
                      pre_member_stp_valid,
                      pre_member_stp_state))) &&
                pre_static_mac_sets_equal(
                    expected->pre_static_macs,
                    expected->pre_static_mac_count,
                    actual->pre_static_macs,
                    actual->pre_static_mac_count);
        case L2_STEP_PVID_SET:
            return PRE_OPTIONAL_EQ(pre_pvid_valid, pre_pvid);
        case L2_STEP_VLAN_STP_SET:
            return PRE_OPTIONAL_EQ(pre_stp_valid, pre_stp_state);
        case L2_STEP_PORT_SET_ADMIN:
            return hal_port_admin_transaction_snapshot_equal(
                &expected->pre_admin, &actual->pre_admin);
        case L2_STEP_PORT_SET_MTU:
            return PRE_OPTIONAL_EQ(pre_mtu_valid, pre_mtu);
        case L2_STEP_PORT_SET_SPEED:
            return PRE_OPTIONAL2_EQ(
                pre_speed_valid, pre_speed, pre_ethernet_mode) &&
                hal_port_admin_transaction_snapshot_equal(
                    &expected->pre_admin, &actual->pre_admin);
        case L2_STEP_PORT_PARSER_SET:
            return PRE_OPTIONAL_EQ(pre_parser_valid, pre_parser_mode);
        case L2_STEP_PORT_INGRESS_FILTER_SET:
            return PRE_OPTIONAL_EQ(pre_ingress_filter_valid, pre_ingress_filter);
        case L2_STEP_MAC_AGING_SET:
            return PRE_OPTIONAL_EQ(pre_aging_valid, pre_aging_time);
        case L2_STEP_STATIC_MAC_ADD:
        case L2_STEP_STATIC_MAC_DEL:
            return PRE_EQ(pre_mac_valid) &&
                (!expected->pre_mac_valid ||
                 (PRE_EQ(pre_mac_static) &&
                  PRE_EQ(pre_mac_type) &&
                  PRE_EQ(pre_mac_ae_id) &&
                  (expected->pre_mac_ae_id >= 0 ||
                   PRE_EQ(pre_mac_port))));
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL:
            return PRE_EQ(pre_igmp_listener_present);
        case L2_STEP_LAG_CREATE:
            return PRE_EQ(pre_lag_existed);
        case L2_STEP_LAG_DELETE:
            return PRE_EQ(pre_lag_existed) &&
                expected->pre_lag_attributes.valid == actual->pre_lag_attributes.valid &&
                (!expected->pre_lag_attributes.valid ||
                 !memcmp(expected->pre_lag_attributes.values, actual->pre_lag_attributes.values,
                         sizeof(expected->pre_lag_attributes.values))) &&
                PRE_OPTIONAL_EQ(
                    pre_lag_hash_rotation_valid,
                    pre_lag_hash_rotation) &&
                PRE_OPTIONAL_EQ(
                    pre_lag_lacp_disposition_valid,
                    pre_lag_lacp_disposition) &&
                PRE_EQ(pre_lag_member_count) &&
                (expected->pre_lag_member_count == 0 ||
                 memcmp(expected->pre_lag_members,
                        actual->pre_lag_members,
                        (size_t)expected->pre_lag_member_count *
                        sizeof(expected->pre_lag_members[0])) == 0);
        case L2_STEP_LAG_ADD_PORT:
        case L2_STEP_LAG_DEL_PORT:
            return PRE_EQ(pre_lag_existed) &&
                PRE_EQ(pre_lag_member_existed);
        case L2_STEP_LAG_HASH_ROTATION_SET:
            return PRE_EQ(pre_lag_existed) &&
                PRE_OPTIONAL_EQ(
                    pre_lag_hash_rotation_valid,
                    pre_lag_hash_rotation);
        case L2_STEP_DHCP_SNOOPING_SET:
        case L2_STEP_DHCP_SNOOPING_DEL:
        case L2_STEP_ARP_INSPECTION_SET:
        case L2_STEP_ARP_INSPECTION_DEL:
        case L2_STEP_ARP_INSPECTION_BINDING_SET:
        case L2_STEP_ARP_INSPECTION_BINDING_DEL:
        case L2_STEP_USER_FILTER_SET:
        case L2_STEP_USER_FILTER_DEL:
            return PRE_EQ(pre_security_table_present) &&
                PRE_EQ(pre_security_present);
        case L2_STEP_INGRESS_IPV4_ACL_SET:
        case L2_STEP_INGRESS_IPV4_ACL_DEL:
            return PRE_EQ(pre_security_table_present) &&
                PRE_EQ(pre_ingress_ipv4_acl_present);
        case L2_STEP_ACL_POLICER_SET:
        case L2_STEP_ACL_POLICER_DEL:
            return acl_policer_transaction_state_equal(
                &expected->pre_acl_policer,
                &actual->pre_acl_policer);
        case L2_STEP_EGRESS_ACL_SET:
        case L2_STEP_EGRESS_ACL_DEL:
            return acl_egress_transaction_state_equal(
                &expected->pre_egress_acl,
                &actual->pre_egress_acl);
        case L2_STEP_ACL_INDEPENDENT_SET:
        case L2_STEP_ACL_INDEPENDENT_DEL:
            return acl_independent_transaction_state_equal(
                &expected->pre_acl_independent,
                &actual->pre_acl_independent);
        case L2_STEP_COPP_CLASS_SET:
            return copp_policer_transaction_state_equal(
                &expected->pre_copp, &actual->pre_copp);
        case L2_STEP_STORM_CONTROL_SET:
        case L2_STEP_STORM_CONTROL_DEL:
            return storm_transaction_state_equal(
                &expected->pre_storm, &actual->pre_storm);
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            return storm_transaction_state_equal(
                &expected->pre_ingress_rate_limit,
                &actual->pre_ingress_rate_limit);
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            return egress_rate_transaction_state_equal(
                &expected->pre_egress_rate_limit,
                &actual->pre_egress_rate_limit);
        case L2_STEP_QOS_INTERFACE_SET:
        case L2_STEP_QOS_INTERFACE_DEL:
            return qos_interface_transaction_state_equal(
                &expected->pre_qos_interface,
                &actual->pre_qos_interface);
        case L2_STEP_QOS_TC_SMP_SET:
            return PRE_OPTIONAL_EQ(pre_qos_smp_valid, pre_qos_smp);
        case L2_STEP_QOS_DSCP_SET:
            return PRE_OPTIONAL_EQ(pre_qos_dscp_valid, pre_qos_dscp_priority);
        case L2_STEP_QOS_PFC_SET:
        case L2_STEP_QOS_PFC_DEL:
            return PRE_EQ(pre_qos_pfc_valid) &&
                (!expected->pre_qos_pfc_valid ||
                 (PRE_EQ(pre_qos_pfc_rx_class_mask) &&
                  PRE_EQ(pre_qos_pfc_tx_pause_mode) &&
                  PRE_EQ(pre_qos_pfc_tx_class_mask) &&
                  PRE_EQ(pre_qos_pfc_lossless_smp_mask) &&
                  PRE_EQ(pre_qos_pfc_shared_pause_mask) &&
                  PRE_EQ(pre_qos_pfc_pc3_smp) &&
                  fm10k_pfc_wd_policy_equal(&expected->pre_qos_pfc_watchdog, &actual->pre_qos_pfc_watchdog)));
        case L2_STEP_QOS_PRIORITY_MAP_SET:
        case L2_STEP_QOS_PRIORITY_MAP_DEL:
            return PRE_OPTIONAL_EQ(
                pre_qos_priority_map_valid,
                pre_qos_traffic_class);
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
            return PRE_OPTIONAL_EQ(
                pre_qos_scheduler_tc_map_valid,
                pre_qos_scheduler_shaping_group);
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            return qos_scheduler_transaction_state_equal(
                &expected->pre_qos_scheduler_topology,
                &actual->pre_qos_scheduler_topology);
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            return qos_scheduler_group_shaping_transaction_state_equal(
                &expected->pre_qos_scheduler_group_shaping,
                &actual->pre_qos_scheduler_group_shaping);
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
            return PRE_OPTIONAL_EQ(
                pre_qos_scheduler_port_valid,
                pre_qos_scheduler_traffic_class_enable_mask);
        case L2_STEP_QOS_WATERMARK_SET:
        case L2_STEP_QOS_WATERMARK_DEL:
            return hal_qos_watermark_transaction_snapshot_equal(
                &expected->pre_qos_watermark,
                &actual->pre_qos_watermark);
        case L2_STEP_MIRROR_SESSION_SET:
        case L2_STEP_MIRROR_SESSION_DEL:
            return hal_mirror_state_equal(
                &expected->pre_mirror, &actual->pre_mirror);
        default:
            return false;
    }

#undef PRE_OPTIONAL2_EQ
#undef PRE_OPTIONAL_EQ
#undef PRE_EQ
}

static bool qos_auto_pause_trigger_step(l2_step_type type) {
    return type == L2_STEP_PORT_SET_MTU ||
           type == L2_STEP_PORT_SET_SPEED ||
           type == L2_STEP_FM10K_GROUP_SET ||
           type == L2_STEP_QOS_TC_SMP_SET ||
           type == L2_STEP_QOS_PFC_SET ||
           type == L2_STEP_QOS_PFC_DEL ||
           type == L2_STEP_QOS_PRIORITY_MAP_SET ||
           type == L2_STEP_QOS_PRIORITY_MAP_DEL;
}

static int capture_original_plan(int sw, l2_apply_plan *plan) {
    if (!plan || plan->n_steps <= 0 ||
        plan->n_steps > L2_PLAN_MAX_STEPS ||
        plan->n_steps > plan->step_capacity || !plan->steps ||
        l2_apply_plan_allocate_original(plan, plan->n_steps) != 0)
        return -1;

    plan->qos_auto_pause_watermark_snapshot_required = false;
    memset(&plan->pre_qos_auto_pause_watermark, 0,
           sizeof(plan->pre_qos_auto_pause_watermark));
    for (int i = 0; i < plan->n_steps; i++) {
        if (qos_auto_pause_trigger_step(plan->steps[i].type)) {
            plan->qos_auto_pause_watermark_snapshot_required = true;
            break;
        }
    }
    if (plan->qos_auto_pause_watermark_snapshot_required) {
        plan->pre_qos_auto_pause_watermark =
            hal_qos_auto_pause_watermark_transaction_snapshot_get(sw);
        if (plan->pre_qos_auto_pause_watermark.state !=
            HAL_TRANSACTION_SNAPSHOT_PRESENT) {
            NL_LOG_ERR(
                "original L2 auto-pause watermark image capture failed "
                "status=%d",
                plan->pre_qos_auto_pause_watermark.sdk_status);
            return -1;
        }
        if (plan->pre_qos_auto_pause_watermark.auto_pause_mode == 0) {
            /*
             * PFC/SWPRI writes do not run SetWatermarks() while auto-pause
             * is disabled.  Keep the common raw image for exact rollback,
             * but do not grant calculator-reconstruction authority to a
             * direct SET/DEL.  Such a DEL must use durable provenance.
             */
            for (int i = 0; i < plan->n_steps; i++)
                if (plan->steps[i].type ==
                        L2_STEP_QOS_WATERMARK_SET ||
                    plan->steps[i].type ==
                        L2_STEP_QOS_WATERMARK_DEL)
                    plan->steps[i].qos_watermark_reconcile = 0;
        }
    }

    plan->original_n_steps = 0;
    for (int i = 0; i < plan->n_steps; i++) {
        l2_apply_plan_checkpoint(plan);
        l2_apply_step *snapshot = &plan->original_steps[i];

        plan->steps[i].fm10k_tx_id = plan->tx_id;
        clear_security_table_creation_token(&plan->steps[i]);
        *snapshot = plan->steps[i];
        snapshot->pre_static_macs = NULL;
        snapshot->pre_vlan_members = NULL;
        clear_step_pre_state(snapshot);
        if (capture_step_pre_state(sw, snapshot, false) != 0) {
            NL_LOG_ERR(
                "original L2 snapshot failed step=%d type=%d",
                i, snapshot->type);
            plan->original_n_steps = 0;
            return -1;
        }
        if ((snapshot->type == L2_STEP_STATIC_MAC_ADD ||
             snapshot->type == L2_STEP_STATIC_MAC_DEL) &&
            snapshot->pre_mac_valid &&
            snapshot->pre_mac_type != FM_ADDRESS_STATIC) {
            NL_LOG_ERR(
                "static MAC apply would destroy a foreign entry "
                "step=%d vid=%u type=%d",
                i, snapshot->vid, snapshot->pre_mac_type);
            plan->original_n_steps = 0;
            return -1;
        }
        plan->original_n_steps++;
    }
    return 0;
}

static int verify_original_plan(int sw, l2_apply_plan *plan) {
    int mismatches = 0;
    const hal_lag_handle_set_snapshot *lag_before = NULL;
    hal_lag_handle_set_snapshot expected_lags;
    hal_lag_handle_set_snapshot actual_lags;
    bool has_lag_handle_authority = false;

    if (!plan || plan->original_n_steps != plan->n_steps ||
        plan->n_steps <= 0)
        return -1;
    for (int i = 0; i < plan->original_n_steps; i++) {
        l2_apply_plan_checkpoint(plan);
        const l2_apply_step *expected = &plan->original_steps[i];
        l2_apply_step actual = *expected;

        actual.pre_static_macs = NULL;
        actual.pre_vlan_members = NULL;
        clear_step_pre_state(&actual);
        if (capture_step_pre_state(sw, &actual, false) != 0 ||
            !step_pre_state_equal(expected, &actual)) {
            mismatches++;
            NL_LOG_CRIT(
                "L2 rollback read-back mismatch step=%d type=%d "
                "vid=%u port=%d ae=%d",
                i, expected->type, expected->vid,
                expected->port, expected->ae_id);
        }
        clear_step_pre_state(&actual);
    }

    /*
     * Per-AE verification cannot see an orphan created with an unknown SDK
     * output handle, nor a foreign LAG removed by an ambiguous create result.
     * Normalize only allocator-owned replacements from planned LAG deletes,
     * then require the complete global handle set to match the original.
     */
    for (int i = 0; i < plan->original_n_steps; i++) {
        const l2_apply_step *original = &plan->original_steps[i];

        if (original->type != L2_STEP_LAG_CREATE &&
            original->type != L2_STEP_LAG_DELETE)
            continue;
        lag_before = &original->pre_lag_handles;
        has_lag_handle_authority = true;
        break;
    }
    if (has_lag_handle_authority) {
        expected_lags = *lag_before;
        actual_lags = hal_lag_handle_set_snapshot_get(sw);
        for (int i = 0; i < plan->original_n_steps; i++) {
            const l2_apply_step *original =
                &plan->original_steps[i];
            int current_lag;
            int old_index = -1;
            bool current_already_present = false;

            if (original->type != L2_STEP_LAG_DELETE ||
                !original->pre_lag_existed)
                continue;
            current_lag = valid_ae_id(original->ae_id) ?
                g_ae_lag_id[original->ae_id] :
                (plan->steps[i].restored_lag_id > 0 ?
                 plan->steps[i].restored_lag_id :
                 plan->steps[i].lag_id);
            if (current_lag <= 0) {
                mismatches++;
                break;
            }
            for (int j = 0; j < expected_lags.count; j++) {
                if (expected_lags.lag_ids[j] ==
                    original->pre_lag_id)
                    old_index = j;
                if (expected_lags.lag_ids[j] == current_lag)
                    current_already_present = true;
            }
            if (old_index < 0) {
                if (!current_already_present) {
                    mismatches++;
                    break;
                }
                continue;
            }
            if (current_lag != original->pre_lag_id &&
                current_already_present) {
                mismatches++;
                break;
            }
            expected_lags.lag_ids[old_index] = current_lag;
        }
        if (!hal_lag_handle_set_snapshot_equal(
                &expected_lags, &actual_lags)) {
            mismatches++;
            NL_LOG_CRIT(
                "L2 rollback global LAG handle-set mismatch "
                "expected-state=%d expected=%d actual-state=%d "
                "actual=%d sdk=%d",
                (int)expected_lags.state, expected_lags.count,
                (int)actual_lags.state, actual_lags.count,
                actual_lags.sdk_status);
        }
    }

    if (plan->qos_auto_pause_watermark_snapshot_required) {
        hal_qos_auto_pause_watermark_transaction_snapshot readback =
            hal_qos_auto_pause_watermark_transaction_snapshot_get(sw);

        if (!hal_qos_auto_pause_watermark_transaction_snapshot_equal(
                &plan->pre_qos_auto_pause_watermark, &readback)) {
            mismatches++;
            NL_LOG_CRIT(
                "L2 rollback auto-pause watermark image mismatch "
                "status=%d",
                readback.sdk_status);
        }
    }
    return mismatches == 0 ? 0 : -1;
}

static int apply_one_step(int sw, l2_apply_step *step) {
    switch (step->type) {
        case L2_STEP_VLAN_CREATE: {
            fm_status st = fmCreateVlan((fm_int)sw, step->vid);
            if (st == FM_ERR_VLAN_ALREADY_EXISTS) st = FM_OK;
            if (st != FM_OK) NL_LOG_ERR("vlan-create vid=%d: %s", step->vid, fmErrorMsg(st));
            return (int)st;
        }
        case L2_STEP_VLAN_DELETE: {
            if (!step->pre_vlan_existed)
                return 0;
            if (step->pre_static_mac_count != 0 ||
                step->pre_vlan_member_count != 0) {
                NL_LOG_ERR(
                    "vlan-delete vid=%d has unplanned dependents "
                    "static-macs=%d members=%d",
                    step->vid, step->pre_static_mac_count,
                    step->pre_vlan_member_count);
                return NL_ERR_PRE_STATE_MISSING;
            }
            fm_status st = fmDeleteVlan((fm_int)sw, step->vid);
            if (st != FM_OK) NL_LOG_ERR("vlan-delete vid=%d: %s", step->vid, fmErrorMsg(st));
            return (int)st;
        }
        case L2_STEP_VLAN_ADD_PORT: {
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            fm_status st = fmAddVlanPort((fm_int)sw, step->vid, step->port,
                                          step->tagged ? TRUE : FALSE);
            if (st == FM_ERR_VLAN_ALREADY_EXISTS) st = FM_OK;
            if (st != FM_OK) NL_LOG_ERR("vlan-add-port vid=%d port=%d: %s",
                                         step->vid, step->port, fmErrorMsg(st));
            return (int)st;
        }
        case L2_STEP_VLAN_REM_PORT: {
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            if (!step->pre_member_existed)
                return 0;
            fm_status st = fmDeleteVlanPort((fm_int)sw, step->vid, step->port);
            if (st != FM_OK) NL_LOG_ERR("vlan-rem-port vid=%d port=%d: %s",
                                         step->vid, step->port, fmErrorMsg(st));
            if (st == FM_OK &&
                restore_vlan_static_macs(sw, step->vid, step) != 0) {
                NL_LOG_ERR(
                    "vlan-rem-port vid=%d port=%d static-MAC "
                    "preservation failed",
                    step->vid, step->port);
                return NL_ERR_SDK_CALL_FAILED;
            }
            return (int)st;
        }
        case L2_STEP_PVID_SET: {
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            fm_uint32 pv = (fm_uint32)step->vid;
            fm_status st = fmSetPortAttribute((fm_int)sw, step->port, FM_PORT_DEF_VLAN, &pv);
            if (st != FM_OK) NL_LOG_ERR("pvid-set port=%d vid=%d: %s",
                                         step->port, step->vid, fmErrorMsg(st));
            return (int)st;
        }
        case L2_STEP_VLAN_STP_SET: {
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            fm_status st = fmSetVlanPortState((fm_int)sw, step->vid, step->port, step->stp_state);
            if (st != FM_OK) NL_LOG_ERR("stp-set vid=%d port=%d state=%d: %s",
                                         step->vid, step->port, step->stp_state, fmErrorMsg(st));
            return (int)st;
        }
        case L2_STEP_PORT_SET_ADMIN:
            return hal_port_admin_transaction_apply(
                sw, step->port, step->admin_mode,
                &step->pre_admin);
        case L2_STEP_FM10K_GROUP_SET:
            if (!step->pre_fm10k_group_valid) return NL_ERR_PRE_STATE_MISSING;
            return hal_fm10k_group_apply(sw, &step->fm10k_group, &step->pre_fm10k_group, step->fm10k_tx_id);
        case L2_STEP_FM10K_FAN_SET:
            return hal_fm10k_fan_apply(sw, &step->fm10k_fan, &step->pre_fm10k_fan);
        case L2_STEP_PORT_SET_MTU:
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            return hal_port_set_mtu(sw, step->port, step->mtu);
        case L2_STEP_PORT_SET_SPEED:
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            return hal_port_set_speed(sw, step->port, step->speed);
        case L2_STEP_PORT_INGRESS_FILTER_SET: {
            if (resolve_target_port(sw, step) <= 0) return -1;
            fm_bool enabled = step->ingress_filtering ? TRUE : FALSE;
            return (int)fmSetPortAttribute(sw, step->port, FM_PORT_DROP_BV, &enabled);
        }
        case L2_STEP_PORT_PARSER_SET: {
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            fm_int mode = step->parser_mode;
            fm_status st = fmSetPortAttribute((fm_int)sw, step->port, FM_PORT_PARSER, &mode);
            if (st != FM_OK) NL_LOG_ERR("port-parser-set port=%d mode=%d: %s",
                                         step->port, step->parser_mode, fmErrorMsg(st));
            return (int)st;
        }
        case L2_STEP_MAC_AGING_SET:
            return hal_mac_aging_set(sw, step->aging_time);
        case L2_STEP_STATIC_MAC_ADD:
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            return hal_static_mac_add(sw, step->vid, step->mac, step->port);
        case L2_STEP_STATIC_MAC_DEL:
            if (!step->pre_mac_valid || !step->pre_mac_static)
                return 0;
            return hal_static_mac_delete(sw, step->vid, step->mac);
        case L2_STEP_IGMP_LISTENER_SET:
            return hal_l2_mcast_listener_set(sw, step->vid, step->mac,
                                              step->port);
        case L2_STEP_IGMP_LISTENER_DEL:
            return hal_l2_mcast_listener_delete(sw, step->vid, step->mac,
                                                 step->port);
        case L2_STEP_LAG_CREATE: {
            int lag = resolve_lag_id(sw, step);
            bool created = false;
            int sdk_status = (int)FM_OK;
            int create_status;

            if (lag > 0)
                return 0;
            if (lag < 0)
                return NL_ERR_HW_STATE_OUT_OF_SYNC;

            create_status = hal_lag_create_classified(
                sw, &step->pre_lag_handles,
                &lag, &created, &sdk_status);
            if (created) {
                step->lag_id = lag;
                remember_ae_lag(step->ae_id, step->lag_id);
            }
            if (create_status != 0) {
                NL_LOG_ERR(
                    "lag-create ae=%d classified-status=%d sdk=%d "
                    "created=%d hw-lag=%d",
                    step->ae_id, create_status, sdk_status,
                    created ? 1 : 0, lag);
                return create_status;
            }
            if (!created || lag <= 0)
                return NL_ERR_HW_STATE_OUT_OF_SYNC;
            if (lag_lacp_to_cpu(sw, lag) != 0)
                return -1;
            NL_LOG_INFO("lag-create ae=%d hw-lag=%d", step->ae_id, step->lag_id);
            return 0;
        }
        case L2_STEP_LAG_DELETE: {
            int lag = resolve_lag_id(sw, step);
            int vlan_memberships;

            if (lag <= 0)
                return 0;
            vlan_memberships = lag_vlan_membership_count(sw, lag);
            if (step->pre_lag_member_count != 0 ||
                vlan_memberships != 0) {
                NL_LOG_ERR(
                    "lag-delete ae=%d hw-lag=%d has %d "
                    "unplanned members and %d VLAN memberships",
                    step->ae_id, lag,
                    step->pre_lag_member_count,
                    vlan_memberships);
                return NL_ERR_PRE_STATE_MISSING;
            }
            int st = hal_lag_delete(sw, lag);
            if (st != 0) {
                NL_LOG_ERR(
                    "lag-delete ae=%d hw-lag=%d: status=%d",
                    step->ae_id, lag, st);
            } else {
                step->lag_delete_issued = true;
                forget_ae_lag(step->ae_id, lag);
            }
            return st;
        }
        case L2_STEP_LAG_ADD_PORT: {
            int lag = resolve_lag_id(sw, step);
            int member;

            if (lag <= 0)
                return NL_ERR_PRE_STATE_MISSING;
            member = hw_lag_member_state(sw, lag, step->port);
            if (member == HW_CAPTURE_ERROR)
                return NL_ERR_SDK_CALL_FAILED;
            if (member == HW_CAPTURE_PRESENT)
                return 0;
            return hal_lag_add_port(sw, lag, step->port);
        }
        case L2_STEP_LAG_DEL_PORT: {
            int lag = resolve_lag_id(sw, step);
            int member;

            if (lag <= 0)
                return 0;
            member = hw_lag_member_state(sw, lag, step->port);
            if (member == HW_CAPTURE_ERROR)
                return NL_ERR_SDK_CALL_FAILED;
            if (member == HW_CAPTURE_ABSENT)
                return 0;
            return hal_lag_del_port_transaction(sw, lag, step->port, step->fm10k_tx_id);
        }
        case L2_STEP_LAG_HASH_ROTATION_SET: {
            int lag = resolve_lag_id(sw, step);
            if (lag <= 0) {
                NL_LOG_ERR("lag-hash-rotation-set ae=%d: no hardware LAG",
                           step->ae_id);
                return -1;
            }
            return hal_lag_set_hash_rotation(sw, lag,
                                             step->lag_hash_rotation);
        }
        case L2_STEP_DHCP_SNOOPING_SET: {
            int status = hal_l2_security_dhcp_snooping_set(
                sw, (u16)step->security_vid, step->security_port);
            return security_set_result_with_creation_token(step, status);
        }
        case L2_STEP_DHCP_SNOOPING_DEL:
            return hal_l2_security_dhcp_snooping_delete(
                sw, (u16)step->security_vid, step->security_port);
        case L2_STEP_ARP_INSPECTION_SET: {
            int status = hal_l2_security_arp_inspection_set(
                sw, (u16)step->security_vid, step->security_port);
            return security_set_result_with_creation_token(step, status);
        }
        case L2_STEP_ARP_INSPECTION_DEL:
            return hal_l2_security_arp_inspection_delete(
                sw, (u16)step->security_vid, step->security_port);
        case L2_STEP_ARP_INSPECTION_BINDING_SET: {
            int status = hal_l2_security_arp_binding_set(
                sw, (u16)step->security_vid, step->security_port,
                step->security_mac, step->security_ip);
            return security_set_result_with_creation_token(step, status);
        }
        case L2_STEP_ARP_INSPECTION_BINDING_DEL:
            return hal_l2_security_arp_binding_delete(
                sw, (u16)step->security_vid, step->security_port,
                step->security_mac, step->security_ip);
        case L2_STEP_USER_FILTER_SET: {
            int status = hal_l2_security_user_filter_set(
                sw, (u16)step->security_vid, step->security_port,
                step->security_mac, step->security_mac_kind);
            return security_set_result_with_creation_token(step, status);
        }
        case L2_STEP_USER_FILTER_DEL:
            return hal_l2_security_user_filter_delete(
                sw, (u16)step->security_vid, step->security_port,
                step->security_mac, step->security_mac_kind);
        case L2_STEP_INGRESS_IPV4_ACL_SET: {
            int status = hal_ingress_ipv4_acl_set(
                sw, &step->ingress_ipv4_acl);
            return security_set_result_with_creation_token(step, status);
        }
        case L2_STEP_INGRESS_IPV4_ACL_DEL:
            return hal_ingress_ipv4_acl_delete(sw, &step->ingress_ipv4_acl);
        case L2_STEP_ACL_POLICER_SET: {
            hal_acl_policer_owner_result result;
            memset(&result, 0, sizeof(result));
            return hal_acl_policer_owner_transaction_apply(
                sw, &step->acl_policer,
                &step->pre_acl_policer, &result);
        }
        case L2_STEP_ACL_POLICER_DEL: {
            hal_acl_policer_owner_result result;
            memset(&result, 0, sizeof(result));
            return hal_acl_policer_owner_rollback_match(
                sw, &step->acl_policer, &result);
        }
        case L2_STEP_EGRESS_ACL_SET: {
            hal_acl_egress_owner_result result;
            memset(&result, 0, sizeof(result));
            return hal_acl_egress_owner_apply(
                sw, &step->egress_acl, &result);
        }
        case L2_STEP_EGRESS_ACL_DEL: {
            hal_acl_egress_owner_result result;
            memset(&result, 0, sizeof(result));
            return hal_acl_egress_owner_rollback_match(
                sw, &step->egress_acl, &result);
        }
        case L2_STEP_ACL_INDEPENDENT_SET: {
            hal_acl_independent_result result;
            memset(&result, 0, sizeof(result));
            return hal_acl_independent_transaction_apply(
                sw, &step->acl_independent,
                &step->pre_acl_independent, &result);
        }
        case L2_STEP_ACL_INDEPENDENT_DEL: {
            hal_acl_independent_result result;
            memset(&result, 0, sizeof(result));
            return hal_acl_independent_rollback_match(
                sw, &step->acl_independent, &result);
        }
        case L2_STEP_COPP_CLASS_SET:
            return hal_control_plane_copp_set(sw, step->copp_class,
                                              step->copp_rate_pps,
                                              step->copp_burst_pkts);
        case L2_STEP_STORM_CONTROL_SET: {
            int requested_rate = step->storm_rate_kbps;
            int requested_burst = step->storm_burst_bytes;
            int rc = hal_storm_control_set_kind(sw, step->port, step->storm_kind,
                                           step->storm_rate_kbps,
                                           step->storm_burst_bytes);
            if (rc != 0)
                return rc;

            /*
             * FM storm controller rate/capacity values are quantized by
             * hardware. Normalize this apply step to the effective values so
             * read-back verification checks the ASIC contract instead of the
             * user-entered decimal.
             */
            hal_storm_control_entry entry;
            if (hal_storm_control_get_kind(sw, step->port, step->storm_kind, &entry) == 0) {
                step->storm_rate_kbps = entry.rate_kbps;
                step->storm_burst_bytes = entry.burst_bytes;
                if (entry.rate_kbps != requested_rate ||
                    entry.burst_bytes != requested_burst) {
                    NL_LOG_NOTICE("storm-control port=%d normalized "
                                  "rate=%d->%dKbps burst=%d->%d",
                                  step->port, requested_rate,
                                  entry.rate_kbps, requested_burst,
                                  entry.burst_bytes);
                }
            } else {
                return -1;
            }
            return 0;
        }
        case L2_STEP_STORM_CONTROL_DEL:
            return hal_storm_control_delete_kind(sw, step->port, step->storm_kind);
        case L2_STEP_INGRESS_RATE_LIMIT_SET: {
            int requested_rate = step->ingress_rate_limit_rate_kbps;
            int requested_burst = step->ingress_rate_limit_burst_bytes;
            int rc = hal_ingress_rate_limit_set(sw, step->port,
                                        step->ingress_rate_limit_rate_kbps,
                                        step->ingress_rate_limit_burst_bytes);
            if (rc != 0)
                return rc;

            hal_storm_control_entry entry;
            if (hal_ingress_rate_limit_get(sw, step->port, &entry) == 0) {
                step->ingress_rate_limit_rate_kbps = entry.rate_kbps;
                step->ingress_rate_limit_burst_bytes = entry.burst_bytes;
                if (entry.rate_kbps != requested_rate ||
                    entry.burst_bytes != requested_burst) {
                    NL_LOG_NOTICE("ingress-rate-limit port=%d normalized "
                                  "rate=%d->%dKbps burst=%d->%d",
                                  step->port, requested_rate,
                                  entry.rate_kbps, requested_burst,
                                  entry.burst_bytes);
                }
            }
            return 0;
        }
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            return hal_ingress_rate_limit_delete(sw, step->port);
        case L2_STEP_EGRESS_RATE_LIMIT_SET: {
            int requested_rate = step->egress_rate_limit_rate_kbps;
            int requested_burst = step->egress_rate_limit_burst_bytes;
            int rc = hal_egress_rate_limit_set(
                sw, step->port, step->egress_rate_limit_rate_kbps,
                step->egress_rate_limit_burst_bytes);
            if (rc != 0)
                return rc;

            hal_egress_rate_limit_entry entry;
            if (hal_egress_rate_limit_get(sw, step->port, &entry) == 0) {
                step->egress_rate_limit_rate_kbps = entry.rate_kbps;
                step->egress_rate_limit_burst_bytes = entry.burst_bytes;
                if (entry.rate_kbps != requested_rate ||
                    entry.burst_bytes != requested_burst) {
                    NL_LOG_NOTICE("egress-rate-limit port=%d normalized "
                                  "rate=%d->%dKbps burst=%d->%d",
                                  step->port, requested_rate,
                                  entry.rate_kbps, requested_burst,
                                  entry.burst_bytes);
                }
            }
            return 0;
        }
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            return hal_egress_rate_limit_delete(sw, step->port);
        case L2_STEP_QOS_INTERFACE_SET:
        case L2_STEP_QOS_INTERFACE_DEL: {
            if (resolve_target_port_state(sw, step) != HW_CAPTURE_PRESENT) return NL_ERR_PRE_STATE_MISSING;
            int trust = step->type == L2_STEP_QOS_INTERFACE_SET ? step->qos_trust_mode : HAL_QOS_TRUST_IEEE8021P;
            int priority = step->type == L2_STEP_QOS_INTERFACE_SET ? step->qos_default_priority : 0;
            return valid_ae_id(step->ae_id) ? hal_lag_qos_set(sw, step->lag_id, trust, priority) :
                hal_qos_interface_set(sw, step->port, trust, priority);
        }
        case L2_STEP_QOS_TC_SMP_SET:
            return hal_qos_tc_smp_set(sw, step->qos_traffic_class, step->qos_smp);
        case L2_STEP_QOS_DSCP_SET:
            return hal_qos_dscp_set(sw, step->qos_dscp, step->qos_dscp_priority);
        case L2_STEP_QOS_PFC_SET: {
            int st = hal_qos_pfc_apply(sw, step->port,
                                     step->qos_pfc_rx_class_mask,
                                     step->qos_pfc_tx_pause_mode,
                                     step->qos_pfc_tx_class_mask,
                                     step->qos_pfc_lossless_smp_mask,
                                     step->qos_pfc_shared_pause_mask);
            return st ? st : hal_pfc_watchdog_configure(sw, step->port, &step->qos_pfc_watchdog);
        }
        case L2_STEP_QOS_PFC_DEL: {
            int st = hal_qos_pfc_delete(sw, step->port);
            fm10k_pfc_wd_policy disabled = fm10k_pfc_wd_default_policy();
            return st ? st : hal_pfc_watchdog_configure(sw, step->port, &disabled);
        }
        case L2_STEP_QOS_PRIORITY_MAP_SET:
            return hal_qos_priority_map_set(sw,
                                            step->qos_switch_priority,
                                            step->qos_traffic_class);
        case L2_STEP_QOS_PRIORITY_MAP_DEL:
            return hal_qos_priority_map_delete(sw,
                                               step->qos_switch_priority);
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
            return hal_qos_scheduler_tc_map_set(
                sw, step->port, step->qos_scheduler_traffic_class,
                step->qos_scheduler_shaping_group);
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
            return hal_qos_scheduler_tc_map_delete(
                sw, step->port, step->qos_scheduler_traffic_class);
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
            return hal_qos_scheduler_group_set(
                sw, step->port, step->qos_scheduler_group,
                step->qos_scheduler_strict_priority,
                step->qos_scheduler_weight);
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            return hal_qos_scheduler_group_delete(
                sw, step->port, step->qos_scheduler_group);
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET: {
            u64 requested_rate = step->qos_scheduler_group_rate_bps;
            u64 requested_burst = step->qos_scheduler_group_burst_bits;
            int rc = hal_qos_scheduler_group_shaping_set(
                sw, step->port, step->qos_scheduler_group,
                step->qos_scheduler_group_rate_bps,
                step->qos_scheduler_group_burst_bits);
            if (rc != 0)
                return rc;

            u64 rate = 0;
            u64 burst = 0;
            if (hal_qos_scheduler_group_shaping_get(
                    sw, step->port, step->qos_scheduler_group,
                    &rate, &burst) == 0) {
                step->qos_scheduler_group_rate_bps = rate;
                step->qos_scheduler_group_burst_bits = burst;
                if (rate != requested_rate || burst != requested_burst) {
                    NL_LOG_NOTICE("qos scheduler port=%d group=%d shaping normalized rate=%llu->%llu burst=%llu->%llu",
                                  step->port,
                                  step->qos_scheduler_group,
                                  (unsigned long long)requested_rate,
                                  (unsigned long long)rate,
                                  (unsigned long long)requested_burst,
                                  (unsigned long long)burst);
                }
            }
            return 0;
        }
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            return hal_qos_scheduler_group_shaping_delete(
                sw, step->port, step->qos_scheduler_group);
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
            return hal_qos_scheduler_port_set(
                sw, step->port,
                step->qos_scheduler_traffic_class_enable_mask);
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
            return hal_qos_scheduler_port_delete(sw, step->port);
        case L2_STEP_QOS_WATERMARK_SET:
            return hal_qos_watermark_transaction_apply(
                sw, step->port, step->qos_watermark_attr,
                step->qos_watermark_index,
                step->qos_watermark_value,
                step->qos_watermark_owner_create,
                step->qos_watermark_reconcile,
                &step->pre_qos_watermark);
        case L2_STEP_QOS_WATERMARK_DEL:
            return hal_qos_watermark_transaction_delete(
                sw, step->port, step->qos_watermark_attr,
                step->qos_watermark_index,
                step->qos_watermark_reconcile,
                &step->pre_qos_watermark,
                &step->qos_watermark_delete_target);
        case L2_STEP_MIRROR_SESSION_SET:
            return hal_mirror_session_replace(sw, &step->mirror);
        case L2_STEP_MIRROR_SESSION_DEL:
            return hal_mirror_session_delete(sw, step->mirror.group);
        default:
            NL_LOG_ERR("apply_one_step: unknown step type %d", step->type);
            return -1;
    }
}

static int lag_handle_set_replace(
    hal_lag_handle_set_snapshot *set, int old_lag_id, int new_lag_id) {
    int old_index = -1;

    if (!set ||
        set->state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
        set->count < 0 || set->count > NETLAB_MAX_AE ||
        old_lag_id <= 0 || new_lag_id <= 0)
        return -1;
    for (int i = 0; i < set->count; i++) {
        if (set->lag_ids[i] == old_lag_id)
            old_index = i;
        if (set->lag_ids[i] == new_lag_id &&
            new_lag_id != old_lag_id)
            return -1;
    }
    if (old_index < 0)
        return 0;
    set->lag_ids[old_index] = new_lag_id;
    return 0;
}

static int lag_delete_create_base(
    const l2_apply_plan *plan, int step_index,
    hal_lag_handle_set_snapshot *create_base) {
    const l2_apply_step *step;
    int removed_index = -1;

    if (!plan || !create_base || step_index < 0 ||
        step_index >= plan->n_steps)
        return -1;
    step = &plan->steps[step_index];
    *create_base = step->pre_lag_handles;
    if (create_base->state ==
            HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
        create_base->count <= 0 ||
        create_base->count > NETLAB_MAX_AE)
        return -1;
    for (int i = 0; i < create_base->count; i++)
        if (create_base->lag_ids[i] == step->pre_lag_id) {
            removed_index = i;
            break;
        }
    if (removed_index < 0)
        return -1;
    for (int i = removed_index + 1; i < create_base->count; i++)
        create_base->lag_ids[i - 1] = create_base->lag_ids[i];
    create_base->count--;
    create_base->state = create_base->count == 0 ?
        HAL_TRANSACTION_SNAPSHOT_ABSENT :
        HAL_TRANSACTION_SNAPSHOT_PRESENT;
    create_base->sdk_status = (int)FM_OK;

    /*
     * A later delete is restored first.  Its semantic AE is authoritative,
     * while its allocator-owned SDK handle may differ from the handle that
     * was present in this step's apply-time before-image.  Normalize those
     * already-restored handles before attributing a create delta.
     */
    for (int i = step_index + 1; i < plan->n_steps; i++) {
        const l2_apply_step *later = &plan->steps[i];
        int live_lag_id;

        if (later->type != L2_STEP_LAG_DELETE ||
            !later->pre_lag_existed)
            continue;
        live_lag_id = later->restored_lag_id > 0 ?
            later->restored_lag_id :
            (valid_ae_id(later->ae_id) ?
             g_ae_lag_id[later->ae_id] : later->lag_id);
        if (live_lag_id <= 0)
            continue;
        if (lag_handle_set_replace(
                create_base, later->pre_lag_id,
                live_lag_id) != 0)
            return -1;
    }
    return 0;
}

static int restore_lag_delete(
    int sw, l2_apply_plan *plan, int step_index,
    l2_apply_step *step,
    const l2_apply_step *original) {
    int lag = 0;
    int state;

    if (!step || !original || !original->pre_lag_existed)
        return 0;
    if (step->restored_lag_id > 0) {
        state = hw_lag_exists_state(
            sw, step->restored_lag_id);
        if (state == HW_CAPTURE_ERROR)
            return -1;
        if (state == HW_CAPTURE_PRESENT) {
            lag = step->restored_lag_id;
            remember_ae_lag(step->ae_id, lag);
        } else {
            step->restored_lag_id = 0;
        }
    }
    if (lag == 0 && !step->lag_delete_issued) {
        lag = resolve_lag_id(sw, step);
        if (lag < 0)
            return -1;
        if (lag > 0)
            step->restored_lag_id = lag;
    }
    if (lag == 0) {
        hal_lag_handle_set_snapshot create_base;
        hal_lag_handle_set_snapshot current;
        int new_lag = -1;
        bool created = false;
        int sdk_status = (int)FM_OK;
        int create_status;
        int delta_status;

        if (step->lag_delete_issued &&
            hal_lag_wait_absent(
                sw, step->pre_lag_id).state !=
                HAL_PRESENCE_ABSENT)
            return -1;
        if (valid_ae_id(step->ae_id) &&
            g_ae_lag_id[step->ae_id] > 0)
            return -1;

        if (lag_delete_create_base(
                plan, step_index, &create_base) != 0)
            return -1;

        /*
         * A previous restore attempt may have created a live replacement but
         * lost its output token when the post-image enumeration failed.
         * Re-adopt exactly one global addition; clean multiple attributable
         * additions back to the retained base before retrying.
         */
        current = hal_lag_handle_set_snapshot_get(sw);
        delta_status = hal_lag_handle_set_single_addition(
            &create_base, &current, &new_lag);
        if (delta_status == 1) {
            lag = new_lag;
            step->restored_lag_id = lag;
            step->lag_id = lag;
            remember_ae_lag(step->ae_id, lag);
        } else if (delta_status < 0) {
            if (hal_lag_handle_set_restore_after_create(
                    sw, &create_base) != 0)
                return -1;
        }

        if (lag > 0)
            goto restore_lag_composite;
        create_status = hal_lag_create_classified(
            sw, &create_base, &new_lag, &created, &sdk_status);
        if (created && new_lag > 0) {
            lag = new_lag;
            step->restored_lag_id = lag;
            step->lag_id = lag;
            remember_ae_lag(step->ae_id, lag);
        }
        if (create_status != 0 &&
            !(create_status == NL_ERR_SDK_CALL_FAILED && created)) {
            NL_LOG_CRIT(
                "LAG restore create classification failed ae=%d "
                "status=%d sdk=%d created=%d hw-lag=%d",
                step->ae_id, create_status, sdk_status,
                created ? 1 : 0, new_lag);
            return -1;
        }
        if (!created || lag <= 0)
            return -1;
        if (create_status == NL_ERR_SDK_CALL_FAILED)
            NL_LOG_WARN(
                "LAG restore reuses authoritative live LAG %d "
                "after create sdk=%d",
                lag, sdk_status);
    }

restore_lag_composite:
    if (step->pre_lag_attributes.valid &&
        hal_lag_attributes_restore(sw, lag, &step->pre_lag_attributes)) return -1;
    if (original->pre_lag_hash_rotation_valid &&
        hal_lag_set_hash_rotation(
            sw, lag, original->pre_lag_hash_rotation) != 0)
        return -1;
    if (original->pre_lag_lacp_disposition_valid) {
        fm_uint32 value =
            (fm_uint32)original->pre_lag_lacp_disposition;
        if (fmSetLAGAttribute(
                (fm_int)sw, FM_LAG_LACP_DISPOSITION,
                (fm_int)lag, &value) != FM_OK)
            return -1;
    } else {
        if (lag_lacp_to_cpu(sw, lag) != 0)
            return -1;
    }
    /* Native plans explicitly remove every member before deleting a LAG.
     * Their inverse steps reattach after the aggregate VLAN/port policy has
     * been restored. Reattaching here would project an incomplete policy. */
    if (original->pre_lag_attributes.valid) return 0;
    for (int i = 0; i < original->pre_lag_member_count; i++) {
        int port = original->pre_lag_members[i];
        int member = hw_lag_member_state(sw, lag, port);

        if (member == HW_CAPTURE_ERROR)
            return -1;
        if (member == HW_CAPTURE_ABSENT &&
            hal_lag_restore_port(sw, lag, port, plan->tx_id) != 0)
            return -1;
    }
    return 0;
}

static int restore_single_mac_pre_state(
    int sw, const l2_apply_step *step) {
    int port;

    if (!step)
        return -1;
    if (!step->pre_mac_valid)
        return hal_static_mac_delete(
            sw, step->vid, step->mac);
    if (!step->pre_mac_static ||
        (step->pre_mac_type != FM_ADDRESS_STATIC &&
         step->pre_mac_type != FM_ADDRESS_SECURE_STATIC))
        return -1;

    if (valid_ae_id(step->pre_mac_ae_id)) {
        l2_apply_step target;

        memset(&target, 0, sizeof(target));
        target.ae_id = step->pre_mac_ae_id;
        target.port = step->pre_mac_port;
        port = resolve_target_port(sw, &target);
    } else {
        port = step->pre_mac_port;
    }
    if (port <= 0)
        return -1;

    fm_macAddressEntry entry;
    fm_status st;

    memset(&entry, 0, sizeof(entry));
    entry.macAddress =
        ((fm_macaddr)step->mac[0] << 40) |
        ((fm_macaddr)step->mac[1] << 32) |
        ((fm_macaddr)step->mac[2] << 24) |
        ((fm_macaddr)step->mac[3] << 16) |
        ((fm_macaddr)step->mac[4] << 8) |
        (fm_macaddr)step->mac[5];
    entry.vlanID = (fm_uint16)step->vid;
    entry.type = (fm_int)step->pre_mac_type;
    entry.destMask = FM_DESTMASK_UNUSED;
    entry.port = (fm_int)port;
    st = fmAddAddress((fm_int)sw, &entry);
    return st == FM_OK ? 0 : (int)st;
}

static int rollback_one_step(
    int sw, l2_apply_plan *plan, int step_index,
    l2_apply_step *step,
    const l2_apply_step *original) {
    fm_status st = FM_OK;

    switch (step->type) {
        case L2_STEP_VLAN_CREATE:
            if (!step->pre_vlan_existed) {
                st = fmDeleteVlan((fm_int)sw, step->vid);
                if (st != FM_OK &&
                    hw_vlan_exists_state(sw, step->vid) ==
                        HW_CAPTURE_ABSENT)
                    st = FM_OK;
            }
            break;
        case L2_STEP_VLAN_DELETE:
            if (step->pre_vlan_existed) {
                st = fmCreateVlan((fm_int)sw, step->vid);
                if (st == FM_ERR_VLAN_ALREADY_EXISTS)
                    st = FM_OK;
            }
            break;
        case L2_STEP_VLAN_ADD_PORT:
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            if (step->pre_member_existed) {
                bool current_tagged = false;
                int member = hw_vlan_member_state(
                    sw, step->vid, step->port, &current_tagged);

                if (member == HW_CAPTURE_ERROR)
                    return -1;
                if (member == HW_CAPTURE_PRESENT &&
                    current_tagged != step->pre_member_tagged) {
                    st = fmDeleteVlanPort(
                        (fm_int)sw, step->vid, step->port);
                    if (st != FM_OK)
                        return -1;
                    st = fmAddVlanPort(
                        (fm_int)sw, step->vid, step->port,
                        step->pre_member_tagged ? TRUE : FALSE);
                    if (st != FM_OK &&
                        st != FM_ERR_VLAN_ALREADY_EXISTS)
                        return -1;
                } else if (member == HW_CAPTURE_ABSENT) {
                    st = fmAddVlanPort(
                        (fm_int)sw, step->vid, step->port,
                        step->pre_member_tagged ? TRUE : FALSE);
                    if (st != FM_OK &&
                        st != FM_ERR_VLAN_ALREADY_EXISTS)
                        return -1;
                }
                if (step->pre_member_stp_valid) {
                    st = fmSetVlanPortState(
                        (fm_int)sw, step->vid, step->port,
                        step->pre_member_stp_state);
                    if (st != FM_OK)
                        return -1;
                }
            } else {
                int member = hw_vlan_member_state(
                    sw, step->vid, step->port, NULL);

                if (member == HW_CAPTURE_ERROR)
                    return -1;
                if (member == HW_CAPTURE_PRESENT) {
                    st = fmDeleteVlanPort(
                        (fm_int)sw, step->vid, step->port);
                    if (st != FM_OK)
                        return -1;
                }
            }
            if (restore_vlan_static_macs(
                    sw, step->vid, step) != 0)
                return -1;
            break;
        case L2_STEP_VLAN_REM_PORT:
            if (resolve_target_port(sw, step) <= 0)
                return -1;
            if (step->pre_member_existed) {
                bool current_tagged = false;
                int member = hw_vlan_member_state(
                    sw, step->vid, step->port, &current_tagged);

                if (member == HW_CAPTURE_ERROR)
                    return -1;
                if (member == HW_CAPTURE_PRESENT &&
                    current_tagged != step->pre_member_tagged) {
                    st = fmDeleteVlanPort(
                        (fm_int)sw, step->vid, step->port);
                    if (st != FM_OK)
                        return -1;
                    member = HW_CAPTURE_ABSENT;
                }
                if (member == HW_CAPTURE_ABSENT) {
                    st = fmAddVlanPort(
                        (fm_int)sw, step->vid, step->port,
                        step->pre_member_tagged ? TRUE : FALSE);
                    if (st != FM_OK &&
                        st != FM_ERR_VLAN_ALREADY_EXISTS)
                        return -1;
                }
                if (step->pre_member_stp_valid) {
                    st = fmSetVlanPortState(
                        (fm_int)sw, step->vid, step->port,
                        step->pre_member_stp_state);
                    if (st != FM_OK)
                        return -1;
                }
            }
            if (restore_vlan_static_macs(
                    sw, step->vid, step) != 0)
                return -1;
            break;
        case L2_STEP_PVID_SET:
            if (step->pre_pvid_valid) {
                if (resolve_target_port(sw, step) <= 0)
                    return -1;
                fm_uint32 pvid = step->pre_pvid;
                st = fmSetPortAttribute((fm_int)sw, (fm_int)step->port,
                                        FM_PORT_DEF_VLAN, &pvid);
            }
            break;
        case L2_STEP_VLAN_STP_SET:
            if (step->pre_stp_valid) {
                if (resolve_target_port(sw, step) <= 0)
                    return -1;
                st = fmSetVlanPortState((fm_int)sw, step->vid, step->port,
                                        step->pre_stp_state);
            }
            break;
        case L2_STEP_PORT_SET_ADMIN:
            if (hal_port_admin_transaction_restore(
                    sw, step->port, &step->pre_admin) != 0)
                return -1;
            break;
        case L2_STEP_FM10K_GROUP_SET:
            if (!step->pre_fm10k_group_valid) return NL_ERR_PRE_STATE_MISSING;
            return hal_fm10k_group_restore(sw, &step->pre_fm10k_group, step->fm10k_tx_id);
        case L2_STEP_FM10K_FAN_SET:
            return hal_fm10k_fan_restore(sw, &step->pre_fm10k_fan);
        case L2_STEP_PORT_SET_MTU:
            if (step->pre_mtu_valid) {
                if (resolve_target_port(sw, step) <= 0)
                    return -1;
                if (hal_port_set_mtu(sw, step->port, step->pre_mtu) != 0)
                    return -1;
            }
            break;
        case L2_STEP_PORT_SET_SPEED:
            if (step->pre_speed_valid) {
                if (resolve_target_port(sw, step) <= 0)
                    return -1;
                if (hal_port_restore_speed(
                        sw, step->port, step->pre_speed,
                        step->pre_ethernet_mode,
                        &step->pre_admin) != 0)
                    return -1;
            }
            break;
        case L2_STEP_PORT_PARSER_SET:
            if (step->pre_parser_valid) {
                fm_int parser = step->pre_parser_mode;
                if (resolve_target_port(sw, step) <= 0)
                    return -1;
                st = fmSetPortAttribute((fm_int)sw, (fm_int)step->port,
                                        FM_PORT_PARSER, &parser);
            }
            break;
        case L2_STEP_PORT_INGRESS_FILTER_SET:
            if (step->pre_ingress_filter_valid) {
                if (resolve_target_port(sw, step) <= 0) return -1;
                fm_bool enabled = step->pre_ingress_filter ? TRUE : FALSE;
                st = fmSetPortAttribute(sw, step->port, FM_PORT_DROP_BV, &enabled);
            }
            break;
        case L2_STEP_MAC_AGING_SET:
            if (step->pre_aging_valid) {
                if (hal_mac_aging_set(sw, step->pre_aging_time) != 0)
                    return -1;
            }
            break;
        case L2_STEP_STATIC_MAC_ADD:
            if (restore_single_mac_pre_state(sw, step) != 0)
                return -1;
            break;
        case L2_STEP_STATIC_MAC_DEL:
            if (restore_single_mac_pre_state(sw, step) != 0)
                return -1;
            break;
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL:
            if (step->pre_igmp_listener_present) {
                if (hal_l2_mcast_listener_set(
                        sw, step->vid, step->mac, step->port) != 0)
                    return -1;
            } else if (hal_l2_mcast_listener_delete(
                           sw, step->vid, step->mac, step->port) != 0) {
                return -1;
            }
            break;
        case L2_STEP_LAG_CREATE:
            if (!step->pre_lag_existed) {
                int restore_status =
                    hal_lag_handle_set_restore_after_create(
                        sw, &step->pre_lag_handles);
                int lag = resolve_lag_id(sw, step);

                if (lag == 0)
                    forget_ae_lag(step->ae_id, step->lag_id);
                if (restore_status != 0 || lag < 0)
                    return -1;
            }
            break;
        case L2_STEP_LAG_DELETE:
            if (restore_lag_delete(
                    sw, plan, step_index, step, original) != 0)
                return -1;
            break;
        case L2_STEP_LAG_ADD_PORT: {
            int lag = resolve_lag_id(sw, step);
            if (!step->pre_lag_member_existed && lag > 0) {
                int member = hw_lag_member_state(
                    sw, lag, step->port);
                if (member == HW_CAPTURE_ERROR)
                    return -1;
                if (member == HW_CAPTURE_PRESENT &&
                    hal_lag_del_port(sw, lag, step->port) != 0)
                    return -1;
            }
            break;
        }
        case L2_STEP_LAG_DEL_PORT: {
            int lag = resolve_lag_id(sw, step);
            if (step->pre_lag_member_existed && lag > 0) {
                int member = hw_lag_member_state(
                    sw, lag, step->port);
                if (member == HW_CAPTURE_ERROR)
                    return -1;
                if (member == HW_CAPTURE_ABSENT &&
                    hal_lag_restore_port(sw, lag, step->port, plan->tx_id) != 0)
                    return -1;
            }
            break;
        }
        case L2_STEP_LAG_HASH_ROTATION_SET: {
            int lag = resolve_lag_id(sw, step);
            if (step->pre_lag_hash_rotation_valid && lag > 0) {
                if (hal_lag_set_hash_rotation(
                        sw, lag, step->pre_lag_hash_rotation) != 0)
                    return -1;
            }
            break;
        }
        case L2_STEP_DHCP_SNOOPING_SET:
            if (!step->pre_security_present) {
                if (hal_l2_security_dhcp_snooping_delete(
                        sw, (u16)step->security_vid,
                        step->security_port) != 0)
                    return -1;
            }
            return release_security_table_created_by_step(step);
        case L2_STEP_DHCP_SNOOPING_DEL:
            if (step->pre_security_present) {
                if (hal_l2_security_dhcp_snooping_set(
                        sw, (u16)step->security_vid,
                        step->security_port) != 0)
                    return -1;
            }
            break;
        case L2_STEP_ARP_INSPECTION_SET:
            if (!step->pre_security_present) {
                if (hal_l2_security_arp_inspection_delete(
                        sw, (u16)step->security_vid,
                        step->security_port) != 0)
                    return -1;
            }
            return release_security_table_created_by_step(step);
        case L2_STEP_ARP_INSPECTION_DEL:
            if (step->pre_security_present) {
                if (hal_l2_security_arp_inspection_set(
                        sw, (u16)step->security_vid,
                        step->security_port) != 0)
                    return -1;
            }
            break;
        case L2_STEP_ARP_INSPECTION_BINDING_SET:
            if (!step->pre_security_present) {
                if (hal_l2_security_arp_binding_delete(
                        sw, (u16)step->security_vid, step->security_port,
                        step->security_mac, step->security_ip) != 0)
                    return -1;
            }
            return release_security_table_created_by_step(step);
        case L2_STEP_ARP_INSPECTION_BINDING_DEL:
            if (step->pre_security_present) {
                if (hal_l2_security_arp_binding_set(
                        sw, (u16)step->security_vid, step->security_port,
                        step->security_mac, step->security_ip) != 0)
                    return -1;
            }
            break;
        case L2_STEP_USER_FILTER_SET:
            if (!step->pre_security_present) {
                if (hal_l2_security_user_filter_delete(
                        sw, (u16)step->security_vid, step->security_port,
                        step->security_mac, step->security_mac_kind) != 0)
                    return -1;
            }
            return release_security_table_created_by_step(step);
        case L2_STEP_USER_FILTER_DEL:
            if (step->pre_security_present) {
                if (hal_l2_security_user_filter_set(
                        sw, (u16)step->security_vid, step->security_port,
                        step->security_mac, step->security_mac_kind) != 0)
                    return -1;
            }
            break;
        case L2_STEP_INGRESS_IPV4_ACL_SET:
            if (!step->pre_ingress_ipv4_acl_present) {
                if (hal_ingress_ipv4_acl_delete(
                        sw, &step->ingress_ipv4_acl) != 0)
                    return -1;
            }
            return release_security_table_created_by_step(step);
        case L2_STEP_INGRESS_IPV4_ACL_DEL:
            if (step->pre_ingress_ipv4_acl_present) {
                if (hal_ingress_ipv4_acl_set(
                        sw, &step->ingress_ipv4_acl) != 0)
                    return -1;
            }
            break;
        case L2_STEP_ACL_POLICER_SET:
        case L2_STEP_ACL_POLICER_DEL:
            if (hal_acl_policer_owner_transaction_restore(
                    sw, &step->acl_policer,
                    &step->pre_acl_policer) != 0)
                return -1;
            break;
        case L2_STEP_EGRESS_ACL_SET:
        case L2_STEP_EGRESS_ACL_DEL:
            if (hal_acl_egress_owner_transaction_restore(
                    sw, &step->egress_acl,
                    &step->pre_egress_acl) != 0)
                return -1;
            break;
        case L2_STEP_ACL_INDEPENDENT_SET:
        case L2_STEP_ACL_INDEPENDENT_DEL:
            if (hal_acl_independent_transaction_restore(
                    sw, &step->acl_independent,
                    &step->pre_acl_independent) != 0)
                return -1;
            break;
        case L2_STEP_COPP_CLASS_SET:
            if (hal_control_plane_copp_transaction_restore(
                    sw, step->copp_class, &step->pre_copp) != 0)
                return -1;
            break;
        case L2_STEP_STORM_CONTROL_SET:
        case L2_STEP_STORM_CONTROL_DEL:
            if (step->pre_storm.state ==
                HAL_TRANSACTION_SNAPSHOT_PRESENT) {
                if (hal_storm_control_set_kind(sw, step->port, step->storm_kind,
                        (int)step->pre_storm.rate_kbps,
                        (int)step->pre_storm.capacity_bytes) != 0)
                    return -1;
            } else if (step->pre_storm.state !=
                           HAL_TRANSACTION_SNAPSHOT_ABSENT ||
                       hal_storm_control_delete_kind(
                           sw, step->port, step->storm_kind) != 0) {
                return -1;
            }
            break;
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            if (step->pre_ingress_rate_limit.state ==
                HAL_TRANSACTION_SNAPSHOT_PRESENT) {
                if (hal_ingress_rate_limit_set(sw, step->port,
                        (int)step->pre_ingress_rate_limit.rate_kbps,
                        (int)step->pre_ingress_rate_limit.capacity_bytes) != 0)
                    return -1;
            } else if (step->pre_ingress_rate_limit.state !=
                           HAL_TRANSACTION_SNAPSHOT_ABSENT ||
                       hal_ingress_rate_limit_delete(
                           sw, step->port) != 0) {
                return -1;
            }
            break;
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            if (hal_egress_rate_limit_transaction_restore(
                    sw, step->port,
                    &step->pre_egress_rate_limit) != 0)
                return -1;
            break;
        case L2_STEP_QOS_INTERFACE_SET:
        case L2_STEP_QOS_INTERFACE_DEL: {
            /* The earlier LAG_CREATE step owns removal of a new aggregate. */
            if (valid_ae_id(step->ae_id) && step->pre_qos_interface.state == HAL_TRANSACTION_SNAPSHOT_ABSENT)
                break;
            if (resolve_target_port_state(sw, step) != HW_CAPTURE_PRESENT) return -1;
            int status = valid_ae_id(step->ae_id) ?
                hal_lag_qos_restore(sw, step->lag_id, &step->pre_qos_interface) :
                hal_qos_interface_transaction_restore(sw, step->port, &step->pre_qos_interface);
            if (status) return -1;
            break;
        }
        case L2_STEP_QOS_TC_SMP_SET:
            if (!step->pre_qos_smp_valid ||
                hal_qos_tc_smp_set(sw, step->qos_traffic_class, step->pre_qos_smp)) return -1;
            break;
        case L2_STEP_QOS_DSCP_SET:
            if (!step->pre_qos_dscp_valid ||
                hal_qos_dscp_set(sw, step->qos_dscp, step->pre_qos_dscp_priority)) return -1;
            break;
        case L2_STEP_QOS_PFC_SET:
        case L2_STEP_QOS_PFC_DEL:
            if (step->pre_qos_pfc_valid) {
                if (hal_qos_pfc_apply(
                        sw, step->port,
                        step->pre_qos_pfc_rx_class_mask,
                        step->pre_qos_pfc_tx_pause_mode,
                        step->pre_qos_pfc_tx_class_mask,
                        step->pre_qos_pfc_lossless_smp_mask,
                        step->pre_qos_pfc_shared_pause_mask) != 0)
                    return -1;
                if (hal_qos_pfc_pc3_smp_set(sw, step->port, step->pre_qos_pfc_pc3_smp)) return -1;
                if (hal_pfc_watchdog_configure(sw, step->port, &step->pre_qos_pfc_watchdog)) return -1;
            } else if (hal_qos_pfc_delete(sw, step->port) != 0) {
                return -1;
            } else {
                fm10k_pfc_wd_policy disabled = fm10k_pfc_wd_default_policy();
                if (hal_pfc_watchdog_configure(sw, step->port, &disabled)) return -1;
            }
            break;
        case L2_STEP_QOS_PRIORITY_MAP_SET:
        case L2_STEP_QOS_PRIORITY_MAP_DEL:
            if (step->pre_qos_priority_map_valid) {
                if (hal_qos_priority_map_set(
                        sw, step->qos_switch_priority,
                        step->pre_qos_traffic_class) != 0)
                    return -1;
            } else if (hal_qos_priority_map_delete(
                           sw, step->qos_switch_priority) != 0) {
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
            if (step->pre_qos_scheduler_tc_map_valid) {
                if (hal_qos_scheduler_tc_map_set(
                        sw, step->port,
                        step->qos_scheduler_traffic_class,
                        step->pre_qos_scheduler_shaping_group) != 0)
                    return -1;
            } else if (hal_qos_scheduler_tc_map_delete(
                           sw, step->port,
                           step->qos_scheduler_traffic_class) != 0) {
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            if (hal_qos_scheduler_topology_transaction_restore(
                    sw, step->port,
                    &step->pre_qos_scheduler_topology) != 0)
                return -1;
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            if (hal_qos_scheduler_group_shaping_transaction_restore(
                    sw, step->port, step->qos_scheduler_group,
                    &step->pre_qos_scheduler_group_shaping) != 0)
                return -1;
            break;
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
            if (step->pre_qos_scheduler_port_valid) {
                if (hal_qos_scheduler_port_transaction_restore(
                        sw, step->port,
                        (u32)step->
                            pre_qos_scheduler_traffic_class_enable_mask) != 0)
                    return -1;
            } else if (hal_qos_scheduler_port_delete(
                           sw, step->port) != 0) {
                return -1;
            }
            break;
        case L2_STEP_QOS_WATERMARK_SET:
        case L2_STEP_QOS_WATERMARK_DEL:
            if (hal_qos_watermark_transaction_restore(
                    sw, step->port,
                    step->qos_watermark_attr,
                    step->qos_watermark_index,
                    &step->pre_qos_watermark) != 0)
                return -1;
            break;
        case L2_STEP_MIRROR_SESSION_SET:
        case L2_STEP_MIRROR_SESSION_DEL:
            if (step->pre_mirror.exists) {
                if (hal_mirror_session_replace(sw,
                                               &step->pre_mirror) != 0)
                    return -1;
            } else if (hal_mirror_session_delete(
                           sw, step->mirror.group) != 0) {
                return -1;
            }
            break;
        default:
            return -1;
    }

    if (st != FM_OK) {
        NL_LOG_CRIT("rollback step type=%d vid=%d port=%d failed: %s",
                    step->type, step->vid, step->port, fmErrorMsg(st));
        return -1;
    }
    return 0;
}

static int rollback_steps(int sw, l2_apply_plan *plan, int last_idx,
                          const char *reason) {
    int failed = 0;
    bool restore_auto_pause_image = false;

    NL_LOG_WARN("hal_apply_l2_plan: rolling back through step %d (%s)",
                last_idx, reason ? reason : "unknown");
    for (int j = 0; j <= last_idx; j++)
        if (qos_auto_pause_trigger_step(plan->steps[j].type)) {
            restore_auto_pause_image = true;
            break;
        }
    int next = last_idx;
    if (plan->fm10k_scope_present) {
        if (!plan->rollback_started) {
            plan->rollback_started = true;
            plan->rollback_next_idx = last_idx;
        }
        next = plan->rollback_next_idx;
        if (next < -1 || next > last_idx) return -1;
    }
    for (int j = next; j >= 0; j--) {
        l2_apply_plan_checkpoint(plan);
        const l2_apply_step *original =
            j < plan->original_n_steps ?
            &plan->original_steps[j] : NULL;

        if (rollback_one_step(
                sw, plan, j, &plan->steps[j], original) != 0) {
            failed++;
            /* Preserve reverse dependency order. Replaying a completed
             * physical-port inverse after reattaching its LAG is invalid. */
            if (plan->fm10k_scope_present) break;
        } else if (plan->fm10k_scope_present) {
            plan->rollback_next_idx = j - 1;
        }
    }
    if ((!plan->fm10k_scope_present || !failed) && restore_auto_pause_image &&
        plan->qos_auto_pause_watermark_snapshot_required &&
        hal_qos_auto_pause_watermark_transaction_restore(
            sw, &plan->pre_qos_auto_pause_watermark) != 0) {
        NL_LOG_CRIT(
            "L2 rollback shared auto-pause watermark image restore failed");
        failed++;
    }
    return failed == 0 ? 0 : -1;
}

static int rollback_and_verify(int sw, l2_apply_plan *plan, int last_idx,
                               const char *reason) {
    int write_status;
    int verify_status;

    write_status = rollback_steps(sw, plan, last_idx, reason);
    verify_status = verify_original_plan(sw, plan);
    if (verify_status == 0 && plan->fm10k_scope_present)
        verify_status = hal_lag_transaction_check(plan->tx_id, false);
    if (verify_status == 0) {
        plan->rollback_last_idx = -1;
        plan->rollback_started = false;
        plan->rollback_next_idx = -1;
        if (write_status != 0) {
            NL_LOG_WARN(
                "L2 rollback SDK status was nonzero but exact "
                "original-state read-back succeeded");
        }
        return 0;
    }
    return write_status != 0 ?
        NL_ERR_ROLLBACK_FAILED :
        NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED;
}

int hal_apply_l2_plan(int sw, l2_apply_plan *plan,
                       struct sdk_result *results, int max_results) {
    if (!plan || plan->n_steps <= 0) return -1;
    if (results && plan->n_steps > max_results) return -1;
    if (plan->n_steps > L2_PLAN_MAX_STEPS ||
        plan->n_steps > plan->step_capacity || !plan->steps)
        return -1;

    /* Never snapshot a watchdog's temporary RX mask as persistent pre-state. */
    if (hal_pfc_watchdog_quiesce(sw)) return NL_ERR_HW_STATE_OUT_OF_SYNC;

    plan->rollback_last_idx = -1;
    plan->rollback_started = false;
    plan->rollback_next_idx = -1;
    if (capture_original_plan(sw, plan) != 0)
        return NL_ERR_PRE_STATE_MISSING;

    int applied = 0;
    for (int i = 0; i < plan->n_steps; i++) {
        l2_apply_plan_checkpoint(plan);
        clear_step_pre_state(&plan->steps[i]);
        if (capture_step_pre_state(sw, &plan->steps[i], true) != 0) {
            NL_LOG_ERR("apply step %d pre-state capture failed", i);
            if (i > 0) {
                int rollback_status = rollback_and_verify(
                    sw, plan, i - 1, "pre-state capture failed");
                if (rollback_status != 0)
                    return rollback_status;
            }
            return NL_ERR_PRE_STATE_MISSING;
        }
        if ((plan->steps[i].type == L2_STEP_STATIC_MAC_ADD ||
             plan->steps[i].type == L2_STEP_STATIC_MAC_DEL) &&
            plan->steps[i].pre_mac_valid &&
            plan->steps[i].pre_mac_type != FM_ADDRESS_STATIC) {
            NL_LOG_ERR(
                "apply step %d found foreign MAC type=%d",
                i, plan->steps[i].pre_mac_type);
            if (i > 0) {
                int rollback_status = rollback_and_verify(
                    sw, plan, i - 1,
                    "foreign static-MAC pre-state");
                if (rollback_status != 0)
                    return rollback_status;
            }
            return NL_ERR_PRE_STATE_MISSING;
        }

        plan->rollback_last_idx = i;
        int st = apply_one_step(sw, &plan->steps[i]);
        if (results && i < max_results) {
            results[i].status = st;
            results[i].sdk_status = st;
        }
        if (st == 0 || st == 71) applied++;  // 71 = FM_ERR_VLAN_ALREADY_EXISTS is OK
        else {
            NL_LOG_ERR("apply step %d failed: status=%d", i, st);
            int rollback_status = rollback_and_verify(
                sw, plan, i, "apply failed");
            if (rollback_status != 0)
                return rollback_status;
            if (st == NL_ERR_ROLLBACK_FAILED ||
                st == NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED ||
                (plan->fm10k_scope_present &&
                 (st < 0 || st == NL_ERR_HW_STATE_OUT_OF_SYNC ||
                  st == NL_ERR_RPC_TIMEOUT || st == NL_ERR_SDK_TIMEOUT)))
                return NL_ERR_SDK_CALL_FAILED;
            return st;
        }
    }

    NL_LOG_INFO("hal_apply_l2_plan: %d steps applied", applied);

    // Verify hardware read-back after successful apply.
    int vn = plan->n_steps;
    struct verify_result *vresults = calloc(
        (size_t)vn, sizeof(*vresults));
    if (!vresults) {
        NL_LOG_CRIT("hal_apply_l2_plan: read-back result allocation failed");
        int rollback_status = rollback_and_verify(
            sw, plan, plan->n_steps - 1,
            "read-back result allocation failed");
        return rollback_status != 0 ? rollback_status : NL_ERR;
    }
    int vret = verify_apply_plan(sw, plan, vresults, vn);
    if (vret != 0) {
        NL_LOG_CRIT("hal_apply_l2_plan: read-back verify FAILED after successful apply!");
        for (int i = 0; i < vn; i++) {
            if (!vresults[i].readback_ok) {
                NL_LOG_ERR("  verify step %d: %s", i, vresults[i].detail);
            }
        }
        int rollback_status = rollback_and_verify(
            sw, plan, plan->n_steps - 1,
            "read-back verify failed");
        free(vresults);
        if (rollback_status != 0)
            return rollback_status;
        return NL_ERR_READBACK_MISMATCH;  // commit must not promote config
    }

    free(vresults);
    NL_LOG_INFO("hal_apply_l2_plan: all %d steps verified OK", applied);
    return 0;
}

int hal_rollback_l2_plan(int sw, l2_apply_plan *plan) {
    if (hal_pfc_watchdog_quiesce(sw)) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    int status;

    if (!plan || plan->n_steps <= 0 ||
        plan->n_steps > L2_PLAN_MAX_STEPS ||
        plan->n_steps > plan->step_capacity || !plan->steps ||
        plan->original_n_steps != plan->n_steps ||
        plan->original_n_steps > plan->original_capacity ||
        !plan->original_steps ||
        plan->rollback_last_idx < 0 ||
        plan->rollback_last_idx >= plan->n_steps)
        return NL_ERR_PRE_STATE_MISSING;

    status = rollback_and_verify(
        sw, plan, plan->rollback_last_idx,
        "persistent transaction rollback");
    if (status != 0)
        return status;
    NL_LOG_NOTICE(
        "hal_rollback_l2_plan: tx=0x%lx restored %d steps",
        plan->tx_id, plan->n_steps);
    return 0;
}
