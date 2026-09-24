/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/hal_presence.h"
#include "netlab/interface_id.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <stdint.h>
#include <stdlib.h>

static hal_presence_snapshot vlan_snapshot(hal_presence_state state,
                                           fm_status sdk_status,
                                           bool tagged) {
    hal_presence_snapshot snapshot;

    snapshot.state = state;
    snapshot.sdk_status = (int)sdk_status;
    snapshot.tagged = tagged;
    return snapshot;
}

hal_presence_snapshot hal_vlan_presence_snapshot(int sw, u16 vid) {
    if (vid < 1 || vid > 4094) return vlan_snapshot(HAL_PRESENCE_READ_ERROR, FM_ERR_INVALID_VLAN, false);
    fm_int cur = -1;
    fm_status st = fmGetVlanFirst((fm_int)sw, &cur);

    if (st != FM_OK)
        return vlan_snapshot(HAL_PRESENCE_READ_ERROR, st, false);

    unsigned visited = 0;
    while (cur != -1) {
        if (cur < 1 || cur > 4094 || ++visited > 4094)
            return vlan_snapshot(HAL_PRESENCE_READ_ERROR, FM_FAIL, false);
        fm_int next = -1;

        if ((u16)cur == vid)
            return vlan_snapshot(HAL_PRESENCE_PRESENT, FM_OK, false);
        st = fmGetVlanNext((fm_int)sw, cur, &next);
        if (st != FM_OK)
            return vlan_snapshot(HAL_PRESENCE_READ_ERROR, st, false);
        cur = next;
    }
    return vlan_snapshot(HAL_PRESENCE_ABSENT, FM_OK, false);
}

hal_presence_snapshot hal_vlan_member_snapshot(int sw, u16 vid, int port) {
    fm_int cur = -1;
    fm_status st = fmGetVlanPortFirst(
        (fm_int)sw, (fm_int)vid, &cur);

    if (st == FM_ERR_INVALID_VLAN)
        return vlan_snapshot(HAL_PRESENCE_ABSENT, st, false);
    if (st != FM_OK)
        return vlan_snapshot(HAL_PRESENCE_READ_ERROR, st, false);

    unsigned visited = 0;
    while (cur != -1) {
        if (cur < 0 || ++visited > 65536)
            return vlan_snapshot(HAL_PRESENCE_READ_ERROR, FM_FAIL, false);
        fm_int next = -1;

        if ((int)cur == port) {
            fm_bool tag = FALSE;

            st = fmGetVlanPortTag(
                (fm_int)sw, (fm_int)vid, (fm_int)port, &tag);
            if (st != FM_OK)
                return vlan_snapshot(
                    HAL_PRESENCE_READ_ERROR, st, false);
            return vlan_snapshot(
                HAL_PRESENCE_PRESENT, FM_OK, tag ? true : false);
        }
        st = fmGetVlanPortNext(
            (fm_int)sw, (fm_int)vid, cur, &next);
        if (st != FM_OK)
            return vlan_snapshot(HAL_PRESENCE_READ_ERROR, st, false);
        cur = next;
    }

    /*
     * FM10840 may omit LAG logical ports from the cardinal VLAN iterator.
     * A successful direct tag read is the authoritative membership read.
     */
    fm_bool tag = FALSE;
    st = fmGetVlanPortTag(
        (fm_int)sw, (fm_int)vid, (fm_int)port, &tag);
    if (st == FM_OK)
        return vlan_snapshot(
            HAL_PRESENCE_PRESENT, FM_OK, tag ? true : false);
    if (st == FM_ERR_INVALID_PORT || st == FM_ERR_INVALID_VLAN)
        return vlan_snapshot(HAL_PRESENCE_ABSENT, st, false);
    return vlan_snapshot(HAL_PRESENCE_READ_ERROR, st, false);
}

int hal_vlan_create(int sw, u16 vid) {
    fm_status st = fmCreateVlan((fm_int)sw, (fm_uint16)vid);
    if (st != FM_OK)
        NL_LOG_ERR("fmCreateVlan(sw=%d, vid=%u): %s", sw, vid, fmErrorMsg(st));
    return (st == FM_OK) ? 0 : -1;
}

int hal_vlan_delete(int sw, u16 vid) {
    fm_status st = fmDeleteVlan((fm_int)sw, (fm_uint16)vid);
    hal_presence_snapshot snapshot;

    snapshot = hal_vlan_presence_snapshot(sw, vid);
    /* Recovery may replay a deletion after a fresh SDK baseline or after a
     * lost reply. Only a complete absence readback makes it idempotent. */
    if (st != FM_OK && snapshot.state != HAL_PRESENCE_ABSENT) return -1;
    if (snapshot.state != HAL_PRESENCE_ABSENT) {
        NL_LOG_ERR(
            "VLAN %u delete read-back not absent: state=%d sdk=%d",
            vid, (int)snapshot.state, snapshot.sdk_status);
        return -1;
    }
    return 0;
}

int hal_vlan_add_port(int sw, u16 vid, int port, bool tagged) {
    fm_status st = fmAddVlanPort((fm_int)sw, (fm_uint16)vid, (fm_int)port,
                                  tagged ? TRUE : FALSE);
    if (st != FM_OK)
        NL_LOG_ERR("fmAddVlanPort(sw=%d, vid=%u, port=%d): %s",
                    sw, vid, port, fmErrorMsg(st));
    return (st == FM_OK) ? 0 : -1;
}

int hal_vlan_remove_port(int sw, u16 vid, int port) {
    fm_status st = fmDeleteVlanPort((fm_int)sw, (fm_uint16)vid, (fm_int)port);
    hal_presence_snapshot snapshot;

    if (st != FM_OK)
        return -1;
    snapshot = hal_vlan_member_snapshot(sw, vid, port);
    if (snapshot.state != HAL_PRESENCE_ABSENT) {
        NL_LOG_ERR(
            "VLAN %u port %d remove read-back not absent: state=%d sdk=%d",
            vid, port, (int)snapshot.state, snapshot.sdk_status);
        return -1;
    }
    return 0;
}

int hal_pvid_set(int sw, int port, u16 vid) {
    fm_uint32 v = (fm_uint32)vid;
    fm_status st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                                       FM_PORT_DEF_VLAN, &v);
    return (st == FM_OK) ? 0 : -1;
}

int hal_get_stp_table(int sw, struct sdk_result *result) {
    nl_stp_snapshot snapshot = {0};
    size_t capacity = 0;
    fm_int cur_vlan;
    fm_status status;
    u32 vlan_count = 0;

    if (!result)
        return -1;
    nl_stp_snapshot_reset(&result->data.stp_table);
    status = fmGetVlanFirst((fm_int)sw, &cur_vlan);
    if (status != FM_OK || cur_vlan < -1 || cur_vlan == 0)
        return -1;

    while (cur_vlan > 0) {
        fm_int cur_port;
        fm_int next_vlan;
        u32 port_count = 0;
        u32 enumerated_port_count = 0;

        if (cur_vlan > 4094 || ++vlan_count > NL_STP_SNAPSHOT_MAX_VLANS)
            goto fail;
        status = fmGetVlanPortFirst(
            (fm_int)sw, (fm_uint16)cur_vlan, &cur_port);
        if (status != FM_OK || cur_port < -1)
            goto fail;
        /* IES 4.3.2 returns -1 at the end. Port zero is a valid CPU port
         * and must be skipped without terminating the cardinal iterator. */
        while (cur_port >= 0) {
            fm_int next_port;

            if (++enumerated_port_count > 65536U)
                goto fail;
            if (nl_ifid_is_user_port((int)cur_port)) {
                nl_stp_snapshot_entry *entry;
                fm_int stp_state;

                /* CPU and internal SDK ports do not consume the 24 user-port
                 * budget, but every SDK iterator step remains bounded. */
                if (++port_count > NL_STP_SNAPSHOT_MAX_PORTS)
                    goto fail;
                if (cur_port > UINT16_MAX ||
                    snapshot.n_entries >= NL_STP_SNAPSHOT_MAX_ENTRIES)
                    goto fail;
                if (fmGetVlanPortState(
                        (fm_int)sw, (fm_uint16)cur_vlan,
                        cur_port, &stp_state) != FM_OK ||
                    stp_state < FM_STP_STATE_DISABLED ||
                    stp_state > FM_STP_STATE_BLOCKING)
                    goto fail;
                if (snapshot.n_entries == capacity) {
                    size_t next_capacity =
                        capacity ? capacity * 2U : 256U;
                    nl_stp_snapshot_entry *grown;

                    if (next_capacity > NL_STP_SNAPSHOT_MAX_ENTRIES)
                        next_capacity = NL_STP_SNAPSHOT_MAX_ENTRIES;
                    grown = realloc(snapshot.entries,
                                    next_capacity * sizeof(*grown));
                    if (!grown)
                        goto fail;
                    snapshot.entries = grown;
                    capacity = next_capacity;
                }
                entry = &snapshot.entries[snapshot.n_entries++];
                entry->vlan = (u16)cur_vlan;
                entry->port = (u16)cur_port;
                entry->state = (u8)stp_state;
            }

            status = fmGetVlanPortNext((fm_int)sw, (fm_uint16)cur_vlan,
                                       cur_port, &next_port);
            if (status != FM_OK || next_port < -1 ||
                next_port == cur_port)
                goto fail;
            cur_port = next_port;
        }
        status = fmGetVlanNext((fm_int)sw, cur_vlan, &next_vlan);
        if (status != FM_OK || next_vlan < -1 || next_vlan == 0 ||
            (next_vlan != -1 && next_vlan <= cur_vlan))
            goto fail;
        cur_vlan = next_vlan;
    }
    snapshot.total_entries = snapshot.n_entries;
    if (nl_stp_snapshot_finalize(&snapshot) != 0)
        goto fail;
    result->data.stp_table = snapshot;
    return 0;

fail:
    nl_stp_snapshot_reset(&snapshot);
    return -1;
}
