/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "stp_show.h"

#include "stp_internal.h"
#include "netlab/error.h"
#include "netlab/monotonic.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static bool append_stp_text(char *buf, size_t buf_size, size_t *off,
                            const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || !fmt || *off >= buf_size)
        return false;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return false;
    *off += (size_t)n;
    return true;
}

static void send_stp_response(nl_conn *conn, const nl_msg_hdr *msg,
                              s32 error_code, const char *text, size_t len) {
    nl_msg_hdr *resp;

    if (!conn || !msg || !text || len > NETLAB_MAX_MSG)
        return;
    resp = nl_msg_alloc((u32)len);
    if (!resp)
        return;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
}

static void send_stp_capacity_error(nl_conn *conn, const nl_msg_hdr *msg) {
    static const char detail[] =
        "STP state response exceeds the IPC message capacity";

    send_stp_response(conn, msg, NL_ERR_CAPABILITY_INSUFFICIENT,
                      detail, sizeof(detail) - 1);
}

static void xml_escape_attr(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst || dst_len == 0)
        return;
    if (!src)
        src = "";
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        const char *rep = NULL;
        size_t len;

        switch (*p) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default:
            dst[off++] = *p;
            continue;
        }
        len = strlen(rep);
        if (off + len >= dst_len)
            break;
        memcpy(dst + off, rep, len);
        off += len;
    }
    dst[off] = '\0';
}

static const char *stp_port_role(const stp_port_stats *ps) {
    if (!ps || !ps->rstp_enabled)
        return "disabled";
    if (ps->guard_blocked)
        return "disabled";
    if (ps->protocol_blocked)
        return "alternate";
    switch (ps->role) {
    case STP_ROLE_ROOT:
        return "root";
    case STP_ROLE_ALTERNATE:
        return "alternate";
    case STP_ROLE_DESIGNATED:
        return "designated";
    case STP_ROLE_DISABLED:
    default:
        return "disabled";
    }
}

static const char *stp_role_name(stp_role_id role) {
    switch (role) {
    case STP_ROLE_ROOT:
        return "root";
    case STP_ROLE_ALTERNATE:
        return "alternate";
    case STP_ROLE_DESIGNATED:
        return "designated";
    case STP_ROLE_DISABLED:
    default:
        return "disabled";
    }
}

static const char *stp_port_state(const stp_port_stats *ps) {
    if (!ps || !ps->rstp_enabled)
        return "disabled";
    if (ps->guard_blocked || ps->protocol_blocked)
        return "discarding";
    return "forwarding";
}

static void format_mst_vlan_list(const stp_mst_instance_state *inst,
                                 char *out, size_t out_size) {
    size_t off = 0;
    int shown = 0;

    if (!out || out_size == 0)
        return;
    out[0] = '\0';
    if (!inst)
        return;
    for (int vid = 1; vid <= 4094; vid++) {
        int n;

        if (!inst->vlan_map[vid])
            continue;
        if (shown >= 24) {
            snprintf(out + off, out_size - off, "%s...",
                     off == 0 ? "" : ",");
            return;
        }
        n = snprintf(out + off, out_size - off, "%s%d",
                     off == 0 ? "" : ",", vid);
        if (n <= 0 || off + (size_t)n >= out_size)
            return;
        off += (size_t)n;
        shown++;
    }
    if (shown == 0)
        snprintf(out, out_size, "-");
}

void stp_show_send_state(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    size_t off = 0;
    bool complete = true;
    time_t now = nl_monotonic_seconds();
    u8 mac[6];
    u8 bridge_id[8];
    u8 root_id[8];
    char bridge_text[32];
    char root_text[32];
    int root_port;
    u32 root_path_cost;
    char mst_digest[STP_MST_DIGEST_LEN * 2 + 1];
    char mst_name[96];

    if (!buf) {
        send_stp_capacity_error(conn, msg);
        return;
    }
    reconcile_rstp_roles();
    load_system_mac(mac);
    stp_build_bridge_id(bridge_id, mac, stpd_bridge_priority());
    stp_format_bridge_id(bridge_id, bridge_text, sizeof(bridge_text));

    pthread_mutex_lock(&g_stp.lock);
    if (stp_bridge_id_is_zero(g_stp.selected_root_id))
        memcpy(root_id, bridge_id, 8);
    else
        memcpy(root_id, g_stp.selected_root_id, 8);
    root_port = g_stp.root_port;
    root_path_cost = g_stp.selected_root_path_cost;
    stp_format_bridge_id(root_id, root_text, sizeof(root_text));
    stpd_mst_digest_hex(mst_digest, sizeof(mst_digest));
    xml_escape_attr(g_stp.mst_config_name, mst_name, sizeof(mst_name));

    complete = append_stp_text(buf, NETLAB_MAX_MSG, &off,
        "<stp-state protocol=\"%s\" bridge-id=\"%s\" root-id=\"%s\" "
        "root-port=\"%d\" root-path-cost=\"%u\" hello-time=\"%d\" "
        "max-age=\"%d\" forward-delay=\"%d\" "
        "mst-max-hops=\"%d\" "
        "mst-name=\"%s\" mst-revision=\"%u\" mst-digest=\"%s\" "
        "mst-instances=\"%d\">\n",
        stpd_protocol_name(), bridge_text, root_text, root_port, root_path_cost,
        stpd_hello_sec(), stpd_max_age_sec(), stpd_forward_delay_sec(),
        stpd_mst_max_hops(), mst_name, g_stp.mst_revision, mst_digest,
        g_stp.mst_instance_count);

    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        stp_mst_instance_state *inst = &g_stp.mst_instances[i];
        char inst_root[32];
        char vlans[192];

        if (!inst->valid)
            continue;
        stp_format_bridge_id(stp_bridge_id_is_zero(inst->selected_root_id) ?
                             inst->bridge_id : inst->selected_root_id,
                             inst_root, sizeof(inst_root));
        format_mst_vlan_list(inst, vlans, sizeof(vlans));
        if (!append_stp_text(buf, NETLAB_MAX_MSG, &off,
            "  <mst-instance id=\"%d\" bridge-priority=\"%d\" "
            "root-id=\"%s\" root-port=\"%d\" root-path-cost=\"%u\" "
            "remaining-hops=\"%d\" vlan-count=\"%d\" vlans=\"%s\"/>\n",
            inst->id, inst->bridge_priority, inst_root, inst->root_port,
            inst->selected_root_path_cost, inst->selected_remaining_hops,
            inst->vlan_count, vlans)) {
            complete = false;
            break;
        }
    }

    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        char ifname[32];
        char proto_err[192];
        char guard_err[192];
        char reset_reason[96];

        if (!ps->valid)
            continue;
        if (!ps->rstp_enabled && ps->rx_bpdus == 0 && ps->tx_bpdus == 0 &&
            !ps->protocol_blocked && !ps->guard_blocked)
            continue;

        ifname_from_port(ps->port, ifname, sizeof(ifname));
        xml_escape_attr(ps->protocol_last_error, proto_err, sizeof(proto_err));
        xml_escape_attr(ps->guard_last_error, guard_err, sizeof(guard_err));
        xml_escape_attr(ps->last_sync_reset_reason, reset_reason,
                        sizeof(reset_reason));

        if (!append_stp_text(buf, NETLAB_MAX_MSG, &off,
            "  <port interface=\"%s\" port=\"%d\" vlan=\"%d\" "
            "enabled=\"%s\" role=\"%s\" state=\"%s\" "
            "edge=\"%s\" root-protection=\"%s\" loop-protection=\"%s\" "
            "path-cost=\"%d\" port-priority=\"%d\" port-id=\"0x%04x\" "
            "guard-state=\"%s\" block-reason=\"%s\" "
            "protocol-blocked=\"%s\" protocol-blocks=\"%llu\" "
            "loop-peer-port=\"%d\" loop-age=\"%d\" "
            "rx-bpdus=\"%llu\" tx-bpdus=\"%llu\" "
            "rx-proposals=\"%llu\" rx-agreements=\"%llu\" "
            "tx-proposals=\"%llu\" tx-agreements=\"%llu\" tx-tc=\"%llu\" "
            "last-rx-age=\"%d\" last-tx-age=\"%d\" "
            "last-proposal-age=\"%d\" last-agreement-age=\"%d\" "
            "root-id=\"%s\" bridge-id=\"%s\" "
            "sync-resets=\"%llu\" last-sync-reset-age=\"%d\" "
            "sync-reset-reason=\"%s\" "
            "protocol-last-error=\"%s\" guard-last-error=\"%s\"/>\n",
            ifname, ps->port, ps->vlan,
            ps->rstp_enabled ? "true" : "false",
            stp_port_role(ps), stp_port_state(ps),
            ps->edge ? "true" : "false",
            ps->root_protection ? "true" : "false",
            ps->loop_protection ? "true" : "false",
            stpd_port_path_cost(ps->port),
            stpd_port_priority(ps->port),
            stp_port_id(ps->port, stpd_port_priority(ps->port)),
            ps->guard_blocked ? "blocked" :
                ps->bpdu_guard_enabled ? "enabled" :
                ps->edge ? "edge" : "off",
            block_reason_name(ps->block_reason),
            ps->protocol_blocked ? "true" : "false",
            (unsigned long long)ps->protocol_blocks,
            ps->loop_peer_port,
            ps->loop_last_seen ? (int)(now - ps->loop_last_seen) : -1,
            (unsigned long long)ps->rx_bpdus,
            (unsigned long long)ps->tx_bpdus,
            (unsigned long long)ps->proposal_bpdus,
            (unsigned long long)ps->agreement_bpdus,
            (unsigned long long)ps->tx_proposal_bpdus,
            (unsigned long long)ps->tx_agreement_bpdus,
            (unsigned long long)ps->tx_tc_bpdus,
            ps->last_seen ? (int)(now - ps->last_seen) : -1,
            ps->last_tx ? (int)(now - ps->last_tx) : -1,
            ps->last_proposal_seen ? (int)(now - ps->last_proposal_seen) : -1,
            ps->last_agreement_seen ? (int)(now - ps->last_agreement_seen) : -1,
            ps->last_root_id, ps->last_bridge_id,
            (unsigned long long)ps->sync_resets,
            ps->last_sync_reset ? (int)(now - ps->last_sync_reset) : -1,
            reset_reason[0] ? reset_reason : "-",
            proto_err, guard_err)) {
            complete = false;
            break;
        }
    }
    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        char ifname[32];

        if (!ps->valid)
            continue;
        ifname_from_port(ps->port, ifname, sizeof(ifname));
        for (int j = 0; j < STPD_MAX_MSTI; j++) {
            stp_port_msti_stats *ms = &ps->msti[j];
            char reset_reason[96];

            if (!ms->valid)
                continue;
            if (ms->role == STP_ROLE_DISABLED && ms->rx_bpdus == 0)
                continue;
            xml_escape_attr(ms->last_sync_reset_reason, reset_reason,
                            sizeof(reset_reason));
            if (!append_stp_text(buf, NETLAB_MAX_MSG, &off,
                "  <mst-port interface=\"%s\" port=\"%d\" "
                "msti=\"%d\" role=\"%s\" state=\"%s\" "
                "rx-bpdus=\"%llu\" proposals=\"%llu\" "
                "agreements=\"%llu\" tx-proposals=\"%llu\" "
                "tx-agreements=\"%llu\" last-rx-age=\"%d\" "
                "last-proposal-age=\"%d\" last-agreement-age=\"%d\" "
                "last-tx-age=\"%d\" agreement-pending=\"%s\" "
                "path-cost=\"%d\" port-priority=\"%d\" port-id=\"0x%04x\" "
                "remaining-hops=\"%d\" peer-role=\"%s\" "
                "sync-resets=\"%llu\" last-sync-reset-age=\"%d\" "
                "sync-reset-reason=\"%s\" last-flags=\"0x%02x\" "
                "block-reason=\"%s\"/>\n",
                ifname, ps->port, ms->mstid, stp_role_name(ms->role),
                ms->protocol_blocked ? "discarding" :
                    ms->role == STP_ROLE_DISABLED ? "disabled" :
                    "forwarding",
                (unsigned long long)ms->rx_bpdus,
                (unsigned long long)ms->proposal_bpdus,
                (unsigned long long)ms->agreement_bpdus,
                (unsigned long long)ms->tx_proposal_bpdus,
                (unsigned long long)ms->tx_agreement_bpdus,
                ms->last_seen ? (int)(now - ms->last_seen) : -1,
                ms->last_proposal_seen ?
                    (int)(now - ms->last_proposal_seen) : -1,
                ms->last_agreement_seen ?
                    (int)(now - ms->last_agreement_seen) : -1,
                ms->last_tx ? (int)(now - ms->last_tx) : -1,
                ms->agreement_due_until > now ? "true" : "false",
                stpd_msti_port_path_cost(ms->mstid, ps->port),
                stpd_msti_port_priority(ms->mstid, ps->port),
                stp_port_id(ps->port,
                            stpd_msti_port_priority(ms->mstid, ps->port)),
                ms->remaining_hops,
                stp_role_name(ms->last_peer_role),
                (unsigned long long)ms->sync_resets,
                ms->last_sync_reset ? (int)(now - ms->last_sync_reset) : -1,
                reset_reason[0] ? reset_reason : "-",
                ms->last_flags & 0xff,
                block_reason_name(ms->block_reason))) {
                complete = false;
                break;
            }
        }
        if (!complete)
            break;
    }
    if (complete)
        complete = append_stp_text(buf, NETLAB_MAX_MSG, &off,
                                   "</stp-state>\n");
    pthread_mutex_unlock(&g_stp.lock);

    if (complete)
        send_stp_response(conn, msg, 0, buf, off);
    else
        send_stp_capacity_error(conn, msg);
    free(buf);
}

void stp_show_send_monitor(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    size_t off = 0;
    bool complete = true;
    time_t now = nl_monotonic_seconds();
    u64 sync_resets = 0;

    if (!buf) {
        send_stp_capacity_error(conn, msg);
        return;
    }
    pthread_mutex_lock(&g_stp.lock);
    for (int i = 0; i < STPD_MAX_PORTS; i++)
        if (g_stp.ports[i].valid)
            sync_resets += g_stp.ports[i].sync_resets;
    complete = append_stp_text(buf, NETLAB_MAX_MSG, &off,
        "<stp-monitor total-bpdus=\"%llu\" malformed-bpdus=\"%llu\" "
        "topology-change-bpdus=\"%llu\" proposals=\"%llu\" "
        "agreements=\"%llu\" mac-flushes=\"%llu\" "
        "tx-bpdus=\"%llu\" tx-proposals=\"%llu\" "
        "tx-agreements=\"%llu\" tx-tc=\"%llu\" tx-failures=\"%llu\" "
        "sync-resets=\"%llu\" "
        "packetd-reconnects=\"%llu\" last-rx-age=\"%d\" "
        "last-mac-flush-age=\"%d\" "
        "last-mac-flush-scope=\"%s\" "
        "last-mac-flush-reason=\"%s\">\n",
        (unsigned long long)g_stp.total_bpdus,
        (unsigned long long)g_stp.malformed_bpdus,
        (unsigned long long)g_stp.topology_change_bpdus,
        (unsigned long long)g_stp.proposal_bpdus,
        (unsigned long long)g_stp.agreement_bpdus,
        (unsigned long long)g_stp.mac_flushes,
        (unsigned long long)g_stp.tx_bpdus,
        (unsigned long long)g_stp.tx_proposal_bpdus,
        (unsigned long long)g_stp.tx_agreement_bpdus,
        (unsigned long long)g_stp.tx_tc_bpdus,
        (unsigned long long)g_stp.tx_failures,
        (unsigned long long)sync_resets,
        (unsigned long long)g_stp.packetd_reconnects,
        g_stp.last_rx ? (int)(now - g_stp.last_rx) : -1,
        g_stp.last_mac_flush ? (int)(now - g_stp.last_mac_flush) : -1,
        g_stp.last_mac_flush_scope[0] ? g_stp.last_mac_flush_scope : "-",
        g_stp.last_mac_flush_reason[0] ? g_stp.last_mac_flush_reason : "-");

    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        const char *guard_state;
        const char *protocol;
        char ifname[64];
        char reset_reason[96];

        if (!ps->valid)
            continue;
        guard_state = ps->guard_blocked ? "blocked" :
                      ps->bpdu_guard_enabled ? "enabled" :
                      ps->edge ? "edge" : "off";
        protocol = ps->rx_bpdus > 0 ?
                   stp_bpdu_protocol_name(ps->last_version,
                                          ps->last_type) : "-";
        ifname_from_port(ps->port, ifname, sizeof(ifname));
        xml_escape_attr(ps->last_sync_reset_reason, reset_reason,
                        sizeof(reset_reason));
        if (!append_stp_text(buf, NETLAB_MAX_MSG, &off,
            "  <port interface=\"%s\" port=\"%d\" vlan=\"%d\" "
            "rx-bpdus=\"%llu\" stp=\"%llu\" rstp=\"%llu\" mstp=\"%llu\" "
            "tcn=\"%llu\" unknown=\"%llu\" malformed=\"%llu\" "
            "topology-change-bpdus=\"%llu\" proposals=\"%llu\" "
            "agreements=\"%llu\" mac-flushes=\"%llu\" "
            "last-mac-flush-age=\"%d\" "
            "last-mac-flush-scope=\"%s\" "
            "last-mac-flush-reason=\"%s\" "
            "last-proposal-age=\"%d\" last-agreement-age=\"%d\" "
            "last-age=\"%d\" protocol=\"%s\" version=\"%d\" "
            "bpdu-type=\"0x%02x\" flags=\"0x%02x\" "
            "peer-timers-valid=\"%s\" peer-message-age-ticks=\"%u\" "
            "peer-hello-time-ticks=\"%u\" peer-max-age-ticks=\"%u\" "
            "peer-forward-delay-ticks=\"%u\" "
            "root-id=\"%s\" bridge-id=\"%s\" port-id=\"0x%04x\" "
            "rstp-enabled=\"%s\" tx-bpdus=\"%llu\" "
            "tx-proposals=\"%llu\" tx-agreements=\"%llu\" "
            "tx-tc=\"%llu\" tx-failures=\"%llu\" sync-resets=\"%llu\" "
            "last-sync-reset-age=\"%d\" sync-reset-reason=\"%s\" "
            "last-tx-age=\"%d\" "
            "edge=\"%s\" root-protection=\"%s\" loop-protection=\"%s\" "
            "guard-enabled=\"%s\" guard-state=\"%s\" "
            "protocol-blocked=\"%s\" block-reason=\"%s\" "
            "guard-blocks=\"%llu\" guard-last-error=\"%s\"/>\n",
            ifname, ps->port, ps->vlan,
            (unsigned long long)ps->rx_bpdus,
            (unsigned long long)ps->stp_bpdus,
            (unsigned long long)ps->rstp_bpdus,
            (unsigned long long)ps->mstp_bpdus,
            (unsigned long long)ps->tcn_bpdus,
            (unsigned long long)ps->unknown_bpdus,
            (unsigned long long)ps->malformed_bpdus,
            (unsigned long long)ps->topology_change_bpdus,
            (unsigned long long)ps->proposal_bpdus,
            (unsigned long long)ps->agreement_bpdus,
            (unsigned long long)ps->mac_flushes,
            ps->last_mac_flush ? (int)(now - ps->last_mac_flush) : -1,
            ps->last_mac_flush_scope[0] ? ps->last_mac_flush_scope : "-",
            ps->last_mac_flush_reason[0] ? ps->last_mac_flush_reason : "-",
            ps->last_proposal_seen ? (int)(now - ps->last_proposal_seen) : -1,
            ps->last_agreement_seen ? (int)(now - ps->last_agreement_seen) : -1,
            ps->last_seen ? (int)(now - ps->last_seen) : -1,
            protocol, ps->last_version, ps->last_type, ps->last_flags,
            ps->last_peer_timers_valid ? "true" : "false",
            ps->last_peer_message_age_ticks,
            ps->last_peer_hello_time_ticks,
            ps->last_peer_max_age_ticks,
            ps->last_peer_forward_delay_ticks,
            ps->last_root_id, ps->last_bridge_id, ps->last_port_id,
            ps->rstp_enabled ? "true" : "false",
            (unsigned long long)ps->tx_bpdus,
            (unsigned long long)ps->tx_proposal_bpdus,
            (unsigned long long)ps->tx_agreement_bpdus,
            (unsigned long long)ps->tx_tc_bpdus,
            (unsigned long long)ps->tx_failures,
            (unsigned long long)ps->sync_resets,
            ps->last_sync_reset ? (int)(now - ps->last_sync_reset) : -1,
            reset_reason[0] ? reset_reason : "-",
            ps->last_tx ? (int)(now - ps->last_tx) : -1,
            ps->edge ? "true" : "false",
            ps->root_protection ? "true" : "false",
            ps->loop_protection ? "true" : "false",
            ps->bpdu_guard_enabled ? "true" : "false",
            guard_state,
            ps->protocol_blocked ? "true" : "false",
            block_reason_name(ps->block_reason),
            (unsigned long long)ps->guard_blocks,
            ps->guard_last_error)) {
            complete = false;
            break;
        }
    }
    if (complete)
        complete = append_stp_text(buf, NETLAB_MAX_MSG, &off,
                                   "</stp-monitor>\n");
    pthread_mutex_unlock(&g_stp.lock);

    if (complete)
        send_stp_response(conn, msg, 0, buf, off);
    else
        send_stp_capacity_error(conn, msg);
    free(buf);
}
