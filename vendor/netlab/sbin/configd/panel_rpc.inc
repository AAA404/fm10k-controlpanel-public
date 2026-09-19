/*
 * FM10K Web transaction entry, included after configd's existing helpers.
 * The global candidate, journal, confirmed timer and immutable snapshots
 * remain the only configuration authority. No web-owned active JSON file.
 */
#define PANEL_ROOT "/netlab:netlab-config/chassis/fm10k-panel"
#include "netlab/fm10k_board_types.h"

static bool panel_job_valid(const char *job) {
    if (!job || strlen(job) != 32) return false;
    for (int i = 0; i < 32; ++i)
        if (!((job[i] >= '0' && job[i] <= '9') ||
              (job[i] >= 'a' && job[i] <= 'f'))) return false;
    return true;
}
static bool panel_managed(void) {
    return g_ctx.active && nl_yang_exists(g_ctx.active, PANEL_ROOT);
}
static bool panel_board_bound(void) {
    /*
     * The native switchd adapter must advertise this contract from its SDK
     * owner thread after profile, ABI and board identity checks. Neither an
     * environment flag nor a Web request can assert this capability.
     */
    const char *profile = g_ctx.active ? nl_yang_get(g_ctx.active, PANEL_ROOT "/profile") : NULL;
    if (!nl_fm10k_profile_known(profile)) return false;
    if (configd_native_control_mode()) {
        u64 generation = 0;
        bool bound = false;
        if (configd_native_status(profile, &generation, &bound) || generation != g_ctx.native_generation || !bound) {
            g_ctx.hw_out_of_sync = true;
            return false;
        }
        return !g_ctx.hw_out_of_sync;
    }
    char expected_profile[80];
    snprintf(expected_profile, sizeof(expected_profile), "\"profile\":\"%s\"", profile);
    nl_rpc_response reply = {0};
    int n = nl_rpc_call_alloc_ex(
        nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET", "/var/run/netlab/switchd.sock"),
        NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD, 132, 0,
        (const u8 *)"contract", 8, 3000, &reply);
    bool bound = n > 0 && reply.error_code == 0 &&
        strstr((const char *)reply.payload, "\"board_hal\":\"bound\"") &&
        strstr((const char *)reply.payload, expected_profile);
    nl_rpc_response_free(&reply);
    return bound;
}
static const char *panel_confirmed_outcome(const nl_commit_confirmed *record) {
    if (g_ctx.hw_out_of_sync || g_ctx.active_authority_uncertain)
        return "uncertain";
    if (record->state == NL_CONFIRM_AWAITING)
        return record->tx_id == g_ctx.active_commit_id ? "awaiting_confirmation" : "uncertain";
    if (record->state == NL_CONFIRMED)
        return record->tx_id == g_ctx.active_commit_id ? "confirmed" : "unknown";
    /* TIMED_OUT also records unsuccessful rollback attempts. Only the
     * committed rollback journal and the exact immutable before-image prove
     * that the original configuration actually became active again. */
    nl_commit_journal journal;
    if (record->state != NL_TIMED_OUT ||
        nl_journal_get(g_ctx.active_commit_id, &journal) != NL_OK ||
        journal.state != NL_JOURNAL_COMMITTED ||
        journal.base_commit_id != record->tx_id ||
        journal.resulting_commit_id != g_ctx.active_commit_id)
        return "uncertain";
    char *before = read_commit_snapshot_xml(record->previous_commit_id);
    char *active = read_commit_snapshot_xml(g_ctx.active_commit_id);
    bool restored = before && active && strcmp(before, active) == 0;
    free(before);
    free(active);
    return restored ? "rolled_back" : "uncertain";
}
static int handle_panel_snapshot(nl_conn *conn, nl_msg_hdr *msg) {
    char *xml = g_ctx.active ? nl_yang_to_xml(g_ctx.active) : NULL;
    nl_commit_confirmed confirmed = {0};
    const char *job = g_ctx.active ? nl_yang_get(g_ctx.active, PANEL_ROOT "/job-id") : NULL;
    bool have_record = nl_confirmed_load_readonly(&confirmed) == NL_OK;
    bool pending = have_record && confirmed.state == NL_CONFIRM_AWAITING;
    s64 remaining = pending ? nl_confirmed_remaining_seconds(&confirmed) : 0;
    s64 deadline = pending ? nl_confirmed_display_deadline(&confirmed) : 0;
    const char *startup = getenv("NETLAB_FM10K_STARTUP_MODE");
    const char *stage = startup && !strcmp(startup, "control") ? "control" :
        startup && !strcmp(startup, "basic100g") ? "basic100g" : "observe";
    if (!xml) return send_text(conn, msg, NL_ERR_INVALID_VALUE, "active configuration unavailable");
    if (pending && (remaining < 0 || deadline <= 0)) {
        free(xml);
        return send_text(conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC, "commit-confirmed clock unavailable");
    }
    size_t capacity = strlen(xml) + 1024;
    char *text = malloc(capacity);
    if (!text) { free(xml); return send_text(conn, msg, -1, "out of memory"); }
    bool native_bound = panel_board_bound();
    snprintf(text, capacity,
        "<fm10k-panel-state api=\"1\" revision=\"%llu\" pending=\"%s\" "
        "job-id=\"%s\" deadline=\"%lld\" remaining-seconds=\"%lld\" synchronized=\"%s\" board-hal=\"%s\" "
        "transaction-revision=\"%llu\" transaction-state=\"%s\" startup-mode=\"%s\" recovery=\"active-replay-v1\">%s"
        "</fm10k-panel-state>",
        (unsigned long long)(g_ctx.active_commit_id + 1),
        pending ? "true" : "false", panel_job_valid(job) ? job : "",
        (long long)deadline, (long long)remaining,
        g_ctx.hw_out_of_sync || !native_bound ? "false" : "true",
        native_bound ? "bound" : "unbound",
        (unsigned long long)(have_record ? confirmed.tx_id + 1 : 0),
        have_record ? panel_confirmed_outcome(&confirmed) : "unknown", stage, xml);
    int result = send_text(conn, msg, 0, text);
    free(text); free(xml); return result;
}
static bool panel_pending(nl_commit_confirmed *out) {
    return nl_confirmed_load_readonly(out) == NL_OK &&
        out->state == NL_CONFIRM_AWAITING;
}
static bool panel_number(char *s, unsigned long long *out) {
    if (!s || !*s) return false;
    for (char *p = s; *p; ++p) if (*p < '0' || *p > '9') return false;
    char *end = NULL; errno = 0;
    *out = strtoull(s, &end, 10);
    return !errno && end && !*end;
}
static int handle_panel_recover(nl_conn *conn, nl_msg_hdr *msg) {
    char revision[21] = {0}, detail[512] = {0};
    unsigned long long expected = 0;
    if (!panel_managed() || !configd_native_control_mode())
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, "recovery requires native control mode");
    if (!msg->payload_len || msg->payload_len >= sizeof(revision))
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, "invalid recovery revision");
    memcpy(revision, msg->payload, msg->payload_len);
    if (strlen(revision) != msg->payload_len || !panel_number(revision, &expected) ||
        expected != g_ctx.active_commit_id + 1)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, "stale recovery revision");
    if (g_ctx.commit_locked || !candidate_matches_active_configuration())
        return send_text(conn, msg, NL_ERR_COMMIT_LOCKED, "pending commit or candidate edits exist");
    /* This entry shares the production authority lock. Replay and readback
     * resolve retained journals/scopes; no Web request can clear a guard. */
    nl_error_code rc = reconcile_active_state(detail, sizeof(detail));
    if (rc != NL_ERR_OK)
        return send_text(conn, msg, rc, detail[0] ? detail : nl_error_msg(rc));
    nl_commit_confirmed confirmed;
    if (nl_confirmed_load_readonly(&confirmed) == NL_OK &&
        configd_confirmed_timeout_due(&confirmed))
        configd_apply_confirmed_timeout(&confirmed);
    if (g_ctx.hw_out_of_sync || g_ctx.active_authority_uncertain || !panel_board_bound())
        return send_text(conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC, "recovery readback or expired rollback remains unresolved");
    return handle_panel_snapshot(conn, msg);
}
static bool panel_tree_allowed(nl_yang_session *tree, const char *job) {
    const char *profile = nl_yang_get(tree, PANEL_ROOT "/profile");
    const char *stored_job = nl_yang_get(tree, PANEL_ROOT "/job-id");
    const char *intent = nl_yang_get(tree, PANEL_ROOT "/intent");
    static const char *closed[] = {
        "/netlab:netlab-config/interfaces-routing",
        "/netlab:netlab-config/routing-options",
        "/netlab:netlab-config/routing-instances",
        "/netlab:netlab-config/protocols/ospf",
        "/netlab:netlab-config/protocols/bgp",
        "/netlab:netlab-config/system",
        "/netlab:netlab-config/snmp",
        "/netlab:netlab-config/chassis/port-mode",
        "/netlab:netlab-config/chassis/network-services"
    };
    const char *active_profile = g_ctx.active ? nl_yang_get(g_ctx.active, PANEL_ROOT "/profile") : NULL;
    if (!nl_fm10k_profile_known(profile) || !active_profile || strcmp(profile, active_profile) || !stored_job ||
        strcmp(job, stored_job) || !intent || !*intent) return false;
    for (size_t i = 0; i < sizeof(closed) / sizeof(closed[0]); ++i)
        if (nl_yang_has_explicit(tree, closed[i])) return false;
    return true;
}
static nl_error_code panel_prepare_candidate(const u8 *payload, u32 length,
        const char *job, struct lyd_node **previous, char *detail, size_t size) {
    *previous = nl_yang_data_clone(g_ctx.candidate);
    if (!*previous) {
        snprintf(detail, size, "cannot snapshot candidate");
        return NL_ERR_INVALID_VALUE;
    }
    /* Web supplies semantic XML, not a hash-authoritative checkpoint.
     * configd still owns canonical serialization and durable publication. */
    nl_error_code rc = validate_candidate_xml_payload_mode(
        payload, length, true, false, detail, size);
    if (rc == NL_ERR_OK && !panel_tree_allowed(g_ctx.candidate, job)) {
        snprintf(detail, size, "panel profile/job mismatch or closed L3/system namespace");
        rc = NL_ERR_INVALID_VALUE;
    }
    if (rc != NL_ERR_OK) {
        nl_yang_data_set(g_ctx.candidate, *previous);
        *previous = NULL;
    }
    return rc;
}
static int handle_panel_replace(nl_conn *conn, nl_msg_hdr *msg, bool apply) {
    if (!g_ctx.active || !g_ctx.candidate)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, "configd is not initialized");
    nl_commit_confirmed pending;
    if (panel_pending(&pending) || !candidate_matches_active_configuration())
        return send_text(conn, msg, NL_ERR_COMMIT_LOCKED, "pending commit or candidate edits exist");
    if (g_ctx.hw_out_of_sync)
        return send_text(conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC, "hardware authority is out of sync");
    if (!panel_board_bound())
        return send_text(conn, msg, NL_ERR_PFE_DOWN,
            "FM10K board HAL contract is not bound; hardware writes remain disabled");
    char *envelope = calloc((size_t)msg->payload_len + 1, 1);
    if (!envelope) return send_text(conn, msg, -1, "out of memory");
    memcpy(envelope, msg->payload, msg->payload_len);
    char *line[4] = {envelope, NULL, NULL, NULL};
    for (int i = 1; i < 4; ++i) {
        char *newline = strchr(line[i - 1], '\n');
        if (!newline) goto bad;
        *newline = 0; line[i] = newline + 1;
    }
    unsigned long long expected = 0, timeout = 0;
    if (!panel_number(line[0], &expected) || !panel_number(line[2], &timeout) ||
        timeout < 30 || timeout > 300 || !panel_job_valid(line[1]) ||
        expected != g_ctx.active_commit_id + 1 || strlen(line[3]) !=
        msg->payload_len - (size_t)(line[3] - envelope)) goto bad;
    struct lyd_node *previous = NULL;
    char detail[512] = {0};
    nl_error_code rc = panel_prepare_candidate(
        (const u8 *)line[3], (u32)strlen(line[3]), line[1], &previous, detail, sizeof(detail));
    int result;
    if (rc != NL_ERR_OK) {
        free(envelope);
        return send_text(conn, msg, rc, detail);
    }
    if (apply) {
        nl_msg_hdr *commit = nl_msg_alloc(32);
        if (!commit) { result = send_text(conn, msg, -1, "out of memory"); }
        else {
            commit->request_id = msg->request_id;
            commit->daemon_id = msg->daemon_id;
            commit->method = NL_CONFIGD_COMMIT_CONFIRMED;
            commit->payload_len = (u32)snprintf((char *)commit->payload, 32, "%llu", timeout);
            result = handle_commit(conn, commit);
            nl_msg_free(commit);
        }
    } else result = handle_commit_check(conn, msg);
    if (!apply || expected == g_ctx.active_commit_id + 1) {
        nl_yang_data_set(g_ctx.candidate, previous);
        previous = NULL;
    }
    lyd_free_all(previous); free(envelope); return result;
bad:
    free(envelope);
    return send_text(conn, msg, NL_ERR_INVALID_VALUE, "stale revision or invalid panel request envelope");
}
static int handle_panel_finish(nl_conn *conn, nl_msg_hdr *msg, bool confirm) {
    nl_commit_confirmed pending;
    char job[33] = {0};
    if (msg->payload_len != 32) return send_text(conn, msg, NL_ERR_INVALID_VALUE, "invalid job ID");
    memcpy(job, msg->payload, 32);
    const char *current = g_ctx.active ? nl_yang_get(g_ctx.active, PANEL_ROOT "/job-id") : NULL;
    if (!panel_job_valid(job) || !current || strcmp(job, current) ||
        !panel_pending(&pending) || pending.tx_id != g_ctx.active_commit_id)
        return send_text(conn, msg, NL_ERR_COMMIT_LOCKED, "job is no longer awaiting confirmation");
    if (confirm) {
        if (g_ctx.hw_out_of_sync || g_ctx.active_authority_uncertain)
            return send_text(conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC, "hardware authority is out of sync");
        pending.state = NL_CONFIRMED;
        if (nl_confirmed_save(&pending) != NL_OK)
            return send_text(conn, msg, NL_ERR_JOURNAL_CORRUPT, "confirmation could not be persisted");
    } else {
        configd_apply_confirmed_timeout(&pending);
        if (g_ctx.hw_out_of_sync || panel_pending(&pending) ||
            strcmp(panel_confirmed_outcome(&pending), "rolled_back") != 0)
            return send_text(conn, msg, NL_ERR_ROLLBACK_FAILED, "configuration rollback was not verified");
    }
    return send_text(conn, msg, NL_ERR_OK, "ok");
}
