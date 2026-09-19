#include <time.h>
static time_t fixture_wall = 1000;
static time_t fixture_time(time_t *out) {
    if (out) *out = fixture_wall;
    return fixture_wall;
}
#define time fixture_time
#define main lacpd_daemon_entry
#include "../vendor/netlab/sbin/lacpd/main.c"
#undef main
#undef time
#include <assert.h>

static const char *active_path;
static bool links[25], attached[25];
static int fail_port, changes, transmissions;
static int lag_error;
static uint64_t hardware_generation = 1;
static const char *lag_reply;
static char status_xml[32768];
nl_msg_hdr *nl_msg_alloc(u32 length) { return calloc(1, sizeof(nl_msg_hdr) + length); }
void nl_msg_free(nl_msg_hdr *msg) { free(msg); }
nl_status nl_send(nl_conn *conn, nl_msg_hdr *msg) {
    (void)conn; assert(msg->payload_len < sizeof(status_xml));
    memcpy(status_xml, msg->payload, msg->payload_len); status_xml[msg->payload_len] = '\0'; return NL_OK;
}
nl_status nl_send_response(nl_conn *conn, u64 request, s32 error) {
    (void)conn; (void)request; (void)error; assert(false); return NL_ERR;
}
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
void nl_config_file_path(char *out, size_t capacity, const char *name) {
    assert(!strcmp(name, "active.conf")); snprintf(out, capacity, "%s", active_path);
}
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) { (void)name; return fallback; }
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service, nl_rpc_method method,
                  u64 tx, const u8 *payload, int length, u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)tx; (void)length; (void)timeout;
    assert(caller == NL_DAEMON_LACPD && service == NL_DAEMON_SWITCHD); *error = 0;
    int port = 0, lag = 0;
    if (method == NL_SWITCHD_LAG_GET_ALL) {
        if (lag_error) { *error = lag_error; return 0; }
        assert(lag_reply && (int)strlen(lag_reply) < capacity);
        memcpy(out, lag_reply, strlen(lag_reply)); return (int)strlen(lag_reply);
    }
    if (method == NL_SWITCHD_PORT_GET_STATE) {
        assert(sscanf((const char *)payload, "port=%d", &port) == 1 && port > 0 && port <= 24);
        return snprintf((char *)out, (size_t)capacity, "link=%s", links[port] ? "UP" : "DOWN");
    }
    assert(method == NL_SWITCHD_LAG_ADD_PORT || method == NL_SWITCHD_LAG_DEL_PORT);
    uint64_t generation = 0;
    assert(nl_lag_runtime_request_parse((const char *)payload, true, &lag, &port, &generation));
    assert(lag == 7 && port > 0 && port <= 24 && generation == hardware_generation);
    ++changes;
    if (port == fail_port) { *error = NL_ERR_SDK_CALL_FAILED; return 0; }
    attached[port] = method == NL_SWITCHD_LAG_ADD_PORT; return 0;
}
int lacp_packet_tx(const char *path, int port, const u8 *frame, int length) {
    (void)path; assert(port > 0 && frame && length == 128); ++transmissions; return 0;
}
static void partner(lacp_lag *lag, lacp_member *member, int partner_port) {
    member->partner_valid = true; member->last_rx = nl_monotonic_seconds(); member->link_up = true;
    member->partner = (lacp_info){.system_priority = 32768, .system_mac = {2,0,0,0,0,2},
        .key = 99, .port_priority = 32768, .port = (u16)partner_port,
        .state = LACP_STATE_AGGREGATION | LACP_STATE_SYNC};
    member->partner_view_of_us = (lacp_info){.system_priority = g_lacp.system_priority,
        .key = lag_actor_key(lag), .port_priority = member_actor_port_priority(member), .port = (u16)member->port};
    memcpy(member->partner_view_of_us.system_mac, g_lacp.actor_mac, 6);
}
int main(int argc, char **argv) {
    assert(argc == 4);
    assert(nl_ifid_resolver_init(NULL) == NL_OK && !nl_port_scope_init("lacpd"));
    assert(!pthread_mutex_init(&g_lacp.lock, NULL));
    load_system_mac(g_actor_mac); memcpy(g_lacp.actor_mac, g_actor_mac, 6);
    nl_port_scope_on_resume_monotonic(resume_member_timers);
    active_path = argv[1]; assert(load_config_locked(true));
    lacp_lag *lag = &g_lacp.lags[0];
    assert(lag->configured && lag->n_members == 2 && lag->min_links == 2);
    lag_reply = "<lags native-generation=\"0000000000000001\"><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"ok\" code=\"0\"/></lag></lags>";
    poll_lag_hw();
    assert(g_lacp.native_required && g_lacp.native_hw_valid && g_lacp.native_generation == 1);
    lacp_member_ref first = {0,1}, second = {0,5};
    links[1] = links[5] = true;
    run_member_cycle(&first); run_member_cycle(&second);
    assert(!changes && transmissions == 2 && !attached[1] && !attached[5]);
    assert(lag_actor_key(lag) == 1);
    partner(lag, &lag->members[0], 1); partner(lag, &lag->members[1], 2);
    lag->members[1].partner.state &= (u8)~LACP_STATE_SYNC;
    assert(!member_oper_up(lag, &lag->members[0], nl_monotonic_seconds()));
    lag->members[1].partner.state |= LACP_STATE_SYNC;
    assert(member_oper_up(lag, &lag->members[0], nl_monotonic_seconds()));
    assert(!(actor_state(lag, &lag->members[0], nl_monotonic_seconds()) & LACP_STATE_DISTRIBUTING));
    fail_port = 1; run_member_cycle(&first);
    assert(!lag->members[0].hw_attached && !attached[1]);
    fail_port = 0; run_member_cycle(&first); run_member_cycle(&second);
    assert(attached[1] && attached[5] && lag->members[0].hw_attached);
    assert(actor_state(lag, &lag->members[0], nl_monotonic_seconds()) & LACP_STATE_DISTRIBUTING);
    assert(load_config_locked(true) && lag->members[0].partner_valid && lag->members[0].hw_attached);

    /* Clock corrections must neither expire a live partner nor extend an
     * expired partner or force a premature periodic transmission. */
    int saved_interval = lag->tx_interval_sec;
    lag->tx_interval_sec = 60;
    const time_t corrections[] = {1, 2000000000};
    for (unsigned i = 0; i < sizeof(corrections) / sizeof(*corrections); ++i) {
        fixture_wall = corrections[i];
        assert(fixture_time(NULL) == corrections[i]);
        partner(lag, &lag->members[0], 1); partner(lag, &lag->members[1], 2);
        lag->members[0].last_tx = nl_monotonic_seconds();
        lacp_member_action clock_action;
        prepare_member_action_locked(&first, true, &clock_action);
        assert(lag->members[0].partner_valid && !clock_action.send_pdu && !clock_action.change_hw);
        lag->members[0].last_rx -= partner_timeout_sec(&lag->members[0]) + 1;
        prepare_member_action_locked(&first, true, &clock_action);
        assert(!lag->members[0].partner_valid && clock_action.change_hw && !clock_action.desired_hw);
    }
    lag->tx_interval_sec = saved_interval;
    partner(lag, &lag->members[0], 1); partner(lag, &lag->members[1], 2);

    lag_error = NL_ERR_PRE_STATE_MISSING;
    poll_lag_hw();
    assert(!lag->lag_id && !lag->members[0].hw_attached && !lag->members[1].hw_attached);
    assert(!(actor_state(lag, &lag->members[0], nl_monotonic_seconds()) & LACP_STATE_DISTRIBUTING));
    nl_msg_hdr query = {0}; handle_get_lacp(NULL, &query);
    assert(strstr(status_xml, "status=\"unknown\"") && strstr(status_xml, "health=\"hardware-readback\""));
    lag_error = 0;
    lag_reply = "<lags native-generation=\"0000000000000001\"><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"ok\" code=\"0\"/><member port=\"1\"/><member port=\"5\"/></lag></lags>";
    poll_lag_hw(); assert(lag->lag_id == 7 && lag->members[0].hw_attached);
    handle_get_lacp(NULL, &query);
    assert(strstr(status_xml, "status=\"up\"") && strstr(status_xml, "up-members=\"2\""));

    /* Preserve a real encoded peer PDU across a new SDK lifetime. The old
     * numeric handle is reused, but neither old partner state nor a queued
     * PDU may reauthorize membership. Same-generation reads preserve it. */
    u8 peer_pdus[2][128];
    for (int i = 0; i < 2; ++i) {
        lacp_member *m = &lag->members[i];
        assert(build_lacpdu(lag, m, peer_pdus[i], sizeof(peer_pdus[i])) == 128);
        memcpy(peer_pdus[i] + 6, m->partner.system_mac, 6);
        lacp_write_info(peer_pdus[i] + 18, &m->partner);
        lacp_write_info(peer_pdus[i] + 38, &m->partner_view_of_us);
    }
    u64 old_packet_time = nl_port_scope_clock();
    u64 sent = lag->members[0].tx_pdus, received = lag->members[0].rx_pdus;
    poll_lag_hw();
    assert(lag->members[0].partner_valid && lag->members[0].hw_attached);
    hardware_generation = 2;
    attached[1] = attached[5] = false;
    lag_reply = "<lags native-generation=\"0000000000000002\"><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"ok\" code=\"0\"/></lag></lags>";
    poll_lag_hw();
    assert(g_lacp.native_generation == 2 && lag->lag_id == 7);
    assert(!lag->members[0].partner_valid && !lag->members[1].partner_valid);
    assert(!lag->members[0].link_up && !lag->members[1].link_up);
    assert(lag->members[0].tx_pdus == sent && lag->members[0].rx_pdus == received);
    int generation_changes = changes;
    run_member_cycle(&first); run_member_cycle(&second);
    assert(changes == generation_changes && !attached[1] && !attached[5]);
    receive_lacpdu(peer_pdus[0], 128, 1, old_packet_time);
    receive_lacpdu(peer_pdus[0], 128, 1, g_lacp.native_epoch_started);
    assert(!lag->members[0].partner_valid && lag->members[0].rx_pdus == received);
    u64 fresh;
    do { fresh = nl_port_scope_clock(); } while (fresh <= g_lacp.native_epoch_started);
    receive_lacpdu(peer_pdus[0], 128, 1, fresh);
    receive_lacpdu(peer_pdus[1], 128, 5, fresh);
    run_member_cycle(&first); run_member_cycle(&second);
    assert(changes == generation_changes + 2 && attached[1] && attached[5]);
    assert(lag->members[0].rx_pdus == received + 1);

    const char *bad_snapshots[] = {
        "<lags></lags>", "<lags native-generation=\"0000000000000000\"></lags>",
        "<lags native-generation=\"2\"></lags>", "<lags native-generation=\"0000000000000002\">",
    };
    const char *valid_reply = "<lags native-generation=\"0000000000000002\"><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"ok\" code=\"0\"/><member port=\"1\"/><member port=\"5\"/></lag></lags>";
    for (size_t i = 0; i < sizeof(bad_snapshots) / sizeof(bad_snapshots[0]); ++i) {
        lag_reply = bad_snapshots[i]; poll_lag_hw();
        assert(!g_lacp.native_hw_valid && !lag->lag_id);
        generation_changes = changes;
        run_member_cycle(&first); assert(changes == generation_changes);
        lag_reply = valid_reply; poll_lag_hw();
        assert(g_lacp.native_hw_valid && lag->members[0].partner_valid && lag->members[0].hw_attached);
    }

    uint64_t parsed = 0;
    int parsed_lag, parsed_port;
    assert(nl_lag_runtime_request_parse("7 1", false, &parsed_lag, &parsed_port, &parsed));
    assert(!parsed && parsed_lag == 7 && parsed_port == 1);
    assert(!nl_lag_runtime_request_parse("7 1", true, &parsed_lag, &parsed_port, &parsed));
    assert(!nl_lag_runtime_request_parse("7 1 generation=0000000000000000", true, &parsed_lag, &parsed_port, &parsed));
    assert(!nl_lag_runtime_request_parse("7 1 generation=0000000000000002 extra", true, &parsed_lag, &parsed_port, &parsed));

    int before_changes = changes, before_tx = transmissions;
    assert(!nl_port_scope_begin(99, 15, 20));
    links[1] = false; run_member_cycle(&first);
    assert(changes == before_changes && transmissions == before_tx && attached[1]);
    time_t before = lag->members[1].last_rx;
    resume_member_timers(15, 8); assert(lag->members[1].last_rx == before);
    assert(!nl_port_scope_end(99)); run_member_cycle(&first); run_member_cycle(&second);
    assert(!attached[1] && !attached[5]);

    active_path = argv[2]; assert(load_config_locked(true));
    assert(!strcmp(lag->mode, "passive") && !lag->members[0].partner_valid);
    before_tx = transmissions; links[1] = true;
    run_member_cycle(&first); assert(transmissions == before_tx && !attached[1]);
    active_path = argv[3]; assert(load_config_locked(true));
    assert(!strcmp(lag->mode, "static")); links[5] = false;
    run_member_cycle(&second); run_member_cycle(&first); assert(!attached[1]);
    links[5] = true; run_member_cycle(&second); run_member_cycle(&first);
    assert(attached[1] && attached[5] && transmissions == before_tx);
    hardware_generation = 3;
    attached[1] = attached[5] = false;
    lag_reply = "<lags native-generation=\"0000000000000003\"><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"ok\" code=\"0\"/></lag></lags>";
    poll_lag_hw();
    run_member_cycle(&first); assert(!attached[1]); /* Second member has no fresh link sample yet. */
    run_member_cycle(&second); run_member_cycle(&first);
    assert(attached[1] && attached[5] && transmissions == before_tx);
    lacp_lag *sibling = &g_lacp.lags[1]; init_lag_defaults(sibling, 1);
    sibling->configured = true; sibling->n_members = 1; sibling->members[0].port = 9;
    lag_reply = "<lags native-generation=\"0000000000000003\"><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"error\" code=\"-1\"/><member port=\"1\"/></lag>"
        "<lag ae=\"1\" name=\"ae1\" id=\"9\" logical-port=\"101\">"
        "<member-readback status=\"ok\" code=\"0\"/><member port=\"9\"/></lag></lags>";
    poll_lag_hw();
    assert(!lag->lag_id && !lag->members[0].hw_attached);
    assert(sibling->lag_id == 9 && sibling->members[0].hw_attached);
    active_path = "/missing/configuration"; assert(!load_config_locked(true) && lag->configured);
    pthread_mutex_destroy(&g_lacp.lock);
    puts("production LACP: SDK restart, stale PDUs, negotiation, minimum-links, static/passive modes and scope passed");
    return 0;
}
