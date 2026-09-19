#define main stpd_daemon_entry
#include "../vendor/netlab/sbin/stpd/main.c"
#undef main
#include <assert.h>

static const char *active_path;
static const char *lag_reply = "<lags></lags>";
static int lag_error;
static int hardware[256], changed_ports[128], changed_states[128], changed;
static int fail_block_port;

void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
void nl_config_file_path(char *out, size_t capacity, const char *filename) {
    assert(!strcmp(filename, "active.conf")); snprintf(out, capacity, "%s", active_path);
}
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) { (void)name; return fallback; }
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service, nl_rpc_method method,
                  u64 tx, const u8 *payload, int length, u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)tx; (void)payload; (void)length; (void)timeout;
    assert(caller == NL_DAEMON_STPD && service == NL_DAEMON_SWITCHD && method == NL_SWITCHD_LAG_GET_ALL);
    assert((int)strlen(lag_reply) < capacity);
    memcpy(out, lag_reply, strlen(lag_reply)); *error = lag_error; return (int)strlen(lag_reply);
}
bool stp_switchd_port_link_up(const char *socket, int port) { (void)socket; return port > 0 && port <= 24; }
int stp_switchd_collect_hardware_port_vlans(const char *socket, int port, int *vlans, int capacity) {
    (void)socket; assert(port > 0 && capacity > 0); vlans[0] = 1; return 1;
}
int stp_switchd_set_port_stp_state(const char *socket, int port, int vid, int state) {
    (void)socket; assert(port > 0 && port < 256 && vid == 1 && (state == 3 || state == 4));
    if (port == fail_block_port && state == 4) return NL_ERR_SDK_CALL_FAILED;
    assert(changed < 128); changed_ports[changed] = port; changed_states[changed++] = state;
    hardware[port] = state; return 0;
}
int stp_switchd_clear_dynamic_macs(const char *socket, int port, int vid) {
    (void)socket; (void)port; (void)vid; return 0;
}
int stp_switchd_get_mac_snapshot(const char *socket, nl_mac_snapshot *snapshot) {
    (void)socket; memset(snapshot, 0, sizeof(*snapshot)); return -1;
}
void nl_mac_snapshot_reset(nl_mac_snapshot *snapshot) { (void)snapshot; }

static void lag_mapping(void) {
    const char *xml = "<netlab-config><interfaces>"
        "<interface><name>et-0/0/0</name><ether-options><ieee8023ad>ae0</ieee8023ad></ether-options></interface>"
        "<interface><name>et-0/0/4</name><ether-options><ieee8023ad>ae0</ieee8023ad></ether-options></interface>"
        "<interface><name>et-0/0/8</name><ether-options><ieee8023ad>ae1</ieee8023ad></ether-options></interface>"
        "</interfaces></netlab-config>";
    stp_lag_load_config(xml);
    assert(stp_port_from_name("ae0") == 64 && stp_port_from_name("ae1") == 65);
    assert(stp_port_from_name("ae00") == -1 && stp_port_from_name("ae64") == -1);
    assert(stp_lag_ingress(1) == -1 && stp_lag_ingress(13) == 13);
    lag_reply = "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member port=\"5\"/></lag><lag ae=\"1\" name=\"ae1\" id=\"9\" logical-port=\"101\">"
        "<member port=\"9\"/></lag></lags>";
    assert(stp_lag_refresh("fixture"));
    assert(stp_lag_ingress(1) == -1 && stp_lag_ingress(5) == 64 && stp_lag_ingress(9) == 65);
    assert(stp_lag_egress(64) == 5 && stp_lag_hardware_port(64) == 100);
    assert(stp_port_scope_mask(64) == 0x11 && stp_port_scope_mask(65) == 0x100);
    assert(!nl_port_scope_begin(22, 15, 50)); assert(stp_port_paused(64) && !stp_port_paused(65));
    assert(!nl_port_scope_end(22));
    const char *valid = lag_reply;
    lag_reply = "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"error\" code=\"-1\"/><member port=\"5\"/></lag>"
        "<lag ae=\"1\" name=\"ae1\" id=\"9\" logical-port=\"101\">"
        "<member-readback status=\"ok\" code=\"0\"/><member port=\"9\"/></lag></lags>";
    assert(stp_lag_refresh("fixture"));
    assert(stp_lag_egress(64) == -1 && stp_lag_hardware_port(64) == -1);
    assert(stp_lag_egress(65) == 9 && stp_lag_hardware_port(65) == 101);
    const char *invalid[] = {
        "<lags><lag ae=\"0\" name=\"ae1\" id=\"7\" logical-port=\"100\"></lag></lags>",
        "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\"><member port=\"1\"/><member port=\"1\"/></lag></lags>",
        "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\"><member port=\"13\"/></lag></lags>",
        "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
    };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        lag_reply = invalid[i]; assert(!stp_lag_refresh("fixture"));
        assert(stp_lag_hardware_port(64) == -1 && stp_lag_egress(64) == -1);
    }
    lag_reply = valid; lag_error = NL_ERR_RPC_TIMEOUT;
    assert(!stp_lag_refresh("fixture")); lag_error = 0;
}

int main(int argc, char **argv) {
    assert(argc == 2); active_path = argv[1];
    assert(nl_ifid_resolver_init(NULL) == NL_OK && !nl_port_scope_init("stpd"));
    assert(!pthread_mutex_init(&g_stp.lock, NULL));
    nl_port_scope_on_resume(resume_stp_timers);
    g_stp.started_at = nl_monotonic_seconds() - 300;
    hardware[1] = hardware[5] = 4; /* l2d's blocking baseline */
    assert(reload_stp_config_if_needed(true));
    stp_port_stats *a = find_port_stats_locked(1), *b = find_port_stats_locked(5);
    assert(a && b && a->configuration_pending && b->configuration_pending);
    reconcile_rstp_roles();
    assert(hardware[1] == 4 && hardware[5] == 4);
    for (int i = 0; i < changed; ++i) assert(changed_states[i] == 4);

    a->configuration_since = b->configuration_since = nl_monotonic_seconds() - 20;
    a->configuration_pending = b->configuration_pending = true;
    b->protocol_blocked = false; changed = 0; fail_block_port = 5;
    reconcile_rstp_roles(); assert(hardware[1] == 4 && changed == 0);
    fail_block_port = 0;
    reconcile_rstp_roles();
    assert(hardware[1] == 3 && hardware[5] == 4 && changed == 2);
    assert(changed_ports[0] == 5 && changed_states[0] == 4 && changed_ports[1] == 1);
    assert(!a->configuration_pending && b->protocol_blocked);
    changed = 0; assert(reload_stp_config_if_needed(true)); reconcile_rstp_roles();
    assert(changed == 0 && !a->configuration_pending && b->protocol_blocked);

    a->last_seen = b->last_seen = nl_monotonic_seconds() - 5;
    time_t before_a = a->last_seen, before_b = b->last_seen;
    assert(!nl_port_scope_begin(11, 15, 50));
    stp_apply_op target = {1, 1, 4, STP_BLOCK_ALTERNATE};
    stp_apply_op sibling = {5, 1, 3, STP_BLOCK_NONE};
    assert(!apply_protocol_op(&target) && apply_protocol_op(&sibling));
    assert(hardware[1] == 3 && hardware[5] == 3);
    resume_stp_timers(15, 9);
    assert(a->last_seen == before_a + 9 && b->last_seen == before_b);
    assert(!nl_port_scope_end(11));
    lag_mapping();
    free(g_active_stp_xml); pthread_mutex_destroy(&g_stp.lock);
    puts("production RSTP: startup blocking, ordered transitions, failures, scope and LAG mapping passed");
    return 0;
}
