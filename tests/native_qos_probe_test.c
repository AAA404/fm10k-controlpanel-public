#include "../vendor/netlab/sbin/l2d/l2_hw_probe.c"
#include <assert.h>

static int calls;
static bool fail;
static bool native, enabled;
static int admin_calls;
static bool invalid_board;
bool nl_platform_identity_get(nl_platform_identity *out) {
    memset(out, 0, sizeof(*out)); strcpy(out->chassis_name, "sil001-hw5-a11");
    return native;
}
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    (void)name; return fallback;
}
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                  nl_rpc_method method, u64 tx, const u8 *payload, int length,
                  u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)tx; (void)timeout;
    assert(caller == NL_DAEMON_L2D && service == NL_DAEMON_SWITCHD);
    if (method == NL_SWITCHD_FM10K_CONFIG_GET) {
        nl_fm10k_config_snapshot snapshot = {0};
        assert(!length && capacity == (int)sizeof(snapshot));
        snapshot.schema = NL_FM10K_CONFIG_SCHEMA; snapshot.bytes = sizeof(snapshot);
        snapshot.group_valid_mask = invalid_board ? 0 : 0x3f;
        for (int i = 0; i < 6; ++i) {
            snapshot.groups[i].epl = i < 3 ? i : i + 2;
            snapshot.groups[i].mode = 100;
            snapshot.groups[i].enabled = enabled ? 1 : 0;
            for (int lane = 0; lane < 4; ++lane) snapshot.groups[i].lane_gbps[lane] = 25;
        }
        memcpy(out, &snapshot, sizeof(snapshot)); *error = 0; ++admin_calls;
        return sizeof(snapshot);
    }
    assert(method == NL_SWITCHD_COS_GET);
    assert(length == 9 && !memcmp(payload, "scheduler", 9));
    ++calls; *error = 0;
    if (fail) return -1;
    assert(capacity >= 40000);
    memset(out, ' ', 35000);
    int n = snprintf((char *)out + 35000, (size_t)capacity - 35000,
        "<class-of-service><scheduler><interface port=\"24\"><traffic-class id=\"7\" shaping-group=\"3\"/>"
        "</interface></scheduler></class-of-service>");
    return 35000 + n;
}
int main(void) {
    cfg_qos_scheduler_tc_map_intent entry = {0};
    entry.port.hw_port = 24; entry.traffic_class = 7; entry.shaping_group = 3;
    char error[256];
    l2_hw_probe_begin(true);
    assert(!l2_hw_qos_scheduler_tc_map_mismatch(&entry));
    entry.shaping_group = 4;
    assert(l2_hw_qos_scheduler_tc_map_mismatch(&entry) && calls == 1);
    assert(l2_hw_probe_finish(error, sizeof(error)) && !g_probe_state.qos[3].text);
    entry.shaping_group = 3;
    l2_hw_probe_begin(true);
    assert(!l2_hw_qos_scheduler_tc_map_mismatch(&entry) && calls == 2);
    assert(l2_hw_probe_finish(error, sizeof(error)));
    fail = true;
    l2_hw_probe_begin(true);
    (void)l2_hw_qos_scheduler_tc_map_mismatch(&entry);
    (void)l2_hw_qos_scheduler_tc_map_mismatch(&entry);
    assert(calls == 3 && !l2_hw_probe_finish(error, sizeof(error)));
    assert(strstr(error, "RPC failed"));
    native = true; fail = false;
    l2_hw_probe_begin(true);
    assert(l2_hw_admin_mismatch(1, false) && !l2_hw_admin_mismatch(5, true));
    assert(admin_calls == 1); /* No event-cache query and one snapshot per plan. */
    assert(l2_hw_probe_finish(error, sizeof(error)));
    enabled = true;
    l2_hw_probe_begin(true);
    assert(!l2_hw_admin_mismatch(1, false) && l2_hw_admin_mismatch(5, true));
    assert(admin_calls == 2 && l2_hw_probe_finish(error, sizeof(error)));
    invalid_board = true;
    l2_hw_probe_begin(true);
    (void)l2_hw_admin_mismatch(1, false);
    (void)l2_hw_admin_mismatch(5, true);
    assert(admin_calls == 3 && !l2_hw_probe_finish(error, sizeof(error)));
    assert(strstr(error, "live board group is incomplete"));
    return 0;
}
