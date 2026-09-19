#include "../vendor/netlab/sbin/l2d/l2_hw_probe.c"
#include <assert.h>

static const char *reply;
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                  nl_rpc_method method, u64 tx, const u8 *payload, int length,
                  u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)tx; (void)payload; (void)length; (void)timeout;
    assert(caller == NL_DAEMON_L2D && service == NL_DAEMON_SWITCHD &&
        (method == NL_SWITCHD_LAG_GET_ALL || method == NL_SWITCHD_PORT_MTU_GET));
    assert((int)strlen(reply) < capacity);
    *error = 0; memcpy(out, reply, strlen(reply)); return (int)strlen(reply);
}
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) { (void)name; return fallback; }
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
int main(void) {
    char error[256] = {0}; int members[24];
    reply = "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"error\" code=\"-1\"/><member port=\"1\"/></lag>"
        "<lag ae=\"1\" name=\"ae1\" id=\"9\" logical-port=\"101\">"
        "<member-readback status=\"ok\" code=\"0\"/><member port=\"9\"/></lag></lags>";
    l2_hw_probe_begin(true);
    assert(!l2_hw_lag_missing(0));
    assert(!l2_hw_probe_finish(error, sizeof(error)) && strstr(error, "LAG member read-back failed"));
    l2_hw_probe_begin(true);
    assert(l2_hw_ae_logical_port(0) == 0);
    assert(!l2_hw_probe_finish(error, sizeof(error)));
    l2_hw_probe_begin(true);
    assert(!hardware_ae_member_ports(0, members, 24));
    assert(!l2_hw_probe_finish(error, sizeof(error)));
    l2_hw_probe_begin(true);
    assert(!l2_hw_lag_missing(1) && l2_hw_ae_logical_port(1) == 101);
    assert(hardware_ae_member_ports(1, members, 24) == 1 && members[0] == 9);
    assert(l2_hw_probe_finish(error, sizeof(error)));
    reply = "<lags><lag ae=\"0\" name=\"ae0\" id=\"7\" logical-port=\"100\">"
        "<member-readback status=\"ok\" code=\"0\"/></lag></lags>";
    l2_hw_probe_begin(true);
    assert(!l2_hw_lag_missing(0) && !hardware_ae_member_ports(0, members, 24));
    assert(l2_hw_probe_finish(error, sizeof(error)));
    cfg_qos_interface_intent classifier = {.port = {.is_aggregate = true, .ae_id = 0},
                                          .trust_mode = HAL_QOS_TRUST_NONE, .default_priority = 0};
    l2_hw_probe_begin(true);
    assert(!l2_hw_qos_interface_mismatch(&classifier));
    assert(!l2_hw_probe_finish(error, sizeof(error))); /* Missing QoS is not a match. */
    const char *states[] = {
        "<qos-readback status=\"ok\" code=\"0\" trust=\"0\" default-priority=\"0\"/>",
        "<qos-readback status=\"ok\" code=\"0\" trust=\"1\" default-priority=\"3\"/>",
        "<qos-readback status=\"ok\" code=\"0\" trust=\"-1\" default-priority=\"-1\"/>",
        "<qos-readback status=\"error\" code=\"-1\" trust=\"0\" default-priority=\"0\"/>",
        "<qos-readback status=\"ok\" code=\"0\" trust=\"bad\" default-priority=\"0\"/>",
    };
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "<lags><lag ae=\"0\" id=\"7\" logical-port=\"100\">"
            "<member-readback status=\"ok\" code=\"0\"/>%s</lag></lags>", states[i]);
        reply = buffer;
        l2_hw_probe_begin(true);
        assert(l2_hw_qos_interface_mismatch(&classifier) == (i == 1 || i == 2));
        assert(l2_hw_probe_finish(error, sizeof(error)) == (i < 3));
    }
    reply = "<lags></lags>";
    l2_hw_probe_begin(true);
    assert(l2_hw_qos_interface_mismatch(&classifier) && l2_hw_lag_missing(0));
    assert(l2_hw_probe_finish(error, sizeof(error)));
    reply = "<lags>";
    l2_hw_probe_begin(true);
    assert(!l2_hw_lag_missing(0) && !l2_hw_qos_interface_mismatch(&classifier));
    assert(!l2_hw_probe_finish(error, sizeof(error)));
    puts("L2 production probes distinguish complete absence, classifier drift and unreadable LAG state");
    cfg_port_ref aggregate = {.is_aggregate = true, .ae_id = 0, .hw_port = 100};
    reply = "port=100 mtu=9000 max-frame=9024 pvid=100";
    l2_hw_probe_begin(true);
    assert(!l2_hw_mtu_mismatch(&aggregate, 9000) && l2_hw_mtu_mismatch(&aggregate, 8000));
    assert(!l2_hw_pvid_mismatch(&aggregate, 100) && l2_hw_pvid_mismatch(&aggregate, 200));
    assert(l2_hw_probe_finish(error, sizeof(error)));
    reply = "port=101 mtu=9000 max-frame=9024 pvid=100";
    l2_hw_probe_begin(true);
    assert(!l2_hw_pvid_mismatch(&aggregate, 100));
    assert(!l2_hw_probe_finish(error, sizeof(error)));
    return 0;
}
