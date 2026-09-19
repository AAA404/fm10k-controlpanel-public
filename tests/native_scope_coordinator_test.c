#include "netlab/ipc.h"
#include "netlab/port_scope.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exercise the production coordinator, including packetd's distinct wire
 * format. Only daemon transport and reload acknowledgements are simulated. */
#include "../vendor/netlab/sbin/configd/runtime_scope.c"

static nl_port_scope_status states[PEERS];
static int fault_peer = -1, fault_method, fault_after, fault_remaining;
static int event_peer[256], event_method[256], events;
static bool reload_ok = true;
static unsigned reloads;
static char packet_reply[128];
static size_t packet_length;
static int packet_stage, packet_error;
static u32 request_length;

static int peer_index(nl_daemon_id id) {
    for (unsigned i = 0; i < PEERS; ++i) if (peers[i].id == id) return (int)i;
    assert(false); return -1;
}
static int transport(int peer, int method, u64 tx, u32 mask, nl_port_scope_status *out) {
    assert(events < 256);
    event_peer[events] = peer; event_method[events++] = method;
    bool inject = peer == fault_peer && method == fault_method && fault_remaining > 0;
    if (inject) --fault_remaining;
    if (inject && !fault_after) return NL_ERR_DAEMON_UNREACHABLE;
    nl_port_scope_status *s = &states[peer];
    int rc = 0;
    if (method == NL_PORT_SCOPE_BEGIN) {
        if (s->degraded) rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
        else if (s->tx_id && (s->tx_id != tx || (s->mask & ~mask))) rc = NL_ERR_COMMIT_LOCKED;
        else { s->tx_id = tx; s->mask = mask; }
    } else if (method == NL_PORT_SCOPE_END) {
        if (s->degraded) rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
        else if (s->tx_id && s->tx_id != tx) rc = NL_ERR_COMMIT_LOCKED;
        else { s->tx_id = 0; s->mask = 0; }
    } else assert(method == NL_PORT_SCOPE_STATUS);
    *out = *s;
    return inject ? NL_ERR_RPC_TIMEOUT : rc;
}
const char *nl_ipc_socket_path_from_env(const char *env, const char *fallback) {
    (void)env; return fallback;
}
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                  nl_rpc_method method, u64 tx, const u8 *payload, int length,
                  u8 *out, int capacity, int timeout, s32 *error) {
    (void)path;
    assert(caller == NL_DAEMON_CONFIGD && timeout == 7000 && capacity == sizeof(nl_port_scope_status));
    u32 mask = 0;
    if ((int)method == NL_PORT_SCOPE_BEGIN) {
        assert(length == 8 && payload);
        u32 data[2]; memcpy(data, payload, sizeof(data)); assert(data[0] == NL_PORT_SCOPE_SCHEMA);
        mask = data[1];
    } else assert(length == 0 && payload == NULL);
    *error = transport(peer_index(service), method, tx, mask, (nl_port_scope_status *)out);
    return *error == NL_ERR_DAEMON_UNREACHABLE || *error == NL_ERR_RPC_TIMEOUT ? -1 : capacity;
}
nl_status nl_client_connect_timeout(const char *path, nl_conn *conn, u32 timeout) {
    assert(!strcmp(path, peers[0].path) && timeout == 7000);
    memset(conn, 0, sizeof(*conn)); packet_stage = 0; packet_error = 0;
    return NL_OK;
}
void nl_client_close(nl_conn *conn) { (void)conn; }
nl_status nl_send_record(nl_conn *conn, const void *data, size_t length) {
    (void)conn;
    if (packet_stage++ == 0) { assert(length == 4); memcpy(&request_length, data, 4); return NL_OK; }
    assert(length == ntohl(request_length) && length < 100);
    char text[100], verb[16]; unsigned long long tx; unsigned mask;
    memcpy(text, data, length); text[length] = 0;
    assert(sscanf(text, "scope %15s %llx %x", verb, &tx, &mask) == 3);
    int method = !strcmp(verb, "begin") ? NL_PORT_SCOPE_BEGIN : !strcmp(verb, "end") ? NL_PORT_SCOPE_END : NL_PORT_SCOPE_STATUS;
    nl_port_scope_status state = {0};
    int rc = transport(0, method, tx, mask, &state);
    packet_error = rc == NL_ERR_DAEMON_UNREACHABLE || rc == NL_ERR_RPC_TIMEOUT;
    packet_length = (size_t)snprintf(packet_reply, sizeof(packet_reply), "scope %u %016llx %06x %u %d",
        state.schema, (unsigned long long)state.tx_id, state.mask, state.degraded, rc);
    return NL_OK;
}
ssize_t nl_recv_peer_record(nl_conn *conn, void *out, size_t capacity, int flags) {
    (void)conn; (void)flags;
    if (packet_error) return -1;
    if (packet_stage++ == 2) {
        assert(capacity == 4); u32 n = htonl((u32)packet_length); memcpy(out, &n, 4); return 4;
    }
    assert(capacity == packet_length); memcpy(out, packet_reply, packet_length); return (ssize_t)packet_length;
}
bool configd_runtime_reload_checked(void) {
    ++reloads;
    for (unsigned i = 0; i < PEERS; ++i) assert(states[i].tx_id == 42 && states[i].mask == 0x000f0f);
    return reload_ok;
}

static const char plan[] =
    "# fm10k-scope-v1 mask=000f0f\n"
    "fm10k-group-set epl=0 mode=0 lane0=10 lane1=25 lane2=10 lane3=25 enabled=0\n"
    "fm10k-group-set epl=2 mode=100 lane0=25 lane1=25 lane2=25 lane3=25 enabled=1\n";
static char error[256];
static void reset(void) {
    memset(states, 0, sizeof(states));
    for (unsigned i = 0; i < PEERS; ++i) states[i].schema = NL_PORT_SCOPE_SCHEMA;
    fault_peer = -1; fault_remaining = 0; events = 0; reloads = 0; reload_ok = true;
    engaged = false; not_dispatched = 0;
}
static void check_states(u64 tx) {
    for (unsigned i = 0; i < PEERS; ++i) {
        assert(states[i].tx_id == tx); assert(states[i].mask == (tx ? 0xf0fU : 0));
    }
}
static int begin(void) { return configd_scope_begin(42, plan, strlen(plan), error, sizeof(error)); }
static int finish(void) { return configd_scope_finish(42, true, error, sizeof(error)); }
int main(void) {
    setenv("NETLAB_FM10K_NATIVE", "1", 1);
    reset(); assert(!begin()); check_states(42); assert(configd_scope_engaged());
    assert(!finish()); check_states(0); assert(!configd_scope_engaged() && reloads == 1);
    assert(event_peer[events - 1] == 0 && event_method[events - 1] == NL_PORT_SCOPE_END);
    assert(!finish()); assert(reloads == 1);

    for (unsigned peer = 0; peer < PEERS; ++peer) for (int after = 0; after < 2; ++after) {
        reset(); fault_peer = (int)peer; fault_method = NL_PORT_SCOPE_BEGIN; fault_after = after; fault_remaining = 1;
        assert(begin()); assert(configd_scope_was_not_dispatched(42)); check_states(0);
        assert(!configd_scope_engaged());
        reset(); assert(!begin());
        fault_peer = (int)peer; fault_method = NL_PORT_SCOPE_END; fault_after = after; fault_remaining = 1;
        assert(finish()); check_states(42); assert(configd_scope_engaged());
        assert(!finish()); check_states(0);
    }
    reset(); assert(!begin()); reload_ok = false;
    assert(finish()); check_states(42); reload_ok = true; assert(!finish()); check_states(0);
    for (unsigned peer = 0; peer < PEERS; ++peer) {
        reset(); assert(!begin());
        states[peer].tx_id = 0; states[peer].mask = 0; engaged = false; /* daemon/configd restart */
        assert(!finish()); check_states(0);
        reset(); assert(!begin()); states[peer].degraded = 1;
        assert(finish()); check_states(42); assert(reloads == 0);
        reset(); assert(!begin()); states[peer].tx_id = 43;
        assert(finish()); assert(states[peer].tx_id == 43 && reloads == 0);
        reset(); assert(!begin()); states[peer].mask = 0xf;
        assert(!finish()); check_states(0); assert(reloads == 1);
    }
    reset();
    states[0].tx_id = 42; states[0].mask = 1;
    states[3].tx_id = 42; states[3].mask = 15;
    assert(!begin()); check_states(42); assert(!finish()); check_states(0);
    for (int after = 0; after < 2; ++after) {
        reset(); assert(!begin());
        states[0].mask = 1;
        fault_peer = 2; fault_method = NL_PORT_SCOPE_BEGIN; fault_after = after; fault_remaining = 1;
        assert(begin() && !configd_scope_was_not_dispatched(42));
        check_states(42); /* No retained barrier is unwound after a lost acknowledgement. */
        assert(!begin() && !finish()); check_states(0);
    }
    reset(); const char invalid[] = "fm10k-group-set invalid\n";
    assert(configd_scope_begin(42, invalid, strlen(invalid), error, sizeof(error)));
    assert(events == 0);
    const char no_ports[] = "# fm10k-scope-v1 mask=000000\nvlan-create vid=3\n";
    assert(!configd_scope_begin(42, no_ports, strlen(no_ports), error, sizeof(error)));
    assert(events == 0 && !configd_scope_engaged());
    const char undeclared[] = "vlan-create vid=3\n";
    assert(configd_scope_begin(42, undeclared, strlen(undeclared), error, sizeof(error)));
    assert(events == 0 && configd_scope_was_not_dispatched(42));
    puts("scope coordinator: acquisition, reload, lost replies, rejoin and owner checks passed");
    return 0;
}
