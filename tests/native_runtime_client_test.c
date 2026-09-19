#include "../vendor/netlab/sbin/configd/native_runtime.c"
#include <assert.h>

static u64 current = 7;
static u64 verified;
static bool ready = true, bound, lose_ack, replace_epoch, reject_bind;
static const char *actual_profile = "sil001-hw5-a11";
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    (void)name; return fallback;
}
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                  nl_rpc_method method, u64 tx, const u8 *payload, int length,
                  u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)timeout;
    assert(caller == NL_DAEMON_CONFIGD && service == NL_DAEMON_SWITCHD);
    *error = 0;
    if (method == NL_SWITCHD_FM10K_BOARD_GET) {
        assert(!tx && length == 8 && !memcmp(payload, "contract", 8));
        return snprintf((char *)out, (size_t)capacity,
            "{\"profile\":\"%s\",\"native_ready\":%s,\"board_hal\":\"%s\",\"native_generation\":\"%016llx\",\"native_commit\":\"%016llx\"}",
            actual_profile, ready ? "true" : "false", bound ? "bound" : "unbound", (unsigned long long)current,
            (unsigned long long)verified);
    }
    assert(method == NL_SWITCHD_FM10K_BIND && tx == 42 && length == 16);
    struct { u32 schema, reserved; u64 generation; } request;
    memcpy(&request, payload, sizeof(request));
    assert(request.schema == 1 && !request.reserved && request.generation == 7);
    if (reject_bind) *error = NL_ERR_RPC_BUSY;
    else if (replace_epoch) ++current;
    else { bound = true; verified = tx; }
    if (lose_ack) { *error = NL_ERR_RPC_TIMEOUT; return -1; }
    return 0;
}
int main(void) {
    const nl_rpc_contract *contract = nl_rpc_contract_lookup(NL_DAEMON_SWITCHD, NL_SWITCHD_FM10K_BIND);
    assert(contract && contract->caller_mask == (UINT64_C(1) << NL_DAEMON_CONFIGD));
    assert(!(contract->flags & NL_RPC_CONTRACT_MGMT_EXPOSED));
    assert(contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED);
    u64 generation; bool actual_bound;
    assert(!configd_native_status(actual_profile, &generation, &actual_bound) && generation == 7 && !actual_bound);
    ready = false;
    assert(configd_native_status(actual_profile, &generation, &actual_bound));
    ready = true; actual_profile = "sil001-hw4-b0";
    assert(configd_native_status("sil001-hw5-a11", &generation, &actual_bound));
    actual_profile = "sil001-hw5-a11";
    lose_ack = true;
    assert(!configd_native_bind(actual_profile, 7, 42));
    /* A stale bound flag from an earlier commit cannot prove a lost bind. */
    reject_bind = true; verified = 41;
    assert(configd_native_bind(actual_profile, 7, 42));
    lose_ack = false; verified = 42;
    assert(configd_native_bind(actual_profile, 7, 42) == NL_ERR_RPC_BUSY);
    reject_bind = false; lose_ack = true;
    bound = false; replace_epoch = true;
    assert(configd_native_bind(actual_profile, 7, 42));
    puts("native client: profile/readiness, private bind and lost-ack epoch readback verified");
    return 0;
}
