/* Run the production configd replay/journal selection and L3 compiler with
 * real libyang. Only platform inventory, L2 planning and daemon RPCs are
 * fixtures; no SDK or device is opened. */
#define main configd_daemon_entry
#include "../vendor/netlab/sbin/configd/main.c"
#undef main
#include <assert.h>

static const char *chassis = "sil001-hw5-a11";
static const char *asic = "FM10840";
static bool identity_available = true, pfe_up = true;
static int l2_applies, finalized, l3_calls, refreshed, l2_failure;
static bool require_removed_owner;
static const char *fixture_dir;
static nl_commit_journal recovery_journal;
const char *nl_config_dir(void) { return fixture_dir; }
nl_status nl_journal_get(u64 tx, nl_commit_journal *out) {
    if (!recovery_journal.tx_id || tx != recovery_journal.tx_id) return NL_ERR;
    *out = recovery_journal; return NL_OK;
}

void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
const char *nl_error_msg(nl_error_code code) { (void)code; return "fixture SDK failure"; }
bool nl_platform_identity_get(nl_platform_identity *out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->chassis_name, sizeof(out->chassis_name), "%s", chassis);
    return identity_available;
}
bool nl_platform_board_get(nl_board_profile *out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->asic, sizeof(out->asic), "%s", asic);
    return true;
}
bool nl_platform_system_mac(u8 mac[NL_MAC_ADDR_LEN]) {
    const u8 address[] = {2, 0, 0, 0, 0, 1}; memcpy(mac, address, sizeof(address)); return true;
}
bool nl_platform_ffu_slices(nl_ffu_slice_allocation *out) {
    memset(out, 0, sizeof(*out)); out->configured = true;
    return true; /* Route slices advertised even on the L2-only profile. */
}
bool nl_ifid_get_by_name(const char *name, nl_port_entry *out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->canonical_name, sizeof(out->canonical_name), "%s", name);
    snprintf(out->role, sizeof(out->role), "external");
    snprintf(out->capabilities, sizeof(out->capabilities), "L2,ROUTE");
    out->flags = NL_PORT_FLAG_EXTERNAL; out->logical_port = 1; return true;
}
int nl_ifid_get_all(nl_port_entry *ports, int capacity) {
    assert(capacity > 0); nl_ifid_get_by_name("et-0/0/0", ports); return 1;
}
bool configd_switchd_pfe_up(char *detail, size_t size) {
    if (!pfe_up) snprintf(detail, size, "SDK unavailable");
    return pfe_up;
}
int configd_l2_build_plan(nl_yang_session *before, nl_yang_session *after, bool require_hw,
                         char *plan, size_t size, int *length, bool *has_l2,
                         char *error, size_t error_size) {
    (void)require_hw; (void)error; (void)error_size;
    assert(before && after);
    if (require_removed_owner) {
        assert(before != after);
        assert(nl_yang_exists(before, "/netlab:netlab-config/vlans/vlan[name='V99']"));
        assert(!nl_yang_exists(after, "/netlab:netlab-config/vlans/vlan[name='V99']"));
    }
    *length = snprintf(plan, size, "# fm10k-scope-v1 mask=000001\nvlan-create vid=2\n");
    *has_l2 = true; return 0;
}
int configd_switchd_apply_l2_plan(u64 tx, const char *plan, int length,
                                 char *response, size_t size, s32 *error) {
    assert(tx == 42 && plan && length > 0); ++l2_applies;
    *error = l2_failure;
    return snprintf(response, size, "%s", l2_failure ? "SDK apply failed" : "verified");
}
int configd_switchd_mark_success(u64 tx, char *response, size_t size, s32 *error) {
    assert(tx == 42); ++finalized; *error = 0; return snprintf(response, size, "verified");
}
void configd_l2_refresh_cache(void) { ++refreshed; }
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                   nl_rpc_method method, u64 tx, const u8 *payload, int length,
                   u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)tx; (void)payload; (void)length; (void)timeout;
    assert(caller == NL_DAEMON_CONFIGD && service == NL_DAEMON_RPD);
    assert(strcmp(asic, "FM10840")); /* The board's L2 replay must never get here. */
    ++l3_calls; *error = 0;
    const char *reply = method == NL_RPD_READBACK ?
        "<persistent-l3-owner-readback owner-mode=\"none\" hardware-apply=\"disabled\">"
        "<usage rifs=\"0\" arp=\"0\" next-hops=\"0\" routes=\"0\" ecmp-groups=\"0\"/>"
        "</persistent-l3-owner-readback>" : "ok";
    assert(method == NL_RPD_VALIDATE_PLAN || method == NL_RPD_APPLY_PLAN || method == NL_RPD_READBACK);
    assert((int)strlen(reply) < capacity); memcpy(out, reply, strlen(reply)); return (int)strlen(reply);
}
static void reset_counters(void) {
    l2_applies = finalized = l3_calls = refreshed = l2_failure = 0;
    g_ctx.hw_out_of_sync = false; pfe_up = true;
}
static int replay(nl_yang_session *source, bool full) {
    char detail[2048];
    return replay_configuration_to_hardware(source, full, 42, true, detail, sizeof(detail));
}
int main(int argc, char **argv) {
    assert(argc == 2); fixture_dir = argv[1];
    g_ctx.active = nl_yang_session_create(NULL); assert(g_ctx.active);
    g_ctx.active_commit_id = 42;
    assert(nl_yang_set(g_ctx.active, "/netlab:netlab-config/vlans/vlan[name='V2']/vlan-id", "2") == NL_ERR_OK);
    const char *profiles[] = {"sil001-hw5-a11", "sil001-hw4-b0"};
    char journal[2048];
    for (unsigned i = 0; i < sizeof(profiles) / sizeof(*profiles); ++i) {
        chassis = profiles[i]; reset_counters();
        assert(!configd_l3_public_apply_enabled());
        assert(!build_active_replay_journal_plan(NULL, journal, sizeof(journal)));
        assert(strstr(journal, "switchd-l2") && !strstr(journal, "rpd-l3"));
        assert(replay(g_ctx.active, true) == NL_ERR_OK);
        assert(l2_applies == 1 && finalized == 1 && refreshed == 1 && !l3_calls);
    }
    reset_counters(); assert(replay(g_ctx.active, false) == NL_ERR_OK);
    assert(l2_applies == 1 && finalized == 1 && !l3_calls);

    /* Confirmed rollback must retain the superseded owner image for both
     * participant selection and removal, including post-publication replay. */
    nl_yang_session *superseded = nl_yang_session_create(NULL); assert(superseded);
    assert(nl_yang_set(superseded, "/netlab:netlab-config/vlans/vlan[name='V99']/vlan-id", "99") == NL_ERR_OK);
    char *source_xml = nl_yang_to_xml(superseded); assert(source_xml);
    require_removed_owner = true; reset_counters();
    assert(!build_active_replay_journal_plan(source_xml, journal, sizeof(journal)));
    char detail[512];
    assert(replay_snapshot_to_active(source_xml, 42, detail, sizeof(detail)) == NL_ERR_OK);
    assert(l2_applies == 1 && finalized == 1);
    char directory[512], source_path[512], restored_path[512];
    assert(rollback_dir_buf(directory, sizeof(directory)) && !mkdir(directory, 0700));
    assert(rollback_path_buf(source_path, sizeof(source_path), 41));
    assert(rollback_path_buf(restored_path, sizeof(restored_path), 43));
    assert(!persist_xml_file(source_path, source_xml));
    char *payload = read_commit_snapshot_payload(41); assert(payload);
    assert(!persist_xml_file(restored_path, payload));
    char *original_bytes = read_text_file(source_path), *restored_bytes = read_text_file(restored_path);
    assert(original_bytes && restored_bytes && !strcmp(original_bytes, restored_bytes));
    free(payload); free(original_bytes); free(restored_bytes);
    recovery_journal.tx_id = 42; recovery_journal.base_commit_id = 41;
    recovery_journal.state = NL_JOURNAL_HW_OUT_OF_SYNC;
    reset_counters();
    assert(replay_active_to_hardware(true, detail, sizeof(detail)) == NL_ERR_OK);
    assert(l2_applies == 1 && finalized == 1);
    require_removed_owner = false; recovery_journal.tx_id = 0;
    free(source_xml); nl_yang_session_destroy(superseded);

    nl_yang_session *routed = nl_yang_session_create(NULL); assert(routed);
    assert(nl_yang_set(routed, "/netlab:netlab-config/routing-options/autonomous-system", "65000") == NL_ERR_OK);
    /* Existing L3 intent cannot disappear during recovery or migration. */
    reset_counters(); assert(replay(routed, true) == NL_ERR_INVALID_VALUE);
    assert(!l2_applies && !finalized && !l3_calls && g_ctx.hw_out_of_sync);
    nl_yang_session *l2 = g_ctx.active; g_ctx.active = routed;
    reset_counters(); assert(replay(l2, true) == NL_ERR_INVALID_VALUE);
    assert(!l2_applies && !l3_calls && g_ctx.hw_out_of_sync);
    assert(!build_active_replay_journal_plan(NULL, journal, sizeof(journal)) && strstr(journal, "rpd-l3"));
    g_ctx.active = l2;

    reset_counters(); pfe_up = false; assert(replay(l2, true) == NL_ERR_PFE_DOWN);
    assert(!l2_applies && !l3_calls);
    reset_counters(); l2_failure = NL_ERR_SDK_CALL_FAILED;
    assert(replay(l2, true) == NL_ERR_SDK_CALL_FAILED);
    assert(l2_applies == 1 && !finalized && !refreshed && g_ctx.hw_out_of_sync);

    /* An incomplete identity cannot opt out of the existing L3 cleanup. */
    reset_counters(); identity_available = false;
    assert(replay(l2, true) == NL_ERR_INVALID_VALUE && !l2_applies && !l3_calls);
    identity_available = true;
    chassis = "generic-routing"; asic = "generic"; reset_counters();
    assert(configd_l3_public_apply_enabled());
    assert(!build_active_replay_journal_plan(NULL, journal, sizeof(journal)) && strstr(journal, "rpd-l3"));
    assert(replay(l2, true) == NL_ERR_OK);
    assert(l2_applies == 1 && finalized == 1 && refreshed == 1 && l3_calls == 3);
    nl_yang_session_destroy(routed); nl_yang_session_destroy(l2);
    free(g_ctx.l2_plan_workspace); free(g_ctx.l3_plan_workspace);
    puts("configd replay: L2-only recovery, consistent journal owners, L3 rejection, and routed empty-owner cleanup passed");
    return 0;
}
