/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2_client.h"
#include "l3_client.h"
#include "runtime_client.h"
#include "switchd_client.h"
#include "runtime_scope.h"
#include "native_runtime.h"
#include "public_capabilities.h"
#include "netlab/daemon.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include "netlab/error.h"
#include "netlab/yang_config.h"
#include "netlab/journal.h"
#include "netlab/pfe_capability.h"
#include "netlab/interface_id.h"
#include "netlab/config.h"
#include "netlab/l2_plan.h"
#include "netlab/l2_plan_build.h"
#include "netlab/monotonic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/sha.h>

#define CONFIGD_SOCKET "/var/run/netlab/configd.sock"
#define CONFIGD_YANG_DIR "include/netlab"
#define CONFIGD_JOURNAL_SCAN_MAX 4096
#define CONFIGD_COMMIT_COMMENT_MAX 256
#define CONFIGD_CONFIRMED_DEFAULT_SECONDS 600
#define CONFIGD_CONFIRMED_MIN_SECONDS 1
#define CONFIGD_CONFIRMED_MAX_SECONDS 3600
#define CONFIGD_PRODUCTION_CONTROL_DIR "production-live-run-control"
#define CONFIGD_AUTHORITY_LOCK_FILE "config-authority.lock"
#define CONFIGD_ACTIVE_GUARD_FILE "active.json"
#define CONFIGD_ACTIVE_GUARD_MAX_BYTES (64U * 1024U)
#define CONFIGD_GUARD_ENVELOPE_PREFIX "netlab-config-authority-v1 "
#define CONFIGD_GUARD_DIGEST_LEN 64U
#define CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES 511U
#define CONFIGD_LONG_ERROR_RESPONSE_MAX_BYTES 1023U
#define CONFIGD_ERROR_TRAILING_DETAIL_MAX_BYTES 256U

// ===== Global candidate/active configuration state =====
typedef struct {
    nl_yang_session *candidate;        // global candidate (libyang)
    nl_yang_session *active;           // active config (libyang)
    u64              active_commit_id;
    bool             commit_locked;
    bool             hw_out_of_sync;
    bool             public_capability_cleanup_required;
    bool             active_authority_uncertain;
    bool             production_guard_authorized;
    bool             guarded_restore_response;
    u64              native_generation;
    u64              native_failed_generation;
    time_t           native_next_poll;
    char            *l2_plan_workspace;
    char            *l3_plan_workspace;
    char             guarded_restore_pointer_sha256[65];
    char             guarded_restore_content_sha256[65];
} configd_ctx;

static configd_ctx g_ctx;

static char *configd_l2_plan_workspace(void) {
    if (!g_ctx.l2_plan_workspace)
        g_ctx.l2_plan_workspace = calloc(NL_L2_PLAN_MAX_BYTES, 1U);
    return g_ctx.l2_plan_workspace;
}

static char *configd_l3_plan_workspace(void) {
    if (!g_ctx.l3_plan_workspace)
        g_ctx.l3_plan_workspace = calloc(NL_L3_PLAN_MAX_BYTES, 1U);
    return g_ctx.l3_plan_workspace;
}

typedef struct {
    bool confirmed;
    s64 confirm_seconds;
    char comment[CONFIGD_COMMIT_COMMENT_MAX];
} configd_commit_options;

typedef enum {
    CONFIG_XML_INVALID = -1,
    CONFIG_XML_EMPTY = 0,
    CONFIG_XML_HAS_DATA = 1,
} config_xml_result;

// ===== Forward declarations =====
static int handle_set(nl_conn *conn, nl_msg_hdr *msg);
static int handle_delete(nl_conn *conn, nl_msg_hdr *msg);
static int handle_commit(nl_conn *conn, nl_msg_hdr *msg);
static int handle_rollback(nl_conn *conn, nl_msg_hdr *msg);
static int handle_get_candidate(nl_conn *conn, nl_msg_hdr *msg);
static int handle_commit_check(nl_conn *conn, nl_msg_hdr *msg);
static int handle_get_active(nl_conn *conn, nl_msg_hdr *msg);
static int handle_diff(nl_conn *conn, nl_msg_hdr *msg);
static int handle_replay_active(nl_conn *conn, nl_msg_hdr *msg);
static void configd_native_replay_tick(void);
static int handle_rollback_history(nl_conn *conn, nl_msg_hdr *msg);
static int handle_reconcile(nl_conn *conn, nl_msg_hdr *msg);
static int handle_confirmed_status(nl_conn *conn, nl_msg_hdr *msg);
static int handle_public_capability_status(nl_conn *conn,
                                           nl_msg_hdr *msg);
static int handle_production_guard_arm_check(nl_conn *conn,
                                             nl_msg_hdr *msg);
static int handle_production_guarded_restore_xml(nl_conn *conn,
                                                 nl_msg_hdr *msg);
static int handle_production_guard_complete_check(nl_conn *conn,
                                                  nl_msg_hdr *msg);
static int configd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx);
static int configd_on_init(void *ctx);
static void configd_on_idle(void *ctx, s64 elapsed_ms);
static void configd_on_shutdown(void *ctx);
static int handle_set(nl_conn *conn, nl_msg_hdr *msg);
static char *read_text_file(const char *path);
static bool load_xml_into_sessions(const char *xml);
static nl_error_code replace_candidate_xml_payload(
    const u8 *payload, u32 payload_len, char *detail, size_t detail_size);
static nl_error_code replay_configuration_to_hardware(
    nl_yang_session *source, bool full_replay, u64 tx_id,
    bool require_pfe, char *detail, size_t detail_size);
static nl_error_code replay_snapshot_to_active(const char *xml, u64 tx_id,
                                               char *detail, size_t detail_size);
static nl_error_code replay_active_to_hardware(bool require_pfe,
                                               char *detail,
                                               size_t detail_size);
static int send_guarded_restore_proof(nl_conn *conn, nl_msg_hdr *msg);
static void configd_check_confirmed_timeout_if_unblocked(void);
static config_xml_result parse_config_xml_data(
    nl_yang_session *session, const char *xml, struct lyd_node **data_tree);

static bool configd_test_l2_socket_allowed(const char *path) {
    char canonical[PATH_MAX];
    char parent[PATH_MAX];
    char *separator;
    struct stat parent_st;
    struct stat socket_st;
    size_t path_length;

    if (!path || path[0] != '/' || !nl_ipc_socket_path_safe(path))
        return false;
    path_length = strlen(path);
    if (path_length == 0 || path_length >= sizeof(parent) ||
        !realpath(path, canonical) || strcmp(path, canonical) != 0 ||
        (strncmp(canonical, "/tmp/", 5) != 0 &&
         strncmp(canonical, "/var/tmp/", 9) != 0) ||
        lstat(canonical, &socket_st) != 0 ||
        !S_ISSOCK(socket_st.st_mode) || socket_st.st_nlink != 1 ||
        socket_st.st_uid != geteuid())
        return false;

    memcpy(parent, canonical, path_length + 1U);
    separator = strrchr(parent, '/');
    if (!separator || separator == parent)
        return false;
    *separator = '\0';
    if (lstat(parent, &parent_st) != 0 || !S_ISDIR(parent_st.st_mode) ||
        parent_st.st_uid != geteuid() ||
        (parent_st.st_mode & 0777U) != 0700U)
        return false;
    return true;
}

static char *configd_test_read_l2_xml(const char *path) {
    struct stat st;
    char *buffer = NULL;
    size_t offset = 0;
    int fd;

    if (!path || !path[0])
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_size <= 0 ||
        (uintmax_t)st.st_size > NL_L2_PLAN_CONFIG_MAX_BYTES) {
        close(fd);
        return NULL;
    }
    buffer = calloc((size_t)st.st_size + 1U, 1U);
    if (!buffer) {
        close(fd);
        return NULL;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t count = read(fd, buffer + offset,
                             (size_t)st.st_size - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            free(buffer);
            close(fd);
            return NULL;
        }
        offset += (size_t)count;
    }
    close(fd);
    if (memchr(buffer, '\0', offset) != NULL) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

static int configd_l2_plan_test_main(const char *active_path,
                                     const char *candidate_path,
                                     const char *require_hardware_text) {
    const char *control = getenv("NETLAB_CONFIGD_TEST_CONTROL");
    const char *socket_path = getenv("NETLAB_L2D_SOCKET");
    nl_yang_session *active = NULL;
    nl_yang_session *candidate = NULL;
    struct lyd_node *active_tree = NULL;
    struct lyd_node *candidate_tree = NULL;
    char *active_xml = NULL;
    char *candidate_xml = NULL;
    char *plan = NULL;
    char error[512] = {0};
    int plan_length = 0;
    int status = 1;
    bool has_l2 = false;
    bool require_hardware;
    config_xml_result active_result;
    config_xml_result candidate_result;

    if (!control || strcmp(control, "1") != 0 ||
        !configd_test_l2_socket_allowed(socket_path) ||
        !require_hardware_text ||
        (strcmp(require_hardware_text, "0") != 0 &&
         strcmp(require_hardware_text, "1") != 0)) {
        fprintf(stderr,
                "error: configd L2 test build requires explicit test "
                "control and an isolated temporary socket\n");
        return 2;
    }
    require_hardware = strcmp(require_hardware_text, "1") == 0;
    active_xml = configd_test_read_l2_xml(active_path);
    candidate_xml = configd_test_read_l2_xml(candidate_path);
    active = nl_yang_session_create(CONFIGD_YANG_DIR);
    candidate = nl_yang_session_create(CONFIGD_YANG_DIR);
    if (!active_xml || !candidate_xml || !active || !candidate) {
        fprintf(stderr, "error: failed to load bounded L2 test input\n");
        goto out;
    }
    active_result = parse_config_xml_data(active, active_xml, &active_tree);
    candidate_result = parse_config_xml_data(
        candidate, candidate_xml, &candidate_tree);
    if (active_result == CONFIG_XML_INVALID ||
        candidate_result == CONFIG_XML_INVALID) {
        fprintf(stderr, "error: invalid L2 test configuration XML\n");
        goto out;
    }
    if (active_result == CONFIG_XML_HAS_DATA) {
        nl_yang_data_set(active, active_tree);
        active_tree = NULL;
    }
    if (candidate_result == CONFIG_XML_HAS_DATA) {
        nl_yang_data_set(candidate, candidate_tree);
        candidate_tree = NULL;
    }
    plan = calloc(NL_L2_PLAN_MAX_BYTES, 1U);
    if (!plan) {
        fprintf(stderr, "error: failed to allocate bounded L2 plan\n");
        goto out;
    }
    if (configd_l2_build_plan(
            active, candidate, require_hardware,
            plan, NL_L2_PLAN_MAX_BYTES, &plan_length, &has_l2,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "%s\n", error[0] ? error : "L2 plan build failed");
        goto out;
    }
    if (plan_length > 0 &&
        fwrite(plan, 1, (size_t)plan_length, stdout) !=
            (size_t)plan_length) {
        fprintf(stderr, "error: failed to write L2 test plan\n");
        goto out;
    }
    status = 0;

out:
    lyd_free_all(active_tree);
    lyd_free_all(candidate_tree);
    nl_yang_session_destroy(active);
    nl_yang_session_destroy(candidate);
    free(active_xml);
    free(candidate_xml);
    free(plan);
    return status;
}

static bool candidate_sha256(const char *candidate_xml, char digest_hex[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t len;

    if (!candidate_xml || !digest_hex)
        return false;
    len = strlen(candidate_xml);
    while (len > 0 &&
           (candidate_xml[len - 1] == '\n' ||
            candidate_xml[len - 1] == '\r'))
        len--;
    if (!SHA256((const unsigned char *)candidate_xml, len, digest))
        return false;
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(digest_hex + i * 2, 3, "%02x", digest[i]);
    digest_hex[64] = '\0';
    return true;
}

static bool sha256_bytes_hex(const void *data, size_t length,
                             char digest_hex[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];

    if ((!data && length > 0) || !digest_hex ||
        !SHA256((const unsigned char *)data, length, digest))
        return false;
    for (size_t i = 0; i < sizeof(digest); i++)
        snprintf(digest_hex + i * 2, 3, "%02x", digest[i]);
    digest_hex[64] = '\0';
    return true;
}

static bool lowercase_sha256_text(const char *text) {
    if (!text || strlen(text) != CONFIGD_GUARD_DIGEST_LEN)
        return false;
    for (size_t i = 0; i < CONFIGD_GUARD_DIGEST_LEN; i++) {
        if (!isdigit((unsigned char)text[i]) &&
            !(text[i] >= 'a' && text[i] <= 'f'))
            return false;
    }
    return true;
}

static int build_journal_plan(char *out, size_t out_size,
                              bool has_l2, bool has_l3) {
    const char *separator = "";
    size_t off = 0;
    int n;

    if (!out || out_size < 3)
        return -1;
    out[off++] = '[';
    out[off] = '\0';
    if (has_l2) {
        n = snprintf(out + off, out_size - off,
                     "%s{\"participant\":\"switchd-l2\","
                     "\"apply\":\"apply_l2_plan\","
                     "\"verify\":\"sdk-readback\","
                     "\"undo\":\"l2-plan-rollback\"}", separator);
        if (n <= 0 || (size_t)n >= out_size - off)
            return -1;
        off += (size_t)n;
        separator = ",";
    }
    if (has_l3) {
        n = snprintf(out + off, out_size - off,
                     "%s{\"participant\":\"rpd-l3\","
                     "\"apply\":\"persistent-owner-apply\","
                     "\"verify\":\"sdk-readback\","
                     "\"undo\":\"persistent-owner-rollback\"}",
                     separator);
        if (n <= 0 || (size_t)n >= out_size - off)
            return -1;
        off += (size_t)n;
    }
    if (off + 2 > out_size)
        return -1;
    out[off++] = ']';
    out[off] = '\0';
    return 0;
}

static nl_status journal_record_step(u64 tx_id, bool rollback,
                                     const char *participant,
                                     const char *operation,
                                     const char *status) {
    char step[512];
    int n;

    n = snprintf(step, sizeof(step),
                 "{\"participant\":\"%s\",\"operation\":\"%s\","
                 "\"status\":\"%s\",\"recorded_at\":%ld}",
                 participant, operation, status, (long)time(NULL));
    if (n <= 0 || (size_t)n >= sizeof(step))
        return NL_ERR;
    return rollback ? nl_journal_append_rollback(tx_id, step) :
                      nl_journal_append_applied(tx_id, step);
}

static bool rollback_candidate_l2_plan(u64 tx_id, bool has_pending_l2,
                                       char *resp, size_t resp_size) {
    s32 rollback_ec = 0;
    int rollback_rn;
    bool verified;
    const char *status;

    if (!has_pending_l2)
        return true;
    rollback_rn = configd_switchd_rollback_l2_plan(
        tx_id, resp, resp_size, &rollback_ec);
    verified = configd_switchd_l2_rollback_verified(
        tx_id, rollback_rn, rollback_ec, resp);
    status = verified ? "ok" : (rollback_rn < 0 ? "unknown" : "failed");
    if (journal_record_step(tx_id, true, "switchd-l2",
                            "l2-plan-rollback", status) != NL_OK)
        return false;
    return verified;
}

static bool rollback_verified_candidate(u64 tx_id, bool has_l3,
                                        bool has_pending_l2,
                                        char *l3_resp,
                                        size_t l3_resp_size,
                                        char *l2_resp,
                                        size_t l2_resp_size) {
    int rollback_ec = 0;
    int rollback_rn;
    bool l3_verified = true;
    const char *status;

    if (has_l3) {
        rollback_rn = configd_l3_rollback(
            tx_id, l3_resp, l3_resp_size, &rollback_ec);
        l3_verified = configd_l3_rollback_verified(
            tx_id, rollback_rn, rollback_ec, l3_resp);
        status = l3_verified ? "ok" :
                 (rollback_rn < 0 ? "unknown" : "failed");
        if (journal_record_step(
                tx_id, true, "rpd-l3",
                "persistent-owner-rollback", status) != NL_OK)
            return false;
    }
    if (!l3_verified)
        return false;
    return rollback_candidate_l2_plan(
        tx_id, has_pending_l2, l2_resp, l2_resp_size);
}

static bool finalize_active_replay_l2(u64 tx_id, bool has_applied_l2,
                                      char *resp, size_t resp_size) {
    s32 mark_ec = 0;
    int mark_rn;

    if (!has_applied_l2)
        return true;
    mark_rn = configd_switchd_mark_success(
        tx_id, resp, resp_size, &mark_ec);
    return mark_rn >= 0 && mark_ec == 0;
}

static bool journal_finalize_failure(u64 tx_id, bool force_out_of_sync) {
    if (!force_out_of_sync && configd_scope_engaged()) {
        char response[512] = {0}; s32 ec = 0;
        int rn = configd_switchd_mark_failed(tx_id, response, sizeof(response), &ec);
        if (rn < 0 || ec) force_out_of_sync = true;
    }
    if (!force_out_of_sync &&
        nl_journal_update_state(
            tx_id, NL_JOURNAL_FAILED_ROLLED_BACK) == NL_OK)
        return false;

    if (nl_journal_update_state(
            tx_id, NL_JOURNAL_HW_OUT_OF_SYNC) != NL_OK) {
        NL_LOG_CRIT("journal tx=0x%lx could not persist HW_OUT_OF_SYNC",
                    tx_id);
    }
    g_ctx.hw_out_of_sync = true;
    return true;
}

static int send_text(nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
                     const char *text) {
    size_t len = text ? strlen(text) : 0;
    nl_msg_hdr *resp = nl_msg_alloc((u32)len);

    if (!resp)
        return -1;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
    return 0;
}

/*
 * Compose an error from trusted framing and bounded backend diagnostics.
 * The required suffix is reserved before either diagnostic is copied so a
 * large SDK/owner response cannot hide rollback or repair-finalization state.
 */
static size_t compose_bounded_error_text(
        char *response, size_t response_size, const char *prefix,
        const char *detail, const char *required_suffix,
        const char *trailing_detail) {
    size_t max_payload_bytes;
    size_t prefix_length;
    size_t suffix_length;
    size_t trailing_length;
    size_t detail_length;
    size_t trailing_limit;
    size_t remaining;
    size_t offset = 0;

    if (!response || response_size == 0)
        return 0;
    max_payload_bytes = response_size - 1U;
    prefix = prefix ? prefix : "";
    detail = detail ? detail : "";
    required_suffix = required_suffix ? required_suffix : "";
    trailing_detail = trailing_detail ? trailing_detail : "";

    prefix_length = strnlen(prefix, max_payload_bytes);
    remaining = max_payload_bytes - prefix_length;
    suffix_length = strnlen(required_suffix, remaining);
    remaining -= suffix_length;
    trailing_limit = remaining < CONFIGD_ERROR_TRAILING_DETAIL_MAX_BYTES ?
        remaining : CONFIGD_ERROR_TRAILING_DETAIL_MAX_BYTES;
    trailing_length = strnlen(trailing_detail, trailing_limit);
    detail_length = strnlen(detail, remaining - trailing_length);

    if (prefix_length > 0) {
        memcpy(response + offset, prefix, prefix_length);
        offset += prefix_length;
    }
    if (detail_length > 0) {
        memcpy(response + offset, detail, detail_length);
        offset += detail_length;
    }
    if (suffix_length > 0) {
        memcpy(response + offset, required_suffix, suffix_length);
        offset += suffix_length;
    }
    if (trailing_length > 0) {
        memcpy(response + offset, trailing_detail, trailing_length);
        offset += trailing_length;
    }
    response[offset] = '\0';
    return offset;
}

static int send_bounded_error_response(
        nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
        size_t max_payload_bytes, const char *prefix, const char *detail,
        const char *required_suffix, const char *trailing_detail) {
    char response[CONFIGD_LONG_ERROR_RESPONSE_MAX_BYTES + 1U];

    if (max_payload_bytes > CONFIGD_LONG_ERROR_RESPONSE_MAX_BYTES)
        max_payload_bytes = CONFIGD_LONG_ERROR_RESPONSE_MAX_BYTES;
    (void)compose_bounded_error_text(
        response, max_payload_bytes + 1U, prefix, detail,
        required_suffix, trailing_detail);
    return send_text(conn, msg, error_code, response);
}

static bool reject_candidate_public_capabilities(nl_conn *conn,
                                                 nl_msg_hdr *msg) {
    char detail[512] = {0};
    char response[640];

    if (configd_public_capabilities_validate(
            g_ctx.candidate, detail, sizeof(detail)))
        return false;
    snprintf(response, sizeof(response),
             "error: commit rejected: %s",
             detail[0] ? detail :
             "public capability authority rejected candidate");
    send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE, response);
    return true;
}

static void refresh_public_capability_cleanup_required(void) {
    char detail[512] = {0};
    bool was_required = g_ctx.public_capability_cleanup_required;

    g_ctx.public_capability_cleanup_required =
        configd_public_capabilities_cleanup_required(
            g_ctx.active, detail, sizeof(detail));
    if (g_ctx.public_capability_cleanup_required && !was_required)
        NL_LOG_WARN("active configuration requires closed-capability cleanup: %s",
                    detail[0] ? detail : "closed intent is present");
    else if (!g_ctx.public_capability_cleanup_required && was_required)
        NL_LOG_NOTICE(
            "active configuration no longer contains closed-capability intent");
}

static int handle_public_capability_status(nl_conn *conn,
                                           nl_msg_hdr *msg) {
    configd_public_capability_status status;
    char inspection_detail[256] = {0};
    char response[4096];
    size_t offset = 0;
    int written;
    bool inspection_complete;
    bool closed_intent;
    bool cleanup_or_unknown;
    const char *cleanup_required;
    const char *replay_admission;
    const char *replay_deferred;
    const char *replay_reason;

    inspection_complete = configd_public_capabilities_status(
        g_ctx.active, &status, inspection_detail,
        sizeof(inspection_detail));
    closed_intent = g_ctx.public_capability_cleanup_required ||
        status.closed_root_count > 0;
    cleanup_or_unknown = closed_intent || !inspection_complete;
    cleanup_required = cleanup_or_unknown ?
        "true" : "false";
    replay_admission = cleanup_or_unknown ?
        "deferred" : "eligible";
    replay_deferred = cleanup_or_unknown ?
        "true" : "false";
    replay_reason = !inspection_complete ?
        "capability-inspection-incomplete" :
        (closed_intent ?
         "closed-public-capability-intent" : "none");
    written = snprintf(
        response, sizeof(response),
        "<configd-public-capability-status schema=\"1\" "
        "cleanup-required=\"%s\" inspection-complete=\"%s\" "
        "active-commit-id=\"%016lx\">\n"
        "  <active-replay admission=\"%s\" deferred=\"%s\" "
        "reason-code=\"%s\"/>\n"
        "  <closed-roots count=\"%zu\">\n",
        cleanup_required, inspection_complete ? "true" : "false",
        g_ctx.active_commit_id, replay_admission, replay_deferred,
        replay_reason, status.closed_root_count);
    if (written < 0 || (size_t)written >= sizeof(response))
        return send_text(conn, msg, (s32)NL_ERR,
                         "error: public capability status exceeds response capacity");
    offset = (size_t)written;
    for (size_t i = 0; i < status.closed_root_count; i++) {
        const configd_public_capability_closed_root *root =
            &status.closed_roots[i];

        written = snprintf(
            response + offset, sizeof(response) - offset,
            "    <closed-root capability-id=\"%s\" xpath=\"%s\" "
            "cleanup-delete-command=\"%s\"/>\n",
            root->capability_id, root->xpath,
            root->cleanup_delete_command);
        if (written < 0 || (size_t)written >= sizeof(response) - offset)
            return send_text(
                conn, msg, (s32)NL_ERR,
                "error: public capability status exceeds response capacity");
        offset += (size_t)written;
    }
    written = snprintf(
        response + offset, sizeof(response) - offset,
        "  </closed-roots>\n"
        "  <inspection-detail>%s</inspection-detail>\n"
        "</configd-public-capability-status>",
        inspection_complete ? "" : inspection_detail);
    if (written < 0 || (size_t)written >= sizeof(response) - offset)
        return send_text(conn, msg, (s32)NL_ERR,
                         "error: public capability status exceeds response capacity");
    return send_text(conn, msg, 0, response);
}

static bool reject_noncleanup_candidate_when_required(
        nl_conn *conn, nl_msg_hdr *msg) {
    char detail[512] = {0};
    char response[704];

    if (!g_ctx.public_capability_cleanup_required)
        return false;
    if (configd_public_capabilities_cleanup_candidate(
            g_ctx.active, g_ctx.candidate, detail, sizeof(detail)))
        return false;
    snprintf(response, sizeof(response),
             "error: active configuration requires a cleanup-only commit: %s",
             detail[0] ? detail :
             "remove all closed public capability intent before other changes");
    send_text(conn, msg, (s32)NL_ERR_COMMIT_LOCKED, response);
    return true;
}

static void active_path_buf(char *buf, size_t size) {
    nl_config_file_path(buf, size, "active.conf");
}

typedef enum {
    PRODUCTION_GUARD_POINTER_NONE = 0,
    PRODUCTION_GUARD_POINTER_VALID,
    PRODUCTION_GUARD_POINTER_INVALID,
} production_guard_pointer_result;

typedef struct {
    char *content;
    size_t length;
    char sha256[65];
    bool armed;
    bool finalizing;
    bool completed;
} production_guard_pointer;

static void production_control_path_buf(char *buf, size_t size,
                                        const char *name) {
    snprintf(buf, size, "%s/%s/%s", nl_config_dir(),
             CONFIGD_PRODUCTION_CONTROL_DIR, name);
}

static int fsync_parent_dir(const char *path);

static bool production_control_directory_ready(void) {
    char path[512];
    struct stat st;
    bool created = false;
    int dir_fd;
    int sync_rc;
    int close_rc;

    snprintf(path, sizeof(path), "%s/%s", nl_config_dir(),
             CONFIGD_PRODUCTION_CONTROL_DIR);
    if (mkdir(path, 0700) == 0)
        created = true;
    else if (errno != EEXIST)
        return false;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
        S_ISLNK(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
        (st.st_mode & 0777) != 0700)
        return false;
    if (created) {
        dir_fd = open(
            path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dir_fd < 0)
            return false;
        sync_rc = fsync(dir_fd);
        close_rc = close(dir_fd);
        if (sync_rc != 0 || close_rc != 0)
            return false;
        if (fsync_parent_dir(path) != 0)
            return false;
    }
    return true;
}

static int production_authority_lock(bool nonblocking) {
    char path[512];
    struct stat st;
    int fd;
    int operation = LOCK_EX;

    if (!production_control_directory_ready())
        return -1;
    production_control_path_buf(
        path, sizeof(path), CONFIGD_AUTHORITY_LOCK_FILE);
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != 0 || st.st_nlink != 1 || (st.st_mode & 0777) != 0600) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    if (nonblocking)
        operation |= LOCK_NB;
    if (flock(fd, operation) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static void production_authority_unlock(int fd) {
    if (fd < 0)
        return;
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
}

static bool pointer_member_matches(const char *content, size_t length,
                                   size_t offset, const char *literal) {
    size_t literal_length;

    if (!content || !literal)
        return false;
    literal_length = strlen(literal);
    return offset + literal_length <= length - 1U &&
           memcmp(content + offset, literal, literal_length) == 0 &&
           (content[offset + literal_length] == ',' ||
            content[offset + literal_length] == '}');
}

/*
 * active.json is canonical JSON, but finalizing/completed records embed the
 * original armed pointer as a nested object.  A raw substring search would
 * therefore see both the outer state and the nested "armed" state and reject
 * every legitimate finalization.  Scan JSON structure and classify only
 * direct members of the root object.
 */
static bool classify_canonical_pointer(const char *content, size_t length,
                                       bool *armed, bool *finalizing,
                                       bool *completed) {
    static const char contract[] =
        "\"contract\":\"netlab-production-active-guard\"";
    static const char armed_member[] = "\"state\":\"armed\"";
    static const char finalizing_member[] = "\"state\":\"finalizing\"";
    static const char completed_member[] = "\"state\":\"completed\"";
    char stack[128];
    size_t depth = 0;
    unsigned contract_count = 0;
    unsigned state_count = 0;
    bool in_string = false;
    bool escaped = false;

    if (!content || !armed || !finalizing || !completed || length < 4U ||
        content[0] != '{' || content[length - 2U] != '}' ||
        content[length - 1U] != '\n' ||
        memchr(content, '\0', length) != NULL)
        return false;
    *armed = false;
    *finalizing = false;
    *completed = false;

    for (size_t i = 0; i < length - 1U; i++) {
        unsigned char ch = (unsigned char)content[i];

        if (in_string) {
            if (escaped) {
                if (ch == 'u') {
                    if (i + 4U >= length - 1U)
                        return false;
                    for (size_t digit = 1; digit <= 4U; digit++) {
                        if (!isxdigit((unsigned char)content[i + digit]))
                            return false;
                    }
                    i += 4U;
                } else if (strchr("\"\\/bfnrt", (int)ch) == NULL) {
                    return false;
                }
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            } else if (ch < 0x20U) {
                return false;
            }
            continue;
        }
        if (ch == '"') {
            bool root_member = depth == 1U && stack[0] == '{' &&
                               (i == 1U || content[i - 1U] == ',');

            if (root_member) {
                if (pointer_member_matches(
                        content, length, i, contract))
                    contract_count++;
                if (pointer_member_matches(
                        content, length, i, armed_member)) {
                    *armed = true;
                    state_count++;
                } else if (pointer_member_matches(
                               content, length, i, finalizing_member)) {
                    *finalizing = true;
                    state_count++;
                } else if (pointer_member_matches(
                               content, length, i, completed_member)) {
                    *completed = true;
                    state_count++;
                }
            }
            in_string = true;
        } else if (ch == '{' || ch == '[') {
            if (depth >= sizeof(stack))
                return false;
            stack[depth++] = (char)ch;
        } else if (ch == '}' || ch == ']') {
            char expected = ch == '}' ? '{' : '[';

            if (depth == 0 || stack[depth - 1U] != expected)
                return false;
            depth--;
            if (depth == 0 && i != length - 2U)
                return false;
        } else if (isspace(ch)) {
            /* Canonical JSON has no whitespace except its final newline. */
            return false;
        }
    }
    return !in_string && !escaped && depth == 0 &&
           contract_count == 1U && state_count == 1U;
}

static production_guard_pointer_result read_production_guard_pointer(
    production_guard_pointer *pointer) {
    char path[512];
    struct stat before;
    struct stat opened;
    struct stat after;
    size_t offset = 0;
    int fd = -1;

    if (!pointer)
        return PRODUCTION_GUARD_POINTER_INVALID;
    memset(pointer, 0, sizeof(*pointer));
    production_control_path_buf(
        path, sizeof(path), CONFIGD_ACTIVE_GUARD_FILE);
    if (lstat(path, &before) != 0)
        return errno == ENOENT ? PRODUCTION_GUARD_POINTER_NONE :
                                PRODUCTION_GUARD_POINTER_INVALID;
    if (!S_ISREG(before.st_mode) || S_ISLNK(before.st_mode) ||
        before.st_uid != 0 || before.st_gid != 0 || before.st_nlink != 1 ||
        (before.st_mode & 0777) != 0600 || before.st_size <= 0 ||
        before.st_size > (off_t)CONFIGD_ACTIVE_GUARD_MAX_BYTES)
        return PRODUCTION_GUARD_POINTER_INVALID;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
        opened.st_size != before.st_size || !S_ISREG(opened.st_mode) ||
        opened.st_uid != 0 || opened.st_gid != 0 || opened.st_nlink != 1 ||
        (opened.st_mode & 0777) != 0600)
        goto invalid;
    pointer->content = calloc(1, (size_t)opened.st_size + 1U);
    if (!pointer->content)
        goto invalid;
    while (offset < (size_t)opened.st_size) {
        ssize_t n = read(fd, pointer->content + offset,
                         (size_t)opened.st_size - offset);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto invalid;
        offset += (size_t)n;
    }
    if (close(fd) != 0) {
        fd = -1;
        goto invalid;
    }
    fd = -1;
    if (lstat(path, &after) != 0 || after.st_dev != opened.st_dev ||
        after.st_ino != opened.st_ino || after.st_size != opened.st_size ||
        !S_ISREG(after.st_mode) || after.st_uid != 0 || after.st_gid != 0 ||
        after.st_nlink != 1 || (after.st_mode & 0777) != 0600 ||
        after.st_mtim.tv_sec != opened.st_mtim.tv_sec ||
        after.st_mtim.tv_nsec != opened.st_mtim.tv_nsec ||
        !sha256_bytes_hex(pointer->content, offset, pointer->sha256))
        goto invalid;
    pointer->length = offset;
    if (!classify_canonical_pointer(
            pointer->content, pointer->length,
            &pointer->armed, &pointer->finalizing,
            &pointer->completed))
        goto invalid;
    return PRODUCTION_GUARD_POINTER_VALID;

invalid:
    if (fd >= 0)
        close(fd);
    free(pointer->content);
    memset(pointer, 0, sizeof(*pointer));
    return PRODUCTION_GUARD_POINTER_INVALID;
}

static void free_production_guard_pointer(
    production_guard_pointer *pointer) {
    if (!pointer)
        return;
    free(pointer->content);
    memset(pointer, 0, sizeof(*pointer));
}

static bool path_join_component(char *buf, size_t size,
                                const char *dir, const char *component) {
    size_t dir_length;
    size_t component_length;
    size_t offset;
    bool separator_required;

    if (!buf || size == 0)
        return false;
    buf[0] = '\0';
    if (!dir || !dir[0] || !component || !component[0])
        return false;
    dir_length = strlen(dir);
    component_length = strlen(component);
    separator_required = dir[dir_length - 1U] != '/';
    if (dir_length >= size)
        return false;
    offset = dir_length;
    if (separator_required) {
        if (offset + 1U >= size)
            return false;
        offset++;
    }
    if (component_length >= size - offset)
        return false;
    memcpy(buf, dir, dir_length);
    if (separator_required)
        buf[dir_length] = '/';
    memcpy(buf + offset, component, component_length);
    buf[offset + component_length] = '\0';
    return true;
}

static bool rollback_dir_buf(char *buf, size_t size) {
    return path_join_component(buf, size, nl_config_dir(), "rollback");
}

static bool rollback_path_buf(char *buf, size_t size, u64 commit_id) {
    char dir[512];
    char component[32];
    int written;

    if (!buf || size == 0)
        return false;
    buf[0] = '\0';
    written = snprintf(component, sizeof(component),
                       "%016" PRIx64 ".conf", commit_id);
    return written > 0 && (size_t)written < sizeof(component) &&
           rollback_dir_buf(dir, sizeof(dir)) &&
           path_join_component(buf, size, dir, component);
}

static bool rollback_commit_marker_path_buf(
    char *buf, size_t size, u64 commit_id) {
    char dir[512];
    char component[32];
    int written;

    if (!buf || size == 0)
        return false;
    buf[0] = '\0';
    written = snprintf(component, sizeof(component),
                       "%016" PRIx64 ".committed", commit_id);
    return written > 0 && (size_t)written < sizeof(component) &&
           rollback_dir_buf(dir, sizeof(dir)) &&
           path_join_component(buf, size, dir, component);
}

static void rollback_history_migration_path_buf(char *buf, size_t size) {
    nl_journal_file_path(
        buf, size, "rollback-history-commit-markers-v1");
}

static bool candidate_snapshot_dir_buf(char *buf, size_t size) {
    return path_join_component(buf, size, nl_journal_dir(), "candidates");
}

static bool candidate_snapshot_path_buf(
    char *buf, size_t size, u64 tx_id) {
    char dir[512];
    char component[32];
    int written;

    if (!buf || size == 0)
        return false;
    buf[0] = '\0';
    written = snprintf(component, sizeof(component),
                       "%016" PRIx64 ".conf", tx_id);
    return written > 0 && (size_t)written < sizeof(component) &&
           candidate_snapshot_dir_buf(dir, sizeof(dir)) &&
           path_join_component(buf, size, dir, component);
}

static bool commit_comment_path_buf(char *buf, size_t size, u64 commit_id) {
    char dir[512];
    char component[32];
    int written;

    if (!buf || size == 0)
        return false;
    buf[0] = '\0';
    written = snprintf(component, sizeof(component),
                       "%016" PRIx64 ".comment", commit_id);
    return written > 0 && (size_t)written < sizeof(component) &&
           rollback_dir_buf(dir, sizeof(dir)) &&
           path_join_component(buf, size, dir, component);
}

static int parent_dir_path(const char *path, char *dir, size_t dir_size,
                           const char **base) {
    const char *slash;
    size_t len;

    if (!path || !path[0] || !dir || dir_size == 0 || !base)
        return -1;
    slash = strrchr(path, '/');
    if (!slash) {
        if (snprintf(dir, dir_size, ".") >= (int)dir_size)
            return -1;
        *base = path;
        return 0;
    }
    len = (slash == path) ? 1 : (size_t)(slash - path);
    if (len == 0 || len >= dir_size)
        return -1;
    memcpy(dir, path, len);
    dir[len] = '\0';
    *base = slash + 1;
    return **base ? 0 : -1;
}

static int fsync_parent_dir(const char *path) {
    char dir[512];
    const char *base;
    int fd;
    int rc = 0;

    if (parent_dir_path(path, dir, sizeof(dir), &base) != 0)
        return -1;
    (void)base;
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return -1;
    if (fsync(fd) != 0)
        rc = -1;
    if (close(fd) != 0)
        rc = -1;
    return rc;
}

static int unlink_file_durable(const char *path) {
    if (!path)
        return -1;
    if (unlink(path) != 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    return fsync_parent_dir(path);
}

static int persist_text_file(const char *path, const char *text) {
    char dir[512];
    char tmpl[1024];
    const char *base;
    int fd;
    FILE *f;
    int rc = 0;

    if (!path || !text)
        return -1;
    if (parent_dir_path(path, dir, sizeof(dir), &base) != 0)
        return -1;
    if (snprintf(tmpl, sizeof(tmpl), "%s/.%s.tmp.XXXXXX", dir, base) >=
        (int)sizeof(tmpl))
        return -1;
    fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    if (fchmod(fd, 0600) != 0)
        rc = -1;
    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    if (fprintf(f, "%s\n", text) < 0)
        rc = -1;
    if (fflush(f) != 0)
        rc = -1;
    if (fsync(fd) != 0)
        rc = -1;
    if (fclose(f) != 0)
        rc = -1;
    if (rc != 0) {
        unlink(tmpl);
        return -1;
    }
    if (rename(tmpl, path) != 0) {
        unlink(tmpl);
        return -1;
    }
    if (fsync_parent_dir(path) != 0)
        return -1;
    return 0;
}

static int persist_xml_file(const char *path, const char *xml) {
    return persist_text_file(path, xml);
}

static bool text_matches_ignoring_trailing_newlines(
    const char *left, const char *right) {
    size_t left_len;
    size_t right_len;

    if (!left || !right)
        return false;
    left_len = strlen(left);
    right_len = strlen(right);
    while (left_len > 0 &&
           (left[left_len - 1] == '\n' || left[left_len - 1] == '\r'))
        left_len--;
    while (right_len > 0 &&
           (right[right_len - 1] == '\n' || right[right_len - 1] == '\r'))
        right_len--;
    return left_len == right_len &&
           memcmp(left, right, left_len) == 0;
}

static bool sanitize_commit_comment(const char *value, size_t value_len,
                                    char *comment, size_t comment_size,
                                    char *err, size_t err_size) {
    size_t out = 0;

    if (comment && comment_size > 0)
        comment[0] = '\0';
    while (value_len > 0 && *value && isspace((unsigned char)*value)) {
        value++;
        value_len--;
    }
    while (value_len > 0 &&
           isspace((unsigned char)value[value_len - 1]))
        value_len--;
    if (value_len == 0) {
        if (err && err_size > 0)
            snprintf(err, err_size, "commit comment cannot be empty");
        return false;
    }
    if (value_len >= comment_size) {
        if (err && err_size > 0)
            snprintf(err, err_size, "commit comment is too long");
        return false;
    }
    for (size_t i = 0; i < value_len; i++) {
        unsigned char ch = (unsigned char)value[i];
        if (ch == '\r' || ch == '\n' || ch == '\t')
            comment[out++] = ' ';
        else if (ch == '"')
            comment[out++] = '\'';
        else
            comment[out++] = (char)ch;
    }
    comment[out] = '\0';
    return true;
}

static bool parse_commit_options(const nl_msg_hdr *msg,
                                 configd_commit_options *opts,
                                 char *err, size_t err_size) {
    char payload[512];
    char *cursor;

    if (!opts)
        return false;
    memset(opts, 0, sizeof(*opts));
    opts->confirm_seconds = CONFIGD_CONFIRMED_DEFAULT_SECONDS;
    opts->confirmed = msg &&
        msg->method == NL_CONFIGD_COMMIT_CONFIRMED;
    if (err && err_size > 0)
        err[0] = '\0';
    if (!msg || msg->payload_len == 0)
        return true;
    if (msg->payload_len >= sizeof(payload)) {
        if (err && err_size > 0)
            snprintf(err, err_size, "commit option payload is too large");
        return false;
    }

    memcpy(payload, msg->payload, msg->payload_len);
    payload[msg->payload_len] = '\0';
    if (msg->method == NL_CONFIGD_COMMIT_CONFIRMED &&
        strchr(payload, '=') == NULL) {
        char *end = NULL;
        long seconds = strtol(payload, &end, 10);

        while (end && *end && isspace((unsigned char)*end))
            end++;
        if (!end || *end != '\0' ||
            seconds < CONFIGD_CONFIRMED_MIN_SECONDS ||
            seconds > CONFIGD_CONFIRMED_MAX_SECONDS) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "confirmed timeout must be %d-%d seconds",
                         CONFIGD_CONFIRMED_MIN_SECONDS,
                         CONFIGD_CONFIRMED_MAX_SECONDS);
            return false;
        }
        opts->confirm_seconds = seconds;
        return true;
    }
    cursor = payload;
    while (cursor && *cursor) {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');
        char *value;
        size_t value_len;

        if (newline) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor = NULL;
        }
        while (*line && isspace((unsigned char)*line))
            line++;
        if (!*line)
            continue;
        value = strchr(line, '=');
        if (!value) {
            if (err && err_size > 0)
                snprintf(err, err_size, "unsupported commit option");
            return false;
        }
        *value++ = '\0';
        value_len = strlen(value);
        while (value_len > 0 &&
               isspace((unsigned char)value[value_len - 1]))
            value_len--;
        if (strcmp(line, "comment") == 0) {
            if (!sanitize_commit_comment(value, value_len, opts->comment,
                                         sizeof(opts->comment), err, err_size))
                return false;
        } else if (strcmp(line, "confirmed") == 0) {
            char number[32];
            char *end = NULL;
            long seconds;

            if (value_len == 0 || value_len >= sizeof(number)) {
                if (err && err_size > 0)
                    snprintf(err, err_size, "invalid confirmed timeout");
                return false;
            }
            memcpy(number, value, value_len);
            number[value_len] = '\0';
            seconds = strtol(number, &end, 10);
            if (!end || *end != '\0' ||
                seconds < CONFIGD_CONFIRMED_MIN_SECONDS ||
                seconds > CONFIGD_CONFIRMED_MAX_SECONDS) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "confirmed timeout must be %d-%d seconds",
                             CONFIGD_CONFIRMED_MIN_SECONDS,
                             CONFIGD_CONFIRMED_MAX_SECONDS);
                return false;
            }
            opts->confirmed = true;
            opts->confirm_seconds = seconds;
        } else {
            if (err && err_size > 0)
                snprintf(err, err_size, "unsupported commit option");
            return false;
        }
    }
    return true;
}

static int persist_commit_comment(u64 commit_id, const char *comment) {
    char path[512];

    if (commit_id == 0 || !comment || !comment[0])
        return 0;
    if (!commit_comment_path_buf(path, sizeof(path), commit_id))
        return -1;
    return persist_text_file(path, comment);
}

static void read_commit_comment(u64 commit_id, char *buf, size_t size) {
    char path[512];
    char *text;

    if (!buf || size == 0)
        return;
    buf[0] = '\0';
    if (!commit_comment_path_buf(path, sizeof(path), commit_id))
        return;
    text = read_text_file(path);
    if (!text)
        return;
    snprintf(buf, size, "%s", text);
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\t')
            buf[i] = ' ';
        if (buf[i] == '"')
            buf[i] = '\'';
    }
    while (buf[0]) {
        size_t len = strlen(buf);
        if (len == 0 || !isspace((unsigned char)buf[len - 1]))
            break;
        buf[len - 1] = '\0';
    }
    free(text);
}

static char *read_text_file(const char *path) {
    FILE *f;
    char *buf;
    long len;
    size_t n;

    if (!path)
        return NULL;
    f = fopen(path, "r");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    len = ftell(f);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = calloc(1, (size_t)len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/*
 * Configuration emptiness is a schema-tree property.  Looking for selected
 * XML tag spellings silently classified valid top-level branches as empty
 * whenever a new model branch was added.
 */
static bool tree_has_configuration(const struct lyd_node *tree) {
    return tree && lyd_child(tree) != NULL;
}

static config_xml_result parse_config_xml_data(
    nl_yang_session *session, const char *xml, struct lyd_node **data_tree) {
    struct lyd_node *tree;

    if (data_tree)
        *data_tree = NULL;
    if (!session || !xml || !data_tree)
        return CONFIG_XML_INVALID;
    tree = nl_yang_from_xml(session, xml);
    if (!tree || !tree->schema || !tree->schema->name ||
        strcmp(tree->schema->name, "netlab-config") != 0 || tree->next) {
        if (tree)
            lyd_free_all(tree);
        return CONFIG_XML_INVALID;
    }
    if (!tree_has_configuration(tree)) {
        lyd_free_all(tree);
        return CONFIG_XML_EMPTY;
    }
    *data_tree = tree;
    return CONFIG_XML_HAS_DATA;
}

static bool configd_public_capabilities_xml_replayable(
        const char *xml, char *detail, size_t detail_size) {
    struct lyd_node *tree = NULL;
    config_xml_result result;
    bool replayable;

    result = parse_config_xml_data(g_ctx.active, xml, &tree);
    if (result == CONFIG_XML_INVALID) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "configuration snapshot is not valid netlab XML");
        return false;
    }
    replayable = configd_public_capabilities_validate_tree(
        tree, detail, detail_size);
    lyd_free_all(tree);
    return replayable;
}

static int cmp_u64_asc(const void *a, const void *b) {
    u64 av = *(const u64 *)a;
    u64 bv = *(const u64 *)b;

    if (av < bv)
        return -1;
    if (av > bv)
        return 1;
    return 0;
}

static bool rollback_snapshot_digest(u64 commit_id, char digest[65]) {
    char path[512];
    char *xml;
    bool valid;

    if (commit_id == 0 || !digest)
        return false;
    if (!rollback_path_buf(path, sizeof(path), commit_id))
        return false;
    xml = read_text_file(path);
    if (!xml)
        return false;
    valid = candidate_sha256(xml, digest);
    free(xml);
    return valid;
}

static bool rollback_commit_marker_valid(
    u64 commit_id, const char *digest) {
    char path[512];
    char expected[192];
    char *content;
    bool valid;

    if (commit_id == 0 || !digest || strlen(digest) != 64)
        return false;
    if (!rollback_commit_marker_path_buf(
            path, sizeof(path), commit_id))
        return false;
    content = read_text_file(path);
    if (!content)
        return false;
    snprintf(expected, sizeof(expected),
             "netlab-committed-snapshot-v1\n"
             "tx-id=0x%016lx\n"
             "sha256=%s",
             commit_id, digest);
    valid = text_matches_ignoring_trailing_newlines(content, expected);
    free(content);
    return valid;
}

static bool rollback_journal_proves_committed(
    u64 commit_id, const char *digest) {
    nl_commit_journal journal;

    return commit_id != 0 && digest && strlen(digest) == 64 &&
           nl_journal_get(commit_id, &journal) == NL_OK &&
           journal.state == NL_JOURNAL_COMMITTED &&
           journal.resulting_commit_id == commit_id &&
           strcmp(journal.candidate_hash, digest) == 0;
}

static int mark_rollback_snapshot_committed(u64 commit_id) {
    char path[512];
    char content[192];
    char digest[65];
    struct stat st;

    if (commit_id == 0)
        return 0;
    if (!rollback_snapshot_digest(commit_id, digest))
        return -1;
    if (!rollback_commit_marker_path_buf(
            path, sizeof(path), commit_id))
        return -1;
    if (lstat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode))
            return -1;
        return rollback_commit_marker_valid(commit_id, digest) ? 0 : -1;
    }
    if (errno != ENOENT)
        return -1;
    snprintf(content, sizeof(content),
             "netlab-committed-snapshot-v1\n"
             "tx-id=0x%016lx\n"
             "sha256=%s",
             commit_id, digest);
    return persist_text_file(path, content);
}

static bool rollback_snapshot_is_committed(
    u64 commit_id, u64 active_commit_id) {
    char digest[65];

    if (commit_id == 0 || commit_id > active_commit_id)
        return false;
    /*
     * tx_counter is the unconditional proof for its selected payload.  Older
     * generations need either the explicit post-commit marker or a retained
     * terminal journal whose candidate hash binds the exact snapshot bytes.
     */
    if (commit_id == active_commit_id)
        return true;
    if (!rollback_snapshot_digest(commit_id, digest))
        return false;
    return rollback_commit_marker_valid(commit_id, digest) ||
           rollback_journal_proves_committed(commit_id, digest);
}

static int collect_rollback_ids_raw(
    u64 *ids, int max_ids, u64 max_commit_id) {
    DIR *d;
    struct dirent *entry;
    int n = 0;
    char rollback_dir[512];

    if (!ids || max_ids <= 0)
        return 0;
    if (!rollback_dir_buf(rollback_dir, sizeof(rollback_dir)))
        return -1;
    d = opendir(rollback_dir);
    if (!d)
        return 0;

    while ((entry = readdir(d)) != NULL) {
        char *end = NULL;
        u64 id;

        if (entry->d_name[0] == '.')
            continue;
        if (!strstr(entry->d_name, ".conf"))
            continue;
        id = strtoull(entry->d_name, &end, 16);
        if (!end || strcmp(end, ".conf") != 0)
            continue;
        if (id == 0)
            continue;
        if (max_commit_id > 0 && id > max_commit_id)
            continue;
        if (n < max_ids) {
            ids[n++] = id;
        } else {
            int min_idx = 0;
            for (int i = 1; i < n; i++) {
                if (ids[i] < ids[min_idx])
                    min_idx = i;
            }
            if (id > ids[min_idx])
                ids[min_idx] = id;
        }
    }
    closedir(d);
    qsort(ids, (size_t)n, sizeof(ids[0]), cmp_u64_asc);
    return n;
}

static int collect_rollback_ids(
    u64 *ids, int max_ids, u64 active_commit_id) {
    DIR *dir;
    struct dirent *entry;
    char rollback_dir[512];
    int count = 0;

    if (!ids || max_ids <= 0)
        return 0;
    if (!rollback_dir_buf(rollback_dir, sizeof(rollback_dir)))
        return -1;
    dir = opendir(rollback_dir);
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL) {
        char *end = NULL;
        u64 id;

        if (entry->d_name[0] == '.')
            continue;
        id = strtoull(entry->d_name, &end, 16);
        if (!end || strcmp(end, ".conf") != 0 ||
            id == 0 || id > active_commit_id ||
            !rollback_snapshot_is_committed(
                id, active_commit_id))
            continue;
        /*
         * Filter authority before bounding the result.  Failed transaction
         * gaps may be numerically newer than valid history and must never
         * crowd committed generations out of rollback/history responses.
         */
        if (count < max_ids) {
            ids[count++] = id;
        } else {
            int min_idx = 0;

            for (int i = 1; i < count; i++) {
                if (ids[i] < ids[min_idx])
                    min_idx = i;
            }
            if (id > ids[min_idx])
                ids[min_idx] = id;
        }
    }
    closedir(dir);
    qsort(ids, (size_t)count, sizeof(ids[0]), cmp_u64_asc);
    return count;
}

static int migrate_legacy_rollback_markers(u64 active_commit_id) {
    char path[512];
    char expected[128];
    char *existing;
    struct stat st;
    u64 ids[256];
    int count;

    rollback_history_migration_path_buf(path, sizeof(path));
    snprintf(expected, sizeof(expected),
             "netlab-rollback-history-marker-migration-v1\n"
             "legacy-cutoff=0x%016lx",
             active_commit_id);
    if (lstat(path, &st) == 0) {
        unsigned long cutoff = 0;
        int consumed = 0;
        const char *tail;
        bool valid;

        if (!S_ISREG(st.st_mode))
            return -1;
        existing = read_text_file(path);
        if (!existing)
            return -1;
        if (sscanf(existing,
                   "netlab-rollback-history-marker-migration-v1\n"
                   "legacy-cutoff=0x%16lx%n",
                   &cutoff, &consumed) != 1 ||
            consumed <= 0) {
            free(existing);
            return -1;
        }
        tail = existing + consumed;
        while (*tail && isspace((unsigned char)*tail))
            tail++;
        valid = *tail == '\0' && (u64)cutoff <= active_commit_id;
        free(existing);
        return valid ? 0 : -1;
    }
    if (errno != ENOENT)
        return -1;

    /*
     * This marker is created during daemon initialization, before this code
     * can accept its first transaction.  The previous implementation used a
     * contiguous committed-generation counter, so every pre-existing rollback
     * snapshot at or below the startup pointer is legacy committed history.
     * Once this migration record exists, new generations are admitted only by
     * their exact post-commit marker or terminal journal proof.
     */
    count = active_commit_id == 0 ? 0 :
        collect_rollback_ids_raw(
            ids, (int)(sizeof(ids) / sizeof(ids[0])),
            active_commit_id);
    if (count < 0)
        return -1;
    for (int i = 0; i < count; i++) {
        if (mark_rollback_snapshot_committed(ids[i]) != 0)
            return -1;
    }
    return persist_text_file(path, expected);
}

static int discard_staged_active_snapshot(
    u64 tx_id, u64 active_commit_id) {
    char snapshot_path[512];
    char marker_path[512];
    struct stat st;

    if (tx_id == 0 || tx_id == active_commit_id)
        return -1;
    if (!rollback_commit_marker_path_buf(
            marker_path, sizeof(marker_path), tx_id))
        return -1;
    if (lstat(marker_path, &st) == 0 || errno != ENOENT)
        return -1;
    if (!rollback_path_buf(snapshot_path, sizeof(snapshot_path), tx_id))
        return -1;
    return unlink_file_durable(snapshot_path);
}

static int prune_rollback_snapshots(u64 active_commit_id) {
    u64 ids[256];

    for (;;) {
        int n = collect_rollback_ids(
            ids, (int)(sizeof(ids) / sizeof(ids[0])),
            active_commit_id);
        int remove_count;

        if (n < 0)
            return -1;
        if (n <= NL_CONFIG_MAX_ROLLBACK)
            return 0;
        remove_count = n - NL_CONFIG_MAX_ROLLBACK;
        for (int i = 0; i < n && remove_count > 0; i++) {
            char path[512];
            char marker_path[512];
            char comment_path[512];

            if (ids[i] == active_commit_id)
                continue;
            if (!rollback_path_buf(path, sizeof(path), ids[i]) ||
                !rollback_commit_marker_path_buf(
                    marker_path, sizeof(marker_path), ids[i]) ||
                !commit_comment_path_buf(
                    comment_path, sizeof(comment_path), ids[i]))
                return -1;
            /*
             * Removing the snapshot first makes an interrupted prune
             * invisible to history enumeration.  Marker/comment orphans are
             * non-authoritative.  Re-scan after each bounded batch so even a
             * legacy directory larger than this work buffer converges to the
             * configured retention limit.
             */
            if (unlink_file_durable(path) != 0 ||
                unlink_file_durable(marker_path) != 0 ||
                unlink_file_durable(comment_path) != 0)
                return -1;
            remove_count--;
        }
        if (remove_count != 0)
            return -1;
    }
}

static int persist_immutable_snapshot(
    const char *path, const char *dir, u64 tx_id,
    const char *xml, const char *kind) {
    char *existing;
    struct stat dir_stat;

    if (!path || !dir || tx_id == 0 || !xml)
        return -1;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        NL_LOG_ERR(
            "failed to create %s snapshot dir %s",
            kind ? kind : "immutable", dir);
        return -1;
    }
    if (lstat(dir, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode)) {
        NL_LOG_ERR(
            "%s snapshot path is not a directory: %s",
            kind ? kind : "immutable", dir);
        return -1;
    }
    if (fsync_parent_dir(dir) != 0) {
        NL_LOG_ERR(
            "failed to persist %s snapshot directory %s",
            kind ? kind : "immutable", dir);
        return -1;
    }
    existing = read_text_file(path);
    if (existing) {
        if (!text_matches_ignoring_trailing_newlines(existing, xml)) {
            NL_LOG_CRIT(
                "immutable %s snapshot collision tx=0x%lx path=%s",
                kind ? kind : "transaction", tx_id, path);
            free(existing);
            return -1;
        }
        free(existing);
        return 0;
    }
    if (persist_xml_file(path, xml) != 0) {
        NL_LOG_ERR("failed to persist immutable %s snapshot %s",
                   kind ? kind : "transaction", path);
        return -1;
    }
    return 0;
}

static int persist_candidate_snapshot(u64 tx_id, const char *xml) {
    char path[512];
    char dir[512];

    if (!candidate_snapshot_dir_buf(dir, sizeof(dir)) ||
        !candidate_snapshot_path_buf(path, sizeof(path), tx_id))
        return -1;
    return persist_immutable_snapshot(
        path, dir, tx_id, xml, "candidate");
}

static int persist_active_snapshot(u64 commit_id, const char *xml) {
    char path[512];
    char rollback_dir[512];

    if (!rollback_dir_buf(rollback_dir, sizeof(rollback_dir)) ||
        !rollback_path_buf(path, sizeof(path), commit_id))
        return -1;
    if (persist_immutable_snapshot(
            path, rollback_dir, commit_id, xml, "active") != 0)
        return -1;
    return 0;
}

static char *empty_config_xml(void) {
    const char *empty = "<netlab-config/>";
    char *xml = calloc(1, strlen(empty) + 1);

    if (xml)
        strcpy(xml, empty);
    return xml;
}

static char *read_commit_snapshot_xml(u64 commit_id) {
    char path[512];

    if (commit_id == 0)
        return empty_config_xml();
    if (!rollback_path_buf(path, sizeof(path), commit_id))
        return NULL;
    return read_text_file(path);
}

static char *read_commit_snapshot_payload(u64 commit_id) {
    char *xml = read_commit_snapshot_xml(commit_id);
    if (xml && commit_id) {
        /* persist_text_file adds one framing LF. Strip exactly that byte
         * before republishing a stored snapshot, preserving its XML bytes. */
        size_t n = strlen(xml);
        if (!n || xml[n - 1] != '\n') { free(xml); return NULL; }
        xml[n - 1] = 0;
    }
    return xml;
}

typedef enum {
    ACTIVE_AUTHORITY_NOT_COMMITTED = 0,
    ACTIVE_AUTHORITY_COMMITTED = 1,
    ACTIVE_AUTHORITY_COMMITTED_POSTPUBLISH_FAILED = 2,
    ACTIVE_AUTHORITY_OBSERVED_NEW_UNCERTAIN = -1,
    ACTIVE_AUTHORITY_UNKNOWN = -2,
} active_authority_result;

static active_authority_result classify_active_pointer_save_failure(
    u64 previous_commit_id, u64 commit_id,
    nl_status read_status, u64 observed_commit_id) {
    if (read_status != NL_OK)
        return ACTIVE_AUTHORITY_UNKNOWN;
    if (observed_commit_id == previous_commit_id)
        return ACTIVE_AUTHORITY_NOT_COMMITTED;
    if (observed_commit_id == commit_id)
        return ACTIVE_AUTHORITY_OBSERVED_NEW_UNCERTAIN;
    return ACTIVE_AUTHORITY_UNKNOWN;
}

/*
 * The immutable snapshot is the payload and tx_counter is its only commit
 * point.  active.conf is a materialized mirror for readers that have not yet
 * moved to the pointer API; it is never startup authority.
 */
static active_authority_result persist_active_authority(
    u64 previous_commit_id, u64 commit_id, const char *xml) {
    char active_path[512];
    u64 observed = 0;

    if (persist_active_snapshot(commit_id, xml) != 0)
        return ACTIVE_AUTHORITY_NOT_COMMITTED;
    if (nl_tx_id_save(commit_id) != NL_OK) {
        active_authority_result classified;
        nl_status read_status;

        /*
         * An atomic rename can succeed even if its final directory fsync
         * reports an error.  Classify every observation explicitly: only the
         * exact old pointer authorizes rollback; an observed new pointer keeps
         * all before-images until restart resolves durability; unreadable or
         * third-generation pointers are conflicting authority.
         */
        read_status = nl_tx_id_load(&observed);
        classified = classify_active_pointer_save_failure(
            previous_commit_id, commit_id, read_status, observed);
        if (classified !=
            ACTIVE_AUTHORITY_OBSERVED_NEW_UNCERTAIN)
            return classified;

        /*
         * Align legacy readers with the currently observed pointer, but never
         * turn this visible observation into a durability claim or release a
         * hardware before-image.
         */
        active_path_buf(active_path, sizeof(active_path));
        (void)persist_xml_file(active_path, xml);
        return classified;
    }

    /*
     * The pointer is now the durable commit point.  active.conf is only its
     * materialized mirror and must not expose the candidate before this point.
     * Any failure from here forward retains all participant before-images and
     * is recovered as an already-committed authority.
     */
    active_path_buf(active_path, sizeof(active_path));
    if (persist_xml_file(active_path, xml) != 0 ||
        mark_rollback_snapshot_committed(commit_id) != 0 ||
        prune_rollback_snapshots(commit_id) != 0)
        return ACTIVE_AUTHORITY_COMMITTED_POSTPUBLISH_FAILED;
    return ACTIVE_AUTHORITY_COMMITTED;
}

static bool materialize_active_mirror(const char *xml) {
    char active_path[512];
    char *existing;
    bool matches;

    if (!xml)
        return false;
    active_path_buf(active_path, sizeof(active_path));
    existing = read_text_file(active_path);
    matches = existing &&
              text_matches_ignoring_trailing_newlines(existing, xml);
    free(existing);
    return matches || persist_xml_file(active_path, xml) == 0;
}

static bool repair_active_snapshot_metadata(void) {
    char *xml;
    bool repaired;

    if (g_ctx.active_commit_id == 0)
        return true;
    xml = read_commit_snapshot_xml(g_ctx.active_commit_id);
    if (!xml)
        return false;
    repaired = materialize_active_mirror(xml) &&
               mark_rollback_snapshot_committed(
                   g_ctx.active_commit_id) == 0 &&
               prune_rollback_snapshots(
                   g_ctx.active_commit_id) == 0;
    free(xml);
    return repaired;
}

static bool load_active_authority(void) {
    char active_path[512];
    char counter_path[512];
    char *xml = NULL;
    struct stat st;
    bool counter_exists;
    bool active_exists;

    nl_journal_file_path(counter_path, sizeof(counter_path), "tx_counter");
    active_path_buf(active_path, sizeof(active_path));
    counter_exists = stat(counter_path, &st) == 0 && S_ISREG(st.st_mode);
    active_exists = stat(active_path, &st) == 0 && S_ISREG(st.st_mode);

    if (nl_tx_id_load(&g_ctx.active_commit_id) != NL_OK) {
        /*
         * Generation zero is the explicit empty genesis authority.  An
         * existing mirror without a readable pointer is ambiguous and must
         * never become an implicit fallback authority.
         */
        if (counter_exists || active_exists) {
            NL_LOG_CRIT(
                "active authority unavailable: tx_counter is unreadable");
            return false;
        }
        g_ctx.active_commit_id = 0;
        xml = empty_config_xml();
        if (!xml || nl_tx_id_save(0) != NL_OK) {
            free(xml);
            NL_LOG_CRIT("failed to initialize empty active authority");
            return false;
        }
    } else {
        xml = read_commit_snapshot_xml(g_ctx.active_commit_id);
        if (!xml) {
            NL_LOG_CRIT(
                "active authority snapshot missing commit-id=0x%lx",
                g_ctx.active_commit_id);
            return false;
        }
    }

    if (!load_xml_into_sessions(xml)) {
        NL_LOG_CRIT(
            "active authority snapshot invalid commit-id=0x%lx",
            g_ctx.active_commit_id);
        free(xml);
        return false;
    }
    if (!materialize_active_mirror(xml)) {
        NL_LOG_CRIT(
            "failed to materialize active.conf from commit-id=0x%lx",
            g_ctx.active_commit_id);
        free(xml);
        return false;
    }
    if (migrate_legacy_rollback_markers(
            g_ctx.active_commit_id) != 0 ||
        mark_rollback_snapshot_committed(
            g_ctx.active_commit_id) != 0 ||
        prune_rollback_snapshots(g_ctx.active_commit_id) != 0) {
        NL_LOG_CRIT(
            "failed to establish committed rollback history metadata "
            "for commit-id=0x%lx",
            g_ctx.active_commit_id);
        free(xml);
        return false;
    }
    NL_LOG_INFO("loaded active authority commit-id=0x%lx (%zu bytes)",
                g_ctx.active_commit_id, strlen(xml));
    free(xml);
    return true;
}

static nl_yang_session *replay_source_session(const char *xml) {
    nl_yang_session *source = nl_yang_session_create(CONFIGD_YANG_DIR);
    struct lyd_node *tree = NULL;
    if (!source) return NULL;
    if (!xml || parse_config_xml_data(source, xml, &tree) == CONFIG_XML_INVALID) {
        nl_yang_session_destroy(source); return NULL;
    }
    nl_yang_data_set(source, tree);
    return source;
}

static int build_active_replay_journal_plan(
    const char *source_xml, char *journal_plan, size_t journal_plan_size) {
    char *l2_plan = configd_l2_plan_workspace();
    char *l3_plan = configd_l3_plan_workspace();
    char l2_error[512] = {0};
    char l3_error[512] = {0};
    int l2_plan_len = 0;
    int l3_plan_len = 0;
    bool has_l2 = false;
    bool has_l3 = false;

    if (!journal_plan || !g_ctx.active || !l2_plan || !l3_plan)
        return -1;
    nl_yang_session *source = source_xml ? replay_source_session(source_xml) : g_ctx.active;
    if (!source) return -1;
    bool failed = configd_l2_build_plan(
            source, g_ctx.active, true,
            l2_plan, NL_L2_PLAN_MAX_BYTES,
            &l2_plan_len, &has_l2,
            l2_error, sizeof(l2_error)) != 0 ||
        configd_l3_build_plan(
            source, g_ctx.active,
            l3_plan, NL_L3_PLAN_MAX_BYTES,
            &l3_plan_len, &has_l3,
            l3_error, sizeof(l3_error)) != 0;
    if (source_xml) nl_yang_session_destroy(source);
    if (failed) return -1;
    /*
     * Preserve the empty L3 owner cleanup on routed platforms. The fixed
     * FM10840 L2-only contract has no rpd owner; use the same participant
     * decision as replay_configuration_to_hardware().
     */
    has_l3 = configd_l3_full_replay_required(has_l3);
    (void)l2_plan_len;
    (void)l3_plan_len;
    return build_journal_plan(
        journal_plan, journal_plan_size, has_l2, has_l3);
}

static bool load_xml_into_sessions(const char *xml) {
    struct lyd_node *active_tree = NULL;
    struct lyd_node *candidate_tree = NULL;
    config_xml_result active_result;
    config_xml_result candidate_result;

    if (!xml)
        return false;
    active_result = parse_config_xml_data(
        g_ctx.active, xml, &active_tree);
    if (active_result == CONFIG_XML_INVALID)
        return false;
    candidate_result = parse_config_xml_data(
        g_ctx.candidate, xml, &candidate_tree);
    if (candidate_result == CONFIG_XML_INVALID) {
        if (active_tree)
            lyd_free_all(active_tree);
        return false;
    }
    nl_yang_data_set(g_ctx.active, active_tree);
    nl_yang_data_set(g_ctx.candidate, candidate_tree);
    refresh_public_capability_cleanup_required();
    return true;
}

/*
 * Replace only the volatile candidate.  The caller must still execute the
 * ordinary commit-check/commit path, which remains the sole owner of journal,
 * tx_counter, rollback snapshot, active mirror, and hardware publication.
 */
static nl_error_code validate_candidate_xml_payload_mode(
    const u8 *payload, u32 payload_len, bool replace_candidate, bool exact_bytes,
    char *detail, size_t detail_size) {
    char *xml = NULL;
    char *roundtrip = NULL;
    struct lyd_node *tree = NULL;
    size_t roundtrip_len;
    config_xml_result parse_result;

    if (detail && detail_size > 0)
        detail[0] = '\0';
    if (!g_ctx.candidate) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate configuration is unavailable");
        return NL_ERR_INVALID_VALUE;
    }
    if (!payload || payload_len == 0 ||
        payload_len > NETLAB_CONFIG_XML_MAX) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate XML payload size is invalid");
        return NL_ERR_INVALID_VALUE;
    }
    if (memchr(payload, '\0', payload_len) != NULL) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate XML contains an embedded NUL byte");
        return NL_ERR_INVALID_VALUE;
    }

    xml = malloc((size_t)payload_len + 1U);
    if (!xml) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate XML allocation failed");
        return (nl_error_code)NL_ERR;
    }
    memcpy(xml, payload, payload_len);
    xml[payload_len] = '\0';

    /*
     * nl_yang_from_xml() is the strict schema parse.  In particular, doing
     * this before the historical empty-config normalization prevents random
     * text (or an unknown XML document) from being accepted as an empty tree.
     */
    parse_result = parse_config_xml_data(g_ctx.candidate, xml, &tree);
    if (parse_result == CONFIG_XML_INVALID) {
        free(xml);
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate XML is not a valid netlab-config document");
        return NL_ERR_INVALID_VALUE;
    }

    if (!configd_public_capabilities_validate_tree(
            tree, detail, detail_size)) {
        if (tree)
            lyd_free_all(tree);
        free(xml);
        return NL_ERR_INVALID_VALUE;
    }

    if (parse_result == CONFIG_XML_EMPTY) {
        /* The explicit empty top container is represented by a NULL tree. */
        roundtrip = strdup(
            "<netlab-config xmlns=\"urn:netlab:config\"/>");
    } else if (lyd_print_mem(&roundtrip, tree, LYD_XML,
                             LYD_PRINT_WITHSIBLINGS) != LY_SUCCESS ||
               !roundtrip) {
        lyd_free_all(tree);
        free(xml);
        free(roundtrip);
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate XML cannot be serialized losslessly");
        return NL_ERR_INVALID_VALUE;
    }

    /*
     * persist_text_file() appends exactly one LF to the serializer output.
     * The guarded checkpoint digest is a raw-byte authority, so accepting a
     * normalized-equivalent payload here would let the subsequent commit
     * publish different bytes and make its restore proof fail after the
     * commit point.  Admit only the exact bytes that the commit will persist.
     */
    roundtrip_len = roundtrip ? strlen(roundtrip) : 0U;
    if (!roundtrip || roundtrip_len >= NETLAB_CONFIG_XML_MAX ||
        (exact_bytes && (payload_len != (u32)roundtrip_len + 1U ||
        memcmp(payload, roundtrip, roundtrip_len) != 0 ||
        payload[roundtrip_len] != '\n'))) {
        if (tree)
            lyd_free_all(tree);
        free(xml);
        free(roundtrip);
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "candidate XML does not match exact persisted canonical bytes");
        return NL_ERR_INVALID_VALUE;
    }

    free(roundtrip);
    free(xml);
    if (replace_candidate)
        nl_yang_data_set(g_ctx.candidate, tree);
    else if (tree)
        lyd_free_all(tree);
    return NL_ERR_OK;
}

static nl_error_code validate_candidate_xml_payload(
    const u8 *payload, u32 payload_len, bool replace_candidate,
    char *detail, size_t detail_size) {
    /* Guarded checkpoint restore is byte-authoritative. Only the panel's
     * versioned semantic request path opts into normalization below. */
    return validate_candidate_xml_payload_mode(
        payload, payload_len, replace_candidate, true, detail, detail_size);
}

static nl_error_code replace_candidate_xml_payload(
    const u8 *payload, u32 payload_len, char *detail, size_t detail_size) {
    return validate_candidate_xml_payload(
        payload, payload_len, true, detail, detail_size);
}

static void configd_confirm_pending_commit(void) {
    nl_commit_confirmed c;

    if (nl_confirmed_load(&c) != NL_OK)
        return;
    if (c.state != NL_CONFIRM_AWAITING)
        return;
    c.state = NL_CONFIRMED;
    (void)nl_confirmed_save(&c);
    NL_LOG_INFO("commit confirmed tx=0x%lx confirmed by commit",
                c.tx_id);
}

static bool configd_save_confirmed_awaiting(
    u64 tx_id, u64 previous_commit_id, s64 deadline) {
    nl_commit_confirmed c;
    nl_commit_journal journal;

    if (nl_journal_get(tx_id, &journal) != NL_OK || !journal.commit_confirmed ||
        journal.confirm_deadline != deadline || journal.confirm_previous_commit_id != previous_commit_id)
        return false;
    memset(&c, 0, sizeof(c));
    c.tx_id = tx_id;
    c.previous_commit_id = previous_commit_id;
    c.confirm_deadline = deadline;
    c.confirm_monotonic_deadline = journal.confirm_monotonic_deadline;
    memcpy(c.confirm_boot_id, journal.confirm_boot_id, sizeof(c.confirm_boot_id));
    c.state = NL_CONFIRM_AWAITING;
    if (nl_confirmed_save(&c) != NL_OK) {
        NL_LOG_ERR("commit confirmed tx=0x%lx failed to persist pending state",
                   tx_id);
        return false;
    }
    NL_LOG_INFO("commit confirmed tx=0x%lx awaiting confirmation for %ld seconds previous=0x%lx",
                tx_id, (long)nl_confirmed_remaining_seconds(&c), previous_commit_id);
    return true;
}

static bool configd_recover_active_confirmed_intent(void) {
    nl_commit_journal journal;
    nl_commit_confirmed confirmed;
    char confirmed_path[512];
    struct stat confirmed_stat;
    nl_status confirmed_status;
    bool active_intent = false;

    if (g_ctx.active_commit_id != 0 &&
        nl_journal_get(g_ctx.active_commit_id, &journal) == NL_OK &&
        journal.commit_confirmed) {
        if ((journal.state != NL_JOURNAL_VERIFY_OK &&
             journal.state != NL_JOURNAL_HW_MARKED_COMMITTED &&
             journal.state != NL_JOURNAL_COMMITTED &&
             journal.state != NL_JOURNAL_HW_OUT_OF_SYNC) ||
            journal.base_commit_id !=
                journal.confirm_previous_commit_id) {
            NL_LOG_CRIT(
                "active commit-confirmed journal has inconsistent "
                "authority tx=0x%lx state=%d base=0x%lx previous=0x%lx",
                journal.tx_id, (int)journal.state,
                journal.base_commit_id,
                journal.confirm_previous_commit_id);
            return false;
        }
        active_intent = true;
    }
    confirmed_status = nl_confirmed_load_readonly(&confirmed);
    if (confirmed_status != NL_OK) {
        nl_journal_file_path(
            confirmed_path, sizeof(confirmed_path), "confirmed.json");
        errno = 0;
        if (lstat(confirmed_path, &confirmed_stat) == 0 ||
            errno != ENOENT) {
            NL_LOG_CRIT(
                "commit-confirmed scheduling record exists but is "
                "unreadable or invalid for active tx=0x%lx",
                g_ctx.active_commit_id);
            return false;
        }
        if (!active_intent)
            return true;
    } else if (!active_intent) {
        if (confirmed.tx_id > g_ctx.active_commit_id ||
            (confirmed.tx_id == g_ctx.active_commit_id &&
             (confirmed.state == NL_CONFIRM_AWAITING ||
              confirmed.state == NL_TIMED_OUT))) {
            NL_LOG_CRIT(
                "commit-confirmed scheduling record has no matching "
                "active journal intent record=0x%lx active=0x%lx",
                confirmed.tx_id, g_ctx.active_commit_id);
            return false;
        }
        return true;
    } else {
        if (confirmed.tx_id == journal.tx_id &&
            confirmed.previous_commit_id ==
                journal.confirm_previous_commit_id &&
            confirmed.confirm_deadline ==
                journal.confirm_deadline &&
            confirmed.confirm_monotonic_deadline == journal.confirm_monotonic_deadline &&
            !strcmp(confirmed.confirm_boot_id, journal.confirm_boot_id))
            return true;
        if (confirmed.tx_id >= journal.tx_id) {
            NL_LOG_CRIT(
                "commit-confirmed scheduling authority conflicts with "
                "active journal tx=0x%lx record=0x%lx",
                journal.tx_id, confirmed.tx_id);
            return false;
        }
    }
    NL_LOG_WARN(
        "recovering commit-confirmed intent from journal tx=0x%lx",
        journal.tx_id);
    return configd_save_confirmed_awaiting(
        journal.tx_id, journal.confirm_previous_commit_id,
        journal.confirm_deadline);
}

static bool confirmed_record_matches_active_intent(
    const nl_commit_confirmed *confirmed) {
    nl_commit_journal journal;

    return confirmed && confirmed->tx_id != 0 &&
           (confirmed->state == NL_CONFIRM_AWAITING ||
            confirmed->state == NL_TIMED_OUT) &&
           g_ctx.active_commit_id == confirmed->tx_id &&
           nl_journal_get(confirmed->tx_id, &journal) == NL_OK &&
           journal.state == NL_JOURNAL_COMMITTED &&
           journal.resulting_commit_id == confirmed->tx_id &&
           journal.commit_confirmed &&
           journal.base_commit_id ==
               confirmed->previous_commit_id &&
           journal.confirm_deadline == confirmed->confirm_deadline &&
           journal.confirm_monotonic_deadline == confirmed->confirm_monotonic_deadline &&
           !strcmp(journal.confirm_boot_id, confirmed->confirm_boot_id) &&
           journal.confirm_previous_commit_id ==
               confirmed->previous_commit_id;
}

static bool configd_confirmed_timeout_due(nl_commit_confirmed *c) {

    if (!c)
        return false;
    if (c->state == NL_CONFIRMED) {
        if (c->tx_id > g_ctx.active_commit_id) {
            g_ctx.hw_out_of_sync = true;
            NL_LOG_CRIT(
                "future confirmed record tx=0x%lx active=0x%lx",
                c->tx_id, g_ctx.active_commit_id);
        }
        return false;
    }
    if (c->state == NL_TIMED_OUT) {
        if (g_ctx.active_commit_id == c->tx_id)
            return true;
        if (g_ctx.active_commit_id < c->tx_id) {
            g_ctx.hw_out_of_sync = true;
            NL_LOG_CRIT(
                "future commit-confirmed timeout record tx=0x%lx "
                "active=0x%lx; refusing rollback",
                c->tx_id, g_ctx.active_commit_id);
        }
        return false;
    }
    if (c->state != NL_CONFIRM_AWAITING)
        return false;
    if (g_ctx.active_commit_id != c->tx_id) {
        /*
         * Only the currently active generation may time out.  A newer commit
         * confirms it; a non-active staged record never authorizes rollback.
         */
        if (g_ctx.active_commit_id > c->tx_id) {
            c->state = NL_CONFIRMED;
            if (nl_confirmed_save(c) != NL_OK)
                g_ctx.hw_out_of_sync = true;
        } else {
            g_ctx.hw_out_of_sync = true;
            NL_LOG_CRIT(
                "future commit-confirmed awaiting record tx=0x%lx "
                "active=0x%lx; refusing rollback",
                c->tx_id, g_ctx.active_commit_id);
        }
        return false;
    }
    if (!confirmed_record_matches_active_intent(c)) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT(
            "awaiting commit-confirmed record does not match active "
            "journal intent tx=0x%lx active=0x%lx",
            c->tx_id, g_ctx.active_commit_id);
        return false;
    }
    s64 remaining = nl_confirmed_remaining_seconds(c);
    if (remaining < 0) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT("cannot verify commit-confirmed clock; refusing automatic rollback");
        return false;
    }
    return remaining == 0;
}

static void configd_apply_confirmed_timeout(nl_commit_confirmed *c) {
    char *previous_xml;
    char *current_xml;
    char detail[512] = {0};
    u64 old_commit_id;
    u64 rollback_tx_id;
    nl_error_code replay_rc;
    active_authority_result authority;
    char candidate_hash[65];
    char journal_plan[1024];
    bool journal_created = false;

    if (!c)
        return;
    /*
     * confirmed.json is a scheduling record, never rollback authority by
     * itself.  Bind it again at the mutation boundary to the exact committed
     * journal intent selected by tx_counter.
     */
    if (!confirmed_record_matches_active_intent(c)) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT(
            "commit-confirmed record does not match active journal intent "
            "tx=0x%lx active=0x%lx; refusing rollback",
            c->tx_id, g_ctx.active_commit_id);
        return;
    }
    if (g_ctx.commit_locked || g_ctx.hw_out_of_sync)
        return;
    old_commit_id = g_ctx.active_commit_id;
    current_xml = read_commit_snapshot_payload(old_commit_id);
    if (!current_xml) {
        g_ctx.hw_out_of_sync = true;
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timed out but current active snapshot 0x%lx is unavailable",
            c->tx_id, old_commit_id);
        return;
    }
    previous_xml = read_commit_snapshot_payload(c->previous_commit_id);
    if (!previous_xml) {
        free(current_xml);
        g_ctx.hw_out_of_sync = true;
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT("commit confirmed tx=0x%lx timed out but previous snapshot 0x%lx is unavailable",
                    c->tx_id, c->previous_commit_id);
        return;
    }
    if (!configd_public_capabilities_xml_replayable(
            previous_xml, detail, sizeof(detail))) {
        free(current_xml);
        free(previous_xml);
        g_ctx.hw_out_of_sync = true;
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timed out but previous snapshot "
            "cannot be replayed by current public capability authority: %s",
            c->tx_id, detail[0] ? detail : "closed capability intent");
        return;
    }
    if (!load_xml_into_sessions(previous_xml)) {
        (void)load_xml_into_sessions(current_xml);
        free(current_xml);
        free(previous_xml);
        g_ctx.hw_out_of_sync = true;
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT("commit confirmed tx=0x%lx timed out but previous snapshot is invalid",
                    c->tx_id);
        return;
    }

    if (nl_tx_sequence_next(old_commit_id, &rollback_tx_id) != NL_OK) {
        (void)load_xml_into_sessions(current_xml);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback could not reserve transaction id",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }

    if (!candidate_sha256(previous_xml, candidate_hash) ||
        build_active_replay_journal_plan(
            current_xml, journal_plan, sizeof(journal_plan)) != 0 ||
        nl_journal_create(
            rollback_tx_id, old_commit_id, candidate_hash) != NL_OK) {
        (void)load_xml_into_sessions(current_xml);
        (void)materialize_active_mirror(current_xml);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback journal creation failed",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }
    journal_created = true;
    if (nl_journal_set_plan(rollback_tx_id, journal_plan) != NL_OK ||
        persist_candidate_snapshot(rollback_tx_id, previous_xml) != 0 ||
        nl_journal_update_state(
            rollback_tx_id, NL_JOURNAL_APPLYING) != NL_OK) {
        (void)journal_finalize_failure(rollback_tx_id, false);
        (void)load_xml_into_sessions(current_xml);
        (void)materialize_active_mirror(current_xml);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback preparation failed",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }

    /*
     * A confirmed-timeout rollback is a new committed configuration.  Publish
     * its immutable payload first, then converge hardware to that authority;
     * replay may release its own method-40 snapshot only after the pointer is
     * committed.
     */
    authority = persist_active_authority(
        old_commit_id, rollback_tx_id, previous_xml);
    if (authority == ACTIVE_AUTHORITY_NOT_COMMITTED) {
        bool restored = load_xml_into_sessions(current_xml) &&
                        materialize_active_mirror(current_xml);
        bool discarded = discard_staged_active_snapshot(
                             rollback_tx_id, old_commit_id) == 0;
        bool blocked;

        blocked = journal_created &&
                  journal_finalize_failure(
                      rollback_tx_id, !restored || !discarded);
        if (!restored || !discarded || blocked)
            g_ctx.hw_out_of_sync = true;
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback publication "
            "did not commit restore=%s staged-discard=%s",
            c->tx_id, restored ? "ok" : "failed",
            discarded ? "ok" : "failed");
        free(current_xml);
        free(previous_xml);
        return;
    }
    if (authority == ACTIVE_AUTHORITY_UNKNOWN) {
        (void)load_xml_into_sessions(current_xml);
        g_ctx.hw_out_of_sync = true;
        g_ctx.active_authority_uncertain = true;
        (void)journal_finalize_failure(rollback_tx_id, true);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback commit point durability is unknown",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }
    g_ctx.active_commit_id = rollback_tx_id;
    if (authority == ACTIVE_AUTHORITY_OBSERVED_NEW_UNCERTAIN) {
        g_ctx.hw_out_of_sync = true;
        g_ctx.active_authority_uncertain = true;
        (void)journal_finalize_failure(rollback_tx_id, true);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback pointer observes "
            "the new generation but durability is unknown",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }
    if (authority ==
        ACTIVE_AUTHORITY_COMMITTED_POSTPUBLISH_FAILED) {
        g_ctx.hw_out_of_sync = true;
        (void)journal_finalize_failure(rollback_tx_id, true);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback authority "
            "committed but mirror/history finalization failed",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }

    replay_rc = replay_snapshot_to_active(current_xml, rollback_tx_id, detail, sizeof(detail));
    if (replay_rc != NL_ERR_OK) {
        g_ctx.hw_out_of_sync = true;
        (void)journal_finalize_failure(rollback_tx_id, true);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT("commit confirmed tx=0x%lx timeout rollback failed: %s",
                    c->tx_id, detail);
        free(current_xml);
        free(previous_xml);
        return;
    }
    if (nl_journal_update_state(
            rollback_tx_id,
            NL_JOURNAL_HW_MARKED_COMMITTED) != NL_OK ||
        nl_journal_set_resulting_commit(
            rollback_tx_id, rollback_tx_id) != NL_OK ||
        nl_journal_update_state(
            rollback_tx_id, NL_JOURNAL_COMMITTED) != NL_OK) {
        (void)journal_finalize_failure(rollback_tx_id, true);
        c->state = NL_TIMED_OUT;
        (void)nl_confirmed_save(c);
        NL_LOG_CRIT(
            "commit confirmed tx=0x%lx timeout rollback journal finalization failed",
            c->tx_id);
        free(current_xml);
        free(previous_xml);
        return;
    }
    persist_commit_comment(rollback_tx_id, "commit confirmed timeout rollback");
    configd_runtime_notify_reload();
    configd_l2_refresh_cache();
    c->state = NL_TIMED_OUT;
    (void)nl_confirmed_save(c);
    NL_LOG_WARN("commit confirmed tx=0x%lx timed out; rolled back to 0x%lx as tx=0x%lx",
                c->tx_id, c->previous_commit_id, rollback_tx_id);
    free(current_xml);
    free(previous_xml);
}

static void configd_check_confirmed_timeout(void) {
    nl_commit_confirmed c;
    char path[512];
    struct stat st;

    if (nl_confirmed_load(&c) != NL_OK) {
        nl_journal_file_path(path, sizeof(path), "confirmed.json");
        errno = 0;
        if (lstat(path, &st) == 0 || errno != ENOENT) {
            g_ctx.hw_out_of_sync = true;
            NL_LOG_CRIT(
                "commit-confirmed scheduling record is unreadable "
                "or invalid");
        }
        return;
    }
    if (!configd_confirmed_timeout_due(&c))
        return;
    configd_apply_confirmed_timeout(&c);
}

static bool parse_rollback_generation(const nl_msg_hdr *msg, int *generation) {
    char buf[32];
    char *end = NULL;
    long value;

    if (!generation)
        return false;
    *generation = 0;
    if (!msg || msg->payload_len == 0)
        return true;
    if (msg->payload_len >= sizeof(buf))
        return false;
    memcpy(buf, msg->payload, msg->payload_len);
    buf[msg->payload_len] = '\0';
    value = strtol(buf, &end, 10);
    while (end && (*end == ' ' || *end == '\t' ||
                   *end == '\r' || *end == '\n'))
        end++;
    if (!end || *end != '\0' || value < 0 || value > NL_CONFIG_MAX_ROLLBACK)
        return false;
    *generation = (int)value;
    return true;
}

static const char *uid_name(uid_t uid, char *buf, size_t size) {
    struct passwd *pw = getpwuid(uid);

    if (pw && pw->pw_name)
        return pw->pw_name;
    if (buf && size > 0)
        snprintf(buf, size, "%u", (unsigned int)uid);
    return buf ? buf : "unknown";
}

static void format_local_time(time_t when, char *buf, size_t size) {
    struct tm tmv;

    if (!buf || size == 0)
        return;
    if (localtime_r(&when, &tmv) == NULL) {
        snprintf(buf, size, "unknown time");
        return;
    }
    if (strftime(buf, size, "%Y-%m-%d %H:%M:%S %Z", &tmv) == 0)
        snprintf(buf, size, "unknown time");
}

static bool journal_has_participant(const nl_commit_journal *journal,
                                    const char *participant) {
    return journal && participant && participant[0] &&
           strstr(journal->plan, participant) != NULL;
}

static bool journal_candidate_snapshot_valid(
    const nl_commit_journal *journal) {
    char path[512];
    char digest[65];
    char *xml;
    bool valid;

    if (!journal || !journal->candidate_hash[0])
        return false;
    if (!candidate_snapshot_path_buf(
            path, sizeof(path), journal->tx_id))
        return false;
    xml = read_text_file(path);
    if (!xml)
        return false;
    valid = candidate_sha256(xml, digest) &&
            strcmp(digest, journal->candidate_hash) == 0;
    free(xml);
    return valid;
}

typedef enum {
    RECOVERY_REVERSE_EXACT = 0,
    RECOVERY_REVERSE_PRE_STATE_MISSING,
    RECOVERY_REVERSE_FAILED,
} recovery_reverse_result;

static bool l3_rollback_pre_state_missing(
    int rpc_result, int daemon_ec, const char *response) {
    return rpc_result >= 0 && daemon_ec == NL_ERR_INVALID_VALUE &&
           response &&
           strstr(response,
                  "<l3-persistent-rollback status=\"invalid\"") &&
           strstr(response,
                  "no persistent owner rollback available");
}

static recovery_reverse_result recovery_reverse_candidate(
    u64 tx_id, bool has_l3, bool has_l2) {
    char l3_response[32768] = {0};
    char l2_response[4096] = {0};
    int l3_ec = 0;
    s32 l2_ec = 0;
    int rpc_result;
    const char *status;

    if (has_l3) {
        rpc_result = configd_l3_rollback(
            tx_id, l3_response, sizeof(l3_response), &l3_ec);
        if (configd_l3_rollback_verified(
                tx_id, rpc_result, l3_ec, l3_response)) {
            if (journal_record_step(
                    tx_id, true, "rpd-l3",
                    "persistent-owner-rollback", "ok") != NL_OK)
                return RECOVERY_REVERSE_FAILED;
        } else if (l3_rollback_pre_state_missing(
                       rpc_result, l3_ec, l3_response)) {
            if (journal_record_step(
                    tx_id, true, "rpd-l3",
                    "persistent-owner-rollback", "pre-state-missing")
                != NL_OK)
                return RECOVERY_REVERSE_FAILED;
            return RECOVERY_REVERSE_PRE_STATE_MISSING;
        } else {
            status = rpc_result < 0 ? "unknown" : "failed";
            (void)journal_record_step(
                tx_id, true, "rpd-l3",
                "persistent-owner-rollback", status);
            return RECOVERY_REVERSE_FAILED;
        }
    }

    if (has_l2) {
        rpc_result = configd_switchd_rollback_l2_plan(
            tx_id, l2_response, sizeof(l2_response), &l2_ec);
        if (configd_switchd_l2_rollback_verified(
                tx_id, rpc_result, l2_ec, l2_response)) {
            if (journal_record_step(
                    tx_id, true, "switchd-l2",
                    "l2-plan-rollback", "ok") != NL_OK)
                return RECOVERY_REVERSE_FAILED;
        } else if (rpc_result >= 0 &&
                   l2_ec == NL_ERR_PRE_STATE_MISSING) {
            if (journal_record_step(
                    tx_id, true, "switchd-l2",
                    "l2-plan-rollback", "pre-state-missing") != NL_OK)
                return RECOVERY_REVERSE_FAILED;
            return RECOVERY_REVERSE_PRE_STATE_MISSING;
        } else {
            status = rpc_result < 0 ? "unknown" : "failed";
            (void)journal_record_step(
                tx_id, true, "switchd-l2",
                "l2-plan-rollback", status);
            return RECOVERY_REVERSE_FAILED;
        }
    }
    return RECOVERY_REVERSE_EXACT;
}

static nl_error_code reconcile_candidate_snapshot_to_active(
    const nl_commit_journal *journal,
    char *detail, size_t detail_size) {
    nl_yang_session *source;
    struct lyd_node *tree;
    char path[512];
    char *xml;
    config_xml_result parse_result;
    nl_error_code result;

    if (!journal)
        return NL_ERR_INVALID_VALUE;
    if (!candidate_snapshot_path_buf(
            path, sizeof(path), journal->tx_id))
        return NL_ERR_PRE_STATE_MISSING;
    xml = read_text_file(path);
    if (!xml)
        return NL_ERR_PRE_STATE_MISSING;
    source = nl_yang_session_create(CONFIGD_YANG_DIR);
    if (!source) {
        free(xml);
        return (nl_error_code)NL_ERR;
    }
    parse_result = parse_config_xml_data(source, xml, &tree);
    free(xml);
    if (parse_result == CONFIG_XML_INVALID) {
        nl_yang_session_destroy(source);
        return NL_ERR_JOURNAL_CORRUPT;
    }
    nl_yang_data_set(source, tree);
    result = replay_configuration_to_hardware(
        source, false, journal->tx_id, true, detail, detail_size);
    nl_yang_session_destroy(source);
    return result;
}

/*
 * Resolve transaction ownership before active replay.  A speculative
 * transaction (ID newer than tx_counter) must prove reverse L3->L2 rollback.
 * A transaction selected by tx_counter is already committed; method 20 may be
 * retried to release a retained L2 snapshot, or active replay will recreate
 * and verify the durable state if switchd lost volatile tracker state.
 */
static nl_error_code prepare_unresolved_for_active_replay(
    char *detail, size_t detail_size) {
    nl_commit_journal *journals;
    int count = 0;
    nl_status scan_status;

    if (g_ctx.active_authority_uncertain) {
        if (detail && detail_size > 0)
            snprintf(
                detail, detail_size,
                "error: active commit-point durability is unresolved; restart recovery must re-read tx_counter");
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    journals = calloc(CONFIGD_JOURNAL_SCAN_MAX, sizeof(*journals));
    if (!journals)
        return (nl_error_code)NL_ERR;
    scan_status = nl_journal_scan_unresolved(
        journals, &count, CONFIGD_JOURNAL_SCAN_MAX);
    if (scan_status != NL_OK) {
        free(journals);
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "error: unresolved journal scan is incomplete");
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    for (int i = 0; i < count; i++) {
        nl_commit_journal *journal = &journals[i];
        bool has_l2 = journal_has_participant(journal, "switchd-l2");
        bool has_l3 = journal_has_participant(journal, "rpd-l3");

        if (journal->state != NL_JOURNAL_HW_OUT_OF_SYNC) {
            if (detail && detail_size > 0)
                snprintf(
                    detail, detail_size,
                    "error: unresolved transaction 0x%lx has non-recoverable state %d",
                    journal->tx_id, (int)journal->state);
            free(journals);
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
        }
        if (!journal_candidate_snapshot_valid(journal)) {
            if (detail && detail_size > 0)
                snprintf(
                    detail, detail_size,
                    "error: unresolved transaction 0x%lx immutable candidate snapshot is missing or corrupt",
                    journal->tx_id);
            free(journals);
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
        }

        if (journal->tx_id > g_ctx.active_commit_id) {
            recovery_reverse_result reverse =
                recovery_reverse_candidate(
                    journal->tx_id, has_l3, has_l2);
            nl_journal_state terminal_state =
                NL_JOURNAL_FAILED_ROLLED_BACK;

            if (reverse == RECOVERY_REVERSE_PRE_STATE_MISSING) {
                nl_error_code reconcile =
                    reconcile_candidate_snapshot_to_active(
                        journal, detail, detail_size);

                if (reconcile != NL_ERR_OK) {
                    free(journals);
                    return NL_ERR_HW_STATE_OUT_OF_SYNC;
                }
                if (journal_record_step(
                        journal->tx_id, false, "configd",
                        "candidate-to-active-reconcile", "ok") != NL_OK) {
                    free(journals);
                    return NL_ERR_HW_STATE_OUT_OF_SYNC;
                }
                terminal_state = NL_JOURNAL_RECONCILED_TO_ACTIVE;
            } else if (reverse != RECOVERY_REVERSE_EXACT) {
                if (detail && detail_size > 0)
                    snprintf(
                        detail, detail_size,
                        "error: speculative transaction 0x%lx could not prove exact L3-to-L2 rollback",
                        journal->tx_id);
                free(journals);
                return NL_ERR_HW_STATE_OUT_OF_SYNC;
            }
            if (discard_staged_active_snapshot(
                    journal->tx_id,
                    g_ctx.active_commit_id) != 0) {
                if (detail && detail_size > 0)
                    snprintf(
                        detail, detail_size,
                        "error: speculative transaction 0x%lx was "
                        "reversed but its uncommitted active snapshot "
                        "could not be durably discarded",
                        journal->tx_id);
                free(journals);
                return NL_ERR_HW_STATE_OUT_OF_SYNC;
            }
            if (nl_journal_update_state(
                    journal->tx_id, terminal_state) != NL_OK) {
                free(journals);
                return NL_ERR_HW_STATE_OUT_OF_SYNC;
            }
            NL_LOG_NOTICE(
                "recovery resolved speculative tx=0x%lx active=0x%lx mode=%s",
                journal->tx_id, g_ctx.active_commit_id,
                terminal_state == NL_JOURNAL_FAILED_ROLLED_BACK ?
                "exact-rollback" : "reconciled-to-active");
            continue;
        }

        if (journal->tx_id < g_ctx.active_commit_id) {
            if (detail && detail_size > 0)
                snprintf(
                    detail, detail_size,
                    "error: unresolved transaction 0x%lx predates active authority 0x%lx; automatic replay cannot prove candidate-only cleanup",
                    journal->tx_id, g_ctx.active_commit_id);
            free(journals);
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
        }

        if (has_l2) {
            char response[4096] = {0};
            s32 error_code = 0;
            int response_len = configd_switchd_mark_success(
                journal->tx_id, response, sizeof(response), &error_code);

            if (response_len < 0 ||
                (error_code != 0 &&
                 error_code != NL_ERR_HW_STATE_OUT_OF_SYNC)) {
                if (detail && detail_size > 0)
                    snprintf(
                        detail, detail_size,
                        "error: committed transaction 0x%lx L2 finalization failed rn=%d ec=%d",
                        journal->tx_id, response_len, error_code);
                free(journals);
                return NL_ERR_HW_STATE_OUT_OF_SYNC;
            }
            if (error_code == 0)
                NL_LOG_NOTICE(
                    "recovery finalized retained durable L2 tx=0x%lx",
                    journal->tx_id);
            else
                NL_LOG_INFO(
                    "recovery durable L2 tx=0x%lx has no finalizable tracker; active replay will verify it",
                    journal->tx_id);
        }
    }
    free(journals);
    return NL_ERR_OK;
}

static int finalize_replayed_active_journals(int *committed_out) {
    nl_commit_journal *journals;
    int count = 0;
    int committed = 0;

    if (committed_out)
        *committed_out = 0;
    journals = calloc(CONFIGD_JOURNAL_SCAN_MAX, sizeof(*journals));
    if (!journals)
        return -1;
    if (nl_journal_scan_unresolved(
            journals, &count, CONFIGD_JOURNAL_SCAN_MAX) != NL_OK) {
        free(journals);
        return -1;
    }
    for (int i = 0; i < count; i++) {
        if (journals[i].state != NL_JOURNAL_HW_OUT_OF_SYNC ||
            journals[i].tx_id != g_ctx.active_commit_id) {
            free(journals);
            return -1;
        }
        if (nl_journal_set_resulting_commit(
                journals[i].tx_id, g_ctx.active_commit_id) != NL_OK ||
            nl_journal_update_state(
                journals[i].tx_id, NL_JOURNAL_COMMITTED) != NL_OK) {
            free(journals);
            return -1;
        }
        committed++;
    }
    free(journals);
    if (committed_out)
        *committed_out = committed;
    return 0;
}

static nl_error_code replay_configuration_to_hardware(
    nl_yang_session *source, bool full_replay, u64 tx_id,
    bool require_pfe, char *detail, size_t detail_size) {
    char pfe_detail[1024] = {0};
    char *plan_buf = configd_l2_plan_workspace();
    char *l3_plan_buf = configd_l3_plan_workspace();
    char plan_err[512] = {0};
    char l3_plan_err[512] = {0};
    char sw_resp[4096] = {0};
    char l3_resp[32768] = {0};
    char l3_verify[32768] = {0};
    int plan_len = 0;
    int l3_plan_len = 0;
    bool has_l2 = false;
    bool has_l3 = false;
    s32 sw_ec = 0;
    int l3_ec = 0;
    int sw_rn;
    int l3_rn;

    if (!source || !g_ctx.active || !plan_buf || !l3_plan_buf ||
        tx_id == 0) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size, "active configuration is not loaded");
        return NL_ERR_INVALID_VALUE;
    }

    if (!configd_public_capabilities_validate(
            source, detail, detail_size)) {
        if (source == g_ctx.active &&
            configd_public_capabilities_cleanup_required(
                source, NULL, 0)) {
            g_ctx.public_capability_cleanup_required = true;
            NL_LOG_WARN(
                "active replay deferred until closed public capability intent is removed");
        } else {
            g_ctx.hw_out_of_sync = true;
        }
        return NL_ERR_INVALID_VALUE;
    }

    if (!configd_switchd_pfe_up(pfe_detail, sizeof(pfe_detail))) {
        if (require_pfe) {
            if (detail && detail_size > 0)
                (void)compose_bounded_error_text(
                    detail, detail_size,
                    "error: active replay rejected: forwarding plane is "
                    "unavailable\nreason: ",
                    pfe_detail[0] ? pfe_detail : "PFE is not UP", "", "");
            return NL_ERR_PFE_DOWN;
        }
        NL_LOG_WARN("active replay skipped: %s",
                    pfe_detail[0] ? pfe_detail : "PFE is not UP");
        if (detail && detail_size > 0)
            snprintf(detail, detail_size, "active replay skipped: PFE is not UP");
        return NL_ERR_OK;
    }

    if (configd_l2_build_plan(source, g_ctx.active, full_replay,
                              plan_buf, NL_L2_PLAN_MAX_BYTES,
                              &plan_len, &has_l2,
                              plan_err, sizeof(plan_err)) != 0) {
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size, "error: ",
                plan_err[0] ? plan_err :
                "failed to build active replay plan", "", "");
        return NL_ERR_INVALID_VALUE;
    }

    if (configd_l3_build_plan(source, g_ctx.active,
                              l3_plan_buf, NL_L3_PLAN_MAX_BYTES,
                              &l3_plan_len, &has_l3,
                              l3_plan_err, sizeof(l3_plan_err)) != 0) {
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size, "error: ",
                l3_plan_err[0] ? l3_plan_err :
                "failed to build active L3 replay plan", "", "");
        return NL_ERR_INVALID_VALUE;
    }

    /*
     * The rpd plan replaces a complete owner image, including an empty one
     * on routed platforms. FM10840's fixed L2-only release must be able to
     * replay its L2 configuration without starting a nonexistent L3 owner.
     */
    if (full_replay)
        has_l3 = configd_l3_full_replay_required(has_l3);

    if (!has_l2 && !has_l3) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size, "active replay noop");
        NL_LOG_INFO("active replay noop");
        return NL_ERR_OK;
    }

    if (has_l3 && !configd_l3_public_apply_enabled()) {
        g_ctx.hw_out_of_sync = true;
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size,
                "error: active replay rejected: ",
                configd_l3_public_apply_gate_reason(), "", "");
        return NL_ERR_INVALID_VALUE;
    }

    if (configd_l3_validate_plan(l3_plan_buf, l3_plan_len, has_l3,
                                 l3_plan_err, sizeof(l3_plan_err)) != 0) {
        g_ctx.hw_out_of_sync = true;
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size,
                "error: active replay L3 validation failed: ",
                l3_plan_err[0] ? l3_plan_err :
                "rpd resource validation failed", "", "");
        return NL_ERR_INVALID_VALUE;
    }

    sw_rn = 0;
    if (has_l2 && plan_len > 0)
        sw_rn = configd_switchd_apply_l2_plan(tx_id, plan_buf, plan_len,
                                              sw_resp, sizeof(sw_resp),
                                              &sw_ec);
    if (has_l2 && (sw_rn < 0 || sw_ec != 0)) {
        g_ctx.hw_out_of_sync = true;
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size,
                "error: active replay hardware apply failed: ",
                sw_resp[0] ? sw_resp :
                nl_error_msg(NL_ERR_SDK_CALL_FAILED), "", "");
        return sw_ec ? (nl_error_code)sw_ec : NL_ERR_SDK_CALL_FAILED;
    }

    l3_rn = configd_l3_apply_plan(l3_plan_buf, l3_plan_len, has_l3,
                                  tx_id, l3_resp, sizeof(l3_resp),
                                  &l3_ec);
    if (has_l3 && (l3_rn < 0 || l3_ec != 0)) {
        bool l2_finalized;

        /*
         * Replay repairs the already-durable active configuration.  Once L2
         * matches that authority, never restore the pre-replay drift merely
         * because a later participant failed.
         */
        l2_finalized = finalize_active_replay_l2(
            tx_id, has_l2 && plan_len > 0, sw_resp, sizeof(sw_resp));
        g_ctx.hw_out_of_sync = true;
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size,
                "error: active replay L3 apply failed: ",
                l3_resp[0] ? l3_resp :
                "rpd persistent owner apply failed",
                l2_finalized ? "" :
                "\nreason: repaired L2 state could not be finalized", "");
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    l3_rn = configd_l3_verify_readback(l3_plan_buf, l3_plan_len, has_l3,
                                       l3_verify, sizeof(l3_verify),
                                       &l3_ec);
    if (has_l3 && (l3_rn < 0 || l3_ec != 0)) {
        bool l2_finalized;

        /*
         * This is repair, not a candidate transaction.  Rolling either owner
         * back would reinstate drift instead of the durable active state.
         */
        l2_finalized = finalize_active_replay_l2(
            tx_id, has_l2 && plan_len > 0, sw_resp, sizeof(sw_resp));
        g_ctx.hw_out_of_sync = true;
        if (detail && detail_size > 0)
            (void)compose_bounded_error_text(
                detail, detail_size,
                "error: active replay L3 read-back failed: ",
                l3_verify[0] ? l3_verify :
                "rpd persistent owner read-back failed",
                l2_finalized ? "" :
                "\nreason: repaired L2 state could not be finalized", "");
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    if (!finalize_active_replay_l2(
            tx_id, has_l2 && plan_len > 0, sw_resp, sizeof(sw_resp))) {
        g_ctx.hw_out_of_sync = true;
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "error: active replay mark_success failed");
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }

    configd_l2_refresh_cache();
    if (detail && detail_size > 0)
        snprintf(detail, detail_size,
                 "active replay applied l2=%d bytes l3=%d bytes",
                 has_l2 ? plan_len : 0, has_l3 ? l3_plan_len : 0);
    NL_LOG_NOTICE("active replay applied l2_plan_len=%d l3_plan_len=%d tx=0x%lx",
                  has_l2 ? plan_len : 0, has_l3 ? l3_plan_len : 0, tx_id);
    return NL_ERR_OK;
}

static nl_error_code replay_active_to_hardware(bool require_pfe,
                                               char *detail,
                                               size_t detail_size) {
    u64 tx_id = g_ctx.active_commit_id ? g_ctx.active_commit_id : 1;

    nl_commit_journal journal;
    if (g_ctx.active_commit_id && nl_journal_get(tx_id, &journal) == NL_OK &&
        journal.state == NL_JOURNAL_HW_OUT_OF_SYNC && journal.base_commit_id < tx_id) {
        char *source = read_commit_snapshot_xml(journal.base_commit_id);
        if (!source) return NL_ERR_PRE_STATE_MISSING;
        nl_error_code rc = replay_snapshot_to_active(source, tx_id, detail, detail_size);
        free(source); return rc;
    }

    return replay_configuration_to_hardware(
        g_ctx.active, true, tx_id, require_pfe, detail, detail_size);
}

static nl_error_code replay_snapshot_to_active(const char *xml, u64 tx_id,
                                               char *detail, size_t detail_size) {
    /* Keep the old owner image until the new authority has removed its
     * VLAN/MAC/LAG/policy objects, including recovery after publication. */
    nl_yang_session *source = replay_source_session(xml);
    if (!source) return NL_ERR_JOURNAL_CORRUPT;
    nl_error_code rc = replay_configuration_to_hardware(source, true, tx_id, true, detail, detail_size);
    nl_yang_session_destroy(source);
    return rc;
}

// ===== Init / Shutdown =====
static int configd_on_init(void *ctx) {
    (void)ctx;
    memset(&g_ctx, 0, sizeof(g_ctx));
    const char *observe = getenv("NETLAB_FM10K_OBSERVE_ONLY");
    /* The installation snapshot is intent only until a real replay is proven. */
    if ((observe && !strcmp(observe, "1")) || configd_native_control_mode()) g_ctx.hw_out_of_sync = true;
    mkdir(nl_config_dir(), 0700);
    mkdir(nl_journal_dir(), 0700);
    g_ctx.candidate = nl_yang_session_create(CONFIGD_YANG_DIR);
    g_ctx.active = nl_yang_session_create(CONFIGD_YANG_DIR);
    if (!g_ctx.candidate || !g_ctx.active ||
        !configd_l2_plan_workspace() || !configd_l3_plan_workspace()) {
        NL_LOG_CRIT("failed to create config sessions");
        return -1;
    }
    nl_ifid_resolver_init("default");
    if (!load_active_authority())
        return -1;

    int journal_scan_max = CONFIGD_JOURNAL_SCAN_MAX;
    nl_journal_migration_stats migration = {0};
    bool confirmed_legacy_migrated = false;
    nl_status confirmed_migration_st =
        nl_confirmed_migrate_legacy_terminal_sentinel(
            &confirmed_legacy_migrated);
    nl_status init_st = nl_journal_initialize_v2(0, &migration);
    nl_commit_journal *journals = calloc((size_t)journal_scan_max,
                                         sizeof(*journals));
    int jcount = 0;
    int committed = 0, stale = 0, oos = 0;
    if (confirmed_migration_st != NL_OK) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT(
            "legacy commit-confirmed terminal sentinel migration failed");
    } else if (confirmed_legacy_migrated) {
        NL_LOG_NOTICE(
            "removed legacy zero-valued TIMED_OUT scheduling sentinel");
    }
    nl_status scan_st = journals && init_st == NL_OK ?
        nl_journal_scan_unresolved(journals, &jcount, journal_scan_max) :
        NL_ERR_HW_OUT_OF_SYNC;
    if (scan_st == NL_OK || jcount > 0) {
        for (int i = 0; i < jcount; i++) {
            if (nl_journal_recover(&journals[i]) != NL_OK)
                NL_LOG_ERR("recovery failed for tx=0x%lx", journals[i].tx_id);
            if (journals[i].state == NL_JOURNAL_HW_OUT_OF_SYNC)
                g_ctx.hw_out_of_sync = true;
            if (journals[i].state == NL_JOURNAL_COMMITTED) committed++;
            if (journals[i].state == NL_JOURNAL_HW_OUT_OF_SYNC) oos++;
            if (journals[i].state == NL_JOURNAL_PREPARED) stale++;
        }
    }
    if (scan_st != NL_OK) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT("journal recovery incomplete; blocking commit");
    }
    free(journals);
    if (migration.migrated) {
        NL_LOG_NOTICE("journal v2 migration: scanned=%lu unresolved=%lu "
                      "retained-terminal=%lu removed-terminal=%lu",
                      migration.scanned, migration.unresolved,
                      migration.retained_terminal,
                      migration.removed_terminal);
    }
    if (jcount > 0)
        NL_LOG_INFO("recovery: scanned %d journals, committed=%d, stale_prepared=%d, hw_out_of_sync=%d",
                    jcount, committed, stale, oos);
    if (!configd_recover_active_confirmed_intent()) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT(
            "active commit-confirmed intent could not be reconstructed");
    }
    configd_check_confirmed_timeout_if_unblocked();
    if (!g_ctx.hw_out_of_sync)
        NL_LOG_INFO("active replay pending dependency-ready trigger "
                    "commit-id=%lu", g_ctx.active_commit_id);
    return 0;
}

static void configd_on_idle(void *ctx, s64 elapsed_ms) {
    (void)ctx;
    (void)elapsed_ms;
    configd_check_confirmed_timeout_if_unblocked();
    configd_native_replay_tick();
}

static void configd_on_shutdown(void *ctx) {
    (void)ctx;
    if (g_ctx.candidate) { nl_yang_session_destroy(g_ctx.candidate); g_ctx.candidate = NULL; }
    if (g_ctx.active) { nl_yang_session_destroy(g_ctx.active); g_ctx.active = NULL; }
    free(g_ctx.l2_plan_workspace);
    g_ctx.l2_plan_workspace = NULL;
    free(g_ctx.l3_plan_workspace);
    g_ctx.l3_plan_workspace = NULL;
    nl_ifid_resolver_destroy();
}

// ===== Handle: set =====
// Payload format: "path\0value"  or  "path" (container with no value)
static int handle_set(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.candidate) { nl_send_response(conn, msg->request_id, -1); return 0; }

    if (msg->payload_len == 0) {
        nl_send_response(conn, msg->request_id, NL_ERR_INVALID_PATH);
        return 0;
    }

    char *payload = malloc(msg->payload_len + 1);
    if (!payload) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
    memcpy(payload, msg->payload, msg->payload_len);
    payload[msg->payload_len] = '\0';

    // Split into path and value by null byte
    char *val = NULL;
    for (u32 i = 0; i < msg->payload_len; i++) {
        if (payload[i] == '\0') {
            payload[i] = '\0';  // terminate path
            if (i + 1 < msg->payload_len)
                val = payload + i + 1;
            break;
        }
    }
    // If no null byte, entire payload is path and value is empty (delete leaf)
    const char *path = payload;
    const char *value = val ? val : "";

    // Resolve short CLI paths to full XPath
    char xpath[512];
    xpath[0] = '\0';
    // If path starts with "/", it's already a full XPath, otherwise it's CLI-style
    // For CLI-style: "vlans vlan V100 vlan-id" -> "/netlab:vlans/vlan[name='V100']/vlan-id"
    // For now, accept both forms
    snprintf(xpath, sizeof(xpath), "%s", path);

    char capability_detail[512] = {0};
    if (!configd_public_capability_path_allowed(
            xpath, capability_detail, sizeof(capability_detail))) {
        char response[640];
        snprintf(response, sizeof(response), "error: set rejected: %s",
                 capability_detail[0] ? capability_detail :
                 "public capability authority rejected path");
        send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE, response);
        free(payload);
        return 0;
    }

    nl_error_code rc = nl_yang_set(g_ctx.candidate, xpath, value);
    if (rc != (nl_error_code)NL_OK) {
        const char *err_msg = nl_error_msg(rc);
        size_t elen = err_msg ? strlen(err_msg) : 0;
        nl_msg_hdr *resp = nl_msg_alloc((u32)elen + 16);
        if (resp) {
            resp->type = NL_MSG_ERROR;
            resp->request_id = msg->request_id;
            resp->error_code = (s32)rc;
            resp->payload_len = (u32)(elen + 1);
            if (err_msg) memcpy(resp->payload, err_msg, elen + 1);
            nl_send(conn, resp);
            nl_msg_free(resp);
        }
    } else {
        nl_send_response(conn, msg->request_id, NL_OK);
    }

    free(payload);
    return 0;
}

// ===== Handle: delete =====
static int handle_delete(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.candidate) { nl_send_response(conn, msg->request_id, -1); return 0; }

    if (msg->payload_len == 0) {
        nl_send_response(conn, msg->request_id, NL_ERR_INVALID_PATH);
        return 0;
    }

    char *path = malloc(msg->payload_len + 1);
    if (!path) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
    memcpy(path, msg->payload, msg->payload_len);
    path[msg->payload_len] = '\0';

    nl_error_code rc = nl_yang_delete(g_ctx.candidate, path);
    if (rc != (nl_error_code)NL_OK) {
        const char *err_msg = nl_error_msg(rc);
        size_t elen = err_msg ? strlen(err_msg) : 0;
        nl_msg_hdr *resp = nl_msg_alloc((u32)elen + 16);
        if (resp) {
            resp->type = NL_MSG_ERROR;
            resp->request_id = msg->request_id;
            resp->error_code = (s32)rc;
            resp->payload_len = (u32)(elen + 1);
            if (err_msg) memcpy(resp->payload, err_msg, elen + 1);
            nl_send(conn, resp);
            nl_msg_free(resp);
        }
    } else {
        nl_send_response(conn, msg->request_id, NL_OK);
    }
    free(path);
    return 0;
}

// ===== Handle: commit =====
static int handle_commit(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.candidate) { nl_send_response(conn, msg->request_id, -1); return 0; }
    configd_commit_options opts;
    char commit_option_err[160];
    u64 previous_commit_id = g_ctx.active_commit_id;
    s64 confirmed_deadline = 0;

    if (reject_candidate_public_capabilities(conn, msg))
        return 0;
    if (reject_noncleanup_candidate_when_required(conn, msg))
        return 0;

    if (!parse_commit_options(msg, &opts, commit_option_err,
                              sizeof(commit_option_err))) {
        char err[256];
        snprintf(err, sizeof(err), "error: invalid commit option\nreason: %s",
                 commit_option_err[0] ? commit_option_err : "unknown");
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE, err);
    }
    if (g_ctx.public_capability_cleanup_required && opts.confirmed) {
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            "error: commit confirmed is forbidden for a cleanup-only commit\n"
            "reason: its timeout would restore closed capability intent "
            "that current replay authority rejects\n"
            "hint: commit the exact cleanup without the confirmed option");
    }
    if (g_ctx.production_guard_authorized && opts.confirmed) {
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            "error: commit confirmed is forbidden while a production guard is armed");
    }

    // Check HW_OUT_OF_SYNC
    if (g_ctx.hw_out_of_sync) {
        nl_msg_hdr *resp = nl_msg_alloc(256);
        if (resp) {
            resp->type = NL_MSG_ERROR;
            resp->request_id = msg->request_id;
            resp->error_code = (s32)NL_ERR_HW_STATE_OUT_OF_SYNC;
            const char *err = nl_error_msg(NL_ERR_HW_STATE_OUT_OF_SYNC);
            const char *hint = nl_error_hint(NL_ERR_HW_STATE_OUT_OF_SYNC);
            int plen = snprintf((char *)resp->payload, 256, "%s\nhint: %s",
                               err ? err : "", hint ? hint : "");
            resp->payload_len = (u32)plen;
            nl_send(conn, resp);
            nl_msg_free(resp);
        }
        return 0;
    }

    // Check PFE capability before any candidate can touch hardware state.
    bool switchd_available = false;
    (void)switchd_available;
    {
        char pfe_detail[1024] = {0};
        nl_error_code pfe_rc;

        pfe_rc = configd_switchd_commit_pfe_check(&switchd_available,
                                                  pfe_detail,
                                                  sizeof(pfe_detail));
        if (pfe_rc != NL_ERR_OK) {
            nl_msg_hdr *resp = nl_msg_alloc(512);
            if (resp) {
                resp->type = NL_MSG_ERROR;
                resp->request_id = msg->request_id;
                resp->error_code = (s32)pfe_rc;
                snprintf((char *)resp->payload, 512, "%s",
                         nl_error_msg(pfe_rc));
                resp->payload_len = (u32)strlen((char *)resp->payload);
                nl_send(conn, resp);
                nl_msg_free(resp);
            }
            return 0;
        }
    }

    // If switchd is unreachable, reject commits with hardware changes.
    char *plan_buf = configd_l2_plan_workspace();
    char *l3_plan_buf = configd_l3_plan_workspace();
    int plan_len = 0;
    bool has_l2 = false;
    char plan_err[512] = {0};
    int l3_plan_len = 0;
    bool has_l3 = false;
    char l3_plan_err[512] = {0};
    if (configd_l2_build_plan(g_ctx.active, g_ctx.candidate,
                              switchd_available,
                              plan_buf, NL_L2_PLAN_MAX_BYTES,
                              &plan_len, &has_l2,
                              plan_err, sizeof(plan_err)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            plan_err[0] ? plan_err : "invalid L2 configuration", "", "");
        return 0;
    }
    if (configd_l2_validate_plan(plan_buf, plan_len, has_l2,
                          plan_err, sizeof(plan_err)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            plan_err[0] ? plan_err : "L2 feature validation failed", "", "");
        return 0;
    }
    if (configd_l3_build_plan(g_ctx.active, g_ctx.candidate,
                              l3_plan_buf, NL_L3_PLAN_MAX_BYTES,
                              &l3_plan_len, &has_l3,
                              l3_plan_err, sizeof(l3_plan_err)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            l3_plan_err[0] ? l3_plan_err : "invalid L3 configuration", "", "");
        return 0;
    }
    if (configd_l3_validate_plan(l3_plan_buf, l3_plan_len, has_l3,
                                 l3_plan_err, sizeof(l3_plan_err)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            l3_plan_err[0] ? l3_plan_err : "L3 feature validation failed", "", "");
        return 0;
    }
    if (has_l3 && !configd_l3_public_apply_enabled()) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            configd_l3_public_apply_gate_reason(), "", "");
        return 0;
    }

    if (!switchd_available) {
        if (has_l2 || has_l3) {
            nl_msg_hdr *resp = nl_msg_alloc(512);
            if (resp) {
                const char *err_text = "error: commit rejected: forwarding plane is unavailable\n"
                                       "reason: switchd unreachable\n"
                                       "hint: start switchd or check \"show chassis forwarding\"";
                resp->type = NL_MSG_ERROR;
                resp->request_id = msg->request_id;
                resp->error_code = (s32)NL_ERR_PFE_DOWN;
                resp->payload_len = (u32)strlen(err_text);
                memcpy(resp->payload, err_text, strlen(err_text));
                nl_send(conn, resp);
                nl_msg_free(resp);
            }
            return 0;
        }
    }

    // Check commit lock
    if (g_ctx.commit_locked) {
        nl_send_response(conn, msg->request_id, NL_ERR_COMMIT_LOCKED);
        return 0;
    }

    g_ctx.commit_locked = true;

    // Reserve a never-reused transaction attempt ID.
    u64 tx_id = 0;
    if (nl_tx_sequence_next(g_ctx.active_commit_id, &tx_id) != NL_OK) {
        g_ctx.commit_locked = false;
        return send_text(
            conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
            "error: commit rejected: failed to reserve transaction id");
    }

    // Serialize candidate for journal
    char *candidate_xml = nl_yang_to_xml(g_ctx.candidate);
    char candidate_hash[65];
    char journal_plan[1024];
    if (!candidate_xml) {
        g_ctx.commit_locked = false;
        NL_LOG_ERR("commit tx=0x%lx failed: candidate serialization failed",
                   tx_id);
        return send_text(conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
                         "error: commit rejected: failed to serialize candidate configuration");
    }
    if (!candidate_sha256(candidate_xml, candidate_hash) ||
        build_journal_plan(journal_plan, sizeof(journal_plan),
                           has_l2, has_l3) != 0) {
        free(candidate_xml);
        g_ctx.commit_locked = false;
        return send_text(conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
                         "error: commit rejected: failed to build journal v2 metadata");
    }

    // Journal: PREPARED
    if (nl_journal_create(tx_id, g_ctx.active_commit_id,
                          candidate_hash) != NL_OK) {
        free(candidate_xml);
        g_ctx.commit_locked = false;
        NL_LOG_ERR("commit tx=0x%lx failed: cannot create journal", tx_id);
        return send_text(conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
                         "error: commit rejected: failed to create commit journal");
    }
    if (nl_journal_set_plan(tx_id, journal_plan) != NL_OK) {
        (void)journal_finalize_failure(tx_id, false);
        free(candidate_xml);
        g_ctx.commit_locked = false;
        return send_text(conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
                         "error: commit rejected: failed to persist journal apply plan");
    }

    /*
     * Persist the candidate payload before the first hardware mutation.  It
     * remains immutable whether this attempt commits or rolls back; tx_counter
     * alone decides whether the payload is active.
     */
    if (persist_candidate_snapshot(tx_id, candidate_xml) != 0) {
        (void)journal_finalize_failure(tx_id, false);
        free(candidate_xml);
        g_ctx.commit_locked = false;
        return send_text(
            conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
            "error: commit rejected: failed to persist immutable candidate snapshot");
    }

    // Journal: APPLYING
    if (nl_journal_update_state(tx_id, NL_JOURNAL_APPLYING) != NL_OK) {
        (void)journal_finalize_failure(tx_id, false);
        free(candidate_xml);
        g_ctx.commit_locked = false;
        NL_LOG_ERR("commit tx=0x%lx failed: cannot persist APPLYING journal state",
                   tx_id);
        return send_text(conn, msg, (s32)NL_ERR_JOURNAL_CORRUPT,
                         "error: commit rejected: failed to persist commit journal state");
    }

    // Send to switchd HAL via method 40 (apply_l2_plan).
    char sw_resp[4096];
    char l3_resp[32768];
    char l3_verify[32768];
    int sw_rn = 0;
    int l3_rn = 0;
    s32 sw_ec = 0;
    int l3_ec = 0;
    bool hardware_touched = (switchd_available && has_l2 && plan_len > 0) ||
                            has_l3;
    (void)switchd_available;
    sw_resp[0] = '\0';
    l3_resp[0] = '\0';
    l3_verify[0] = '\0';
    if (plan_len > 0 && has_l2 && switchd_available) {
        sw_rn = configd_switchd_apply_l2_plan(tx_id, plan_buf, plan_len,
                                              sw_resp, sizeof(sw_resp),
                                              &sw_ec);
    }

    if (has_l2 && switchd_available && (sw_rn < 0 || sw_ec != 0)) {
        bool rollback_failed = (sw_rn < 0 ||
                                sw_ec == NL_ERR_ROLLBACK_FAILED ||
                                sw_ec == NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED ||
                                sw_ec == NL_ERR_HW_STATE_OUT_OF_SYNC);
        char fail_resp[512] = {0};
        s32 fail_ec = 0;
        int fail_rn = 0;

        if (journal_record_step(
                tx_id, false, "switchd-l2", "apply_l2_plan",
                sw_rn < 0 ? "unknown" : "failed") != NL_OK)
            rollback_failed = true;
        if (!rollback_failed) {
            fail_rn = configd_switchd_mark_failed(
                tx_id, fail_resp, sizeof(fail_resp), &fail_ec);
            if (fail_rn < 0 || fail_ec != 0)
                rollback_failed = true;
        }
        if (journal_record_step(
                tx_id, true, "switchd-l2", "automatic-rollback",
                rollback_failed ?
                (sw_rn < 0 ? "unknown" : "failed") : "ok") != NL_OK)
            rollback_failed = true;

        rollback_failed = journal_finalize_failure(
            tx_id, rollback_failed);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_ERR("commit tx=0x%lx failed: switchd apply rn=%d ec=%d resp=%s",
                   tx_id, sw_rn, sw_ec, sw_resp);
        nl_msg_hdr *resp = nl_msg_alloc(512);
        if (resp) {
            resp->type = NL_MSG_ERROR;
            resp->request_id = msg->request_id;
            resp->error_code = rollback_failed ?
                               (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                               (s32)NL_ERR_SDK_CALL_FAILED;
            snprintf((char *)resp->payload, 512,
                     "error: hardware apply failed: %s%s",
                     sw_resp[0] ? sw_resp : nl_error_msg(NL_ERR_SDK_CALL_FAILED),
                     rollback_failed ? "\nreason: rollback failed or apply status is unknown" : "");
            resp->payload_len = (u32)strlen((char *)resp->payload);
            nl_send(conn, resp);
            nl_msg_free(resp);
        }
        return 0;
    }

    if (plan_len > 0 && has_l2 && switchd_available &&
        journal_record_step(tx_id, false, "switchd-l2",
                            "apply-and-verify", "ok") != NL_OK) {
        bool restored = rollback_verified_candidate(
            tx_id, false, true, l3_resp, sizeof(l3_resp),
            sw_resp, sizeof(sw_resp));
        bool blocked = journal_finalize_failure(tx_id, !restored);

        g_ctx.commit_locked = false;
        free(candidate_xml);
        return send_text(
            conn, msg,
            blocked ? (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                      (s32)NL_ERR_JOURNAL_CORRUPT,
            blocked ?
            "error: L2 journal evidence failed and exact rollback is incomplete" :
            "error: L2 journal evidence failed; candidate was rolled back");
    }

    if (has_l3) {
        l3_rn = configd_l3_apply_plan(l3_plan_buf, l3_plan_len, has_l3,
                                      tx_id, l3_resp, sizeof(l3_resp),
                                      &l3_ec);
        if (l3_rn < 0 || l3_ec != 0) {
            configd_l3_apply_failure_evidence evidence;
            bool l3_pre_state_proven;
            bool journal_failed = false;
            bool l2_rollback_ok = true;
            bool rollback_failed;
            const char *l3_undo;
            const char *l3_undo_status;
            const char *failure_reason;

            evidence = configd_l3_apply_failure_classify(
                tx_id, l3_rn, l3_ec, l3_resp);
            l3_pre_state_proven =
                evidence != CONFIGD_L3_APPLY_FAILURE_UNKNOWN;
            l3_undo =
                evidence == CONFIGD_L3_APPLY_FAILURE_RESTORED ?
                "automatic-rollback" :
                (evidence == CONFIGD_L3_APPLY_FAILURE_NO_MUTATION ?
                 "no-mutation-proven" : "rollback-unproven");
            l3_undo_status = l3_pre_state_proven ? "ok" :
                             (l3_rn < 0 ? "unknown" : "failed");
            if (journal_record_step(
                    tx_id, false, "rpd-l3", "persistent-owner-apply",
                    l3_rn < 0 ? "unknown" : "failed") != NL_OK)
                journal_failed = true;
            if (journal_record_step(
                    tx_id, true, "rpd-l3", l3_undo,
                    l3_undo_status) != NL_OK)
                journal_failed = true;
            if (l3_pre_state_proven)
                l2_rollback_ok = rollback_candidate_l2_plan(
                    tx_id, switchd_available && has_l2 && plan_len > 0,
                    sw_resp, sizeof(sw_resp));
            rollback_failed = journal_failed || !l3_pre_state_proven ||
                              !l2_rollback_ok;
            failure_reason = l3_rn < 0 ?
                "L3 apply transport outcome is unknown; L2 rollback was not attempted" :
                (!l3_pre_state_proven ?
                 "L3 response did not prove its exact pre-state; L2 rollback was not attempted" :
                 (rollback_failed ?
                  "L2 exact rollback failed or its evidence could not be journaled" :
                  ""));

            rollback_failed = journal_finalize_failure(
                tx_id, rollback_failed);
            g_ctx.commit_locked = false;
            free(candidate_xml);
            NL_LOG_ERR("commit tx=0x%lx failed: rpd apply rn=%d ec=%d resp=%s",
                       tx_id, l3_rn, l3_ec, l3_resp);
            (void)send_bounded_error_response(
                conn, msg,
                rollback_failed ? (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                                  (s32)NL_ERR_SDK_CALL_FAILED,
                CONFIGD_LONG_ERROR_RESPONSE_MAX_BYTES,
                "error: L3 hardware apply failed: ",
                l3_resp[0] ? l3_resp :
                "rpd persistent owner apply failed",
                rollback_failed ?
                (failure_reason[0] ?
                 "\nreason: transaction rollback is incomplete\n"
                 "detail: " :
                 "\nreason: transaction rollback is incomplete") : "",
                rollback_failed && failure_reason[0] ?
                failure_reason : "");
            return 0;
        }

        if (journal_record_step(tx_id, false, "rpd-l3",
                                "persistent-owner-apply", "ok") != NL_OK) {
            bool restored = rollback_verified_candidate(
                tx_id, true,
                switchd_available && has_l2 && plan_len > 0,
                l3_resp, sizeof(l3_resp),
                sw_resp, sizeof(sw_resp));
            bool blocked = journal_finalize_failure(tx_id, !restored);

            g_ctx.commit_locked = false;
            free(candidate_xml);
            return send_text(
                conn, msg,
                blocked ? (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                          (s32)NL_ERR_JOURNAL_CORRUPT,
                blocked ?
                "error: L3 journal evidence failed and exact rollback is incomplete" :
                "error: L3 journal evidence failed; candidate was rolled back");
        }

        l3_rn = configd_l3_verify_readback(l3_plan_buf, l3_plan_len,
                                           has_l3, l3_verify,
                                           sizeof(l3_verify), &l3_ec);
        if (l3_rn < 0 || l3_ec != 0) {
            char l3_rollback[16384] = {0};
            int rollback_ec = 0;
            int rollback_rn;
            bool l3_rollback_verified;
            bool journal_failed = false;
            bool l2_rollback_ok = true;
            bool rollback_failed;
            const char *failure_reason;

            rollback_rn = configd_l3_rollback(tx_id, l3_rollback,
                                              sizeof(l3_rollback),
                                              &rollback_ec);
            l3_rollback_verified = configd_l3_rollback_verified(
                tx_id, rollback_rn, rollback_ec, l3_rollback);
            if (journal_record_step(
                    tx_id, false, "rpd-l3", "sdk-readback",
                    l3_verify[0] ? "failed" : "unknown") != NL_OK)
                journal_failed = true;
            if (journal_record_step(
                    tx_id, true, "rpd-l3", "persistent-owner-rollback",
                    l3_rollback_verified ? "ok" :
                    (rollback_rn < 0 ? "unknown" : "failed")) != NL_OK)
                journal_failed = true;
            if (l3_rollback_verified)
                l2_rollback_ok = rollback_candidate_l2_plan(
                    tx_id, switchd_available && has_l2 && plan_len > 0,
                    sw_resp, sizeof(sw_resp));
            rollback_failed = journal_failed || !l3_rollback_verified ||
                              !l2_rollback_ok;
            failure_reason = !l3_rollback_verified ?
                "L3 exact rollback was not proven; L2 rollback was not attempted" :
                (rollback_failed ?
                 "L2 exact rollback failed or its evidence could not be journaled" :
                 "");
            rollback_failed = journal_finalize_failure(
                tx_id, rollback_failed);
            g_ctx.commit_locked = false;
            free(candidate_xml);
            NL_LOG_ERR("commit tx=0x%lx failed: rpd readback rn=%d ec=%d resp=%s rollback=%s",
                       tx_id, l3_rn, l3_ec, l3_verify, l3_rollback);
            (void)send_bounded_error_response(
                conn, msg,
                rollback_failed ? (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                                  (s32)NL_ERR_SDK_CALL_FAILED,
                CONFIGD_LONG_ERROR_RESPONSE_MAX_BYTES,
                "error: L3 read-back verification failed: ",
                l3_verify[0] ? l3_verify :
                "rpd persistent owner read-back failed",
                rollback_failed ?
                "\nreason: transaction rollback is incomplete: " : "",
                rollback_failed ?
                (failure_reason[0] ? failure_reason :
                 (l3_rollback[0] ? l3_rollback : "unknown")) : "");
            return 0;
        }
        if (journal_record_step(tx_id, false, "rpd-l3",
                                "sdk-readback", "ok") != NL_OK) {
            bool restored = rollback_verified_candidate(
                tx_id, true,
                switchd_available && has_l2 && plan_len > 0,
                l3_resp, sizeof(l3_resp),
                sw_resp, sizeof(sw_resp));
            bool blocked = journal_finalize_failure(tx_id, !restored);

            g_ctx.commit_locked = false;
            free(candidate_xml);
            return send_text(
                conn, msg,
                blocked ? (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                          (s32)NL_ERR_JOURNAL_CORRUPT,
                blocked ?
                "error: L3 verification evidence failed and exact rollback is incomplete" :
                "error: L3 verification evidence failed; candidate was rolled back");
        }
    }

    // Journal: VERIFYING → VERIFY_OK
    if (nl_journal_update_state(tx_id, NL_JOURNAL_VERIFYING) != NL_OK ||
        nl_journal_update_state(tx_id, NL_JOURNAL_VERIFY_OK) != NL_OK) {
        bool restored = !hardware_touched ||
            rollback_verified_candidate(
                tx_id, has_l3,
                switchd_available && has_l2 && plan_len > 0,
                l3_resp, sizeof(l3_resp),
                sw_resp, sizeof(sw_resp));
        bool blocked = journal_finalize_failure(tx_id, !restored);

        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT("commit tx=0x%lx failed: cannot persist verify journal state",
                    tx_id);
        return send_text(conn, msg,
                         blocked ?
                         (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                         (s32)NL_ERR_JOURNAL_CORRUPT,
                         blocked ?
                         "error: commit failed: journal persistence failed and exact rollback is incomplete" :
                         "error: commit rejected: journal persistence failed; candidate was rolled back");
    }

    if (opts.confirmed) {
        confirmed_deadline = (s64)time(NULL) + opts.confirm_seconds;
        if (confirmed_deadline <= 0 ||
            nl_journal_set_confirmed_intent_monotonic(
                tx_id, previous_commit_id,
                confirmed_deadline, opts.confirm_seconds) != NL_OK) {
            bool restored = !hardware_touched ||
                rollback_verified_candidate(
                    tx_id, has_l3,
                    switchd_available && has_l2 && plan_len > 0,
                    l3_resp, sizeof(l3_resp),
                    sw_resp, sizeof(sw_resp));
            bool blocked = journal_finalize_failure(tx_id, !restored);

            g_ctx.commit_locked = false;
            free(candidate_xml);
            return send_text(
                conn, msg,
                blocked ? (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                          (s32)NL_ERR_JOURNAL_CORRUPT,
                blocked ?
                "error: commit-confirmed intent persistence failed and exact rollback is incomplete" :
                "error: commit-confirmed intent persistence failed; candidate was rolled back");
        }
    }

    /*
     * Publish the candidate while switchd still retains the L2 before-image
     * for method 41.  The tx_counter rename is the commit point.  Method 20 is
     * irreversible and must never release that snapshot before the pointer is
     * durably observed.
     */
    active_authority_result authority =
        persist_active_authority(previous_commit_id, tx_id, candidate_xml);
    if (authority == ACTIVE_AUTHORITY_NOT_COMMITTED) {
        bool restored = !hardware_touched ||
            rollback_verified_candidate(
                tx_id, has_l3,
                switchd_available && has_l2 && plan_len > 0,
                l3_resp, sizeof(l3_resp),
                sw_resp, sizeof(sw_resp));
        char *active_xml =
            read_commit_snapshot_xml(previous_commit_id);
        bool mirror_restored = active_xml &&
                               materialize_active_mirror(active_xml);
        bool staged_discarded = discard_staged_active_snapshot(
                                    tx_id, previous_commit_id) == 0;
        bool blocked;

        free(active_xml);
        blocked = journal_finalize_failure(
            tx_id, !restored || !mirror_restored ||
                   !staged_discarded);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT(
            "commit tx=0x%lx active publication did not commit "
            "rollback=%s mirror=%s staged-discard=%s",
            tx_id, restored ? "verified" : "unverified",
            mirror_restored ? "restored" : "failed",
            staged_discarded ? "ok" : "failed");
        return send_text(conn, msg,
                         blocked ?
                         (s32)NL_ERR_HW_STATE_OUT_OF_SYNC :
                         (s32)NL_ERR_JOURNAL_CORRUPT,
                         blocked ?
                         "error: commit failed: active publication failed and exact pre-state restoration is incomplete" :
                         "error: commit rejected: failed to persist active configuration");
    }
    if (authority == ACTIVE_AUTHORITY_UNKNOWN) {
        /*
         * An unreadable or third-generation pointer is conflicting authority.
         * Neither rollback nor method 20 is authorized, and the in-memory
         * authority remains unchanged until restart can read the commit point.
         */
        g_ctx.active_authority_uncertain = true;
        (void)journal_finalize_failure(tx_id, true);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT(
            "commit tx=0x%lx active commit point durability is unknown; retained hardware pre-state",
            tx_id);
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: commit durability is unknown; transaction before-images remain retained");
    }
    if (authority == ACTIVE_AUTHORITY_OBSERVED_NEW_UNCERTAIN) {
        /*
         * The new pointer is visible after a failed directory fsync, but its
         * crash durability is not proven.  Reflect that observation in memory
         * without releasing participant before-images.
         */
        g_ctx.active_commit_id = tx_id;
        (void)load_xml_into_sessions(candidate_xml);
        g_ctx.active_authority_uncertain = true;
        (void)journal_finalize_failure(tx_id, true);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT(
            "commit tx=0x%lx observes the new active pointer but "
            "commit-point durability is unknown; retained hardware pre-state",
            tx_id);
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: new commit point is visible but durability is unknown; "
            "transaction before-images remain retained");
    }
    if (authority ==
        ACTIVE_AUTHORITY_COMMITTED_POSTPUBLISH_FAILED) {
        g_ctx.active_commit_id = tx_id;
        (void)load_xml_into_sessions(candidate_xml);
        (void)journal_finalize_failure(tx_id, true);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT(
            "commit tx=0x%lx authority committed but active mirror/history "
            "finalization failed; retained hardware pre-state",
            tx_id);
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: commit authority is durable but post-commit metadata "
            "finalization failed; transaction before-images remain retained");
    }

    g_ctx.active_commit_id = tx_id;
    if (!load_xml_into_sessions(candidate_xml)) {
        (void)journal_finalize_failure(tx_id, true);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
                         "error: committed active snapshot could not be promoted in memory");
    }
    if (opts.confirmed &&
        !configd_save_confirmed_awaiting(
            tx_id, previous_commit_id, confirmed_deadline)) {
        (void)journal_finalize_failure(tx_id, true);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: commit-confirmed authority committed but timeout state materialization failed");
    }

    // Mark success on switchd (if available)
    if (nl_journal_update_state(tx_id,
                                NL_JOURNAL_HW_MARKED_COMMITTED) != NL_OK) {
        (void)journal_finalize_failure(tx_id, true);

        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT("commit tx=0x%lx failed: cannot persist HW_MARKED_COMMITTED journal state",
                    tx_id);
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: commit authority is durable but journal finalization "
            "failed; transaction before-images remain retained");
    }
    if (switchd_available && has_l2 && plan_len > 0) {
        s32 mark_ec = 0;
        int mark_rn;

        mark_rn = configd_switchd_mark_success(tx_id, sw_resp,
                                               sizeof(sw_resp), &mark_ec);
        if (mark_rn < 0 || mark_ec != 0) {
            (void)journal_finalize_failure(tx_id, true);
            g_ctx.commit_locked = false;
            free(candidate_xml);
            NL_LOG_CRIT("commit tx=0x%lx mark_success failed rn=%d ec=%d",
                        tx_id, mark_rn, mark_ec);
            nl_send_response(conn, msg->request_id, NL_ERR_HW_STATE_OUT_OF_SYNC);
            return 0;
        }
    }

    configd_runtime_notify_reload();
    configd_l2_refresh_cache();

    if (persist_commit_comment(tx_id, opts.comment) != 0)
        NL_LOG_WARN("commit tx=0x%lx complete but comment persistence failed",
                    tx_id);
    if (!opts.confirmed)
        configd_confirm_pending_commit();

    // Journal: COMMITTED
    if (nl_journal_set_resulting_commit(tx_id, tx_id) != NL_OK ||
        nl_journal_update_state(tx_id, NL_JOURNAL_COMMITTED) != NL_OK) {
        (void)journal_finalize_failure(tx_id, true);
        g_ctx.commit_locked = false;
        free(candidate_xml);
        NL_LOG_CRIT("commit tx=0x%lx failed: cannot persist COMMITTED journal state",
                    tx_id);
        return send_text(conn, msg,
                         (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
                         "error: commit failed: final journal persistence failed; commit state is out of sync");
    }

    g_ctx.commit_locked = false;
    free(candidate_xml);

    NL_LOG_INFO("commit tx=0x%lx complete, new active_commit_id=%lu",
                tx_id, g_ctx.active_commit_id);
    if (g_ctx.guarded_restore_response)
        return send_guarded_restore_proof(conn, msg);
    nl_send_response(conn, msg->request_id, NL_OK);
    return 0;
}

// ===== Handle: rollback =====
static int handle_rollback(nl_conn *conn, nl_msg_hdr *msg) {
    int generation = 0;
    struct lyd_node *tree = NULL;

    if (!g_ctx.candidate || !g_ctx.active) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    if (!parse_rollback_generation(msg, &generation)) {
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE,
                         "error: invalid rollback number");
    }

    if (generation == 0) {
        // Reset candidate to match active.
        char *active_xml = nl_yang_to_xml(g_ctx.active);
        if (!active_xml)
            return send_text(conn, msg, (s32)NL_ERR_ROLLBACK_FAILED,
                             "error: rollback failed: cannot clone active configuration");
        config_xml_result parse_result = parse_config_xml_data(
            g_ctx.candidate, active_xml, &tree);
        free(active_xml);
        if (parse_result == CONFIG_XML_INVALID)
            return send_text(conn, msg, (s32)NL_ERR_ROLLBACK_FAILED,
                             "error: rollback failed: active configuration is invalid");
        nl_yang_data_set(g_ctx.candidate, tree);
        NL_LOG_INFO("rollback 0: candidate reset to active_commit_id=%lu",
                    g_ctx.active_commit_id);
        nl_send_response(conn, msg->request_id, NL_OK);
        return 0;
    }

    u64 ids[NL_CONFIG_MAX_ROLLBACK + 8];
    int n_ids = collect_rollback_ids(ids,
                                     (int)(sizeof(ids) / sizeof(ids[0])),
                                     g_ctx.active_commit_id);
    if (n_ids < 0)
        return send_text(
            conn, msg, (s32)NL_ERR_PRE_STATE_MISSING,
            "error: rollback unavailable\n"
            "reason: rollback storage path exceeds supported length");
    if (n_ids <= generation) {
        char err[768];
        snprintf(err, sizeof(err),
                 "error: rollback %d unavailable\n"
                 "reason: only %d committed configuration snapshot%s available",
                 generation, n_ids, n_ids == 1 ? " is" : "s are");
        return send_text(conn, msg, (s32)NL_ERR_PRE_STATE_MISSING, err);
    }

    u64 target_id = ids[n_ids - generation - 1];
    char path[512];
    if (!rollback_path_buf(path, sizeof(path), target_id))
        return send_text(
            conn, msg, (s32)NL_ERR_PRE_STATE_MISSING,
            "error: rollback unavailable\n"
            "reason: rollback snapshot path exceeds supported length");
    char *xml = read_text_file(path);
    if (!xml) {
        char err[768];
        snprintf(err, sizeof(err),
                 "error: rollback %d unavailable\nreason: cannot read %s",
                 generation, path);
        return send_text(conn, msg, (s32)NL_ERR_PRE_STATE_MISSING, err);
    }

    config_xml_result parse_result = parse_config_xml_data(
        g_ctx.candidate, xml, &tree);
    free(xml);
    if (parse_result == CONFIG_XML_INVALID) {
        char err[160];
        snprintf(err, sizeof(err),
                 "error: rollback %d failed\nreason: invalid rollback snapshot",
                 generation);
        return send_text(conn, msg, (s32)NL_ERR_ROLLBACK_FAILED, err);
    }

    nl_yang_data_set(g_ctx.candidate, tree);
    NL_LOG_INFO("rollback %d: candidate loaded commit_id=%lu",
                generation, target_id);
    nl_send_response(conn, msg->request_id, NL_OK);
    return 0;
}

typedef struct {
    const u8 *cursor;
    u32 remaining;
} guarded_payload_cursor;

static bool guarded_consume_literal(guarded_payload_cursor *payload,
                                    const char *literal) {
    size_t length;

    if (!payload || !literal)
        return false;
    length = strlen(literal);
    if (length > payload->remaining ||
        memcmp(payload->cursor, literal, length) != 0)
        return false;
    payload->cursor += length;
    payload->remaining -= (u32)length;
    return true;
}

static bool guarded_consume_sha256(guarded_payload_cursor *payload,
                                   const char *field, char digest[65]) {
    char prefix[64];
    int prefix_len;

    if (!payload || !field || !digest)
        return false;
    prefix_len = snprintf(prefix, sizeof(prefix), "%s=", field);
    if (prefix_len <= 0 || prefix_len >= (int)sizeof(prefix) ||
        !guarded_consume_literal(payload, prefix) ||
        payload->remaining < CONFIGD_GUARD_DIGEST_LEN + 1U)
        return false;
    memcpy(digest, payload->cursor, CONFIGD_GUARD_DIGEST_LEN);
    digest[CONFIGD_GUARD_DIGEST_LEN] = '\0';
    if (!lowercase_sha256_text(digest) ||
        payload->cursor[CONFIGD_GUARD_DIGEST_LEN] != '\n')
        return false;
    payload->cursor += CONFIGD_GUARD_DIGEST_LEN + 1U;
    payload->remaining -= CONFIGD_GUARD_DIGEST_LEN + 1U;
    return true;
}

static bool guarded_consume_tx_id(guarded_payload_cursor *payload,
                                  u64 *tx_id) {
    static const char prefix[] = "tx-id=0x";
    char value[17];
    char *end = NULL;
    unsigned long long parsed;

    if (!payload || !tx_id || !guarded_consume_literal(payload, prefix) ||
        payload->remaining < 17U)
        return false;
    memcpy(value, payload->cursor, 16);
    value[16] = '\0';
    if (payload->cursor[16] != '\n')
        return false;
    errno = 0;
    parsed = strtoull(value, &end, 16);
    if (errno != 0 || !end || *end != '\0' || parsed == 0)
        return false;
    payload->cursor += 17;
    payload->remaining -= 17U;
    *tx_id = (u64)parsed;
    return true;
}

static bool production_confirmed_state_quiescent(void) {
    nl_commit_confirmed confirmed;
    char path[512];
    struct stat st;

    if (nl_confirmed_load_readonly(&confirmed) == NL_OK) {
        if (confirmed.state == NL_CONFIRM_AWAITING)
            return false;
        if (confirmed.state == NL_TIMED_OUT)
            return g_ctx.active_commit_id > confirmed.tx_id;
        return confirmed.state == NL_CONFIRMED &&
               g_ctx.active_commit_id >= confirmed.tx_id;
    }
    nl_journal_file_path(path, sizeof(path), "confirmed.json");
    errno = 0;
    return lstat(path, &st) != 0 && errno == ENOENT;
}

static bool active_authority_exact_hashes(
    u64 expected_tx_id, const char *expected_content_sha256,
    char snapshot_sha256[65], char mirror_sha256[65]) {
    char active_path[512];
    char normalized_snapshot[65];
    char normalized_active[65];
    char *snapshot = NULL;
    char *mirror = NULL;
    char *active_xml = NULL;
    u64 durable_tx_id = 0;
    bool valid = false;

    if (expected_tx_id == 0 ||
        expected_tx_id != g_ctx.active_commit_id ||
        nl_tx_id_load(&durable_tx_id) != NL_OK ||
        durable_tx_id != expected_tx_id ||
        !lowercase_sha256_text(expected_content_sha256) || !g_ctx.active)
        return false;
    snapshot = read_commit_snapshot_xml(expected_tx_id);
    active_path_buf(active_path, sizeof(active_path));
    mirror = read_text_file(active_path);
    active_xml = nl_yang_to_xml(g_ctx.active);
    if (!snapshot || !mirror || !active_xml ||
        !sha256_bytes_hex(snapshot, strlen(snapshot), snapshot_sha256) ||
        !sha256_bytes_hex(mirror, strlen(mirror), mirror_sha256) ||
        strcmp(snapshot_sha256, expected_content_sha256) != 0 ||
        strcmp(mirror_sha256, expected_content_sha256) != 0 ||
        !candidate_sha256(snapshot, normalized_snapshot) ||
        !candidate_sha256(active_xml, normalized_active) ||
        !rollback_commit_marker_valid(
            expected_tx_id, normalized_snapshot) ||
        strcmp(normalized_snapshot, normalized_active) != 0)
        goto out;
    valid = true;

out:
    free(snapshot);
    free(mirror);
    free(active_xml);
    return valid;
}

static int send_guarded_restore_proof(nl_conn *conn,
                                      nl_msg_hdr *msg) {
    char snapshot_sha256[65];
    char mirror_sha256[65];
    char response[768];

    if (!active_authority_exact_hashes(
            g_ctx.active_commit_id,
            g_ctx.guarded_restore_content_sha256,
            snapshot_sha256, mirror_sha256)) {
        g_ctx.hw_out_of_sync = true;
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: guarded restore committed without exact active authority proof");
    }
    snprintf(response, sizeof(response),
             "{\"active-mirror-sha256\":\"%s\","
             "\"active-tx-id\":%" PRIu64 ","
             "\"active-tx-id-hex\":\"0x%016" PRIx64 "\","
             "\"contract\":\"netlab-production-guarded-restore-proof\","
             "\"content-sha256\":\"%s\","
             "\"pointer-sha256\":\"%s\","
             "\"schema-version\":1,"
             "\"snapshot-sha256\":\"%s\","
             "\"status\":\"restored\"}",
             mirror_sha256, g_ctx.active_commit_id,
             g_ctx.active_commit_id,
             g_ctx.guarded_restore_content_sha256,
             g_ctx.guarded_restore_pointer_sha256,
             snapshot_sha256);
    return send_text(conn, msg, 0, response);
}

static bool candidate_matches_active_configuration(void) {
    char *candidate_xml = NULL;
    char *active_xml = NULL;
    char candidate_digest[65];
    char active_digest[65];
    bool matches = false;

    if (!g_ctx.candidate || !g_ctx.active)
        return false;
    candidate_xml = nl_yang_to_xml(g_ctx.candidate);
    active_xml = nl_yang_to_xml(g_ctx.active);
    if (candidate_xml && active_xml &&
        candidate_sha256(candidate_xml, candidate_digest) &&
        candidate_sha256(active_xml, active_digest) &&
        strcmp(candidate_digest, active_digest) == 0)
        matches = true;
    free(candidate_xml);
    free(active_xml);
    return matches;
}

static int handle_production_guard_arm_check(nl_conn *conn,
                                             nl_msg_hdr *msg) {
    static const char contract[] =
        "netlab-production-guard-arm-check-v1\n";
    guarded_payload_cursor payload;
    char expected_sha256[65];
    char payload_sha256[65];
    char snapshot_sha256[65];
    char mirror_sha256[65];
    char detail[256];
    char response[640];
    u64 expected_tx_id = 0;
    nl_error_code xml_rc;
    production_guard_pointer pointer;
    production_guard_pointer_result pointer_result;
    int probe_fd;

    /*
     * The scheduler must own the cross-process authority lock while asking
     * configd to inspect its in-memory candidate.  Every mutating dispatch
     * uses a nonblocking acquisition, so this is a stable compare-and-arm
     * window rather than an advisory preflight result.
     */
    errno = 0;
    probe_fd = production_authority_lock(true);
    if (probe_fd >= 0) {
        production_authority_unlock(probe_fd);
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            "error: production guard arm check requires the scheduler authority lock");
    }
    if (errno != EWOULDBLOCK && errno != EAGAIN)
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            "error: production guard authority lock is unavailable");
    pointer_result = read_production_guard_pointer(&pointer);
    free_production_guard_pointer(&pointer);
    if (pointer_result != PRODUCTION_GUARD_POINTER_NONE)
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            pointer_result == PRODUCTION_GUARD_POINTER_VALID ?
                "error: a production configuration guard is already active" :
                "error: production configuration guard state is invalid");

    payload = (guarded_payload_cursor){msg->payload, msg->payload_len};
    if (!guarded_consume_literal(&payload, contract) ||
        !guarded_consume_tx_id(&payload, &expected_tx_id) ||
        !guarded_consume_sha256(
            &payload, "content-sha256", expected_sha256) ||
        !guarded_consume_literal(&payload, "\n") ||
        payload.remaining == 0 ||
        payload.remaining > NETLAB_CONFIG_XML_MAX ||
        !sha256_bytes_hex(payload.cursor, payload.remaining, payload_sha256) ||
        strcmp(payload_sha256, expected_sha256) != 0)
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE,
                         "error: malformed production guard arm proof");
    if (g_ctx.hw_out_of_sync || g_ctx.active_authority_uncertain ||
        expected_tx_id != g_ctx.active_commit_id ||
        !production_confirmed_state_quiescent())
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            "error: configuration authority is not quiescent for production guard arm");
    if (!candidate_matches_active_configuration()) {
        return send_text(
            conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
            "error: candidate differs from active configuration during production guard arm");
    }
    if (!active_authority_exact_hashes(
            expected_tx_id, expected_sha256,
            snapshot_sha256, mirror_sha256))
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: active authority does not match production checkpoint");
    xml_rc = validate_candidate_xml_payload(
        payload.cursor, payload.remaining, false, detail, sizeof(detail));
    if (xml_rc != (nl_error_code)NL_OK)
        return send_text(
            conn, msg, (s32)xml_rc,
            "error: production checkpoint XML is not exactly recoverable");
    snprintf(response, sizeof(response),
             "{\"active-mirror-sha256\":\"%s\","
             "\"active-tx-id\":%" PRIu64 ","
             "\"active-tx-id-hex\":\"0x%016" PRIx64 "\","
             "\"candidate-clean\":true,"
             "\"contract\":\"netlab-production-guard-arm-proof\","
             "\"content-sha256\":\"%s\","
             "\"pending-confirmed\":false,"
             "\"recoverable\":true,"
             "\"schema-version\":1,"
             "\"snapshot-sha256\":\"%s\","
             "\"status\":\"armable\"}",
             mirror_sha256, expected_tx_id, expected_tx_id, expected_sha256,
             snapshot_sha256);
    return send_text(conn, msg, 0, response);
}

static int handle_production_guarded_restore_xml(nl_conn *conn,
                                                 nl_msg_hdr *msg) {
    static const char contract[] =
        "netlab-production-guarded-restore-v1\n";
    guarded_payload_cursor payload;
    char pointer_sha256[65];
    char expected_sha256[65];
    char observed_sha256[65];
    char detail[256];
    nl_msg_hdr *commit_msg;
    nl_error_code rc;
    int result;

    payload = (guarded_payload_cursor){msg->payload, msg->payload_len};
    if (!guarded_consume_literal(&payload, contract) ||
        !guarded_consume_sha256(
            &payload, "pointer-sha256", pointer_sha256) ||
        !guarded_consume_sha256(
            &payload, "content-sha256", expected_sha256) ||
        !guarded_consume_literal(&payload, "\n") ||
        payload.remaining == 0 ||
        payload.remaining > NETLAB_CONFIG_XML_MAX ||
        !sha256_bytes_hex(payload.cursor, payload.remaining,
                          observed_sha256) ||
        strcmp(observed_sha256, expected_sha256) != 0)
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE,
                         "error: malformed guarded restore payload");
    if (strcmp(pointer_sha256,
               g_ctx.guarded_restore_pointer_sha256) != 0 ||
        !production_confirmed_state_quiescent())
        return send_text(conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                         "error: guarded restore authority is unavailable");
    rc = replace_candidate_xml_payload(
        payload.cursor, payload.remaining, detail, sizeof(detail));
    if (rc != (nl_error_code)NL_OK)
        return send_text(conn, msg, (s32)rc,
                         "error: guarded restore XML validation failed");
    commit_msg = nl_msg_alloc(0);
    if (!commit_msg)
        return send_text(conn, msg, (s32)NL_ERR,
                         "error: guarded restore commit allocation failed");
    commit_msg->type = NL_MSG_REQUEST;
    commit_msg->request_id = msg->request_id;
    commit_msg->daemon_id = msg->daemon_id;
    commit_msg->method = NL_CONFIGD_COMMIT;
    g_ctx.production_guard_authorized = true;
    g_ctx.guarded_restore_response = true;
    snprintf(g_ctx.guarded_restore_content_sha256,
             sizeof(g_ctx.guarded_restore_content_sha256), "%s",
             expected_sha256);
    result = handle_commit(conn, commit_msg);
    nl_msg_free(commit_msg);
    g_ctx.production_guard_authorized = false;
    g_ctx.guarded_restore_response = false;
    g_ctx.guarded_restore_content_sha256[0] = '\0';
    return result;
}

static int handle_production_guard_complete_check(nl_conn *conn,
                                                  nl_msg_hdr *msg) {
    static const char contract[] =
        "netlab-production-guard-complete-v1\n";
    guarded_payload_cursor payload;
    char pointer_sha256[65];
    char expected_sha256[65];
    char snapshot_sha256[65];
    char mirror_sha256[65];
    char response[640];
    u64 expected_tx_id = 0;

    payload = (guarded_payload_cursor){msg->payload, msg->payload_len};
    if (!guarded_consume_literal(&payload, contract) ||
        !guarded_consume_sha256(
            &payload, "pointer-sha256", pointer_sha256) ||
        !guarded_consume_tx_id(&payload, &expected_tx_id) ||
        !guarded_consume_sha256(
            &payload, "content-sha256", expected_sha256) ||
        payload.remaining != 0 ||
        strcmp(pointer_sha256,
               g_ctx.guarded_restore_pointer_sha256) != 0)
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE,
                         "error: malformed production guard completion proof");
    if (!active_authority_exact_hashes(
            expected_tx_id, expected_sha256,
            snapshot_sha256, mirror_sha256))
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: completed production guard does not match active authority");
    snprintf(response, sizeof(response),
             "{\"active-mirror-sha256\":\"%s\","
             "\"active-tx-id\":%" PRIu64 ","
             "\"active-tx-id-hex\":\"0x%016" PRIx64 "\","
             "\"contract\":\"netlab-production-guard-complete-proof\","
             "\"content-sha256\":\"%s\","
             "\"pointer-sha256\":\"%s\","
             "\"schema-version\":1,"
             "\"snapshot-sha256\":\"%s\","
             "\"status\":\"complete\"}",
             mirror_sha256, expected_tx_id, expected_tx_id, expected_sha256,
             pointer_sha256, snapshot_sha256);
    return send_text(conn, msg, 0, response);
}

// ===== Handle: rollback history =====
static int handle_rollback_history(nl_conn *conn, nl_msg_hdr *msg) {
    char buf[8192];
    int off = 0;
    u64 ids[NL_CONFIG_MAX_ROLLBACK + 8];
    int n_ids;

    if (!g_ctx.active) {
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE,
                         "error: active configuration is not loaded");
    }

    n_ids = collect_rollback_ids(ids,
                                 (int)(sizeof(ids) / sizeof(ids[0])),
                                 g_ctx.active_commit_id);
    if (n_ids < 0)
        return send_text(
            conn, msg, (s32)NL_ERR_PRE_STATE_MISSING,
            "error: rollback history unavailable\n"
            "reason: rollback storage path exceeds supported length");

    for (int gen = 0; gen < n_ids; gen++) {
        u64 id = ids[n_ids - gen - 1];
        char path[512];
        struct stat st;
        char ts[64];
        char owner_buf[32];
        char comment[CONFIGD_COMMIT_COMMENT_MAX];
        const char *owner = "root";

        if (!rollback_path_buf(path, sizeof(path), id))
            return send_text(
                conn, msg, (s32)NL_ERR_PRE_STATE_MISSING,
                "error: rollback history unavailable\n"
                "reason: rollback snapshot path exceeds supported length");
        comment[0] = '\0';
        if (stat(path, &st) == 0) {
            format_local_time(st.st_mtime, ts, sizeof(ts));
            owner = uid_name(st.st_uid, owner_buf, sizeof(owner_buf));
        } else {
            snprintf(ts, sizeof(ts), "unknown time");
        }

        read_commit_comment(id, comment, sizeof(comment));
        if (comment[0]) {
            off += snprintf(buf + off, sizeof(buf) - (size_t)off,
                            "%d\t%s by %s via cli comment \"%s\"\n",
                            gen, ts, owner, comment);
        } else {
            off += snprintf(buf + off, sizeof(buf) - (size_t)off,
                            "%d\t%s by %s via cli\n", gen, ts, owner);
        }
        if (off >= (int)sizeof(buf) - 128)
            break;
    }

    if (off == 0)
        off += snprintf(buf + off, sizeof(buf) - (size_t)off,
                        "0\tcurrent active configuration\n");

    return send_text(conn, msg, 0, buf);
}

static int handle_confirmed_status(nl_conn *conn, nl_msg_hdr *msg) {
    nl_commit_confirmed c;
    char buf[768];
    char deadline[64];

    if (nl_confirmed_load_readonly(&c) != NL_OK)
        return send_text(conn, msg, 0, "Commit confirmed: none\n");

    if (c.state == NL_CONFIRM_AWAITING) {
        s64 remaining = nl_confirmed_remaining_seconds(&c);
        s64 display_deadline = nl_confirmed_display_deadline(&c);
        if (remaining < 0 || display_deadline <= 0)
            return send_text(conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC, "commit-confirmed clock unavailable");
        format_local_time((time_t)display_deadline, deadline, sizeof(deadline));
        snprintf(buf, sizeof(buf),
                 "Commit confirmed: awaiting confirmation\n"
                 "  commit-id       : 0x%016lx\n"
                 "  previous        : 0x%016lx\n"
                 "  rollback in     : %ld seconds\n"
                 "  deadline        : %s\n",
                 c.tx_id, c.previous_commit_id, (long)remaining, deadline);
    } else if (c.state == NL_CONFIRMED) {
        snprintf(buf, sizeof(buf),
                 "Commit confirmed: confirmed\n"
                 "  commit-id       : 0x%016lx\n"
                 "  previous        : 0x%016lx\n",
                 c.tx_id, c.previous_commit_id);
    } else {
        snprintf(buf, sizeof(buf),
                 "Commit confirmed: timed out\n"
                 "  commit-id       : 0x%016lx\n"
                 "  previous        : 0x%016lx\n",
                 c.tx_id, c.previous_commit_id);
    }
    return send_text(conn, msg, 0, buf);
}

// ===== Handle: get_candidate (show) =====
static int handle_get_candidate(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.candidate) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    char *xml = nl_yang_to_xml(g_ctx.candidate);
    if (!xml) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    int plen = (int)strlen(xml);
    nl_msg_hdr *resp = nl_msg_alloc((u32)plen);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)plen;
        memcpy(resp->payload, xml, (size_t)plen);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(xml);
    return 0;
}

// ===== Handle: commit_check =====
static int handle_commit_check(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.candidate) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
    if (reject_candidate_public_capabilities(conn, msg))
        return 0;
    if (reject_noncleanup_candidate_when_required(conn, msg))
        return 0;

    char *plan_buf = configd_l2_plan_workspace();
    char *l3_plan_buf = configd_l3_plan_workspace();
    int plan_len = 0;
    bool has_l2 = false;
    char err_buf[512] = {0};
    int l3_plan_len = 0;
    bool has_l3 = false;
    char l3_err_buf[512] = {0};
    if (configd_l2_build_plan(g_ctx.active, g_ctx.candidate, false,
                              plan_buf, NL_L2_PLAN_MAX_BYTES,
                              &plan_len, &has_l2,
                              err_buf, sizeof(err_buf)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            err_buf[0] ? err_buf : "invalid configuration", "", "");
        return 0;
    }
    if (configd_l2_validate_plan(plan_buf, plan_len, has_l2,
                          err_buf, sizeof(err_buf)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            err_buf[0] ? err_buf : "L2 feature validation failed", "", "");
        return 0;
    }
    if (configd_l3_build_plan(g_ctx.active, g_ctx.candidate,
                              l3_plan_buf, NL_L3_PLAN_MAX_BYTES,
                              &l3_plan_len, &has_l3,
                              l3_err_buf, sizeof(l3_err_buf)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            l3_err_buf[0] ? l3_err_buf : "invalid L3 configuration", "", "");
        return 0;
    }
    if (configd_l3_validate_plan(l3_plan_buf, l3_plan_len, has_l3,
                                 l3_err_buf, sizeof(l3_err_buf)) != 0) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            l3_err_buf[0] ? l3_err_buf : "L3 feature validation failed", "", "");
        return 0;
    }
    if (has_l3 && !configd_l3_public_apply_enabled()) {
        (void)send_bounded_error_response(
            conn, msg, (s32)NL_ERR_INVALID_VALUE,
            CONFIGD_SHORT_ERROR_RESPONSE_MAX_BYTES, "error: ",
            configd_l3_public_apply_gate_reason(), "", "");
        return 0;
    }
    (void)plan_len;
    (void)has_l2;

    NL_LOG_INFO("commit check passed");
    nl_send_response(conn, msg->request_id, NL_OK);
    return 0;
}

static bool configd_active_replay_capability_invariant(
        char *detail, size_t detail_size) {
    refresh_public_capability_cleanup_required();
    if (!g_ctx.public_capability_cleanup_required)
        return true;
    if (detail && detail_size > 0)
        snprintf(
            detail, detail_size,
            "error: active replay deferred until closed public capability "
            "intent is removed");
    return false;
}

// ===== Handle: active replay =====
static nl_error_code reconcile_active_state(char *detail, size_t size) {
    u64 generation = 0;
    bool bound = false;
    const char *profile = g_ctx.active ? nl_yang_get(g_ctx.active, "/netlab:netlab-config/chassis/fm10k-panel/profile") : NULL;
    bool native = configd_native_control_mode();
    if (native && configd_native_status(profile, &generation, &bound)) return NL_ERR_PFE_DOWN;
    nl_error_code rc = prepare_unresolved_for_active_replay(
        detail, size);

    if (rc == NL_ERR_OK)
        rc = replay_active_to_hardware(true, detail, size);
    if (rc == NL_ERR_OK &&
        !configd_active_replay_capability_invariant(
            detail, size)) {
        g_ctx.hw_out_of_sync = true;
        rc = NL_ERR_INVALID_VALUE;
    }
    if (rc == NL_ERR_OK && !repair_active_snapshot_metadata()) {
        g_ctx.hw_out_of_sync = true;
        rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
        snprintf(detail, size,
                 "error: active replay succeeded but committed "
                 "mirror/history metadata repair failed");
    }
    /*
     * Reconstruct pending timeout scheduling while the active journal is
     * still unresolved.  Its transition to COMMITTED runs terminal
     * compaction, so the pin must already exist before that transition.
     */
    if (rc == NL_ERR_OK &&
        !configd_recover_active_confirmed_intent()) {
        g_ctx.hw_out_of_sync = true;
        rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
        snprintf(
            detail, size,
            "error: active replay repaired hardware but could not "
            "restore commit-confirmed scheduling authority");
    }
    if (rc == NL_ERR_OK && finalize_replayed_active_journals(NULL) != 0) {
        g_ctx.hw_out_of_sync = true;
        rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
        snprintf(detail, size,
                 "error: active replay succeeded but durable journal finalization failed");
    }
    if (rc == NL_ERR_OK && native) {
        /* Full readback can be a no-op after configd restarts. Release any
         * retained lease of this committed transaction only after proving
         * the active hardware image and reloading its protocol consumers. */
        int scope = configd_scope_finish(g_ctx.active_commit_id, true, detail, size);
        if (scope) rc = (nl_error_code)scope;
        else rc = (nl_error_code)configd_native_bind(profile, generation, g_ctx.active_commit_id);
        if (rc == NL_ERR_OK) {
            g_ctx.native_generation = generation;
            g_ctx.native_failed_generation = 0;
        }
    }
    if (rc == NL_ERR_OK) {
        g_ctx.hw_out_of_sync = false;
        configd_runtime_notify_reload();
    } else g_ctx.hw_out_of_sync = true;
    return rc;
}

static int handle_replay_active(nl_conn *conn, nl_msg_hdr *msg) {
    char detail[512] = {0};
    nl_error_code rc = reconcile_active_state(detail, sizeof(detail));

    if (rc == NL_ERR_OK)
        send_text(conn, msg, 0, detail[0] ? detail : "active replay complete");
    else
        send_text(conn, msg, (s32)rc, detail[0] ? detail : nl_error_msg(rc));
    return 0;
}

static void configd_native_replay_tick(void) {
    time_t now = nl_monotonic_seconds();
    if (!configd_native_control_mode() || !g_ctx.active || g_ctx.commit_locked ||
        now <= 0 || now < g_ctx.native_next_poll) return;
    g_ctx.native_next_poll = now + 5;
    const char *profile = nl_yang_get(g_ctx.active, "/netlab:netlab-config/chassis/fm10k-panel/profile");
    u64 generation = 0;
    bool bound = false;
    if (configd_native_status(profile, &generation, &bound)) {
        g_ctx.hw_out_of_sync = true;
        return;
    }
    if (generation == g_ctx.native_generation && bound && !g_ctx.hw_out_of_sync) return;
    g_ctx.hw_out_of_sync = true;
    if (generation == g_ctx.native_failed_generation || !configd_scope_peers_available()) return;
    int lock_fd = production_authority_lock(true);
    if (lock_fd < 0) return;
    char detail[512] = {0};
    nl_error_code rc = reconcile_active_state(detail, sizeof(detail));
    production_authority_unlock(lock_fd);
    if (rc == NL_ERR_OK)
        NL_LOG_NOTICE("native configuration replay verified for SDK generation %016llx", (unsigned long long)generation);
    else {
        /* Do not turn an ambiguous apply failure into a repeated hardware
         * experiment or an automatic ASIC/service reset. Explicit recovery
         * or a new SDK lifetime must resolve the failed transaction. */
        g_ctx.native_failed_generation = generation;
        NL_LOG_ERR("native startup replay remains out of sync (%d): %s", (int)rc, detail);
    }
}

static int handle_reconcile(nl_conn *conn, nl_msg_hdr *msg) {
    if (configd_native_control_mode()) return handle_replay_active(conn, msg);
    char detail[512] = {0};
    int committed = 0;
    nl_error_code rc = prepare_unresolved_for_active_replay(
        detail, sizeof(detail));

    if (rc == NL_ERR_OK)
        rc = replay_active_to_hardware(true, detail, sizeof(detail));
    if (rc == NL_ERR_OK &&
        !configd_active_replay_capability_invariant(
            detail, sizeof(detail))) {
        g_ctx.hw_out_of_sync = true;
        return send_text(conn, msg, (s32)NL_ERR_INVALID_VALUE, detail);
    }
    if (rc == NL_ERR_OK && !repair_active_snapshot_metadata()) {
        g_ctx.hw_out_of_sync = true;
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: reconcile repaired hardware but committed "
            "mirror/history metadata repair failed");
    }
    if (rc != NL_ERR_OK)
        return send_text(conn, msg, (s32)rc,
                         detail[0] ? detail : nl_error_msg(rc));
    if (!configd_recover_active_confirmed_intent()) {
        g_ctx.hw_out_of_sync = true;
        return send_text(
            conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
            "error: reconcile repaired hardware but could not "
            "restore commit-confirmed scheduling authority");
    }
    if (finalize_replayed_active_journals(&committed) != 0) {
        g_ctx.hw_out_of_sync = true;
        return send_text(conn, msg, (s32)NL_ERR_HW_STATE_OUT_OF_SYNC,
                         "error: reconcile failed: cannot persist journal recovery");
    }
    g_ctx.hw_out_of_sync = false;
    configd_runtime_notify_reload();
    NL_LOG_NOTICE("hardware state reconciled: %s committed-journals=%d",
                  detail[0] ? detail : "active replay complete", committed);
    {
        char resp[768];
        snprintf(resp, sizeof(resp),
                 "reconcile complete\n%s\nfinalized durable journals: %d",
                 detail[0] ? detail : "active replay complete", committed);
        return send_text(conn, msg, 0, resp);
    }
}

// ===== Handle: get_active =====
static int handle_get_active(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.active) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    char *xml = nl_yang_to_xml(g_ctx.active);
    if (!xml) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    int plen = (int)strlen(xml);
    nl_msg_hdr *resp = nl_msg_alloc((u32)plen);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)plen;
        memcpy(resp->payload, xml, (size_t)plen);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(xml);
    return 0;
}

// ===== Handle: diff (show | compare) =====
static int handle_diff(nl_conn *conn, nl_msg_hdr *msg) {
    if (!g_ctx.candidate || !g_ctx.active) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    // Get candidate tree for diff
    struct lyd_node *cand_tree = NULL;
    char *cand_xml = nl_yang_to_xml(g_ctx.candidate);
    if (cand_xml) {
        cand_tree = nl_yang_from_xml(g_ctx.candidate, cand_xml);
        free(cand_xml);
    }

    struct lyd_node *active_tree = NULL;
    char *active_xml = nl_yang_to_xml(g_ctx.active);
    if (active_xml) {
        active_tree = nl_yang_from_xml(g_ctx.candidate, active_xml);
        free(active_xml);
    }

    char buf[8192];
    int off = 0;

    struct lyd_node *diff = nl_yang_diff(g_ctx.candidate, active_tree, cand_tree);
    if (diff) {
        int n = nl_yang_diff_to_compare(g_ctx.candidate, diff, buf + off,
                                        (int)(sizeof(buf) - off));
        if (n > 0) off += n;
        if (n <= 0) {
            off += snprintf(buf + off, sizeof(buf) - off,
                            "\nNo changes between candidate and active config\n");
        }
        lyd_free_tree(diff);
    } else {
        off += snprintf(buf + off, sizeof(buf) - off,
                        "\nNo changes between candidate and active config\n");
    }

    if (cand_tree) lyd_free_tree(cand_tree);
    if (active_tree) lyd_free_tree(active_tree);

    nl_msg_hdr *resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    return 0;
}

#include "panel_rpc.inc"

static bool configd_method_mutates_authority(u16 method) {
    switch (method) {
    case NL_CONFIGD_PANEL_VALIDATE:
    case NL_CONFIGD_PANEL_APPLY:
    case NL_CONFIGD_PANEL_CONFIRM:
    case NL_CONFIGD_PANEL_ROLLBACK:
    case NL_CONFIGD_PANEL_RECOVER:
    case NL_CONFIGD_SET:
    case NL_CONFIGD_DELETE:
    case NL_CONFIGD_COMMIT:
    case NL_CONFIGD_ROLLBACK:
    case NL_CONFIGD_COMMIT_CONFIRMED:
    case NL_CONFIGD_REPLAY_ACTIVE:
    case NL_CONFIGD_RECONCILE:
    case NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML:
    case NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK:
        return true;
    default:
        return false;
    }
}

static bool payload_has_guard_envelope(const nl_msg_hdr *msg) {
    size_t prefix_len = strlen(CONFIGD_GUARD_ENVELOPE_PREFIX);

    return msg && msg->payload_len >= prefix_len &&
           memcmp(msg->payload, CONFIGD_GUARD_ENVELOPE_PREFIX,
                  prefix_len) == 0;
}

static nl_msg_hdr *strip_guard_envelope(const nl_msg_hdr *msg,
                                        const char *expected_sha256) {
    size_t prefix_len = strlen(CONFIGD_GUARD_ENVELOPE_PREFIX);
    size_t envelope_len = prefix_len + CONFIGD_GUARD_DIGEST_LEN + 1U;
    nl_msg_hdr *stripped;
    u32 payload_len;

    if (!msg || !lowercase_sha256_text(expected_sha256) ||
        msg->payload_len < envelope_len ||
        memcmp(msg->payload, CONFIGD_GUARD_ENVELOPE_PREFIX,
               prefix_len) != 0 ||
        memcmp(msg->payload + prefix_len, expected_sha256,
               CONFIGD_GUARD_DIGEST_LEN) != 0 ||
        msg->payload[envelope_len - 1U] != '\n')
        return NULL;
    payload_len = msg->payload_len - (u32)envelope_len;
    stripped = nl_msg_alloc(payload_len);
    if (!stripped)
        return NULL;
    memcpy(stripped, msg, NL_HDR_SIZE);
    stripped->payload_len = payload_len;
    if (payload_len > 0)
        memcpy(stripped->payload, msg->payload + envelope_len, payload_len);
    return stripped;
}

static int dispatch_configd_method(nl_conn *conn, nl_msg_hdr *msg) {
    switch (msg->method) {
    case NL_CONFIGD_PANEL_SNAPSHOT: return handle_panel_snapshot(conn, msg);
    case NL_CONFIGD_PANEL_VALIDATE: return handle_panel_replace(conn, msg, false);
    case NL_CONFIGD_PANEL_APPLY: return handle_panel_replace(conn, msg, true);
    case NL_CONFIGD_PANEL_CONFIRM: return handle_panel_finish(conn, msg, true);
    case NL_CONFIGD_PANEL_ROLLBACK: return handle_panel_finish(conn, msg, false);
    case NL_CONFIGD_PANEL_RECOVER: return handle_panel_recover(conn, msg);
    case NL_CONFIGD_SET: return handle_set(conn, msg);
    case NL_CONFIGD_DELETE: return handle_delete(conn, msg);
    case NL_CONFIGD_COMMIT: return handle_commit(conn, msg);
    case NL_CONFIGD_ROLLBACK: return handle_rollback(conn, msg);
    case NL_CONFIGD_GET_CANDIDATE: return handle_get_candidate(conn, msg);
    case NL_CONFIGD_COMMIT_CHECK: return handle_commit_check(conn, msg);
    case NL_CONFIGD_COMMIT_CONFIRMED: return handle_commit(conn, msg);
    case NL_CONFIGD_GET_ACTIVE: return handle_get_active(conn, msg);
    case NL_CONFIGD_DIFF: return handle_diff(conn, msg);
    case NL_CONFIGD_REPLAY_ACTIVE: return handle_replay_active(conn, msg);
    case NL_CONFIGD_ROLLBACK_HISTORY:
        return handle_rollback_history(conn, msg);
    case NL_CONFIGD_RECONCILE: return handle_reconcile(conn, msg);
    case NL_CONFIGD_CONFIRMED_STATUS:
        return handle_confirmed_status(conn, msg);
    case NL_CONFIGD_PRODUCTION_GUARD_ARM_CHECK:
        return handle_production_guard_arm_check(conn, msg);
    case NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML:
        return handle_production_guarded_restore_xml(conn, msg);
    case NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK:
        return handle_production_guard_complete_check(conn, msg);
    case NL_CONFIGD_PUBLIC_CAPABILITY_STATUS:
        return handle_public_capability_status(conn, msg);
    default: nl_send_response(conn, msg->request_id, -1); return 0;
    }
}

static void configd_check_confirmed_timeout_if_unblocked(void) {
    production_guard_pointer pointer;
    production_guard_pointer_result pointer_result;
    int lock_fd;

    lock_fd = production_authority_lock(true);
    if (lock_fd < 0)
        return;
    pointer_result = read_production_guard_pointer(&pointer);
    if (pointer_result == PRODUCTION_GUARD_POINTER_NONE)
        configd_check_confirmed_timeout();
    else if (pointer_result == PRODUCTION_GUARD_POINTER_INVALID) {
        g_ctx.hw_out_of_sync = true;
        NL_LOG_CRIT("production guard pointer is invalid; blocking timeout mutation");
    }
    free_production_guard_pointer(&pointer);
    production_authority_unlock(lock_fd);
}

// ===== Dispatch =====
static int configd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    production_guard_pointer pointer;
    production_guard_pointer_result pointer_result;
    nl_msg_hdr *stripped = NULL;
    nl_msg_hdr *effective = msg;
    bool mutation;
    bool internal_replay;
    int lock_fd = -1;
    int result;

    (void)ctx;
    if (msg->method == NL_CONFIGD_PRODUCTION_GUARD_ARM_CHECK)
        return dispatch_configd_method(conn, msg);
    if (msg->method == NL_CONFIGD_PUBLIC_CAPABILITY_STATUS)
        return dispatch_configd_method(conn, msg);
    if (panel_managed() && (msg->method == NL_CONFIGD_SET ||
        msg->method == NL_CONFIGD_DELETE || msg->method == NL_CONFIGD_COMMIT ||
        msg->method == NL_CONFIGD_COMMIT_CONFIRMED || msg->method == NL_CONFIGD_ROLLBACK))
        return send_text(conn, msg, NL_ERR_COMMIT_LOCKED,
            "FM10K panel owns the canonical candidate; use its atomic versioned API");
    mutation = configd_method_mutates_authority(msg->method);
    if (!mutation) {
        configd_check_confirmed_timeout_if_unblocked();
        return dispatch_configd_method(conn, msg);
    }
    lock_fd = production_authority_lock(true);
    if (lock_fd < 0)
        return send_text(conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                         "error: configuration authority transition is busy");
    pointer_result = read_production_guard_pointer(&pointer);
    if (pointer_result == PRODUCTION_GUARD_POINTER_INVALID) {
        result = send_text(conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                           "error: production configuration guard is invalid");
        goto out;
    }
    internal_replay = msg->method == NL_CONFIGD_REPLAY_ACTIVE &&
                      msg->daemon_id == NL_DAEMON_INTERNAL;
    if (pointer_result == PRODUCTION_GUARD_POINTER_NONE) {
        if (payload_has_guard_envelope(msg) ||
            msg->method == NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML ||
            msg->method == NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK) {
            result = send_text(
                conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                "error: production configuration guard is not active");
            goto out;
        }
        configd_check_confirmed_timeout();
    } else if (internal_replay) {
        /* Startup may replay the already committed active image. */
    } else if (msg->method ==
               NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML) {
        if (!pointer.finalizing) {
            result = send_text(
                conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                "error: production guard is not in finalizing state");
            goto out;
        }
        snprintf(g_ctx.guarded_restore_pointer_sha256,
                 sizeof(g_ctx.guarded_restore_pointer_sha256), "%s",
                 pointer.sha256);
    } else if (msg->method ==
               NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK) {
        if (!pointer.completed) {
            result = send_text(
                conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                "error: production guard is not in completed state");
            goto out;
        }
        snprintf(g_ctx.guarded_restore_pointer_sha256,
                 sizeof(g_ctx.guarded_restore_pointer_sha256), "%s",
                 pointer.sha256);
    } else {
        if (!pointer.armed ||
            msg->method == NL_CONFIGD_COMMIT_CONFIRMED) {
            result = send_text(
                conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                "error: production configuration guard blocks this writer");
            goto out;
        }
        stripped = strip_guard_envelope(msg, pointer.sha256);
        if (!stripped) {
            result = send_text(
                conn, msg, (s32)NL_ERR_COMMIT_LOCKED,
                "error: production configuration guard token is missing or stale");
            goto out;
        }
        effective = stripped;
        g_ctx.production_guard_authorized = true;
    }
    result = dispatch_configd_method(conn, effective);

out:
    g_ctx.production_guard_authorized = false;
    g_ctx.guarded_restore_pointer_sha256[0] = '\0';
    if (stripped)
        nl_msg_free(stripped);
    free_production_guard_pointer(&pointer);
    production_authority_unlock(lock_fd);
    return result;
}

// ===== Main =====
int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name        = "configd",
        .socket_path = nl_ipc_socket_path_from_env("NETLAB_CONFIGD_SOCKET",
                                                   CONFIGD_SOCKET),
        .service_id  = NL_DAEMON_CONFIGD,
        .auth_mode   = NL_DAEMON_AUTH_STANDARD,
        .dispatch    = configd_dispatch,
        .ctx         = NULL,
        .on_init     = configd_on_init,
        .on_shutdown = configd_on_shutdown,
        .poll_interval_ms = 1000,
        .on_idle     = configd_on_idle,
    };

    if (argc == 5 && strcmp(argv[1], "--test-build-l2-plan") == 0)
        return configd_l2_plan_test_main(argv[2], argv[3], argv[4]);
    if (argc != 1) {
        fprintf(stderr,
                "usage: %s [--test-build-l2-plan ACTIVE CANDIDATE "
                "REQUIRE_HW]\n", argv[0]);
        return 2;
    }
    return nl_daemon_run(&cfg);
}
