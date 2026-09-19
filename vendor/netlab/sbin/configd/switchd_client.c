/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "switchd_client.h"
#include "runtime_scope.h"
#include "netlab/ipc.h"
#include "netlab/pfe_capability.h"
#include <stdio.h>
#include <string.h>

#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
/* Six EPL transitions were measured near the former 30-second limit. */
#define L2_TRANSACTION_TIMEOUT_MS 60000

static void terminate_resp(char *resp, size_t resp_size, int rn) {
    size_t pos;

    if (!resp || resp_size == 0)
        return;
    if (rn < 0)
        pos = 0;
    else if ((size_t)rn >= resp_size)
        pos = resp_size - 1;
    else
        pos = (size_t)rn;
    resp[pos] = '\0';
}

static int switchd_call(nl_rpc_method method, u64 tx_id, const u8 *payload,
                        int payload_len, char *resp, size_t resp_size,
                        int timeout_ms, s32 *error_code) {
    s32 ec = 0;
    int rn;

    if (resp && resp_size > 0)
        resp[0] = '\0';
    rn = nl_rpc_call_ex(
        nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET", SWITCHD_SOCKET),
        NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD, method, tx_id, payload,
        payload_len, (u8 *)resp,
        resp_size > 0 ? (int)resp_size - 1 : 0, timeout_ms, &ec);
    terminate_resp(resp, resp_size, rn);
    if (error_code)
        *error_code = ec;
    return rn;
}

static int query_pfe(char *resp, size_t resp_size, s32 *error_code) {
    static const char pfe_status[] = "pfe_status";

    return switchd_call(NL_SWITCHD_PFE_STATUS_GET, 0,
                        (const u8 *)pfe_status,
                        (int)strlen(pfe_status), resp, resp_size,
                        5000, error_code);
}

bool configd_switchd_pfe_up(char *detail, size_t detail_size) {
    char pfe_resp[NETLAB_PFE_STATUS_JSON_BYTES + 1] = {0};
    s32 pfe_ec = 0;
    int pfe_rn;

    pfe_rn = query_pfe(pfe_resp, sizeof(pfe_resp), &pfe_ec);
    if (pfe_rn <= 0 || pfe_ec != 0) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size, "switchd unreachable or PFE query failed");
        return false;
    }

    if (strstr(pfe_resp, "\"status\": \"UP\"") ||
        strstr(pfe_resp, "\"status\":\"UP\""))
        return true;

    if (detail && detail_size > 0)
        snprintf(detail, detail_size, "%s", pfe_resp);
    return false;
}

nl_error_code configd_switchd_commit_pfe_check(bool *switchd_available,
                                               char *detail,
                                               size_t detail_size) {
    char pfe_resp[NETLAB_PFE_STATUS_JSON_BYTES + 1] = {0};
    s32 pfe_ec = 0;
    int pfe_rn;

    if (switchd_available)
        *switchd_available = false;
    if (detail && detail_size > 0)
        detail[0] = '\0';

    pfe_rn = query_pfe(pfe_resp, sizeof(pfe_resp), &pfe_ec);
    if (pfe_rn > 0 && pfe_ec == 0 && pfe_resp[0]) {
        if (switchd_available)
            *switchd_available = true;
        if (strstr(pfe_resp, "PFE_DOWN") || strstr(pfe_resp, "SDK_DOWN")) {
            if (detail && detail_size > 0)
                snprintf(detail, detail_size, "%s", pfe_resp);
            return NL_ERR_PFE_DOWN;
        }
    }
    return NL_ERR_OK;
}

int configd_switchd_apply_l2_plan(u64 tx_id, const char *plan, int plan_len,
                                  char *resp, size_t resp_size,
                                  s32 *error_code) {
    int scope = configd_scope_begin(tx_id, plan, (size_t)plan_len, resp, resp_size);
    if (scope) { if (error_code) *error_code = scope; return resp ? (int)strlen(resp) : 0; }
    return switchd_call(NL_SWITCHD_L2_PLAN_APPLY, tx_id,
                        (const u8 *)plan, plan_len,
                        resp, resp_size, L2_TRANSACTION_TIMEOUT_MS, error_code);
}

int configd_switchd_rollback_l2_plan(u64 tx_id, char *resp,
                                     size_t resp_size, s32 *error_code) {
    return switchd_call(NL_SWITCHD_L2_PLAN_ROLLBACK, tx_id,
                        NULL, 0, resp, resp_size, L2_TRANSACTION_TIMEOUT_MS, error_code);
}

bool configd_switchd_l2_rollback_verified(u64 tx_id, int rpc_result,
                                          s32 error_code,
                                          const char *resp) {
    char tx_attr[48];

    if (rpc_result < 0 || error_code != 0 || !resp)
        return false;
    snprintf(tx_attr, sizeof(tx_attr), "tx-id=\"%016lx\"", tx_id);
    return strstr(resp, "<l2-plan-rollback status=\"ok\"") != NULL &&
           strstr(resp, tx_attr) != NULL &&
           strstr(resp, "sdk-write=\"live\"") != NULL &&
           strstr(resp, "sdk-readback=\"live\"") != NULL &&
           (strstr(resp, "idempotent=\"true\"") != NULL ||
            strstr(resp, "mismatches=\"0\"") != NULL);
}

int configd_switchd_mark_success(u64 tx_id, char *resp, size_t resp_size,
                                 s32 *error_code) {
    char tx_buf[32];

    snprintf(tx_buf, sizeof(tx_buf), "%016lx", tx_id);
    s32 ec = 0;
    int rn = switchd_call(NL_SWITCHD_COMMIT_MARK_SUCCESS, tx_id,
                        (const u8 *)tx_buf, (int)strlen(tx_buf),
                        resp, resp_size, 5000, &ec);
    if (rn >= 0 && !ec) ec = configd_scope_finish(tx_id, true, resp, resp_size);
    if (error_code) *error_code = ec;
    return rn;
}

int configd_switchd_mark_failed(u64 tx_id, char *resp, size_t resp_size,
                                s32 *error_code) {
    char tx_buf[32];

    snprintf(tx_buf, sizeof(tx_buf), "%016lx", tx_id);
    s32 ec = 0;
    int rn = configd_scope_was_not_dispatched(tx_id) ? 0 : switchd_call(NL_SWITCHD_COMMIT_MARK_FAILED, tx_id,
                        (const u8 *)tx_buf, (int)strlen(tx_buf),
                        resp, resp_size, 5000, &ec);
    if (rn >= 0 && !ec) ec = configd_scope_finish(tx_id, false, resp, resp_size);
    if (error_code) *error_code = ec;
    return rn;
}
