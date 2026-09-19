#include "rpc_response.h"
#include "netlab/error.h"
#include <string.h>

int hal_rpc_send_payload(nl_conn *conn, u64 request_id, s32 error_code,
                         const void *payload, u32 payload_len) {
    nl_msg_hdr *resp;

    if (!conn)
        return -1;
    if (payload_len > NETLAB_MAX_MSG) {
        static const char detail[] =
            "switchd response exceeds the IPC message capacity";

        return hal_rpc_send_payload(
            conn, request_id, NL_ERR_CAPABILITY_INSUFFICIENT,
            detail, (u32)sizeof(detail) - 1);
    }
    if (payload_len > 0 && !payload)
        return -1;

    resp = nl_msg_alloc(payload_len);
    if (!resp)
        return -1;

    /* Preserve switchd's wire contract: callers inspect error_code. */
    resp->type = NL_MSG_RESPONSE;
    resp->request_id = request_id;
    resp->error_code = error_code;
    resp->payload_len = payload_len;
    if (payload && payload_len > 0)
        memcpy(resp->payload, payload, payload_len);
    int rc = nl_send(conn, resp) == NL_OK ? 0 : -1;
    nl_msg_free(resp);
    return rc;
}

int hal_rpc_send_text(nl_conn *conn, u64 request_id, s32 error_code,
                      const char *text) {
    u32 len = text ? (u32)strlen(text) : 0;

    return hal_rpc_send_payload(conn, request_id, error_code, text, len);
}
