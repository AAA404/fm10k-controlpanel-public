#ifndef SWITCHD_RPC_RESPONSE_H
#define SWITCHD_RPC_RESPONSE_H

#include "netlab/ipc.h"

int hal_rpc_send_payload(nl_conn *conn, u64 request_id, s32 error_code,
                         const void *payload, u32 payload_len);
int hal_rpc_send_text(nl_conn *conn, u64 request_id, s32 error_code,
                      const char *text);

#endif
