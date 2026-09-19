#include "l2_client.h"
#include "netlab/ipc.h"
#include "netlab/l2_plan_build.h"
#include "netlab/l2_plan.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define L2D_SOCKET "/var/run/netlab/l2d.sock"

static const char *l2d_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_L2D_SOCKET", L2D_SOCKET);
}

int configd_l2_validate_plan(const char *plan, int plan_len, bool has_l2,
                             char *err, size_t err_size) {
    char resp[1024] = {0};
    s32 ec = 0;
    int rn;

    if (err && err_size > 0)
        err[0] = '\0';
    if (!has_l2 || plan_len <= 0)
        return 0;

    rn = nl_rpc_call_ex(l2d_socket_path(), NL_DAEMON_CONFIGD,
                        NL_DAEMON_L2D, NL_L2D_VALIDATE_PLAN, 0,
                        (const u8 *)plan, plan_len,
                        (u8 *)resp, sizeof(resp) - 1, 5000, &ec);
    if (rn >= 0 && ec == 0)
        return 0;

    if (err && err_size > 0) {
        snprintf(err, err_size, "%s",
                 resp[0] ? resp : "l2d validation failed");
    }
    return -1;
}

void configd_l2_refresh_cache(void) {
    char refresh_resp[32] = {0};
    s32 refresh_ec = 0;

    (void)nl_rpc_call_ex(l2d_socket_path(), NL_DAEMON_CONFIGD,
                         NL_DAEMON_L2D, NL_L2D_VALIDATE_PLAN, 0,
                         (const u8 *)"", 0,
                         (u8 *)refresh_resp, sizeof(refresh_resp),
                         3000, &refresh_ec);
}

static int parse_l2d_plan_response(const char *resp, int resp_len,
                                   char *plan, size_t plan_size,
                                   int *plan_len, bool *has_l2,
                                   char *err, size_t err_size) {
    const char *line_end;
    int hdr_has_l2 = 0;
    int hdr_plan_len = 0;
    int consumed = 0;
    size_t header_len;
    size_t line_len;
    char header[64];

    if (!resp || resp_len < 0 || !plan || !plan_len || !has_l2) {
        snprintf(err, err_size, "invalid l2d plan response");
        return -1;
    }
    line_end = memchr(resp, '\n', (size_t)resp_len);
    line_len = line_end ? (size_t)(line_end - resp) : 0U;
    if (!line_end || line_len == 0 || line_len >= sizeof(header)) {
        snprintf(err, err_size, "malformed l2d plan response");
        return -1;
    }
    memcpy(header, resp, line_len);
    header[line_len] = '\0';
    if (sscanf(header, "has-l2=%d plan-len=%d%n",
               &hdr_has_l2, &hdr_plan_len, &consumed) != 2 ||
        consumed < 0 || (size_t)consumed != line_len ||
        (hdr_has_l2 != 0 && hdr_has_l2 != 1) || hdr_plan_len < 0 ||
        (size_t)hdr_plan_len > NL_L2_PLAN_MAX_BYTES) {
        snprintf(err, err_size, "malformed l2d plan response");
        return -1;
    }
    header_len = line_len + 1U;
    if ((size_t)resp_len != header_len + (size_t)hdr_plan_len ||
        (size_t)hdr_plan_len >= plan_size) {
        snprintf(err, err_size, "truncated l2d plan response");
        return -1;
    }
    memcpy(plan, resp + header_len, (size_t)hdr_plan_len);
    plan[hdr_plan_len] = '\0';
    *plan_len = hdr_plan_len;
    *has_l2 = hdr_has_l2 != 0;
    return 0;
}

static int l2_plan_build_token_generate(
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES]) {
    size_t offset = 0;
    u8 combined = 0;

    while (offset < NL_L2_PLAN_BUILD_TOKEN_BYTES) {
        ssize_t count = getrandom(
            token + offset, NL_L2_PLAN_BUILD_TOKEN_BYTES - offset, 0);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        offset += (size_t)count;
    }
    for (size_t i = 0; i < NL_L2_PLAN_BUILD_TOKEN_BYTES; i++)
        combined |= token[i];
    return combined != 0 ? 0 : -1;
}

static int l2_plan_build_control_call(nl_rpc_method method,
                                      const void *payload,
                                      int payload_length,
                                      int timeout_ms) {
    u8 response[1] = {0};
    s32 error_code = 0;
    int response_length;

    response_length = nl_rpc_call_ex(
        l2d_socket_path(), NL_DAEMON_CONFIGD, NL_DAEMON_L2D,
        method, 0, payload, payload_length,
        response, sizeof(response), timeout_ms, &error_code);
    return response_length == 0 && error_code == 0 ? 0 : -1;
}

static void l2_plan_build_abort(
    const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES]) {
    u8 request[32];
    int request_length = nl_l2_plan_build_token_encode(
        token, request, sizeof(request));

    if (request_length > 0)
        (void)l2_plan_build_control_call(
            NL_L2D_BUILD_PLAN_ABORT, request, request_length, 3000);
}

static int l2_plan_build_send_stream(
    const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
    nl_l2_plan_build_stream stream, const char *xml, size_t xml_length) {
    const size_t chunk_capacity =
        NETLAB_MAX_MSG - NL_L2_PLAN_BUILD_PART_HEADER_BYTES;
    u8 *request;
    size_t offset = 0;
    int status = -1;

    if (!xml || xml_length == 0 ||
        xml_length > NL_L2_PLAN_CONFIG_MAX_BYTES)
        return -1;
    request = malloc(NETLAB_MAX_MSG);
    if (!request)
        return -1;
    while (offset < xml_length) {
        nl_l2_plan_build_part part = {0};
        size_t chunk = xml_length - offset;
        int request_length;

        if (chunk > chunk_capacity)
            chunk = chunk_capacity;
        memcpy(part.token, token, sizeof(part.token));
        part.stream = stream;
        part.offset = (u32)offset;
        part.total_length = (u32)xml_length;
        request_length = nl_l2_plan_build_part_encode(
            &part, xml + offset, chunk, request, NETLAB_MAX_MSG);
        if (request_length <= 0 ||
            l2_plan_build_control_call(
                NL_L2D_BUILD_PLAN_PART, request, request_length,
                5000) != 0)
            goto out;
        offset += chunk;
    }
    status = 0;

out:
    free(request);
    return status;
}

int configd_l2_build_plan(nl_yang_session *active,
                          nl_yang_session *candidate,
                          bool require_hw,
                          char *plan, size_t plan_size,
                          int *plan_len, bool *has_l2,
                          char *err, size_t err_size) {
    char *active_xml = NULL;
    char *candidate_xml = NULL;
    nl_rpc_response response = {0};
    nl_l2_plan_build_begin begin = {0};
    u8 begin_request[64];
    u8 commit_request[32];
    size_t active_len;
    size_t candidate_len;
    int begin_length;
    int commit_length;
    int rn;
    int ret = -1;
    bool staged = false;

    if (err && err_size > 0)
        err[0] = '\0';
    if (plan && plan_size > 0)
        plan[0] = '\0';
    if (plan_len)
        *plan_len = 0;
    if (has_l2)
        *has_l2 = false;
    if (!active || !candidate || !plan || plan_size == 0 ||
        !plan_len || !has_l2) {
        snprintf(err, err_size, "invalid L2 plan request");
        return -1;
    }

    active_xml = nl_yang_to_xml(active);
    candidate_xml = nl_yang_to_xml(candidate);
    if (!active_xml || !candidate_xml) {
        snprintf(err, err_size, "failed to serialize config for l2d");
        goto out;
    }
    active_len = strlen(active_xml);
    candidate_len = strlen(candidate_xml);
    if (active_len == 0 || candidate_len == 0 ||
        active_len > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        candidate_len > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        l2_plan_build_token_generate(begin.token) != 0) {
        snprintf(err, err_size,
                 "configuration exceeds the bounded L2 plan session");
        goto out;
    }
    begin.active_length = (u32)active_len;
    begin.candidate_length = (u32)candidate_len;
    begin.require_hardware = require_hw;
    begin_length = nl_l2_plan_build_begin_encode(
        &begin, begin_request, sizeof(begin_request));
    if (begin_length <= 0 || l2_plan_build_control_call(
            NL_L2D_BUILD_PLAN_BEGIN, begin_request, begin_length,
            5000) != 0) {
        snprintf(err, err_size, "l2d plan staging begin failed");
        goto out;
    }
    staged = true;
    if (l2_plan_build_send_stream(
            begin.token, NL_L2_PLAN_BUILD_ACTIVE,
            active_xml, active_len) != 0 ||
        l2_plan_build_send_stream(
            begin.token, NL_L2_PLAN_BUILD_CANDIDATE,
            candidate_xml, candidate_len) != 0) {
        snprintf(err, err_size, "l2d plan staging transfer failed");
        goto out;
    }
    commit_length = nl_l2_plan_build_token_encode(
        begin.token, commit_request, sizeof(commit_request));
    if (commit_length <= 0) {
        snprintf(err, err_size, "l2d plan staging token failed");
        goto out;
    }

    rn = nl_rpc_call_alloc_ex(
        l2d_socket_path(), NL_DAEMON_CONFIGD, NL_DAEMON_L2D,
        NL_L2D_BUILD_PLAN_COMMIT, 0, commit_request,
        commit_length, 30000, &response);
    if (rn < 0 || response.error_code != 0) {
        snprintf(err, err_size, "%s",
                 response.payload && response.payload[0] ?
                     (const char *)response.payload :
                     "l2d plan build failed");
        goto out;
    }
    if (parse_l2d_plan_response((const char *)response.payload, rn,
                                plan, plan_size,
                                plan_len, has_l2,
                                err, err_size) != 0)
        goto out;
    ret = 0;
    staged = false;

out:
    if (staged)
        l2_plan_build_abort(begin.token);
    free(active_xml);
    free(candidate_xml);
    nl_rpc_response_free(&response);
    return ret;
}
