#!/usr/bin/env python3.11
# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
"""Exercise configd's multi-message L2 plan-build client with large trees."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from build_support import libyang_flags


ROOT = Path(__file__).resolve().parents[2]

C_SOURCE = r'''
#include "l2_client.h"
#include "netlab/ipc.h"
#include "netlab/l2_plan_build.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_LENGTH 600000U

static char *active_xml;
static char *candidate_xml;
static u8 session_token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
static u32 expected_offset[3];
static int begin_calls;
static int part_calls;
static int commit_calls;
static int abort_calls;
static int fail_part_call;
static int commit_response_mode;
static int failures;

#define EXPECT(name, expression) do {                                      \
    if (expression) printf("PASS: %s\n", name);                           \
    else { printf("FAIL: %s\n", name); failures++; }                      \
} while (0)

const char *nl_ipc_socket_path_from_env(const char *name,
                                        const char *fallback) {
    (void)name;
    return fallback;
}

char *nl_yang_to_xml(nl_yang_session *session) {
    if (session == (nl_yang_session *)(uintptr_t)1U)
        return strdup(active_xml);
    if (session == (nl_yang_session *)(uintptr_t)2U)
        return strdup(candidate_xml);
    return NULL;
}

int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller,
                   nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                   const u8 *payload, int payload_len,
                   u8 *resp_buf, int max_resp, int timeout_ms,
                   s32 *error_code) {
    (void)socket_path; (void)tx_id; (void)resp_buf; (void)max_resp;
    if (error_code)
        *error_code = 0;
    if (caller != NL_DAEMON_CONFIGD || service != NL_DAEMON_L2D ||
        timeout_ms <= 0 || !payload || payload_len <= 0)
        return -1;
    if (method == NL_L2D_BUILD_PLAN_BEGIN) {
        nl_l2_plan_build_begin begin;
        begin_calls++;
        if (nl_l2_plan_build_begin_decode(
                payload, (size_t)payload_len, &begin) != 0 ||
            begin.active_length != CONFIG_LENGTH ||
            begin.candidate_length != CONFIG_LENGTH)
            return -1;
        memcpy(session_token, begin.token, sizeof(session_token));
        expected_offset[NL_L2_PLAN_BUILD_ACTIVE] = 0;
        expected_offset[NL_L2_PLAN_BUILD_CANDIDATE] = 0;
        return 0;
    }
    if (method == NL_L2D_BUILD_PLAN_PART) {
        nl_l2_plan_build_part part;
        const u8 *data = NULL;
        size_t data_length = 0;
        part_calls++;
        if (fail_part_call > 0 && part_calls == fail_part_call) {
            if (error_code)
                *error_code = NL_ERR_INVALID_VALUE;
            return -1;
        }
        if (nl_l2_plan_build_part_decode(
                payload, (size_t)payload_len, &part,
                &data, &data_length) != 0 ||
            memcmp(part.token, session_token,
                   sizeof(session_token)) != 0 ||
            part.offset != expected_offset[part.stream] ||
            part.total_length != CONFIG_LENGTH || data_length == 0)
            return -1;
        expected_offset[part.stream] += (u32)data_length;
        return 0;
    }
    if (method == NL_L2D_BUILD_PLAN_ABORT) {
        u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
        abort_calls++;
        return nl_l2_plan_build_token_decode(
                   payload, (size_t)payload_len, token) == 0 &&
               memcmp(token, session_token, sizeof(token)) == 0 ? 0 : -1;
    }
    return -1;
}

int nl_rpc_call_alloc_ex(const char *socket_path, nl_daemon_id caller,
                         nl_daemon_id service, nl_rpc_method method,
                         u64 tx_id, const u8 *payload, int payload_len,
                         int timeout_ms, nl_rpc_response *response) {
    static const char valid_body[] =
        "has-l2=1 plan-len=20\nvlan-create vid=100\n";
    static const char extended_body[] =
        "has-l2=1 plan-len=20\nvlan-create vid=100\nX";
    static const char junk_header_body[] =
        "has-l2=1 plan-len=20 junk\nvlan-create vid=100\n";
    static const char invalid_flag_body[] =
        "has-l2=2 plan-len=20\nvlan-create vid=100\n";
    const char *body = valid_body;
    size_t body_length = sizeof(valid_body) - 1U;
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];

    (void)socket_path; (void)tx_id;
    if (!response || caller != NL_DAEMON_CONFIGD ||
        service != NL_DAEMON_L2D ||
        method != NL_L2D_BUILD_PLAN_COMMIT || timeout_ms < 10000 ||
        nl_l2_plan_build_token_decode(
            payload, (size_t)payload_len, token) != 0 ||
        memcmp(token, session_token, sizeof(token)) != 0)
        return -1;
    commit_calls++;
    if (commit_response_mode == 1) {
        body = extended_body;
        body_length = sizeof(extended_body) - 1U;
    } else if (commit_response_mode == 2) {
        body = junk_header_body;
        body_length = sizeof(junk_header_body) - 1U;
    } else if (commit_response_mode == 3) {
        body = invalid_flag_body;
        body_length = sizeof(invalid_flag_body) - 1U;
    }
    memset(response, 0, sizeof(*response));
    response->payload_len = (u32)body_length;
    response->payload = calloc(response->payload_len + 1U, 1);
    if (!response->payload)
        return -1;
    memcpy(response->payload, body, response->payload_len);
    return (int)response->payload_len;
}

void nl_rpc_response_free(nl_rpc_response *response) {
    if (!response)
        return;
    free(response->payload);
    memset(response, 0, sizeof(*response));
}

static void reset_calls(void) {
    memset(session_token, 0, sizeof(session_token));
    memset(expected_offset, 0, sizeof(expected_offset));
    begin_calls = 0;
    part_calls = 0;
    commit_calls = 0;
    abort_calls = 0;
    fail_part_call = 0;
    commit_response_mode = 0;
}

int main(void) {
    char *plan = calloc(1, 256U * 1024U);
    char error[512] = {0};
    int plan_length = 0;
    bool has_l2 = false;
    int status;

    active_xml = malloc(CONFIG_LENGTH + 1U);
    candidate_xml = malloc(CONFIG_LENGTH + 1U);
    if (!plan || !active_xml || !candidate_xml)
        return 1;
    memset(active_xml, 'a', CONFIG_LENGTH);
    memset(candidate_xml, 'c', CONFIG_LENGTH);
    active_xml[CONFIG_LENGTH] = '\0';
    candidate_xml[CONFIG_LENGTH] = '\0';

    reset_calls();
    status = configd_l2_build_plan(
        (nl_yang_session *)(uintptr_t)1U,
        (nl_yang_session *)(uintptr_t)2U,
        true, plan, 256U * 1024U, &plan_length, &has_l2,
        error, sizeof(error));
    EXPECT("large active and candidate trees use one staged session",
           status == 0 && begin_calls == 1 && commit_calls == 1 &&
           abort_calls == 0);
    EXPECT("each stream is transferred completely in bounded parts",
           part_calls == 6 &&
           expected_offset[NL_L2_PLAN_BUILD_ACTIVE] == CONFIG_LENGTH &&
           expected_offset[NL_L2_PLAN_BUILD_CANDIDATE] == CONFIG_LENGTH);
    EXPECT("commit response is parsed without truncation",
           has_l2 && plan_length == 20 &&
           strcmp(plan, "vlan-create vid=100\n") == 0);

    reset_calls();
    fail_part_call = 2;
    status = configd_l2_build_plan(
        (nl_yang_session *)(uintptr_t)1U,
        (nl_yang_session *)(uintptr_t)2U,
        false, plan, 256U * 1024U, &plan_length, &has_l2,
        error, sizeof(error));
    EXPECT("part failure aborts and never commits partial authority",
           status != 0 && begin_calls == 1 && part_calls == 2 &&
           commit_calls == 0 && abort_calls == 1 && !has_l2 &&
           plan_length == 0);

    for (int mode = 1; mode <= 3; mode++) {
        reset_calls();
        commit_response_mode = mode;
        status = configd_l2_build_plan(
            (nl_yang_session *)(uintptr_t)1U,
            (nl_yang_session *)(uintptr_t)2U,
            false, plan, 256U * 1024U, &plan_length, &has_l2,
            error, sizeof(error));
        EXPECT(mode == 1 ? "response with trailing bytes is rejected" :
               mode == 2 ? "response with header suffix is rejected" :
                           "response with non-boolean has-l2 is rejected",
               status != 0 && commit_calls == 1 && abort_calls == 1 &&
               !has_l2 && plan_length == 0);
    }

    free(plan);
    free(active_xml);
    free(candidate_xml);
    return failures ? 1 : 0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="netlab-configd-l2-stage-") as td:
        source = Path(td) / "configd_l2_staged_build_test.c"
        binary = Path(td) / "configd_l2_staged_build_test"
        source.write_text(C_SOURCE, encoding="utf-8")
        built = subprocess.run(
            [
                "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", *libyang_flags()[0],
                "-Werror", "-pedantic", "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin/configd"), str(source),
                str(ROOT / "sbin/configd/l2_client.c"),
                str(ROOT / "lib/libipc/l2_plan_build.c"),
                "-o", str(binary),
            ],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if built.returncode != 0:
            print("FAIL: configd staged L2 client fixture builds")
            print(built.stdout, end="")
            return 1
        print("PASS: configd staged L2 client fixture builds")
        run = subprocess.run(
            [str(binary)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=15, check=False,
        )
        print(run.stdout, end="")
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
