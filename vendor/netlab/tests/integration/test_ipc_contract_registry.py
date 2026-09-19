#!/usr/bin/env python3.11
"""Typed IPC registry, caller identity, response, and deadline contracts."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def test_compiled_registry_and_client() -> int:
    source = r'''
#include "netlab/ipc.h"
#include "netlab/identity_broker.h"
#include "netlab/sflow.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

_Static_assert(NL_DAEMON_L3D == 17,
               "retired L3D wire reservation must remain 17");
_Static_assert(NL_DAEMON_IDENTITYD == 18,
               "identityd wire identity must remain 18");
_Static_assert(NL_SWITCHD_RESERVED_LAG_CREATE == 70,
               "retired direct LAG create wire method must remain 70");
_Static_assert(NL_SWITCHD_RESERVED_MAC_TABLE_GET == 50,
               "retired lossy MAC table wire method must remain 50");
_Static_assert(NL_SWITCHD_RESERVED_STP_STATE_GET == 51,
               "retired lossy STP table wire method must remain 51");
_Static_assert(NL_CONFIGD_PRODUCTION_GUARD_ARM_CHECK == 15,
               "production guard arm-check wire method must remain 15");
_Static_assert(NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML == 16,
               "production guarded restore wire method must remain 16");
_Static_assert(NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK == 17,
               "production guard completion wire method must remain 17");
_Static_assert(NL_CONFIGD_PUBLIC_CAPABILITY_STATUS == 18,
               "public capability status wire method must remain 18");

#define RESPONSE_LEN (100U * 1024U)
#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

typedef struct {
    int listen_fd;
    int ok;
    u64 request_ids[2];
    u32 timeout_ms[2];
} server_state;

typedef struct {
    nl_daemon_id service;
    nl_rpc_method method;
} internal_authority_key;

static int internal_authority_expected(nl_daemon_id service,
                                       nl_rpc_method method) {
    static const internal_authority_key allowed[] = {
        {NL_DAEMON_SWITCHD, NL_SWITCHD_PORT_GET_INVENTORY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_VLAN_CREATE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_VLAN_DELETE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_PFE_STATUS_GET},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_POLICER_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_TX_DRY_RUN},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_SHADOW_MISMATCH_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_FAILURE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_SDK_READBACK_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_SDK_WRITE_CANARY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_SFLOW_LIVE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_RIF_LIVE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_ARP_LIVE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_ECMP_LIVE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_ROUTE_LIVE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_PERSISTENT_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_PERSISTENT_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_L3_PERSISTENT_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_OWNER_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_OWNER_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_OWNER_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_POLICER_OWNER_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_POLICER_OWNER_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_POLICER_OWNER_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_EGRESS_PROBE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_GENERAL_ALLOCATOR_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_GENERAL_ALLOCATOR_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_ACL_GENERAL_ALLOCATOR_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_WATERMARK_OWNER_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_QOS_WATERMARK_OWNER_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_APPLY},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_READBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_RECONCILE},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_ROLLBACK},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_SNAPSHOT_BEGIN},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_SNAPSHOT_PART},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_SNAPSHOT_COMMIT},
        {NL_DAEMON_SWITCHD, NL_SWITCHD_RPD_FIB_SNAPSHOT_ABORT},
        {NL_DAEMON_CONFIGD, NL_CONFIGD_REPLAY_ACTIVE},
        {NL_DAEMON_CONFIGD, NL_CONFIGD_PRODUCTION_GUARD_ARM_CHECK},
        {NL_DAEMON_CONFIGD, NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML},
        {NL_DAEMON_CONFIGD, NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK},
        {NL_DAEMON_L2D, NL_L2D_SHOW_ETHERNET_SWITCHING},
        {NL_DAEMON_RPD, NL_RPD_STATE},
    };

    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (allowed[i].service == service && allowed[i].method == method)
            return 1;
    }
    return 0;
}

static void *serve(void *arg) {
    server_state *state = arg;

    for (int i = 0; i < 2; i++) {
        nl_conn conn = {0};
        nl_msg_hdr *request = NULL;
        nl_msg_hdr *response = NULL;

        if (nl_server_accept(state->listen_fd, &conn) != NL_OK ||
            nl_server_authenticate(&conn) != NL_OK ||
            nl_recv(&conn, &request) != NL_OK || !request)
            return NULL;
        state->request_ids[i] = request->request_id;
        state->timeout_ms[i] = request->timeout_ms;
        if (request->type != NL_MSG_REQUEST ||
            request->daemon_id != NL_DAEMON_CONFIGD ||
            request->method != NL_L2D_BUILD_PLAN_COMMIT ||
            request->request_id == 0 || request->timeout_ms == 0 ||
            request->timeout_ms > 1000)
            goto request_out;

        response = nl_msg_alloc(RESPONSE_LEN);
        if (!response)
            goto request_out;
        response->type = NL_MSG_RESPONSE;
        response->request_id = request->request_id;
        response->method = request->method;
        response->daemon_id = NL_DAEMON_L2D;
        memset(response->payload, 'x', RESPONSE_LEN);
        if (nl_send(&conn, response) != NL_OK)
            goto request_out;
        nl_msg_free(response);
        nl_msg_free(request);
        close(conn.fd);
        continue;

request_out:
        nl_msg_free(response);
        nl_msg_free(request);
        close(conn.fd);
        return NULL;
    }
    state->ok = 1;
    return NULL;
}

static int contract_registry_valid(void) {
    static const nl_rpc_method l3_methods[] = {
        NL_SWITCHD_L3_TX_DRY_RUN,
        NL_SWITCHD_L3_TX_APPLY,
        NL_SWITCHD_L3_TX_READBACK,
        NL_SWITCHD_L3_TX_ROLLBACK,
        NL_SWITCHD_L3_SHADOW_MISMATCH_PROBE,
        NL_SWITCHD_L3_FAILURE_PROBE,
        NL_SWITCHD_L3_SDK_READBACK_PROBE,
        NL_SWITCHD_L3_SDK_WRITE_CANARY,
        NL_SWITCHD_L3_RIF_LIVE_PROBE,
        NL_SWITCHD_L3_ARP_LIVE_PROBE,
        NL_SWITCHD_L3_ECMP_LIVE_PROBE,
        NL_SWITCHD_L3_ROUTE_LIVE_PROBE,
        NL_SWITCHD_L3_PERSISTENT_APPLY,
        NL_SWITCHD_L3_PERSISTENT_READBACK,
        NL_SWITCHD_L3_PERSISTENT_ROLLBACK,
    };

    if (nl_rpc_contract_count() == 0)
        return 0;
    for (size_t i = 0; i < nl_rpc_contract_count(); i++) {
        const nl_rpc_contract *left = nl_rpc_contract_at(i);

        if (!left || !left->name || !left->name[0] ||
            left->max_request_len > NETLAB_MAX_MSG ||
            left->max_response_len > NETLAB_MAX_MSG)
            return 0;
        if ((int)left->internal_authority_allowed !=
                internal_authority_expected(left->service, left->method) ||
            (int)nl_rpc_contract_caller_allowed(
                left, NL_DAEMON_INTERNAL) !=
                internal_authority_expected(left->service, left->method))
            return 0;
        if ((left->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) &&
            left->service != NL_DAEMON_MGMTD &&
            !nl_rpc_contract_caller_allowed(left, NL_DAEMON_MGMTD))
            return 0;
        for (size_t j = i + 1; j < nl_rpc_contract_count(); j++) {
            const nl_rpc_contract *right = nl_rpc_contract_at(j);

            if (right && left->service == right->service &&
                left->method == right->method)
                return 0;
        }
    }

    for (size_t i = 0; i < sizeof(l3_methods) / sizeof(l3_methods[0]); i++) {
        const nl_rpc_contract *contract = nl_rpc_contract_lookup(
            NL_DAEMON_SWITCHD, l3_methods[i]);

        if (!contract ||
            !nl_rpc_contract_caller_allowed(contract, NL_DAEMON_RPD) ||
            ((int)nl_rpc_contract_caller_allowed(
                 contract, NL_DAEMON_INTERNAL) !=
             internal_authority_expected(
                 NL_DAEMON_SWITCHD, l3_methods[i])) ||
            nl_rpc_contract_caller_allowed(contract, NL_DAEMON_L3D) ||
            nl_rpc_contract_caller_allowed(contract, NL_DAEMON_CONFIGD) ||
            nl_rpc_contract_caller_allowed(contract, NL_DAEMON_MGMTD) ||
            nl_rpc_contract_caller_allowed(contract, NL_DAEMON_SWITCHD))
            return 0;
    }

    const nl_rpc_contract *l2_rollback = nl_rpc_contract_lookup(
        NL_DAEMON_SWITCHD, NL_SWITCHD_L2_PLAN_ROLLBACK);
    const u8 forbidden_rollback_payload[] = "payload";
    if (!l2_rollback ||
        strcmp(l2_rollback->name, "l2-plan-rollback") != 0 ||
        l2_rollback->request_format != NL_RPC_PAYLOAD_NONE ||
        l2_rollback->response_format != NL_RPC_PAYLOAD_TEXT ||
        l2_rollback->max_request_len != 0 ||
        l2_rollback->max_response_len != 512 ||
        l2_rollback->flags != NL_RPC_CONTRACT_TX_ID_REQUIRED ||
        l2_rollback->access != NL_RPC_ACCESS_INTERNAL ||
        !nl_rpc_contract_payload_valid(
            l2_rollback->request_format, NULL, 0,
            l2_rollback->max_request_len) ||
        nl_rpc_contract_payload_valid(
            l2_rollback->request_format, forbidden_rollback_payload,
            sizeof(forbidden_rollback_payload) - 1U,
            l2_rollback->max_request_len))
        return 0;
    for (int caller = (int)NL_DAEMON_INTERNAL;
         caller <= (int)NL_DAEMON_IDENTITYD; caller++) {
        if (nl_rpc_contract_caller_allowed(
                l2_rollback, (nl_daemon_id)caller) !=
            ((nl_daemon_id)caller == NL_DAEMON_CONFIGD))
            return 0;
    }

    const nl_rpc_contract *sflow_probe = nl_rpc_contract_lookup(
        NL_DAEMON_SWITCHD, NL_SWITCHD_SFLOW_LIVE_PROBE);
    if (!sflow_probe ||
        sflow_probe->request_format != NL_RPC_PAYLOAD_TEXT ||
        sflow_probe->response_format != NL_RPC_PAYLOAD_TEXT ||
        sflow_probe->max_request_len !=
            NL_SFLOW_V1_PROBE_REQUEST_MAX ||
        sflow_probe->max_response_len !=
            NL_SFLOW_V1_PROBE_RESPONSE_MAX ||
        sflow_probe->flags != NL_RPC_CONTRACT_TX_ID_REQUIRED ||
        sflow_probe->access != NL_RPC_ACCESS_INTERNAL ||
        !nl_rpc_contract_caller_allowed(
            sflow_probe, NL_DAEMON_INTERNAL))
        return 0;
    for (int caller = (int)NL_DAEMON_MGMTD;
         caller <= (int)NL_DAEMON_IDENTITYD; caller++) {
        if (nl_rpc_contract_caller_allowed(
                sflow_probe, (nl_daemon_id)caller))
            return 0;
    }

    const nl_rpc_contract *sflow_batch = nl_rpc_contract_lookup(
        NL_DAEMON_SWITCHD, NL_SWITCHD_SFLOW_BATCH_GET);
    if (!sflow_batch ||
        sflow_batch->request_format != NL_RPC_PAYLOAD_BINARY ||
        sflow_batch->response_format != NL_RPC_PAYLOAD_BINARY ||
        sflow_batch->max_request_len !=
            sizeof(nl_sflow_batch_request_v1) ||
        sflow_batch->max_response_len !=
            sizeof(nl_sflow_batch_response_v1) ||
        sflow_batch->flags != 0 ||
        sflow_batch->access != NL_RPC_ACCESS_INTERNAL ||
        !nl_rpc_contract_caller_allowed(
            sflow_batch, NL_DAEMON_STATSD) ||
        nl_rpc_contract_caller_allowed(
            sflow_batch, NL_DAEMON_INTERNAL))
        return 0;
    for (int caller = (int)NL_DAEMON_MGMTD;
         caller <= (int)NL_DAEMON_IDENTITYD; caller++) {
        if ((nl_daemon_id)caller != NL_DAEMON_STATSD &&
            nl_rpc_contract_caller_allowed(
                sflow_batch, (nl_daemon_id)caller))
            return 0;
    }

    static const struct {
        nl_rpc_method method;
        u32 request_size;
        u32 response_size;
    } identity_methods[] = {
        {
            NL_IDENTITYD_CAPTURE,
            sizeof(nl_identity_capture_request),
            sizeof(nl_identity_capture_response),
        },
        {
            NL_IDENTITYD_VERIFY,
            sizeof(nl_identity_verify_request),
            sizeof(nl_identity_verify_response),
        },
        {
            NL_IDENTITYD_RELEASE,
            sizeof(nl_identity_release_request),
            sizeof(nl_identity_release_response),
        },
    };
    for (size_t i = 0;
         i < sizeof(identity_methods) / sizeof(identity_methods[0]); i++) {
        const nl_rpc_contract *contract = nl_rpc_contract_lookup(
            NL_DAEMON_IDENTITYD, identity_methods[i].method);

        if (!contract ||
            contract->request_format != NL_RPC_PAYLOAD_BINARY ||
            contract->response_format != NL_RPC_PAYLOAD_BINARY ||
            contract->max_request_len != identity_methods[i].request_size ||
            contract->max_response_len != identity_methods[i].response_size ||
            contract->flags != 0 ||
            contract->access != NL_RPC_ACCESS_INTERNAL)
            return 0;
        for (int caller = (int)NL_DAEMON_INTERNAL;
             caller <= (int)NL_DAEMON_IDENTITYD; caller++) {
            if (nl_rpc_contract_caller_allowed(
                    contract, (nl_daemon_id)caller) !=
                ((nl_daemon_id)caller == NL_DAEMON_CHASSISD))
                return 0;
        }
    }

    const nl_rpc_contract *egress = nl_rpc_contract_lookup(
        NL_DAEMON_SWITCHD, NL_SWITCHD_EGRESS_ACL_COUNTERS_GET);
    const nl_rpc_contract *port_state = nl_rpc_contract_lookup(
        NL_DAEMON_SWITCHD, NL_SWITCHD_PORT_GET_STATE);
    const nl_rpc_contract *reload = nl_rpc_contract_lookup(
        NL_DAEMON_IFD, NL_IFD_RELOAD);
    const nl_rpc_contract *config_set = nl_rpc_contract_lookup(
        NL_DAEMON_CONFIGD, NL_CONFIGD_SET);
    const nl_rpc_contract *guard_arm = nl_rpc_contract_lookup(
        NL_DAEMON_CONFIGD, NL_CONFIGD_PRODUCTION_GUARD_ARM_CHECK);
    const nl_rpc_contract *guard_restore = nl_rpc_contract_lookup(
        NL_DAEMON_CONFIGD, NL_CONFIGD_PRODUCTION_GUARDED_RESTORE_XML);
    const nl_rpc_contract *guard_complete = nl_rpc_contract_lookup(
        NL_DAEMON_CONFIGD, NL_CONFIGD_PRODUCTION_GUARD_COMPLETE_CHECK);
    const nl_rpc_contract *capability_status = nl_rpc_contract_lookup(
        NL_DAEMON_CONFIGD, NL_CONFIGD_PUBLIC_CAPABILITY_STATUS);
    const u8 path_value[] = {'/', 'a', '\0', 'b'};
    const u8 empty_value[] = {'/', 'a', '\0'};
    const u8 path_only[] = {'/', 'a'};
    const u8 empty_path[] = {'\0', 'b'};
    const u8 duplicate_separator[] = {'/', 'a', '\0', 'b', '\0', 'c'};
    const u8 guarded_path_value[] =
        "netlab-config-authority-v1 "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "/a\0b";
    return egress && port_state && reload && config_set &&
           guard_arm && guard_restore && guard_complete && capability_status &&
           config_set->request_format == NL_RPC_PAYLOAD_PATH_VALUE &&
           guard_arm->request_format == NL_RPC_PAYLOAD_TEXT &&
           guard_restore->request_format == NL_RPC_PAYLOAD_TEXT &&
           guard_complete->request_format == NL_RPC_PAYLOAD_TEXT &&
           guard_arm->access == NL_RPC_ACCESS_INTERNAL &&
           guard_restore->access == NL_RPC_ACCESS_INTERNAL &&
           guard_complete->access == NL_RPC_ACCESS_INTERNAL &&
           capability_status->request_format == NL_RPC_PAYLOAD_NONE &&
           capability_status->response_format == NL_RPC_PAYLOAD_TEXT &&
           capability_status->access == NL_RPC_ACCESS_VIEW &&
           (capability_status->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) &&
           nl_rpc_contract_caller_allowed(
               capability_status, NL_DAEMON_MGMTD) &&
           !(guard_arm->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) &&
           !(guard_restore->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) &&
           !(guard_complete->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) &&
           nl_rpc_contract_caller_allowed(
               guard_arm, NL_DAEMON_INTERNAL) &&
           nl_rpc_contract_caller_allowed(
               guard_restore, NL_DAEMON_INTERNAL) &&
           nl_rpc_contract_caller_allowed(
               guard_complete, NL_DAEMON_INTERNAL) &&
           !nl_rpc_contract_caller_allowed(
               guard_arm, NL_DAEMON_MGMTD) &&
           !(egress->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) &&
           !nl_rpc_contract_caller_allowed(egress, NL_DAEMON_MGMTD) &&
           nl_rpc_contract_caller_allowed(port_state, NL_DAEMON_LACPD) &&
           nl_rpc_contract_caller_allowed(reload, NL_DAEMON_CONFIGD) &&
           nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_PATH_VALUE, path_value,
               sizeof(path_value), sizeof(path_value)) &&
           nl_rpc_contract_payload_valid(
               config_set->request_format, guarded_path_value,
               sizeof(guarded_path_value) - 1U,
               config_set->max_request_len) &&
           nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_PATH_VALUE, empty_value,
               sizeof(empty_value), sizeof(empty_value)) &&
           nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_PATH_VALUE, path_only,
               sizeof(path_only), sizeof(path_only)) &&
           !nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_PATH_VALUE, empty_path,
               sizeof(empty_path), sizeof(empty_path)) &&
           !nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_PATH_VALUE, duplicate_separator,
               sizeof(duplicate_separator), sizeof(duplicate_separator)) &&
           !nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_PATH_VALUE, path_value,
               sizeof(path_value), sizeof(path_value) - 1) &&
           !nl_rpc_contract_payload_valid(
               NL_RPC_PAYLOAD_TEXT, (const u8 *)"a\0b", 3, 3);
}

static int deadline_valid(void) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000L};
    u32 remaining;

    nl_rpc_deadline_scope_enter(200);
    nanosleep(&pause, NULL);
    remaining = nl_rpc_effective_timeout_ms(1000);
    if (remaining == 0 || remaining >= 200)
        return 0;
    pause.tv_nsec = 220000000L;
    nanosleep(&pause, NULL);
    if (nl_rpc_effective_timeout_ms(1000) != 0)
        return 0;
    nl_rpc_deadline_scope_leave();
    return nl_rpc_effective_timeout_ms(123) == 123;
}

int main(int argc, char **argv) {
    server_state state = {0};
    pthread_t server;
    nl_rpc_response first = {0};
    nl_rpc_response second = {0};
    const u8 request[24] = {1};
    int first_len;
    int second_len;

    CHECK("socket path provided", argc == 2);
    CHECK("registry is internally consistent", contract_registry_valid());
    CHECK("retired direct LAG create has no IPC contract",
          nl_rpc_contract_lookup(
              NL_DAEMON_SWITCHD,
              NL_SWITCHD_RESERVED_LAG_CREATE) == NULL);
    CHECK("retired lossy MAC table has no IPC contract",
          nl_rpc_contract_lookup(
              NL_DAEMON_SWITCHD,
              NL_SWITCHD_RESERVED_MAC_TABLE_GET) == NULL);
    CHECK("retired lossy STP table has no IPC contract",
          nl_rpc_contract_lookup(
              NL_DAEMON_SWITCHD,
              NL_SWITCHD_RESERVED_STP_STATE_GET) == NULL);
    CHECK("retired single-frame L2 plan builder has no IPC contract",
          nl_rpc_contract_lookup(
              NL_DAEMON_L2D,
              NL_L2D_RESERVED_BUILD_PLAN_V1) == NULL);
    unlink(argv[1]);
    CHECK("server listens", nl_server_listen(argv[1], &state.listen_fd) == NL_OK);
    CHECK("server thread starts",
          pthread_create(&server, NULL, serve, &state) == 0);

    first_len = nl_rpc_call_alloc_ex(
        argv[1], NL_DAEMON_CONFIGD, NL_DAEMON_L2D,
        NL_L2D_BUILD_PLAN_COMMIT, 0,
        request, (int)sizeof(request), 1000, &first);
    second_len = nl_rpc_call_alloc_ex(
        argv[1], NL_DAEMON_CONFIGD, NL_DAEMON_L2D,
        NL_L2D_BUILD_PLAN_COMMIT, 0,
        request, (int)sizeof(request), 1000, &second);
    pthread_join(server, NULL);
    close(state.listen_fd);
    unlink(argv[1]);

    CHECK("dynamic responses preserve full payload",
          first_len == (int)RESPONSE_LEN && second_len == (int)RESPONSE_LEN &&
          first.payload && second.payload &&
          first.payload[RESPONSE_LEN] == 0 && second.payload[RESPONSE_LEN] == 0);
    CHECK("request ids are unique and observable",
          state.ok && first.request_id != 0 && second.request_id != 0 &&
          first.request_id != second.request_id &&
          first.request_id == state.request_ids[0] &&
          second.request_id == state.request_ids[1]);
    CHECK("wire deadlines are populated",
          state.timeout_ms[0] > 0 && state.timeout_ms[1] > 0);
    nl_rpc_response_free(&first);
    nl_rpc_response_free(&second);
    CHECK("deadline scope clamps and expires", deadline_valid());
    return 0;
}
'''

    with tempfile.TemporaryDirectory() as directory:
        directory_path = Path(directory)
        source_path = directory_path / "ipc_contract_registry.c"
        executable = directory_path / "ipc_contract_registry"
        socket_path = directory_path / "registry.sock"
        source_path.write_text(source, encoding="utf-8")
        build = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE", "-I", str(ROOT / "include"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "libipc" / "ipc_contract.c"),
                str(ROOT / "lib" / "libipc" / "rpc_client.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(source_path), "-lpthread", "-o", str(executable),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            return check("typed IPC C contract builds", False, build.stdout)
        run = subprocess.run(
            [str(executable), str(socket_path)],
            cwd=ROOT,
            env={**os.environ, "LC_ALL": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        return check(
            "typed IPC registry, allocation, identity, and deadline hold",
            run.returncode == 0,
            run.stdout,
        )


def test_mgmtd_backend_socket_overrides() -> int:
    source = r'''
#include "mgmtd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

typedef struct {
    nl_daemon_id daemon;
    const char *environment;
    const char *path;
} override_case;

static const mgmtd_backend_info *find_backend(nl_daemon_id daemon) {
    for (size_t i = 0; i < mgmtd_backend_count(); i++) {
        const mgmtd_backend_info *backend = mgmtd_backend_at(i);

        if (backend && backend->daemon_id == daemon)
            return backend;
    }
    return NULL;
}

int main(void) {
    static const override_case cases[] = {
        {NL_DAEMON_CONFIGD, "NETLAB_CONFIGD_SOCKET",
         "/tmp/netlab-route-configd.sock"},
        {NL_DAEMON_IFD, "NETLAB_IFD_SOCKET",
         "/tmp/netlab-route-ifd.sock"},
        {NL_DAEMON_CHASSISD, "NETLAB_CHASSISD_SOCKET",
         "/tmp/netlab-route-chassisd.sock"},
        {NL_DAEMON_SWITCHD, "NETLAB_SWITCHD_SOCKET",
         "/tmp/netlab-route-switchd.sock"},
        {NL_DAEMON_PACKETD, "NETLAB_PACKETD_SOCKET",
         "/tmp/netlab-route-packetd.sock"},
        {NL_DAEMON_LLDPD, "NETLAB_LLDPD_SOCKET",
         "/tmp/netlab-route-lldpd.sock"},
        {NL_DAEMON_LACPD, "NETLAB_LACPD_SOCKET",
         "/tmp/netlab-route-lacpd.sock"},
        {NL_DAEMON_LINKMOND, "NETLAB_LINKMOND_SOCKET",
         "/tmp/netlab-route-linkmond.sock"},
        {NL_DAEMON_L2D, "NETLAB_L2D_SOCKET",
         "/tmp/netlab-route-l2d.sock"},
        {NL_DAEMON_RPD, "NETLAB_RPD_SOCKET",
         "/tmp/netlab-route-rpd.sock"},
        {NL_DAEMON_STATSD, "NETLAB_STATSD_SOCKET",
         "/tmp/netlab-route-statsd.sock"},
        {NL_DAEMON_STPD, "NETLAB_STPD_SOCKET",
         "/tmp/netlab-route-stpd.sock"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const mgmtd_backend_info *backend = find_backend(cases[i].daemon);

        CHECK("backend exists", backend != NULL);
        CHECK("override installs",
              setenv(cases[i].environment, cases[i].path, 1) == 0);
        CHECK("backend consumes its isolated socket override",
              strcmp(mgmtd_backend_socket_path(backend), cases[i].path) == 0);
    }
    CHECK("xcvrd virtual route shares the switchd override",
          strcmp(mgmtd_backend_socket_path(find_backend(NL_DAEMON_XCVRD)),
                 "/tmp/netlab-route-switchd.sock") == 0);
    CHECK("unsafe override fails closed to the compiled route",
          setenv("NETLAB_IFD_SOCKET", "relative.sock", 1) == 0 &&
          strcmp(mgmtd_backend_socket_path(find_backend(NL_DAEMON_IFD)),
                 "/var/run/netlab/ifd.sock") == 0);
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as directory:
        source_path = Path(directory) / "mgmtd_socket_overrides.c"
        executable = Path(directory) / "mgmtd_socket_overrides"
        source_path.write_text(source, encoding="utf-8")
        build = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin" / "mgmtd"),
                str(ROOT / "sbin" / "mgmtd" / "routes.c"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "libipc" / "ipc_contract.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(source_path), "-lpthread", "-o", str(executable),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            return check(
                "mgmtd isolated backend override contract builds",
                False, build.stdout)
        run = subprocess.run(
            [str(executable)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        return check(
            "mgmtd routes every isolated backend through an explicit override",
            run.returncode == 0,
            run.stdout,
        )


def test_source_contracts() -> int:
    failed = 0
    contract_header = (ROOT / "include" / "netlab" /
                       "ipc_contract.h").read_text(encoding="utf-8")
    identity_header = (ROOT / "include" / "netlab" /
                       "identity_broker.h").read_text(encoding="utf-8")
    contract_source = (ROOT / "lib" / "libipc" /
                       "ipc_contract.c").read_text(encoding="utf-8")
    sources: list[Path] = []
    for root_name in ("lib", "sbin", "tools"):
        sources.extend((ROOT / root_name).rglob("*.c"))
    client_sources = [
        path for path in sources
        if path != ROOT / "lib" / "libipc" / "rpc_client.c"
    ]
    combined = "\n".join(path.read_text(encoding="utf-8")
                           for path in client_sources)
    raw_method = re.compile(
        r"nl_rpc_call_(?:alloc_)?ex\s*\("
        r"\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[0-9]+\s*,",
        re.DOTALL,
    )
    old_api = re.compile(r"\bnl_rpc_call\s*\(")
    switchd = (ROOT / "sbin" / "switchd" / "rpc_server.c").read_text(
        encoding="utf-8")
    dispatch = switchd.split("switch (msg->method)", 1)[1]
    daemon = (ROOT / "lib" / "libdaemon" / "daemon.c").read_text(
        encoding="utf-8")
    routes = (ROOT / "sbin" / "mgmtd" / "routes.c").read_text(
        encoding="utf-8")
    backend = (ROOT / "sbin" / "mgmtd" / "backend.c").read_text(
        encoding="utf-8")
    rpc_client = (ROOT / "lib" / "libipc" / "rpc_client.c").read_text(
        encoding="utf-8")
    l2_client = (ROOT / "sbin" / "configd" / "l2_client.c").read_text(
        encoding="utf-8")

    method_blocks = re.findall(
        r"enum nl_[a-z0-9_]+_method\s*\{(.*?)\};",
        contract_header + "\n" + identity_header,
        re.DOTALL,
    )
    named_methods = {
        name
        for block in method_blocks
        for name in re.findall(r"\b(NL_[A-Z0-9_]+)\s*=", block)
    }
    reserved_methods = {
        "NL_SWITCHD_RESERVED_LAG_CREATE",
        "NL_SWITCHD_RESERVED_MAC_TABLE_GET",
        "NL_SWITCHD_RESERVED_STP_STATE_GET",
        "NL_L2D_RESERVED_BUILD_PLAN_V1",
    }
    registered_methods = set(re.findall(
        r"\bC(?:I)?\s*\(\s*NL_DAEMON_[A-Z0-9_]+\s*,\s*"
        r"(NL_[A-Z0-9_]+)\b",
        contract_source,
    ))

    failed += check("every active named method has exactly one registry contract",
                    reserved_methods <= named_methods and
                    reserved_methods.isdisjoint(registered_methods) and
                    named_methods - reserved_methods == registered_methods and
                    len(named_methods - reserved_methods) ==
                    len(registered_methods),
                    "missing={} extra={}".format(
                        sorted(named_methods - reserved_methods -
                               registered_methods),
                        sorted(registered_methods -
                               (named_methods - reserved_methods)),
                    ))
    failed += check("C clients no longer use the untyped RPC API",
                    old_api.search(combined) is None)
    failed += check("C client call sites use named method constants",
                    raw_method.search(combined) is None,
                    raw_method.search(combined).group(0)
                    if raw_method.search(combined) else "")
    internal_callers = {
        str(path.relative_to(ROOT))
        for path in client_sources
        if "nl_rpc_call" in path.read_text(encoding="utf-8")
        and "NL_DAEMON_INTERNAL" in path.read_text(encoding="utf-8")
    }
    failed += check(
        "sealed helper is the sole C INTERNAL transport authority",
        internal_callers == {"tools/internal-rpc/main.c"},
        repr(sorted(internal_callers)),
    )
    failed += check("switchd dispatch uses named method constants",
                    re.search(r"msg->method\s*==\s*[0-9]+", switchd) is None and
                    re.search(r"^\s*case\s+[0-9]+\s*:", dispatch,
                              re.MULTILINE) is None)
    failed += check("common daemon ingress owns typed caller authorization",
                    "nl_rpc_contract_lookup" in daemon and
                    "nl_rpc_contract_payload_valid" in daemon and
                    "nl_rpc_contract_caller_allowed" in daemon and
                    "daemon_verify_standard_peer" in daemon)
    failed += check("switchd has no duplicate caller policy path",
                    not (ROOT / "sbin" / "switchd" /
                         "rpc_policy.c").exists() and
                    not (ROOT / "sbin" / "switchd" /
                         "rpc_policy.h").exists() and
                    "nl_rpc_contract_caller_allowed" not in switchd)
    failed += check("mgmtd routes derive exposure from the registry",
                    "NL_RPC_CONTRACT_MGMT_EXPOSED" in routes and
                    "nl_rpc_contract_lookup" in routes and
                    "static const u16 view" not in routes)
    failed += check("xcvrd virtual routing cannot alias other switchd methods",
                    "method != NL_SWITCHD_XCVR_INFO_GET" in routes and
                    "contract_service = NL_DAEMON_SWITCHD" in routes)
    failed += check("mgmtd forwards its real identity and remaining deadline",
                    "forwarded->daemon_id = NL_DAEMON_MGMTD" in backend and
                    "forwarded->timeout_ms = timeout_ms" in backend and
                    "nl_rpc_effective_timeout_ms" in backend)
    failed += check("RPC client generates ids and writes wire timeout",
                    "nl_rpc_next_request_id()" in rpc_client and
                    "msg->request_id = request_id" in rpc_client and
                    "msg->timeout_ms = effective_timeout" in rpc_client and
                    "request_id = 1" not in rpc_client)
    failed += check("a variable-size production consumer uses allocation API",
                    "nl_rpc_call_alloc_ex" in l2_client and
                    "NL_L2_PLAN_MAX_BYTES + 256" not in l2_client)
    return failed


def main() -> int:
    failed = test_compiled_registry_and_client()
    failed += test_mgmtd_backend_socket_overrides()
    failed += test_source_contracts()
    print(f"\nResults: {'all passed' if failed == 0 else str(failed) + ' failed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
