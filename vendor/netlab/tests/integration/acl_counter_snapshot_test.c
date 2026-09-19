#include "netlab/acl_counter_snapshot.h"
#include "netlab/ipc.h"
#include "sbin/l2d/l2d_switchd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum mock_mode {
    MOCK_OK,
    MOCK_MALFORMED,
    MOCK_INCOMPLETE,
    MOCK_TIMEOUT,
};

static enum mock_mode g_mode;
static int g_calls;

static void fail_at(const char *file, int line, const char *expr) {
    fprintf(stderr, "%s:%d: check failed: %s\n", file, line, expr);
    exit(1);
}

#define CHECK(expr) do { \
    if (!(expr)) \
        fail_at(__FILE__, __LINE__, #expr); \
} while (0)

static void fill_query(nl_acl_counter_query *query, u16 count) {
    memset(query, 0, sizeof(*query));
    query->n_entries = count;
    for (u16 i = 0; i < count; i++) {
        nl_acl_counter_query_entry *entry = &query->entries[i];

        entry->id = i;
        if (i < 64) {
            entry->kind = NL_ACL_COUNTER_KIND_USER_FILTER;
            entry->mac_kind = NL_ACL_COUNTER_MAC_SOURCE;
            entry->match.vid = (u16)(100 + i);
            entry->match.port = 1;
            entry->mac[0] = 0x02;
            entry->mac[5] = (u8)(i + 1);
        } else if (i < 128) {
            entry->kind = NL_ACL_COUNTER_KIND_INGRESS_IPV4;
            entry->match.vid = (u16)(200 + i);
            entry->match.port = 2;
            entry->match.flags = NL_ACL_COUNTER_MATCH_PROTOCOL;
            entry->match.protocol = 1;
        } else if (i < 136) {
            entry->kind = NL_ACL_COUNTER_KIND_EGRESS;
            entry->match.port = (u16)(i - 127);
        } else if (i < 144) {
            entry->kind = NL_ACL_COUNTER_KIND_POLICER;
            entry->match.port = (u16)(i - 135);
            entry->dst_mac = 0x020000000001ULL + i;
            entry->rate_kbps = 1000;
            entry->burst_bytes = 65536;
        } else {
            entry->kind = NL_ACL_COUNTER_KIND_INDEPENDENT;
            entry->family = NL_ACL_COUNTER_FAMILY_ETHERNET;
            entry->action = NL_ACL_COUNTER_ACTION_DROP;
            entry->slot = i - 144;
            entry->match.vid = (u16)(300 + i);
            entry->match.port = 3;
            entry->match.flags = NL_ACL_COUNTER_MATCH_SRC_MAC;
            entry->src_mac = 0x020000001000ULL + i;
        }
    }
    CHECK(nl_acl_counter_query_validate(query) == 0);
}

int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller,
                   nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                   const u8 *payload, int payload_len,
                   u8 *resp_buf, int max_resp, int timeout_ms,
                   s32 *error_code) {
    nl_acl_counter_query query;
    nl_acl_counter_snapshot snapshot;
    int encoded;

    (void)tx_id;
    CHECK(socket_path != NULL);
    CHECK(caller == NL_DAEMON_L2D);
    CHECK(service == NL_DAEMON_SWITCHD);
    CHECK(method == NL_SWITCHD_ACL_COUNTER_SNAPSHOT_GET);
    CHECK(timeout_ms == 10000);
    g_calls++;
    if (error_code)
        *error_code = 0;
    if (g_mode == MOCK_TIMEOUT)
        return -1;
    CHECK(nl_acl_counter_query_decode(
              payload, (size_t)payload_len, &query) == 0);
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.complete = true;
    snapshot.generation = 9;
    snapshot.sampled_monotonic_ms = 1234;
    snapshot.n_entries = query.n_entries;
    for (u16 i = 0; i < query.n_entries; i++) {
        snapshot.entries[i].id = query.entries[i].id;
        snapshot.entries[i].kind = query.entries[i].kind;
        snapshot.entries[i].state = NL_ACL_COUNTER_STATE_ABSENT;
    }
    encoded = nl_acl_counter_snapshot_encode(
        &snapshot, resp_buf, (size_t)max_resp);
    CHECK(encoded > 0);
    if (g_mode == MOCK_MALFORMED)
        resp_buf[0] ^= 0xff;
    if (g_mode == MOCK_INCOMPLETE)
        resp_buf[15] = 0;
    return encoded;
}

static void test_codec_boundaries(void) {
    static const u16 counts[] = {0, 64, 176};
    nl_acl_counter_query query;
    nl_acl_counter_query decoded_query;
    nl_acl_counter_snapshot snapshot;
    nl_acl_counter_snapshot decoded_snapshot;
    u8 *wire = malloc(65536);

    CHECK(wire != NULL);
    for (size_t ci = 0; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
        int n;

        fill_query(&query, counts[ci]);
        n = nl_acl_counter_query_encode(&query, wire, 65536);
        CHECK(n == (int)nl_acl_counter_query_wire_size(counts[ci]));
        memset(&decoded_query, 0, sizeof(decoded_query));
        CHECK(nl_acl_counter_query_decode(
                  wire, (size_t)n, &decoded_query) == 0);
        CHECK(decoded_query.n_entries == counts[ci]);

        memset(&snapshot, 0, sizeof(snapshot));
        snapshot.complete = true;
        snapshot.generation = 7;
        snapshot.sampled_monotonic_ms = 8;
        snapshot.n_entries = counts[ci];
        for (u16 i = 0; i < counts[ci]; i++) {
            snapshot.entries[i].id = i;
            snapshot.entries[i].kind = query.entries[i].kind;
            snapshot.entries[i].state = NL_ACL_COUNTER_STATE_INSTALLED;
            snapshot.entries[i].packets = i;
            snapshot.entries[i].octets = (u64)i * 64;
        }
        n = nl_acl_counter_snapshot_encode(&snapshot, wire, 65536);
        CHECK(n == (int)nl_acl_counter_snapshot_wire_size(counts[ci]));
        memset(&decoded_snapshot, 0, sizeof(decoded_snapshot));
        CHECK(nl_acl_counter_snapshot_decode(
                  wire, (size_t)n, &decoded_snapshot) == 0);
        CHECK(decoded_snapshot.n_entries == counts[ci]);
        CHECK(decoded_snapshot.complete);
    }

    fill_query(&query, 1);
    int n = nl_acl_counter_query_encode(&query, wire, 65536);
    CHECK(n > 0);
    wire[16 + 112] = 1;
    CHECK(nl_acl_counter_query_decode(wire, (size_t)n, &decoded_query) != 0);
    n = nl_acl_counter_query_encode(&query, wire, 65536);
    CHECK(n > 0);
    wire[16 + 23] = 1;
    CHECK(nl_acl_counter_query_decode(wire, (size_t)n, &decoded_query) != 0);
    free(wire);
}

static void test_single_rpc_and_failure_atomicity(void) {
    static const u16 counts[] = {0, 64, 176};
    nl_acl_counter_query query;
    nl_acl_counter_snapshot snapshot;

    for (size_t ci = 0; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
        fill_query(&query, counts[ci]);
        memset(&snapshot, 0, sizeof(snapshot));
        g_mode = MOCK_OK;
        g_calls = 0;
        CHECK(l2d_switchd_get_acl_counter_snapshot(
                  "/tmp/mock", &query, &snapshot) == 0);
        CHECK(g_calls == 1);
        CHECK(snapshot.complete);
        CHECK(snapshot.n_entries == counts[ci]);
    }

    fill_query(&query, 176);
    for (g_mode = MOCK_MALFORMED; g_mode <= MOCK_TIMEOUT; g_mode++) {
        memset(&snapshot, 0xa5, sizeof(snapshot));
        g_calls = 0;
        CHECK(l2d_switchd_get_acl_counter_snapshot(
                  "/tmp/mock", &query, &snapshot) != 0);
        CHECK(g_calls == 1);
        CHECK(!snapshot.complete);
        CHECK(snapshot.generation == 0);
        CHECK(snapshot.n_entries == 0);
    }
}

int main(void) {
    test_codec_boundaries();
    test_single_rpc_and_failure_atomicity();
    puts("acl-counter-snapshot: PASS");
    return 0;
}
