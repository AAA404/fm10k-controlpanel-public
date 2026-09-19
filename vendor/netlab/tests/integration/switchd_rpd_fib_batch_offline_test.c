#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool g_lookup_owner_applied;
static bool g_lookup_map_all;
static int g_dynamic_apply_calls;
static int g_dynamic_readback_calls;
static int g_dynamic_last_sw;
static int g_dynamic_last_routes;
static int g_dynamic_last_nexthops;
static bool g_dynamic_last_enabled;
static u64 g_dynamic_last_tx_id;
static bool g_dynamic_fail_next_apply;
static int g_dynamic_fail_apply_call;

bool nl_ifid_name_is_user_port(const char *name) {
    return name && strncmp(name, "et-", 3) == 0;
}

int hal_l3_persistent_owner_lookup_next_hop(
        const char *table, const char *ip, const char *rif,
        hal_l3_persistent_next_hop_ref *ref) {
    if (!table || !ip || !rif || !ref)
        return -1;
    memset(ref, 0, sizeof(*ref));
    ref->owner_applied = g_lookup_owner_applied;
    ref->found = g_lookup_owner_applied && g_lookup_map_all;
    ref->next_hop_id = ref->found ? 101 : -1;
    ref->rif_index = ref->found ? 7 : -1;
    ref->vlan = ref->found ? 100 : 0;
    snprintf(ref->ip, sizeof(ref->ip), "%s", ip);
    snprintf(ref->rif, sizeof(ref->rif), "%s", rif);
    snprintf(ref->table, sizeof(ref->table), "%s", table);
    ref->vrid = strcmp(table, "inet.0") == 0 ? 0 : 1;
    snprintf(ref->interface_addr, sizeof(ref->interface_addr), "%s",
             ref->found ? "192.0.2.1/24" : "");
    return 0;
}

int hal_l3_persistent_owner_lookup_table(const char *table, int *vrid) {
    if (!table || !vrid)
        return -1;
    if (strcmp(table, "inet.0") == 0) {
        *vrid = 0;
        return 0;
    }
    if (strcmp(table, "blue.inet.0") == 0) {
        *vrid = 1;
        return 0;
    }
    return -1;
}

int hal_l3_intent_probe(const hal_l3_intent_plan *plan, char *resp,
                        size_t resp_size) {
    (void)plan;
    snprintf(resp, resp_size, "<stub/>");
    return 0;
}

int hal_l3_intent_sdk_preflight(const hal_l3_intent_plan *plan, char *resp,
                                size_t resp_size) {
    (void)plan;
    snprintf(resp, resp_size, "<stub/>");
    return 0;
}

int hal_l3_sdk_readback_probe(int sw, char *resp, size_t resp_size) {
    (void)sw;
    snprintf(resp, resp_size, "<stub/>");
    return 0;
}

int hal_l3_sdk_owner_verify(int sw, const hal_l3_intent_plan *expected,
                            char *resp, size_t resp_size) {
    (void)sw;
    (void)expected;
    snprintf(resp, resp_size, "<stub/>");
    return 0;
}

int hal_l3_rif_live_probe(int sw, const hal_l3_intent_plan *plan,
                          bool acknowledged, u64 tx_id, char *resp,
                          size_t resp_size) {
    (void)sw;
    (void)plan;
    (void)acknowledged;
    (void)tx_id;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_arp_live_probe(int sw, const hal_l3_intent_plan *plan,
                          bool acknowledged, u64 tx_id, char *resp,
                          size_t resp_size) {
    (void)sw;
    (void)plan;
    (void)acknowledged;
    (void)tx_id;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_ecmp_live_probe(int sw, const hal_l3_intent_plan *plan,
                           bool acknowledged, u64 tx_id, char *resp,
                           size_t resp_size) {
    (void)sw;
    (void)plan;
    (void)acknowledged;
    (void)tx_id;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_route_live_probe(int sw, const hal_l3_intent_plan *plan,
                            bool acknowledged, u64 tx_id, int hold_sec,
                            const char *router_mac_text,
                            char *resp, size_t resp_size) {
    (void)sw;
    (void)plan;
    (void)acknowledged;
    (void)tx_id;
    (void)hold_sec;
    (void)router_mac_text;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_persistent_owner_apply(int sw, const hal_l3_intent_plan *plan,
                                  bool acknowledged, u64 tx_id,
                                  char *resp, size_t resp_size) {
    (void)sw;
    (void)plan;
    (void)acknowledged;
    (void)tx_id;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_persistent_owner_readback(int sw, char *resp, size_t resp_size) {
    (void)sw;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_persistent_owner_rollback(int sw, bool acknowledged, u64 tx_id,
                                     char *resp, size_t resp_size) {
    (void)sw;
    (void)acknowledged;
    (void)tx_id;
    snprintf(resp, resp_size, "<stub/>");
    return -1;
}

int hal_l3_dynamic_fib_owner_apply(int sw,
                                   const hal_l3_dynamic_fib_plan *plan,
                                   bool enabled, u64 tx_id,
                                   char *resp, size_t resp_size) {
    int nexthops = 0;

    g_dynamic_apply_calls++;
    g_dynamic_last_sw = sw;
    g_dynamic_last_enabled = enabled;
    g_dynamic_last_tx_id = tx_id;
    g_dynamic_last_routes = plan ? plan->n_routes : -1;
    if (plan) {
        for (int i = 0; i < plan->n_routes; i++)
            nexthops += plan->routes[i].n_nexthops;
    }
    g_dynamic_last_nexthops = nexthops;
    if (g_dynamic_fail_next_apply ||
        (g_dynamic_fail_apply_call > 0 &&
         g_dynamic_apply_calls == g_dynamic_fail_apply_call)) {
        g_dynamic_fail_next_apply = false;
        g_dynamic_fail_apply_call = 0;
        snprintf(resp, resp_size,
                 "<fib-live-owner status=\"error\" source=\"switchd\" "
                 "owner=\"rpd\" hardware-apply=\"dynamic\" "
                 "sdk-write=\"live\" reason=\"injected failure\"/>");
        return -1;
    }
    snprintf(resp, resp_size,
             "<fib-live-owner status=\"ok\" source=\"switchd\" "
             "owner=\"rpd\" hardware-apply=\"dynamic\" "
             "sdk-write=\"live\" sdk-readback=\"live\" tx-id=\"%llu\" "
             "routes=\"%d\" nexthops=\"%d\" enabled=\"%s\"/>",
             (unsigned long long)tx_id, g_dynamic_last_routes,
             g_dynamic_last_nexthops, enabled ? "true" : "false");
    return 0;
}

int hal_l3_dynamic_fib_owner_readback(int sw, char *resp,
                                      size_t resp_size) {
    g_dynamic_readback_calls++;
    g_dynamic_last_sw = sw;
    snprintf(resp, resp_size,
             "<fib-live-owner-readback status=\"empty\" source=\"switchd\" "
             "owner=\"rpd\" hardware-apply=\"dynamic\" "
             "sdk-write=\"disabled\" sdk-readback=\"live\"/>");
    return 0;
}

int hal_l3_dynamic_fib_owner_rollback(int sw, bool enabled, u64 tx_id,
                                      char *resp, size_t resp_size) {
    (void)sw;
    (void)enabled;
    (void)tx_id;
    snprintf(resp, resp_size, "<fib-live-owner-rollback status=\"stub\"/>");
    return 0;
}

#include "../../sbin/switchd/l3_plan_parser.c"

static void reset_fib_test_state(void) {
    for (int slot = 0; slot < L3_FIB_OWNER_SLOTS; slot++) {
        if (g_l3_fib_owner[slot].pre !=
            g_l3_fib_owner[slot].current)
            free(g_l3_fib_owner[slot].pre);
        free(g_l3_fib_owner[slot].current);
        fib_snapshot_stage_reset(&g_l3_fib_snapshot[slot]);
    }
    memset(g_l3_fib_owner, 0, sizeof(g_l3_fib_owner));
    memset(g_l3_fib_snapshot, 0, sizeof(g_l3_fib_snapshot));
}

static void reset_l3_tx_test_state(void) {
    if (g_l3_tx_owner.pre != g_l3_tx_owner.current)
        free(g_l3_tx_owner.pre);
    free(g_l3_tx_owner.current);
    memset(&g_l3_tx_owner, 0, sizeof(g_l3_tx_owner));
}

static int check_contains(const char *name, const char *body,
                          const char *needle) {
    if (strstr(body, needle)) {
        printf("PASS: %s\n", name);
        return 0;
    }
    printf("FAIL: %s missing %s\n%s\n", name, needle, body);
    return 1;
}

static int check_absent(const char *name, const char *body,
                        const char *needle) {
    if (!strstr(body, needle)) {
        printf("PASS: %s\n", name);
        return 0;
    }
    printf("FAIL: %s unexpectedly found %s\n%s\n", name, needle, body);
    return 1;
}

static char *build_scale_batch(int routes) {
    size_t size = 128 + (size_t)routes * 320;
    char *buf = malloc(size);
    size_t off;

    if (!buf)
        return NULL;
    off = (size_t)snprintf(buf, size,
                           "fib-batch table=inet.0 generation=4096 "
                           "fib-update-id=4096\n");
    if (off >= size) {
        free(buf);
        return NULL;
    }
    for (int i = 0; i < routes; i++) {
        int second = 64 + (i / 256);
        int third = i % 256;
        int n = snprintf(
            buf + off, size - off,
            "fib-route op=replace prefix=10.%d.%d.0/24 protocol=bgp "
            "preference=170 metric=%d nexthops=192.0.2.2@irb.100 "
            "egress-rif=irb.100 installed-state=pending-fib "
            "route-generation=4096 fib-update-id=4096 "
            "owner-role=dynamic-fib\n",
            second, third, i);

        if (n < 0 || (size_t)n >= size - off) {
            free(buf);
            return NULL;
        }
        off += (size_t)n;
    }
    return buf;
}

static char *build_wide_nexthop_batch(void) {
    char *buf = calloc(1, 4096);
    size_t off;

    if (!buf)
        return NULL;
    off = (size_t)snprintf(
        buf, 4096,
        "fib-batch table=inet.0 generation=4096 fib-update-id=4096\n"
        "fib-route op=replace prefix=10.0.0.0/24 protocol=bgp "
        "preference=170 metric=1 nexthops=");
    for (int i = 0; i < L3_FIB_MAX_NEXTHOPS; i++) {
        char rif[64];
        int n;

        memset(rif, 'a', sizeof(rif) - 1);
        rif[sizeof(rif) - 2] = (char)('A' + i);
        rif[sizeof(rif) - 1] = '\0';
        n = snprintf(buf + off, 4096 - off, "%s192.0.2.%d@%s",
                     i == 0 ? "" : ",", i + 1, rif);
        if (n < 0 || (size_t)n >= 4096 - off) {
            free(buf);
            return NULL;
        }
        off += (size_t)n;
    }
    if (snprintf(buf + off, 4096 - off,
                 " egress-rif=irb.100 installed-state=pending-fib "
                 "route-generation=4096 fib-update-id=4096 "
                 "owner-role=dynamic-fib\n") >= (int)(4096 - off)) {
        free(buf);
        return NULL;
    }
    return buf;
}

#define TEST_SNAPSHOT_MAX_PARTS 512

typedef struct {
    const char *payload;
    size_t bytes;
    size_t offsets[TEST_SNAPSHOT_MAX_PARTS];
    size_t spans[TEST_SNAPSHOT_MAX_PARTS];
    int part_routes[TEST_SNAPSHOT_MAX_PARTS];
    int routes;
    int parts;
    u64 digest;
} snapshot_fixture;

static u64 test_snapshot_digest(const char *data, size_t length) {
    u64 digest = L3_FIB_SNAPSHOT_DIGEST_INIT;

    for (size_t i = 0; i < length; i++) {
        digest ^= (u8)data[i];
        digest *= L3_FIB_SNAPSHOT_DIGEST_PRIME;
    }
    return digest;
}

static int snapshot_fixture_prepare(snapshot_fixture *fixture,
                                    const char *payload, int routes,
                                    size_t part_limit) {
    size_t offset = 0;
    int counted_routes = 0;

    if (!fixture || !payload || routes < 0 || part_limit == 0 ||
        part_limit > L3_FIB_SNAPSHOT_PART_MAX_BYTES)
        return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->payload = payload;
    fixture->bytes = strlen(payload);
    fixture->routes = routes;
    fixture->digest = test_snapshot_digest(payload, fixture->bytes);
    while (offset < fixture->bytes) {
        size_t span = fixture->bytes - offset;
        size_t cursor = 0;
        int part_routes = 0;

        if (fixture->parts >= TEST_SNAPSHOT_MAX_PARTS)
            return -1;
        if (span > part_limit) {
            span = part_limit;
            while (span > 0 && payload[offset + span - 1] != '\n')
                span--;
        }
        if (span == 0 || payload[offset + span - 1] != '\n')
            return -1;
        while (cursor < span) {
            const char *line = payload + offset + cursor;
            const char *newline = memchr(line, '\n', span - cursor);
            size_t line_len;

            if (!newline)
                return -1;
            line_len = (size_t)(newline - line);
            if (line_len >= 10 && memcmp(line, "fib-route ", 10) == 0)
                part_routes++;
            cursor += line_len + 1;
        }
        fixture->offsets[fixture->parts] = offset;
        fixture->spans[fixture->parts] = span;
        fixture->part_routes[fixture->parts] = part_routes;
        fixture->parts++;
        counted_routes += part_routes;
        offset += span;
    }
    return fixture->parts > 0 && counted_routes == routes ? 0 : -1;
}

static int snapshot_control(const snapshot_fixture *fixture,
                            const char *operation, u64 tx_id,
                            char *resp, size_t resp_size) {
    char request[512];
    int n;

    n = snprintf(request, sizeof(request),
                 "fib-snapshot-%s table=inet.0 generation=4096 "
                 "fib-update-id=4096 routes=%d parts=%d bytes=%llu "
                 "digest=%llu",
                 operation, fixture->routes, fixture->parts,
                 (unsigned long long)fixture->bytes,
                 (unsigned long long)fixture->digest);
    if (n < 0 || (size_t)n >= sizeof(request))
        return -1;
    if (strcmp(operation, "begin") == 0)
        return l3_fib_snapshot_begin(request, tx_id, resp, resp_size);
    if (strcmp(operation, "commit") == 0)
        return l3_fib_snapshot_commit(0, request, tx_id, resp, resp_size);
    if (strcmp(operation, "abort") == 0)
        return l3_fib_snapshot_abort(request, tx_id, resp, resp_size);
    return -1;
}

static int snapshot_send_part(const snapshot_fixture *fixture, int part,
                              u64 tx_id, char *resp, size_t resp_size) {
    char *request;
    size_t request_size;
    int header_len;
    int rc;

    if (!fixture || part < 0 || part >= fixture->parts)
        return -1;
    request_size = fixture->spans[part] + 1024u;
    request = malloc(request_size);
    if (!request)
        return -1;
    header_len = snprintf(
        request, request_size,
        "fib-snapshot-part table=inet.0 generation=4096 "
        "fib-update-id=4096 routes=%d parts=%d bytes=%llu digest=%llu "
        "part=%d offset=%llu part-bytes=%llu part-routes=%d\n",
        fixture->routes, fixture->parts,
        (unsigned long long)fixture->bytes,
        (unsigned long long)fixture->digest, part,
        (unsigned long long)fixture->offsets[part],
        (unsigned long long)fixture->spans[part],
        fixture->part_routes[part]);
    if (header_len < 0 ||
        (size_t)header_len + fixture->spans[part] >= request_size) {
        free(request);
        return -1;
    }
    memcpy(request + header_len,
           fixture->payload + fixture->offsets[part],
           fixture->spans[part]);
    request[header_len + fixture->spans[part]] = '\0';
    rc = l3_fib_snapshot_part(request, tx_id, resp, resp_size);
    free(request);
    return rc;
}

static int snapshot_apply(const snapshot_fixture *fixture, u64 tx_id,
                          char *resp, size_t resp_size) {
    if (snapshot_control(fixture, "begin", tx_id, resp, resp_size) != 0)
        return -1;
    for (int part = 0; part < fixture->parts; part++)
        if (snapshot_send_part(fixture, part, tx_id,
                               resp, resp_size) != 0)
            return -1;
    return snapshot_control(fixture, "commit", tx_id, resp, resp_size);
}

static int run_snapshot_tests(void) {
    static const int scales[] = {1, 128, 512, 1024, 4096};
    char resp[65536];
    char *payloads[5] = {0};
    snapshot_fixture fixtures[5];
    char *wide = NULL;
    int failed = 0;

    unsetenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY");
    reset_fib_test_state();
    for (size_t i = 0; i < sizeof(scales) / sizeof(scales[0]); i++) {
        char name[96];

        payloads[i] = build_scale_batch(scales[i]);
        if (!payloads[i] ||
            snapshot_fixture_prepare(&fixtures[i], payloads[i], scales[i],
                                     L3_FIB_SNAPSHOT_PART_MAX_BYTES) != 0 ||
            snapshot_apply(&fixtures[i], 5000 + i,
                           resp, sizeof(resp)) != 0) {
            printf("FAIL: %d-route typed snapshot applies\n%s\n",
                   scales[i], resp);
            failed++;
            continue;
        }
        snprintf(name, sizeof(name), "%d-route typed snapshot applies",
                 scales[i]);
        failed += check_contains(name, resp,
                                 "<fib-snapshot-commit status=\"ok\"");
        snprintf(name, sizeof(name), "%d-route typed snapshot route count",
                 scales[i]);
        {
            char expected[32];

            snprintf(expected, sizeof(expected), "routes=\"%d\"",
                     scales[i]);
            failed += check_contains(name, resp, expected);
        }
    }

    wide = build_wide_nexthop_batch();
    if (wide) {
        snapshot_fixture wide_fixture;
        l3_fib_state *pre_before_retry;
        l3_fib_state *current_before_retry;

        if (snapshot_fixture_prepare(&wide_fixture, wide, 1,
                                     L3_FIB_SNAPSHOT_PART_MAX_BYTES) != 0 ||
            snapshot_apply(&wide_fixture, 5500, resp, sizeof(resp)) != 0 ||
            !g_l3_fib_owner[0].current ||
            g_l3_fib_owner[0].current->routes[0].n_nexthops !=
                L3_FIB_MAX_NEXTHOPS) {
            printf("FAIL: 16 long nexthops survive typed snapshot\n%s\n",
                   resp);
            failed++;
        } else {
            printf("PASS: 16 long nexthops survive typed snapshot\n");
            pre_before_retry = g_l3_fib_owner[0].pre;
            current_before_retry = g_l3_fib_owner[0].current;
            if (snapshot_apply(&wide_fixture, 5500,
                               resp, sizeof(resp)) != 0 ||
                g_l3_fib_owner[0].pre != pre_before_retry ||
                g_l3_fib_owner[0].current != current_before_retry ||
                !strstr(resp, "idempotent switchd rpd FIB retry")) {
                printf("FAIL: identical snapshot retry preserves rollback "
                       "authority\n%s\n", resp);
                failed++;
            } else {
                printf("PASS: identical snapshot retry preserves rollback "
                       "authority\n");
            }
            if (payloads[0] &&
                (snapshot_apply(&fixtures[0], 5500,
                                resp, sizeof(resp)) == 0 ||
                 g_l3_fib_owner[0].pre != pre_before_retry ||
                 g_l3_fib_owner[0].current != current_before_retry ||
                 !strstr(resp, "transaction-conflict"))) {
                printf("FAIL: divergent same-id snapshot retry is rejected "
                       "without mutation\n%s\n", resp);
                failed++;
            } else if (payloads[0]) {
                printf("PASS: divergent same-id snapshot retry is rejected "
                       "without mutation\n");
            }
            if (l3_fib_batch_rollback(0, 5500,
                                      resp, sizeof(resp)) != 0 ||
                g_l3_fib_owner[0].current != pre_before_retry) {
                printf("FAIL: idempotent retry rollback restores original "
                       "before-image\n%s\n", resp);
                failed++;
            } else {
                printf("PASS: idempotent retry rollback restores original "
                       "before-image\n");
            }
        }
    } else {
        printf("FAIL: 16 long nexthop fixture allocates\n");
        failed++;
    }

    if (payloads[2]) {
        l3_fib_state *owner_before = g_l3_fib_owner[0].current;

        if (snapshot_control(&fixtures[2], "begin", 5600,
                             resp, sizeof(resp)) != 0 ||
            !g_l3_fib_snapshot[0].active ||
            !g_l3_fib_snapshot[0].state ||
            !g_l3_fib_snapshot[0].prefix_slots ||
            g_l3_fib_snapshot[0].started_ns == 0 ||
            g_l3_fib_snapshot[0].deadline_ns <=
                g_l3_fib_snapshot[0].started_ns ||
            l3_fib_snapshot_sweep(
                g_l3_fib_snapshot[0].deadline_ns - 1) != 0 ||
            !g_l3_fib_snapshot[0].active ||
            l3_fib_snapshot_sweep(
                g_l3_fib_snapshot[0].deadline_ns) != 1 ||
            g_l3_fib_snapshot[0].active ||
            g_l3_fib_snapshot[0].state ||
            g_l3_fib_snapshot[0].prefix_slots ||
            g_l3_fib_owner[0].current != owner_before) {
            printf("FAIL: abandoned snapshot is actively swept\n%s\n", resp);
            failed++;
        } else {
            printf("PASS: abandoned snapshot is actively swept\n");
        }
    }

    if (payloads[0] && payloads[2]) {
        snapshot_fixture small_parts;

        if (snapshot_apply(&fixtures[0], 6000, resp, sizeof(resp)) != 0 ||
            snapshot_fixture_prepare(&small_parts, payloads[2], 512,
                                     4096) != 0 || small_parts.parts < 2) {
            printf("FAIL: snapshot failure fixtures prepare\n%s\n", resp);
            failed++;
        } else {
            int baseline_routes = g_l3_fib_owner[0].current->n_routes;

            if (snapshot_control(&small_parts, "begin", 6001,
                                 resp, sizeof(resp)) != 0 ||
                snapshot_send_part(&small_parts, 0, 6001,
                                   resp, sizeof(resp)) != 0 ||
                snapshot_control(&small_parts, "commit", 6001,
                                 resp, sizeof(resp)) == 0 ||
                g_l3_fib_snapshot[0].active ||
                !g_l3_fib_owner[0].current ||
                g_l3_fib_owner[0].current->n_routes != baseline_routes) {
                printf("FAIL: incomplete snapshot is discarded\n%s\n", resp);
                failed++;
            } else {
                printf("PASS: incomplete snapshot is discarded\n");
            }

            if (snapshot_control(&small_parts, "begin", 6002,
                                 resp, sizeof(resp)) != 0 ||
                snapshot_send_part(&small_parts, 1, 6002,
                                   resp, sizeof(resp)) == 0 ||
                g_l3_fib_snapshot[0].active ||
                !g_l3_fib_owner[0].current ||
                g_l3_fib_owner[0].current->n_routes != baseline_routes) {
                printf("FAIL: out-of-order snapshot part is discarded\n%s\n",
                       resp);
                failed++;
            } else {
                printf("PASS: out-of-order snapshot part is discarded\n");
            }

            if (snapshot_control(&small_parts, "begin", 6003,
                                 resp, sizeof(resp)) != 0 ||
                snapshot_send_part(&small_parts, 0, 6003,
                                   resp, sizeof(resp)) != 0 ||
                snapshot_send_part(&small_parts, 0, 6003,
                                   resp, sizeof(resp)) == 0 ||
                g_l3_fib_snapshot[0].active ||
                !g_l3_fib_owner[0].current ||
                g_l3_fib_owner[0].current->n_routes != baseline_routes) {
                printf("FAIL: duplicate snapshot part is discarded\n%s\n",
                       resp);
                failed++;
            } else {
                printf("PASS: duplicate snapshot part is discarded\n");
            }

            setenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY", "1", 1);
            g_lookup_owner_applied = true;
            g_lookup_map_all = true;
            g_dynamic_fail_next_apply = true;
            if (snapshot_control(&small_parts, "begin", 6004,
                                 resp, sizeof(resp)) != 0) {
                printf("FAIL: commit failure snapshot begins\n%s\n", resp);
                failed++;
            } else {
                int part;

                for (part = 0; part < small_parts.parts; part++)
                    if (snapshot_send_part(&small_parts, part, 6004,
                                           resp, sizeof(resp)) != 0)
                        break;
                if (part != small_parts.parts ||
                    snapshot_control(&small_parts, "commit", 6004,
                                     resp, sizeof(resp)) == 0 ||
                    g_l3_fib_snapshot[0].active ||
                    !g_l3_fib_owner[0].current ||
                    g_l3_fib_owner[0].current->n_routes != baseline_routes) {
                    printf("FAIL: failed live commit preserves owner\n%s\n",
                           resp);
                    failed++;
                } else {
                    printf("PASS: failed live commit preserves owner\n");
                }
            }
            unsetenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY");
        }
    }
    for (size_t i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++)
        free(payloads[i]);
    free(wide);
    reset_fib_test_state();
    return failed ? 1 : 0;
}

static char *read_fixture_file(const char *path) {
    FILE *fh = fopen(path, "rb");
    long size;
    char *buf;

    if (!fh)
        return NULL;
    if (fseek(fh, 0, SEEK_END) != 0) {
        fclose(fh);
        return NULL;
    }
    size = ftell(fh);
    if (size < 0) {
        fclose(fh);
        return NULL;
    }
    if (fseek(fh, 0, SEEK_SET) != 0) {
        fclose(fh);
        return NULL;
    }
    buf = malloc((size_t)size + 1);
    if (!buf) {
        fclose(fh);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, fh) != (size_t)size) {
        free(buf);
        fclose(fh);
        return NULL;
    }
    buf[size] = '\0';
    fclose(fh);
    return buf;
}

static int run_planner_fixture_dir(const char *dir, int expected_routes) {
    char path[1024];
    char resp[32768];
    char expect[64];
    int failed = 0;
    int applied = 0;

    unsetenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY");
    reset_fib_test_state();
    for (int idx = 0; ; idx++) {
        char *payload;

        snprintf(path, sizeof(path), "%s/fib-batch-%03d.txt", dir, idx);
        payload = read_fixture_file(path);
        if (!payload) {
            if (idx == 0) {
                printf("FAIL: planner fixture first batch missing: %s (%s)\n",
                       path, strerror(errno));
                return 1;
            }
            break;
        }
        if (l3_fib_batch_apply(0, payload, 900000 + idx, resp,
                               sizeof(resp)) != 0) {
            printf("FAIL: planner fixture batch %d rejected by switchd "
                   "parser\n%s\n", idx, resp);
            failed++;
            free(payload);
            break;
        }
        free(payload);
        applied++;
    }
    if (applied > 0) {
        printf("PASS: planner fixture batches apply through switchd parser\n");
    }
    if (expected_routes >= 0) {
        snprintf(expect, sizeof(expect), "routes=\"%d\"", expected_routes);
        failed += check_contains("planner fixture final route count",
                                 resp, expect);
    }
    failed += check_contains("planner fixture final shadow verify",
                             resp, "<fib-shadow-verify");
    failed += check_contains("planner fixture final owner status",
                             resp, "<fib-batch-apply status=\"ok\"");
    reset_fib_test_state();
    return failed;
}

static int run_l3_tx_owner_tests(void) {
    const char *state_a =
        "l3-router-set mac=02:00:00:10:84:00\n"
        "l3-rif-set name=et-0/0/0.0 vlan=4094 port=et-0/0/0 "
        "address=198.51.100.1/31\n";
    const char *state_b =
        "l3-router-set mac=02:00:00:10:84:00\n"
        "l3-rif-set name=et-0/0/0.0 vlan=4094 port=et-0/0/0 "
        "address=203.0.113.1/31\n";
    char resp[32768];
    l3_tx_state *state_a_owner;
    int failed = 0;

    reset_l3_tx_test_state();
    if (l3_transaction_hidden_apply(state_a, 700, resp,
                                    sizeof(resp)) != 0 ||
        !g_l3_tx_owner.current || !g_l3_tx_owner.pre ||
        g_l3_tx_owner.current->n_rifs != 1 ||
        g_l3_tx_owner.pre->n_rifs != 0) {
        printf("FAIL: persistent transaction first heap owner apply\n%s\n",
               resp);
        failed++;
        goto out;
    }
    state_a_owner = g_l3_tx_owner.current;
    if (l3_transaction_hidden_apply(state_b, 701, resp,
                                    sizeof(resp)) != 0 ||
        !g_l3_tx_owner.current || g_l3_tx_owner.pre != state_a_owner ||
        strcmp(g_l3_tx_owner.current->rifs[0].address,
               "203.0.113.1/31") != 0 ||
        strcmp(g_l3_tx_owner.pre->rifs[0].address,
               "198.51.100.1/31") != 0) {
        printf("FAIL: persistent transaction owner-slot swaps snapshots\n"
               "%s\n", resp);
        failed++;
        goto out;
    }
    if (l3_transaction_hidden_readback(0, false, resp,
                                       sizeof(resp)) != 0 ||
        !strstr(resp, "rollback-available=\"true\"") ||
        !strstr(resp, "<usage rifs=\"1\"") ||
        !strstr(resp, "<pre-state rifs=\"1\"")) {
        printf("FAIL: persistent transaction heap owner readback\n%s\n",
               resp);
        failed++;
        goto out;
    }
    if (l3_transaction_hidden_rollback(701, resp, sizeof(resp)) != 0 ||
        g_l3_tx_owner.current != state_a_owner || g_l3_tx_owner.pre ||
        strcmp(g_l3_tx_owner.current->rifs[0].address,
               "198.51.100.1/31") != 0 ||
        g_l3_tx_owner.rollback_available) {
        printf("FAIL: persistent transaction ownership rollback\n%s\n",
               resp);
        failed++;
        goto out;
    }
    if (l3_transaction_hidden_rollback(701, resp, sizeof(resp)) == 0 ||
        g_l3_tx_owner.current != state_a_owner) {
        printf("FAIL: persistent transaction repeated rollback is stable\n"
               "%s\n", resp);
        failed++;
        goto out;
    }

    reset_l3_tx_test_state();
    if (l3_transaction_hidden_apply(state_a, 702, resp,
                                    sizeof(resp)) != 0 ||
        l3_transaction_hidden_rollback(702, resp, sizeof(resp)) != 0 ||
        !g_l3_tx_owner.current || g_l3_tx_owner.current->n_rifs != 0 ||
        g_l3_tx_owner.pre || g_l3_tx_owner.rollback_available) {
        printf("FAIL: persistent transaction first rollback restores empty\n"
               "%s\n", resp);
        failed++;
        goto out;
    }
    printf("PASS: persistent transaction owner-slot apply/readback/rollback\n");
out:
    reset_l3_tx_test_state();
    return failed;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--snapshot") == 0)
        return run_snapshot_tests();
    if (argc >= 2)
        return run_planner_fixture_dir(
            argv[1], argc >= 3 ? atoi(argv[2]) : -1);

    const char *batch =
        "fib-batch table=inet.0 generation=10 fib-update-id=20\n"
        "fib-route prefix=192.0.2.0/24 protocol=connected "
        "preference=0 metric=0 nexthops=- egress-rif=irb.100 "
        "installed-state=owner-applied route-generation=10 "
        "fib-update-id=20 owner-role=persistent-owner\n"
        "fib-route prefix=203.0.113.0/24 protocol=ospf "
        "preference=10 metric=20 "
        "nexthops=192.0.2.1@irb.100,192.0.2.2@irb.100 "
        "egress-rif=irb.100 installed-state=pending-fib "
        "route-generation=10 fib-update-id=20 owner-role=dynamic-fib\n";
    const char *multicast_batch =
        "fib-batch table=inet.0 generation=10 fib-update-id=20\n"
        "fib-route prefix=224.0.0.0/4 protocol=ospf "
        "preference=10 metric=20 nexthops=192.0.2.1@irb.100 "
        "egress-rif=irb.100 installed-state=pending-fib "
        "route-generation=10 fib-update-id=20 owner-role=dynamic-fib\n";
    char resp[32768];
    int failed = 0;

    failed += run_l3_tx_owner_tests();

    {
        const char *physical_rif =
            "l3-router-set mac=02:00:00:10:84:00\n"
            "l3-rif-set name=et-0/0/0.0 vlan=4094 port=et-0/0/0 "
            "address=198.51.100.1/31\n";
        const char *physical_rif_without_owner =
            "l3-router-set mac=02:00:00:10:84:00\n"
            "l3-rif-set name=et-0/0/0.0 vlan=4094 "
            "address=198.51.100.1/31\n";
        l3_tx_state state;

        if (l3_transaction_parse(physical_rif, &state, resp,
                                 sizeof(resp)) != 0 ||
            state.n_rifs != 1 ||
            strcmp(state.rifs[0].name, "et-0/0/0.0") != 0 ||
            strcmp(state.rifs[0].port, "et-0/0/0") != 0 ||
            state.rifs[0].vlan != 4094) {
            printf("FAIL: physical routed RIF transaction parse\n%s\n",
                   resp);
            failed++;
        } else {
            printf("PASS: physical routed RIF transaction parse\n");
        }
        if (l3_transaction_parse(physical_rif_without_owner, &state, resp,
                                 sizeof(resp)) == 0) {
            printf("FAIL: physical routed RIF without port unexpectedly "
                   "parsed\n");
            failed++;
        } else {
            failed += check_contains(
                "physical routed RIF requires explicit port ownership",
                resp, "physical rif requires port intent");
        }
    }

    unsetenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY");
    g_lookup_owner_applied = false;
    g_lookup_map_all = false;
    g_dynamic_apply_calls = 0;
    g_dynamic_readback_calls = 0;
    if (l3_fib_batch_apply(0, batch, 100, resp, sizeof(resp)) != 0) {
        printf("FAIL: owner-empty batch apply failed\n%s\n", resp);
        failed++;
    } else {
        failed += check_contains("owner-empty handle map missing", resp,
                                 "<fib-handle-map source=\"switchd-rpd-fib-owner\" owner=\"persistent\" status=\"missing\"");
        failed += check_contains("owner-empty unmapped nexthops", resp,
                                 "unmapped-nexthops=\"2\"");
        failed += check_contains("owner-empty reports handle blocker", resp,
                                 "next-hop-handle-map");
        failed += check_contains("owner-empty reports operator gate", resp,
                                 "operator-gate");
        failed += check_absent("gate closed does not apply live owner", resp,
                               "<fib-live-owner status=\"ok\"");
        failed += check_contains("gate closed reads live owner", resp,
                                 "<fib-live-owner-readback status=\"empty\"");
        failed += check_absent("live engine is no longer missing", resp,
                               "sdk-apply-engine");
        if (g_dynamic_apply_calls != 0 || g_dynamic_readback_calls != 1) {
            printf("FAIL: gate closed live calls apply=%d readback=%d\n",
                   g_dynamic_apply_calls, g_dynamic_readback_calls);
            failed++;
        }
    }
    if (l3_fib_batch_readback(0, resp, sizeof(resp)) != 0) {
        printf("FAIL: owner-empty readback failed\n%s\n", resp);
        failed++;
    } else {
        failed += check_contains("readback includes handle map", resp,
                                 "<fib-handle-map source=\"switchd-rpd-fib-owner\"");
        failed += check_contains("readback includes live owner", resp,
                                 "<fib-live-owner-readback status=\"empty\"");
    }
    {
        const char *vrf_batch =
            "fib-batch table=blue.inet.0 generation=10 fib-update-id=20\n"
            "fib-route prefix=198.51.100.0/24 protocol=bgp "
            "preference=170 metric=50 nexthops=198.18.0.2@vlan200 "
            "egress-rif=vlan200 installed-state=pending-fib "
            "route-generation=10 fib-update-id=20 "
            "owner-role=dynamic-fib\n";

        if (l3_fib_batch_apply(0, vrf_batch, 101, resp,
                               sizeof(resp)) != 0) {
            printf("FAIL: VRF table FIB batch failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("VRF FIB batch selects table owner",
                                     resp, "table=\"blue.inet.0\"");
            failed += check_contains("VRF FIB batch keeps independent route",
                                     resp, "routes=\"1\"");
        }
        if (l3_fib_batch_readback(0, resp, sizeof(resp)) != 0) {
            printf("FAIL: table-scoped FIB readback failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("global FIB owner remains independent",
                                     resp, "<fib-readback status=\"ok\" "
                                     "owner=\"rpd\" table=\"inet.0\"");
            failed += check_contains("VRF FIB owner appears in readback",
                                     resp, "<fib-table "
                                     "table=\"blue.inet.0\" vrid=\"1\"");
        }
        if (l3_fib_batch_rollback(0, 101, resp, sizeof(resp)) != 0) {
            printf("FAIL: VRF FIB rollback failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("VRF FIB rollback is table scoped",
                                     resp, "table=\"blue.inet.0\"");
        }
    }
    {
        char *scale_4096 = build_scale_batch(4096);
        char *scale_4097 = build_scale_batch(4097);

        if (!scale_4096 || !scale_4097) {
            printf("FAIL: scale FIB batches allocate\n");
            failed++;
        } else if (l3_fib_batch_apply(0, scale_4096, 4096, resp,
                                      sizeof(resp)) != 0) {
            printf("FAIL: 4096-route FIB scale batch failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("4096-route FIB scale batch applies",
                                     resp, "routes=\"4096\"");
            failed += check_contains("4096-route FIB scale batch is bounded",
                                     resp,
                                     "<truncated reason=\"emit-limit\"");
        }
        if (scale_4097 &&
            l3_fib_batch_apply(0, scale_4097, 4097, resp,
                               sizeof(resp)) == 0) {
            printf("FAIL: 4097-route FIB scale batch unexpectedly applied\n"
                   "%s\n", resp);
            failed++;
        } else if (scale_4097) {
            failed += check_contains("4097-route FIB scale batch rejects",
                                     resp, "too many fib routes");
        }
        free(scale_4096);
        free(scale_4097);
        if (l3_fib_batch_apply(0, batch, 100, resp, sizeof(resp)) != 0) {
            printf("FAIL: post-scale small FIB fixture restore failed\n%s\n",
                   resp);
            failed++;
        } else {
            failed += check_contains("post-scale small FIB fixture restored",
                                     resp, "routes=\"2\"");
        }
    }
    {
        const char *delta_add =
            "fib-batch table=inet.0 generation=11 fib-update-id=21 "
            "mode=delta\n"
            "fib-route op=replace prefix=198.51.100.0/24 protocol=bgp "
            "preference=170 metric=100 nexthops=192.0.2.3@irb.100 "
            "egress-rif=irb.100 installed-state=pending-fib "
            "route-generation=11 fib-update-id=21 owner-role=dynamic-fib\n";
        const char *delta_delete =
            "fib-batch table=inet.0 generation=12 fib-update-id=22 "
            "mode=delta\n"
            "fib-route op=delete prefix=203.0.113.0/24\n";

        if (l3_fib_batch_apply(0, delta_add, 103, resp, sizeof(resp)) != 0) {
            printf("FAIL: delta add FIB batch failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("delta add uses merge intent", resp,
                                     "mode=\"delta-merge\"");
            failed += check_contains("delta add preserves previous routes",
                                     resp, "<pre-state routes=\"2\"");
            failed += check_contains("delta add appends route", resp,
                                     "<post-state routes=\"3\"");
            failed += check_contains("delta add route visible", resp,
                                     "prefix=\"198.51.100.0/24\"");
        }
        if (l3_fib_batch_apply(0, delta_delete, 104, resp,
                               sizeof(resp)) != 0) {
            printf("FAIL: delta delete FIB batch failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("delta delete uses merge intent", resp,
                                     "mode=\"delta-merge\"");
            failed += check_contains("delta delete removes one route", resp,
                                     "<post-state routes=\"2\"");
        }
        if (l3_fib_batch_readback(0, resp, sizeof(resp)) != 0) {
            printf("FAIL: delta readback failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_absent("delta delete removes OSPF prefix",
                                   resp, "prefix=\"203.0.113.0/24\"");
            failed += check_contains("delta delete keeps BGP prefix",
                                     resp, "prefix=\"198.51.100.0/24\"");
        }
    }
    if (l3_fib_batch_apply(0, multicast_batch, 100, resp,
                           sizeof(resp)) == 0) {
        printf("FAIL: multicast FIB batch unexpectedly applied\n%s\n", resp);
        failed++;
    } else {
        failed += check_contains("multicast FIB batch is rejected", resp,
                                 "invalid fib prefix");
    }

    setenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY", "1", 1);
    g_lookup_owner_applied = false;
    g_lookup_map_all = false;
    g_dynamic_apply_calls = 0;
    if (l3_fib_batch_apply(0, batch, 101, resp, sizeof(resp)) != 0) {
        printf("FAIL: live-gated unmapped batch apply failed\n%s\n", resp);
        failed++;
    } else {
        failed += check_contains("live-gated unmapped stays blocked", resp,
                                 "live-ready=\"false\"");
        failed += check_contains("live-gated unmapped reports blocker", resp,
                                 "next-hop-handle-map");
        failed += check_contains("live-gated cleanup applied", resp,
                                 "<fib-live-owner status=\"ok\"");
        if (g_dynamic_apply_calls != 1 || g_dynamic_last_routes != 0 ||
            !g_dynamic_last_enabled || g_dynamic_last_tx_id != 101) {
            printf("FAIL: live cleanup calls=%d routes=%d enabled=%s tx=%llu\n",
                   g_dynamic_apply_calls, g_dynamic_last_routes,
                   g_dynamic_last_enabled ? "true" : "false",
                   (unsigned long long)g_dynamic_last_tx_id);
            failed++;
        }
    }

    g_lookup_owner_applied = true;
    g_lookup_map_all = true;
    g_dynamic_apply_calls = 0;
    if (l3_fib_batch_apply(0, batch, 102, resp, sizeof(resp)) != 0) {
        printf("FAIL: mapped batch apply failed\n%s\n", resp);
        failed++;
    } else {
        failed += check_contains("mapped handle map ready", resp,
                                 "handle-map=\"ready\"");
        failed += check_contains("mapped nexthop count", resp,
                                 "mapped-nexthops=\"2\"");
        failed += check_contains("mapped zero unmapped nexthops", resp,
                                 "unmapped-nexthops=\"0\"");
        failed += check_absent("mapped removes handle blocker", resp,
                               "next-hop-handle-map");
        failed += check_contains("mapped live ready", resp,
                                 "live-ready=\"true\"");
        failed += check_contains("mapped live apply present", resp,
                                 "<fib-live-owner status=\"ok\"");
        if (g_dynamic_apply_calls != 1 || g_dynamic_last_routes != 1 ||
            g_dynamic_last_nexthops != 2 || !g_dynamic_last_enabled ||
            g_dynamic_last_tx_id != 102) {
            printf("FAIL: mapped live apply calls=%d routes=%d nh=%d "
                   "enabled=%s tx=%llu\n",
                   g_dynamic_apply_calls, g_dynamic_last_routes,
                   g_dynamic_last_nexthops,
                   g_dynamic_last_enabled ? "true" : "false",
                   (unsigned long long)g_dynamic_last_tx_id);
            failed++;
        }
    }
    {
        const char *staged_fail_delta =
            "fib-batch table=inet.0 generation=13 fib-update-id=23 "
            "mode=delta\n"
            "fib-route op=replace prefix=198.51.100.0/24 protocol=bgp "
            "preference=170 metric=100 nexthops=192.0.2.3@irb.100 "
            "egress-rif=irb.100 installed-state=pending-fib "
            "route-generation=13 fib-update-id=23 owner-role=dynamic-fib\n";

        g_dynamic_fail_next_apply = true;
        if (l3_fib_batch_apply(0, staged_fail_delta, 103, resp,
                               sizeof(resp)) == 0) {
            printf("FAIL: injected live failure unexpectedly committed\n%s\n",
                   resp);
            failed++;
        } else {
            failed += check_contains("live failure rejects staged FIB state",
                                     resp,
                                     "rejected staged state because live dynamic FIB sync failed");
        }
        if (l3_fib_batch_readback(0, resp, sizeof(resp)) != 0) {
            printf("FAIL: post-live-failure readback failed\n%s\n", resp);
            failed++;
        } else {
            failed += check_contains("post-live-failure keeps mapped batch",
                                     resp, "prefix=\"203.0.113.0/24\"");
            failed += check_absent("post-live-failure does not commit delta",
                                   resp, "prefix=\"198.51.100.0/24\"");
        }
    }
    {
        const char *global_initial =
            "fib-batch table=inet.0 generation=20 fib-update-id=30\n"
            "fib-route prefix=203.0.113.0/24 protocol=bgp "
            "preference=170 metric=10 nexthops=192.0.2.2@irb.100 "
            "egress-rif=irb.100 installed-state=pending-fib "
            "route-generation=20 fib-update-id=30 owner-role=dynamic-fib\n";
        const char *global_updated =
            "fib-batch table=inet.0 generation=21 fib-update-id=31\n"
            "fib-route prefix=203.0.114.0/24 protocol=bgp "
            "preference=170 metric=11 nexthops=192.0.2.2@irb.100 "
            "egress-rif=irb.100 installed-state=pending-fib "
            "route-generation=21 fib-update-id=31 owner-role=dynamic-fib\n";
        const char *vrf_initial =
            "fib-batch table=blue.inet.0 generation=20 fib-update-id=30\n"
            "fib-route prefix=198.51.100.0/24 protocol=bgp "
            "preference=170 metric=10 nexthops=198.18.0.2@vlan200 "
            "egress-rif=vlan200 installed-state=pending-fib "
            "route-generation=20 fib-update-id=30 owner-role=dynamic-fib\n";
        const char *vrf_updated =
            "fib-batch table=blue.inet.0 generation=21 fib-update-id=31\n"
            "fib-route prefix=198.51.101.0/24 protocol=bgp "
            "preference=170 metric=11 nexthops=198.18.0.2@vlan200 "
            "egress-rif=vlan200 installed-state=pending-fib "
            "route-generation=21 fib-update-id=31 owner-role=dynamic-fib\n";

        reset_fib_test_state();
        if (l3_fib_batch_apply(0, global_initial, 200, resp,
                               sizeof(resp)) != 0 ||
            l3_fib_batch_apply(0, vrf_initial, 201, resp,
                               sizeof(resp)) != 0 ||
            l3_fib_batch_apply(0, global_updated, 300, resp,
                               sizeof(resp)) != 0 ||
            l3_fib_batch_apply(0, vrf_updated, 300, resp,
                               sizeof(resp)) != 0) {
            printf("FAIL: dual-table rollback fixture setup\n%s\n", resp);
            failed++;
        } else {
            g_dynamic_apply_calls = 0;
            g_dynamic_fail_apply_call = 2;
            if (l3_fib_batch_rollback(0, 300, resp,
                                      sizeof(resp)) == 0) {
                printf("FAIL: injected second-table rollback unexpectedly "
                       "succeeded\n%s\n", resp);
                failed++;
            } else {
                failed += check_contains(
                    "dual-table rollback reports compensated failure", resp,
                    "compensated staged rollback");
                if (!g_l3_fib_owner[0].current ||
                    !g_l3_fib_owner[1].current ||
                    strcmp(g_l3_fib_owner[0].current->routes[0].prefix,
                           "203.0.114.0/24") != 0 ||
                    strcmp(g_l3_fib_owner[1].current->routes[0].prefix,
                           "198.51.101.0/24") != 0 ||
                    !g_l3_fib_owner[0].rollback_available ||
                    !g_l3_fib_owner[1].rollback_available ||
                    g_dynamic_apply_calls != 3) {
                    printf("FAIL: compensated rollback changed table state "
                           "calls=%d global=%s vrf=%s\n",
                           g_dynamic_apply_calls,
                           g_l3_fib_owner[0].current ?
                               g_l3_fib_owner[0].current->routes[0].prefix :
                               "<missing>",
                           g_l3_fib_owner[1].current ?
                               g_l3_fib_owner[1].current->routes[0].prefix :
                               "<missing>");
                    failed++;
                } else {
                    printf("PASS: compensated rollback preserves both table "
                           "owners\n");
                }
            }
            if (l3_fib_batch_rollback(0, 300, resp,
                                      sizeof(resp)) != 0) {
                printf("FAIL: dual-table rollback retry failed\n%s\n", resp);
                failed++;
            } else if (!g_l3_fib_owner[0].current ||
                       !g_l3_fib_owner[1].current ||
                       strcmp(
                           g_l3_fib_owner[0].current->routes[0].prefix,
                           "203.0.113.0/24") != 0 ||
                       strcmp(g_l3_fib_owner[1].current->routes[0].prefix,
                              "198.51.100.0/24") != 0 ||
                       g_l3_fib_owner[0].rollback_available ||
                       g_l3_fib_owner[1].rollback_available) {
                printf("FAIL: dual-table rollback retry did not restore both "
                       "owners\n");
                failed++;
            } else {
                printf("PASS: dual-table rollback retry restores both table "
                       "owners\n");
            }
        }
    }

    reset_fib_test_state();
    return failed ? 1 : 0;
}
