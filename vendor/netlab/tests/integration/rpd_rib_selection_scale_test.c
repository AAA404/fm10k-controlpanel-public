#include "rib.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t rpd_test_strcmp_calls;

int rpd_test_strcmp(const char *left, const char *right) {
    const unsigned char *a = (const unsigned char *)left;
    const unsigned char *b = (const unsigned char *)right;

    rpd_test_strcmp_calls++;
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int)*a - (int)*b;
}

static int check(const char *name, int ok, int scale, size_t comparisons) {
    printf("%s: %s scale=%d comparisons=%zu\n",
           ok ? "PASS" : "FAIL", name, scale, comparisons);
    return ok ? 0 : 1;
}

static void prefix_for_index(int index, char *out, size_t out_size) {
    snprintf(out, out_size, "10.%d.%d.0/24",
             64 + index / 256, index % 256);
}

static void populate_rib(rpd_rib *rib, int count) {
    rpd_rib_init(rib);
    for (int i = 0; i < count; i++) {
        rpd_rib_route *route = &rib->routes[i];

        route->active = true;
        prefix_for_index(i, route->prefix, sizeof(route->prefix));
        snprintf(route->protocol, sizeof(route->protocol), "bgp");
        route->preference = 170;
        route->metric = i;
        snprintf(route->installed_state, sizeof(route->installed_state),
                 "pending-fib");
    }
}

int main(void) {
    static const int scales[] = {1, 128, 512, 4096};
    static rpd_rib rib;
    char *fib;
    size_t fib_size = (size_t)RPD_RIB_MAX_ROUTES * 512u + 4096u;
    int failed = 0;

    fib = malloc(fib_size);
    if (!fib)
        return 1;
    for (size_t scale_i = 0;
         scale_i < sizeof(scales) / sizeof(scales[0]); scale_i++) {
        rpd_rib_update_result result = {0};
        char last_prefix[40];
        size_t comparison_limit;
        size_t full_len = 0;
        char *full = NULL;
        int affected;
        int routes = -1;
        int count = scales[scale_i];
        int rc;

        populate_rib(&rib, count);
        prefix_for_index(count - 1, last_prefix, sizeof(last_prefix));
        rpd_test_strcmp_calls = 0;
        rc = rpd_rib_compile_fib_batch_alloc(&rib, 10, 11, &full,
                                             &full_len, &routes);
        comparison_limit = 32768u + (size_t)count * 128u;
        failed += check("bounded full RIB selection",
                        rc == 0 && full && full_len > 0 && routes == count &&
                        strstr(full, last_prefix) != NULL &&
                        (count != 4096 || full_len > 256u * 1024u) &&
                        rpd_test_strcmp_calls <= comparison_limit,
                        count, rpd_test_strcmp_calls);
        free(full);

        affected = count < RPD_RIB_UPDATE_AFFECTED_MAX ?
            count : RPD_RIB_UPDATE_AFFECTED_MAX;
        result.affected_prefix_count = affected;
        for (int i = 0; i < affected; i++) {
            int route_index = ((i + 1) * count) / affected - 1;

            prefix_for_index(route_index, result.affected_prefixes[i],
                             sizeof(result.affected_prefixes[i]));
        }
        rpd_test_strcmp_calls = 0;
        routes = -1;
        rc = rpd_rib_compile_fib_delta(&rib, &result, 12, 13, fib,
                                       fib_size, &routes);
        comparison_limit = 32768u + (size_t)count * 64u +
                           (size_t)affected * 32u;
        failed += check("indexed delta prefix selection",
                        rc > 0 && routes == affected &&
                        strstr(fib, last_prefix) != NULL &&
                        rpd_test_strcmp_calls <= comparison_limit,
                        count, rpd_test_strcmp_calls);
    }
    {
        rpd_rib_route *route;
        char *full = NULL;
        size_t full_len = 0;
        int routes = -1;

        rpd_rib_init(&rib);
        route = &rib.routes[0];
        route->active = true;
        snprintf(route->prefix, sizeof(route->prefix), "10.0.0.0/24");
        snprintf(route->protocol, sizeof(route->protocol), "connected");
        snprintf(route->installed_state, sizeof(route->installed_state),
                 "owner-applied");
        route->n_nexthops = RPD_RIB_MAX_NEXTHOPS;
        for (int i = 0; i < RPD_RIB_MAX_NEXTHOPS; i++) {
            rpd_rib_arp *arp = &rib.arps[i];

            snprintf(route->nexthops[i].address,
                     sizeof(route->nexthops[i].address),
                     "192.0.2.%d", i + 1);
            memset(route->nexthops[i].egress_rif, 'a',
                   sizeof(route->nexthops[i].egress_rif) - 1);
            route->nexthops[i].egress_rif[
                sizeof(route->nexthops[i].egress_rif) - 2] =
                    (char)('A' + i);
            route->nexthops[i].egress_rif[
                sizeof(route->nexthops[i].egress_rif) - 1] = '\0';
            arp->active = true;
            snprintf(arp->ip, sizeof(arp->ip), "%s",
                     route->nexthops[i].address);
            snprintf(arp->rif, sizeof(arp->rif), "%s",
                     route->nexthops[i].egress_rif);
        }
        failed += check(
            "16 long nexthops serialize without truncation",
            rpd_rib_compile_fib_batch_alloc(&rib, 20, 21, &full,
                                            &full_len, &routes) == 0 &&
            full && routes == 1 && full_len > 1024 &&
            strstr(full, "192.0.2.16@") != NULL,
            RPD_RIB_MAX_NEXTHOPS, full_len);
        free(full);
    }
    free(fib);
    return failed ? 1 : 0;
}
