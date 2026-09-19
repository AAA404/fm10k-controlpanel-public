#ifndef RPD_RIB_H
#define RPD_RIB_H

#include "netlab/types.h"
#include <stdbool.h>
#include <stddef.h>

#define RPD_RIB_TABLE "inet.0"
#define RPD_RIB_TABLE_LEN 64
#define RPD_RIB_MAIN_KERNEL_TABLE 254
#define RPD_RIB_VRF_V1_KERNEL_TABLE 1001
#define RPD_RIB_MAX_ROUTES 4096
#define RPD_RIB_MAX_ARP 1024
#define RPD_RIB_MAX_NEXTHOPS 16
#define RPD_RIB_MAX_IDEMPOTENCY 256
#define RPD_RIB_XML_ROUTE_LIMIT 64
#define RPD_RIB_XML_ARP_LIMIT 64
#define RPD_RIB_UPDATE_AFFECTED_MAX 128

typedef struct {
    char address[40];
    char egress_rif[64];
} rpd_rib_nexthop;

typedef struct {
    bool active;
    char prefix[40];
    char protocol[16];
    int preference;
    int metric;
    rpd_rib_nexthop nexthops[RPD_RIB_MAX_NEXTHOPS];
    int n_nexthops;
    char egress_rif[64];
    char installed_state[32];
    u64 generation;
    u64 fib_update_id;
} rpd_rib_route;

typedef struct {
    bool active;
    char ip[40];
    char mac[32];
    char rif[64];
    char egress_port[64];
    char source[16];
    char installed_state[32];
    u64 generation;
    u64 fib_update_id;
} rpd_rib_arp;

typedef struct {
    bool used;
    char key[96];
    u32 fingerprint;
    u64 generation;
    u64 fib_update_id;
} rpd_rib_idempotency;

typedef struct {
    char table[RPD_RIB_TABLE_LEN];
    u32 kernel_table;
    rpd_rib_route routes[RPD_RIB_MAX_ROUTES];
    rpd_rib_arp arps[RPD_RIB_MAX_ARP];
    rpd_rib_idempotency idempotency[RPD_RIB_MAX_IDEMPOTENCY];
    int idempotency_head;
} rpd_rib;

typedef struct {
    int candidates;
    int best_routes;
    int connected;
    int static_routes;
    int ospf;
    int bgp;
    int ecmp_routes;
    int ecmp_members;
    int arp_entries;
} rpd_rib_stats;

typedef struct {
    bool changed;
    bool idempotent;
    bool idempotency_conflict;
    int routes_changed;
    int routes_deleted;
    int routes_unchanged;
    int ecmp_routes;
    int ecmp_members;
    int affected_prefix_count;
    bool affected_prefix_overflow;
    char affected_prefixes[RPD_RIB_UPDATE_AFFECTED_MAX][40];
    u64 generation;
    u64 fib_update_id;
    char idempotency_key[96];
    char detail[160];
} rpd_rib_update_result;

void rpd_rib_init(rpd_rib *rib);
int rpd_rib_init_table(rpd_rib *rib, const char *table);
int rpd_rib_init_scope(rpd_rib *rib, const char *table, u32 kernel_table);
void rpd_rib_get_stats(const rpd_rib *rib, rpd_rib_stats *stats);
int rpd_rib_apply_fpm_text(rpd_rib *rib, const char *payload, int payload_len,
                           u64 generation, u64 fib_update_id,
                           rpd_rib_update_result *result,
                           char *err, size_t err_size);
int rpd_rib_sync_static_plan(rpd_rib *rib, const char *payload,
                             int payload_len, u64 generation,
                             u64 fib_update_id,
                             rpd_rib_update_result *result,
                             char *err, size_t err_size);
int rpd_rib_sync_dynamic_arp_text(rpd_rib *rib, const char *payload,
                                  int payload_len, u64 generation,
                                  u64 fib_update_id,
                                  rpd_rib_update_result *result,
                                  char *err, size_t err_size);
int rpd_rib_purge_dynamic_protocols(rpd_rib *rib, u64 generation,
                                    u64 fib_update_id,
                                    rpd_rib_update_result *result,
                                    char *err, size_t err_size);
int rpd_rib_compile_fib_batch(const rpd_rib *rib, u64 generation,
                              u64 fib_update_id, char *buf,
                              size_t buf_size, int *routes_out);
int rpd_rib_compile_fib_batch_alloc(const rpd_rib *rib, u64 generation,
                                    u64 fib_update_id, char **buf_out,
                                    size_t *len_out, int *routes_out);
int rpd_rib_fib_route_count(const rpd_rib *rib);
void rpd_rib_mark_dynamic_fib_installed(rpd_rib *rib);
void rpd_rib_mark_dynamic_fib_installed_through(rpd_rib *rib,
                                                u64 generation,
                                                u64 fib_update_id);
int rpd_rib_compile_fib_delta(const rpd_rib *rib,
                              const rpd_rib_update_result *result,
                              u64 generation, u64 fib_update_id,
                              char *buf, size_t buf_size, int *routes_out);
int rpd_rib_append_xml(const rpd_rib *rib, char *buf, size_t buf_size,
                       size_t *off);

#endif
