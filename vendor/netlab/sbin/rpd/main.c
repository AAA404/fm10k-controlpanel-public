#include "rib.h"
#include "frr_config.h"
#include "frr_runtime.h"
#include "fpm.h"
#include "switchd_owner_rpc.h"
#ifdef NETLAB_FPM_TEST_AUTHORITY
#include "fpm_test_authority.h"
#endif
#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/ipc.h"
#include "netlab/l3_capacity.h"
#include "netlab/l3_owner.h"
#include "netlab/log.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RPD_SOCKET "/var/run/netlab/rpd.sock"
#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define RPD_STATIC_PLAN_MAX 65536
#define RPD_FIB_BATCH_MAX NETLAB_MAX_MSG
#define RPD_FIB_SNAPSHOT_PART_DATA_MAX 60000
#define RPD_FIB_SNAPSHOT_DIGEST_INIT UINT64_C(14695981039346656037)
#define RPD_FIB_SNAPSHOT_DIGEST_PRIME UINT64_C(1099511628211)
#define RPD_SWITCHD_FIB_RPC_TIMEOUT_MS 120000
#define RPD_FIB_PIPELINE_QUEUE_MAX 64
#define RPD_OPLOG_MAX 16
#define RPD_STATE_MAX 65536
#define RPD_PATH_MAX 256
#define RPD_SOCKET_PATH_MAX 100
#define RPD_FPM_RIF_MAP_MAX NL_L3_PERSISTENT_MAX_RIFS
#define RPD_FPM_RIF_MAP_TEXT_MAX \
    ((size_t)RPD_FPM_RIF_MAP_MAX * 96u)
#define RPD_VRF_V1_VRID 1
#define RPD_VRF_V1_KERNEL_TABLE 1001
#define RPD_FPM_SYNC_BATCH_SIZE_DEFAULT 128
#define RPD_FPM_SYNC_BATCH_MS_DEFAULT 5000

typedef struct {
    int ifindex;
    char rif[64];
    char source[16];
} rpd_ifindex_rif_map;

typedef struct {
    u64 update_id;
    u64 generation;
    u64 tx_id;
    char action[32];
    char result[32];
    int rifs;
    int arp;
    int next_hops;
    int routes;
    int ecmp_groups;
    char idempotency_key[96];
    time_t when;
} rpd_oplog_entry;

typedef struct {
    bool enabled;
    char name[64];
    char table[RPD_RIB_TABLE_LEN];
    u32 vrid;
    u32 kernel_table;
} rpd_vrf_context;

typedef struct {
    rpd_rib *rib;
    rpd_rib_update_result result;
    int updates;
    s64 started_ms;
} rpd_fpm_sync_batch;

typedef enum {
    RPD_FIB_PROGRAM_APPLY = 0,
    RPD_FIB_PROGRAM_SNAPSHOT,
    RPD_FIB_PROGRAM_RECONCILE,
} rpd_fib_program_kind;

typedef struct {
    rpd_fib_program_kind kind;
    char *payload;
    int payload_len;
    int expected_routes;
    int updates;
    int attempts;
    u64 generation;
    u64 fib_update_id;
    s64 queued_ms;
    char table[RPD_RIB_TABLE_LEN];
    char reason[96];
} rpd_fib_program_task;

typedef struct {
    nl_l3_owner *l3_owner;
    pthread_mutex_t lock;
    bool lock_ready;
    u64 generation;
    u64 fib_update_id;
    u64 last_tx_id;
    time_t started_at;
    time_t last_apply;
    time_t last_rollback;
    time_t last_reconcile;
    time_t last_readback;
    time_t last_fib_sync;
    time_t last_fib_readback;
    s32 last_owner_ec;
    s32 last_fib_ec;
    char drift_state[24];
    char drift_reason[160];
    char owner_mode[32];
    char switchd_owner_status[32];
    char fib_sync_state[32];
    char fib_sync_reason[192];
    char switchd_fib_status[32];
    char switchd_fib_live_status[32];
    char switchd_fib_live_gate[16];
    char switchd_fib_live_ready[8];
    char switchd_fib_live_missing[192];
    char switchd_fib_live_reason[192];
    int switchd_fib_routes;
    int switchd_fib_dynamic_routes;
    int switchd_fib_owner_routes;
    int switchd_fib_ifindex_rifs;
    u64 switchd_fib_generation;
    u64 switchd_fib_update_id;
    bool frr_config_enabled;
    bool fpm_programming_enabled;
    bool defer_fpm_fib_sync;
    int fpm_sync_batch_size;
    int fpm_sync_batch_ms;
    rpd_fpm_sync_batch fpm_sync_batch[2];
    u64 fpm_sync_batch_flushes;
    u64 fpm_sync_batch_errors;
    int fpm_sync_batch_last_size;
    pthread_cond_t fib_program_cond;
    bool fib_program_cond_ready;
    pthread_t fib_program_thread;
    bool fib_program_thread_started;
    bool fib_program_accepting;
    bool fib_program_stop_requested;
    bool fib_program_inflight;
    rpd_fib_program_task fib_program_queue[RPD_FIB_PIPELINE_QUEUE_MAX];
    int fib_program_queue_head;
    int fib_program_queue_count;
    int fib_program_queue_high_water;
    u64 fib_program_enqueued;
    u64 fib_program_completed;
    u64 fib_program_failures;
    u64 fib_program_backpressure;
    u64 fib_program_stale_acks;
    u64 fib_program_coalesced_updates;
    u64 fib_program_acked_generation;
    u64 fib_program_acked_update_id;
    s64 fib_program_last_queue_ms;
    s64 fib_program_last_rpc_ms;
    char fib_program_last_error[192];
    bool churn_gate_enabled;
    int churn_window_ms;
    int churn_max_updates;
    int churn_used;
    s64 churn_window_start_ms;
    u64 churn_drops;
    time_t last_churn_drop;
    char churn_state[32];
    char churn_reason[160];
    bool periodic_reconcile_enabled;
    int periodic_reconcile_ms;
    s64 last_periodic_reconcile_ms;
    u64 periodic_reconcile_runs;
    u64 periodic_reconcile_errors;
    bool linux_arp_enabled;
    int linux_arp_interval_ms;
    s64 last_linux_arp_ms;
    time_t last_linux_arp;
    u64 linux_arp_runs;
    u64 linux_arp_errors;
    int linux_arp_entries;
    char linux_arp_status[32];
    char linux_arp_reason[160];
    char linux_arp_ifname[64];
    char linux_arp_rif[64];
    char linux_arp_ip_path[RPD_PATH_MAX];
    rpd_ifindex_rif_map fpm_rif_map[RPD_FPM_RIF_MAP_MAX];
    int fpm_rif_map_entries;
    u64 fpm_rif_map_hits;
    char fpm_rif_map_status[32];
    char fpm_rif_map_reason[160];
    char static_owner_plan[RPD_STATIC_PLAN_MAX];
    int static_owner_plan_len;
    bool static_owner_plan_valid;
    char static_owner_applied_plan[RPD_STATIC_PLAN_MAX];
    int static_owner_applied_plan_len;
    bool static_owner_applied_plan_valid;
    bool static_rib_only_routes;
    bool static_owner_rib_routes_installed;
    char rollback_static_owner_plan[RPD_STATIC_PLAN_MAX];
    int rollback_static_owner_plan_len;
    bool rollback_static_owner_plan_valid;
    char rollback_static_owner_applied_plan[RPD_STATIC_PLAN_MAX];
    int rollback_static_owner_applied_plan_len;
    bool rollback_static_owner_applied_plan_valid;
    bool rollback_static_rib_only_routes;
    bool rollback_static_owner_rib_routes_installed;
    rpd_rib rib;
    rpd_rib rollback_rib;
    rpd_rib vrf_rib;
    rpd_rib rollback_vrf_rib;
    rpd_vrf_context vrf;
    rpd_vrf_context rollback_vrf;
    bool rollback_rib_available;
    rpd_frr_config frr_intent;
    rpd_frr_config rollback_frr_intent;
    rpd_frr_runtime frr_runtime;
    rpd_fpm_listener fpm;
    pthread_t maintenance_thread;
    atomic_bool maintenance_running;
    bool maintenance_thread_started;
    u64 maintenance_runs;
    u64 maintenance_errors;
    u64 frr_observation_discards;
    time_t last_maintenance;
    rpd_oplog_entry oplog[RPD_OPLOG_MAX];
    int oplog_head;
    int oplog_count;
} rpd_ctx;

typedef struct {
    int rifs;
    int arp;
    int next_hops;
    int routes;
    int ecmp_groups;
    bool has_dynamic_protocol;
    char idempotency_key[96];
} rpd_plan_stats;

static rpd_ctx g_rpd;
static char g_rpd_socket_path[RPD_SOCKET_PATH_MAX] = RPD_SOCKET;
static char g_switchd_socket_path[RPD_SOCKET_PATH_MAX] = SWITCHD_SOCKET;

static int fpm_sync_batch_flush_locked(rpd_ctx *rpd,
                                       rpd_fpm_sync_batch *batch,
                                       const char *reason);
static int sync_switchd_fib_locked(const char *reason, bool force);

static void rpd_lock(rpd_ctx *rpd) {
    if (rpd && rpd->lock_ready)
        pthread_mutex_lock(&rpd->lock);
}

static void rpd_unlock(rpd_ctx *rpd) {
    if (rpd && rpd->lock_ready)
        pthread_mutex_unlock(&rpd->lock);
}

static bool env_truthy(const char *name) {
    const char *v = getenv(name);

    return v && (strcmp(v, "1") == 0 ||
                 strcmp(v, "true") == 0 ||
                 strcmp(v, "TRUE") == 0 ||
                 strcmp(v, "yes") == 0 ||
                 strcmp(v, "YES") == 0);
}

static bool frr_config_gate_default(void) {
    return !env_truthy("NETLAB_DISABLE_RPD_FRR_CONFIG");
}

static bool frr_runtime_start_gate_default(void) {
    return !env_truthy("NETLAB_DISABLE_RPD_FRR_RUNTIME");
}

static bool fpm_programming_default(void) {
    if (env_truthy("NETLAB_DISABLE_RPD_FPM"))
        return false;
    if (env_truthy("NETLAB_ENABLE_RPD_FPM"))
        return true;
    return rpd_frr_runtime_present();
}

static int env_int_default(const char *name, int fallback, int min, int max) {
    const char *v = getenv(name);
    char *end = NULL;
    long n;

    if (!v || !*v)
        return fallback;
    n = strtol(v, &end, 10);
    if (!end || *end || n < min || n > max)
        return fallback;
    return (int)n;
}

static bool token_safe(const char *s) {
    if (!s || !s[0])
        return false;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return false;
    }
    return true;
}

static int parse_vrf_context(const char *payload, int payload_len,
                             rpd_vrf_context *vrf,
                             char *err, size_t err_size) {
    const char *p;
    const char *end;

    if (!vrf || payload_len < 0) {
        snprintf(err, err_size, "invalid VRF plan context");
        return -1;
    }
    memset(vrf, 0, sizeof(*vrf));
    p = payload;
    end = payload ? payload + payload_len : payload;
    while (p && p < end) {
        char line[512];
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t len = nl ? (size_t)(nl - p) : (size_t)(end - p);

        if (len >= sizeof(line)) {
            snprintf(err, err_size, "VRF plan line is too long");
            return -1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        if (strncmp(line, "virtual-router ", 15) == 0 ||
            strncmp(line, "l3-virtual-router-set ", 22) == 0) {
            char extra[2];
            char expected_table[RPD_RIB_TABLE_LEN];
            unsigned int vrid = 0;
            unsigned int kernel_table = 0;
            int fields;

            if (vrf->enabled) {
                snprintf(err, err_size,
                         "VRF V1 supports one virtual router");
                return -1;
            }
            if (strncmp(line, "virtual-router ", 15) == 0)
                fields = sscanf(line,
                                "virtual-router name %63s table %63s "
                                "vrid %u kernel-table %u %1s",
                                vrf->name, vrf->table, &vrid,
                                &kernel_table, extra);
            else
                fields = sscanf(line,
                                "l3-virtual-router-set name=%63s table=%63s "
                                "vrid=%u kernel-table=%u %1s",
                                vrf->name, vrf->table, &vrid,
                                &kernel_table, extra);
            if (snprintf(expected_table, sizeof(expected_table),
                         "%s.inet.0", vrf->name) >=
                (int)sizeof(expected_table)) {
                snprintf(err, err_size,
                         "VRF V1 table name exceeds limit");
                return -1;
            }
            if (fields != 4 || !token_safe(vrf->name) ||
                !token_safe(vrf->table) || vrid != RPD_VRF_V1_VRID ||
                kernel_table != RPD_VRF_V1_KERNEL_TABLE ||
                strcmp(vrf->table, expected_table) != 0) {
                snprintf(err, err_size,
                         "invalid VRF V1 virtual-router record");
                return -1;
            }
            vrf->enabled = true;
            vrf->vrid = vrid;
            vrf->kernel_table = kernel_table;
        }
        p = nl ? nl + 1 : end;
    }
    return 0;
}

static const char *socket_path_from_env(const char *env_name,
                                        const char *fallback,
                                        char *out,
                                        size_t out_size) {
    const char *env = getenv(env_name);

    if (!out || out_size == 0)
        return fallback;
    if (env && token_safe(env) && strlen(env) < out_size)
        snprintf(out, out_size, "%s", env);
    else
        snprintf(out, out_size, "%s", fallback);
    return out;
}

static void init_socket_paths(void) {
    (void)socket_path_from_env("NETLAB_RPD_SOCKET", RPD_SOCKET,
                               g_rpd_socket_path,
                               sizeof(g_rpd_socket_path));
    (void)socket_path_from_env("NETLAB_SWITCHD_SOCKET", SWITCHD_SOCKET,
                               g_switchd_socket_path,
                               sizeof(g_switchd_socket_path));
}

static bool find_ip_program(char *out, size_t out_size) {
    const char *env = getenv("NETLAB_RPD_IP_CMD");
    const char *paths[] = {
        "/sbin/ip",
        "/usr/sbin/ip",
        "/usr/bin/ip",
        "/bin/ip",
    };

    if (env && env[0] && token_safe(env) && access(env, X_OK) == 0) {
        snprintf(out, out_size, "%s", env);
        return true;
    }
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], X_OK) == 0) {
            snprintf(out, out_size, "%s", paths[i]);
            return true;
        }
    }
    if (out && out_size)
        out[0] = '\0';
    return false;
}

static s64 monotonic_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static bool frr_dynamic_config_open(void) {
    char err[192] = {0};

    return g_rpd.frr_config_enabled &&
           g_rpd.frr_runtime.start_gate_enabled &&
           g_rpd.fpm_programming_enabled &&
           g_rpd.fpm.enabled &&
           rpd_frr_runtime_preflight(&g_rpd.frr_runtime,
                                     err, sizeof(err)) == 0;
}

static bool frr_dynamic_config_open_cached(void) {
    return g_rpd.frr_config_enabled &&
           g_rpd.frr_runtime.start_gate_enabled &&
           g_rpd.fpm_programming_enabled &&
           g_rpd.fpm.enabled &&
           g_rpd.frr_runtime.preflight_ready;
}

static void append_gate_missing(char *buf, size_t size, const char *item) {
    size_t len;
    int n;

    if (!buf || size == 0 || !item || !item[0])
        return;
    len = strlen(buf);
    if (len >= size - 1)
        return;
    n = snprintf(buf + len, size - len, "%s%s",
                 len ? ", " : "", item);
    (void)n;
}

static void dynamic_gate_reason(char *buf, size_t size) {
    char missing[384] = {0};
    char runtime_err[192] = {0};

    if (!buf || size == 0)
        return;
    buf[0] = '\0';
    if (!g_rpd.frr_config_enabled)
        append_gate_missing(missing, sizeof(missing),
                            env_truthy("NETLAB_DISABLE_RPD_FRR_CONFIG") ?
                            "NETLAB_DISABLE_RPD_FRR_CONFIG=1" :
                            "FRR config writer disabled");
    if (!g_rpd.frr_runtime.start_gate_enabled)
        append_gate_missing(missing, sizeof(missing),
                            env_truthy("NETLAB_DISABLE_RPD_FRR_RUNTIME") ?
                            "NETLAB_DISABLE_RPD_FRR_RUNTIME=1" :
                            "FRR runtime starter disabled");
    if (!g_rpd.fpm_programming_enabled)
        append_gate_missing(missing, sizeof(missing),
                            env_truthy("NETLAB_DISABLE_RPD_FPM") ?
                            "NETLAB_DISABLE_RPD_FPM=1" :
                            "FPM listener requires FRR runtime or NETLAB_ENABLE_RPD_FPM=1");
    else if (!g_rpd.fpm.enabled)
        append_gate_missing(missing, sizeof(missing),
                            "FPM listener is not listening");
    if (!rpd_frr_runtime_program_present("zebra"))
        append_gate_missing(missing, sizeof(missing), "FRR zebra binary");
    if (!rpd_frr_runtime_program_present("ospfd"))
        append_gate_missing(missing, sizeof(missing), "FRR ospfd binary");
    if (!rpd_frr_runtime_program_present("bgpd"))
        append_gate_missing(missing, sizeof(missing), "FRR bgpd binary");
    if (rpd_frr_runtime_preflight(&g_rpd.frr_runtime,
                                  runtime_err, sizeof(runtime_err)) != 0 &&
        runtime_err[0])
        append_gate_missing(missing, sizeof(missing), runtime_err);

    if (missing[0]) {
        snprintf(buf, size, "missing gate(s): %s", missing);
    } else {
        snprintf(buf, size, "FRR runtime and FPM listener are open");
    }
}

static void dynamic_gate_reason_cached(char *buf, size_t size) {
    char missing[384] = {0};

    if (!buf || size == 0)
        return;
    buf[0] = '\0';
    if (!g_rpd.frr_config_enabled)
        append_gate_missing(missing, sizeof(missing),
                            env_truthy("NETLAB_DISABLE_RPD_FRR_CONFIG") ?
                            "NETLAB_DISABLE_RPD_FRR_CONFIG=1" :
                            "FRR config writer disabled");
    if (!g_rpd.frr_runtime.start_gate_enabled)
        append_gate_missing(missing, sizeof(missing),
                            env_truthy("NETLAB_DISABLE_RPD_FRR_RUNTIME") ?
                            "NETLAB_DISABLE_RPD_FRR_RUNTIME=1" :
                            "FRR runtime starter disabled");
    if (!g_rpd.fpm_programming_enabled)
        append_gate_missing(missing, sizeof(missing),
                            env_truthy("NETLAB_DISABLE_RPD_FPM") ?
                            "NETLAB_DISABLE_RPD_FPM=1" :
                            "FPM listener requires FRR runtime or NETLAB_ENABLE_RPD_FPM=1");
    else if (!g_rpd.fpm.enabled)
        append_gate_missing(missing, sizeof(missing),
                            "FPM listener is not listening");
    if (!g_rpd.frr_runtime.zebra_path[0])
        append_gate_missing(missing, sizeof(missing), "FRR zebra binary");
    if (!g_rpd.frr_runtime.ospfd_path[0])
        append_gate_missing(missing, sizeof(missing), "FRR ospfd binary");
    if (!g_rpd.frr_runtime.bgpd_path[0])
        append_gate_missing(missing, sizeof(missing), "FRR bgpd binary");
    if (!g_rpd.frr_runtime.preflight_ready &&
        g_rpd.frr_runtime.preflight_reason[0])
        append_gate_missing(missing, sizeof(missing),
                            g_rpd.frr_runtime.preflight_reason);

    if (missing[0]) {
        snprintf(buf, size, "missing gate(s): %s", missing);
    } else {
        snprintf(buf, size, "FRR runtime and FPM listener are open");
    }
}

static bool starts_with_n(const char *line, size_t len, const char *prefix) {
    size_t prefix_len;

    if (!line || !prefix)
        return false;
    prefix_len = strlen(prefix);
    return len >= prefix_len && memcmp(line, prefix, prefix_len) == 0;
}

static int send_text(nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
                     const char *fmt, ...) {
    va_list ap;
    va_list render_ap;
    int n;
    int rendered;
    nl_msg_hdr *resp;

    va_start(ap, fmt);
    va_copy(render_ap, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(render_ap);
        return -1;
    }
    if (n >= NETLAB_MAX_MSG)
        n = NETLAB_MAX_MSG - 1;

    resp = nl_msg_alloc((u32)n);
    if (!resp) {
        va_end(render_ap);
        return -1;
    }
    rendered = vsnprintf((char *)resp->payload, (size_t)n + 1,
                         fmt, render_ap);
    va_end(render_ap);
    if (rendered < 0) {
        nl_msg_free(resp);
        return -1;
    }
    if (rendered < n)
        n = rendered;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)n;
    nl_send(conn, resp);
    nl_msg_free(resp);
    return 0;
}

static void plan_stats(const char *payload, int payload_len,
                       rpd_plan_stats *stats) {
    const char *p;
    const char *end;

    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!payload || payload_len <= 0)
        return;
    p = payload;
    end = payload + payload_len;
    while (p < end) {
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);

        if (len >= 4 && strncmp(line, "rif ", 4) == 0)
            stats->rifs++;
        else if (len >= 4 && strncmp(line, "arp ", 4) == 0)
            stats->arp++;
        else if (len >= 9 && strncmp(line, "next-hop ", 9) == 0)
            stats->next_hops++;
        else if ((len >= 6 && strncmp(line, "route ", 6) == 0) ||
                 (len >= 17 && strncmp(line, "rib-static-route ", 17) == 0))
            stats->routes++;
        else if (len >= 5 && strncmp(line, "ecmp ", 5) == 0)
            stats->ecmp_groups++;
        else if (len >= 9 && strncmp(line, "protocol ", 9) == 0)
            stats->has_dynamic_protocol = true;
        p = nl ? nl + 1 : end;
    }
}

static bool plan_has_owner_objects(const char *payload, int payload_len) {
    rpd_plan_stats stats;

    plan_stats(payload, payload_len, &stats);
    return stats.rifs || stats.arp || stats.next_hops || stats.routes ||
           stats.ecmp_groups;
}

static bool frr_config_has_dynamic(const rpd_frr_config *cfg) {
    return cfg && (cfg->ospf_enabled || cfg->bgp_enabled || cfg->policies);
}

static bool frr_config_has_route_protocols(const rpd_frr_config *cfg) {
    return cfg && (cfg->ospf_enabled || cfg->bgp_enabled);
}

static bool rollback_owner_not_needed(const rpd_ctx *rpd, s32 owner_ec) {
    if (!rpd || owner_ec != NL_ERR_INVALID_VALUE ||
        !rpd->rollback_rib_available)
        return false;
    if (!frr_config_has_dynamic(&rpd->frr_intent) &&
        !frr_config_has_dynamic(&rpd->rollback_frr_intent))
        return false;
    return !plan_has_owner_objects(rpd->static_owner_plan,
                                   rpd->static_owner_plan_len) &&
           !plan_has_owner_objects(rpd->rollback_static_owner_plan,
                                   rpd->rollback_static_owner_plan_len);
}

static int copy_static_plan_filtered(const char *payload, int payload_len,
                                     char *out, size_t out_size,
                                     bool *stripped_dynamic,
                                     bool include_rib_static) {
    const char *p;
    const char *end;
    size_t off = 0;

    if (stripped_dynamic)
        *stripped_dynamic = false;
    if (!out || out_size == 0)
        return -1;
    out[0] = '\0';
    if (!payload || payload_len <= 0)
        return 0;
    p = payload;
    end = payload + payload_len;
    while (p < end) {
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) + 1 : (size_t)(end - line);

        if (starts_with_n(line, len, "protocol ") ||
            starts_with_n(line, len, "policy ") ||
            (!include_rib_static &&
             starts_with_n(line, len, "rib-static-route "))) {
            if (stripped_dynamic)
                *stripped_dynamic = true;
        } else {
            if (off + len >= out_size)
                return -1;
            memcpy(out + off, line, len);
            off += len;
            out[off] = '\0';
        }
        p = nl ? nl + 1 : end;
    }
    return (int)off;
}

static int copy_static_plan(const char *payload, int payload_len,
                            char *out, size_t out_size,
                            bool *stripped_dynamic) {
    return copy_static_plan_filtered(payload, payload_len, out, out_size,
                                     stripped_dynamic, false);
}

static int copy_static_rib_plan(const char *payload, int payload_len,
                                char *out, size_t out_size,
                                bool *stripped_dynamic) {
    return copy_static_plan_filtered(payload, payload_len, out, out_size,
                                     stripped_dynamic, true);
}

static void record_op_common(const char *action, const char *result, u64 tx_id,
                             const rpd_plan_stats *stats,
                             bool advance_update_id) {
    rpd_oplog_entry *entry = &g_rpd.oplog[g_rpd.oplog_head];

    memset(entry, 0, sizeof(*entry));
    if (advance_update_id)
        entry->update_id = ++g_rpd.fib_update_id;
    else
        entry->update_id = g_rpd.fib_update_id;
    entry->generation = g_rpd.generation;
    entry->tx_id = tx_id;
    snprintf(entry->action, sizeof(entry->action), "%s", action ? action : "-");
    snprintf(entry->result, sizeof(entry->result), "%s", result ? result : "-");
    entry->when = time(NULL);
    if (stats) {
        entry->rifs = stats->rifs;
        entry->arp = stats->arp;
        entry->next_hops = stats->next_hops;
        entry->routes = stats->routes;
        entry->ecmp_groups = stats->ecmp_groups;
        snprintf(entry->idempotency_key, sizeof(entry->idempotency_key),
                 "%s", stats->idempotency_key[0] ?
                 stats->idempotency_key : "-");
    }
    g_rpd.oplog_head = (g_rpd.oplog_head + 1) % RPD_OPLOG_MAX;
    if (g_rpd.oplog_count < RPD_OPLOG_MAX)
        g_rpd.oplog_count++;
}

static void record_op(const char *action, const char *result, u64 tx_id,
                      const rpd_plan_stats *stats) {
    record_op_common(action, result, tx_id, stats, true);
}

static void record_op_no_bump(const char *action, const char *result,
                              u64 tx_id, const rpd_plan_stats *stats) {
    record_op_common(action, result, tx_id, stats, false);
}

static void copy_attr_after(const char *text, const char *anchor,
                            const char *attr, char *out, size_t out_size,
                            const char *fallback) {
    char pattern[64];
    const char *p;
    const char *q;
    size_t len;

    if (!out || out_size == 0)
        return;
    snprintf(out, out_size, "%s", fallback ? fallback : "");
    if (!text || !attr)
        return;
    p = anchor ? strstr(text, anchor) : text;
    if (!p)
        return;
    snprintf(pattern, sizeof(pattern), "%s=\"", attr);
    p = strstr(p, pattern);
    if (!p)
        return;
    p += strlen(pattern);
    q = strchr(p, '"');
    if (!q)
        return;
    len = (size_t)(q - p);
    if (len >= out_size)
        len = out_size - 1;
    memcpy(out, p, len);
    out[len] = '\0';
}

static bool attr_nonzero_after(const char *text, const char *anchor,
                               const char *attr) {
    char value[32];
    char *end = NULL;
    long n;

    copy_attr_after(text, anchor, attr, value, sizeof(value), "0");
    n = strtol(value, &end, 10);
    return end != value && n != 0;
}

static void set_drift_state(const char *state, const char *reason) {
    snprintf(g_rpd.drift_state, sizeof(g_rpd.drift_state), "%s",
             state ? state : "unknown");
    snprintf(g_rpd.drift_reason, sizeof(g_rpd.drift_reason), "%s",
             reason ? reason : "");
}

static u64 attr_u64_after(const char *text, const char *anchor,
                          const char *attr, u64 fallback) {
    char value[32];
    char *end = NULL;
    unsigned long long n;

    copy_attr_after(text, anchor, attr, value, sizeof(value), "");
    if (!value[0])
        return fallback;
    n = strtoull(value, &end, 10);
    if (!end || *end)
        return fallback;
    return (u64)n;
}

static int attr_int_after(const char *text, const char *anchor,
                          const char *attr, int fallback) {
    char value[32];
    char *end = NULL;
    long n;

    copy_attr_after(text, anchor, attr, value, sizeof(value), "");
    if (!value[0])
        return fallback;
    n = strtol(value, &end, 10);
    if (!end || *end || n < 0 || n > 2147483647L)
        return fallback;
    return (int)n;
}

static const char *fib_table_anchor(const char *body, const char *table) {
    const char *anchor = body;

    if (!body || !table || !table[0])
        return NULL;
    while ((anchor = strstr(anchor, "<fib-table ")) != NULL) {
        char candidate[RPD_RIB_TABLE_LEN];

        copy_attr_after(anchor, NULL, "table", candidate,
                        sizeof(candidate), "");
        if (strcmp(candidate, table) == 0)
            return anchor;
        anchor += strlen("<fib-table ");
    }
    return NULL;
}

static void set_fib_sync_state(const char *state, const char *reason) {
    snprintf(g_rpd.fib_sync_state, sizeof(g_rpd.fib_sync_state), "%s",
             state ? state : "unknown");
    snprintf(g_rpd.fib_sync_reason, sizeof(g_rpd.fib_sync_reason), "%s",
             reason ? reason : "");
}

static void update_fib_live_from_response(const char *body) {
    const char *anchor = "<live-eligibility";

    if (!body || !strstr(body, anchor))
        return;
    copy_attr_after(body, anchor, "status", g_rpd.switchd_fib_live_status,
                    sizeof(g_rpd.switchd_fib_live_status), "unknown");
    copy_attr_after(body, anchor, "gate", g_rpd.switchd_fib_live_gate,
                    sizeof(g_rpd.switchd_fib_live_gate), "unknown");
    copy_attr_after(body, anchor, "live-ready",
                    g_rpd.switchd_fib_live_ready,
                    sizeof(g_rpd.switchd_fib_live_ready), "false");
    copy_attr_after(body, anchor, "missing", g_rpd.switchd_fib_live_missing,
                    sizeof(g_rpd.switchd_fib_live_missing), "-");
    copy_attr_after(body, anchor, "reason", g_rpd.switchd_fib_live_reason,
                    sizeof(g_rpd.switchd_fib_live_reason), "-");
    g_rpd.switchd_fib_dynamic_routes =
        attr_int_after(body, anchor, "dynamic-routes",
                       g_rpd.switchd_fib_dynamic_routes);
    g_rpd.switchd_fib_owner_routes =
        attr_int_after(body, anchor, "owner-routes",
                       g_rpd.switchd_fib_owner_routes);
    g_rpd.switchd_fib_ifindex_rifs =
        attr_int_after(body, anchor, "ifindex-rifs",
                       g_rpd.switchd_fib_ifindex_rifs);
}

static int expected_fib_route_count_locked(const rpd_rib *rib,
                                           int *routes_out) {
    int routes = rpd_rib_fib_route_count(rib);

    if (routes < 0)
        return -1;
    if (routes_out)
        *routes_out = routes;
    return 0;
}

static void set_churn_state(const char *state, const char *reason) {
    snprintf(g_rpd.churn_state, sizeof(g_rpd.churn_state), "%s",
             state ? state : "unknown");
    snprintf(g_rpd.churn_reason, sizeof(g_rpd.churn_reason), "%s",
             reason ? reason : "");
}

static void set_fpm_rif_map_status(rpd_ctx *rpd, const char *state,
                                   const char *reason) {
    if (!rpd)
        return;
    snprintf(rpd->fpm_rif_map_status, sizeof(rpd->fpm_rif_map_status), "%s",
             state ? state : "unknown");
    snprintf(rpd->fpm_rif_map_reason, sizeof(rpd->fpm_rif_map_reason), "%s",
             reason ? reason : "-");
}

static int parse_ifindex_token(const char *text) {
    const char *p = text;
    char *end = NULL;
    long n;

    if (!p || !p[0])
        return 0;
    if (strncmp(p, "ifindex", 7) == 0)
        p += 7;
    n = strtol(p, &end, 10);
    if (!end || *end || n <= 0 || n > 2147483647L)
        return 0;
    return (int)n;
}

static int fpm_rif_map_add(rpd_ctx *rpd, int ifindex, const char *rif,
                           const char *source) {
    if (!rpd || ifindex <= 0 || !rif || !token_safe(rif) ||
        strlen(rif) >= sizeof(rpd->fpm_rif_map[0].rif) ||
        (source && strlen(source) >= sizeof(rpd->fpm_rif_map[0].source)))
        return -1;
    for (int i = 0; i < rpd->fpm_rif_map_entries; i++) {
        if (rpd->fpm_rif_map[i].ifindex == ifindex) {
            snprintf(rpd->fpm_rif_map[i].rif,
                     sizeof(rpd->fpm_rif_map[i].rif), "%s", rif);
            snprintf(rpd->fpm_rif_map[i].source,
                     sizeof(rpd->fpm_rif_map[i].source), "%s",
                     source ? source : "env");
            return 0;
        }
    }
    if (rpd->fpm_rif_map_entries >= RPD_FPM_RIF_MAP_MAX)
        return -1;
    rpd->fpm_rif_map[rpd->fpm_rif_map_entries].ifindex = ifindex;
    snprintf(rpd->fpm_rif_map[rpd->fpm_rif_map_entries].rif,
             sizeof(rpd->fpm_rif_map[rpd->fpm_rif_map_entries].rif),
             "%s", rif);
    snprintf(rpd->fpm_rif_map[rpd->fpm_rif_map_entries].source,
             sizeof(rpd->fpm_rif_map[rpd->fpm_rif_map_entries].source),
             "%s", source ? source : "env");
    rpd->fpm_rif_map_entries++;
    return 0;
}

static const char *fpm_rif_map_lookup(const rpd_ctx *rpd, int ifindex) {
    if (!rpd || ifindex <= 0)
        return NULL;
    for (int i = 0; i < rpd->fpm_rif_map_entries; i++)
        if (rpd->fpm_rif_map[i].ifindex == ifindex)
            return rpd->fpm_rif_map[i].rif;
    return NULL;
}

static bool append_replaced(char *out, size_t out_size, size_t *off,
                            const char *src, const char *pattern,
                            const char *replacement) {
    size_t pattern_len;
    size_t replacement_len;
    const char *p;
    const char *match;

    if (!out || !off || !src || !pattern || !replacement)
        return false;
    pattern_len = strlen(pattern);
    replacement_len = strlen(replacement);
    if (pattern_len == 0)
        return false;
    p = src;
    while ((match = strstr(p, pattern)) != NULL) {
        size_t literal = (size_t)(match - p);

        if (*off + literal + replacement_len >= out_size)
            return false;
        memcpy(out + *off, p, literal);
        *off += literal;
        memcpy(out + *off, replacement, replacement_len);
        *off += replacement_len;
        p = match + pattern_len;
    }
    if (*off + strlen(p) >= out_size)
        return false;
    strcpy(out + *off, p);
    *off += strlen(p);
    return true;
}

static bool replace_all_token(const char *in, char *out, size_t out_size,
                              const char *pattern,
                              const char *replacement) {
    size_t off = 0;

    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    return append_replaced(out, out_size, &off, in, pattern, replacement);
}

static bool replace_all_token_swap(char **current, char **scratch,
                                   const char *pattern,
                                   const char *replacement) {
    char *swap;

    if (!current || !*current || !scratch)
        return false;
    if (!*scratch) {
        *scratch = malloc(NETLAB_MAX_MSG + 1U);
        if (!*scratch)
            return false;
    }
    if (!replace_all_token(*current, *scratch, NETLAB_MAX_MSG + 1U,
                           pattern, replacement))
        return false;
    swap = *current;
    *current = *scratch;
    *scratch = swap;
    return true;
}

static int normalize_fpm_rifs_alloc_locked(rpd_ctx *rpd,
                                           const char *payload,
                                           int payload_len, char **out,
                                           bool *changed) {
    char *cur = NULL;
    char *next = NULL;
    int normalized_len;

    if (changed)
        *changed = false;
    if (out)
        *out = NULL;
    if (!payload || payload_len < 0 || !out ||
        payload_len >= NETLAB_MAX_MSG)
        return -1;
    cur = malloc(NETLAB_MAX_MSG + 1U);
    if (!cur)
        goto error;
    if (rpd && strcmp(rpd->fpm_rif_map_status, "error") == 0)
        goto error;
    memcpy(cur, payload, (size_t)payload_len);
    cur[payload_len] = '\0';
    for (int i = 0; rpd && i < rpd->fpm_rif_map_entries; i++) {
        char pattern[32];
        char replacement[96];
        bool hit = false;

        snprintf(pattern, sizeof(pattern), "@ifindex%d",
                 rpd->fpm_rif_map[i].ifindex);
        snprintf(replacement, sizeof(replacement), "@%s",
                 rpd->fpm_rif_map[i].rif);
        if (strstr(cur, pattern)) {
            if (!replace_all_token_swap(&cur, &next,
                                        pattern, replacement))
                goto error;
            hit = true;
        }
        snprintf(pattern, sizeof(pattern), " rif=ifindex%d",
                 rpd->fpm_rif_map[i].ifindex);
        snprintf(replacement, sizeof(replacement), " rif=%s",
                 rpd->fpm_rif_map[i].rif);
        if (strstr(cur, pattern)) {
            if (!replace_all_token_swap(&cur, &next,
                                        pattern, replacement))
                goto error;
            hit = true;
        }
        snprintf(pattern, sizeof(pattern), " egress-rif=ifindex%d",
                 rpd->fpm_rif_map[i].ifindex);
        snprintf(replacement, sizeof(replacement), " egress-rif=%s",
                 rpd->fpm_rif_map[i].rif);
        if (strstr(cur, pattern)) {
            if (!replace_all_token_swap(&cur, &next,
                                        pattern, replacement))
                goto error;
            hit = true;
        }
        if (hit) {
            rpd->fpm_rif_map_hits++;
            if (changed)
                *changed = true;
        }
    }
    normalized_len = (int)strlen(cur);
    free(next);
    *out = cur;
    return normalized_len;

error:
    free(cur);
    free(next);
    return -1;
}

static void init_fpm_rif_map(rpd_ctx *rpd) {
    const char *env = getenv("NETLAB_RPD_FPM_IFINDEX_RIF_MAP");
    int invalid = 0;

    if (!rpd)
        return;
    rpd->fpm_rif_map_entries = 0;
    rpd->fpm_rif_map_hits = 0;
    if (env && env[0]) {
        char *buf = NULL;
        char *save = NULL;
        char *tok;

        if (strlen(env) > RPD_FPM_RIF_MAP_TEXT_MAX) {
            invalid++;
        } else {
            buf = strdup(env);
            if (!buf) {
                invalid++;
            }
        }
        if (buf) {
            tok = strtok_r(buf, ",", &save);
            while (tok) {
                char *eq = strchr(tok, '=');
                int ifindex = 0;

                if (eq) {
                    *eq++ = '\0';
                    ifindex = parse_ifindex_token(tok);
                }
                if (ifindex <= 0 || !eq || !token_safe(eq) ||
                    fpm_rif_map_add(rpd, ifindex, eq, "env") != 0)
                    invalid++;
                tok = strtok_r(NULL, ",", &save);
            }
            free(buf);
        }
    }
    if (rpd->linux_arp_ifname[0] && rpd->linux_arp_rif[0]) {
        unsigned int ifindex = if_nametoindex(rpd->linux_arp_ifname);

        if (ifindex > 0 &&
            !fpm_rif_map_lookup(rpd, (int)ifindex) &&
            token_safe(rpd->linux_arp_rif)) {
            if (fpm_rif_map_add(rpd, (int)ifindex,
                                rpd->linux_arp_rif, "tap") != 0)
                invalid++;
        }
    }
    if (invalid > 0) {
        set_fpm_rif_map_status(rpd, "error",
                               "one or more FPM ifindex map entries invalid");
    } else if (rpd->fpm_rif_map_entries > 0) {
        set_fpm_rif_map_status(rpd, "ok",
                               "FPM ifindex to RIF map active");
    } else {
        set_fpm_rif_map_status(rpd, "empty",
                               "no FPM ifindex to RIF map entries");
    }
}

static bool churn_gate_allow_locked(char *err, size_t err_size) {
    s64 now_ms;

    if (!g_rpd.churn_gate_enabled)
        return true;
    now_ms = monotonic_ms();
    if (g_rpd.churn_window_start_ms <= 0 ||
        now_ms - g_rpd.churn_window_start_ms >=
        g_rpd.churn_window_ms) {
        g_rpd.churn_window_start_ms = now_ms;
        g_rpd.churn_used = 0;
        set_churn_state("ok", "route churn within configured gate");
    }
    if (g_rpd.churn_used >= g_rpd.churn_max_updates) {
        g_rpd.churn_drops++;
        g_rpd.last_churn_drop = time(NULL);
        set_churn_state("limited",
                        "dynamic route update rate exceeded churn gate");
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "route churn gate limited dynamic route updates");
        return false;
    }
    g_rpd.churn_used++;
    return true;
}

static void update_fib_sync_from_response(const char *body, s32 ec,
                                          const char *fallback_reason) {
    const char *anchor = body && strstr(body, "<fib-snapshot-commit") ?
        "<fib-snapshot-commit" : "<fib-batch-apply";

    g_rpd.last_fib_ec = ec;
    if (ec != 0) {
        set_fib_sync_state("error", fallback_reason ?
                           fallback_reason :
                           "switchd FIB batch returned an error");
        return;
    }
    if (!body || !strstr(body, anchor)) {
        set_fib_sync_state("unknown",
                           "switchd FIB batch response was not recognized");
        return;
    }
    copy_attr_after(body, anchor, "status", g_rpd.switchd_fib_status,
                    sizeof(g_rpd.switchd_fib_status), "unknown");
    g_rpd.switchd_fib_routes =
        attr_int_after(body, anchor, "routes", g_rpd.switchd_fib_routes);
    g_rpd.switchd_fib_generation =
        attr_u64_after(body, anchor, "generation",
                       g_rpd.switchd_fib_generation);
    g_rpd.switchd_fib_update_id =
        attr_u64_after(body, anchor, "fib-update-id",
                       g_rpd.switchd_fib_update_id);
    update_fib_live_from_response(body);
    g_rpd.last_fib_sync = time(NULL);
    if (strcmp(g_rpd.switchd_fib_status, "ok") == 0)
        set_fib_sync_state("ok", "switchd accepted rpd FIB batch");
    else
        set_fib_sync_state("unknown",
                           "switchd FIB batch status was not ok");
}

static int reconcile_switchd_fib_locked(const char *reason) {
    char resp[65536];
    s32 ec = NL_ERR_DAEMON_UNREACHABLE;
    int resp_len;
    const char *reconcile_anchor = "<fib-reconcile";
    const char *readback_anchor = "<fib-readback";
    char reconcile_status[32] = {0};
    int readback_routes;
    int expected_routes;
    const char *vrf_anchor = NULL;

    resp_len = nl_rpc_call_ex(g_switchd_socket_path, NL_DAEMON_RPD,
                              NL_DAEMON_SWITCHD,
                              NL_SWITCHD_RPD_FIB_RECONCILE,
                              g_rpd.fib_update_id,
                              NULL, 0, (u8 *)resp,
                              (int)sizeof(resp) - 1,
                              RPD_SWITCHD_FIB_RPC_TIMEOUT_MS, &ec);
    g_rpd.last_fib_ec = ec;
    if (resp_len < 0) {
        set_fib_sync_state("pending",
                           "switchd FIB reconcile RPC is unavailable");
        return -1;
    }
    resp[resp_len] = '\0';
    g_rpd.last_fib_readback = time(NULL);
    if (ec != 0 || !strstr(resp, reconcile_anchor) ||
        !strstr(resp, readback_anchor)) {
        set_fib_sync_state("error",
                           reason ? reason :
                           "switchd FIB reconcile returned an error");
        return -1;
    }
    copy_attr_after(resp, reconcile_anchor, "status", reconcile_status,
                    sizeof(reconcile_status), "unknown");
    if (strcmp(reconcile_status, "ok") != 0) {
        set_fib_sync_state("error",
                           "switchd FIB reconcile status was not ok");
        return -1;
    }
    copy_attr_after(resp, readback_anchor, "status",
                    g_rpd.switchd_fib_status,
                    sizeof(g_rpd.switchd_fib_status), "unknown");
    readback_routes = attr_int_after(resp, readback_anchor, "routes", -1);
    if (readback_routes >= 0)
        g_rpd.switchd_fib_routes = readback_routes;
    g_rpd.switchd_fib_generation =
        attr_u64_after(resp, readback_anchor, "generation",
                       g_rpd.switchd_fib_generation);
    g_rpd.switchd_fib_update_id =
        attr_u64_after(resp, readback_anchor, "fib-update-id",
                       g_rpd.switchd_fib_update_id);
    update_fib_live_from_response(resp);
    if (expected_fib_route_count_locked(&g_rpd.rib,
                                        &expected_routes) != 0) {
        set_fib_sync_state("error",
                           "failed to compile rpd FIB route count");
        return -1;
    }
    if (readback_routes < 0) {
        set_fib_sync_state("error",
                           "switchd FIB reconcile omitted route count");
        return -1;
    }
    if (strcmp(g_rpd.switchd_fib_status, "ok") == 0 &&
        g_rpd.switchd_fib_generation == g_rpd.generation &&
        g_rpd.switchd_fib_update_id == g_rpd.fib_update_id &&
        readback_routes == expected_routes) {
        if (g_rpd.vrf.enabled) {
            char vrf_state[32];
            int vrf_routes;
            int expected_vrf_routes;
            u64 vrf_generation;
            u64 vrf_update_id;

            vrf_anchor = fib_table_anchor(resp, g_rpd.vrf.table);
            if (!vrf_anchor ||
                expected_fib_route_count_locked(&g_rpd.vrf_rib,
                                                &expected_vrf_routes) != 0) {
                set_fib_sync_state("drift",
                                   "switchd FIB reconcile omitted active VRF table");
                return -1;
            }
            copy_attr_after(vrf_anchor, NULL, "state", vrf_state,
                            sizeof(vrf_state), "unknown");
            vrf_routes = attr_int_after(vrf_anchor, NULL, "routes", -1);
            vrf_generation = attr_u64_after(vrf_anchor, NULL, "generation", 0);
            vrf_update_id = attr_u64_after(vrf_anchor, NULL,
                                           "fib-update-id", 0);
            if (strcmp(vrf_state, "applied") != 0 ||
                vrf_routes != expected_vrf_routes ||
                vrf_generation != g_rpd.generation ||
                vrf_update_id != g_rpd.fib_update_id) {
                char vrf_reason[224];

                snprintf(vrf_reason, sizeof(vrf_reason),
                         "switchd FIB reconcile table %s does not match "
                         "rpd expected generation=%llu update=%llu routes=%d",
                         g_rpd.vrf.table,
                         (unsigned long long)g_rpd.generation,
                         (unsigned long long)g_rpd.fib_update_id,
                         expected_vrf_routes);
                set_fib_sync_state("drift", vrf_reason);
                return -1;
            }
        }
        set_fib_sync_state("ok", "switchd FIB reconcile matches rpd state");
        return 0;
    }
    if (readback_routes != expected_routes) {
        char route_reason[192];

        snprintf(route_reason, sizeof(route_reason),
                 "switchd FIB reconcile route count %d does not match "
                 "rpd expected %d", readback_routes, expected_routes);
        set_fib_sync_state("drift", route_reason);
    } else {
        set_fib_sync_state("drift",
                           "switchd FIB reconcile generation does not match rpd");
    }
    return -1;
}

static void fib_program_task_release(rpd_fib_program_task *task) {
    if (!task)
        return;
    free(task->payload);
    memset(task, 0, sizeof(*task));
}

static bool fib_program_work_pending_locked(const rpd_ctx *rpd) {
    if (!rpd)
        return false;
    return rpd->fib_program_inflight || rpd->fib_program_queue_count > 0 ||
           rpd->fpm_sync_batch[0].updates > 0 ||
           rpd->fpm_sync_batch[1].updates > 0;
}

static int fib_program_enqueue_locked(rpd_ctx *rpd, rpd_rib *rib,
                                      rpd_fib_program_kind kind,
                                      const char *reason,
                                      const char *batch, int batch_len,
                                      int updates) {
    rpd_fib_program_task *task;
    int slot;
    int expected_routes;

    if (!rpd || !rib ||
        (kind != RPD_FIB_PROGRAM_APPLY &&
         kind != RPD_FIB_PROGRAM_SNAPSHOT) ||
        !batch || batch_len <= 0 ||
        !rpd->fib_program_accepting || rpd->fib_program_stop_requested) {
        set_fib_sync_state("error", "invalid rpd FIB pipeline enqueue");
        return -1;
    }
    if (expected_fib_route_count_locked(rib, &expected_routes) != 0) {
        set_fib_sync_state("error", "failed to compile rpd FIB route count");
        return -1;
    }
    if (rpd->fib_program_queue_count >= RPD_FIB_PIPELINE_QUEUE_MAX) {
        rpd->fib_program_backpressure++;
        snprintf(rpd->fib_program_last_error,
                 sizeof(rpd->fib_program_last_error),
                 "FIB programmer queue is full");
        set_fib_sync_state("backpressure",
                           "FIB programmer queue is full; batch retained");
        return -1;
    }
    slot = (rpd->fib_program_queue_head + rpd->fib_program_queue_count) %
        RPD_FIB_PIPELINE_QUEUE_MAX;
    task = &rpd->fib_program_queue[slot];
    memset(task, 0, sizeof(*task));
    task->kind = kind;
    task->payload = malloc((size_t)batch_len);
    if (!task->payload) {
        snprintf(rpd->fib_program_last_error,
                 sizeof(rpd->fib_program_last_error),
                 "FIB programmer payload allocation failed");
        set_fib_sync_state("error", rpd->fib_program_last_error);
        return -1;
    }
    memcpy(task->payload, batch, (size_t)batch_len);
    task->payload_len = batch_len;
    task->expected_routes = expected_routes;
    task->updates = updates;
    task->generation = rpd->generation;
    task->fib_update_id = rpd->fib_update_id;
    task->queued_ms = monotonic_ms();
    snprintf(task->table, sizeof(task->table), "%s", rib->table);
    snprintf(task->reason, sizeof(task->reason), "%s",
             reason && reason[0] ? reason : "fib-sync");
    rpd->fib_program_queue_count++;
    if (rpd->fib_program_queue_count > rpd->fib_program_queue_high_water)
        rpd->fib_program_queue_high_water = rpd->fib_program_queue_count;
    rpd->fib_program_enqueued++;
    set_fib_sync_state("queued", "FIB batch queued for switchd programming");
    pthread_cond_signal(&rpd->fib_program_cond);
    return 0;
}

static int fib_program_enqueue_reconcile_locked(rpd_ctx *rpd,
                                                const char *reason) {
    rpd_fib_program_task *task;
    int slot;
    int expected_routes;

    if (!rpd || !rpd->fib_program_accepting ||
        rpd->fib_program_stop_requested)
        return -1;
    for (int i = 0; i < rpd->fib_program_queue_count; i++) {
        int queued = (rpd->fib_program_queue_head + i) %
            RPD_FIB_PIPELINE_QUEUE_MAX;

        if (rpd->fib_program_queue[queued].kind ==
            RPD_FIB_PROGRAM_RECONCILE) {
            rpd->fib_program_coalesced_updates++;
            return 0;
        }
    }
    if (expected_fib_route_count_locked(&rpd->rib, &expected_routes) != 0 ||
        rpd->fib_program_queue_count >= RPD_FIB_PIPELINE_QUEUE_MAX) {
        rpd->fib_program_backpressure++;
        return -1;
    }
    slot = (rpd->fib_program_queue_head + rpd->fib_program_queue_count) %
        RPD_FIB_PIPELINE_QUEUE_MAX;
    task = &rpd->fib_program_queue[slot];
    memset(task, 0, sizeof(*task));
    task->kind = RPD_FIB_PROGRAM_RECONCILE;
    task->expected_routes = expected_routes;
    task->generation = rpd->generation;
    task->fib_update_id = rpd->fib_update_id;
    task->queued_ms = monotonic_ms();
    snprintf(task->table, sizeof(task->table), "%s", rpd->rib.table);
    snprintf(task->reason, sizeof(task->reason), "%s",
             reason && reason[0] ? reason : "periodic-reconcile");
    rpd->fib_program_queue_count++;
    if (rpd->fib_program_queue_count > rpd->fib_program_queue_high_water)
        rpd->fib_program_queue_high_water = rpd->fib_program_queue_count;
    rpd->fib_program_enqueued++;
    pthread_cond_signal(&rpd->fib_program_cond);
    return 0;
}

static u64 fib_snapshot_digest(const char *data, size_t length) {
    u64 digest = RPD_FIB_SNAPSHOT_DIGEST_INIT;

    for (size_t i = 0; data && i < length; i++) {
        digest ^= (u8)data[i];
        digest *= RPD_FIB_SNAPSHOT_DIGEST_PRIME;
    }
    return digest;
}

static int fib_snapshot_part_span(const char *payload, size_t payload_len,
                                  size_t offset, size_t *span_out,
                                  int *routes_out) {
    size_t span;
    size_t cursor = 0;
    int routes = 0;

    if (!payload || !span_out || !routes_out || offset >= payload_len)
        return -1;
    span = payload_len - offset;
    if (span > RPD_FIB_SNAPSHOT_PART_DATA_MAX) {
        span = RPD_FIB_SNAPSHOT_PART_DATA_MAX;
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
            routes++;
        cursor += line_len + 1;
    }
    *span_out = span;
    *routes_out = routes;
    return 0;
}

static int fib_snapshot_rpc_call(u32 method, u64 tx_id,
                                 const char *payload, int payload_len,
                                 char *resp, size_t resp_size, s32 *ec) {
    int resp_len;

    if (!payload || payload_len <= 0 || !resp || resp_size < 2 || !ec)
        return -1;
    *ec = NL_ERR_DAEMON_UNREACHABLE;
    resp_len = nl_rpc_call_ex(g_switchd_socket_path, NL_DAEMON_RPD,
                              NL_DAEMON_SWITCHD, method, tx_id,
                              (const u8 *)payload, payload_len,
                              (u8 *)resp, (int)resp_size - 1,
                              RPD_SWITCHD_FIB_RPC_TIMEOUT_MS, ec);
    if (resp_len >= 0)
        resp[resp_len] = '\0';
    else
        resp[0] = '\0';
    return resp_len;
}

static bool fib_snapshot_step_ack(const char *resp, s32 ec,
                                  const char *anchor) {
    char status[32];

    if (ec != 0 || !resp || !anchor || !strstr(resp, anchor))
        return false;
    copy_attr_after(resp, anchor, "status", status, sizeof(status),
                    "missing");
    return strcmp(status, "ok") == 0;
}

static int fib_snapshot_control_payload(char *buf, size_t buf_size,
                                        const char *operation,
                                        const rpd_fib_program_task *task,
                                        int parts, size_t bytes,
                                        u64 digest) {
    int n;

    if (!buf || buf_size == 0 || !operation || !task)
        return -1;
    n = snprintf(buf, buf_size,
                 "fib-snapshot-%s table=%s generation=%llu "
                 "fib-update-id=%llu routes=%d parts=%d bytes=%llu "
                 "digest=%llu",
                 operation, task->table,
                 (unsigned long long)task->generation,
                 (unsigned long long)task->fib_update_id,
                 task->expected_routes, parts,
                 (unsigned long long)bytes,
                 (unsigned long long)digest);
    return n < 0 || (size_t)n >= buf_size ? -1 : n;
}

static void fib_snapshot_best_effort_abort(
        const rpd_fib_program_task *task, u64 tx_id, int parts,
        size_t bytes, u64 digest) {
    char request[512];
    char response[4096];
    s32 ec;
    int request_len;

    request_len = fib_snapshot_control_payload(
        request, sizeof(request), "abort", task, parts, bytes, digest);
    if (request_len < 0)
        return;
    (void)fib_snapshot_rpc_call(NL_SWITCHD_RPD_FIB_SNAPSHOT_ABORT,
                                tx_id, request, request_len,
                                response, sizeof(response), &ec);
}

static int fib_program_snapshot_rpc(const rpd_fib_program_task *task,
                                    u64 tx_id, char *resp,
                                    size_t resp_size, s32 *ec) {
    char control[512];
    char step_resp[4096];
    size_t offset = 0;
    u64 digest;
    int parts = 0;
    int counted_routes = 0;
    int control_len;
    int resp_len;

    if (!task || !task->payload || task->payload_len <= 0 ||
        !resp || resp_size < 2 || !ec)
        return -1;
    while (offset < (size_t)task->payload_len) {
        size_t span;
        int routes;

        if (fib_snapshot_part_span(task->payload,
                                   (size_t)task->payload_len, offset,
                                   &span, &routes) != 0) {
            *ec = NL_ERR_MALFORMED_REQUEST;
            snprintf(resp, resp_size,
                     "<fib-snapshot-client status=\"invalid\" "
                     "reason=\"record exceeds part boundary\"/>");
            return (int)strlen(resp);
        }
        counted_routes += routes;
        parts++;
        offset += span;
    }
    if (parts <= 0 || counted_routes != task->expected_routes) {
        *ec = NL_ERR_MALFORMED_REQUEST;
        snprintf(resp, resp_size,
                 "<fib-snapshot-client status=\"invalid\" "
                 "reason=\"route count mismatch\"/>");
        return (int)strlen(resp);
    }
    digest = fib_snapshot_digest(task->payload, (size_t)task->payload_len);
    control_len = fib_snapshot_control_payload(
        control, sizeof(control), "begin", task, parts,
        (size_t)task->payload_len, digest);
    if (control_len < 0) {
        *ec = NL_ERR_MALFORMED_REQUEST;
        return -1;
    }
    resp_len = fib_snapshot_rpc_call(NL_SWITCHD_RPD_FIB_SNAPSHOT_BEGIN,
                                     tx_id, control, control_len,
                                     step_resp, sizeof(step_resp), ec);
    if (resp_len < 0 ||
        !fib_snapshot_step_ack(step_resp, *ec, "<fib-snapshot-begin")) {
        if (resp_len >= 0)
            snprintf(resp, resp_size, "%s", step_resp);
        fib_snapshot_best_effort_abort(task, tx_id, parts,
                                       (size_t)task->payload_len, digest);
        return resp_len;
    }

    offset = 0;
    for (int part = 0; part < parts; part++) {
        char *request;
        size_t span;
        size_t request_size;
        int routes;
        int header_len;
        int request_len;

        if (fib_snapshot_part_span(task->payload,
                                   (size_t)task->payload_len, offset,
                                   &span, &routes) != 0) {
            *ec = NL_ERR_MALFORMED_REQUEST;
            fib_snapshot_best_effort_abort(task, tx_id, parts,
                                           (size_t)task->payload_len, digest);
            return -1;
        }
        request_size = span + 1024u;
        request = malloc(request_size);
        if (!request) {
            *ec = NL_ERR_RPC_BUSY;
            fib_snapshot_best_effort_abort(task, tx_id, parts,
                                           (size_t)task->payload_len, digest);
            return -1;
        }
        header_len = snprintf(
            request, request_size,
            "fib-snapshot-part table=%s generation=%llu fib-update-id=%llu "
            "routes=%d parts=%d bytes=%llu digest=%llu part=%d "
            "offset=%llu part-bytes=%llu part-routes=%d\n",
            task->table, (unsigned long long)task->generation,
            (unsigned long long)task->fib_update_id,
            task->expected_routes, parts,
            (unsigned long long)task->payload_len,
            (unsigned long long)digest, part,
            (unsigned long long)offset, (unsigned long long)span, routes);
        if (header_len < 0 || (size_t)header_len + span >= request_size) {
            free(request);
            *ec = NL_ERR_MALFORMED_REQUEST;
            fib_snapshot_best_effort_abort(task, tx_id, parts,
                                           (size_t)task->payload_len, digest);
            return -1;
        }
        memcpy(request + header_len, task->payload + offset, span);
        request_len = header_len + (int)span;
        request[request_len] = '\0';
        resp_len = fib_snapshot_rpc_call(
            NL_SWITCHD_RPD_FIB_SNAPSHOT_PART, tx_id,
            request, request_len, step_resp, sizeof(step_resp), ec);
        free(request);
        if (resp_len < 0 ||
            !fib_snapshot_step_ack(step_resp, *ec,
                                   "<fib-snapshot-part")) {
            if (resp_len >= 0)
                snprintf(resp, resp_size, "%s", step_resp);
            fib_snapshot_best_effort_abort(task, tx_id, parts,
                                           (size_t)task->payload_len, digest);
            return resp_len;
        }
        offset += span;
    }

    control_len = fib_snapshot_control_payload(
        control, sizeof(control), "commit", task, parts,
        (size_t)task->payload_len, digest);
    if (control_len < 0) {
        *ec = NL_ERR_MALFORMED_REQUEST;
        fib_snapshot_best_effort_abort(task, tx_id, parts,
                                       (size_t)task->payload_len, digest);
        return -1;
    }
    resp_len = fib_snapshot_rpc_call(NL_SWITCHD_RPD_FIB_SNAPSHOT_COMMIT,
                                     tx_id, control, control_len,
                                     resp, resp_size, ec);
    if (resp_len < 0 || *ec != 0)
        fib_snapshot_best_effort_abort(task, tx_id, parts,
                                       (size_t)task->payload_len, digest);
    return resp_len;
}

static int fib_program_rpc(const rpd_fib_program_task *task,
                           char *resp, size_t resp_size, s32 *ec) {
    u64 tx_id;
    int resp_len;

    if (!task || !resp || resp_size < 2 || !ec ||
        ((task->kind == RPD_FIB_PROGRAM_APPLY ||
          task->kind == RPD_FIB_PROGRAM_SNAPSHOT) &&
         (!task->payload || task->payload_len <= 0)))
        return -1;
    tx_id = task->fib_update_id ? task->fib_update_id : task->generation + 1;
    if (task->kind == RPD_FIB_PROGRAM_SNAPSHOT)
        return fib_program_snapshot_rpc(task, tx_id, resp, resp_size, ec);
    *ec = NL_ERR_DAEMON_UNREACHABLE;
    resp_len = nl_rpc_call_ex(g_switchd_socket_path, NL_DAEMON_RPD,
                              NL_DAEMON_SWITCHD,
                              task->kind == RPD_FIB_PROGRAM_RECONCILE ?
                                  NL_SWITCHD_RPD_FIB_RECONCILE :
                                  NL_SWITCHD_RPD_FIB_APPLY,
                              tx_id,
                              (const u8 *)task->payload,
                              task->kind == RPD_FIB_PROGRAM_APPLY ?
                                  task->payload_len : 0,
                              (u8 *)resp, (int)resp_size - 1,
                              RPD_SWITCHD_FIB_RPC_TIMEOUT_MS, ec);
    if (resp_len >= 0)
        resp[resp_len] = '\0';
    else
        resp[0] = '\0';
    return resp_len;
}

static bool fib_program_ack_valid(const rpd_fib_program_task *task,
                                  const char *resp, s32 ec,
                                  char *err, size_t err_size) {
    const char *anchor;
    const char *outer;
    char status[32];
    char table[RPD_RIB_TABLE_LEN];
    u64 generation;
    u64 update_id;
    int routes;

    if (ec != 0) {
        snprintf(err, err_size, "switchd FIB RPC error: %d", ec);
        return false;
    }
    if (!task || !resp) {
        snprintf(err, err_size, "switchd FIB response was not recognized");
        return false;
    }
    outer = task->kind == RPD_FIB_PROGRAM_RECONCILE ?
        "<fib-reconcile" :
        (task->kind == RPD_FIB_PROGRAM_SNAPSHOT ?
         "<fib-snapshot-commit" : "<fib-batch-apply");
    anchor = task->kind == RPD_FIB_PROGRAM_RECONCILE ?
        "<fib-readback" : outer;
    if (!strstr(resp, outer) || !strstr(resp, anchor)) {
        snprintf(err, err_size, "switchd FIB response was not recognized");
        return false;
    }
    if (task->kind == RPD_FIB_PROGRAM_RECONCILE) {
        char outer_status[32];

        copy_attr_after(resp, outer, "status", outer_status,
                        sizeof(outer_status), "missing");
        if (strcmp(outer_status, "ok") != 0) {
            snprintf(err, err_size,
                     "switchd FIB reconcile status is %.16s", outer_status);
            return false;
        }
    }
    copy_attr_after(resp, anchor, "status", status, sizeof(status), "missing");
    copy_attr_after(resp, anchor, "table", table, sizeof(table), "missing");
    generation = attr_u64_after(resp, anchor, "generation", 0);
    update_id = attr_u64_after(resp, anchor, "fib-update-id", 0);
    routes = attr_int_after(resp, anchor, "routes", -1);
    if (strcmp(status, "ok") != 0 || strcmp(table, task->table) != 0 ||
        generation != task->generation || update_id != task->fib_update_id ||
        routes != task->expected_routes) {
        snprintf(err, err_size,
                 "FIB ACK mismatch status=%.16s table=%.40s "
                 "generation=%llu update=%llu routes=%d expected=%llu/%llu/%d",
                 status, table, (unsigned long long)generation,
                 (unsigned long long)update_id, routes,
                 (unsigned long long)task->generation,
                 (unsigned long long)task->fib_update_id,
                 task->expected_routes);
        return false;
    }
    return true;
}

static void update_fib_reconcile_from_response_locked(const char *resp,
                                                      s32 ec) {
    const char *anchor = "<fib-readback";

    g_rpd.last_fib_ec = ec;
    copy_attr_after(resp, anchor, "status", g_rpd.switchd_fib_status,
                    sizeof(g_rpd.switchd_fib_status), "unknown");
    g_rpd.switchd_fib_routes = attr_int_after(
        resp, anchor, "routes", g_rpd.switchd_fib_routes);
    g_rpd.switchd_fib_generation = attr_u64_after(
        resp, anchor, "generation", g_rpd.switchd_fib_generation);
    g_rpd.switchd_fib_update_id = attr_u64_after(
        resp, anchor, "fib-update-id", g_rpd.switchd_fib_update_id);
    update_fib_live_from_response(resp);
    g_rpd.last_fib_readback = time(NULL);
    set_fib_sync_state("ok", "switchd FIB reconcile matches rpd state");
}

static void log_fib_program_ack(const rpd_fib_program_task *task) {
    if (!task)
        return;
    if (task->kind == RPD_FIB_PROGRAM_RECONCILE &&
        strcmp(task->reason, "periodic-reconcile") == 0) {
        NL_LOG_DBG("rpd FIB programmer ack: reason=%s table=%s "
                   "generation=%llu fib-update-id=%llu routes=%d",
                   task->reason, task->table,
                   (unsigned long long)task->generation,
                   (unsigned long long)task->fib_update_id,
                   task->expected_routes);
        return;
    }
    NL_LOG_INFO("rpd FIB programmer ack: reason=%s table=%s "
                "generation=%llu fib-update-id=%llu routes=%d",
                task->reason, task->table,
                (unsigned long long)task->generation,
                (unsigned long long)task->fib_update_id,
                task->expected_routes);
}

static void *rpd_fib_program_main(void *ctx) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;

    for (;;) {
        rpd_fib_program_task task;
        char resp[65536];
        char err[192] = {0};
        s32 ec = NL_ERR_DAEMON_UNREACHABLE;
        s64 rpc_started;
        int resp_len;
        bool ack_ok;
        bool requeued = false;

        memset(&task, 0, sizeof(task));
        rpd_lock(rpd);
        while (rpd->fib_program_queue_count == 0 &&
               !rpd->fib_program_stop_requested)
            pthread_cond_wait(&rpd->fib_program_cond, &rpd->lock);
        if (rpd->fib_program_queue_count == 0 &&
            rpd->fib_program_stop_requested) {
            rpd_unlock(rpd);
            break;
        }
        task = rpd->fib_program_queue[rpd->fib_program_queue_head];
        memset(&rpd->fib_program_queue[rpd->fib_program_queue_head], 0,
               sizeof(rpd->fib_program_queue[0]));
        rpd->fib_program_queue_head =
            (rpd->fib_program_queue_head + 1) % RPD_FIB_PIPELINE_QUEUE_MAX;
        rpd->fib_program_queue_count--;
        rpd->fib_program_inflight = true;
        rpd->fib_program_last_queue_ms = monotonic_ms() - task.queued_ms;
        rpd_unlock(rpd);

        rpc_started = monotonic_ms();
        resp_len = fib_program_rpc(&task, resp, sizeof(resp), &ec);
        ack_ok = resp_len >= 0 &&
            fib_program_ack_valid(&task, resp, ec, err, sizeof(err));

        rpd_lock(rpd);
        rpd->fib_program_inflight = false;
        rpd->fib_program_last_rpc_ms = monotonic_ms() - rpc_started;
        rpd->last_fib_ec = ec;
        if (ack_ok) {
            if (task.fib_update_id < rpd->fib_program_acked_update_id) {
                rpd->fib_program_stale_acks++;
            } else {
                rpd->fib_program_acked_generation = task.generation;
                rpd->fib_program_acked_update_id = task.fib_update_id;
                if (task.kind == RPD_FIB_PROGRAM_RECONCILE)
                    update_fib_reconcile_from_response_locked(resp, ec);
                else
                    update_fib_sync_from_response(resp, ec, task.reason);
                if (strcmp(rpd->switchd_fib_live_status, "ready") == 0 &&
                    strcmp(rpd->switchd_fib_live_ready, "true") == 0) {
                    rpd_rib *rib = strcmp(task.table, rpd->rib.table) == 0 ?
                        &rpd->rib : &rpd->vrf_rib;

                    rpd_rib_mark_dynamic_fib_installed_through(
                        rib, task.generation, task.fib_update_id);
                }
            }
            rpd->fib_program_completed++;
            rpd->fib_program_last_error[0] = '\0';
            log_fib_program_ack(&task);
        } else {
            rpd->fib_program_failures++;
            if (task.kind == RPD_FIB_PROGRAM_APPLY ||
                task.kind == RPD_FIB_PROGRAM_SNAPSHOT)
                rpd->fpm_sync_batch_errors++;
            snprintf(rpd->fib_program_last_error,
                     sizeof(rpd->fib_program_last_error), "%s",
                     err[0] ? err : "switchd FIB RPC unavailable");
            set_fib_sync_state(resp_len < 0 ? "pending" : "error",
                               rpd->fib_program_last_error);
            NL_LOG_WARN("rpd FIB programmer failed: reason=%s table=%s "
                        "generation=%llu fib-update-id=%llu error=%s",
                        task.reason, task.table,
                        (unsigned long long)task.generation,
                        (unsigned long long)task.fib_update_id,
                        rpd->fib_program_last_error);
            if (task.kind == RPD_FIB_PROGRAM_RECONCILE && resp_len >= 0) {
                (void)sync_switchd_fib_locked(
                    "periodic-reconcile-drift", true);
            } else if (!rpd->fib_program_stop_requested && task.attempts < 2 &&
                rpd->fib_program_queue_count < RPD_FIB_PIPELINE_QUEUE_MAX) {
                rpd->fib_program_queue_head =
                    (rpd->fib_program_queue_head - 1 +
                     RPD_FIB_PIPELINE_QUEUE_MAX) %
                    RPD_FIB_PIPELINE_QUEUE_MAX;
                task.attempts++;
                task.queued_ms = monotonic_ms();
                rpd->fib_program_queue[rpd->fib_program_queue_head] = task;
                rpd->fib_program_queue_count++;
                requeued = true;
                set_fib_sync_state("pending",
                                   "FIB programmer will retry failed batch");
            }
        }
        if (ack_ok && fib_program_work_pending_locked(rpd))
            set_fib_sync_state("queued",
                               "FIB programming pipeline has pending work");
        pthread_cond_broadcast(&rpd->fib_program_cond);
        rpd_unlock(rpd);
        if (requeued) {
            struct timespec retry_delay = {
                .tv_sec = 0,
                .tv_nsec = 200000000L,
            };

            while (nanosleep(&retry_delay, &retry_delay) != 0 &&
                   errno == EINTR) {
            }
            memset(&task, 0, sizeof(task));
        } else {
            fib_program_task_release(&task);
        }
    }
    return NULL;
}

static int fib_program_start(rpd_ctx *rpd) {
    if (!rpd || !rpd->lock_ready)
        return -1;
    if (pthread_cond_init(&rpd->fib_program_cond, NULL) != 0)
        return -1;
    rpd->fib_program_cond_ready = true;
    rpd->fib_program_accepting = true;
    rpd->fib_program_stop_requested = false;
    if (pthread_create(&rpd->fib_program_thread, NULL,
                       rpd_fib_program_main, rpd) != 0) {
        rpd->fib_program_accepting = false;
        pthread_cond_destroy(&rpd->fib_program_cond);
        rpd->fib_program_cond_ready = false;
        return -1;
    }
    rpd->fib_program_thread_started = true;
    return 0;
}

static void fib_program_stop(rpd_ctx *rpd) {
    if (!rpd || !rpd->fib_program_cond_ready)
        return;
    rpd_lock(rpd);
    while (rpd->fib_program_thread_started &&
           (rpd->fpm_sync_batch[0].updates > 0 ||
            rpd->fpm_sync_batch[1].updates > 0)) {
        int rc0 = fpm_sync_batch_flush_locked(
            rpd, &rpd->fpm_sync_batch[0], "shutdown-tail-flush");
        int rc1 = fpm_sync_batch_flush_locked(
            rpd, &rpd->fpm_sync_batch[1], "shutdown-tail-flush");

        if (rc0 == 0 && rc1 == 0)
            break;
        if (rpd->fib_program_queue_count < RPD_FIB_PIPELINE_QUEUE_MAX)
            break;
        pthread_cond_wait(&rpd->fib_program_cond, &rpd->lock);
    }
    rpd->fib_program_accepting = false;
    rpd->fib_program_stop_requested = true;
    pthread_cond_broadcast(&rpd->fib_program_cond);
    rpd_unlock(rpd);
    if (rpd->fib_program_thread_started)
        pthread_join(rpd->fib_program_thread, NULL);
    rpd->fib_program_thread_started = false;
    for (int i = 0; i < RPD_FIB_PIPELINE_QUEUE_MAX; i++)
        fib_program_task_release(&rpd->fib_program_queue[i]);
    rpd->fib_program_queue_count = 0;
    pthread_cond_destroy(&rpd->fib_program_cond);
    rpd->fib_program_cond_ready = false;
}

static int send_switchd_fib_batch_locked(rpd_rib *rib,
                                         const char *reason,
                                         const char *batch,
                                         int batch_len,
                                         int routes) {
    if (!batch || batch_len <= 0) {
        set_fib_sync_state("error", "invalid rpd FIB batch");
        return -1;
    }
    return fib_program_enqueue_locked(&g_rpd, rib, RPD_FIB_PROGRAM_APPLY,
                                      reason, batch,
                                      batch_len, routes);
}

static int send_switchd_fib_snapshot_locked(rpd_rib *rib,
                                            const char *reason,
                                            const char *batch,
                                            int batch_len,
                                            int routes) {
    if (!batch || batch_len <= 0) {
        set_fib_sync_state("error", "invalid rpd FIB snapshot");
        return -1;
    }
    return fib_program_enqueue_locked(&g_rpd, rib,
                                      RPD_FIB_PROGRAM_SNAPSHOT,
                                      reason, batch, batch_len, routes);
}

static int sync_switchd_fib_scope_locked(rpd_rib *rib,
                                         const char *reason, bool force) {
    char *batch = NULL;
    size_t batch_size = 0;
    int routes = 0;
    int rc;

    if (rpd_rib_compile_fib_batch_alloc(rib, g_rpd.generation,
                                        g_rpd.fib_update_id, &batch,
                                        &batch_size, &routes) != 0 ||
        batch_size == 0 || batch_size > INT_MAX) {
        free(batch);
        set_fib_sync_state("error", "failed to compile rpd FIB snapshot");
        return -1;
    }
    if (!force &&
        strcmp(g_rpd.fib_sync_state, "ok") == 0 &&
        g_rpd.switchd_fib_generation == g_rpd.generation &&
        g_rpd.switchd_fib_update_id == g_rpd.fib_update_id &&
        g_rpd.switchd_fib_routes == routes) {
        free(batch);
        return 0;
    }
    rc = send_switchd_fib_snapshot_locked(rib, reason, batch,
                                          (int)batch_size, routes);
    free(batch);
    return rc;
}

static int sync_switchd_fib_locked(const char *reason, bool force) {
    int rc;

    rc = sync_switchd_fib_scope_locked(&g_rpd.rib, reason, force);
    if (g_rpd.vrf.enabled &&
        sync_switchd_fib_scope_locked(&g_rpd.vrf_rib, reason, true) != 0)
        rc = -1;
    return rc;
}

static int sync_switchd_fib_delta_locked(rpd_rib *rib, const char *reason,
                                         const rpd_rib_update_result *result) {
    char *batch = NULL;
    int routes = 0;
    int batch_len;
    int rc = -1;

    if (!result || result->affected_prefix_overflow ||
        result->affected_prefix_count <= 0)
        return sync_switchd_fib_scope_locked(rib, reason, true);

    batch = malloc(RPD_FIB_BATCH_MAX);
    if (!batch) {
        set_fib_sync_state("error",
                           "failed to allocate rpd FIB delta buffer");
        return -1;
    }
    batch_len = rpd_rib_compile_fib_delta(rib, result,
                                          g_rpd.generation,
                                          g_rpd.fib_update_id, batch,
                                          RPD_FIB_BATCH_MAX, &routes);
    if (batch_len < 0) {
        set_fib_sync_state("error", "failed to compile rpd FIB delta");
        goto out;
    }
    rc = send_switchd_fib_batch_locked(rib, reason, batch, batch_len,
                                       routes);

out:
    free(batch);
    return rc;
}

static void fpm_sync_batch_reset(rpd_fpm_sync_batch *batch) {
    if (!batch)
        return;
    memset(batch, 0, sizeof(*batch));
}

static rpd_fpm_sync_batch *fpm_sync_batch_for_rib(rpd_ctx *rpd,
                                                  rpd_rib *rib) {
    if (!rpd || !rib)
        return NULL;
    if (rib == &rpd->rib)
        return &rpd->fpm_sync_batch[0];
    if (rib == &rpd->vrf_rib)
        return &rpd->fpm_sync_batch[1];
    return NULL;
}

static int fpm_sync_batch_merge(rpd_ctx *rpd, rpd_fpm_sync_batch *batch,
                                rpd_rib *rib,
                                const rpd_rib_update_result *result) {
    if (!batch || !rib || !result || !result->changed)
        return -1;
    if (!batch->rib) {
        batch->rib = rib;
        batch->started_ms = monotonic_ms();
    }
    if (batch->rib != rib)
        return -1;
    for (int i = 0; i < result->affected_prefix_count; i++) {
        const char *prefix = result->affected_prefixes[i];
        bool duplicate = false;

        for (int j = 0; j < batch->result.affected_prefix_count; j++) {
            if (strcmp(batch->result.affected_prefixes[j], prefix) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            if (rpd)
                rpd->fib_program_coalesced_updates++;
            continue;
        }
        if (batch->result.affected_prefix_count >=
            RPD_RIB_UPDATE_AFFECTED_MAX) {
            batch->result.affected_prefix_overflow = true;
            return -1;
        }
        snprintf(batch->result.affected_prefixes[
                     batch->result.affected_prefix_count],
                 sizeof(batch->result.affected_prefixes[0]), "%s", prefix);
        batch->result.affected_prefix_count++;
    }
    batch->result.changed = true;
    batch->result.generation = result->generation;
    batch->result.fib_update_id = result->fib_update_id;
    batch->result.routes_changed += result->routes_changed;
    batch->result.routes_deleted += result->routes_deleted;
    batch->updates++;
    return 0;
}

static int fpm_sync_batch_flush_locked(rpd_ctx *rpd,
                                       rpd_fpm_sync_batch *batch,
                                       const char *reason) {
    int updates;
    int rc;

    if (!rpd || !batch || batch->updates <= 0)
        return 0;
    updates = batch->updates;
    rc = sync_switchd_fib_delta_locked(batch->rib, reason,
                                       &batch->result);
    if (rc != 0) {
        rpd->fpm_sync_batch_errors++;
        return -1;
    }
    rpd->fpm_sync_batch_flushes++;
    rpd->fpm_sync_batch_last_size = updates;
    fpm_sync_batch_reset(batch);
    return 0;
}

static int fpm_sync_batch_queue_locked(rpd_ctx *rpd, rpd_rib *rib,
                                       const rpd_rib_update_result *result,
                                       const char *reason) {
    rpd_fpm_sync_batch *batch = fpm_sync_batch_for_rib(rpd, rib);
    int new_prefixes = 0;

    if (!batch || !result || !result->changed) {
        set_fib_sync_state("error", "failed to aggregate FPM FIB delta");
        return -1;
    }
    if (result->affected_prefix_overflow) {
        if (batch->updates > 0 &&
            fpm_sync_batch_flush_locked(rpd, batch,
                                        "fpm-route-update-capacity") != 0)
            return -1;
        return sync_switchd_fib_scope_locked(
            rib, reason ? reason : "fpm-route-update-full", true);
    }
    for (int i = 0; i < result->affected_prefix_count; i++) {
        bool duplicate = false;

        for (int j = 0; j < batch->result.affected_prefix_count; j++) {
            if (strcmp(batch->result.affected_prefixes[j],
                       result->affected_prefixes[i]) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
            new_prefixes++;
    }
    if (batch->updates > 0 &&
        (batch->result.affected_prefix_count + new_prefixes >
             RPD_RIB_UPDATE_AFFECTED_MAX)) {
        if (fpm_sync_batch_flush_locked(rpd, batch,
                                        "fpm-route-update-capacity") != 0)
            return -1;
    }
    if (fpm_sync_batch_merge(rpd, batch, rib, result) != 0) {
        set_fib_sync_state("error", "failed to aggregate FPM FIB delta");
        return -1;
    }
    if (batch->updates < rpd->fpm_sync_batch_size)
        return 0;
    return fpm_sync_batch_flush_locked(rpd, batch, reason);
}

static void fpm_sync_batch_flush_due_locked(rpd_ctx *rpd) {
    s64 now_ms;

    if (!rpd || rpd->defer_fpm_fib_sync || rpd->fpm_sync_batch_size <= 1)
        return;
    now_ms = monotonic_ms();
    for (int i = 0; i < 2; i++) {
        rpd_fpm_sync_batch *batch = &rpd->fpm_sync_batch[i];

        if (batch->updates > 0 && batch->started_ms > 0 &&
            now_ms - batch->started_ms >= rpd->fpm_sync_batch_ms)
            (void)fpm_sync_batch_flush_locked(
                rpd, batch, "fpm-route-update-batch-timeout");
    }
}

static int purge_dynamic_protocol_routes_locked(const char *reason, u64 tx_id) {
    rpd_rib_update_result result;
    rpd_plan_stats stats;
    char err[192] = {0};
    u64 next_generation = g_rpd.generation + 1;
    u64 next_update_id = g_rpd.fib_update_id + 1;
    int rc;

    memset(&stats, 0, sizeof(stats));
    rc = rpd_rib_purge_dynamic_protocols(&g_rpd.rib, next_generation,
                                         next_update_id, &result,
                                         err, sizeof(err));
    if (rc != 0) {
        record_op_no_bump("dynamic-protocol-purge", "failed", tx_id, NULL);
        set_drift_state("error",
                        err[0] ? err : "dynamic RIB purge failed");
        return -1;
    }
    stats.routes = result.routes_deleted;
    if (!result.changed) {
        record_op_no_bump("dynamic-protocol-purge", "no-change", tx_id,
                          &stats);
        return 0;
    }
    g_rpd.generation = next_generation;
    record_op("dynamic-protocol-purge", "ok", tx_id, &stats);
    (void)fpm_sync_batch_queue_locked(
        &g_rpd, &g_rpd.rib, &result,
        reason ? reason : "dynamic-protocol-purge");
    return 1;
}

static int rollback_switchd_fib_locked(const char *reason, u64 tx_id) {
    char resp[65536];
    s32 ec = NL_ERR_DAEMON_UNREACHABLE;
    int resp_len;
    const char *anchor = "<fib-rollback-tx";

    resp_len = nl_rpc_call_ex(g_switchd_socket_path, NL_DAEMON_RPD,
                              NL_DAEMON_SWITCHD,
                              NL_SWITCHD_RPD_FIB_ROLLBACK, tx_id,
                              NULL, 0, (u8 *)resp,
                              (int)sizeof(resp) - 1,
                              RPD_SWITCHD_FIB_RPC_TIMEOUT_MS, &ec);
    g_rpd.last_fib_ec = ec;
    if (resp_len < 0) {
        set_fib_sync_state("pending",
                           "switchd FIB rollback RPC is unavailable");
        NL_LOG_WARN("rpd FIB rollback pending: switchd unavailable "
                    "reason=%s", reason ? reason : "-");
        return -1;
    }
    resp[resp_len] = '\0';
    if (ec != 0 || !strstr(resp, anchor)) {
        set_fib_sync_state("error",
                           "switchd FIB rollback returned an error");
        NL_LOG_WARN("rpd FIB rollback failed: ec=%d reason=%s body=%s",
                    ec, reason ? reason : "-", resp);
        return -1;
    }
    copy_attr_after(resp, anchor, "status", g_rpd.switchd_fib_status,
                    sizeof(g_rpd.switchd_fib_status), "unknown");
    g_rpd.switchd_fib_routes =
        attr_int_after(resp, anchor, "routes", g_rpd.switchd_fib_routes);
    g_rpd.switchd_fib_generation =
        attr_u64_after(resp, anchor, "generation",
                       g_rpd.switchd_fib_generation);
    g_rpd.switchd_fib_update_id =
        attr_u64_after(resp, anchor, "fib-update-id",
                       g_rpd.switchd_fib_update_id);
    update_fib_live_from_response(resp);
    g_rpd.last_fib_sync = time(NULL);
    if (strcmp(g_rpd.switchd_fib_status, "ok") == 0) {
        set_fib_sync_state("ok", "switchd accepted rpd FIB rollback");
        return 0;
    }
    set_fib_sync_state("unknown", "switchd FIB rollback status was not ok");
    return -1;
}

static void update_owner_state_from_response(nl_rpc_method method,
                                             const nl_msg_hdr *resp) {
    char *body;
    size_t len;

    if (!resp)
        return;
    g_rpd.last_owner_ec = resp->error_code;
    if (resp->error_code != 0) {
        set_drift_state("error", "last owner operation returned an error");
        return;
    }
    len = resp->payload_len;
    if (len > NETLAB_MAX_MSG)
        len = NETLAB_MAX_MSG;
    body = malloc(len + 1U);
    if (!body) {
        set_drift_state("error",
                        "owner response parser is out of memory");
        return;
    }
    if (len > 0)
        memcpy(body, resp->payload, len);
    body[len] = '\0';

    if (method == NL_RPD_READBACK ||
        strstr(body, "<persistent-l3-owner-readback")) {
        g_rpd.last_readback = time(NULL);
        copy_attr_after(body, "<persistent-l3-owner-readback", "owner-mode",
                        g_rpd.owner_mode, sizeof(g_rpd.owner_mode), "unknown");
        copy_attr_after(body, "<switchd-owner", "status",
                        g_rpd.switchd_owner_status,
                        sizeof(g_rpd.switchd_owner_status), "missing");
        if (strcmp(g_rpd.switchd_owner_status, "unavailable") == 0) {
            set_drift_state("unknown",
                            "switchd owner read-back is unavailable");
        } else if (strcmp(g_rpd.switchd_owner_status, "error") == 0) {
            set_drift_state("drift",
                            "switchd owner read-back returned an error");
        } else if (strstr(body, "persistent-hw-out-of-sync=\"true\"") ||
                   strstr(body, "status=\"out-of-sync\"") ||
                   attr_nonzero_after(body, "<l3-sdk-owner-verify",
                                      "mismatches") ||
                   attr_nonzero_after(body, "<shadow-verify",
                                      "mismatches")) {
            set_drift_state("drift",
                            "switchd read-back does not match rpd intent");
        } else {
            set_drift_state("ok", "last read-back matched available owner state");
        }
    } else if (method == NL_RPD_APPLY_PLAN &&
               strstr(body, "<l3-persistent-apply")) {
        set_drift_state("pending-readback",
                        "apply completed; read-back verification is pending");
    } else if (method == NL_RPD_ROLLBACK &&
               strstr(body, "<l3-persistent-rollback")) {
        set_drift_state("pending-readback",
                        "rollback completed; read-back verification is pending");
    }
    free(body);
}

static int call_owner_method_capture(nl_l3_owner *owner,
                                     const nl_msg_hdr *msg,
                                     nl_l3_owner_method method,
                                     const char *payload, int payload_len,
                                     nl_msg_hdr **owner_resp) {
    nl_msg_hdr *owner_msg;
    nl_conn fake_conn;
    nl_conn peer_conn;
    struct pollfd pfd;
    int fds[2] = {-1, -1};
    int rc;

    if (owner_resp)
        *owner_resp = NULL;
    if (!owner_resp)
        return -1;
    if (payload_len < 0)
        payload_len = payload ? (int)strlen(payload) : 0;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0)
        return -1;
    owner_msg = nl_msg_alloc((u32)payload_len);
    if (!owner_msg) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (msg) {
        memcpy(owner_msg, msg, NL_HDR_SIZE);
    } else {
        owner_msg->type = NL_MSG_REQUEST;
        owner_msg->schema_version = NETLAB_IPC_SCHEMA_CURRENT;
        owner_msg->request_id = 0;
        owner_msg->tx_id = 0;
    }
    owner_msg->method = (u16)method;
    owner_msg->daemon_id = NL_DAEMON_RPD;
    owner_msg->payload_len = (u32)payload_len;
    if (payload_len > 0 && payload)
        memcpy(owner_msg->payload, payload, (size_t)payload_len);

    memset(&fake_conn, 0, sizeof(fake_conn));
    memset(&peer_conn, 0, sizeof(peer_conn));
    fake_conn.fd = fds[0];
    fake_conn.daemon_id = NL_DAEMON_RPD;
    peer_conn.fd = fds[1];

    rc = nl_l3_owner_handle(owner, method, &fake_conn, owner_msg);
    if (rc != 0)
        goto out;
    pfd.fd = fds[1];
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 1000) <= 0) {
        rc = -1;
        goto out;
    }
    if (nl_recv(&peer_conn, owner_resp) != NL_OK || !*owner_resp) {
        rc = -1;
        goto out;
    }
    rc = 0;

out:
    nl_msg_free(owner_msg);
    close(fds[0]);
    close(fds[1]);
    return rc;
}

static int dispatch_owner_method(nl_conn *conn, nl_msg_hdr *msg,
                                 nl_l3_owner_method method,
                                 const char *payload, int payload_len,
                                 s32 *owner_ec) {
    nl_msg_hdr *owner_resp = NULL;
    int rc;

    if (owner_ec)
        *owner_ec = NL_ERR_DAEMON_UNREACHABLE;
    rc = call_owner_method_capture(g_rpd.l3_owner, msg, method,
                                   payload, payload_len,
                                   &owner_resp);
    if (rc != 0 || !owner_resp) {
        return send_text(conn, msg, NL_ERR_RPC_TIMEOUT,
                         "error: rpd owner dispatch failed");
    }
    update_owner_state_from_response(method, owner_resp);
    if (owner_ec)
        *owner_ec = owner_resp->error_code;
    rc = nl_send(conn, owner_resp) == NL_OK ? 0 : -1;
    if (owner_resp)
        nl_msg_free(owner_resp);
    return rc;
}

static bool line_contains_n(const char *line, size_t len,
                            const char *needle) {
    size_t needle_len;

    if (!line || !needle || !needle[0])
        return false;
    needle_len = strlen(needle);
    if (needle_len > len)
        return false;
    for (size_t i = 0; i + needle_len <= len; i++)
        if (memcmp(line + i, needle, needle_len) == 0)
            return true;
    return false;
}

static bool owner_plan_has_line_tokens(const char *plan,
                                       const char *token_a,
                                       const char *token_b) {
    const char *p;

    if (!plan || !token_a || !token_a[0])
        return false;
    p = plan;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        if (line_contains_n(p, len, token_a) &&
            (!token_b || !token_b[0] ||
             line_contains_n(p, len, token_b)))
            return true;
        if (!nl)
            break;
        p = nl + 1;
    }
    return false;
}

static bool owner_plan_has_route_prefix(const char *plan,
                                        const char *prefix) {
    char needle[96];

    if (!prefix || !prefix[0])
        return false;
    snprintf(needle, sizeof(needle), "route prefix %s ", prefix);
    return owner_plan_has_line_tokens(plan, needle, NULL);
}

static bool owner_plan_has_arp(const char *plan, const char *ip,
                               const char *rif) {
    char ip_token[96];
    char rif_token[96];

    if (!ip || !ip[0] || !rif || !rif[0])
        return false;
    snprintf(ip_token, sizeof(ip_token), "arp ip %s ", ip);
    snprintf(rif_token, sizeof(rif_token), " interface %s", rif);
    return owner_plan_has_line_tokens(plan, ip_token, rif_token);
}

static bool owner_plan_has_id(const char *plan, const char *record,
                              int id) {
    char needle[64];

    snprintf(needle, sizeof(needle), "%s%d ", record, id);
    return owner_plan_has_line_tokens(plan, needle, NULL);
}

static int owner_next_free_id(const char *plan, const char *record,
                              int start) {
    for (int id = start; id <= 65535; id++)
        if (!owner_plan_has_id(plan, record, id))
            return id;
    return -1;
}

static int owner_plan_appendf(char *buf, size_t buf_size, size_t *off,
                              const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || *off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}

static bool plan_has_rib_static_route(const char *plan) {
    return plan && strstr(plan, "rib-static-route ") != NULL;
}

static const rpd_rib_arp *owner_rib_find_arp(const rpd_rib *rib,
                                             const char *ip,
                                             const char *rif) {
    if (!rib || !ip || !rif)
        return NULL;
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++) {
        const rpd_rib_arp *arp = &rib->arps[i];

        if (arp->active && strcmp(arp->ip, ip) == 0 &&
            strcmp(arp->rif, rif) == 0)
            return arp;
    }
    return NULL;
}

static bool static_route_resolved_for_owner(const rpd_rib *rib,
                                            const rpd_rib_route *route) {
    if (!rib || !route || !route->active ||
        strcmp(route->protocol, "static") != 0 ||
        route->n_nexthops <= 0)
        return false;
    for (int i = 0; i < route->n_nexthops; i++) {
        const rpd_rib_nexthop *nh = &route->nexthops[i];

        if (!owner_rib_find_arp(rib, nh->address, nh->egress_rif))
            return false;
    }
    return true;
}

static int compile_static_owner_reapply_plan_locked(
        rpd_ctx *rpd, char *out, size_t out_size,
        rpd_plan_stats *stats, char *err, size_t err_size) {
    size_t off;
    int next_hop_id = 62000;
    int ecmp_id = 63000;

    if (!rpd || !out || out_size == 0 || !stats) {
        snprintf(err, err_size, "invalid static owner reapply context");
        return -1;
    }
    memset(stats, 0, sizeof(*stats));
    if (!rpd->static_owner_plan_valid ||
        rpd->static_owner_plan_len < 0 ||
        (size_t)rpd->static_owner_plan_len >= out_size) {
        snprintf(err, err_size, "static owner plan snapshot is unavailable");
        return -1;
    }
    memcpy(out, rpd->static_owner_plan,
           (size_t)rpd->static_owner_plan_len);
    off = (size_t)rpd->static_owner_plan_len;
    out[off] = '\0';
    if (off > 0 && out[off - 1] != '\n' &&
        owner_plan_appendf(out, out_size, &off, "\n") != 0) {
        snprintf(err, err_size, "static owner plan buffer exceeded");
        return -1;
    }

    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        const rpd_rib_route *route = &rpd->rib.routes[i];
        char members[256];
        size_t members_off = 0;
        int member_ids[RPD_RIB_MAX_NEXTHOPS];

        if (!route->active || strcmp(route->protocol, "static") != 0)
            continue;
        if (owner_plan_has_route_prefix(rpd->static_owner_plan,
                                        route->prefix))
            continue;
        if (!static_route_resolved_for_owner(&rpd->rib, route))
            continue;

        memset(member_ids, 0, sizeof(member_ids));
        members[0] = '\0';
        for (int j = 0; j < route->n_nexthops; j++) {
            const rpd_rib_nexthop *nh = &route->nexthops[j];
            const rpd_rib_arp *arp =
                owner_rib_find_arp(&rpd->rib, nh->address,
                                   nh->egress_rif);
            int id;

            if (!arp) {
                snprintf(err, err_size,
                         "static route %s has unresolved ARP",
                         route->prefix);
                return -1;
            }
            if (!owner_plan_has_arp(out, arp->ip, arp->rif)) {
                if (arp->egress_port[0]) {
                    if (owner_plan_appendf(
                            out, out_size, &off,
                            "arp ip %s mac %s interface %s "
                            "egress-port %s\n",
                            arp->ip, arp->mac, arp->rif,
                            arp->egress_port) != 0) {
                        snprintf(err, err_size,
                                 "static owner ARP buffer exceeded");
                        return -1;
                    }
                } else if (owner_plan_appendf(
                               out, out_size, &off,
                               "arp ip %s mac %s interface %s\n",
                               arp->ip, arp->mac, arp->rif) != 0) {
                    snprintf(err, err_size,
                             "static owner ARP buffer exceeded");
                    return -1;
                }
                stats->arp++;
            }
            id = owner_next_free_id(out, "next-hop id ", next_hop_id);
            if (id < 0) {
                snprintf(err, err_size,
                         "static owner next-hop id space exhausted");
                return -1;
            }
            next_hop_id = id + 1;
            if (owner_plan_appendf(out, out_size, &off,
                                   "next-hop id %d arp %s interface %s\n",
                                   id, arp->ip, arp->rif) != 0) {
                snprintf(err, err_size,
                         "static owner next-hop buffer exceeded");
                return -1;
            }
            stats->next_hops++;
            member_ids[j] = id;
            if (owner_plan_appendf(members, sizeof(members),
                                   &members_off, "%s%d",
                                   j == 0 ? "" : ",", id) != 0) {
                snprintf(err, err_size,
                         "static owner ECMP member buffer exceeded");
                return -1;
            }
        }

        if (route->n_nexthops == 1) {
            if (owner_plan_appendf(out, out_size, &off,
                                   "route prefix %s next-hop %d\n",
                                   route->prefix, member_ids[0]) != 0) {
                snprintf(err, err_size,
                         "static owner route buffer exceeded");
                return -1;
            }
        } else {
            int id = owner_next_free_id(out, "ecmp id ", ecmp_id);

            if (id < 0) {
                snprintf(err, err_size,
                         "static owner ECMP id space exhausted");
                return -1;
            }
            ecmp_id = id + 1;
            if (owner_plan_appendf(out, out_size, &off,
                                   "ecmp id %d members %s\n",
                                   id, members) != 0 ||
                owner_plan_appendf(out, out_size, &off,
                                   "route prefix %s ecmp %d\n",
                                   route->prefix, id) != 0) {
                snprintf(err, err_size,
                         "static owner ECMP buffer exceeded");
                return -1;
            }
            stats->ecmp_groups++;
        }
        stats->routes++;
    }
    return (int)off;
}

static void mark_static_owner_reapply_routes_locked(rpd_ctx *rpd) {
    if (!rpd)
        return;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        rpd_rib_route *route = &rpd->rib.routes[i];

        if (!route->active || strcmp(route->protocol, "static") != 0)
            continue;
        if (owner_plan_has_route_prefix(rpd->static_owner_plan,
                                        route->prefix))
            continue;
        if (!static_route_resolved_for_owner(&rpd->rib, route))
            continue;
        snprintf(route->installed_state, sizeof(route->installed_state),
                 "%s", "owner-applied");
        route->generation = rpd->generation;
        route->fib_update_id = rpd->fib_update_id;
    }
}

static bool static_owner_applied_plan_matches(const rpd_ctx *rpd,
                                              const char *plan,
                                              int plan_len) {
    if (!rpd || !plan || plan_len < 0 ||
        !rpd->static_owner_applied_plan_valid ||
        rpd->static_owner_applied_plan_len != plan_len)
        return false;
    return memcmp(rpd->static_owner_applied_plan, plan,
                  (size_t)plan_len) == 0;
}

static void save_static_owner_applied_plan(rpd_ctx *rpd,
                                           const char *plan,
                                           int plan_len) {
    if (!rpd || !plan || plan_len < 0 ||
        (size_t)plan_len >= sizeof(rpd->static_owner_applied_plan))
        return;
    memcpy(rpd->static_owner_applied_plan, plan, (size_t)plan_len);
    rpd->static_owner_applied_plan[plan_len] = '\0';
    rpd->static_owner_applied_plan_len = plan_len;
    rpd->static_owner_applied_plan_valid = true;
}

static int reapply_static_owner_from_rib_locked(rpd_ctx *rpd,
                                                const char *reason) {
    char owner_plan[RPD_STATIC_PLAN_MAX];
    char err[192] = {0};
    rpd_plan_stats stats;
    nl_msg_hdr *owner_resp = NULL;
    int owner_len;
    int rc;

    if (!rpd || !rpd->static_owner_plan_valid ||
        !rpd->static_rib_only_routes)
        return 0;
    owner_len = compile_static_owner_reapply_plan_locked(
        rpd, owner_plan, sizeof(owner_plan), &stats, err, sizeof(err));
    if (owner_len < 0) {
        set_drift_state("error", err[0] ? err :
                        "static owner reapply plan failed");
        record_op_no_bump("static-owner-reapply", "invalid", 0, NULL);
        return -1;
    }
    if (stats.routes == 0 && !rpd->static_owner_rib_routes_installed)
        return 0;
    if (static_owner_applied_plan_matches(rpd, owner_plan, owner_len))
        return 0;

    rc = call_owner_method_capture(g_rpd.l3_owner, NULL, NL_L3_OWNER_APPLY, owner_plan, owner_len,
                                   &owner_resp);
    if (rc != 0 || !owner_resp) {
        set_drift_state("error",
                        "static owner reapply dispatch failed");
        record_op_no_bump("static-owner-reapply", "failed", 0, &stats);
        if (owner_resp)
            nl_msg_free(owner_resp);
        return -1;
    }
    update_owner_state_from_response(NL_RPD_APPLY_PLAN, owner_resp);
    if (owner_resp->error_code != 0) {
        set_drift_state("error",
                        "static owner reapply returned an error");
        record_op_no_bump("static-owner-reapply", "failed", 0, &stats);
        nl_msg_free(owner_resp);
        return -1;
    }
    nl_msg_free(owner_resp);

    rpd->generation++;
    record_op("static-owner-reapply", "ok", 0, &stats);
    mark_static_owner_reapply_routes_locked(rpd);
    rpd->static_owner_rib_routes_installed = stats.routes > 0;
    save_static_owner_applied_plan(rpd, owner_plan, owner_len);
    (void)sync_switchd_fib_locked(reason ? reason :
                                  "static-owner-reapply", true);
    return 1;
}

static bool dynamic_gate_blocked(nl_conn *conn, nl_msg_hdr *msg,
                                 const rpd_plan_stats *stats) {
    char reason[512];

    if (!stats || !stats->has_dynamic_protocol)
        return false;
    if (frr_dynamic_config_open())
        return false;
    dynamic_gate_reason(reason, sizeof(reason));
    (void)send_text(
        conn, msg, NL_ERR_UNSUPPORTED_FEATURE,
        "error: commit rejected: protocols ospf/bgp dynamic routing gate "
        "closed: %s", reason);
    return true;
}

static int validate_static_rib_plan(const char *static_plan, int static_len,
                                    const rpd_vrf_context *vrf,
                                    char *err, size_t err_size) {
    rpd_rib *tmp;
    rpd_rib_update_result result;
    int rc;

    tmp = malloc(sizeof(*tmp));
    if (!tmp) {
        snprintf(err, err_size, "out of memory");
        return -1;
    }
    memcpy(tmp, &g_rpd.rib, sizeof(*tmp));
    memset(&result, 0, sizeof(result));
    rc = rpd_rib_sync_static_plan(tmp, static_plan, static_len,
                                  g_rpd.generation + 1,
                                  g_rpd.fib_update_id + 1,
                                  &result, err, err_size);
    if (rc == 0 && vrf && vrf->enabled) {
        if (g_rpd.vrf.enabled &&
            strcmp(g_rpd.vrf.table, vrf->table) == 0) {
            memcpy(tmp, &g_rpd.vrf_rib, sizeof(*tmp));
        } else if (rpd_rib_init_scope(tmp, vrf->table,
                                      vrf->kernel_table) != 0) {
            snprintf(err, err_size, "invalid VRF RIB scope");
            rc = -1;
        }
        if (rc == 0) {
            memset(&result, 0, sizeof(result));
            rc = rpd_rib_sync_static_plan(tmp, static_plan, static_len,
                                          g_rpd.generation + 1,
                                          g_rpd.fib_update_id + 1,
                                          &result, err, err_size);
        }
    }
    free(tmp);
    return rc;
}

static int clear_vrf_dynamic_owner_locked(char *err, size_t err_size) {
    rpd_rib *tmp;
    rpd_rib_update_result result;
    int rc;

    if (!g_rpd.vrf.enabled)
        return 0;
    tmp = malloc(sizeof(*tmp));
    if (!tmp) {
        snprintf(err, err_size, "out of memory clearing VRF FIB owner");
        return -1;
    }
    memcpy(tmp, &g_rpd.vrf_rib, sizeof(*tmp));
    rc = rpd_rib_purge_dynamic_protocols(tmp,
                                         g_rpd.generation + 1,
                                         g_rpd.fib_update_id + 1,
                                         &result, err, err_size);
    if (rc == 0)
        rc = sync_switchd_fib_scope_locked(tmp,
                                           "vrf-owner-pre-delete", true);
    free(tmp);
    return rc;
}

static int handle_plan_validate(nl_conn *conn, nl_msg_hdr *msg) {
    char static_plan[RPD_STATIC_PLAN_MAX];
    char rib_plan[RPD_STATIC_PLAN_MAX];
    rpd_plan_stats stats;
    bool stripped = false;
    int static_len;
    int rib_len;
    rpd_vrf_context vrf;
    char vrf_err[160] = {0};

    plan_stats((const char *)msg->payload, (int)msg->payload_len, &stats);
    if (parse_vrf_context((const char *)msg->payload,
                          (int)msg->payload_len, &vrf,
                          vrf_err, sizeof(vrf_err)) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd VRF validation failed: %s", vrf_err);
    if (dynamic_gate_blocked(conn, msg, &stats))
        return 0;
    if (stats.has_dynamic_protocol) {
        char frr_err[192] = {0};

        if (rpd_frr_config_validate_plan((const char *)msg->payload,
                                         (int)msg->payload_len,
                                         frr_err, sizeof(frr_err)) != 0)
            return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: rpd FRR intent validation failed: %s",
                             frr_err[0] ? frr_err : "invalid intent");
    }
    static_len = copy_static_plan((const char *)msg->payload,
                                  (int)msg->payload_len,
                                  static_plan, sizeof(static_plan),
                                  &stripped);
    if (static_len < 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd static L3 plan exceeds forwarding buffer");
    rib_len = copy_static_rib_plan((const char *)msg->payload,
                                   (int)msg->payload_len,
                                   rib_plan, sizeof(rib_plan), NULL);
    if (rib_len < 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd static L3 plan exceeds RIB buffer");
    {
        char rib_err[160] = {0};

        if (validate_static_rib_plan(rib_plan, rib_len, &vrf,
                                     rib_err, sizeof(rib_err)) != 0)
            return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: rpd RIB validation failed: %s",
                             rib_err[0] ? rib_err : "invalid static plan");
    }
    return dispatch_owner_method(conn, msg, NL_L3_OWNER_RESOURCE_CHECK, static_plan, static_len, NULL);
}

static int handle_plan_apply(nl_conn *conn, nl_msg_hdr *msg) {
    char static_plan[RPD_STATIC_PLAN_MAX];
    char rib_plan[RPD_STATIC_PLAN_MAX];
    rpd_plan_stats stats;
    bool stripped = false;
    int static_len;
    int rib_len;
    int rc;
    s32 owner_ec = NL_ERR_DAEMON_UNREACHABLE;
    rpd_rib_update_result rib_result;
    char rib_err[160];
    bool rib_sync_ok = false;
    bool had_route_protocols = frr_config_has_route_protocols(&g_rpd.frr_intent);
    bool frr_intent_compile_ok = false;
    bool has_route_protocols = had_route_protocols;
    rpd_vrf_context vrf;
    char vrf_err[160] = {0};
    bool vrf_dynamic_precleared = false;

    plan_stats((const char *)msg->payload, (int)msg->payload_len, &stats);
    if (parse_vrf_context((const char *)msg->payload,
                          (int)msg->payload_len, &vrf,
                          vrf_err, sizeof(vrf_err)) != 0) {
        record_op("static-apply", "blocked", msg->tx_id, &stats);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd VRF validation failed: %s", vrf_err);
    }
    if (dynamic_gate_blocked(conn, msg, &stats))
        return 0;
    if (stats.has_dynamic_protocol) {
        char frr_err[192] = {0};

        if (rpd_frr_config_validate_plan((const char *)msg->payload,
                                         (int)msg->payload_len,
                                         frr_err, sizeof(frr_err)) != 0) {
            record_op("static-apply", "blocked", msg->tx_id, &stats);
            return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: rpd FRR intent validation failed: %s",
                             frr_err[0] ? frr_err : "invalid intent");
        }
    }
    static_len = copy_static_plan((const char *)msg->payload,
                                  (int)msg->payload_len,
                                  static_plan, sizeof(static_plan),
                                  &stripped);
    if (static_len < 0) {
        record_op("static-apply", "blocked", msg->tx_id, &stats);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd static L3 plan exceeds forwarding buffer");
    }
    rib_len = copy_static_rib_plan((const char *)msg->payload,
                                   (int)msg->payload_len,
                                   rib_plan, sizeof(rib_plan), NULL);
    if (rib_len < 0) {
        record_op("static-apply", "blocked", msg->tx_id, &stats);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd static L3 plan exceeds RIB buffer");
    }
    {
        char preflight_err[160] = {0};

        if (validate_static_rib_plan(rib_plan, rib_len, &vrf,
                                     preflight_err,
                                     sizeof(preflight_err)) != 0) {
            record_op(stripped ? "static-apply-dynamic-stripped" :
                      "static-apply", "blocked", msg->tx_id, &stats);
            return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: rpd RIB validation failed: %s",
                             preflight_err[0] ? preflight_err :
                             "invalid static plan");
        }
    }

    if (g_rpd.vrf.enabled &&
        (!vrf.enabled || strcmp(g_rpd.vrf.table, vrf.table) != 0)) {
        char clear_err[192] = {0};

        if (clear_vrf_dynamic_owner_locked(clear_err,
                                           sizeof(clear_err)) != 0) {
            record_op("static-apply", "blocked", msg->tx_id, &stats);
            return send_text(conn, msg, NL_ERR_COMMIT_CONFLICT,
                             "error: VRF dynamic FIB pre-delete failed: %s",
                             clear_err[0] ? clear_err : "switchd rejected clear");
        }
        vrf_dynamic_precleared = true;
    }

    rc = dispatch_owner_method(conn, msg, NL_L3_OWNER_APPLY, static_plan, static_len,
                               &owner_ec);
    if ((rc != 0 || owner_ec != 0) && vrf_dynamic_precleared)
        (void)sync_switchd_fib_scope_locked(&g_rpd.vrf_rib,
                                            "vrf-owner-restore", true);
    if (rc == 0 && owner_ec == 0) {
        u64 next_update_id = g_rpd.fib_update_id + 1;
        char frr_err[192] = {0};

        memcpy(&g_rpd.rollback_rib, &g_rpd.rib, sizeof(g_rpd.rollback_rib));
        memcpy(&g_rpd.rollback_vrf_rib, &g_rpd.vrf_rib,
               sizeof(g_rpd.rollback_vrf_rib));
        g_rpd.rollback_vrf = g_rpd.vrf;
        memcpy(&g_rpd.rollback_frr_intent, &g_rpd.frr_intent,
               sizeof(g_rpd.rollback_frr_intent));
        memcpy(g_rpd.rollback_static_owner_plan,
               g_rpd.static_owner_plan,
               (size_t)g_rpd.static_owner_plan_len + 1);
        g_rpd.rollback_static_owner_plan_len =
            g_rpd.static_owner_plan_len;
        g_rpd.rollback_static_owner_plan_valid =
            g_rpd.static_owner_plan_valid;
        memcpy(g_rpd.rollback_static_owner_applied_plan,
               g_rpd.static_owner_applied_plan,
               (size_t)g_rpd.static_owner_applied_plan_len + 1);
        g_rpd.rollback_static_owner_applied_plan_len =
            g_rpd.static_owner_applied_plan_len;
        g_rpd.rollback_static_owner_applied_plan_valid =
            g_rpd.static_owner_applied_plan_valid;
        g_rpd.rollback_static_rib_only_routes =
            g_rpd.static_rib_only_routes;
        g_rpd.rollback_static_owner_rib_routes_installed =
            g_rpd.static_owner_rib_routes_installed;
        g_rpd.rollback_rib_available = true;
        g_rpd.generation++;
        g_rpd.last_tx_id = msg->tx_id;
        g_rpd.last_apply = time(NULL);
        memcpy(g_rpd.static_owner_plan, static_plan,
               (size_t)static_len);
        g_rpd.static_owner_plan[static_len] = '\0';
        g_rpd.static_owner_plan_len = static_len;
        g_rpd.static_owner_plan_valid = true;
        g_rpd.static_rib_only_routes =
            plan_has_rib_static_route(rib_plan);
        g_rpd.static_owner_rib_routes_installed = false;
        save_static_owner_applied_plan(&g_rpd, static_plan, static_len);
        {
            bool reuse_vrf = g_rpd.vrf.enabled && vrf.enabled &&
                strcmp(g_rpd.vrf.table, vrf.table) == 0;

            g_rpd.vrf = vrf;
            if (!vrf.enabled) {
                (void)rpd_rib_init_scope(&g_rpd.vrf_rib,
                                         "vrf1.inet.0",
                                         RPD_VRF_V1_KERNEL_TABLE);
            } else if (!reuse_vrf &&
                       rpd_rib_init_scope(&g_rpd.vrf_rib, vrf.table,
                                          vrf.kernel_table) != 0) {
                set_drift_state("error", "failed to initialize VRF RIB");
            }
        }
        if (rpd_frr_config_compile_plan(&g_rpd.frr_intent,
                                        (const char *)msg->payload,
                                        (int)msg->payload_len,
                                        g_rpd.generation,
                                        frr_err, sizeof(frr_err)) != 0) {
            set_drift_state("error", frr_err);
            NL_LOG_WARN("rpd FRR intent compile failed: %s", frr_err);
        } else {
            frr_intent_compile_ok = true;
            has_route_protocols =
                frr_config_has_route_protocols(&g_rpd.frr_intent);
            if (rpd_frr_runtime_configure(&g_rpd.frr_runtime,
                                          &g_rpd.frr_intent,
                                          frr_err,
                                          sizeof(frr_err)) != 0) {
                set_drift_state("error", frr_err);
                NL_LOG_WARN("rpd FRR runtime configure failed: %s", frr_err);
            }
        }
        if (rpd_rib_sync_static_plan(&g_rpd.rib, rib_plan, rib_len,
                                     g_rpd.generation, next_update_id,
                                     &rib_result, rib_err,
                                     sizeof(rib_err)) != 0) {
            set_drift_state("error", rib_err);
            NL_LOG_WARN("rpd static RIB sync failed: %s", rib_err);
        } else {
            rib_sync_ok = true;
        }
        if (vrf.enabled) {
            rpd_rib_update_result vrf_result;

            if (rpd_rib_sync_static_plan(&g_rpd.vrf_rib,
                                         rib_plan, rib_len,
                                         g_rpd.generation, next_update_id,
                                         &vrf_result, rib_err,
                                         sizeof(rib_err)) != 0) {
                rib_sync_ok = false;
                set_drift_state("error", rib_err);
                NL_LOG_WARN("rpd VRF static RIB sync failed: %s", rib_err);
            }
        }
    }
    record_op(stripped ? "static-apply-dynamic-stripped" :
              "static-apply", owner_ec == 0 ? "ok" : "failed",
              msg->tx_id, &stats);
    if (owner_ec == 0 && frr_intent_compile_ok &&
        had_route_protocols && !has_route_protocols)
        (void)purge_dynamic_protocol_routes_locked("dynamic-protocol-purge",
                                                   msg->tx_id);
    if (owner_ec == 0 && rib_sync_ok &&
        reapply_static_owner_from_rib_locked(&g_rpd,
                                             "static-owner-reapply") > 0)
        return rc;
    /* A successful persistent apply advances generation/update authority even
     * when the route set is unchanged. Publish that metadata to switchd so
     * the first periodic read-back cannot report synthetic drift. */
    if (owner_ec == 0 && rib_sync_ok)
        (void)sync_switchd_fib_locked("static-commit", false);
    return rc;
}

static int handle_rollback(nl_conn *conn, nl_msg_hdr *msg) {
    nl_msg_hdr *owner_resp = NULL;
    bool owner_not_needed;
    s32 owner_ec = NL_ERR_DAEMON_UNREACHABLE;
    int rc;

    rc = call_owner_method_capture(g_rpd.l3_owner, msg, NL_L3_OWNER_ROLLBACK, NULL, 0, &owner_resp);
    if (rc != 0 || !owner_resp)
        return send_text(conn, msg, NL_ERR_RPC_TIMEOUT,
                         "error: rpd owner dispatch failed");
    update_owner_state_from_response(NL_RPD_ROLLBACK, owner_resp);
    owner_ec = owner_resp->error_code;
    owner_not_needed = rollback_owner_not_needed(&g_rpd, owner_ec);
    if (owner_ec == 0 || owner_not_needed) {
        if (g_rpd.rollback_rib_available) {
            memcpy(&g_rpd.rib, &g_rpd.rollback_rib, sizeof(g_rpd.rib));
            memcpy(&g_rpd.vrf_rib, &g_rpd.rollback_vrf_rib,
                   sizeof(g_rpd.vrf_rib));
            g_rpd.vrf = g_rpd.rollback_vrf;
            memcpy(&g_rpd.frr_intent, &g_rpd.rollback_frr_intent,
                   sizeof(g_rpd.frr_intent));
            memcpy(g_rpd.static_owner_plan,
                   g_rpd.rollback_static_owner_plan,
                   (size_t)g_rpd.rollback_static_owner_plan_len + 1);
            g_rpd.static_owner_plan_len =
                g_rpd.rollback_static_owner_plan_len;
            g_rpd.static_owner_plan_valid =
                g_rpd.rollback_static_owner_plan_valid;
            memcpy(g_rpd.static_owner_applied_plan,
                   g_rpd.rollback_static_owner_applied_plan,
                   (size_t)g_rpd.rollback_static_owner_applied_plan_len + 1);
            g_rpd.static_owner_applied_plan_len =
                g_rpd.rollback_static_owner_applied_plan_len;
            g_rpd.static_owner_applied_plan_valid =
                g_rpd.rollback_static_owner_applied_plan_valid;
            g_rpd.static_rib_only_routes =
                g_rpd.rollback_static_rib_only_routes;
            g_rpd.static_owner_rib_routes_installed =
                g_rpd.rollback_static_owner_rib_routes_installed;
            (void)rpd_frr_runtime_configure(&g_rpd.frr_runtime,
                                            &g_rpd.frr_intent, NULL, 0);
            g_rpd.rollback_rib_available = false;
        }
        g_rpd.generation++;
        g_rpd.last_rollback = time(NULL);
        if (owner_not_needed) {
            g_rpd.last_owner_ec = 0;
            set_drift_state("pending-readback",
                            "dynamic-only rollback restored rpd state");
        }
    }
    record_op("rollback", (owner_ec == 0 || owner_not_needed) ? "ok" : "failed",
              msg->tx_id, NULL);
    (void)rollback_switchd_fib_locked("rollback", msg->tx_id);
    if (owner_ec == 0 || owner_not_needed) {
        (void)sync_switchd_fib_locked("rollback", true);
    }
    if (owner_not_needed) {
        nl_msg_free(owner_resp);
        return send_text(conn, msg, 0,
                         "<l3-persistent-rollback status=\"ok\" tx-id=\"%llu\" "
                         "mode=\"dynamic-only\" owner-rollback=\"not-needed\" "
                         "reason=\"rpd restored RIB and FRR intent snapshot\"/>",
                         (unsigned long long)msg->tx_id);
    }
    rc = nl_send(conn, owner_resp) == NL_OK ? 0 : -1;
    nl_msg_free(owner_resp);
    return rc;
}

static int handle_reconcile(nl_conn *conn, nl_msg_hdr *msg) {
    s32 owner_ec = NL_ERR_DAEMON_UNREACHABLE;
    int rc;

    g_rpd.last_reconcile = time(NULL);
    rc = dispatch_owner_method(conn, msg, NL_L3_OWNER_READBACK, NULL, 0, &owner_ec);
    record_op("reconcile", owner_ec == 0 ? "ok" : "failed",
              msg->tx_id, NULL);
    if (owner_ec == 0 &&
        reconcile_switchd_fib_locked("reconcile") != 0)
        (void)sync_switchd_fib_locked("reconcile", true);
    return rc;
}

static int route_update_table_id(const char *payload, int payload_len,
                                 u32 *table_id,
                                 char *err, size_t err_size) {
    char *buf = NULL;
    char *save = NULL;
    char *tok;
    u32 found = RPD_RIB_MAIN_KERNEL_TABLE;
    bool explicit_table = false;
    int rc = -1;

    if (!payload || payload_len <= 0 || payload_len >= NETLAB_MAX_MSG ||
        !table_id) {
        snprintf(err, err_size, "invalid route update scope");
        return -1;
    }
    buf = malloc((size_t)payload_len + 1U);
    if (!buf) {
        snprintf(err, err_size, "route update parser is out of memory");
        return -1;
    }
    memcpy(buf, payload, (size_t)payload_len);
    buf[payload_len] = '\0';
    tok = strtok_r(buf, " \t\r\n", &save);
    while (tok) {
        if (strncmp(tok, "table-id=", 9) == 0) {
            char *end = NULL;
            unsigned long value = strtoul(tok + 9, &end, 10);

            if (!end || *end || value > 0xffffffffUL || value == 0 ||
                (explicit_table && found != (u32)value)) {
                snprintf(err, err_size, "invalid route update table id");
                goto out;
            }
            found = (u32)value;
            explicit_table = true;
        }
        tok = strtok_r(NULL, " \t\r\n", &save);
    }
    if (found != RPD_RIB_MAIN_KERNEL_TABLE &&
        found != RPD_VRF_V1_KERNEL_TABLE) {
        snprintf(err, err_size, "unsupported route update table id: %u",
                 found);
        goto out;
    }
    *table_id = found;
    rc = 0;

out:
    free(buf);
    return rc;
}

static rpd_rib *route_update_rib_locked(u32 table_id,
                                        char *err, size_t err_size) {
    if (table_id == RPD_RIB_MAIN_KERNEL_TABLE)
        return &g_rpd.rib;
    if (table_id == RPD_VRF_V1_KERNEL_TABLE && g_rpd.vrf.enabled)
        return &g_rpd.vrf_rib;
    snprintf(err, err_size,
             "VRF route update rejected: kernel table %u is not active",
             table_id);
    return NULL;
}

static int handle_dynamic_update(nl_conn *conn, nl_msg_hdr *msg) {
    rpd_rib_update_result result;
    rpd_plan_stats stats;
    char err[192] = {0};
    char *normalized = NULL;
    bool normalized_changed = false;
    u64 next_generation = g_rpd.generation + 1;
    u64 next_update_id = g_rpd.fib_update_id + 1;
    u64 response_generation;
    u64 response_fib_update_id;
    int normalized_len;
    int rc;
    int response_rc;
    int sync_rc = 0;
    u32 table_id;
    rpd_rib *rib;

    memset(&stats, 0, sizeof(stats));
    if (!g_rpd.fpm_programming_enabled || !g_rpd.fpm.enabled) {
        char reason[512];

        dynamic_gate_reason(reason, sizeof(reason));
        return send_text(conn, msg, NL_ERR_UNSUPPORTED_FEATURE,
                         "error: rpd dynamic route update rejected: "
                         "FPM-style route ingestion is not open: %s",
                         reason);
    }
    if (!churn_gate_allow_locked(err, sizeof(err))) {
        record_op_no_bump("dynamic-fpm-update", "churn-limited",
                          msg->tx_id, NULL);
        return send_text(conn, msg, NL_ERR_COMMIT_CONFLICT,
                         "error: %s", err);
    }
    normalized_len = normalize_fpm_rifs_alloc_locked(
        &g_rpd, (const char *)msg->payload, (int)msg->payload_len,
        &normalized, &normalized_changed);
    if (normalized_len < 0) {
        record_op_no_bump("dynamic-fpm-update", "invalid", msg->tx_id, NULL);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd dynamic route update normalization failed");
    }
    if (route_update_table_id(normalized, normalized_len, &table_id,
                              err, sizeof(err)) != 0 ||
        !(rib = route_update_rib_locked(table_id, err, sizeof(err)))) {
        record_op_no_bump("dynamic-fpm-update", "invalid", msg->tx_id,
                          NULL);
        response_rc = send_text(conn, msg, NL_ERR_INVALID_VALUE,
                                "error: %s", err);
        goto out;
    }
    rc = rpd_rib_apply_fpm_text(rib, normalized, normalized_len,
                                next_generation,
                                next_update_id, &result, err, sizeof(err));
    if (rc != 0) {
        record_op_no_bump("dynamic-fpm-update",
                          result.idempotency_conflict ?
                          "idempotency-conflict" : "invalid",
                          msg->tx_id, NULL);
        response_rc = send_text(
            conn, msg,
            result.idempotency_conflict ? NL_ERR_IDEMPOTENCY_CONFLICT :
            NL_ERR_INVALID_VALUE,
            "error: %s", err[0] ? err : "invalid RIB update");
        goto out;
    }
    stats.routes = result.routes_changed + result.routes_deleted;
    stats.ecmp_groups = result.ecmp_routes;
    snprintf(stats.idempotency_key, sizeof(stats.idempotency_key), "%s",
             result.idempotency_key[0] ? result.idempotency_key : "-");
    if (result.changed) {
        g_rpd.generation = next_generation;
        record_op("dynamic-fpm-update", "ok", msg->tx_id, &stats);
        if (g_rpd.defer_fpm_fib_sync) {
            set_fib_sync_state(
                "deferred",
                "NETLAB_RPD_DEFER_FPM_FIB_SYNC=1");
        } else {
            sync_rc = fpm_sync_batch_queue_locked(
                &g_rpd, rib, &result, "dynamic-fpm-update-batch");
        }
    } else {
        record_op_no_bump("dynamic-fpm-update",
                          result.idempotent ? "idempotent" : "no-change",
                          msg->tx_id, &stats);
    }
    if (sync_rc != 0) {
        response_rc = send_text(
            conn, msg, NL_ERR_COMMIT_CONFLICT,
            "error: dynamic route accepted into RIB but FIB "
            "pipeline is under backpressure");
        goto out;
    }
    response_generation = result.generation;
    response_fib_update_id = result.fib_update_id;
    response_rc = send_text(conn, msg, 0,
                            "<rpd-rib-update status=\"ok\" table=\"%s\" "
                     "changed=\"%s\" idempotent=\"%s\" "
                     "generation=\"%llu\" fib-generation=\"%llu\" "
                     "fib-update-id=\"%llu\" "
                     "current-generation=\"%llu\" "
                     "current-fib-update-id=\"%llu\" "
                     "idempotency-key=\"%s\" "
                     "routes-changed=\"%d\" routes-deleted=\"%d\" "
                     "routes-unchanged=\"%d\" ecmp-routes=\"%d\" "
                     "ecmp-members=\"%d\" normalized-rif=\"%s\" "
                     "fib-sync=\"%s\" "
                     "detail=\"%s\"/>",
                     rib->table, result.changed ? "true" : "false",
                     result.idempotent ? "true" : "false",
                     (unsigned long long)response_generation,
                     (unsigned long long)response_generation,
                     (unsigned long long)response_fib_update_id,
                     (unsigned long long)g_rpd.generation,
                     (unsigned long long)g_rpd.fib_update_id,
                     result.idempotency_key[0] ? result.idempotency_key : "-",
                     result.routes_changed, result.routes_deleted,
                     result.routes_unchanged, result.ecmp_routes,
                     result.ecmp_members,
                     normalized_changed ? "true" : "false",
                     g_rpd.fib_sync_state,
                            result.detail);

out:
    free(normalized);
    return response_rc;
}

static int handle_dynamic_arp_update(nl_conn *conn, nl_msg_hdr *msg) {
    rpd_rib_update_result result;
    rpd_plan_stats stats;
    char err[192] = {0};
    u64 next_generation = g_rpd.generation + 1;
    u64 next_update_id = g_rpd.fib_update_id + 1;
    int rc;
    int sync_rc = 0;

    memset(&stats, 0, sizeof(stats));
    if (!g_rpd.fpm_programming_enabled || !g_rpd.fpm.enabled) {
        char reason[512];

        dynamic_gate_reason(reason, sizeof(reason));
        return send_text(conn, msg, NL_ERR_UNSUPPORTED_FEATURE,
                         "error: rpd dynamic ARP update rejected: "
                         "FPM-style route ingestion is not open: %s",
                         reason);
    }
    plan_stats((const char *)msg->payload, (int)msg->payload_len, &stats);
    rc = rpd_rib_sync_dynamic_arp_text(
        &g_rpd.rib, (const char *)msg->payload, (int)msg->payload_len,
        next_generation, next_update_id, &result, err, sizeof(err));
    if (rc != 0) {
        record_op_no_bump("dynamic-arp-sync", "invalid", msg->tx_id,
                          &stats);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: %s", err[0] ? err :
                         "invalid dynamic ARP update");
    }
    if (result.changed) {
        g_rpd.generation = next_generation;
        record_op("dynamic-arp-sync", "ok", msg->tx_id, &stats);
        if (g_rpd.defer_fpm_fib_sync) {
            set_fib_sync_state(
                "deferred",
                "NETLAB_RPD_DEFER_FPM_FIB_SYNC=1");
        } else {
            sync_rc = sync_switchd_fib_delta_locked(
                &g_rpd.rib, "dynamic-arp-sync", &result);
        }
    } else {
        record_op_no_bump("dynamic-arp-sync", "no-change", msg->tx_id,
                          &stats);
    }
    if (sync_rc != 0)
        return send_text(conn, msg, NL_ERR_COMMIT_CONFLICT,
                         "error: dynamic ARP accepted into RIB but FIB "
                         "pipeline is under backpressure");
    return send_text(conn, msg, 0,
                     "<rpd-arp-update status=\"ok\" table=\"inet.0\" "
                     "changed=\"%s\" generation=\"%llu\" "
                     "fib-generation=\"%llu\" fib-update-id=\"%llu\" "
                     "current-generation=\"%llu\" "
                     "current-fib-update-id=\"%llu\" arp=\"%d\" "
                     "fib-sync=\"%s\" detail=\"%s\"/>",
                     result.changed ? "true" : "false",
                     (unsigned long long)result.generation,
                     (unsigned long long)result.generation,
                     (unsigned long long)result.fib_update_id,
                     (unsigned long long)g_rpd.generation,
                     (unsigned long long)g_rpd.fib_update_id,
                     stats.arp,
                     g_rpd.fib_sync_state,
                     result.detail);
}

static int apply_fpm_update_locked(const char *payload, int payload_len,
                                   const char *action,
                                   char *err, size_t err_size) {
    rpd_rib_update_result result;
    rpd_plan_stats stats;
    char *normalized = NULL;
    bool normalized_changed = false;
    u64 next_generation = g_rpd.generation + 1;
    u64 next_update_id = g_rpd.fib_update_id + 1;
    int normalized_len;
    int rc;
    u32 table_id;
    rpd_rib *rib;

    memset(&stats, 0, sizeof(stats));
    if (!churn_gate_allow_locked(err, err_size)) {
        record_op_no_bump(action, "churn-limited", 0, NULL);
        return -1;
    }
    normalized_len = normalize_fpm_rifs_alloc_locked(
        &g_rpd, payload, payload_len, &normalized, &normalized_changed);
    if (normalized_len < 0) {
        snprintf(err, err_size, "FPM route RIF normalization failed");
        record_op_no_bump(action, "invalid", 0, NULL);
        return -1;
    }
    if (route_update_table_id(normalized, normalized_len, &table_id,
                              err, err_size) != 0 ||
        !(rib = route_update_rib_locked(table_id, err, err_size))) {
        record_op_no_bump(action, "invalid", 0, NULL);
        rc = -1;
        goto out;
    }
    rc = rpd_rib_apply_fpm_text(rib, normalized, normalized_len,
                                next_generation, next_update_id,
                                &result, err, err_size);
    if (rc != 0) {
        record_op_no_bump(action, result.idempotency_conflict ?
                          "idempotency-conflict" : "invalid", 0, NULL);
        rc = -1;
        goto out;
    }
    stats.routes = result.routes_changed + result.routes_deleted;
    stats.ecmp_groups = result.ecmp_routes;
    snprintf(stats.idempotency_key, sizeof(stats.idempotency_key), "%s",
             result.idempotency_key[0] ? result.idempotency_key : "-");
    if (result.changed) {
        g_rpd.generation = next_generation;
        record_op(action, "ok", 0, &stats);
        if (g_rpd.defer_fpm_fib_sync) {
            set_fib_sync_state(
                "deferred",
                "NETLAB_RPD_DEFER_FPM_FIB_SYNC=1");
        } else {
            rc = fpm_sync_batch_queue_locked(
                &g_rpd, rib, &result, "fpm-route-update-batch");
            if (rc != 0) {
                snprintf(err, err_size,
                         "FIB programming pipeline backpressure");
                goto out;
            }
        }
    } else {
        record_op_no_bump(action,
                          result.idempotent ? "idempotent" : "no-change",
                          0, &stats);
    }
    rc = 0;

out:
    free(normalized);
    return rc;
}

static int current_fpm_authority_locked(
    rpd_ctx *rpd, rpd_fpm_peer_authority *authority,
    char *err, size_t err_size) {
#ifdef NETLAB_FPM_TEST_AUTHORITY
    (void)rpd;
    return rpd_fpm_test_authority_snapshot(authority, err, err_size);
#else
    rpd_frr_zebra_authority zebra;

    if (!rpd ||
        !rpd_frr_runtime_zebra_authority(
            &rpd->frr_runtime, &zebra, err, err_size))
        return -1;
    memset(authority, 0, sizeof(*authority));
    authority->pid = zebra.pid;
    authority->uid = zebra.uid;
    authority->starttime = zebra.starttime;
    authority->generation = zebra.generation;
    snprintf(authority->executable, sizeof(authority->executable),
             "%s", zebra.executable);
    return 0;
#endif
}

static int rpd_fpm_authority_cb(
    void *ctx, rpd_fpm_peer_authority *authority,
    char *err, size_t err_size) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;
    int rc;

    rpd_lock(rpd);
    rc = current_fpm_authority_locked(
        rpd, authority, err, err_size);
    rpd_unlock(rpd);
    return rc;
}

static bool fpm_peer_matches_authority(
    const rpd_fpm_peer_identity *peer,
    const rpd_fpm_peer_authority *authority) {
    return peer && authority &&
           peer->pid == authority->pid &&
           peer->uid == authority->uid &&
           peer->starttime == authority->starttime &&
           peer->authority_generation == authority->generation &&
           strcmp(peer->executable, authority->executable) == 0;
}

static int rpd_fpm_apply_cb(void *ctx,
                            const rpd_fpm_peer_identity *peer,
                            const char *payload, int payload_len,
                            char *err, size_t err_size) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;
    rpd_fpm_peer_authority authority;
    int rc;

    rpd_lock(rpd);
    if (current_fpm_authority_locked(
            rpd, &authority, err, err_size) != 0 ||
        !fpm_peer_matches_authority(peer, &authority)) {
        if (!err[0])
            snprintf(err, err_size,
                     "FPM apply rejected: managed zebra authority changed");
        rpd_unlock(rpd);
        return RPD_FPM_APPLY_AUTHORITY_REJECTED;
    }
    rc = apply_fpm_update_locked(payload, payload_len, "fpm-route-update",
                                 err, err_size);
    rpd_unlock(rpd);
    return rc;
}

static int run_ip_neigh_capture(const rpd_ctx *rpd, char *out,
                                size_t out_size,
                                char *err, size_t err_size) {
    int fds[2] = {-1, -1};
    pid_t pid;
    size_t off = 0;
    int status = 0;
    int done = 0;

    if (!rpd || !out || out_size == 0 || !rpd->linux_arp_ip_path[0]) {
        snprintf(err, err_size, "Linux ARP ip command is unavailable");
        return -1;
    }
    out[0] = '\0';
    if (pipe(fds) != 0) {
        snprintf(err, err_size, "failed to create Linux ARP pipe");
        return -1;
    }
    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        execl(rpd->linux_arp_ip_path, rpd->linux_arp_ip_path,
              "-4", "neigh", "show", "dev", rpd->linux_arp_ifname,
              (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    fds[1] = -1;
    if (pid < 0) {
        close(fds[0]);
        snprintf(err, err_size, "failed to fork Linux ARP poller");
        return -1;
    }
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    for (int i = 0; i < 20 && !done; i++) {
        struct pollfd pfd;
        char chunk[512];
        ssize_t n;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fds[0];
        pfd.events = POLLIN | POLLHUP;
        (void)poll(&pfd, 1, 50);
        while ((n = read(fds[0], chunk, sizeof(chunk))) > 0) {
            size_t copy = (size_t)n;

            if (copy >= out_size - off)
                copy = out_size - off - 1;
            if (copy > 0) {
                memcpy(out + off, chunk, copy);
                off += copy;
                out[off] = '\0';
            }
        }
        if (waitpid(pid, &status, WNOHANG) == pid)
            done = 1;
    }
    if (!done) {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        close(fds[0]);
        snprintf(err, err_size, "Linux ARP poll timed out");
        return -1;
    }
    close(fds[0]);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        snprintf(err, err_size, "Linux ARP ip command failed");
        return -1;
    }
    return 0;
}

static bool parse_linux_neigh_line(const char *line, char *ip, size_t ip_size,
                                   char *mac, size_t mac_size) {
    char tmp[512];
    char *argv[32];
    int argc = 0;
    char *save = NULL;
    char *tok;
    bool has_mac = false;
    bool usable_state = false;

    if (!line || strlen(line) >= sizeof(tmp))
        return false;
    snprintf(tmp, sizeof(tmp), "%s", line);
    tok = strtok_r(tmp, " \t", &save);
    while (tok && argc < (int)(sizeof(argv) / sizeof(argv[0]))) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " \t", &save);
    }
    if (argc < 1)
        return false;
    if (!token_safe(argv[0]))
        return false;
    snprintf(ip, ip_size, "%s", argv[0]);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "lladdr") == 0 && i + 1 < argc &&
            token_safe(argv[i + 1])) {
            snprintf(mac, mac_size, "%s", argv[i + 1]);
            has_mac = true;
        }
        if (strcmp(argv[i], "REACHABLE") == 0 ||
            strcmp(argv[i], "STALE") == 0 ||
            strcmp(argv[i], "DELAY") == 0 ||
            strcmp(argv[i], "PROBE") == 0 ||
            strcmp(argv[i], "PERMANENT") == 0 ||
            strcmp(argv[i], "NOARP") == 0)
            usable_state = true;
        if (strcmp(argv[i], "FAILED") == 0 ||
            strcmp(argv[i], "INCOMPLETE") == 0)
            return false;
    }
    return has_mac && usable_state;
}

static int linux_neigh_to_rib_payload(rpd_ctx *rpd, const char *neigh,
                                      char *payload, size_t payload_size,
                                      int *entries,
                                      char *err, size_t err_size) {
    char buf[8192];
    char *save = NULL;
    char *line;
    size_t off = 0;
    int count = 0;

    if (!rpd || !payload || payload_size == 0)
        return -1;
    payload[0] = '\0';
    snprintf(buf, sizeof(buf), "%s", neigh ? neigh : "");
    line = strtok_r(buf, "\n", &save);
    while (line) {
        char ip[40];
        char mac[32];

        if (parse_linux_neigh_line(line, ip, sizeof(ip), mac, sizeof(mac))) {
            int n = snprintf(payload + off, payload_size - off,
                             "arp ip %s mac %s interface %s "
                             "egress-port %s\n",
                             ip, mac, rpd->linux_arp_rif,
                             rpd->linux_arp_ifname);
            if (n < 0 || (size_t)n >= payload_size - off) {
                snprintf(err, err_size,
                         "Linux ARP payload exceeded rpd buffer");
                return -1;
            }
            off += (size_t)n;
            count++;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    if (entries)
        *entries = count;
    return 0;
}

static void set_linux_arp_status(rpd_ctx *rpd, const char *status,
                                 const char *reason) {
    if (!rpd)
        return;
    snprintf(rpd->linux_arp_status, sizeof(rpd->linux_arp_status), "%s",
             status ? status : "unknown");
    snprintf(rpd->linux_arp_reason, sizeof(rpd->linux_arp_reason), "%s",
             reason ? reason : "-");
}

static int poll_linux_arp_locked(rpd_ctx *rpd, bool force) {
    char neigh[8192];
    char payload[8192];
    char err[192] = {0};
    rpd_rib_update_result result;
    rpd_plan_stats stats;
    u64 next_generation;
    u64 next_update_id;
    int entries = 0;
    s64 now_ms;

    if (!rpd || !rpd->linux_arp_enabled)
        return 0;
    now_ms = monotonic_ms();
    if (!force && rpd->last_linux_arp_ms > 0 &&
        now_ms - rpd->last_linux_arp_ms < rpd->linux_arp_interval_ms)
        return 0;
    rpd->last_linux_arp_ms = now_ms;
    rpd->linux_arp_runs++;
    if (run_ip_neigh_capture(rpd, neigh, sizeof(neigh),
                             err, sizeof(err)) != 0 ||
        linux_neigh_to_rib_payload(rpd, neigh, payload, sizeof(payload),
                                   &entries, err, sizeof(err)) != 0) {
        rpd->linux_arp_errors++;
        set_linux_arp_status(rpd, "error", err[0] ? err :
                             "Linux ARP poll failed");
        return -1;
    }
    next_generation = rpd->generation + 1;
    next_update_id = rpd->fib_update_id + 1;
    if (rpd_rib_sync_dynamic_arp_text(&rpd->rib, payload,
                                      (int)strlen(payload),
                                      next_generation, next_update_id,
                                      &result, err, sizeof(err)) != 0) {
        rpd->linux_arp_errors++;
        set_linux_arp_status(rpd, "error", err[0] ? err :
                             "Linux ARP RIB sync failed");
        return -1;
    }
    rpd->linux_arp_entries = entries;
    rpd->last_linux_arp = time(NULL);
    set_linux_arp_status(rpd, "ok", result.detail);
    if (result.changed) {
        memset(&stats, 0, sizeof(stats));
        stats.arp = entries;
        rpd->generation = next_generation;
        record_op("linux-arp-sync", "ok", 0, &stats);
        if (reapply_static_owner_from_rib_locked(
                rpd, "linux-arp-static-owner-reapply") <= 0)
            (void)sync_switchd_fib_locked("linux-arp-sync", false);
    }
    return 0;
}

static int handle_rpd_state(nl_conn *conn, nl_msg_hdr *msg) {
    char buf[RPD_STATE_MAX];
    int n;
    size_t off;
    time_t now = time(NULL);
    bool dynamic_open = frr_dynamic_config_open_cached();
    const char *dynamic_state = dynamic_open ? "enabled" : "gated";
    char dynamic_reason[512];

    dynamic_gate_reason_cached(dynamic_reason, sizeof(dynamic_reason));

    n = snprintf(buf, sizeof(buf),
                   "<rpd-state table=\"inet.0\" generation=\"%llu\" "
                   "fib-update-id=\"%llu\" last-tx-id=\"%llu\" "
                   "started-age=\"%ld\" last-apply-age=\"%ld\" "
                   "last-rollback-age=\"%ld\" last-reconcile-age=\"%ld\" "
                   "last-readback-age=\"%ld\" "
                   "last-fib-sync-age=\"%ld\" "
                   "last-fib-readback-age=\"%ld\">\n"
                   "  <frr config-enabled=\"%s\" runtime-present=\"%s\" "
                   "runtime-start-gate=\"%s\" "
                   "fpm-programming-enabled=\"%s\" "
                   "dynamic-config-open=\"%s\" zebra=\"%s\" "
                   "ospfd=\"%s\" bgpd=\"%s\"/>\n"
                   "  <drift state=\"%s\" reason=\"%s\" "
                   "owner-mode=\"%s\" switchd-owner=\"%s\" "
                   "last-owner-ec=\"%d\"/>\n"
                   "  <fib-sync state=\"%s\" reason=\"%s\" "
                   "switchd-status=\"%s\" last-fib-ec=\"%d\" "
                   "generation=\"%llu\" fib-update-id=\"%llu\" "
                   "routes=\"%d\" apply-method=\"%d\" "
                   "snapshot-begin-method=\"%d\" "
                   "snapshot-part-method=\"%d\" "
                   "snapshot-commit-method=\"%d\" "
                   "snapshot-abort-method=\"%d\" "
                   "readback-method=\"%d\" reconcile-method=\"%d\" "
                   "rollback-method=\"%d\" "
                   "fpm-deferred=\"%s\"/>\n"
                   "  <fib-live status=\"%s\" gate=\"%s\" "
                   "live-ready=\"%s\" dynamic-routes=\"%d\" "
                   "owner-routes=\"%d\" ifindex-rifs=\"%d\" "
                   "missing=\"%s\" reason=\"%s\"/>\n"
                   "  <dynamic-routing fpm=\"%s\" ospf=\"%s\" "
                   "bgp=\"%s\" reason=\"%s\"/>\n"
                   "  <churn-gate enabled=\"%s\" state=\"%s\" "
                   "window-ms=\"%d\" max-updates=\"%d\" used=\"%d\" "
                   "drops=\"%llu\" last-drop-age=\"%ld\" "
                   "reason=\"%s\"/>\n"
                   "  <periodic-reconcile enabled=\"%s\" "
                   "interval-ms=\"%d\" runs=\"%llu\" errors=\"%llu\" "
                   "last-age=\"%ld\"/>\n"
                   "  <linux-arp enabled=\"%s\" status=\"%s\" "
                   "reason=\"%s\" ifname=\"%s\" rif=\"%s\" "
                   "ip-command=\"%s\" interval-ms=\"%d\" "
                   "runs=\"%llu\" errors=\"%llu\" entries=\"%d\" "
                   "last-age=\"%ld\"/>\n",
                   (unsigned long long)g_rpd.generation,
                   (unsigned long long)g_rpd.fib_update_id,
                   (unsigned long long)g_rpd.last_tx_id,
                   (long)(now - g_rpd.started_at),
                   g_rpd.last_apply ? (long)(now - g_rpd.last_apply) : -1L,
                   g_rpd.last_rollback ?
                       (long)(now - g_rpd.last_rollback) : -1L,
                   g_rpd.last_reconcile ?
                       (long)(now - g_rpd.last_reconcile) : -1L,
                   g_rpd.last_readback ?
                       (long)(now - g_rpd.last_readback) : -1L,
                   g_rpd.last_fib_sync ?
                       (long)(now - g_rpd.last_fib_sync) : -1L,
                   g_rpd.last_fib_readback ?
                       (long)(now - g_rpd.last_fib_readback) : -1L,
                   g_rpd.frr_config_enabled ? "true" : "false",
                   g_rpd.frr_runtime.runtime_present ? "true" : "false",
                   g_rpd.frr_runtime.start_gate_enabled ? "true" : "false",
                   g_rpd.fpm_programming_enabled ? "true" : "false",
                   dynamic_open ? "true" : "false",
                   g_rpd.frr_runtime.zebra_path[0] ? "true" : "false",
                   g_rpd.frr_runtime.ospfd_path[0] ? "true" : "false",
                   g_rpd.frr_runtime.bgpd_path[0] ? "true" : "false",
                   g_rpd.drift_state,
                   g_rpd.drift_reason,
                   g_rpd.owner_mode,
                   g_rpd.switchd_owner_status,
                   g_rpd.last_owner_ec,
                   g_rpd.fib_sync_state,
                   g_rpd.fib_sync_reason,
                   g_rpd.switchd_fib_status,
                   g_rpd.last_fib_ec,
                   (unsigned long long)g_rpd.switchd_fib_generation,
                   (unsigned long long)g_rpd.switchd_fib_update_id,
                   g_rpd.switchd_fib_routes,
                    NL_SWITCHD_RPD_FIB_APPLY,
                    NL_SWITCHD_RPD_FIB_SNAPSHOT_BEGIN,
                    NL_SWITCHD_RPD_FIB_SNAPSHOT_PART,
                    NL_SWITCHD_RPD_FIB_SNAPSHOT_COMMIT,
                    NL_SWITCHD_RPD_FIB_SNAPSHOT_ABORT,
                    NL_SWITCHD_RPD_FIB_READBACK,
                    NL_SWITCHD_RPD_FIB_RECONCILE,
                    NL_SWITCHD_RPD_FIB_ROLLBACK,
                   g_rpd.defer_fpm_fib_sync ? "true" : "false",
                   g_rpd.switchd_fib_live_status,
                   g_rpd.switchd_fib_live_gate,
                   g_rpd.switchd_fib_live_ready,
                   g_rpd.switchd_fib_dynamic_routes,
                   g_rpd.switchd_fib_owner_routes,
                   g_rpd.switchd_fib_ifindex_rifs,
                   g_rpd.switchd_fib_live_missing,
                   g_rpd.switchd_fib_live_reason,
                   g_rpd.fpm_programming_enabled ? "enabled" : "gated",
                   dynamic_state,
                   dynamic_state,
                   dynamic_reason,
                   g_rpd.churn_gate_enabled ? "true" : "false",
                   g_rpd.churn_state,
                   g_rpd.churn_window_ms,
                   g_rpd.churn_max_updates,
                   g_rpd.churn_used,
                   (unsigned long long)g_rpd.churn_drops,
                   g_rpd.last_churn_drop ?
                       (long)(now - g_rpd.last_churn_drop) : -1L,
                   g_rpd.churn_reason,
                   g_rpd.periodic_reconcile_enabled ? "true" : "false",
                   g_rpd.periodic_reconcile_ms,
                   (unsigned long long)g_rpd.periodic_reconcile_runs,
                   (unsigned long long)g_rpd.periodic_reconcile_errors,
                   g_rpd.last_periodic_reconcile_ms > 0 ?
                       (long)((monotonic_ms() -
                               g_rpd.last_periodic_reconcile_ms) / 1000) :
                       -1L,
                   g_rpd.linux_arp_enabled ? "true" : "false",
                   g_rpd.linux_arp_status,
                   g_rpd.linux_arp_reason,
                   g_rpd.linux_arp_ifname,
                   g_rpd.linux_arp_rif,
                   g_rpd.linux_arp_ip_path[0] ?
                       g_rpd.linux_arp_ip_path : "-",
                   g_rpd.linux_arp_interval_ms,
                   (unsigned long long)g_rpd.linux_arp_runs,
                   (unsigned long long)g_rpd.linux_arp_errors,
                   g_rpd.linux_arp_entries,
                   g_rpd.last_linux_arp ?
                       (long)(now - g_rpd.last_linux_arp) : -1L);
    if (n < 0)
        return -1;
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
    off = (size_t)n;

    n = snprintf(buf + off, sizeof(buf) - off,
                 "  <fpm-sync-batch enabled=\"%s\" size=\"%d\" "
                 "timeout-ms=\"%d\" pending=\"%d\" flushes=\"%llu\" "
                 "errors=\"%llu\" last-size=\"%d\"/>\n",
                 g_rpd.fpm_sync_batch_size > 1 ? "true" : "false",
                 g_rpd.fpm_sync_batch_size,
                 g_rpd.fpm_sync_batch_ms,
                 g_rpd.fpm_sync_batch[0].updates +
                     g_rpd.fpm_sync_batch[1].updates,
                 (unsigned long long)g_rpd.fpm_sync_batch_flushes,
                 (unsigned long long)g_rpd.fpm_sync_batch_errors,
                 g_rpd.fpm_sync_batch_last_size);
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state FPM batch output exceeded buffer");
    off += (size_t)n;

    n = snprintf(buf + off, sizeof(buf) - off,
                 "  <fib-programmer-v2 worker=\"%s\" accepting=\"%s\" "
                 "queue-depth=\"%d\" queue-capacity=\"%d\" "
                 "queue-high-water=\"%d\" inflight=\"%s\" "
                 "enqueued=\"%llu\" completed=\"%llu\" "
                 "failures=\"%llu\" backpressure=\"%llu\" "
                 "coalesced=\"%llu\" stale-acks=\"%llu\" "
                 "acked-generation=\"%llu\" acked-update-id=\"%llu\" "
                 "last-queue-ms=\"%lld\" last-rpc-ms=\"%lld\"/>\n",
                 g_rpd.fib_program_thread_started ? "running" : "stopped",
                 g_rpd.fib_program_accepting ? "true" : "false",
                 g_rpd.fib_program_queue_count,
                 RPD_FIB_PIPELINE_QUEUE_MAX,
                 g_rpd.fib_program_queue_high_water,
                 g_rpd.fib_program_inflight ? "true" : "false",
                 (unsigned long long)g_rpd.fib_program_enqueued,
                 (unsigned long long)g_rpd.fib_program_completed,
                 (unsigned long long)g_rpd.fib_program_failures,
                 (unsigned long long)g_rpd.fib_program_backpressure,
                 (unsigned long long)g_rpd.fib_program_coalesced_updates,
                 (unsigned long long)g_rpd.fib_program_stale_acks,
                 (unsigned long long)g_rpd.fib_program_acked_generation,
                 (unsigned long long)g_rpd.fib_program_acked_update_id,
                 (long long)g_rpd.fib_program_last_queue_ms,
                 (long long)g_rpd.fib_program_last_rpc_ms);
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd FIB programmer output exceeded buffer");
    off += (size_t)n;

    n = snprintf(buf + off, sizeof(buf) - off,
                 "  <maintenance worker=\"%s\" runs=\"%llu\" "
                 "errors=\"%llu\" last-age=\"%ld\" "
                 "frr-observation-discards=\"%llu\"/>\n",
                 atomic_load_explicit(&g_rpd.maintenance_running,
                                      memory_order_relaxed) ?
                     "running" : "stopped",
                 (unsigned long long)g_rpd.maintenance_runs,
                 (unsigned long long)g_rpd.maintenance_errors,
                 g_rpd.last_maintenance ?
                     (long)(now - g_rpd.last_maintenance) : -1L,
                 (unsigned long long)g_rpd.frr_observation_discards);
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd maintenance output exceeded buffer");
    off += (size_t)n;

    if (rpd_frr_config_append_xml(&g_rpd.frr_intent, buf, sizeof(buf),
                                  &off) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state FRR intent output exceeded buffer");

    if (rpd_frr_runtime_append_xml(&g_rpd.frr_runtime, buf, sizeof(buf),
                                   &off) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state FRR runtime output exceeded buffer");

    if (rpd_fpm_append_xml(&g_rpd.fpm, buf, sizeof(buf), &off) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state FPM output exceeded buffer");

    n = snprintf(buf + off, sizeof(buf) - off,
                 "  <fpm-rif-map status=\"%s\" reason=\"%s\" "
                 "entries=\"%d\" hits=\"%llu\">\n",
                 g_rpd.fpm_rif_map_status,
                 g_rpd.fpm_rif_map_reason,
                 g_rpd.fpm_rif_map_entries,
                 (unsigned long long)g_rpd.fpm_rif_map_hits);
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state FPM RIF map output exceeded buffer");
    off += (size_t)n;
    for (int i = 0; i < g_rpd.fpm_rif_map_entries; i++) {
        n = snprintf(buf + off, sizeof(buf) - off,
                     "    <entry ifindex=\"%d\" rif=\"%s\" source=\"%s\"/>\n",
                     g_rpd.fpm_rif_map[i].ifindex,
                     g_rpd.fpm_rif_map[i].rif,
                     g_rpd.fpm_rif_map[i].source);
        if (n < 0 || (size_t)n >= sizeof(buf) - off)
            return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: rpd state FPM RIF map entries exceeded buffer");
        off += (size_t)n;
    }
    n = snprintf(buf + off, sizeof(buf) - off, "  </fpm-rif-map>\n");
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state FPM RIF map output exceeded buffer");
    off += (size_t)n;

    n = snprintf(buf + off, sizeof(buf) - off,
                 "  <virtual-router-v1 enabled=\"%s\" name=\"%s\" "
                 "table=\"%s\" vrid=\"%u\" kernel-table=\"%u\"/>\n",
                 g_rpd.vrf.enabled ? "true" : "false",
                 g_rpd.vrf.enabled ? g_rpd.vrf.name : "-",
                 g_rpd.vrf.enabled ? g_rpd.vrf.table : "-",
                 g_rpd.vrf.enabled ? g_rpd.vrf.vrid : 0,
                 g_rpd.vrf.enabled ? g_rpd.vrf.kernel_table : 0);
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd VRF state output exceeded buffer");
    off += (size_t)n;

    if (rpd_rib_append_xml(&g_rpd.rib, buf, sizeof(buf), &off) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state RIB output exceeded buffer");
    if (g_rpd.vrf.enabled &&
        rpd_rib_append_xml(&g_rpd.vrf_rib, buf, sizeof(buf), &off) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd VRF RIB output exceeded buffer");

    n = snprintf(buf + off, sizeof(buf) - off,
                 "  <op-log count=\"%d\">\n", g_rpd.oplog_count);
    if (n < 0 || (size_t)n >= sizeof(buf) - off)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: rpd state op-log output exceeded buffer");
    off += (size_t)n;

    for (int i = 0; i < g_rpd.oplog_count; i++) {
        int idx = g_rpd.oplog_head - g_rpd.oplog_count + i;
        rpd_oplog_entry *entry;
        if (idx < 0)
            idx += RPD_OPLOG_MAX;
        entry = &g_rpd.oplog[idx];
        n = snprintf(buf + off, sizeof(buf) - off,
                     "    <entry update-id=\"%llu\" tx-id=\"%llu\" "
                     "fib-generation=\"%llu\" age=\"%ld\" "
                     "action=\"%s\" result=\"%s\" "
                     "rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                     "routes=\"%d\" ecmp-groups=\"%d\" "
                     "idempotency-key=\"%s\"/>\n",
                     (unsigned long long)entry->update_id,
                     (unsigned long long)entry->tx_id,
                     (unsigned long long)entry->generation,
                     (long)(now - entry->when),
                     entry->action, entry->result,
                     entry->rifs, entry->arp, entry->next_hops,
                     entry->routes, entry->ecmp_groups,
                     entry->idempotency_key[0] ?
                         entry->idempotency_key : "-");
        if (n < 0 || (size_t)n >= sizeof(buf) - off) {
            off = sizeof(buf) - 1;
            break;
        }
        off += (size_t)n;
    }
    n = snprintf(buf + off, sizeof(buf) - off,
                 "  </op-log>\n</rpd-state>\n");
    if (n < 0)
        return -1;
    if ((size_t)n >= sizeof(buf) - off)
        off = sizeof(buf) - 1;
    else
        off += (size_t)n;
    return send_text(conn, msg, 0, "%s", buf);
}

static int rpd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;
    int rc;

    rpd_lock(rpd);
    switch (msg->method) {
    case NL_RPD_SHOW:
        rc = dispatch_owner_method(conn, msg, NL_L3_OWNER_SHOW, NULL, 0, NULL);
        break;
    case NL_RPD_READBACK:
        rc = dispatch_owner_method(conn, msg, NL_L3_OWNER_READBACK, NULL, 0, NULL);
        break;
    case NL_RPD_VALIDATE_PLAN:
        rc = handle_plan_validate(conn, msg);
        break;
    case NL_RPD_APPLY_PLAN:
        rc = handle_plan_apply(conn, msg);
        break;
    case NL_RPD_ROLLBACK:
        rc = handle_rollback(conn, msg);
        break;
    case NL_RPD_RECONCILE:
        rc = handle_reconcile(conn, msg);
        break;
    case NL_RPD_STATE:
        rc = handle_rpd_state(conn, msg);
        break;
    case NL_RPD_DYNAMIC_ROUTE_UPDATE:
        rc = handle_dynamic_update(conn, msg);
        break;
    case NL_RPD_DYNAMIC_ARP_UPDATE:
        rc = handle_dynamic_arp_update(conn, msg);
        break;
    default:
        rc = send_text(conn, msg, NL_ERR_INVALID_VALUE,
                       "error: unsupported rpd method %u", msg->method);
        break;
    }
    rpd_unlock(rpd);
    return rc;
}

static int rpd_maintenance_once(rpd_ctx *rpd) {
    nl_msg_hdr *readback = NULL;
    rpd_frr_runtime frr_source;
    rpd_frr_runtime frr_observation;
    s64 now_ms;
    s32 owner_ec = NL_ERR_DAEMON_UNREACHABLE;
    int errors = 0;
    bool observation_ready;
    char frr_err[192] = {0};

    if (!rpd)
        return -1;
    rpd_lock(rpd);
    if (rpd_frr_runtime_maintain(&rpd->frr_runtime,
                                 frr_err, sizeof(frr_err)) != 0) {
        NL_LOG_WARN("rpd FRR runtime maintain failed: %s",
                    frr_err[0] ? frr_err : "unknown");
        errors++;
    }
    frr_source = rpd->frr_runtime;
    rpd_unlock(rpd);

    observation_ready = rpd_frr_runtime_collect_observation(
        &frr_source, &frr_observation) == 0;
    if (!observation_ready)
        errors++;

    rpd_lock(rpd);
    if (observation_ready && !rpd_frr_runtime_merge_observation(
            &rpd->frr_runtime, &frr_observation))
        rpd->frr_observation_discards++;
    if (poll_linux_arp_locked(rpd, false) != 0) {
        NL_LOG_WARN("rpd Linux ARP poll failed: %s",
                    rpd->linux_arp_reason);
        errors++;
    }
    fpm_sync_batch_flush_due_locked(rpd);
    if (!rpd->periodic_reconcile_enabled ||
        rpd->periodic_reconcile_ms <= 0) {
        rpd->maintenance_runs++;
        if (errors)
            rpd->maintenance_errors++;
        rpd->last_maintenance = time(NULL);
        rpd_unlock(rpd);
        return errors == 0 ? 0 : -1;
    }
    now_ms = monotonic_ms();
    if (rpd->last_periodic_reconcile_ms > 0 &&
        now_ms - rpd->last_periodic_reconcile_ms <
        rpd->periodic_reconcile_ms) {
        rpd->maintenance_runs++;
        if (errors)
            rpd->maintenance_errors++;
        rpd->last_maintenance = time(NULL);
        rpd_unlock(rpd);
        return errors == 0 ? 0 : -1;
    }
    rpd->last_periodic_reconcile_ms = now_ms;
    rpd->periodic_reconcile_runs++;

    rpd_unlock(rpd);
    if (call_owner_method_capture(g_rpd.l3_owner, NULL, NL_L3_OWNER_READBACK, NULL, 0, &readback) == 0 &&
        readback) {
        owner_ec = readback->error_code;
        rpd_lock(rpd);
        update_owner_state_from_response(NL_RPD_READBACK, readback);
        nl_msg_free(readback);
    } else {
        rpd_lock(rpd);
        owner_ec = NL_ERR_DAEMON_UNREACHABLE;
        set_drift_state("unknown",
                        "periodic owner read-back could not run");
        errors++;
    }
    if (owner_ec != 0)
        errors++;
    if (fib_program_enqueue_reconcile_locked(
            rpd, "periodic-reconcile") != 0)
        errors++;
    record_op_no_bump("periodic-reconcile",
                      errors == 0 ? "ok" : "failed", 0, NULL);
    if (errors)
        rpd->periodic_reconcile_errors++;
    rpd->maintenance_runs++;
    if (errors)
        rpd->maintenance_errors++;
    rpd->last_maintenance = time(NULL);
    rpd_unlock(rpd);
    return errors == 0 ? 0 : -1;
}

static bool rpd_maintenance_wait(rpd_ctx *rpd, int wait_ms) {
    int waited_ms = 0;

    while (atomic_load_explicit(&rpd->maintenance_running,
                                memory_order_relaxed) &&
           waited_ms < wait_ms) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000L};
        int step_ms = wait_ms - waited_ms;

        if (step_ms < 100)
            delay.tv_nsec = (long)step_ms * 1000000L;
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
            if (!atomic_load_explicit(&rpd->maintenance_running,
                                      memory_order_relaxed))
                return false;
        }
        waited_ms += step_ms < 100 ? step_ms : 100;
    }
    return atomic_load_explicit(&rpd->maintenance_running,
                                memory_order_relaxed);
}

static void *rpd_maintenance_main(void *ctx) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;

    while (atomic_load_explicit(&rpd->maintenance_running,
                                memory_order_relaxed)) {
        (void)rpd_maintenance_once(rpd);
        if (!rpd_maintenance_wait(rpd, 1000))
            break;
    }
    return NULL;
}

static int rpd_on_init(void *ctx) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;
    nl_l3_owner_options owner_options = {
        .switchd_socket_path = g_switchd_socket_path,
        .authority_name = "rpd",
        .public_reason =
            "public routing config commits through configd and rpd persistent owner",
        .switchd_caller_daemon = NL_DAEMON_RPD,
    };
    nl_msg_hdr *readback = NULL;

    memset(rpd, 0, sizeof(*rpd));
    pthread_mutex_init(&rpd->lock, NULL);
    rpd->lock_ready = true;
    rpd->l3_owner = nl_l3_owner_create(&owner_options);
    if (!rpd->l3_owner) {
        pthread_mutex_destroy(&rpd->lock);
        rpd->lock_ready = false;
        return -1;
    }
    rpd->started_at = time(NULL);
    rpd->last_owner_ec = 0;
    snprintf(rpd->drift_state, sizeof(rpd->drift_state), "unknown");
    snprintf(rpd->drift_reason, sizeof(rpd->drift_reason),
             "no read-back has run since rpd start");
    snprintf(rpd->owner_mode, sizeof(rpd->owner_mode), "unknown");
    snprintf(rpd->switchd_owner_status, sizeof(rpd->switchd_owner_status),
             "unknown");
    snprintf(rpd->fib_sync_state, sizeof(rpd->fib_sync_state), "unknown");
    snprintf(rpd->fib_sync_reason, sizeof(rpd->fib_sync_reason),
             "no FIB batch sync has run since rpd start");
    snprintf(rpd->switchd_fib_status, sizeof(rpd->switchd_fib_status),
             "unknown");
    snprintf(rpd->switchd_fib_live_status,
             sizeof(rpd->switchd_fib_live_status), "unknown");
    snprintf(rpd->switchd_fib_live_gate,
             sizeof(rpd->switchd_fib_live_gate), "unknown");
    snprintf(rpd->switchd_fib_live_ready,
             sizeof(rpd->switchd_fib_live_ready), "false");
    snprintf(rpd->switchd_fib_live_missing,
             sizeof(rpd->switchd_fib_live_missing), "-");
    snprintf(rpd->switchd_fib_live_reason,
             sizeof(rpd->switchd_fib_live_reason),
             "no switchd FIB live eligibility has been reported");
    set_fpm_rif_map_status(rpd, "empty",
                           "no FPM ifindex to RIF map entries");
    rpd->frr_config_enabled = frr_config_gate_default();
    rpd->fpm_programming_enabled = fpm_programming_default();
    rpd->defer_fpm_fib_sync =
        env_truthy("NETLAB_RPD_DEFER_FPM_FIB_SYNC");
    rpd->fpm_sync_batch_size = env_int_default(
        "NETLAB_RPD_FPM_SYNC_BATCH_SIZE",
        RPD_FPM_SYNC_BATCH_SIZE_DEFAULT, 1,
        RPD_RIB_UPDATE_AFFECTED_MAX);
    rpd->fpm_sync_batch_ms = env_int_default(
        "NETLAB_RPD_FPM_SYNC_BATCH_MS",
        RPD_FPM_SYNC_BATCH_MS_DEFAULT, 100, 5000);
    rpd->churn_gate_enabled =
        !env_truthy("NETLAB_DISABLE_RPD_CHURN_GATE");
    rpd->churn_window_ms = env_int_default("NETLAB_RPD_CHURN_WINDOW_MS",
                                           1000, 100, 60000);
    rpd->churn_max_updates = env_int_default("NETLAB_RPD_CHURN_MAX_UPDATES",
                                             512, 1, 100000);
    set_churn_state(rpd->churn_gate_enabled ? "ok" : "disabled",
                    rpd->churn_gate_enabled ?
                    "route churn within configured gate" :
                    "NETLAB_DISABLE_RPD_CHURN_GATE is set");
    rpd->periodic_reconcile_enabled =
        !env_truthy("NETLAB_DISABLE_RPD_PERIODIC_RECONCILE");
    rpd->periodic_reconcile_ms =
        env_int_default("NETLAB_RPD_PERIODIC_RECONCILE_MS",
                        30000, 1000, 3600000);
    rpd->linux_arp_enabled = env_truthy("NETLAB_ENABLE_RPD_LINUX_ARP");
    rpd->linux_arp_interval_ms =
        env_int_default("NETLAB_RPD_LINUX_ARP_INTERVAL_MS",
                        5000, 1000, 3600000);
    {
        const char *dev = getenv("NETLAB_RPD_LINUX_ARP_DEV");
        const char *tap = getenv("NETLAB_PACKETD_L3_TAP_IFNAME");
        const char *rif = getenv("NETLAB_RPD_LINUX_ARP_RIF");

        if (!dev || !dev[0])
            dev = tap && tap[0] ? tap : "netlab-l3";
        if (!rif || !rif[0])
            rif = dev;
        snprintf(rpd->linux_arp_ifname, sizeof(rpd->linux_arp_ifname),
                 "%s", token_safe(dev) ? dev : "invalid");
        snprintf(rpd->linux_arp_rif, sizeof(rpd->linux_arp_rif),
                 "%s", token_safe(rif) ? rif : "invalid");
        if (!token_safe(dev) || !token_safe(rif)) {
            rpd->linux_arp_enabled = false;
            set_linux_arp_status(rpd, "error",
                                 "invalid Linux ARP interface or RIF");
        } else if (!rpd->linux_arp_enabled) {
            set_linux_arp_status(rpd, "disabled",
                                 "NETLAB_ENABLE_RPD_LINUX_ARP is not set");
        } else if (!find_ip_program(rpd->linux_arp_ip_path,
                                    sizeof(rpd->linux_arp_ip_path))) {
            set_linux_arp_status(rpd, "error",
                                 "Linux ip command is unavailable");
        } else {
            set_linux_arp_status(rpd, "idle",
                                 "Linux ARP poll has not run yet");
        }
    }
    init_fpm_rif_map(rpd);
    rpd_rib_init(&rpd->rib);
    rpd_rib_init(&rpd->rollback_rib);
    (void)rpd_rib_init_scope(&rpd->vrf_rib, "vrf1.inet.0",
                             RPD_VRF_V1_KERNEL_TABLE);
    (void)rpd_rib_init_scope(&rpd->rollback_vrf_rib, "vrf1.inet.0",
                             RPD_VRF_V1_KERNEL_TABLE);
    rpd_frr_config_init(&rpd->frr_intent);
    rpd_frr_config_init(&rpd->rollback_frr_intent);
    rpd_frr_runtime_init(&rpd->frr_runtime, rpd->frr_config_enabled,
                         frr_runtime_start_gate_default());
    rpd_fpm_init(&rpd->fpm);
    if (fib_program_start(rpd) != 0) {
        rpd_fpm_destroy(&rpd->fpm);
        rpd_frr_runtime_stop(&rpd->frr_runtime);
        nl_l3_owner_destroy(rpd->l3_owner);
        rpd->l3_owner = NULL;
        pthread_mutex_destroy(&rpd->lock);
        rpd->lock_ready = false;
        return -1;
    }
    NL_LOG_INFO("rpd starting: frr-config-enabled=%s fpm-enabled=%s "
                "frr-runtime-present=%s",
                rpd->frr_config_enabled ? "true" : "false",
                rpd->fpm_programming_enabled ? "true" : "false",
                rpd_frr_runtime_present() ? "true" : "false");
    rpd_lock(rpd);
    if (call_owner_method_capture(rpd->l3_owner, NULL,
                                  NL_L3_OWNER_READBACK, NULL, 0,
                                  &readback) == 0 &&
        readback) {
        update_owner_state_from_response(NL_RPD_READBACK, readback);
        record_op("restart-reconcile",
                  readback->error_code == 0 ? "ok" : "failed", 0, NULL);
        nl_msg_free(readback);
    } else {
        set_drift_state("unknown", "restart reconcile could not run");
        record_op("restart-reconcile", "failed", 0, NULL);
    }
    if (reconcile_switchd_fib_locked("restart-reconcile") != 0)
        (void)sync_switchd_fib_locked("restart-reconcile", true);
    rpd_unlock(rpd);
    if (rpd->fpm_programming_enabled) {
        char fpm_err[192] = {0};
        int fpm_port = env_int_default("NETLAB_RPD_FPM_PORT",
                                       RPD_FPM_DEFAULT_PORT, 1, 65535);

        if (rpd_fpm_start(&rpd->fpm, fpm_port,
                          rpd_fpm_authority_cb, rpd,
                          rpd_fpm_apply_cb, rpd,
                          fpm_err, sizeof(fpm_err)) != 0) {
            set_drift_state("error", fpm_err);
            NL_LOG_WARN("rpd FPM listener disabled: %s", fpm_err);
        }
    }
    atomic_init(&rpd->maintenance_running, true);
    if (pthread_create(&rpd->maintenance_thread, NULL,
                       rpd_maintenance_main, rpd) != 0) {
        atomic_store_explicit(&rpd->maintenance_running, false,
                              memory_order_relaxed);
        rpd_fpm_destroy(&rpd->fpm);
        fib_program_stop(rpd);
        rpd_frr_runtime_stop(&rpd->frr_runtime);
        nl_l3_owner_destroy(rpd->l3_owner);
        rpd->l3_owner = NULL;
        pthread_mutex_destroy(&rpd->lock);
        rpd->lock_ready = false;
        return -1;
    }
    rpd->maintenance_thread_started = true;
    return 0;
}

static void rpd_on_shutdown(void *ctx) {
    rpd_ctx *rpd = ctx ? (rpd_ctx *)ctx : &g_rpd;

    rpd_fpm_destroy(&rpd->fpm);
    atomic_store_explicit(&rpd->maintenance_running, false,
                          memory_order_relaxed);
    if (rpd->maintenance_thread_started)
        pthread_join(rpd->maintenance_thread, NULL);
    fib_program_stop(rpd);
    rpd_frr_runtime_stop(&rpd->frr_runtime);
    nl_l3_owner_destroy(rpd->l3_owner);
    rpd->l3_owner = NULL;
    if (rpd->lock_ready) {
        pthread_mutex_destroy(&rpd->lock);
        rpd->lock_ready = false;
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1 &&
        strcmp(argv[1], RPD_SWITCHD_OWNER_RPC_MODE) == 0)
        return rpd_switchd_owner_rpc_main(argc, argv);

    init_socket_paths();

    nl_daemon_config cfg = {
        .name = "rpd",
        .socket_path = g_rpd_socket_path,
        .service_id = NL_DAEMON_RPD,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = rpd_dispatch,
        .ctx = &g_rpd,
        .on_init = rpd_on_init,
        .on_shutdown = rpd_on_shutdown,
        .max_concurrent_handlers = 8,
    };

    nl_log_init("rpd", LOG_DAEMON, NL_LOG_INFO);
    return nl_daemon_run(&cfg);
}
