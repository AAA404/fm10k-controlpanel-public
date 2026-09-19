#ifndef RPD_FRR_RUNTIME_H
#define RPD_FRR_RUNTIME_H

#include "frr_config.h"
#include "netlab/types.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#define RPD_FRR_RUNTIME_PATH_MAX 256
#define RPD_FRR_VTYSH_MAX_NEIGHBORS 64
#define RPD_FRR_VTYSH_MAX_PEERS 64

typedef struct {
    char neighbor_id[40];
    char state[32];
    char dead_time[24];
    char address[40];
    char interface[64];
    int priority;
    bool full;
} rpd_frr_ospf_neighbor;

typedef struct {
    char neighbor[40];
    char remote_as[16];
    char uptime[24];
    char state[32];
    char prefixes[16];
    bool established;
} rpd_frr_bgp_peer;

typedef struct {
    pid_t pid;
    uid_t uid;
    u64 starttime;
    u64 generation;
    char executable[RPD_FRR_RUNTIME_PATH_MAX];
} rpd_frr_zebra_authority;

typedef struct {
    bool config_gate_enabled;
    bool start_gate_enabled;
    bool runtime_present;
    bool preflight_ready;
    bool config_written;
    bool processes_started;
    char status[32];
    char reason[192];
    char preflight_reason[192];
    char run_dir[RPD_FRR_RUNTIME_PATH_MAX];
    char config_path[RPD_FRR_RUNTIME_PATH_MAX];
    char zebra_path[RPD_FRR_RUNTIME_PATH_MAX];
    char ospfd_path[RPD_FRR_RUNTIME_PATH_MAX];
    char bgpd_path[RPD_FRR_RUNTIME_PATH_MAX];
    char vtysh_path[RPD_FRR_RUNTIME_PATH_MAX];
    char zebra_module[RPD_FRR_RUNTIME_PATH_MAX];
    uid_t run_uid;
    gid_t run_gid;
    bool runtime_identity_ready;
    pid_t zebra_pid;
    u64 zebra_starttime;
    char zebra_executable[RPD_FRR_RUNTIME_PATH_MAX];
    bool zebra_authority_ready;
    u64 zebra_authority_generation;
    pid_t ospfd_pid;
    pid_t bgpd_pid;
    bool vtysh_present;
    char vtysh_status[32];
    char vtysh_reason[192];
    time_t last_vtysh;
    int vtysh_queries;
    int vtysh_errors;
    int vtysh_parse_errors;
    int ospf_neighbors;
    int ospf_full;
    int ospf_neighbor_entries;
    bool ospf_neighbor_complete;
    bool ospf_neighbor_truncated;
    rpd_frr_ospf_neighbor ospf_neighbor[RPD_FRR_VTYSH_MAX_NEIGHBORS];
    int bgp_peers;
    int bgp_established;
    int bgp_peer_entries;
    bool bgp_peer_complete;
    bool bgp_peer_truncated;
    rpd_frr_bgp_peer bgp_peer[RPD_FRR_VTYSH_MAX_PEERS];
    u64 generation;
    u32 config_hash;
    time_t last_update;
    time_t last_write;
    time_t last_start;
    time_t last_preflight;
    time_t retry_after;
    int start_attempts;
    int restart_events;
    int running_processes;
    int last_errno;
} rpd_frr_runtime;

void rpd_frr_runtime_init(rpd_frr_runtime *rt, bool config_gate_enabled,
                          bool start_gate_enabled);
bool rpd_frr_runtime_present(void);
bool rpd_frr_runtime_program_present(const char *name);
int rpd_frr_runtime_preflight(rpd_frr_runtime *rt,
                              char *err, size_t err_size);
int rpd_frr_runtime_configure(rpd_frr_runtime *rt,
                              const rpd_frr_config *cfg,
                              char *err, size_t err_size);
int rpd_frr_runtime_maintain(rpd_frr_runtime *rt,
                             char *err, size_t err_size);
bool rpd_frr_runtime_zebra_authority(
    const rpd_frr_runtime *rt, rpd_frr_zebra_authority *authority,
    char *err, size_t err_size);
int rpd_frr_runtime_collect_observation(const rpd_frr_runtime *source,
                                        rpd_frr_runtime *observation);
bool rpd_frr_runtime_merge_observation(rpd_frr_runtime *rt,
                                       const rpd_frr_runtime *observation);
void rpd_frr_runtime_stop(rpd_frr_runtime *rt);
int rpd_frr_runtime_append_xml(rpd_frr_runtime *rt, char *buf,
                               size_t buf_size, size_t *off);

#endif
