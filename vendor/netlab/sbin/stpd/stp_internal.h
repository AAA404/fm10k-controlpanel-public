/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_STPD_STP_INTERNAL_H
#define NETLAB_STPD_STP_INTERNAL_H

#include "stp_wire.h"
#include "netlab/types.h"

#include <pthread.h>
#include <time.h>

#define STPD_MAX_PORTS 128
#define STPD_MAX_MSTI STP_MST_MAX_RECORDS
#define STPD_MST_MAX_VLANS 4095
#define STPD_MST_DEFAULT_REMAINING_HOPS 20

typedef enum {
    STP_BLOCK_NONE = 0,
    STP_BLOCK_LOOP,
    STP_BLOCK_ALTERNATE,
    STP_BLOCK_SPLIT_ROOT,
    STP_BLOCK_ROOT_PROTECTION,
} stp_block_reason;

typedef struct {
    bool valid;
    int mstid;
    stp_role_id role;
    bool protocol_blocked;
    stp_block_reason block_reason;
    u64 rx_bpdus;
    u64 proposal_bpdus;
    u64 agreement_bpdus;
    u64 tx_proposal_bpdus;
    u64 tx_agreement_bpdus;
    u64 sync_resets;
    time_t last_seen;
    time_t agreement_due_until;
    time_t last_proposal_seen;
    time_t last_agreement_seen;
    time_t last_sync_reset;
    char last_sync_reset_reason[48];
    time_t last_tx;
    time_t protocol_block_config_mtime;
    int last_flags;
    stp_role_id last_peer_role;
    u8 last_root_raw[8];
    u32 last_root_path_cost;
    int remaining_hops;
} stp_port_msti_stats;

typedef struct {
    bool valid;
    int port;
    int vlan;
    u64 rx_bpdus;
    u64 stp_bpdus;
    u64 rstp_bpdus;
    u64 mstp_bpdus;
    u64 tcn_bpdus;
    u64 topology_change_bpdus;
    u64 proposal_bpdus;
    u64 agreement_bpdus;
    u64 unknown_bpdus;
    u64 malformed_bpdus;
    u64 mac_flushes;
    time_t last_mac_flush;
    char last_mac_flush_scope[96];
    char last_mac_flush_reason[96];
    time_t last_seen;
    int last_version;
    int last_type;
    int last_flags;
    bool last_peer_timers_valid;
    u16 last_peer_message_age_ticks;
    u16 last_peer_max_age_ticks;
    u16 last_peer_hello_time_ticks;
    u16 last_peer_forward_delay_ticks;
    char last_root_id[32];
    char last_bridge_id[32];
    u8 last_root_raw[8];
    u8 last_bridge_raw[8];
    u32 last_root_path_cost;
    int last_port_id;
    stp_role_id role;
    bool rstp_enabled;
    bool configuration_pending;
    time_t configuration_since;
    u64 tx_bpdus;
    u64 tx_proposal_bpdus;
    u64 tx_agreement_bpdus;
    u64 tx_tc_bpdus;
    u64 tx_failures;
    u64 sync_resets;
    time_t last_tx;
    time_t agreement_due_until;
    time_t last_proposal_seen;
    time_t last_agreement_seen;
    time_t last_sync_reset;
    char last_sync_reset_reason[48];
    bool edge;
    bool bpdu_guard_enabled;
    bool root_protection;
    bool loop_protection;
    bool guard_blocked;
    u64 guard_blocks;
    time_t guard_blocked_at;
    char guard_last_error[128];
    bool protocol_blocked;
    stp_block_reason block_reason;
    u64 protocol_blocks;
    time_t protocol_blocked_at;
    time_t protocol_block_config_mtime;
    time_t root_protection_superior_seen;
    u8 root_protection_root_raw[8];
    u8 root_protection_bridge_raw[8];
    u32 root_protection_root_path_cost;
    int root_protection_port_id;
    time_t loop_last_seen;
    int loop_peer_port;
    char protocol_last_error[128];
    stp_port_msti_stats msti[STPD_MAX_MSTI];
} stp_port_stats;

typedef struct {
    bool valid;
    int id;
    int bridge_priority;
    int vlan_count;
    bool vlan_map[STPD_MST_MAX_VLANS];
    int port_path_cost[STPD_MAX_PORTS];
    int port_priority[STPD_MAX_PORTS];
    bool port_priority_valid[STPD_MAX_PORTS];
    u8 bridge_id[8];
    u8 selected_root_id[8];
    u32 selected_root_path_cost;
    int selected_remaining_hops;
    int root_port;
} stp_mst_instance_state;

typedef struct {
    stp_port_stats ports[STPD_MAX_PORTS];
    u64 total_bpdus;
    u64 topology_change_bpdus;
    u64 proposal_bpdus;
    u64 agreement_bpdus;
    u64 mac_flushes;
    u64 tx_bpdus;
    u64 tx_proposal_bpdus;
    u64 tx_agreement_bpdus;
    u64 tx_tc_bpdus;
    u64 tx_failures;
    u64 malformed_bpdus;
    u64 packetd_reconnects;
    time_t last_rx;
    time_t last_mac_flush;
    time_t tc_tx_until;
    char last_mac_flush_scope[96];
    char last_mac_flush_reason[96];
    u8 selected_root_id[8];
    u32 selected_root_path_cost;
    int root_port;
    time_t started_at;
    time_t last_config_check;
    time_t config_mtime;
    long config_mtime_nsec;
    char mst_config_name[STP_MST_CONFIG_NAME_LEN + 1];
    u16 mst_revision;
    u8 mst_digest[STP_MST_DIGEST_LEN];
    int mst_instance_count;
    stp_mst_instance_state mst_instances[STPD_MAX_MSTI];
    pthread_mutex_t lock;
} stpd_state;

typedef struct {
    int port;
    stp_role_id role;
    int extra_flags;
    u8 root_id[8];
    u32 root_path_cost;
    u8 bridge_id[8];
    bool mstp;
    char mst_config_name[STP_MST_CONFIG_NAME_LEN + 1];
    u16 mst_revision;
    u8 mst_digest[STP_MST_DIGEST_LEN];
    int msti_count;
    stp_msti_record msti[STPD_MAX_MSTI];
} stp_tx_info;

extern stpd_state g_stp;

int stpd_hello_sec(void);
int stpd_max_age_sec(void);
int stpd_forward_delay_sec(void);
int stpd_bridge_priority(void);
int stpd_mst_max_hops(void);
int stpd_port_path_cost(int port);
int stpd_port_priority(int port);
int stpd_msti_port_path_cost(int mstid, int port);
int stpd_msti_port_priority(int mstid, int port);
const char *stpd_protocol_name(void);
const char *stpd_mst_config_name(void);
u16 stpd_mst_revision(void);
void stpd_mst_digest_hex(char *out, size_t out_size);
const char *block_reason_name(stp_block_reason reason);
void ifname_from_port(int port, char *buf, size_t buf_len);
void load_system_mac(u8 mac[6]);
void reconcile_rstp_roles(void);

#endif
