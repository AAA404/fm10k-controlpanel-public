#ifndef NETLAB_IGMP_STATE_H
#define NETLAB_IGMP_STATE_H

#include "netlab/types.h"
#include <time.h>

#define IGMP_MAX_DYNAMIC_MEMBERS 512
#define IGMP_MAX_ROUTER_GROUPS (IGMP_MAX_DYNAMIC_MEMBERS * 2)

typedef struct {
    bool used, pending, retiring;
    int vid, port;
    char group[16];
    u32 group_ip;
    u8 mac[6];
    /* CLOCK_BOOTTIME seconds, never a wall-clock or renewed restart lease. */
    time_t expires_at;
} igmp_dynamic_member;

typedef struct {
    bool used;
    int vid;
    u8 mac[6];
    char group[16];
    u32 applied_ports, uncertain_ports;
} igmp_router_group;

typedef struct {
    igmp_dynamic_member dynamic[IGMP_MAX_DYNAMIC_MEMBERS];
    igmp_router_group router_groups[IGMP_MAX_ROUTER_GROUPS];
    u64 tx_sequence;
    /* A crash between timer rebasing and releasing the persistent barrier
     * must not apply the same pause duration twice. */
    u64 resumed_tx[24];
    time_t resumed_seconds[24];
} igmp_runtime_image;

typedef struct {
    bool enabled, has_fingerprint;
    int directory, lock;
    char boot_id[37];
    u64 fingerprint, saves, failures;
} igmp_state_store;

time_t igmp_clock_seconds(void);
/* Native mode defaults to /run/netlab/igmp. An explicit directory enables
 * the same implementation for isolated tests without hardware access. */
int igmp_state_open(igmp_state_store *store, igmp_runtime_image *image);
int igmp_state_save(igmp_state_store *store, const igmp_runtime_image *image);
void igmp_state_close(igmp_state_store *store);

#endif
