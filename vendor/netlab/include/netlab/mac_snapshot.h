#ifndef NETLAB_MAC_SNAPSHOT_H
#define NETLAB_MAC_SNAPSHOT_H

#include "types.h"

#include <stdbool.h>
#include <stddef.h>

#define NL_MAC_SNAPSHOT_MAGIC 0x4e4d4143U
#define NL_MAC_SNAPSHOT_VERSION 1U
#define NL_MAC_SNAPSHOT_MAX_ENTRIES 16384U
#define NL_MAC_SNAPSHOT_COMPLETE (1U << 0)

typedef struct {
    u16 vlan;
    u8 mac[6];
    u16 port;
    int ae_id;
    u32 age;
    bool is_static;
} nl_mac_snapshot_entry;

typedef struct {
    u64 generation;
    u32 total_entries;
    u32 n_entries;
    bool complete;
    nl_mac_snapshot_entry *entries;
} nl_mac_snapshot;

void nl_mac_snapshot_reset(nl_mac_snapshot *snapshot);

// Encode/decode the versioned network-byte-order IPC representation.
// encode returns the number of payload bytes, or -1 on an invalid snapshot.
int nl_mac_snapshot_encode(const nl_mac_snapshot *snapshot,
                           void *buffer, size_t capacity);
int nl_mac_snapshot_decode(const void *buffer, size_t length,
                           nl_mac_snapshot *snapshot);

#endif
