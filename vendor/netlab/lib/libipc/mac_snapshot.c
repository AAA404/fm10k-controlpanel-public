#include "netlab/mac_snapshot.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NL_MAC_WIRE_STATIC (1U << 31)

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 version;
    u16 entry_size;
    u64 generation;
    u32 total_entries;
    u32 n_entries;
    u32 flags;
} nl_mac_snapshot_wire_header;

typedef struct __attribute__((packed)) {
    u16 vlan;
    u16 port;
    u8 ae_id;
    u8 mac[6];
    u32 age_flags;
} nl_mac_snapshot_wire_entry;

_Static_assert(sizeof(nl_mac_snapshot_wire_header) == 28,
               "MAC snapshot wire header changed");
_Static_assert(sizeof(nl_mac_snapshot_wire_entry) == 15,
               "MAC snapshot wire entry changed");

static u64 host_to_network_u64(u64 value) {
    u32 high = htonl((u32)(value >> 32));
    u32 low = htonl((u32)value);

    return ((u64)low << 32) | high;
}

static u64 network_to_host_u64(u64 value) {
    u32 high = ntohl((u32)value);
    u32 low = ntohl((u32)(value >> 32));

    return ((u64)high << 32) | low;
}

void nl_mac_snapshot_reset(nl_mac_snapshot *snapshot) {
    if (!snapshot)
        return;
    free(snapshot->entries);
    memset(snapshot, 0, sizeof(*snapshot));
}

int nl_mac_snapshot_encode(const nl_mac_snapshot *snapshot,
                           void *buffer, size_t capacity) {
    nl_mac_snapshot_wire_header header;
    nl_mac_snapshot_wire_entry *wire_entries;
    size_t length;

    if (!snapshot || !buffer ||
        snapshot->n_entries > NL_MAC_SNAPSHOT_MAX_ENTRIES ||
        snapshot->total_entries < snapshot->n_entries ||
        (snapshot->n_entries > 0 && !snapshot->entries) ||
        (snapshot->complete &&
         snapshot->total_entries != snapshot->n_entries))
        return -1;
    length = sizeof(header) +
        sizeof(*wire_entries) * (size_t)snapshot->n_entries;
    if (length > capacity || length > INT32_MAX)
        return -1;

    memset(&header, 0, sizeof(header));
    header.magic = htonl(NL_MAC_SNAPSHOT_MAGIC);
    header.version = htons(NL_MAC_SNAPSHOT_VERSION);
    header.entry_size = htons((u16)sizeof(*wire_entries));
    header.generation = host_to_network_u64(snapshot->generation);
    header.total_entries = htonl(snapshot->total_entries);
    header.n_entries = htonl(snapshot->n_entries);
    header.flags = htonl(snapshot->complete ? NL_MAC_SNAPSHOT_COMPLETE : 0);
    memcpy(buffer, &header, sizeof(header));
    wire_entries = (nl_mac_snapshot_wire_entry *)((u8 *)buffer +
                                                   sizeof(header));
    for (u32 i = 0; i < snapshot->n_entries; i++) {
        const nl_mac_snapshot_entry *entry = &snapshot->entries[i];
        u32 age_flags;

        if (entry->vlan < 1 || entry->vlan > 4094 || entry->port == 0 ||
            entry->ae_id < -1 || entry->ae_id > INT8_MAX ||
            entry->age > INT32_MAX)
            return -1;
        wire_entries[i].vlan = htons(entry->vlan);
        wire_entries[i].port = htons(entry->port);
        wire_entries[i].ae_id = (u8)(int8_t)entry->ae_id;
        memcpy(wire_entries[i].mac, entry->mac,
               sizeof(wire_entries[i].mac));
        age_flags = entry->age |
            (entry->is_static ? NL_MAC_WIRE_STATIC : 0U);
        wire_entries[i].age_flags = htonl(age_flags);
    }
    return (int)length;
}

int nl_mac_snapshot_decode(const void *buffer, size_t length,
                           nl_mac_snapshot *snapshot) {
    nl_mac_snapshot_wire_header header;
    const nl_mac_snapshot_wire_entry *wire_entries;
    nl_mac_snapshot decoded = {0};
    u32 flags;
    size_t expected;

    if (!buffer || !snapshot || length < sizeof(header))
        return -1;
    memcpy(&header, buffer, sizeof(header));
    if (ntohl(header.magic) != NL_MAC_SNAPSHOT_MAGIC ||
        ntohs(header.version) != NL_MAC_SNAPSHOT_VERSION ||
        ntohs(header.entry_size) != sizeof(nl_mac_snapshot_wire_entry))
        return -1;
    decoded.generation = network_to_host_u64(header.generation);
    decoded.total_entries = ntohl(header.total_entries);
    decoded.n_entries = ntohl(header.n_entries);
    flags = ntohl(header.flags);
    decoded.complete = (flags & NL_MAC_SNAPSHOT_COMPLETE) != 0;
    if ((flags & ~NL_MAC_SNAPSHOT_COMPLETE) != 0 ||
        decoded.n_entries > NL_MAC_SNAPSHOT_MAX_ENTRIES ||
        decoded.total_entries < decoded.n_entries ||
        (decoded.complete &&
         decoded.total_entries != decoded.n_entries))
        return -1;
    expected = sizeof(header) + sizeof(*wire_entries) *
        (size_t)decoded.n_entries;
    if (length != expected)
        return -1;
    if (decoded.n_entries > 0) {
        decoded.entries = calloc(decoded.n_entries,
                                 sizeof(*decoded.entries));
        if (!decoded.entries)
            return -1;
    }
    wire_entries = (const nl_mac_snapshot_wire_entry *)
        ((const u8 *)buffer + sizeof(header));
    for (u32 i = 0; i < decoded.n_entries; i++) {
        nl_mac_snapshot_entry *entry = &decoded.entries[i];
        u32 age_flags = ntohl(wire_entries[i].age_flags);

        entry->vlan = ntohs(wire_entries[i].vlan);
        entry->port = ntohs(wire_entries[i].port);
        entry->ae_id = (int)(int8_t)wire_entries[i].ae_id;
        memcpy(entry->mac, wire_entries[i].mac, sizeof(entry->mac));
        entry->age = age_flags & ~NL_MAC_WIRE_STATIC;
        entry->is_static = (age_flags & NL_MAC_WIRE_STATIC) != 0;
        if (entry->vlan < 1 || entry->vlan > 4094 || entry->port == 0 ||
            entry->ae_id < -1)
            goto invalid;
    }
    nl_mac_snapshot_reset(snapshot);
    *snapshot = decoded;
    return 0;

invalid:
    nl_mac_snapshot_reset(&decoded);
    return -1;
}
