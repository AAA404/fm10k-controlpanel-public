#ifndef NETLAB_STP_SNAPSHOT_H
#define NETLAB_STP_SNAPSHOT_H

#include "ipc_contract.h"
#include "types.h"

#include <stdbool.h>
#include <stddef.h>

#define NL_STP_SNAPSHOT_MAGIC 0x4e535450U
#define NL_STP_SNAPSHOT_VERSION 1U
#define NL_STP_SNAPSHOT_MAX_VLANS 4094U
/* The FM10840 product profiles expose at most 24 VLAN-bearing ports. */
#define NL_STP_SNAPSHOT_MAX_PORTS 24U
#define NL_STP_SNAPSHOT_MAX_ENTRIES \
    (NL_STP_SNAPSHOT_MAX_VLANS * NL_STP_SNAPSHOT_MAX_PORTS)
#define NL_STP_SNAPSHOT_PAGE_ENTRIES 32768U
#define NL_STP_SNAPSHOT_PAGE_COMPLETE (1U << 0)

typedef struct {
    u16 vlan;
    u16 port;
    u8 state;
} nl_stp_snapshot_entry;

typedef struct {
    u64 generation;
    u32 total_entries;
    u32 n_entries;
    bool complete;
    nl_stp_snapshot_entry *entries;
} nl_stp_snapshot;

typedef struct {
    u64 generation;
    u32 offset;
} nl_stp_snapshot_page_request;

typedef struct {
    u64 generation;
    u32 total_entries;
    u32 offset;
    u32 n_entries;
    u32 next_offset;
    bool complete;
    nl_stp_snapshot_entry *entries;
} nl_stp_snapshot_page;

void nl_stp_snapshot_reset(nl_stp_snapshot *snapshot);
void nl_stp_snapshot_page_reset(nl_stp_snapshot_page *page);

/* Sort, validate, and assign a deterministic non-zero content generation. */
int nl_stp_snapshot_finalize(nl_stp_snapshot *snapshot);

int nl_stp_snapshot_page_request_encode(
    const nl_stp_snapshot_page_request *request,
    void *buffer, size_t capacity);
int nl_stp_snapshot_page_request_decode(
    const void *buffer, size_t length,
    nl_stp_snapshot_page_request *request);

int nl_stp_snapshot_page_encode(const nl_stp_snapshot *snapshot, u32 offset,
                                void *buffer, size_t capacity);
int nl_stp_snapshot_page_decode(const void *buffer, size_t length,
                                nl_stp_snapshot_page *page);
int nl_stp_snapshot_append_page(nl_stp_snapshot *snapshot,
                                const nl_stp_snapshot_page *page);

bool nl_stp_snapshot_has_member(const nl_stp_snapshot *snapshot,
                                int vlan, int port);

/* Fetches one generation atomically or fails without returning partial data. */
int nl_stp_snapshot_fetch(const char *socket_path, nl_daemon_id caller,
                          u32 timeout_ms, nl_stp_snapshot *snapshot);

#endif
