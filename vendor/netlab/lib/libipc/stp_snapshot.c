#include "netlab/stp_snapshot.h"

#include "netlab/ipc.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 version;
    u16 request_size;
    u64 generation;
    u32 offset;
} nl_stp_snapshot_wire_request;

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 version;
    u16 entry_size;
    u64 generation;
    u32 total_entries;
    u32 offset;
    u32 n_entries;
    u32 next_offset;
    u32 flags;
} nl_stp_snapshot_wire_header;

typedef struct __attribute__((packed)) {
    u16 vlan;
    u16 port;
    u8 state;
} nl_stp_snapshot_wire_entry;

_Static_assert(sizeof(nl_stp_snapshot_wire_request) == 20,
               "STP snapshot request wire format changed");
_Static_assert(sizeof(nl_stp_snapshot_wire_header) == 36,
               "STP snapshot header wire format changed");
_Static_assert(sizeof(nl_stp_snapshot_wire_entry) == 5,
               "STP snapshot entry wire format changed");

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

static int entry_compare(const void *left, const void *right) {
    const nl_stp_snapshot_entry *a = left;
    const nl_stp_snapshot_entry *b = right;

    if (a->vlan != b->vlan)
        return a->vlan < b->vlan ? -1 : 1;
    if (a->port != b->port)
        return a->port < b->port ? -1 : 1;
    if (a->state != b->state)
        return a->state < b->state ? -1 : 1;
    return 0;
}

static bool entry_valid(const nl_stp_snapshot_entry *entry) {
    return entry && entry->vlan >= 1 && entry->vlan <= 4094 &&
        entry->port > 0 && entry->state <= 4;
}

static bool entry_key_before(const nl_stp_snapshot_entry *left,
                             const nl_stp_snapshot_entry *right) {
    return left->vlan < right->vlan ||
        (left->vlan == right->vlan && left->port < right->port);
}

static u64 snapshot_generation(const nl_stp_snapshot_entry *entries,
                               u32 count) {
    u64 hash = UINT64_C(1469598103934665603);
    const u64 prime = UINT64_C(1099511628211);

    for (unsigned int shift = 0; shift < 32; shift += 8) {
        hash ^= (count >> shift) & 0xffU;
        hash *= prime;
    }
    for (u32 i = 0; i < count; i++) {
        const u8 canonical[] = {
            (u8)(entries[i].vlan >> 8), (u8)entries[i].vlan,
            (u8)(entries[i].port >> 8), (u8)entries[i].port,
            entries[i].state,
        };

        for (size_t j = 0; j < sizeof(canonical); j++) {
            hash ^= canonical[j];
            hash *= prime;
        }
    }
    return hash ? hash : UINT64_MAX;
}

static u64 monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec * UINT64_C(1000) +
        (u64)now.tv_nsec / UINT64_C(1000000);
}

void nl_stp_snapshot_reset(nl_stp_snapshot *snapshot) {
    if (!snapshot)
        return;
    free(snapshot->entries);
    memset(snapshot, 0, sizeof(*snapshot));
}

void nl_stp_snapshot_page_reset(nl_stp_snapshot_page *page) {
    if (!page)
        return;
    free(page->entries);
    memset(page, 0, sizeof(*page));
}

int nl_stp_snapshot_finalize(nl_stp_snapshot *snapshot) {
    if (!snapshot)
        return -1;
    snapshot->generation = 0;
    snapshot->complete = false;
    if (snapshot->n_entries > NL_STP_SNAPSHOT_MAX_ENTRIES ||
        snapshot->total_entries != snapshot->n_entries ||
        (snapshot->n_entries > 0 && !snapshot->entries))
        return -1;
    if (snapshot->n_entries > 1)
        qsort(snapshot->entries, snapshot->n_entries,
              sizeof(*snapshot->entries), entry_compare);
    for (u32 i = 0; i < snapshot->n_entries; i++) {
        if (!entry_valid(&snapshot->entries[i]) ||
            (i > 0 && !entry_key_before(&snapshot->entries[i - 1],
                                        &snapshot->entries[i])))
            return -1;
    }
    snapshot->generation = snapshot_generation(snapshot->entries,
                                               snapshot->n_entries);
    snapshot->complete = true;
    return 0;
}

int nl_stp_snapshot_page_request_encode(
    const nl_stp_snapshot_page_request *request,
    void *buffer, size_t capacity) {
    nl_stp_snapshot_wire_request wire;

    if (!request || !buffer || capacity < sizeof(wire) ||
        request->offset > NL_STP_SNAPSHOT_MAX_ENTRIES ||
        ((request->offset == 0) != (request->generation == 0)))
        return -1;
    memset(&wire, 0, sizeof(wire));
    wire.magic = htonl(NL_STP_SNAPSHOT_MAGIC);
    wire.version = htons(NL_STP_SNAPSHOT_VERSION);
    wire.request_size = htons((u16)sizeof(wire));
    wire.generation = host_to_network_u64(request->generation);
    wire.offset = htonl(request->offset);
    memcpy(buffer, &wire, sizeof(wire));
    return (int)sizeof(wire);
}

int nl_stp_snapshot_page_request_decode(
    const void *buffer, size_t length,
    nl_stp_snapshot_page_request *request) {
    nl_stp_snapshot_wire_request wire;
    nl_stp_snapshot_page_request decoded;

    if (!buffer || !request || length != sizeof(wire))
        return -1;
    memcpy(&wire, buffer, sizeof(wire));
    if (ntohl(wire.magic) != NL_STP_SNAPSHOT_MAGIC ||
        ntohs(wire.version) != NL_STP_SNAPSHOT_VERSION ||
        ntohs(wire.request_size) != sizeof(wire))
        return -1;
    decoded.generation = network_to_host_u64(wire.generation);
    decoded.offset = ntohl(wire.offset);
    if (decoded.offset > NL_STP_SNAPSHOT_MAX_ENTRIES ||
        ((decoded.offset == 0) != (decoded.generation == 0)))
        return -1;
    *request = decoded;
    return 0;
}

int nl_stp_snapshot_page_encode(const nl_stp_snapshot *snapshot, u32 offset,
                                void *buffer, size_t capacity) {
    nl_stp_snapshot_wire_header header;
    nl_stp_snapshot_wire_entry *wire_entries;
    u32 count;
    u32 next;
    size_t length;

    if (!snapshot || !buffer || !snapshot->complete ||
        snapshot->generation == 0 ||
        snapshot->n_entries != snapshot->total_entries ||
        snapshot->n_entries > NL_STP_SNAPSHOT_MAX_ENTRIES ||
        (snapshot->n_entries > 0 && !snapshot->entries) ||
        offset > snapshot->n_entries)
        return -1;
    count = snapshot->n_entries - offset;
    if (count > NL_STP_SNAPSHOT_PAGE_ENTRIES)
        count = NL_STP_SNAPSHOT_PAGE_ENTRIES;
    next = offset + count;
    length = sizeof(header) + sizeof(*wire_entries) * (size_t)count;
    if (length > capacity || length > INT_MAX)
        return -1;

    memset(&header, 0, sizeof(header));
    header.magic = htonl(NL_STP_SNAPSHOT_MAGIC);
    header.version = htons(NL_STP_SNAPSHOT_VERSION);
    header.entry_size = htons((u16)sizeof(*wire_entries));
    header.generation = host_to_network_u64(snapshot->generation);
    header.total_entries = htonl(snapshot->total_entries);
    header.offset = htonl(offset);
    header.n_entries = htonl(count);
    header.next_offset = htonl(next);
    header.flags = htonl(next == snapshot->total_entries ?
                         NL_STP_SNAPSHOT_PAGE_COMPLETE : 0U);
    memcpy(buffer, &header, sizeof(header));
    wire_entries = (nl_stp_snapshot_wire_entry *)
        ((u8 *)buffer + sizeof(header));
    for (u32 i = 0; i < count; i++) {
        const nl_stp_snapshot_entry *entry =
            &snapshot->entries[offset + i];

        if (!entry_valid(entry))
            return -1;
        wire_entries[i].vlan = htons(entry->vlan);
        wire_entries[i].port = htons(entry->port);
        wire_entries[i].state = entry->state;
    }
    return (int)length;
}

int nl_stp_snapshot_page_decode(const void *buffer, size_t length,
                                nl_stp_snapshot_page *page) {
    nl_stp_snapshot_wire_header header;
    const nl_stp_snapshot_wire_entry *wire_entries;
    nl_stp_snapshot_page decoded = {0};
    u32 flags;
    size_t expected;

    if (!buffer || !page || length < sizeof(header))
        return -1;
    memcpy(&header, buffer, sizeof(header));
    if (ntohl(header.magic) != NL_STP_SNAPSHOT_MAGIC ||
        ntohs(header.version) != NL_STP_SNAPSHOT_VERSION ||
        ntohs(header.entry_size) != sizeof(nl_stp_snapshot_wire_entry))
        return -1;
    decoded.generation = network_to_host_u64(header.generation);
    decoded.total_entries = ntohl(header.total_entries);
    decoded.offset = ntohl(header.offset);
    decoded.n_entries = ntohl(header.n_entries);
    decoded.next_offset = ntohl(header.next_offset);
    flags = ntohl(header.flags);
    decoded.complete = (flags & NL_STP_SNAPSHOT_PAGE_COMPLETE) != 0;
    if (decoded.generation == 0 ||
        decoded.total_entries > NL_STP_SNAPSHOT_MAX_ENTRIES ||
        decoded.offset > decoded.total_entries ||
        decoded.n_entries > NL_STP_SNAPSHOT_PAGE_ENTRIES ||
        decoded.n_entries > decoded.total_entries - decoded.offset ||
        decoded.next_offset != decoded.offset + decoded.n_entries ||
        decoded.complete !=
            (decoded.next_offset == decoded.total_entries) ||
        (!decoded.complete && decoded.n_entries == 0) ||
        (flags & ~NL_STP_SNAPSHOT_PAGE_COMPLETE) != 0)
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
    wire_entries = (const nl_stp_snapshot_wire_entry *)
        ((const u8 *)buffer + sizeof(header));
    for (u32 i = 0; i < decoded.n_entries; i++) {
        nl_stp_snapshot_entry *entry = &decoded.entries[i];

        entry->vlan = ntohs(wire_entries[i].vlan);
        entry->port = ntohs(wire_entries[i].port);
        entry->state = wire_entries[i].state;
        if (!entry_valid(entry) ||
            (i > 0 && !entry_key_before(&decoded.entries[i - 1], entry)))
            goto invalid;
    }
    nl_stp_snapshot_page_reset(page);
    *page = decoded;
    return 0;

invalid:
    nl_stp_snapshot_page_reset(&decoded);
    return -1;
}

int nl_stp_snapshot_append_page(nl_stp_snapshot *snapshot,
                                const nl_stp_snapshot_page *page) {
    if (!snapshot || !page || snapshot->complete ||
        page->generation == 0 ||
        page->total_entries > NL_STP_SNAPSHOT_MAX_ENTRIES ||
        page->offset + page->n_entries != page->next_offset ||
        page->next_offset > page->total_entries ||
        page->complete != (page->next_offset == page->total_entries) ||
        (page->n_entries > 0 && !page->entries))
        return -1;
    if (snapshot->n_entries == 0 && snapshot->generation == 0) {
        if (page->offset != 0)
            return -1;
        snapshot->generation = page->generation;
        snapshot->total_entries = page->total_entries;
        if (page->total_entries > 0) {
            snapshot->entries = calloc(page->total_entries,
                                       sizeof(*snapshot->entries));
            if (!snapshot->entries) {
                memset(snapshot, 0, sizeof(*snapshot));
                return -1;
            }
        }
    } else if (page->generation != snapshot->generation ||
               page->total_entries != snapshot->total_entries ||
               page->offset != snapshot->n_entries) {
        return -1;
    }
    if (page->n_entries > 0) {
        if (snapshot->n_entries > 0 &&
            !entry_key_before(&snapshot->entries[snapshot->n_entries - 1],
                              &page->entries[0]))
            return -1;
        memcpy(&snapshot->entries[snapshot->n_entries], page->entries,
               sizeof(*snapshot->entries) * (size_t)page->n_entries);
    }
    snapshot->n_entries = page->next_offset;
    if (page->complete) {
        if (snapshot->n_entries != snapshot->total_entries)
            return -1;
        snapshot->complete = true;
    }
    return 0;
}

bool nl_stp_snapshot_has_member(const nl_stp_snapshot *snapshot,
                                int vlan, int port) {
    u32 low = 0;
    u32 high;

    if (!snapshot || !snapshot->complete || vlan < 1 || vlan > 4094 ||
        port <= 0 || port > UINT16_MAX)
        return false;
    high = snapshot->n_entries;
    while (low < high) {
        u32 mid = low + (high - low) / 2;
        const nl_stp_snapshot_entry *entry = &snapshot->entries[mid];

        if (entry->vlan < vlan ||
            (entry->vlan == vlan && entry->port < port))
            low = mid + 1;
        else
            high = mid;
    }
    return low < snapshot->n_entries &&
        snapshot->entries[low].vlan == vlan &&
        snapshot->entries[low].port == port;
}

int nl_stp_snapshot_fetch(const char *socket_path, nl_daemon_id caller,
                          u32 timeout_ms, nl_stp_snapshot *snapshot) {
    nl_stp_snapshot assembled = {0};
    nl_stp_snapshot_page_request request = {0};
    u64 started;
    unsigned int page_count = 0;

    if (!socket_path || !snapshot || timeout_ms == 0)
        return -1;
    started = monotonic_ms();
    if (started == 0)
        return -1;
    while (!assembled.complete) {
        nl_stp_snapshot_page page = {0};
        nl_rpc_response response = {0};
        u8 request_wire[sizeof(nl_stp_snapshot_wire_request)];
        u64 now = monotonic_ms();
        u64 elapsed;
        u32 remaining;
        int request_len;
        int rn;

        if (now == 0 || now < started)
            goto fail;
        elapsed = now - started;
        if (elapsed >= timeout_ms)
            goto fail;
        remaining = timeout_ms - (u32)elapsed;
        request.generation = assembled.generation;
        request.offset = assembled.n_entries;
        request_len = nl_stp_snapshot_page_request_encode(
            &request, request_wire, sizeof(request_wire));
        if (request_len <= 0)
            goto fail;
        rn = nl_rpc_call_alloc_ex(
            socket_path, caller, NL_DAEMON_SWITCHD,
            NL_SWITCHD_STP_SNAPSHOT_PAGE_GET, 0,
            request_wire, request_len, (int)remaining, &response);
        if (rn <= 0 || response.error_code != 0 ||
            nl_stp_snapshot_page_decode(
                response.payload, response.payload_len, &page) != 0 ||
            nl_stp_snapshot_append_page(&assembled, &page) != 0) {
            nl_stp_snapshot_page_reset(&page);
            nl_rpc_response_free(&response);
            goto fail;
        }
        nl_stp_snapshot_page_reset(&page);
        nl_rpc_response_free(&response);
        page_count++;
        if (page_count >
            NL_STP_SNAPSHOT_MAX_ENTRIES / NL_STP_SNAPSHOT_PAGE_ENTRIES + 1U)
            goto fail;
    }
    nl_stp_snapshot_reset(snapshot);
    *snapshot = assembled;
    return 0;

fail:
    nl_stp_snapshot_reset(&assembled);
    return -1;
}
