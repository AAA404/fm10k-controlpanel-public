#include "igmp_state.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define IGMP_STATE_BYTES (192 * 1024)
#define IGMP_STATE_NAME "ownership.v1"
#define IGMP_PORTS 0x00ffffffU

time_t igmp_clock_seconds(void) {
    struct timespec now;
    return clock_gettime(CLOCK_BOOTTIME, &now) == 0 ? now.tv_sec : (time_t)-1;
}

static u64 fingerprint(const char *data, size_t length) {
    /* Accidental-corruption detection; access control is provided by the
     * private directory, no-follow opens and exclusive process lock. */
    u64 value = 14695981039346656037ULL;
    for (size_t i = 0; i < length; ++i) value = (value ^ (u8)data[i]) * 1099511628211ULL;
    return value;
}

static bool append(char *data, size_t *length, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vsnprintf(data + *length, IGMP_STATE_BYTES - *length, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= IGMP_STATE_BYTES - *length) return false;
    *length += (size_t)n;
    return true;
}

static bool group_fields(u32 ip, char group[16], u8 mac[6]) {
    if (ip < 0xe0000100U || ip > 0xefffffffU) return false;
    struct in_addr address = {.s_addr = htonl(ip)};
    if (!inet_ntop(AF_INET, &address, group, 16)) return false;
    const u8 key[6] = {1, 0, 0x5e, (u8)((ip >> 16) & 0x7f), (u8)(ip >> 8), (u8)ip};
    memcpy(mac, key, 6);
    return true;
}

static bool safe_file(int fd, off_t maximum) {
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
        !(info.st_mode & 0077) && info.st_nlink == 1 && info.st_size >= 0 && info.st_size < maximum;
}

static int transfer(int fd, char *data, size_t size, bool writing) {
    size_t at = 0;
    while (at < size) {
        ssize_t n = writing ? write(fd, data + at, size - at) : read(fd, data + at, size - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        at += (size_t)n;
    }
    return 0;
}

static bool boot_id(char id[37]) {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char text[38] = {0};
    ssize_t n = read(fd, text, sizeof(text));
    close(fd);
    if (n != 37 || text[36] != '\n') return false;
    for (int i = 0; i < 36; ++i) {
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? text[i] != '-' : !strchr("0123456789abcdef", text[i])) return false;
    }
    memcpy(id, text, 36); id[36] = '\0';
    return true;
}

static int decode(char *text, size_t size, const char *boot, igmp_runtime_image *out) {
    char *footer = strstr(text, "CHECKSUM ");
    unsigned long long expected;
    int used = -1;
    if (!footer || (footer != text && footer[-1] != '\n') ||
        sscanf(footer, "CHECKSUM %16llx\n%n", &expected, &used) != 1 || used < 0 ||
        (size_t)(footer - text + used) != size || expected != fingerprint(text, (size_t)(footer - text))) return -1;
    *footer = '\0';
    char *cursor = NULL, *line = strtok_r(text, "\n", &cursor);
    char saved_boot[37];
    long long saved_at;
    unsigned long long sequence;
    used = -1;
    if (!line || sscanf(line, "FM10K_IGMP_V1 %36s %lld %llu%n", saved_boot, &saved_at, &sequence, &used) != 3 ||
        used < 0 || line[used] || saved_at < 0) return -1;
    if (strcmp(saved_boot, boot)) return 1; /* Old system boot: do not replay learned state. */
    time_t now = igmp_clock_seconds();
    if (now < 0 || saved_at > now) return -1;
    out->tx_sequence = sequence;
    while ((line = strtok_r(NULL, "\n", &cursor))) {
        unsigned index, vid, port, ip, pending, retiring, applied, uncertain;
        long long expiry, seconds;
        unsigned long long tx;
        used = -1;
        if (line[0] == 'M') {
            /* A pause carried across reboot may extend a lease beyond
             * this boot's uptime. Check representation, not that clock. */
            if (sscanf(line, "M %u %u %u %x %lld %u %u%n", &index, &vid, &port, &ip,
                       &expiry, &pending, &retiring, &used) != 7 || used < 0 || line[used] ||
                index >= IGMP_MAX_DYNAMIC_MEMBERS || vid < 1 || vid > 4094 || port < 1 || port > 24 ||
                expiry < 0 || pending > 1 || retiring > 1 ||
                (retiring && !pending) || out->dynamic[index].used) return -1;
            igmp_dynamic_member *m = &out->dynamic[index];
            *m = (igmp_dynamic_member){.used = true, .pending = true, .retiring = retiring != 0,
                .vid = (int)vid, .port = (int)port, .group_ip = ip, .expires_at = (time_t)expiry};
            if ((long long)m->expires_at != expiry || !group_fields(ip, m->group, m->mac)) return -1;
            for (unsigned j = 0; j < IGMP_MAX_DYNAMIC_MEMBERS; ++j) {
                const igmp_dynamic_member *other = &out->dynamic[j];
                if (j != index && other->used && other->vid == m->vid && other->port == m->port && other->group_ip == ip) return -1;
            }
        } else if (line[0] == 'R') {
            if (sscanf(line, "R %u %u %x %x %x%n", &index, &vid, &ip, &applied, &uncertain, &used) != 5 ||
                used < 0 || line[used] || index >= IGMP_MAX_ROUTER_GROUPS || vid < 1 || vid > 4094 ||
                ((applied | uncertain) & ~IGMP_PORTS) || out->router_groups[index].used) return -1;
            igmp_router_group *r = &out->router_groups[index];
            *r = (igmp_router_group){.used = true, .vid = (int)vid, .applied_ports = applied,
                                   .uncertain_ports = applied | uncertain};
            if (!group_fields(ip, r->group, r->mac)) return -1;
            for (unsigned j = 0; j < IGMP_MAX_ROUTER_GROUPS; ++j) {
                const igmp_router_group *other = &out->router_groups[j];
                if (j != index && other->used && other->vid == r->vid && !memcmp(other->mac, r->mac, 6)) return -1;
            }
        } else if (line[0] == 'P') {
            /* Paused seconds use wall time and can exceed CLOCK_BOOTTIME
             * after a reboot while the same port transaction is held. */
            if (sscanf(line, "P %u %llx %lld%n", &port, &tx, &seconds, &used) != 3 ||
                used < 0 || line[used] || port < 1 || port > 24 || !tx || seconds < 0 ||
                (long long)(time_t)seconds != seconds ||
                out->resumed_tx[port - 1]) return -1;
            out->resumed_tx[port - 1] = tx;
            out->resumed_seconds[port - 1] = (time_t)seconds;
        } else return -1;
    }
    return 0;
}

int igmp_state_open(igmp_state_store *store, igmp_runtime_image *image) {
    memset(store, 0, sizeof(*store));
    store->directory = store->lock = -1;
    const char *path = getenv("NETLAB_IGMP_STATE_DIR");
    const char *native = getenv("NETLAB_FM10K_NATIVE");
    if ((!path || !*path) && (!native || strcmp(native, "1"))) return 0;
    if (!path || !*path) path = "/run/netlab/igmp";
    store->enabled = true;
    if (!boot_id(store->boot_id) || path[0] != '/' ||
        (mkdir(path, 0700) && errno != EEXIST)) goto fail;
    store->directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (store->directory < 0 || fstat(store->directory, &info) ||
        info.st_uid != geteuid() || (info.st_mode & 0077)) goto fail;
    store->lock = openat(store->directory, "owner.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (store->lock < 0 || !safe_file(store->lock, 1) || flock(store->lock, LOCK_EX | LOCK_NB)) goto fail;
    int fd = openat(store->directory, IGMP_STATE_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        goto fail;
    }
    bool valid = safe_file(fd, IGMP_STATE_BYTES) && fstat(fd, &info) == 0 && info.st_size > 0;
    char *text = calloc(1, IGMP_STATE_BYTES);
    igmp_runtime_image *loaded = calloc(1, sizeof(*loaded));
    int rc = valid && text && loaded && transfer(fd, text, (size_t)info.st_size, false) == 0 ?
             decode(text, (size_t)info.st_size, store->boot_id, loaded) : -1;
    close(fd);
    if (rc == 0) *image = *loaded;
    else if (rc == 1) memset(image, 0, sizeof(*image));
    free(loaded); free(text);
    if (rc >= 0) return 0;
fail:
    ++store->failures;
    igmp_state_close(store);
    return -1;
}

int igmp_state_save(igmp_state_store *store, const igmp_runtime_image *image) {
    if (!store->enabled) return 0;
    char *body = calloc(1, IGMP_STATE_BYTES);
    char *text = calloc(1, IGMP_STATE_BYTES);
    size_t body_size = 0, size = 0;
    time_t now = igmp_clock_seconds();
    bool ok = body && text && now >= 0 && store->directory >= 0;
    if (ok) ok = append(body, &body_size, "SEQ %llu\n", (unsigned long long)image->tx_sequence);
    for (int i = 0; ok && i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        const igmp_dynamic_member *m = &image->dynamic[i];
        if (m->used) ok = append(body, &body_size, "M %d %d %d %08x %lld %u %u\n",
            i, m->vid, m->port, m->group_ip, (long long)m->expires_at, m->pending ? 1U : 0U, m->retiring ? 1U : 0U);
    }
    for (int i = 0; ok && i < IGMP_MAX_ROUTER_GROUPS; ++i) {
        const igmp_router_group *r = &image->router_groups[i];
        if (!r->used) continue;
        struct in_addr address;
        ok = inet_pton(AF_INET, r->group, &address) == 1 && append(body, &body_size,
            "R %d %d %08x %06x %06x\n", i, r->vid, ntohl(address.s_addr), r->applied_ports, r->uncertain_ports);
    }
    for (int i = 0; ok && i < 24; ++i) if (image->resumed_tx[i])
        ok = append(body, &body_size, "P %d %016llx %lld\n", i + 1,
            (unsigned long long)image->resumed_tx[i], (long long)image->resumed_seconds[i]);
    u64 digest = ok ? fingerprint(body, body_size) : 0;
    if (ok && store->has_fingerprint && digest == store->fingerprint) {
        free(body); free(text); return 0;
    }
    /* Sequence participates in the no-change fingerprint but is encoded in
     * the header. Every hardware RPC reserves it before saving the image. */
    const char *records = ok ? strchr(body, '\n') + 1 : NULL;
    if (ok) ok = append(text, &size, "FM10K_IGMP_V1 %s %lld %llu\n%s", store->boot_id,
        (long long)now, (unsigned long long)image->tx_sequence, records);
    if (ok) { u64 sum = fingerprint(text, size); ok = append(text, &size, "CHECKSUM %016llx\n", (unsigned long long)sum); }
    char temporary[96] = {0};
    if (ok) {
        static u64 serial;
        snprintf(temporary, sizeof(temporary), ".ownership.%ld.%llu.tmp", (long)getpid(), (unsigned long long)++serial);
        int fd = openat(store->directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        ok = fd >= 0;
        if (fd >= 0) {
            ok = transfer(fd, text, size, true) == 0 && fsync(fd) == 0;
            if (close(fd)) ok = false;
        }
        if (ok && renameat(store->directory, temporary, store->directory, IGMP_STATE_NAME)) ok = false;
        if (ok && fsync(store->directory)) ok = false;
        if (!ok) (void)unlinkat(store->directory, temporary, 0);
    }
    free(body); free(text);
    if (!ok) { ++store->failures; return -1; }
    store->fingerprint = digest; store->has_fingerprint = true; ++store->saves;
    return 0;
}

void igmp_state_close(igmp_state_store *store) {
    if (store->lock >= 0) close(store->lock);
    if (store->directory >= 0) close(store->directory);
    store->lock = store->directory = -1;
}
