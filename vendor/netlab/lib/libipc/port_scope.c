#include "netlab/port_scope.h"
#include "netlab/error.h"
#include "netlab/monotonic.h"
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t drained = PTHREAD_COND_INITIALIZER;
static unsigned readers[24];
static u64 packet_cutoff[24];
static u64 owner;
static u32 paused;
static time_t started[24];
static time_t started_monotonic[24];
static bool monotonic_resume;
static bool initialized, faulted, ending;
static int directory = -1;
static char state_name[48];
static nl_port_scope_resume_fn resume_hook;
static u32 port_mask(int port) { return port >= 1 && port <= 24 ? 1U << (port - 1) : 0; }

static int save_state(u64 tx, u32 mask, const time_t *at, bool failed) {
    if (directory < 0) return 0;
    char data[1024], temporary[96];
    int n = snprintf(data, sizeof(data), "FM10K_SCOPE_V3 %016llx %08x %u ",
                     (unsigned long long)tx, mask, failed ? 1U : 0U);
    for (int i = 0; i < 24; ++i) {
        int used = snprintf(data + n, sizeof(data) - (size_t)n, "%lld%c",
            (long long)(at && (mask & (1U << i)) ? at[i] : 0), i == 23 ? '\n' : ' ');
        if (used < 0 || (size_t)used >= sizeof(data) - (size_t)n) return -1;
        n += used;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    snprintf(temporary, sizeof(temporary), "%s.%ld.%ld.tmp", state_name, (long)getpid(), now.tv_nsec);
    int fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int rc = write(fd, data, (size_t)n) != n || fsync(fd) != 0;
    if (close(fd)) rc = 1;
    if (!rc && renameat(directory, temporary, directory, state_name)) rc = 1;
    if (!rc && fsync(directory)) rc = 1;
    if (rc) (void)unlinkat(directory, temporary, 0);
    return rc ? -1 : 0;
}
int nl_port_scope_init(const char *service) {
    if (!service || !*service || strlen(service) > 24 || strspn(service, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(service))
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&lock);
    if (initialized) { int rc = faulted ? NL_ERR_HW_STATE_OUT_OF_SYNC : 0; pthread_mutex_unlock(&lock); return rc; }
    initialized = true;
#ifndef __APPLE__
    pthread_condattr_t attributes;
    if (pthread_condattr_init(&attributes)) goto failed;
    int condition_error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    if (!condition_error) condition_error = pthread_cond_destroy(&drained);
    if (!condition_error) condition_error = pthread_cond_init(&drained, &attributes);
    (void)pthread_condattr_destroy(&attributes);
    if (condition_error) goto failed;
#endif
    const char *native = getenv("NETLAB_FM10K_NATIVE");
    if (!native || strcmp(native, "1")) { pthread_mutex_unlock(&lock); return 0; }
    u64 cutoff = nl_port_scope_clock();
    if (!cutoff) goto failed;
    for (int i = 0; i < 24; ++i) packet_cutoff[i] = cutoff;
    const char *path = getenv("NETLAB_PORT_SCOPE_DIR");
    if (!path || !*path) path = "/var/run/netlab/port-scopes";
    if (mkdir(path, 0700) && errno != EEXIST) goto failed;
    directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (directory < 0 || fstat(directory, &st) || st.st_uid != geteuid() || (st.st_mode & 0022)) goto failed;
    snprintf(state_name, sizeof(state_name), "%s.state", service);
    int fd = openat(directory, state_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) { pthread_mutex_unlock(&lock); return 0; }
    if (fd < 0) goto failed;
    char data[1024] = {0};
    int n = (int)read(fd, data, sizeof(data) - 1);
    bool valid_file = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        !(st.st_mode & 0077) && st.st_size > 0 && st.st_size < (off_t)sizeof(data) && n == st.st_size;
    close(fd);
    unsigned long long tx;
    unsigned mask, degraded;
    long long at;
    int used = -1;
    if (!valid_file) goto failed;
    if (sscanf(data, "FM10K_SCOPE_V2 %16llx %8x %lld %u %n", &tx, &mask, &at, &degraded, &used) == 4) {
        if (used != n || (tx && at <= 0) || (long long)(time_t)at != at) goto failed;
        for (int i = 0; i < 24; ++i) started[i] = mask & (1U << i) ? (time_t)at : 0;
    } else {
        used = -1;
        if (sscanf(data, "FM10K_SCOPE_V3 %16llx %8x %u %n", &tx, &mask, &degraded, &used) != 3 ||
            used <= 0 || used >= n) goto failed;
        char *cursor = data + used;
        for (int i = 0; i < 24; ++i) {
            char *end = NULL;
            errno = 0; at = strtoll(cursor, &end, 10);
            if (errno || end == cursor || !isspace((unsigned char)*end) ||
                (mask & (1U << i) ? at <= 0 : at != 0) || (long long)(time_t)at != at) goto failed;
            started[i] = (time_t)at; cursor = end;
        }
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor) goto failed;
    }
    if ((mask & ~NL_PORT_SCOPE_MASK) || (!!tx != !!mask) || degraded > 1 || (!tx && degraded)) goto failed;
    owner = tx; paused = mask; faulted = degraded != 0;
    /* A restarted protocol daemon has no old in-memory interval timers.
     * Preserve the durable barrier, but freeze its new timers from startup. */
    for (int i = 0; i < 24; ++i)
        started_monotonic[i] = mask & (1U << i) ? (time_t)(cutoff / 1000000000ULL) : 0;
    pthread_mutex_unlock(&lock);
    return 0;
failed:
    faulted = true; paused = NL_PORT_SCOPE_MASK;
    pthread_mutex_unlock(&lock);
    return NL_ERR_HW_STATE_OUT_OF_SYNC;
}
void nl_port_scope_on_resume(nl_port_scope_resume_fn hook) {
    pthread_mutex_lock(&lock); resume_hook = hook; monotonic_resume = false; pthread_mutex_unlock(&lock);
}
void nl_port_scope_on_resume_monotonic(nl_port_scope_resume_fn hook) {
    pthread_mutex_lock(&lock); resume_hook = hook; monotonic_resume = true; pthread_mutex_unlock(&lock);
}
bool nl_port_scope_ready(void) {
    pthread_mutex_lock(&lock); bool ok = initialized && !faulted; pthread_mutex_unlock(&lock); return ok;
}
int nl_port_scope_begin(u64 tx, u32 mask, unsigned timeout_ms) {
    if (!tx || !mask || (mask & ~NL_PORT_SCOPE_MASK) || timeout_ms > 30000) return NL_ERR_INVALID_VALUE;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline)) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000L) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&lock);
    int rc = ending ? NL_ERR_RPC_BUSY : !initialized || faulted ? NL_ERR_HW_STATE_OUT_OF_SYNC :
        owner && (owner != tx || (paused & ~mask)) ? NL_ERR_COMMIT_LOCKED : 0;
    if (rc) goto done;
    if (!owner || paused != mask) {
        time_t now = time(NULL);
        time_t mono = nl_monotonic_seconds();
        if (now <= 0 || mono <= 0) { rc = NL_ERR_HW_STATE_OUT_OF_SYNC; goto done; }
        for (int i = 0; i < 24; ++i)
            if ((mask & ~paused) & (1U << i)) {
                started[i] = now;
                started_monotonic[i] = mono;
            }
        owner = tx; paused = mask;
        if (save_state(owner, paused, started, false)) { faulted = true; rc = NL_ERR_HW_STATE_OUT_OF_SYNC; goto done; }
    }
    for (;;) {
        bool busy = false;
        for (int i = 0; i < 24; ++i) if ((mask & (1U << i)) && readers[i]) busy = true;
        if (!busy) break;
#ifdef __APPLE__
        /* Darwin offers a relative wait instead of a monotonic condattr. */
        struct timespec current, remaining;
        int wait_rc = clock_gettime(CLOCK_MONOTONIC, &current);
        if (!wait_rc) {
            remaining.tv_sec = deadline.tv_sec - current.tv_sec;
            remaining.tv_nsec = deadline.tv_nsec - current.tv_nsec;
            if (remaining.tv_nsec < 0) { --remaining.tv_sec; remaining.tv_nsec += 1000000000L; }
            wait_rc = remaining.tv_sec < 0 ? ETIMEDOUT :
                pthread_cond_timedwait_relative_np(&drained, &lock, &remaining);
        }
#else
        int wait_rc = pthread_cond_timedwait(&drained, &lock, &deadline);
#endif
        if (wait_rc) { rc = wait_rc == ETIMEDOUT ? NL_ERR_RPC_TIMEOUT : NL_ERR_HW_STATE_OUT_OF_SYNC; break; }
    }
done:
    pthread_mutex_unlock(&lock); return rc;
}
int nl_port_scope_end(u64 tx) {
    if (!tx) return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&lock);
    int rc = ending ? NL_ERR_RPC_BUSY : faulted ? NL_ERR_HW_STATE_OUT_OF_SYNC : owner && owner != tx ? NL_ERR_COMMIT_LOCKED : 0;
    if (rc || !owner) { pthread_mutex_unlock(&lock); return rc; }
    for (int i = 0; i < 24; ++i) if ((paused & (1U << i)) && readers[i]) {
        pthread_mutex_unlock(&lock); return NL_ERR_RPC_BUSY;
    }
    ending = true;
    u32 mask = paused;
    time_t paused_at[24], now = monotonic_resume ? nl_monotonic_seconds() : time(NULL);
    if (monotonic_resume && now <= 0) {
        ending = false; faulted = true;
        (void)save_state(owner, paused, started, true);
        pthread_mutex_unlock(&lock); return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    memcpy(paused_at, monotonic_resume ? started_monotonic : started, sizeof(paused_at));
    nl_port_scope_resume_fn hook = resume_hook;
    /* Keep the barrier closed while the protocol owner rebases its timers.
     * Do not hold the scope mutex across a protocol-state lock. */
    pthread_mutex_unlock(&lock);
    if (hook) {
        u32 remaining = mask;
        for (int i = 0; i < 24; ++i) if (remaining & (1U << i)) {
            u32 cohort = 0;
            for (int j = i; j < 24; ++j)
                if ((remaining & (1U << j)) && paused_at[j] == paused_at[i]) cohort |= 1U << j;
            time_t duration = now - paused_at[i];
            hook(cohort, duration > 0 ? duration : 0);
            remaining &= ~cohort;
        }
    }
    pthread_mutex_lock(&lock);
    if (owner != tx || paused != mask) rc = NL_ERR_COMMIT_LOCKED;
    else if (faulted || !nl_port_scope_clock() || save_state(0, 0, 0, false)) {
        faulted = true; rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
    } else {
        u64 cutoff = nl_port_scope_clock();
        if (!cutoff) {
            faulted = true; rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
            (void)save_state(owner, paused, started, true);
        } else {
            for (int i = 0; i < 24; ++i) if (mask & (1U << i)) packet_cutoff[i] = cutoff;
            owner = 0; paused = 0; memset(started, 0, sizeof(started));
            memset(started_monotonic, 0, sizeof(started_monotonic));
        }
    }
    ending = false;
    pthread_mutex_unlock(&lock); return rc;
}
void nl_port_scope_degrade(u64 tx) {
    pthread_mutex_lock(&lock);
    if (tx && owner == tx) {
        faulted = true;
        (void)save_state(owner, paused, started, true);
    }
    pthread_mutex_unlock(&lock);
}
nl_port_scope_status nl_port_scope_get(void) {
    pthread_mutex_lock(&lock);
    nl_port_scope_status out = {NL_PORT_SCOPE_SCHEMA, paused, owner, faulted, 0};
    pthread_mutex_unlock(&lock); return out;
}
bool nl_port_scope_enter_mask(u32 mask) {
    mask &= NL_PORT_SCOPE_MASK;
    pthread_mutex_lock(&lock);
    bool ok = !(paused & mask);
    if (ok) for (int i = 0; i < 24; ++i) if (mask & (1U << i)) ++readers[i];
    pthread_mutex_unlock(&lock); return ok;
}
bool nl_port_scope_enter_epoch_mask(u32 mask, u64 issued_at) {
    mask &= NL_PORT_SCOPE_MASK;
    pthread_mutex_lock(&lock);
    bool ok = !(paused & mask);
    for (int i = 0; ok && i < 24; ++i)
        /* Equal timestamps cannot prove that an operation followed resume
         * on clocks whose resolution is coarser than the transition. */
        if ((mask & (1U << i)) && issued_at <= packet_cutoff[i]) ok = false;
    if (ok) for (int i = 0; i < 24; ++i) if (mask & (1U << i)) ++readers[i];
    pthread_mutex_unlock(&lock);
    return ok;
}
u32 nl_port_scope_enter_available(void) {
    pthread_mutex_lock(&lock);
    u32 mask = NL_PORT_SCOPE_MASK & ~paused;
    for (int i = 0; i < 24; ++i) if (mask & (1U << i)) ++readers[i];
    pthread_mutex_unlock(&lock);
    return mask;
}
void nl_port_scope_leave_mask(u32 mask) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < 24; ++i) if ((mask & (1U << i)) && readers[i]) --readers[i];
    pthread_cond_broadcast(&drained);
    pthread_mutex_unlock(&lock);
}
bool nl_port_scope_enter(int port) { return nl_port_scope_enter_mask(port_mask(port)); }
u64 nl_port_scope_clock(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (u64)now.tv_sec * 1000000000ULL + (u64)now.tv_nsec;
}
bool nl_port_scope_packet_enter(int port, u64 received_at) {
    return nl_port_scope_enter_epoch_mask(port_mask(port), received_at);
}
void nl_port_scope_leave(int port) { nl_port_scope_leave_mask(port_mask(port)); }
bool nl_port_scope_paused(int port) {
    pthread_mutex_lock(&lock); bool yes = (paused & port_mask(port)) != 0; pthread_mutex_unlock(&lock); return yes;
}
time_t nl_port_scope_now(int port, time_t wall_now) {
    pthread_mutex_lock(&lock);
    time_t now = paused & port_mask(port) ? started[port - 1] : wall_now;
    pthread_mutex_unlock(&lock); return now;
}
time_t nl_port_scope_now_monotonic(int port, time_t monotonic_now) {
    pthread_mutex_lock(&lock);
    time_t now = paused & port_mask(port) ? started_monotonic[port - 1] : monotonic_now;
    pthread_mutex_unlock(&lock); return now;
}
