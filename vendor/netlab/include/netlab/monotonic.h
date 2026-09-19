#ifndef NETLAB_MONOTONIC_H
#define NETLAB_MONOTONIC_H
#include <time.h>

/* Runtime intervals only. Persistent timestamps and audit dates stay UTC. */
static inline time_t nl_monotonic_seconds(void) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ? now.tv_sec : 0;
}
#endif
