#ifndef NETLAB_LAG_READBACK_H
#define NETLAB_LAG_READBACK_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline bool nl_lag_generation_parse(const char *value, uint64_t *out) {
    if (!value || !out || strlen(value) != 16) return false;
    uint64_t generation = 0;
    for (int i = 0; i < 16; ++i) {
        unsigned char c = (unsigned char)value[i];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10U;
        else return false;
        generation = (generation << 4) | digit;
    }
    if (!generation) return false;
    *out = generation;
    return true;
}

/* Native member handles are meaningful only within one SDK instance. */
static inline bool nl_lag_runtime_request_parse(const char *payload, bool native,
        int *lag, int *port, uint64_t *generation) {
    int consumed = -1;
    if (!payload || !lag || !port || !generation ||
        sscanf(payload, "%d %d %n", lag, port, &consumed) != 2 || consumed < 0 ||
        *lag <= 0 || *port <= 0) return false;
    *generation = 0;
    const char *tail = payload + consumed;
    if (!native) return !*tail;
    const char prefix[] = "generation=";
    return !strncmp(tail, prefix, sizeof(prefix) - 1) &&
        nl_lag_generation_parse(tail + sizeof(prefix) - 1, generation);
}

/* Legacy replies have no marker. New switchd replies mark each LAG so an
 * unreadable or faulted group cannot be mistaken for an empty healthy one. */
static inline bool nl_lag_readback_error(const char *begin, const char *end) {
    if (!begin || !end || end < begin) return true;
    const char *marker = strstr(begin, "<member-readback ");
    const char ok[] = "<member-readback status=\"ok\"";
    return marker && marker < end &&
        ((size_t)(end - marker) < sizeof(ok) - 1 || strncmp(marker, ok, sizeof(ok) - 1));
}
#endif
