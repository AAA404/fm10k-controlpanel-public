#ifndef NETLAB_STORM_CONTROL_H
#define NETLAB_STORM_CONTROL_H

#include <string.h>

/* Zero preserves the reference project's combined broadcast/multicast policy.
 * A typed policy owns one controller per physical ingress port and class. */
typedef enum {
    NL_STORM_COMBINED = 0,
    NL_STORM_BROADCAST = 1,
    NL_STORM_MULTICAST = 2,
    NL_STORM_UNKNOWN_UNICAST = 3,
    NL_STORM_INGRESS = 4,
    NL_STORM_INVALID = -1,
} nl_storm_kind;

#define NL_STORM_CONTROLLER_CAPACITY 16
#define NL_STORM_MIN_RATE_KBPS 22000

static inline const char *nl_storm_kind_name(nl_storm_kind kind) {
    switch (kind) {
    case NL_STORM_COMBINED: return "combined";
    case NL_STORM_BROADCAST: return "broadcast";
    case NL_STORM_MULTICAST: return "multicast";
    case NL_STORM_UNKNOWN_UNICAST: return "unknown-unicast";
    case NL_STORM_INGRESS: return "ingress";
    default: return "invalid";
    }
}

static inline nl_storm_kind nl_storm_kind_parse(const char *text) {
    for (int kind = NL_STORM_COMBINED; kind <= NL_STORM_UNKNOWN_UNICAST; ++kind)
        if (text && !strcmp(text, nl_storm_kind_name((nl_storm_kind)kind)))
            return (nl_storm_kind)kind;
    return NL_STORM_INVALID;
}

#endif
