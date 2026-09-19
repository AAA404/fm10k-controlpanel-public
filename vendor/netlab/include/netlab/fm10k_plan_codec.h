#ifndef NETLAB_FM10K_PLAN_CODEC_H
#define NETLAB_FM10K_PLAN_CODEC_H
#include "fm10k_board_types.h"
#include <ctype.h>
#include <limits.h>
#include <string.h>

#define NL_FM10K_SCOPE_HEADER "# fm10k-scope-v1 mask="
static inline bool nl_fm10k_parse_scope_header(const char *text, size_t size, bool *present, uint32_t *mask) {
    *present = false; *mask = 0;
    const size_t prefix = sizeof(NL_FM10K_SCOPE_HEADER) - 1;
    if (size < prefix || memcmp(text, NL_FM10K_SCOPE_HEADER, prefix)) return true;
    if (size < prefix + 7 || text[prefix + 6] != '\n') return false;
    for (unsigned i = 0; i < 6; ++i) {
        char c = text[prefix + i];
        unsigned digit = c >= '0' && c <= '9' ? (unsigned)(c - '0') :
            c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10) : 16;
        if (digit > 15) return false;
        *mask = (*mask << 4) | digit;
    }
    /* Scope is authoritative metadata, never an override later in a plan. */
    const char *rest = text + prefix + 7;
    size_t remaining = size - prefix - 7;
    for (size_t i = 0; i + prefix <= remaining; ++i)
        if (!memcmp(rest + i, NL_FM10K_SCOPE_HEADER, prefix)) return false;
    *present = true;
    return true;
}

static inline bool nl_fm10k_parse_unsigned(const char *text, const char *const *keys,
                                  int *values, unsigned count) {
    unsigned seen = 0;
    if (!count || count > 16) return false;
    while (*text) {
        while (isspace((unsigned char)*text)) ++text;
        if (!*text) break;
        const char *key = text;
        while (*text && *text != '=' && !isspace((unsigned char)*text)) ++text;
        if (*text != '=') return false;
        size_t length = (size_t)(text - key);
        unsigned i;
        for (i = 0; i < count; ++i)
            if (strlen(keys[i]) == length && !strncmp(key, keys[i], length)) break;
        if (i == count || (seen & (1U << i))) return false;
        ++text;
        int value = 0;
        if (*text < '0' || *text > '9') return false;
        while (*text >= '0' && *text <= '9') {
            int digit = *text++ - '0';
            if (value > (INT_MAX - digit) / 10) return false;
            value = value * 10 + digit;
        }
        if (*text && !isspace((unsigned char)*text)) return false;
        values[i] = value;
        seen |= 1U << i;
    }
    return seen == (1U << count) - 1;
}
static inline bool nl_fm10k_parse_fan(const char *text, fm10k_fan_curve *out) {
    static const char *const keys[] = {"idle", "load", "critical", "idle-pwm",
        "load-pwm", "hysteresis", "response-ms"};
    int v[7];
    if (!nl_fm10k_parse_unsigned(text, keys, v, 7)) return false;
    *out = (fm10k_fan_curve){v[0], v[1], v[2], v[3], v[4], v[5], v[6]};
    return nl_fm10k_fan_valid(out);
}
static inline bool nl_fm10k_parse_group(const char *text, fm10k_group *out) {
    static const char *const keys[] = {"epl", "mode", "lane0", "lane1", "lane2", "lane3", "enabled"};
    int v[7];
    if (!nl_fm10k_parse_unsigned(text, keys, v, 7) || v[6] > 15) return false;
    *out = (fm10k_group){.epl = v[0], .mode = v[1], .lane_gbps = {v[2], v[3], v[4], v[5]},
        .enabled = (uint8_t)v[6]};
    return nl_fm10k_group_valid(out);
}

#endif
