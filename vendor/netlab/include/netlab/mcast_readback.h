#ifndef NETLAB_MCAST_READBACK_H
#define NETLAB_MCAST_READBACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NL_MCAST_READBACK_BYTES (128U * 1024U)

static inline bool nl_mcast_text_take(const char **text, const char *end, const char *literal) {
    size_t length = strlen(literal);
    if ((size_t)(end - *text) < length || memcmp(*text, literal, length)) return false;
    *text += length;
    return true;
}

static inline void nl_mcast_text_space(const char **text, const char *end) {
    while (*text < end && (**text == ' ' || **text == '\n' || **text == '\r' || **text == '\t')) ++*text;
}

static inline bool nl_mcast_text_number(const char **text, const char *end, unsigned maximum, unsigned *out) {
    unsigned value = 0;
    const char *begin = *text;
    if ((size_t)(end - *text) > 1 && **text == '0' && (*text)[1] >= '0' && (*text)[1] <= '9') return false;
    while (*text < end && **text >= '0' && **text <= '9') {
        unsigned digit = (unsigned)(**text - '0');
        if (value > maximum / 10 || (value == maximum / 10 && digit > maximum % 10)) return false;
        value = value * 10 + digit;
        ++*text;
    }
    if (*text == begin || !nl_mcast_text_take(text, end, "\"")) return false;
    *out = value;
    return true;
}

static inline unsigned nl_mcast_key_slot(uint64_t key, unsigned mask) {
    uint64_t mixed = key * UINT64_C(11400714819323198485);
    return (unsigned)(mixed ^ (mixed >> 32)) & mask;
}

/* Validate the entire bounded reply before absence can authorize a replay.
 * Legacy complete replies are accepted; partial/unavailable replies are not.
 * This is the fixed FM10840 external-port projection, not general XML. */
static inline bool nl_mcast_readback_valid(const char *text, size_t length) {
    if (!text || !length || length >= NL_MCAST_READBACK_BYTES || memchr(text, '\0', length)) return false;
    const char *cursor = text, *end = text + length;
    nl_mcast_text_space(&cursor, end);
    if (!nl_mcast_text_take(&cursor, end, "<multicast-owner>") &&
        !nl_mcast_text_take(&cursor, end, "<multicast-owner status=\"ok\">")) return false;
    /* The minimum serialized nonempty group is over 64 bytes, so a reply
     * under 128 KiB cannot fill half of this duplicate-key hash table. */
    uint64_t *keys = calloc(4096, sizeof(*keys));
    if (!keys) return false;
    unsigned groups = 0, listeners = 0, previous_id = 0;
    bool ok = false;
    for (;;) {
        nl_mcast_text_space(&cursor, end);
        if (!nl_mcast_text_take(&cursor, end, "<group id=\"")) break;
        unsigned id, vlan;
        uint64_t mac = 0;
        if (!nl_mcast_text_number(&cursor, end, 65534, &id) || id <= previous_id ||
            !nl_mcast_text_take(&cursor, end, " vlan=\"") ||
            !nl_mcast_text_number(&cursor, end, 4094, &vlan) || !vlan ||
            !nl_mcast_text_take(&cursor, end, " mac=\"")) goto done;
        previous_id = id;
        static const char hex[] = "0123456789abcdef";
        for (int byte = 0; byte < 6; ++byte) {
            unsigned value = 0;
            for (int nibble = 0; nibble < 2; ++nibble) {
                if (cursor == end) goto done;
                const char *digit = strchr(hex, *cursor++);
                if (!digit) goto done;
                value = value * 16 + (unsigned)(digit - hex);
            }
            mac = (mac << 8) | value;
            if (byte < 5 && !nl_mcast_text_take(&cursor, end, ":")) goto done;
        }
        if (!(mac & (UINT64_C(1) << 40)) || !nl_mcast_text_take(&cursor, end, "\">")) goto done;
        uint64_t key = ((uint64_t)vlan << 48) | mac;
        unsigned slot = nl_mcast_key_slot(key, 4095);
        while (keys[slot] && keys[slot] != key) slot = (slot + 1) & 4095;
        if (keys[slot] || ++groups >= 2048) goto done;
        keys[slot] = key;
        uint32_t ports = 0;
        for (;;) {
            nl_mcast_text_space(&cursor, end);
            if (!nl_mcast_text_take(&cursor, end, "<listener port=\"")) break;
            unsigned port, listener_vlan;
            if (!nl_mcast_text_number(&cursor, end, 24, &port) || !port ||
                !nl_mcast_text_take(&cursor, end, " vlan=\"") ||
                !nl_mcast_text_number(&cursor, end, 4094, &listener_vlan) || listener_vlan != vlan ||
                !nl_mcast_text_take(&cursor, end, "/>")) goto done;
            uint32_t bit = UINT32_C(1) << (port - 1);
            if (ports & bit) goto done;
            ports |= bit; ++listeners;
        }
        if (!ports || !nl_mcast_text_take(&cursor, end, "</group>")) goto done;
    }
    unsigned reported_groups, reported_listeners;
    if (!nl_mcast_text_take(&cursor, end, "<summary groups=\"") ||
        !nl_mcast_text_number(&cursor, end, groups, &reported_groups) || reported_groups != groups ||
        !nl_mcast_text_take(&cursor, end, " listeners=\"") ||
        !nl_mcast_text_number(&cursor, end, listeners, &reported_listeners) || reported_listeners != listeners ||
        !nl_mcast_text_take(&cursor, end, "/>")) goto done;
    nl_mcast_text_space(&cursor, end);
    if (!nl_mcast_text_take(&cursor, end, "</multicast-owner>")) goto done;
    nl_mcast_text_space(&cursor, end);
    ok = cursor == end;
done:
    free(keys);
    return ok;
}

#endif
