#include "lldp_format.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void lldp_fmt_chassis_id(char *out, int out_max,
                         const u8 *data, int len, u8 subtype) {
    if (!out || out_max <= 0)
        return;
    out[0] = '\0';
    if (!data || len <= 0)
        return;
    if (subtype == 4 && len == 6) {
        snprintf(out, (size_t)out_max, "%02x:%02x:%02x:%02x:%02x:%02x",
                 data[0], data[1], data[2], data[3], data[4], data[5]);
    } else {
        int off = 0;

        for (int i = 0; i < len && off < out_max - 3; i++)
            off += snprintf(out + off, (size_t)(out_max - off),
                            "%02x", data[i]);
        out[off] = '\0';
    }
}

const char *lldp_chassis_subtype_name(u8 subtype) {
    switch (subtype) {
    case 1: return "chassis-component";
    case 2: return "interface-alias";
    case 3: return "port-component";
    case 4: return "mac-address";
    case 5: return "network-address";
    case 6: return "interface-name";
    case 7: return "locally-assigned";
    default: return "unknown";
    }
}

const char *lldp_port_subtype_name(u8 subtype) {
    switch (subtype) {
    case 1: return "interface-alias";
    case 2: return "port-component";
    case 3: return "mac-address";
    case 4: return "network-address";
    case 5: return "interface-name";
    case 6: return "agent-circuit-id";
    case 7: return "locally-assigned";
    default: return "unknown";
    }
}

void lldp_fmt_bytes(char *out, int out_max, const u8 *data, int len) {
    bool printable = true;
    int off = 0;

    if (!out || out_max <= 0)
        return;
    out[0] = '\0';
    if (!data || len <= 0)
        return;
    for (int i = 0; i < len; i++) {
        if (data[i] < 32 || data[i] > 126) {
            printable = false;
            break;
        }
    }
    if (printable) {
        int n = len < out_max - 1 ? len : out_max - 1;

        memcpy(out, data, (size_t)n);
        out[n] = '\0';
        return;
    }
    for (int i = 0; i < len && off < out_max - 3; i++) {
        off += snprintf(out + off, (size_t)(out_max - off),
                        "%s%02x", i ? ":" : "", data[i]);
    }
    out[out_max - 1] = '\0';
}

void lldp_fmt_string(char *out, int out_max, const u8 *data, int len) {
    int off = 0;
    bool last_space = false;

    if (!out || out_max <= 0)
        return;
    out[0] = '\0';
    if (!data || len <= 0)
        return;
    for (int i = 0; i < len && off < out_max - 1; i++) {
        unsigned char c = data[i];

        if (c >= 32 && c <= 126) {
            out[off++] = (char)c;
            last_space = c == ' ';
        } else if (!last_space) {
            out[off++] = ' ';
            last_space = true;
        }
    }
    while (off > 0 && out[off - 1] == ' ')
        off--;
    out[off] = '\0';
}

void lldp_fmt_caps(char *out, int out_max, u16 caps) {
    struct cap_name { u16 bit; const char *name; };
    static const struct cap_name names[] = {
        {1, "Other"}, {2, "Repeater"}, {4, "Bridge"}, {8, "WLAN"},
        {16, "Router"}, {32, "Telephone"}, {64, "DOCSIS"},
        {128, "Station"},
    };
    int off = 0;

    if (!out || out_max <= 0)
        return;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if ((caps & names[i].bit) == 0)
            continue;
        off += snprintf(out + off, (size_t)(out_max - off),
                        "%s%s", off ? ", " : "", names[i].name);
        if (off >= out_max - 1)
            break;
    }
    if (!out[0])
        snprintf(out, (size_t)out_max, "-");
}
