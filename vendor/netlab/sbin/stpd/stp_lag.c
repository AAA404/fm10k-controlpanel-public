#include "stp_lag.h"
#include "stp_config_text.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/port_scope.h"
#include "netlab/lag_readback.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { u32 configured, attached; int hardware; } bridge_lag;
static bridge_lag lags[STP_AGGREGATE_COUNT];
static pthread_mutex_t lag_lock = PTHREAD_MUTEX_INITIALIZER;
static int aggregate(int port) {
    return port >= STP_AGGREGATE_BASE && port < STP_AGGREGATE_BASE + STP_AGGREGATE_COUNT ?
        port - STP_AGGREGATE_BASE : -1;
}
int stp_port_from_name(const char *name) {
    if (!name) return -1;
    int physical = nl_ifid_name_to_logical_port(name);
    if (physical > 0) return physical;
    unsigned ae; int used = -1;
    if (sscanf(name, "ae%u%n", &ae, &used) != 1 || used != (int)strlen(name) ||
        ae >= STP_AGGREGATE_COUNT || ae >= (unsigned)nl_platform_max_ae()) return -1;
    char canonical[16]; snprintf(canonical, sizeof(canonical), "ae%u", ae);
    return !strcmp(name, canonical) ? STP_AGGREGATE_BASE + (int)ae : -1;
}
void stp_port_name(int port, char *name, size_t size) {
    int ae = aggregate(port);
    if (!name || !size) return;
    if (ae >= 0) snprintf(name, size, "ae%d", ae);
    else if (!nl_ifid_logical_port_to_name(port, name, size)) snprintf(name, size, "unknown");
}
void stp_lag_load_config(const char *xml) {
    u32 masks[STP_AGGREGATE_COUNT] = {0};
    const char *start = xml ? strstr(xml, "<interfaces>") : NULL;
    const char *limit = start ? strstr(start, "</interfaces>") : NULL;
    const char *p = start;
    while (p && limit && (p = strstr(p, "<interface>")) && p < limit) {
        const char *end = strstr(p, "</interface>");
        char name[64] = {0}, member[32] = {0};
        if (!end || end > limit) break;
        if (!stp_config_xml_leaf(p, end, "name", name, sizeof(name)) &&
            !stp_config_xml_leaf(p, end, "ieee8023ad", member, sizeof(member))) {
            int physical = nl_ifid_name_to_logical_port(name);
            int ae = aggregate(stp_port_from_name(member));
            if (physical >= 1 && physical <= 24 && ae >= 0) masks[ae] |= 1U << (physical - 1);
        }
        p = end + strlen("</interface>");
    }
    pthread_mutex_lock(&lag_lock);
    for (int i = 0; i < STP_AGGREGATE_COUNT; ++i) {
        lags[i].configured = masks[i];
        lags[i].attached &= masks[i];
    }
    pthread_mutex_unlock(&lag_lock);
}
bool stp_lag_refresh(const char *socket) {
    char xml[32768] = {0}; s32 error = 0;
    int n = nl_rpc_call_ex(socket, NL_DAEMON_STPD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_LAG_GET_ALL, 0, NULL, 0, (u8 *)xml, sizeof(xml) - 1, 3000, &error);
    bridge_lag next[STP_AGGREGATE_COUNT] = {{0}};
    bool ok = n > 0 && !error && strstr(xml, "</lags>");
    u32 seen_members = 0;
    const char *p = xml;
    while (ok && (p = strstr(p, "<lag "))) {
        const char *end = strstr(p, "</lag>");
        if (end && nl_lag_readback_error(p, end)) {
            p = end + strlen("</lag>");
            continue;
        }
        int ae, id, hw, used = -1;
        char name[16];
        if (!end || sscanf(p, "<lag ae=\"%d\" name=\"%15[^\"]\" id=\"%d\" logical-port=\"%d\">%n",
            &ae, name, &id, &hw, &used) != 4 || used < 0 || p + used > end) { ok = false; break; }
        if (ae >= 0 && ae < STP_AGGREGATE_COUNT && id > 0 && hw > 0) {
            char expected[16]; snprintf(expected, sizeof(expected), "ae%d", ae);
            if (next[ae].hardware || strcmp(name, expected) || hw <= 24) { ok = false; break; }
            for (int i = 0; i < STP_AGGREGATE_COUNT; ++i)
                if (next[i].hardware == hw) ok = false;
            if (!ok) break;
            next[ae].hardware = hw;
            const char *m = p + used;
            while ((m = strstr(m, "<member ")) && m < end) {
                int port;
                if (sscanf(m, "<member port=\"%d\"/>", &port) != 1 || port < 1 || port > 24) {
                    ok = false; break;
                }
                if (seen_members & (1U << (port - 1))) { ok = false; break; }
                seen_members |= 1U << (port - 1);
                next[ae].attached |= 1U << (port - 1); ++m;
            }
        }
        p = end + strlen("</lag>");
    }
    pthread_mutex_lock(&lag_lock);
    for (int i = 0; i < STP_AGGREGATE_COUNT; ++i)
        if (next[i].attached & ~lags[i].configured) ok = false;
    for (int i = 0; i < STP_AGGREGATE_COUNT; ++i) {
        lags[i].hardware = ok ? next[i].hardware : 0;
        lags[i].attached = ok ? next[i].attached & lags[i].configured : 0;
    }
    pthread_mutex_unlock(&lag_lock);
    return ok;
}
int stp_lag_ingress(int physical) {
    int result = physical;
    pthread_mutex_lock(&lag_lock);
    for (int ae = 0; ae < STP_AGGREGATE_COUNT; ++ae) {
        u32 bit = physical >= 1 && physical <= 24 ? 1U << (physical - 1) : 0;
        if (bit && (lags[ae].configured & bit)) {
            result = lags[ae].attached & bit ? STP_AGGREGATE_BASE + ae : -1; break;
        }
    }
    pthread_mutex_unlock(&lag_lock);
    return result;
}
int stp_lag_egress(int port) {
    int ae = aggregate(port), result = port;
    pthread_mutex_lock(&lag_lock);
    if (ae >= 0) {
        result = -1;
        for (int i = 0; i < 24; ++i) if (lags[ae].attached & (1U << i)) { result = i + 1; break; }
    }
    pthread_mutex_unlock(&lag_lock);
    return result;
}
int stp_lag_hardware_port(int port) {
    int ae = aggregate(port);
    pthread_mutex_lock(&lag_lock);
    int hardware = ae >= 0 ? lags[ae].hardware : port;
    pthread_mutex_unlock(&lag_lock);
    return hardware > 0 ? hardware : -1;
}
u32 stp_port_scope_mask(int port) {
    int ae = aggregate(port);
    pthread_mutex_lock(&lag_lock);
    u32 mask = ae >= 0 ? lags[ae].configured : port >= 1 && port <= 24 ? 1U << (port - 1) : 0;
    pthread_mutex_unlock(&lag_lock);
    return mask;
}
bool stp_port_paused(int port) { return (stp_port_scope_mask(port) & nl_port_scope_get().mask) != 0; }
time_t stp_port_now(int port, time_t now) {
    u32 mask = stp_port_scope_mask(port) & nl_port_scope_get().mask;
    for (int i = 0; i < 24; ++i) if (mask & (1U << i)) return nl_port_scope_now_monotonic(i + 1, now);
    return now;
}
