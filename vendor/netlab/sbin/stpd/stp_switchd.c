#include "stp_switchd.h"
#include "netlab/ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int switchd_call_timeout(const char *socket_path, nl_rpc_method method,
                                const u8 *payload, int payload_len,
                                u8 *resp, int resp_max, int timeout_ms,
                                s32 *ec_out) {
    s32 ec = 0;
    u8 scratch[64];
    int rn;

    if (!socket_path)
        return -1;
    if (!resp || resp_max <= 0) {
        resp = scratch;
        resp_max = (int)sizeof(scratch);
    }

    rn = nl_rpc_call_ex(socket_path, NL_DAEMON_STPD, NL_DAEMON_SWITCHD,
                        method, 0,
                        payload, payload_len, resp, resp_max,
                        timeout_ms, &ec);
    if (ec_out)
        *ec_out = ec;
    if (rn < 0 || ec != 0)
        return -1;
    return rn;
}

static int switchd_call(const char *socket_path, nl_rpc_method method,
                        const u8 *payload, int payload_len,
                        u8 *resp, int resp_max, s32 *ec_out) {
    return switchd_call_timeout(socket_path, method, payload, payload_len,
                                resp, resp_max, 5000, ec_out);
}

bool stp_switchd_port_link_up(const char *socket_path, int port) {
    char payload[32];
    u8 resp[128];
    int n;
    int rn;

    if (port <= 0)
        return false;

    n = snprintf(payload, sizeof(payload), "port=%d", port);
    if (n <= 0 || n >= (int)sizeof(payload))
        return false;

    rn = switchd_call(socket_path, NL_SWITCHD_PORT_GET_STATE,
                      (const u8 *)payload, n,
                      resp, sizeof(resp) - 1, NULL);
    if (rn <= 0)
        return false;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    return strstr((char *)resp, "link=UP") != NULL;
}

int stp_switchd_collect_hardware_port_vlans(const char *socket_path,
                                            int port, int *vlans,
                                            int max_vlans) {
    nl_stp_snapshot snapshot = {0};
    int n = 0;

    if (!vlans || max_vlans <= 0 || port <= 0)
        return -1;
    if (stp_switchd_get_stp_snapshot(socket_path, &snapshot) != 0)
        return -1;
    for (u32 i = 0; i < snapshot.n_entries; i++) {
        if (snapshot.entries[i].port != port)
            continue;
        if (n >= max_vlans) {
            nl_stp_snapshot_reset(&snapshot);
            return -1;
        }
        vlans[n++] = snapshot.entries[i].vlan;
    }
    nl_stp_snapshot_reset(&snapshot);
    return n;
}

int stp_switchd_get_stp_snapshot(const char *socket_path,
                                 nl_stp_snapshot *snapshot) {
    return nl_stp_snapshot_fetch(socket_path, NL_DAEMON_STPD, 10000,
                                 snapshot);
}

int stp_switchd_set_port_stp_state(const char *socket_path, int port,
                                   int vid, int state) {
    char payload[64];
    char resp[64];
    s32 ec = 0;
    int n;
    int rn;

    n = snprintf(payload, sizeof(payload), "vid=%d port=%d state=%d",
                 vid, port, state);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_STP_RUNTIME_SET,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp), &ec);
    if (rn < 0 || ec != 0)
        return ec != 0 ? ec : -1;
    return 0;
}

int stp_switchd_clear_dynamic_macs(const char *socket_path, int port,
                                   int vid) {
    char payload[64];
    u8 resp[64];
    s32 ec = 0;
    int n;
    int rn;

    if (port < 0 || vid < 0 || vid > 4094)
        return -1;

    n = snprintf(payload, sizeof(payload), "port=%d vid=%d", port, vid);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_DYNAMIC_MAC_CLEAR,
                      (const u8 *)payload, n,
                      resp, sizeof(resp), &ec);
    if (rn < 0 || ec != 0)
        return ec != 0 ? ec : -1;
    return 0;
}

int stp_switchd_get_mac_snapshot(const char *socket_path,
                                 nl_mac_snapshot *snapshot) {
    u8 *resp;
    s32 ec = 0;
    int rn;

    if (!snapshot)
        return -1;
    resp = malloc(NETLAB_MAX_MSG);
    if (!resp)
        return -1;
    rn = switchd_call_timeout(socket_path, NL_SWITCHD_MAC_SNAPSHOT_GET,
                              (const u8 *)"", 0,
                              resp, NETLAB_MAX_MSG, 3000, &ec);
    if (rn <= 0 || ec != 0 ||
        nl_mac_snapshot_decode(resp, (size_t)rn, snapshot) != 0 ||
        !snapshot->complete) {
        free(resp);
        nl_mac_snapshot_reset(snapshot);
        return -1;
    }
    free(resp);
    return 0;
}
