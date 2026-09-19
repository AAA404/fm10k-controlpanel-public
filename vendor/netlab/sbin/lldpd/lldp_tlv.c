/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "lldp_tlv.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

bool lldp_neighbor_current(const lldp_neighbor *n, time_t now) {
    return n && n->valid && now > 0 && n->monotonic_seen > 0 && now >= n->monotonic_seen &&
           now - n->monotonic_seen < n->ttl;
}

int lldp_neighbor_store(lldp_neighbor table[64], int *count, const lldp_neighbor *nb,
                        time_t now, time_t wall) {
    if (!table || !count || *count < 0 || *count > 64 || !nb || !nb->valid ||
        nb->rx_port <= 0 || !nb->chassis_id_len || nb->chassis_id_len > 64 ||
        !nb->port_id_len || nb->port_id_len > 64 || now <= 0) return -1;
    int slot = -1;
    for (int i = 0; i < *count; i++) {
        const lldp_neighbor *old = &table[i];
        if (old->valid && old->rx_port == nb->rx_port && old->chassis_subtype == nb->chassis_subtype &&
            old->port_subtype == nb->port_subtype && old->chassis_id_len == nb->chassis_id_len &&
            old->port_id_len == nb->port_id_len && !memcmp(old->chassis_id,nb->chassis_id,nb->chassis_id_len) &&
            !memcmp(old->port_id,nb->port_id,nb->port_id_len)) { slot = i; break; }
    }
    if (slot < 0 && !nb->ttl) return -1;
    if (slot < 0) for (int i = 0; i < *count; i++)
        if (!lldp_neighbor_current(&table[i], now)) { slot = i; break; }
    if (slot < 0) { if (*count == 64) return -1; slot = (*count)++; }
    table[slot] = *nb;
    table[slot].valid = nb->ttl != 0;
    table[slot].last_seen = wall;
    table[slot].monotonic_seen = now;
    return slot;
}

int lldp_config_ttl(const lldp_config *cfg) {
    int interval = cfg && cfg->tx_interval > 0 ?
                   cfg->tx_interval : LLDP_DEFAULT_TX_INTERVAL;
    int hold = cfg && cfg->hold_multiplier > 0 ?
               cfg->hold_multiplier : LLDP_DEFAULT_HOLD_MULTIPLIER;
    int ttl = interval * hold;

    if (ttl > 65535)
        ttl = 65535;
    if (ttl < 1)
        ttl = 1;
    return ttl;
}

static int append_tlv(u8 *buf, int buf_max, int *off,
                      int type, const u8 *value, int len) {
    if (!buf || !off || len < 0 || len > 511 ||
        *off < 0 || *off + 2 + len > buf_max)
        return -1;
    buf[(*off)++] = (u8)(((type & 0x7F) << 1) | ((len >> 8) & 0x01));
    buf[(*off)++] = (u8)(len & 0xFF);
    if (len > 0 && value) {
        memcpy(buf + *off, value, (size_t)len);
        *off += len;
    }
    return 0;
}

static int append_management_address_tlv(u8 *buf, int buf_max, int *off,
                                         const lldp_config *cfg,
                                         int ifindex) {
    u8 value[1 + 1 + 16 + 1 + 4 + 1];
    int n = 0;
    u32 ifnum;

    if (!cfg || !cfg->mgmt_configured || cfg->mgmt_addr_len <= 0)
        return 0;
    if (cfg->mgmt_addr_len != 4 && cfg->mgmt_addr_len != 16)
        return -1;
    value[n++] = (u8)(cfg->mgmt_addr_len + 1);
    value[n++] = (u8)cfg->mgmt_subtype;
    memcpy(value + n, cfg->mgmt_addr, (size_t)cfg->mgmt_addr_len);
    n += cfg->mgmt_addr_len;
    value[n++] = 2; /* ifIndex */
    ifnum = htonl((u32)(ifindex > 0 ? ifindex : 0));
    memcpy(value + n, &ifnum, sizeof(ifnum));
    n += (int)sizeof(ifnum);
    value[n++] = 0; /* OID length */
    return append_tlv(buf, buf_max, off, 8, value, n);
}

int lldp_build_lldpdu(u8 *buf, int buf_max,
                      const u8 chassis_mac[6],
                      const char *port_id,
                      const lldp_config *cfg,
                      int ifindex) {
    int off = 0;
    u8 chassis[7];
    u8 port[65];
    u8 ttl[2];
    u8 caps[4];
    int port_len;
    int sys_len;
    int desc_len;
    int local_ttl;
    const char *sys_name;
    const char *sys_desc;

    if (!buf || !chassis_mac || !port_id || !cfg || buf_max <= 0)
        return -1;
    sys_name = cfg->system_name[0] ? cfg->system_name : "netlab";
    sys_desc = cfg->system_description[0] ?
               cfg->system_description : "NetLab switch";

    chassis[0] = 4;
    memcpy(chassis + 1, chassis_mac, 6);
    if (append_tlv(buf, buf_max, &off, 1, chassis, sizeof(chassis)) != 0)
        return -1;

    port_len = (int)strlen(port_id);
    if (port_len <= 0 || port_len > 64)
        return -1;
    port[0] = 5;
    memcpy(port + 1, port_id, (size_t)port_len);
    if (append_tlv(buf, buf_max, &off, 2, port, port_len + 1) != 0)
        return -1;

    local_ttl = lldp_config_ttl(cfg);
    ttl[0] = (u8)((local_ttl >> 8) & 0xff);
    ttl[1] = (u8)(local_ttl & 0xff);
    if (append_tlv(buf, buf_max, &off, 3, ttl, sizeof(ttl)) != 0)
        return -1;

    if (append_tlv(buf, buf_max, &off, 4, (const u8 *)port_id,
                   port_len) != 0)
        return -1;

    caps[0] = 0;
    caps[1] = 4;
    caps[2] = 0;
    caps[3] = 4;

    sys_len = (int)strlen(sys_name);
    if (sys_len < 0 || sys_len > 64)
        return -1;
    if (append_tlv(buf, buf_max, &off, 5, (const u8 *)sys_name,
                   sys_len) != 0)
        return -1;

    desc_len = (int)strlen(sys_desc);
    if (desc_len < 0 || desc_len > 191)
        return -1;
    if (desc_len > 0 &&
        append_tlv(buf, buf_max, &off, 6, (const u8 *)sys_desc,
                   desc_len) != 0)
        return -1;

    if (append_tlv(buf, buf_max, &off, 7, caps, sizeof(caps)) != 0)
        return -1;

    if (append_management_address_tlv(buf, buf_max, &off, cfg,
                                      ifindex) != 0)
        return -1;

    off = dcbx_append(buf, buf_max, off, &cfg->dcbx);
    if (off < 0 || append_tlv(buf, buf_max, &off, 0, NULL, 0) != 0)
        return -1;

    return off;
}

static void parse_mgmt_tlv(const u8 *data, int len,
                           char *out, size_t out_size) {
    int mgmt_len;
    int subtype;
    char addr[INET6_ADDRSTRLEN];

    if (!data || len < 2 || !out || out_size == 0)
        return;
    out[0] = '\0';
    mgmt_len = data[0];
    if (mgmt_len < 2 || 1 + mgmt_len > len)
        return;
    subtype = data[1];
    if (subtype == 1 && mgmt_len == 5) {
        if (inet_ntop(AF_INET, data + 2, addr, sizeof(addr)))
            snprintf(out, out_size, "%s", addr);
    } else if (subtype == 2 && mgmt_len == 17) {
        if (inet_ntop(AF_INET6, data + 2, addr, sizeof(addr)))
            snprintf(out, out_size, "%s", addr);
    }
}

void lldp_parse_lldpdu(const u8 *data, int len, lldp_neighbor *nb,
                       int rx_port) {
    int pos = 0;
    int mandatory = 1;

    if (!nb)
        return;
    memset(nb, 0, sizeof(*nb));
    nb->rx_port = rx_port;
    if (!data || len <= 0)
        return;

    while (pos + 2 <= len) {
        int type = (data[pos] >> 1) & 0x7F;
        int tlv_len = ((data[pos] & 0x01) << 8) | data[pos + 1];
        pos += 2;
        if (pos + tlv_len > len) return;
        if (type == 0) {
            nb->valid = tlv_len == 0 && mandatory == 4;
            return;
        }
        if (mandatory <= 3) {
            if (type != mandatory) return;
            mandatory++;
        } else if (type >= 1 && type <= 3) return;
        if ((type == 1 || type == 2) && (tlv_len < 2 || tlv_len > 65 || data[pos] < 1 || data[pos] > 7)) return;
        if (type == 3 && tlv_len != 2) return;
        if (tlv_len <= 0) {
            pos += tlv_len;
            continue;
        }

        switch (type) {
        case 1: /* Chassis ID */
            if (tlv_len > 1) {
                if (tlv_len - 1 > (int)sizeof(nb->chassis_id))
                    break;
                nb->chassis_subtype = data[pos];
                nb->chassis_id_len = (u8)(tlv_len - 1);
                memcpy(nb->chassis_id, data + pos + 1, nb->chassis_id_len);
            }
            break;
        case 2: /* Port ID */
            if (tlv_len > 1) {
                if (tlv_len - 1 > (int)sizeof(nb->port_id))
                    break;
                nb->port_subtype = data[pos];
                nb->port_id_len = (u8)(tlv_len - 1);
                memcpy(nb->port_id, data + pos + 1, nb->port_id_len);
            }
            break;
        case 3: /* TTL */
            if (tlv_len == 2)
                nb->ttl = (u16)(((u16)data[pos] << 8) | data[pos + 1]);
            break;
        case 4: /* Port Description */
            nb->port_desc_len = (u8)(tlv_len > (int)sizeof(nb->port_desc) ?
                                     (int)sizeof(nb->port_desc) : tlv_len);
            memcpy(nb->port_desc, data + pos, nb->port_desc_len);
            break;
        case 5: /* System Name */
            if (tlv_len > (int)sizeof(nb->sys_name))
                break;
            nb->sys_name_len = (u8)tlv_len;
            memcpy(nb->sys_name, data + pos, nb->sys_name_len);
            break;
        case 6: /* System Description */
            nb->sys_desc_len = (u8)(tlv_len > (int)sizeof(nb->sys_desc) ?
                                    (int)sizeof(nb->sys_desc) : tlv_len);
            memcpy(nb->sys_desc, data + pos, nb->sys_desc_len);
            break;
        case 7: /* System Capabilities */
            if (tlv_len == 4) {
                nb->caps_supported = (u16)(((u16)data[pos] << 8) |
                                           data[pos + 1]);
                nb->caps_enabled = (u16)(((u16)data[pos + 2] << 8) |
                                         data[pos + 3]);
            }
            break;
        case 8: /* Management Address */
            parse_mgmt_tlv(data + pos, tlv_len, nb->mgmt_addr,
                           sizeof(nb->mgmt_addr));
            break;
        case 127:
            dcbx_parse(data + pos, tlv_len, &nb->dcbx);
            break;
        default:
            break;
        }
        pos += tlv_len;
    }
}
