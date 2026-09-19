/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef LLDPPD_LLDP_TLV_H
#define LLDPPD_LLDP_TLV_H

#include "netlab/types.h"
#include "dcbx.h"
#include <time.h>

#define LLDP_DEFAULT_TX_INTERVAL 30
#define LLDP_DEFAULT_HOLD_MULTIPLIER 4

typedef struct {
    bool disabled;
    int tx_interval;
    int hold_multiplier;
    char system_name[64];
    char system_description[192];
    bool mgmt_configured;
    int mgmt_subtype;
    u8 mgmt_addr[16];
    int mgmt_addr_len;
    char mgmt_addr_text[64];
    dcbx_state dcbx;
} lldp_config;

typedef struct {
    u8   chassis_id[64];   u8 chassis_id_len;
    u8   chassis_subtype;
    u8   port_id[64];      u8 port_id_len;
    u8   port_subtype;
    u8   port_desc[128];   u8 port_desc_len;
    u8   sys_name[64];     u8 sys_name_len;
    u8   sys_desc[192];    u8 sys_desc_len;
    u16  ttl;
    u16  caps_supported;
    u16  caps_enabled;
    char mgmt_addr[64];
    time_t last_seen;
    time_t monotonic_seen;
    int   rx_port;
    bool  valid;
    dcbx_state dcbx;
} lldp_neighbor;

int lldp_config_ttl(const lldp_config *cfg);
int lldp_build_lldpdu(u8 *buf, int buf_max,
                      const u8 chassis_mac[6],
                      const char *port_id,
                      const lldp_config *cfg,
                      int ifindex);
void lldp_parse_lldpdu(const u8 *data, int len, lldp_neighbor *nb,
                       int rx_port);
bool lldp_neighbor_current(const lldp_neighbor *neighbor, time_t monotonic_now);
int lldp_neighbor_store(lldp_neighbor table[64], int *count, const lldp_neighbor *received,
                        time_t monotonic_now, time_t wall_now);

#endif
