#ifndef NETLAB_PFE_CAPABILITY_H
#define NETLAB_PFE_CAPABILITY_H

#include "types.h"

#define NETLAB_PFE_STATUS_JSON_BYTES 1024

typedef struct {
    bool sdk_initialized;
    bool switch_enabled;
    bool port_inventory_ok;
    bool port_programming_ok;
    bool vlan_programming_ok;
    bool pvid_programming_ok;
    bool vlan_mode_programming_ok;
    bool l3_interface_programming_ok;
    bool route_programming_ok;
    bool arp_programming_ok;
    bool ecmp_programming_ok;
    bool readback_verify_ok;
    bool packet_io_ok;
    bool platform_i2c_ok;
    bool counters_ok;
    bool transceiver_i2c_ok;
    bool hw_out_of_sync;
    char init_error[128];
} nl_pfe_capability;

void nl_pfe_cap_init(nl_pfe_capability *cap);
bool nl_pfe_can_l2_commit(nl_pfe_capability *cap);
bool nl_pfe_can_l3_commit(nl_pfe_capability *cap);
const char *nl_pfe_status_str(nl_pfe_capability *cap);

void sdk_pfe_capability_register(nl_pfe_capability *cap);
void nl_pfe_cap_set_field(nl_pfe_capability *cap, const char *field, bool val);
int  nl_pfe_cap_to_json(nl_pfe_capability *cap, char *buf, int buf_sz);

#endif
