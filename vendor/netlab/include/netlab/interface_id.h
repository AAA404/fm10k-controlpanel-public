#ifndef NETLAB_INTERFACE_ID_H
#define NETLAB_INTERFACE_ID_H

#include "types.h"

#define NL_MAX_PORTS_PER_PROFILE 256
#define NL_MAX_SWITCHES_PER_PROFILE 16
#define NL_MAX_LANES_PER_PROFILE 1024
#define NL_MAX_XCVRS_PER_PROFILE 256
#define NL_PLATFORM_DEFAULT_PROFILE "config/platform/default.profile"

#define NL_PORT_FLAG_EXTERNAL       0x00000001u
#define NL_PORT_FLAG_TAGGED_TRUNK   0x00000002u
#define NL_PORT_FLAG_LLDP_DEFAULT   0x00000004u
#define NL_PORT_FLAG_RSTP_CAPABLE   0x00000008u
#define NL_PORT_FLAG_LACP_CAPABLE   0x00000010u
#define NL_PORT_FLAG_LLDP_CAPABLE   0x00000020u
#define NL_PORT_FLAG_HIDDEN         0x00000040u
#define NL_PORT_FLAG_CPU_CONTROL    0x00000080u

typedef struct {
    char model[64];
    char chassis_name[64];
    char serial[64];
    char system_name[64];
    char system_description[192];
    u8   system_mac[NL_MAC_ADDR_LEN];
    bool has_system_mac;
    int  max_ae;
    int  rstp_bridge_priority;
    int  rstp_hello_sec;
    int  rstp_bpdu_stale_sec;
    int  lacp_system_priority;
    int  lacp_port_priority;
    int  lacp_ttl_sec;
} nl_platform_identity;

typedef struct {
    bool configured;
    char model[64];
    char asic[32];
    int fci_count;
    int i2c_bus;
    int mux_addr;
    int cpld_ram_addr;
    int reset_gpio_addr;
    int fci_mux[2];
    int environment_mux;
    int power_mux;
    int shared_memory_bytes;
    int tcam_entries;
    int mac_nexthop_entries;
} nl_board_profile;

typedef struct {
    int     index;
    int     number;
    char    uio_dev[64];
    int     cpu_port;
    int     management_pep;
} nl_switch_entry;

typedef struct {
    u64     interface_id;
    char    canonical_name[64];
    char    media_type[8];
    char    role[16];
    char    interface_type[32];
    char    ethernet_mode[32];
    char    capabilities[128];
    u32     flags;
    int     fpc;
    int     pic;
    int     port;
    int     switch_id;
    int     switch_number;
    int     port_index;
    int     logical_port;
    int     front_panel_port;
    int     pcie_port;
    int     epl_port;
    int     lane;
    int     sdk_lane;
    int     hw_resource_id;
    u64     default_speed;
    u64     line_rate;
    u64     scheduler_speed;
    u64     supported_speeds[8];
    int     num_speeds;
    int     rstp_cost;
} nl_port_entry;

typedef struct {
    char    ifname[64];
    int     switch_id;
    int     port_index;
    int     logical_port;
    int     index;
    int     epl_port;
    int     pcie_port;
    int     sdk_lane;
    char    polarity[32];
} nl_lane_entry;

typedef struct {
    int     resource_id;
    char    type[32];
    char    i2c_bus[64];
    int     mux_index;
    int     mux_value;
    int     state_gpio_index;
    int     state_gpio_base;
} nl_xcvr_entry;

typedef struct {
    bool    configured;
    int     ipv4_uc_first;
    int     ipv4_uc_last;
    int     ipv4_mc_first;
    int     ipv4_mc_last;
    int     ipv6_uc_first;
    int     ipv6_uc_last;
    int     ipv6_mc_first;
    int     ipv6_mc_last;
    int     acl_first;
    int     acl_last;
    int     cvlan_first;
    int     cvlan_last;
    int     bst_routing_first;
    int     bst_routing_last;
} nl_ffu_slice_allocation;

// Resolver: canonical name ↔ interface_id
nl_status nl_ifid_resolver_init(const char *profile_path);
void      nl_ifid_resolver_destroy(void);

u64       nl_ifid_resolve(const char *canonical_name);
const char *nl_ifid_reverse(u64 interface_id);
int       nl_ifid_get_all(nl_port_entry *entries, int max);
bool      nl_ifid_get_by_name(const char *canonical_name, nl_port_entry *out);
bool      nl_ifid_get_by_logical_port(int logical_port, nl_port_entry *out);
int       nl_ifid_name_to_logical_port(const char *canonical_name);
bool      nl_ifid_logical_port_to_name(int logical_port,
                                       char *out, size_t out_size);
bool      nl_ifid_supports_tagged_trunk(const char *canonical_name);
bool      nl_ifid_lldp_default_enabled(int logical_port);
bool      nl_ifid_is_external(int logical_port);
bool      nl_ifid_is_cpu_port(int logical_port);
bool      nl_ifid_is_user_port(int logical_port);
bool      nl_ifid_name_is_user_port(const char *canonical_name);

bool      nl_platform_identity_get(nl_platform_identity *out);
bool      nl_platform_board_get(nl_board_profile *out);
int       nl_platform_get_switches(nl_switch_entry *entries, int max);
int       nl_platform_get_lanes(nl_lane_entry *entries, int max);
int       nl_platform_get_xcvrs(nl_xcvr_entry *entries, int max);
bool      nl_platform_ffu_slices(nl_ffu_slice_allocation *out);
int       nl_platform_max_ae(void);
bool      nl_platform_system_mac(u8 mac[NL_MAC_ADDR_LEN]);
bool      nl_platform_parse_mac(const char *text, u8 mac[NL_MAC_ADDR_LEN]);
const char *nl_platform_loaded_profile(void);

#endif
