#ifndef RPD_FRR_CONFIG_H
#define RPD_FRR_CONFIG_H

#include "netlab/types.h"
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define RPD_FRR_CONFIG_MAX 65536
#define RPD_FRR_MAX_BGP_GROUPS 32
#define RPD_FRR_MAX_BGP_NEIGHBORS 64
#define RPD_FRR_MAX_POLICY_TERMS 64
#define RPD_FRR_MAX_RIFS 256
#define RPD_FRR_MAX_LOCAL_ROUTES 256
#define RPD_FRR_MAX_OSPF_AREAS 32
#define RPD_FRR_MAX_OSPF_INTERFACES 128

typedef struct {
    char name[64];
} rpd_frr_rif;

typedef struct {
    char name[64];
    char area[32];
    char linux_ifname[64];
} rpd_frr_ospf_interface;

typedef struct {
    char name[64];
    char type[16];
    char export_policy[64];
    bool hold_time_set;
    u32 hold_time;
} rpd_frr_bgp_group;

typedef struct {
    char group[64];
    char address[64];
    char peer_as[32];
} rpd_frr_bgp_neighbor;

typedef struct {
    char policy[64];
    char term[64];
    char prefix[64];
    char action[16];
} rpd_frr_policy_term;

typedef struct {
    char prefix[64];
    char protocol[16];
} rpd_frr_local_route;

typedef struct {
    bool ospf_enabled;
    bool bgp_enabled;
    bool bgp_local_as_set;
    int ospf_areas;
    int ospf_interfaces;
    int ospf_ifname_maps;
    int routed_interfaces;
    int bgp_groups;
    int bgp_neighbors;
    int bgp_exports;
    int bgp_networks;
    int policies;
    int policy_terms;
    int config_lines;
    bool fpm_enabled;
    u32 fpm_port;
    u32 bgp_local_as;
    u32 config_hash;
    u64 generation;
    time_t last_update;
    char status[32];
    char reason[160];
    char fpm_address[64];
    char config[RPD_FRR_CONFIG_MAX];
    rpd_frr_bgp_group bgp_group_state[RPD_FRR_MAX_BGP_GROUPS];
    int n_bgp_group_state;
    rpd_frr_bgp_neighbor bgp_neighbor_state[RPD_FRR_MAX_BGP_NEIGHBORS];
    int n_bgp_neighbor_state;
    rpd_frr_policy_term policy_term_state[RPD_FRR_MAX_POLICY_TERMS];
    int n_policy_term_state;
    rpd_frr_rif rif_state[RPD_FRR_MAX_RIFS];
    int n_rif_state;
    rpd_frr_local_route local_route_state[RPD_FRR_MAX_LOCAL_ROUTES];
    int n_local_route_state;
    rpd_frr_ospf_interface ospf_interface_state[
        RPD_FRR_MAX_OSPF_INTERFACES];
    int n_ospf_interface_state;
} rpd_frr_config;

void rpd_frr_config_init(rpd_frr_config *cfg);
int rpd_frr_config_compile_plan(rpd_frr_config *cfg, const char *payload,
                                int payload_len, u64 generation,
                                char *err, size_t err_size);
int rpd_frr_config_validate_plan(const char *payload, int payload_len,
                                 char *err, size_t err_size);
int rpd_frr_config_append_xml(const rpd_frr_config *cfg, char *buf,
                              size_t buf_size, size_t *off);

#endif
