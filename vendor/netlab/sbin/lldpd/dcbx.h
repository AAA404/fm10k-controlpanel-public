#ifndef NETLAB_LLDP_DCBX_H
#define NETLAB_LLDP_DCBX_H

#include "netlab/types.h"
#include <stddef.h>

#define DCBX_MAX_APPS 32
typedef struct { u8 priority, selector; u16 protocol; } dcbx_app;
typedef struct {
    bool enabled, malformed;
    bool pfc_present, ets_present, app_present, recommendation_present;
    bool pfc_willing, pfc_mbc, ets_willing, ets_cbs;
    u8 pfc_capability, pfc_mask, ets_capability;
    u8 priority_tc[8], bandwidth[8], tsa[8];
    u8 recommendation_priority_tc[8], recommendation_bandwidth[8], recommendation_tsa[8];
    int n_apps;
    dcbx_app apps[DCBX_MAX_APPS];
} dcbx_state;

/* IEEE 802.1Qaz OUI 00:80:c2, subtypes 9, 10, 11 and 12. No CEE fallback. */
int dcbx_append(u8 *buf, int size, int offset, const dcbx_state *local);
void dcbx_parse(const u8 *value, int size, dcbx_state *remote);
bool dcbx_load_xml(const char *start, const char *end, dcbx_state *local);
const char *dcbx_compare(const dcbx_state *local, const dcbx_state *remote);
int dcbx_format_xml(char *buf, size_t size, const char *tag, const dcbx_state *state);

#endif
