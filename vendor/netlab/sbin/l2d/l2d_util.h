#ifndef L2D_UTIL_H
#define L2D_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include "netlab/stp_snapshot.h"

int l2d_max_ae(void);
int l2d_ae_id_from_name(const char *ifname);
bool l2d_stp_has_member(const nl_stp_snapshot *snapshot, int vid, int port);
bool l2d_xml_attr_value(const char *start, const char *end,
                        const char *attr, char *out, size_t out_size);
int l2d_extract_xml_leaf(const char *start, const char *end,
                         const char *leaf, char *out, size_t out_size);
bool l2d_mac_entry_visible(const char *mac, const char *type,
                           const char *ifname);

#endif
