#ifndef NETLAB_LACPD_LACP_CONFIG_H
#define NETLAB_LACPD_LACP_CONFIG_H

#include "netlab/types.h"

char *lacp_xml_leaf(const char *start, const char *end, const char *tag,
                    char *out, size_t out_size);
bool lacp_xml_attr(const char *start, const char *end, const char *attr,
                   char *out, size_t out_size);
bool lacp_xml_find_container(const char *xml, const char *tag,
                             char **body_start, char **body_end);

bool lacp_config_extract_aggregator(const char *start, const char *end,
                                    char *mode, size_t mode_size,
                                    char *min_links, size_t min_links_size,
                                    char *periodic, size_t periodic_size,
                                    u16 *actor_key);
u16 lacp_config_extract_member_port_priority(const char *start,
                                             const char *end);
void lacp_config_extract_global(const char *xml,
                                u16 *system_priority,
                                u16 *port_priority,
                                u8 actor_system[6]);
int lacp_config_parse_min_links(const char *text);

#endif
