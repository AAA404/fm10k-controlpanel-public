#ifndef STPD_STP_WIRE_H
#define STPD_STP_WIRE_H

#include "netlab/types.h"
#include <stddef.h>

typedef enum {
    STP_ROLE_DISABLED = 0,
    STP_ROLE_DESIGNATED,
    STP_ROLE_ROOT,
    STP_ROLE_ALTERNATE,
} stp_role_id;

#define STP_MST_CONFIG_NAME_LEN 32
#define STP_MST_DIGEST_LEN 16
#define STP_MST_MAX_RECORDS 64

#define STP_RSTP_FLAG_TC        0x01
#define STP_RSTP_FLAG_PROPOSAL  0x02
#define STP_RSTP_FLAG_ROLE_MASK 0x0c
#define STP_RSTP_FLAG_LEARNING  0x10
#define STP_RSTP_FLAG_FORWARDING 0x20
#define STP_RSTP_FLAG_AGREEMENT 0x40
#define STP_RSTP_FLAG_TCA       0x80

typedef struct {
    int mstid;
    int flags;
    u8 regional_root_id[8];
    u32 internal_root_path_cost;
    int bridge_priority;
    int port_priority;
    int remaining_hops;
} stp_msti_record;

typedef struct {
    const u8 *payload;
    int payload_len;
    int version;
    int type;
    int flags;
    int port_id;
    bool has_timers;
    u16 message_age_ticks;
    u16 max_age_ticks;
    u16 hello_time_ticks;
    u16 forward_delay_ticks;
    bool has_priority_vector;
    u8 root_id[8];
    u32 root_path_cost;
    u8 bridge_id[8];
    bool has_mstp;
    int mst_v3_len;
    char mst_config_name[STP_MST_CONFIG_NAME_LEN + 1];
    u16 mst_revision;
    u8 mst_digest[STP_MST_DIGEST_LEN];
    u32 cist_internal_root_path_cost;
    u8 cist_bridge_id[8];
    int cist_remaining_hops;
    int msti_count;
    stp_msti_record msti[STP_MST_MAX_RECORDS];
} stp_bpdu_info;

u16 stp_get_be16(const u8 *buf, int off);
u32 stp_get_be32(const u8 *buf, int off);
void stp_build_bridge_id(u8 out[8], const u8 mac[6], int priority);
void stp_build_mst_bridge_id(u8 out[8], const u8 mac[6],
                             int priority, int mstid);
bool stp_bridge_id_equal(const u8 a[8], const u8 b[8]);
bool stp_bridge_id_is_zero(const u8 id[8]);
u16 stp_port_id(int port, int port_priority);
u16 stp_rstp_port_id(int port);
bool stp_is_bpdu_frame(const u8 *frame, int frame_len);
int stp_parse_bpdu_frame(const u8 *frame, int frame_len, stp_bpdu_info *info);
bool stp_bpdu_type_is_config(int version, int type);
const char *stp_bpdu_protocol_name(int version, int type);
stp_role_id stp_role_from_flags(int flags);
void stp_format_bridge_id(const u8 *id, char *out, size_t out_size);
int stp_mac_to_text(const u8 mac[6], char *out, size_t out_size);
int stp_build_rstp_frame(u8 *frame, int frame_max,
                         const u8 src_mac[6],
                         const u8 root_id[8],
                         u32 root_path_cost,
                         const u8 bridge_id[8],
                         int port,
                         int port_priority,
                         stp_role_id role,
                         int extra_flags,
                         int max_age_sec,
                         int hello_sec,
                         int forward_delay_sec);
int stp_build_mstp_frame(u8 *frame, int frame_max,
                         const u8 src_mac[6],
                         const u8 cist_root_id[8],
                         u32 cist_external_root_path_cost,
                         const u8 cist_regional_root_id[8],
                         const u8 cist_bridge_id[8],
                         int port,
                         int port_priority,
                         stp_role_id role,
                         int extra_flags,
                         int max_age_sec,
                         int hello_sec,
                         int forward_delay_sec,
                         const char *config_name,
                         u16 revision,
                         const u8 digest[STP_MST_DIGEST_LEN],
                         u32 cist_internal_root_path_cost,
                         int remaining_hops,
                         const stp_msti_record *records,
                         int record_count);

#endif
