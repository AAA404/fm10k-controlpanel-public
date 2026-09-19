#include "stp_wire.h"

#include <stdio.h>
#include <string.h>

static void put_be16(u8 *buf, int off, u16 value) {
    buf[off] = (u8)((value >> 8) & 0xff);
    buf[off + 1] = (u8)(value & 0xff);
}

u16 stp_get_be16(const u8 *buf, int off) {
    return (u16)(((u16)buf[off] << 8) | buf[off + 1]);
}

static void put_be32(u8 *buf, int off, u32 value) {
    buf[off] = (u8)((value >> 24) & 0xff);
    buf[off + 1] = (u8)((value >> 16) & 0xff);
    buf[off + 2] = (u8)((value >> 8) & 0xff);
    buf[off + 3] = (u8)(value & 0xff);
}

u32 stp_get_be32(const u8 *buf, int off) {
    return ((u32)buf[off] << 24) |
           ((u32)buf[off + 1] << 16) |
           ((u32)buf[off + 2] << 8) |
           (u32)buf[off + 3];
}

void stp_build_bridge_id(u8 out[8], const u8 mac[6], int priority) {
    put_be16(out, 0, (u16)priority);
    memcpy(out + 2, mac, 6);
}

void stp_build_mst_bridge_id(u8 out[8], const u8 mac[6],
                             int priority, int mstid) {
    u16 id;

    if (!out || !mac)
        return;
    if (mstid < 0)
        mstid = 0;
    if (mstid > 4095)
        mstid = 4095;
    id = (u16)((priority & 0xf000) | (mstid & 0x0fff));
    put_be16(out, 0, id);
    memcpy(out + 2, mac, 6);
}

bool stp_bridge_id_equal(const u8 a[8], const u8 b[8]) {
    return memcmp(a, b, 8) == 0;
}

bool stp_bridge_id_is_zero(const u8 id[8]) {
    static const u8 zero[8] = {0};
    return memcmp(id, zero, sizeof(zero)) == 0;
}

u16 stp_port_id(int port, int port_priority) {
    if (port_priority < 0 || port_priority > 240 ||
        (port_priority % 16) != 0)
        port_priority = 0x80;
    return (u16)(((port_priority & 0xf0) << 8) | (port & 0x0fff));
}

u16 stp_rstp_port_id(int port) {
    return stp_port_id(port, 0x80);
}

static u8 rstp_flags_for_role(stp_role_id role) {
    switch (role) {
    case STP_ROLE_ROOT:
        return 0x08 | STP_RSTP_FLAG_LEARNING | STP_RSTP_FLAG_FORWARDING;
    case STP_ROLE_DESIGNATED:
        return 0x0c | STP_RSTP_FLAG_LEARNING | STP_RSTP_FLAG_FORWARDING;
    case STP_ROLE_ALTERNATE:
        return 0x04;
    default:
        return 0x00;
    }
}

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
                         int forward_delay_sec) {
    static const u8 dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    u8 bpdu[36];
    int frame_len;
    u16 port_id = stp_port_id(port, port_priority);

    if (!frame || !src_mac || !root_id || !bridge_id ||
        frame_max < 60 || port <= 0)
        return -1;

    memset(frame, 0, (size_t)frame_max);
    memset(bpdu, 0, sizeof(bpdu));

    put_be16(bpdu, 0, 0x0000);
    bpdu[2] = 0x02;
    bpdu[3] = 0x02;
    bpdu[4] = (u8)(rstp_flags_for_role(role) |
                   (extra_flags & (STP_RSTP_FLAG_TC |
                                   STP_RSTP_FLAG_PROPOSAL |
                                   STP_RSTP_FLAG_AGREEMENT |
                                   STP_RSTP_FLAG_TCA)));
    memcpy(bpdu + 5, root_id, 8);
    put_be32(bpdu, 13, root_path_cost);
    memcpy(bpdu + 17, bridge_id, 8);
    put_be16(bpdu, 25, port_id);
    put_be16(bpdu, 27, 0);
    put_be16(bpdu, 29, (u16)(max_age_sec * 256));
    put_be16(bpdu, 31, (u16)(hello_sec * 256));
    put_be16(bpdu, 33, (u16)(forward_delay_sec * 256));
    bpdu[35] = 0;

    memcpy(frame, dst, 6);
    memcpy(frame + 6, src_mac, 6);
    put_be16(frame, 12, (u16)(3 + sizeof(bpdu)));
    frame[14] = 0x42;
    frame[15] = 0x42;
    frame[16] = 0x03;
    memcpy(frame + 17, bpdu, sizeof(bpdu));

    frame_len = 17 + (int)sizeof(bpdu);
    return frame_len < 60 ? 60 : frame_len;
}

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
                         int record_count) {
    static const u8 dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    u8 bpdu[1500];
    int bpdu_len;
    int frame_len;
    int v3_len;
    u16 port_id = stp_port_id(port, port_priority);

    if (!frame || !src_mac || !cist_root_id || !cist_regional_root_id ||
        !cist_bridge_id || !digest || frame_max < 60 || port <= 0)
        return -1;
    if (record_count < 0)
        return -1;
    if (record_count > STP_MST_MAX_RECORDS)
        return -1;
    if (record_count > 0 && !records)
        return -1;

    bpdu_len = 102 + (record_count * 16);
    frame_len = 17 + bpdu_len;
    if (bpdu_len > (int)sizeof(bpdu) || frame_max < frame_len)
        return -1;
    v3_len = 64 + (record_count * 16);

    memset(frame, 0, (size_t)frame_max);
    memset(bpdu, 0, sizeof(bpdu));

    put_be16(bpdu, 0, 0x0000);
    bpdu[2] = 0x03;
    bpdu[3] = 0x02;
    bpdu[4] = (u8)(rstp_flags_for_role(role) |
                   (extra_flags & (STP_RSTP_FLAG_TC |
                                   STP_RSTP_FLAG_PROPOSAL |
                                   STP_RSTP_FLAG_AGREEMENT |
                                   STP_RSTP_FLAG_TCA)));
    memcpy(bpdu + 5, cist_root_id, 8);
    put_be32(bpdu, 13, cist_external_root_path_cost);
    memcpy(bpdu + 17, cist_regional_root_id, 8);
    put_be16(bpdu, 25, port_id);
    put_be16(bpdu, 27, 0);
    put_be16(bpdu, 29, (u16)(max_age_sec * 256));
    put_be16(bpdu, 31, (u16)(hello_sec * 256));
    put_be16(bpdu, 33, (u16)(forward_delay_sec * 256));
    bpdu[35] = 0;
    put_be16(bpdu, 36, (u16)v3_len);
    bpdu[38] = 0;
    if (config_name && config_name[0]) {
        size_t name_len = strlen(config_name);
        if (name_len > STP_MST_CONFIG_NAME_LEN)
            name_len = STP_MST_CONFIG_NAME_LEN;
        memcpy(bpdu + 39, config_name, name_len);
    }
    put_be16(bpdu, 71, revision);
    memcpy(bpdu + 73, digest, STP_MST_DIGEST_LEN);
    put_be32(bpdu, 89, cist_internal_root_path_cost);
    memcpy(bpdu + 93, cist_bridge_id, 8);
    bpdu[101] = (u8)(remaining_hops < 0 ? 0 :
                     remaining_hops > 255 ? 255 : remaining_hops);

    for (int i = 0; i < record_count; i++) {
        const stp_msti_record *rec = &records[i];
        int off = 102 + (i * 16);

        bpdu[off] = (u8)(rec->flags & 0xff);
        memcpy(bpdu + off + 1, rec->regional_root_id, 8);
        put_be32(bpdu, off + 9, rec->internal_root_path_cost);
        bpdu[off + 13] = (u8)(rec->bridge_priority & 0xff);
        bpdu[off + 14] = (u8)(rec->port_priority & 0xff);
        bpdu[off + 15] = (u8)(rec->remaining_hops < 0 ? 0 :
                              rec->remaining_hops > 255 ? 255 :
                              rec->remaining_hops);
    }

    memcpy(frame, dst, 6);
    memcpy(frame + 6, src_mac, 6);
    put_be16(frame, 12, (u16)(3 + bpdu_len));
    frame[14] = 0x42;
    frame[15] = 0x42;
    frame[16] = 0x03;
    memcpy(frame + 17, bpdu, (size_t)bpdu_len);

    return frame_len < 60 ? 60 : frame_len;
}

bool stp_is_bpdu_frame(const u8 *frame, int frame_len) {
    static const u8 bpdu_dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    u16 len_type;

    if (!frame || frame_len < 18)
        return false;
    if (memcmp(frame, bpdu_dst, sizeof(bpdu_dst)) != 0)
        return false;
    len_type = (u16)(((u16)frame[12] << 8) | frame[13]);
    if (len_type > 1500)
        return false;
    return frame[14] == 0x42 && frame[15] == 0x42 && frame[16] == 0x03;
}

static int parse_mstp_extension(const u8 *bpdu, int bpdu_len,
                                stp_bpdu_info *info) {
    int v3_len;
    int record_count;
    int stored_count;

    if (!bpdu || !info || info->version != 3 || info->type != 0x02)
        return 0;
    if (bpdu_len < 102)
        return -1;

    v3_len = stp_get_be16(bpdu, 36);
    if (v3_len < 64 || ((v3_len - 64) % 16) != 0)
        return -1;
    if (38 + v3_len > bpdu_len)
        return -1;

    record_count = (v3_len - 64) / 16;
    stored_count = record_count;
    if (stored_count > STP_MST_MAX_RECORDS)
        stored_count = STP_MST_MAX_RECORDS;

    info->has_mstp = true;
    info->mst_v3_len = v3_len;
    memcpy(info->mst_config_name, bpdu + 39, STP_MST_CONFIG_NAME_LEN);
    info->mst_config_name[STP_MST_CONFIG_NAME_LEN] = '\0';
    info->mst_revision = stp_get_be16(bpdu, 71);
    memcpy(info->mst_digest, bpdu + 73, STP_MST_DIGEST_LEN);
    info->cist_internal_root_path_cost = stp_get_be32(bpdu, 89);
    memcpy(info->cist_bridge_id, bpdu + 93, sizeof(info->cist_bridge_id));
    info->cist_remaining_hops = bpdu[101];
    info->msti_count = stored_count;

    for (int i = 0; i < stored_count; i++) {
        const u8 *rec = bpdu + 102 + (i * 16);

        info->msti[i].flags = rec[0];
        memcpy(info->msti[i].regional_root_id, rec + 1, 8);
        info->msti[i].mstid = stp_get_be16(rec, 1) & 0x0fff;
        info->msti[i].internal_root_path_cost = stp_get_be32(rec, 9);
        info->msti[i].bridge_priority = rec[13];
        info->msti[i].port_priority = rec[14];
        info->msti[i].remaining_hops = rec[15];
    }
    return 0;
}

int stp_parse_bpdu_frame(const u8 *frame, int frame_len, stp_bpdu_info *info) {
    const u8 *bpdu;
    int bpdu_len;

    if (!info)
        return -1;
    memset(info, 0, sizeof(*info));

    if (!stp_is_bpdu_frame(frame, frame_len))
        return -1;

    bpdu = frame + 17;
    bpdu_len = frame_len - 17;
    if (bpdu_len < 4 || bpdu[0] != 0 || bpdu[1] != 0)
        return -1;

    info->payload = bpdu;
    info->payload_len = bpdu_len;
    info->version = bpdu[2];
    info->type = bpdu[3];
    if (bpdu_len > 4)
        info->flags = bpdu[4];
    if (bpdu_len >= 27)
        info->port_id = stp_get_be16(bpdu, 25);
    if (bpdu_len >= 35) {
        info->has_timers = true;
        info->message_age_ticks = stp_get_be16(bpdu, 27);
        info->max_age_ticks = stp_get_be16(bpdu, 29);
        info->hello_time_ticks = stp_get_be16(bpdu, 31);
        info->forward_delay_ticks = stp_get_be16(bpdu, 33);
    }
    if (bpdu_len >= 25) {
        memcpy(info->root_id, bpdu + 5, sizeof(info->root_id));
        info->root_path_cost = stp_get_be32(bpdu, 13);
        memcpy(info->bridge_id, bpdu + 17, sizeof(info->bridge_id));
        info->has_priority_vector = true;
    }
    if (parse_mstp_extension(bpdu, bpdu_len, info) != 0)
        return -1;
    return 0;
}

bool stp_bpdu_type_is_config(int version, int type) {
    return (version == 0 && type == 0x00) ||
           (version == 2 && type == 0x02) ||
           (version == 3 && type == 0x02);
}

const char *stp_bpdu_protocol_name(int version, int type) {
    if (type == 0x80)
        return "tcn";
    if (version == 0 && type == 0x00)
        return "stp";
    if (version == 2 && type == 0x02)
        return "rstp";
    if (version == 3 && type == 0x02)
        return "mstp";
    return "unknown";
}

stp_role_id stp_role_from_flags(int flags) {
    switch (flags & STP_RSTP_FLAG_ROLE_MASK) {
    case 0x0c:
        return STP_ROLE_DESIGNATED;
    case 0x08:
        return STP_ROLE_ROOT;
    case 0x04:
        return STP_ROLE_ALTERNATE;
    default:
        return STP_ROLE_DISABLED;
    }
}

void stp_format_bridge_id(const u8 *id, char *out, size_t out_size) {
    u16 prio;

    if (!id || !out || out_size == 0)
        return;
    prio = (u16)(((u16)id[0] << 8) | id[1]);
    snprintf(out, out_size, "%04x.%02x:%02x:%02x:%02x:%02x:%02x",
             prio, id[2], id[3], id[4], id[5], id[6], id[7]);
}

int stp_mac_to_text(const u8 mac[6], char *out, size_t out_size) {
    if (!mac || !out || out_size == 0)
        return -1;
    return snprintf(out, out_size, "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]) > 0 ?
           0 : -1;
}
