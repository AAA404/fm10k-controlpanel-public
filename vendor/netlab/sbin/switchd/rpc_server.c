/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/packet_event.h"
#include "netlab/port_scope.h"
#include "netlab/log.h"
#include "fm10k_board_runtime.h"
#include "fm10k_startup.h"
#include "fm10k_phy.h"
#include "sdk_runtime_scope.h"
#include "netlab/hal.h"
#include "netlab/error.h"
#include "netlab/interface_id.h"
#include "netlab/lag_readback.h"
#include "hal_sdk_runtime.h"
#include "rpc_format.h"
#include "rpc_response.h"
#include "sflow_capture.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_port.h>
#include <api/fm_api_lag.h>
#include <api/fm_api_storm.h>

#define SWITCHD_LAG_XML_BUFFER_SIZE (128 * 1024)

static pthread_mutex_t g_board_env_rpc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_stp_snapshot_rpc_lock = PTHREAD_MUTEX_INITIALIZER;
static nl_stp_snapshot g_stp_snapshot_rpc_cache;
static u64 g_stp_snapshot_invalidation_generation;

static void hal_rpc_dispatch_inner(struct sdk_context *ctx, nl_conn *conn,
                                   nl_msg_hdr *msg);

static u64 monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec * 1000ULL + (u64)now.tv_nsec / 1000000ULL;
}

static const char *port_link_state_name(int state) {
    switch (state) {
    case 0:
        return "up";
    case 1:
    case 2:
    case 4:
    case 5:
    case 7:
        return "down";
    default:
        return "unknown";
    }
}

static bool l2_transaction_scoped_mutator(nl_rpc_method method) {
    switch (method) {
        case NL_SWITCHD_FM10K_FAN_MANUAL:
        case NL_SWITCHD_PORT_SET_ADMIN:
        case NL_SWITCHD_VLAN_CREATE:
        case NL_SWITCHD_VLAN_DELETE:
        case NL_SWITCHD_VLAN_ADD_PORT:
        case NL_SWITCHD_PVID_SET:
        case NL_SWITCHD_PORT_MODE_SET:
        case NL_SWITCHD_L2_PLAN_APPLY:
        case NL_SWITCHD_STP_RUNTIME_SET:
        case NL_SWITCHD_PORT_ADMIN_OVERRIDE:
        case NL_SWITCHD_PORT_SECURITY_ACTION:
        case NL_SWITCHD_LAG_ADD_PORT:
        case NL_SWITCHD_LAG_DEL_PORT:
        case NL_SWITCHD_ACL_POLICER_PROBE:
        case NL_SWITCHD_L3_SDK_WRITE_CANARY:
        case NL_SWITCHD_L3_RIF_LIVE_PROBE:
        case NL_SWITCHD_L3_ARP_LIVE_PROBE:
        case NL_SWITCHD_L3_ECMP_LIVE_PROBE:
        case NL_SWITCHD_L3_ROUTE_LIVE_PROBE:
        case NL_SWITCHD_QOS_QUEUE_PROBE:
        case NL_SWITCHD_QOS_QUEUE_OWNER_APPLY:
        case NL_SWITCHD_QOS_QUEUE_OWNER_ROLLBACK:
        case NL_SWITCHD_ACL_POLICER_OWNER_APPLY:
        case NL_SWITCHD_ACL_POLICER_OWNER_ROLLBACK:
        case NL_SWITCHD_ACL_EGRESS_PROBE:
        case NL_SWITCHD_ACL_GENERAL_ALLOCATOR_APPLY:
        case NL_SWITCHD_ACL_GENERAL_ALLOCATOR_ROLLBACK:
        case NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY:
        case NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_ROLLBACK:
        case NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY:
        case NL_SWITCHD_QOS_WATERMARK_OWNER_ROLLBACK:
        case NL_SWITCHD_SFLOW_LIVE_PROBE:
            return true;
        default:
            return false;
    }
}

static bool stp_snapshot_invalidating_mutator(nl_rpc_method method) {
    switch (method) {
        case NL_SWITCHD_VLAN_CREATE:
        case NL_SWITCHD_VLAN_DELETE:
        case NL_SWITCHD_VLAN_ADD_PORT:
        case NL_SWITCHD_PORT_MODE_SET:
        case NL_SWITCHD_L2_PLAN_APPLY:
        case NL_SWITCHD_L2_PLAN_ROLLBACK:
        case NL_SWITCHD_STP_RUNTIME_SET:
        case NL_SWITCHD_LAG_ADD_PORT:
        case NL_SWITCHD_LAG_DEL_PORT:
            return true;
        default:
            return false;
    }
}

static void stp_snapshot_rpc_cache_invalidate(void) {
    pthread_mutex_lock(&g_stp_snapshot_rpc_lock);
    nl_stp_snapshot_reset(&g_stp_snapshot_rpc_cache);
    g_stp_snapshot_invalidation_generation++;
    if (g_stp_snapshot_invalidation_generation == 0)
        g_stp_snapshot_invalidation_generation++;
    pthread_mutex_unlock(&g_stp_snapshot_rpc_lock);
}

void hal_rpc_dispatch(struct sdk_context *ctx, nl_conn *conn,
                      nl_msg_hdr *msg) {
    bool mutation_lease = false;
    bool invalidates_stp = msg &&
        stp_snapshot_invalidating_mutator(msg->method);
    int status;

    if (ctx && ctx->hw_tracker && msg &&
        l2_transaction_scoped_mutator(msg->method) &&
        !(fm10k_native_profile() && msg->daemon_id != NL_DAEMON_CONFIGD &&
          sdk_native_protocol_runtime(msg->method)) &&
        !(msg->method == NL_SWITCHD_L2_PLAN_APPLY &&
          msg->daemon_id == NL_DAEMON_CONFIGD)) {
        status = hw_state_tracker_begin_l2_mutation(
            ctx->hw_tracker);
        if (status != 0) {
            nl_send_response(conn, msg->request_id, status);
            return;
        }
        mutation_lease = true;
    }

    if (invalidates_stp)
        stp_snapshot_rpc_cache_invalidate();
    hal_rpc_dispatch_inner(ctx, conn, msg);
    if (invalidates_stp)
        stp_snapshot_rpc_cache_invalidate();
    if (mutation_lease)
        hw_state_tracker_end_l2_mutation(ctx->hw_tracker);
}

static void append_rpc_text(char *buf, size_t buf_len, size_t *off,
                            bool *truncated, const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || buf_len == 0 || !off || !fmt)
        return;
    if (*off >= buf_len) {
        if (truncated)
            *truncated = true;
        buf[buf_len - 1] = '\0';
        return;
    }

    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_len - *off, fmt, ap);
    va_end(ap);

    if (n < 0) {
        if (truncated)
            *truncated = true;
        buf[*off] = '\0';
        return;
    }
    if ((size_t)n >= buf_len - *off) {
        *off = buf_len - 1;
        if (truncated)
            *truncated = true;
        buf[*off] = '\0';
        return;
    }
    *off += (size_t)n;
}

static void send_formatted_rpc_response(nl_conn *conn, u64 request_id,
                                        s32 error_code, const char *buf,
                                        size_t buf_size, int len) {
    if (!buf || len < 0 || (size_t)len > buf_size) {
        (void)hal_rpc_send_text(
            conn, request_id, NL_ERR_CAPABILITY_INSUFFICIENT,
            "switchd read-back response exceeds the IPC buffer capacity");
        return;
    }
    (void)hal_rpc_send_payload(conn, request_id, error_code, buf, (u32)len);
}

static void send_pfe_status(struct sdk_context *ctx, nl_conn *conn,
                            nl_msg_hdr *msg) {
    nl_pfe_capability *cap = ctx ? &ctx->pfe_cap : &g_pfe_cap;
    char json[NETLAB_PFE_STATUS_JSON_BYTES];
    int n = nl_pfe_cap_to_json(cap, json, sizeof(json));

    (void)hal_rpc_send_payload(conn, msg->request_id, 0, json, (u32)n);
}

static const char *mirror_direction_name(int direction) {
    switch (direction) {
    case HAL_MIRROR_DIRECTION_INGRESS:
        return "ingress";
    case HAL_MIRROR_DIRECTION_EGRESS:
        return "egress";
    case HAL_MIRROR_DIRECTION_BOTH:
        return "both";
    default:
        return "unknown";
    }
}

static bool pfe_ready_for_rpc(struct sdk_context *ctx) {
    if (!ctx || !ctx->initialized || !ctx->exec)
        return false;
    return strcmp(nl_pfe_status_str(&ctx->pfe_cap), "UP") == 0;
}

static bool active_inventory_has_port(const struct sdk_context *ctx,
                                      int port) {
    if (!ctx || port <= 0)
        return false;
    for (int i = 0; i < ctx->num_cardinal_ports; i++) {
        if (ctx->cardinal_ports[i] == port)
            return true;
    }
    return false;
}

static bool payload_word(const char *payload, const char *key,
                         char *out, size_t out_size);

static const char *payload_key_value(const char *payload, const char *key) {
    char needle[32];
    char *p;

    if (!payload || !key)
        return NULL;
    snprintf(needle, sizeof(needle), "%s=", key);
    p = strstr(payload, needle);
    while (p) {
        if (p == payload || isspace((unsigned char)p[-1]))
            return p + strlen(needle);
        p = strstr(p + strlen(needle), needle);
    }
    return NULL;
}

static bool parse_int_token(const char *text, int min, int max, int *out) {
    char *end = NULL;
    long value;

    if (!text || !text[0] || !out)
        return false;
    errno = 0;
    value = strtol(text, &end, 0);
    if (errno != 0 || end == text || value < min || value > max)
        return false;
    if (*end != '\0')
        return false;
    *out = (int)value;
    return true;
}

static bool parse_sflow_live_probe_payload(const char *payload,
                                           u32 payload_len,
                                           int *port_out) {
    static const char prefix[] =
        "ack=" NL_SFLOW_V1_PROBE_ACK "\nport=";
    const char *digits;
    const char *end;
    unsigned long value = 0;

    if (!payload || !port_out ||
        payload_len <= sizeof(prefix) - 1U ||
        memcmp(payload, prefix, sizeof(prefix) - 1U) != 0)
        return false;

    digits = payload + sizeof(prefix) - 1U;
    end = payload + payload_len;
    if (end[-1] != '\n' || digits == end - 1)
        return false;
    for (const char *cursor = digits; cursor < end - 1; cursor++) {
        unsigned digit;

        if (!isdigit((unsigned char)*cursor))
            return false;
        digit = (unsigned)(*cursor - '0');
        if (value > ((unsigned long)INT_MAX - digit) / 10UL)
            return false;
        value = value * 10UL + digit;
    }
    if (value == 0 || value > INT_MAX)
        return false;
    *port_out = (int)value;
    return true;
}

static bool parse_payload_int_range(const char *payload, int min, int max,
                                    int *out) {
    char text[32];
    size_t n;

    if (!payload || !out)
        return false;
    while (isspace((unsigned char)*payload))
        payload++;
    n = strlen(payload);
    while (n > 0 && isspace((unsigned char)payload[n - 1]))
        n--;
    if (n == 0 || n >= sizeof(text))
        return false;
    memcpy(text, payload, n);
    text[n] = '\0';
    return parse_int_token(text, min, max, out);
}

static bool payload_fully_consumed(const char *payload, int consumed) {
    if (!payload || consumed < 0)
        return false;
    while (payload[consumed]) {
        if (!isspace((unsigned char)payload[consumed]))
            return false;
        consumed++;
    }
    return true;
}

static bool payload_int_range(const char *payload, const char *key,
                              int min, int max, int *out) {
    char text[32];

    if (!payload_word(payload, key, text, sizeof(text)))
        return false;
    return parse_int_token(text, min, max, out);
}

static bool parse_tx_id_payload(const char *payload, u64 *out) {
    char *end = NULL;
    unsigned long long value;

    if (!payload || !payload[0] || !out)
        return false;
    errno = 0;
    value = strtoull(payload, &end, 16);
    if (errno != 0 || end == payload || value == 0)
        return false;
    while (*end) {
        if (!isspace((unsigned char)*end))
            return false;
        end++;
    }
    *out = (u64)value;
    return true;
}

static int payload_int(const char *payload, const char *key, int def) {
    const char *p;
    char text[32];
    size_t n = 0;
    int value;

    if (!payload || !key)
        return def;
    p = payload_key_value(payload, key);
    if (!p)
        return def;
    while (p[n] && !isspace((unsigned char)p[n]))
        n++;
    if (n == 0 || n >= sizeof(text))
        return def;
    memcpy(text, p, n);
    text[n] = '\0';
    return parse_int_token(text, INT_MIN, INT_MAX, &value) ? value : def;
}

static u64 mac_bytes_to_u64(const u8 mac[6]) {
    u64 value = 0;

    if (!mac)
        return 0;
    for (int i = 0; i < 6; i++)
        value = (value << 8) | mac[i];
    return value;
}

static bool payload_ipv4(const char *payload, const char *key, u32 *out) {
    char text[32];
    struct in_addr addr;

    if (!out || !payload_word(payload, key, text, sizeof(text)) ||
        inet_pton(AF_INET, text, &addr) != 1)
        return false;
    *out = ntohl(addr.s_addr);
    return true;
}

static bool payload_word(const char *payload, const char *key,
                         char *out, size_t out_size) {
    const char *p;
    size_t n = 0;

    if (!payload || !key || !out || out_size == 0)
        return false;
    out[0] = '\0';
    p = payload_key_value(payload, key);
    if (!p)
        return false;
    while (p[n] && p[n] != ' ' && p[n] != '\n' && p[n] != '\t')
        n++;
    if (n == 0 || n >= out_size)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool parse_port_range_text(const char *text, int *start, int *end) {
    char buf[32];
    char *dash;
    char *endp;
    long lo;
    long hi;

    if (!text || !start || !end || strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);
    dash = strchr(buf, '-');
    if (!dash || dash == buf || dash[1] == '\0' ||
        strchr(dash + 1, '-'))
        return false;
    *dash++ = '\0';
    lo = strtol(buf, &endp, 10);
    if (*endp != '\0')
        return false;
    hi = strtol(dash, &endp, 10);
    if (*endp != '\0' || lo < 0 || hi < 0 ||
        lo > 65535 || hi > 65535 || lo > hi)
        return false;
    *start = (int)lo;
    *end = (int)hi;
    return true;
}

static void xml_escape_attr(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst || dst_len == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        const char *rep = NULL;
        switch (*p) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default:
            dst[off++] = *p;
            dst[off] = '\0';
            continue;
        }
        while (*rep && off + 1 < dst_len)
            dst[off++] = *rep++;
        dst[off] = '\0';
    }
}

static const char *qos_queue_owner_status(
    nl_rpc_method method, int exec_status,
    const hal_qos_queue_owner_result *owner) {
    if (!owner)
        return "invalid";
    if (exec_status == 0 && owner->ok) {
        if ((method == NL_SWITCHD_QOS_QUEUE_OWNER_READBACK ||
             method == NL_SWITCHD_QOS_QUEUE_OWNER_ROLLBACK) && !owner->active)
            return "empty";
        return "ok";
    }
    if (method == NL_SWITCHD_QOS_QUEUE_OWNER_READBACK)
        return "mismatch";
    if (method == NL_SWITCHD_QOS_QUEUE_OWNER_ROLLBACK)
        return "out-of-sync";
    return "blocked";
}

static void send_qos_queue_owner_xml(nl_conn *conn, u64 request_id,
                                     nl_rpc_method method, int exec_status,
                                     const hal_qos_queue_owner_result *owner) {
    char detail[256];
    char max_text[32];
    char resp[1536];
    const char *tag = method == NL_SWITCHD_QOS_QUEUE_OWNER_APPLY ?
                      "qos-queue-owner-apply" :
                      method == NL_SWITCHD_QOS_QUEUE_OWNER_READBACK ?
                      "qos-queue-owner-readback" :
                                     "qos-queue-owner-rollback";
    int off;

    xml_escape_attr(owner ? owner->detail : "missing result",
                    detail, sizeof(detail));
    if (owner && owner->max_bw_default)
        snprintf(max_text, sizeof(max_text), "default");
    else
        snprintf(max_text, sizeof(max_text), "%llu",
                 owner ? (unsigned long long)owner->max_bw_mbps : 0ULL);

    off = snprintf(resp, sizeof(resp),
        "<%s status=\"%s\" active=\"%s\" port=\"%d\" "
        "queue-id=\"%d\" traffic-class=\"%d\" "
        "min-bw-mbps=\"%llu\" max-bw-mbps=\"%s\" "
        "pre-present=\"%d\" pre-status=\"%d\" "
        "add-status=\"%d\" set-tc-status=\"%d\" "
        "set-min-status=\"%d\" set-max-status=\"%d\" "
        "read-status=\"%d\" rollback-status=\"%d\" "
        "post-read-status=\"%d\" post-present=\"%d\" "
        "compared=\"%d\" mismatches=\"%d\" detail=\"%s\"/>\n",
        tag, qos_queue_owner_status(method, exec_status, owner),
        owner && owner->active ? "true" : "false",
        owner ? owner->port : 0,
        owner ? owner->queue_id : 0,
        owner ? owner->traffic_class : 0,
        owner ? (unsigned long long)owner->min_bw_mbps : 0ULL,
        max_text,
        owner ? owner->pre_present : 0,
        owner ? owner->pre_status : 0,
        owner ? owner->add_status : 0,
        owner ? owner->set_tc_status : 0,
        owner ? owner->set_min_status : 0,
        owner ? owner->set_max_status : 0,
        owner ? owner->read_status : 0,
        owner ? owner->rollback_status : 0,
        owner ? owner->post_read_status : 0,
        owner ? owner->post_present : 0,
        owner ? owner->compared : 0,
        owner ? owner->mismatches : 0,
        detail);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;
    (void)hal_rpc_send_payload(
        conn, request_id,
        (exec_status == 0 && owner && owner->ok) ? 0 : NL_ERR_INVALID_VALUE,
        resp, (u32)off);
}

static const char *qos_queue_profile_owner_status(
    nl_rpc_method method, int exec_status,
    const hal_qos_queue_profile_owner_result *owner) {
    if (!owner)
        return "invalid";
    if (exec_status == 0 && owner->ok) {
        if ((method == NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_READBACK ||
             method == NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_ROLLBACK) &&
            !owner->active)
            return "empty";
        return "ok";
    }
    if (method == NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_READBACK)
        return "mismatch";
    if (method == NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_ROLLBACK)
        return "out-of-sync";
    return "blocked";
}

static void send_qos_queue_profile_owner_xml(
    nl_conn *conn, u64 request_id, nl_rpc_method method, int exec_status,
    const hal_qos_queue_profile_owner_result *owner) {
    char detail[256];
    char resp[4096];
    const char *tag = method == NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY ?
                      "qos-queue-profile-owner-apply" :
                      method == NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_READBACK ?
                      "qos-queue-profile-owner-readback" :
                      "qos-queue-profile-owner-rollback";
    int off;

    xml_escape_attr(owner ? owner->detail : "missing result",
                    detail, sizeof(detail));
    off = snprintf(resp, sizeof(resp),
        "<%s status=\"%s\" active=\"%s\" port=\"%d\" "
        "queue-count=\"%d\" applied-count=\"%d\" "
        "compared=\"%d\" mismatches=\"%d\" cleanup-status=\"%d\" "
        "detail=\"%s\">",
        tag, qos_queue_profile_owner_status(method, exec_status, owner),
        owner && owner->active ? "true" : "false",
        owner ? owner->port : 0,
        owner ? owner->queue_count : 0,
        owner ? owner->applied_count : 0,
        owner ? owner->compared : 0,
        owner ? owner->mismatches : 0,
        owner ? owner->cleanup_status : 0,
        detail);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;

    if (owner) {
        for (int i = 0;
             i < owner->queue_count &&
             i < HAL_QOS_QUEUE_PROFILE_MAX_QUEUES &&
             off < (int)sizeof(resp) - 1; i++) {
            const hal_qos_queue_profile_item_result *queue =
                &owner->queue[i];
            char max_text[32];
            int written;

            if (queue->max_bw_default)
                snprintf(max_text, sizeof(max_text), "default");
            else
                snprintf(max_text, sizeof(max_text), "%llu",
                         (unsigned long long)queue->max_bw_mbps);
            written = snprintf(resp + off, sizeof(resp) - (size_t)off,
                "<queue id=\"%d\" traffic-class=\"%d\" "
                "min-bw-mbps=\"%llu\" max-bw-mbps=\"%s\" "
                "pre-present=\"%d\" pre-status=\"%d\" "
                "add-status=\"%d\" set-tc-status=\"%d\" "
                "set-min-status=\"%d\" set-max-status=\"%d\" "
                "read-status=\"%d\" rollback-status=\"%d\" "
                "post-read-status=\"%d\" post-present=\"%d\" "
                "compared=\"%d\" mismatches=\"%d\"/>",
                queue->queue_id, queue->traffic_class,
                (unsigned long long)queue->min_bw_mbps, max_text,
                queue->pre_present, queue->pre_status,
                queue->add_status, queue->set_tc_status,
                queue->set_min_status, queue->set_max_status,
                queue->read_status, queue->rollback_status,
                queue->post_read_status, queue->post_present,
                queue->compared, queue->mismatches);
            if (written < 0)
                break;
            off += written;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
        }
    }

    if (off < (int)sizeof(resp) - 3)
        off += snprintf(resp + off, sizeof(resp) - (size_t)off,
                        "</%s>\n", tag);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;
    (void)hal_rpc_send_payload(
        conn, request_id,
        (exec_status == 0 && owner && owner->ok) ? 0 : NL_ERR_INVALID_VALUE,
	        resp, (u32)off);
}

static const char *qos_watermark_scope_name(int scope) {
    switch (scope) {
    case HAL_QOS_WATERMARK_SCOPE_PORT:
        return "port";
    case HAL_QOS_WATERMARK_SCOPE_SWITCH:
        return "switch";
    default:
        return "unknown";
    }
}

static int qos_watermark_scope_from_text(const char *text) {
    if (!text || !text[0] || strcmp(text, "port") == 0)
        return HAL_QOS_WATERMARK_SCOPE_PORT;
    if (strcmp(text, "switch") == 0)
        return HAL_QOS_WATERMARK_SCOPE_SWITCH;
    return 0;
}

static const char *qos_watermark_attr_name(int attr) {
    switch (attr) {
    case HAL_QOS_WATERMARK_ATTR_TX_HOG:
        return "tx-hog";
    case HAL_QOS_WATERMARK_ATTR_TX_PRIVATE:
        return "tx-private";
    case HAL_QOS_WATERMARK_ATTR_RX_HOG:
        return "rx-hog";
    case HAL_QOS_WATERMARK_ATTR_RX_PRIVATE:
        return "rx-private";
    case HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_ON:
        return "private-pause-on";
    case HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_OFF:
        return "private-pause-off";
    case HAL_QOS_WATERMARK_ATTR_SHARED_PRI:
        return "shared-pri";
    case HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP:
        return "shared-soft-drop";
    case HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER:
        return "shared-soft-drop-jitter";
    case HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG:
        return "shared-soft-drop-hog";
    case HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE:
        return "tx-soft-drop-on-private";
    case HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE:
        return "tx-soft-drop-on-rxmp-free";
    default:
        return "unknown";
    }
}

static int qos_watermark_attr_from_text(const char *text) {
    if (!text || !text[0] || strcmp(text, "tx-hog") == 0)
        return HAL_QOS_WATERMARK_ATTR_TX_HOG;
    if (strcmp(text, "tx-private") == 0)
        return HAL_QOS_WATERMARK_ATTR_TX_PRIVATE;
    if (strcmp(text, "rx-hog") == 0)
        return HAL_QOS_WATERMARK_ATTR_RX_HOG;
    if (strcmp(text, "rx-private") == 0)
        return HAL_QOS_WATERMARK_ATTR_RX_PRIVATE;
    if (strcmp(text, "private-pause-on") == 0)
        return HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_ON;
    if (strcmp(text, "private-pause-off") == 0)
        return HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_OFF;
    if (strcmp(text, "shared-pri") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_PRI;
    if (strcmp(text, "shared-soft-drop") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP;
    if (strcmp(text, "shared-soft-drop-jitter") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER;
    if (strcmp(text, "shared-soft-drop-hog") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
    if (strcmp(text, "tx-soft-drop-on-private") == 0)
        return HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE;
    if (strcmp(text, "tx-soft-drop-on-rxmp-free") == 0)
        return HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE;
    return 0;
}

static const char *qos_watermark_owner_status(
    nl_rpc_method method, int exec_status,
    const hal_qos_watermark_owner_result *owner) {
    if (!owner)
        return "invalid";
    if (exec_status == 0 && owner->ok) {
        if ((method == NL_SWITCHD_QOS_WATERMARK_OWNER_READBACK ||
             method == NL_SWITCHD_QOS_WATERMARK_OWNER_ROLLBACK) &&
            !owner->active)
            return "empty";
        return "ok";
    }
    if (method == NL_SWITCHD_QOS_WATERMARK_OWNER_READBACK)
        return "mismatch";
    if (method == NL_SWITCHD_QOS_WATERMARK_OWNER_ROLLBACK)
        return "out-of-sync";
    return "blocked";
}

static void send_qos_watermark_owner_xml(
    nl_conn *conn, u64 request_id, nl_rpc_method method, int exec_status,
    const hal_qos_watermark_owner_result *owner) {
    char detail[256];
    char resp[1536];
    const char *tag = method == NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY ?
                      "qos-watermark-owner-apply" :
                      method == NL_SWITCHD_QOS_WATERMARK_OWNER_READBACK ?
                      "qos-watermark-owner-readback" :
                      "qos-watermark-owner-rollback";
    int off;

    xml_escape_attr(owner ? owner->detail : "missing result",
                    detail, sizeof(detail));
    off = snprintf(resp, sizeof(resp),
        "<%s status=\"%s\" active=\"%s\" scope=\"%s\" "
        "port=\"%d\" attr=\"%s\" attr-id=\"%d\" index=\"%d\" "
        "requested-value=\"%d\" original-value=\"%d\" "
        "applied-value=\"%d\" current-value=\"%d\" "
        "pre-read-status=\"%d\" set-status=\"%d\" "
        "read-status=\"%d\" rollback-status=\"%d\" "
        "post-read-status=\"%d\" compared=\"%d\" "
        "mismatches=\"%d\" detail=\"%s\"/>\n",
        tag, qos_watermark_owner_status(method, exec_status, owner),
        owner && owner->active ? "true" : "false",
        qos_watermark_scope_name(owner ? owner->scope : 0),
        owner ? owner->port : 0,
        qos_watermark_attr_name(owner ? owner->attr : 0),
        owner ? owner->attr : 0,
        owner ? owner->index : 0,
        owner ? owner->requested_value : 0,
        owner ? owner->original_value : 0,
        owner ? owner->applied_value : 0,
        owner ? owner->current_value : 0,
        owner ? owner->pre_read_status : 0,
        owner ? owner->set_status : 0,
        owner ? owner->read_status : 0,
        owner ? owner->rollback_status : 0,
        owner ? owner->post_read_status : 0,
        owner ? owner->compared : 0,
        owner ? owner->mismatches : 0,
        detail);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;
    (void)hal_rpc_send_payload(
        conn, request_id,
        (exec_status == 0 && owner && owner->ok) ? 0 : NL_ERR_INVALID_VALUE,
        resp, (u32)off);
}

static const char *acl_policer_owner_status(
    nl_rpc_method method, int exec_status,
    const hal_acl_policer_owner_result *owner) {
    if (!owner)
        return "invalid";
    if (exec_status == 0 && owner->ok) {
        if ((method == NL_SWITCHD_ACL_POLICER_OWNER_READBACK ||
             method == NL_SWITCHD_ACL_POLICER_OWNER_ROLLBACK) &&
            !owner->active)
            return "empty";
        return "ok";
    }
    if (method == NL_SWITCHD_ACL_POLICER_OWNER_READBACK)
        return "mismatch";
    if (method == NL_SWITCHD_ACL_POLICER_OWNER_ROLLBACK)
        return "out-of-sync";
    return "blocked";
}

static void send_acl_policer_owner_xml(
    nl_conn *conn, u64 request_id, nl_rpc_method method, int exec_status,
    const hal_acl_policer_owner_result *owner) {
    char detail[256];
    char resp[1536];
    char dst_mac[32];
    const char *tag = method == NL_SWITCHD_ACL_POLICER_OWNER_APPLY ?
                      "acl-policer-owner-apply" :
                      method == NL_SWITCHD_ACL_POLICER_OWNER_READBACK ?
                      "acl-policer-owner-readback" :
                                      "acl-policer-owner-rollback";
    int off;

    xml_escape_attr(owner ? owner->detail : "missing result",
                    detail, sizeof(detail));
    snprintf(dst_mac, sizeof(dst_mac), "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             owner ? (unsigned long long)((owner->dst_mac >> 40) & 0xff) : 0ULL,
             owner ? (unsigned long long)((owner->dst_mac >> 32) & 0xff) : 0ULL,
             owner ? (unsigned long long)((owner->dst_mac >> 24) & 0xff) : 0ULL,
             owner ? (unsigned long long)((owner->dst_mac >> 16) & 0xff) : 0ULL,
             owner ? (unsigned long long)((owner->dst_mac >> 8) & 0xff) : 0ULL,
             owner ? (unsigned long long)(owner->dst_mac & 0xff) : 0ULL);
    off = snprintf(resp, sizeof(resp),
        "<%s status=\"%s\" active=\"%s\" slot=\"%d\" port=\"%d\" "
        "acl=\"%d\" rule=\"%d\" policer=\"%d\" port-set=\"%d\" "
        "dst-mac=\"%s\" rate-kbps=\"%d\" burst-bytes=\"%d\" "
        "create-status=\"%d\" rule-status=\"%d\" "
        "compile-status=\"%d\" apply-status=\"%d\" "
        "read-status=\"%d\" policer-read-status=\"%d\" "
        "rollback-status=\"%d\" cleanup-status=\"%d\" "
        "rate-readback=\"%d\" burst-readback=\"%d\" "
        "packets=\"%llu\" octets=\"%llu\" "
        "compared=\"%d\" mismatches=\"%d\" detail=\"%s\"/>\n",
        tag, acl_policer_owner_status(method, exec_status, owner),
        owner && owner->active ? "true" : "false",
        owner ? owner->slot : -1,
        owner ? owner->port : 0,
        owner ? owner->acl : 0,
        owner ? owner->rule : 0,
        owner ? owner->policer : 0,
        owner ? owner->port_set : -1,
        dst_mac,
        owner ? owner->rate_kbps : 0,
        owner ? owner->burst_bytes : 0,
        owner ? owner->create_status : 0,
        owner ? owner->rule_status : 0,
        owner ? owner->compile_status : 0,
        owner ? owner->apply_status : 0,
        owner ? owner->read_status : 0,
        owner ? owner->policer_read_status : 0,
        owner ? owner->rollback_status : 0,
        owner ? owner->cleanup_status : 0,
        owner ? owner->rate_readback : 0,
        owner ? owner->burst_readback : 0,
        owner ? (unsigned long long)owner->packets : 0ULL,
        owner ? (unsigned long long)owner->octets : 0ULL,
        owner ? owner->compared : 0,
        owner ? owner->mismatches : 0,
        detail);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;
    (void)hal_rpc_send_payload(
        conn, request_id,
        (exec_status == 0 && owner && owner->ok) ? 0 : NL_ERR_INVALID_VALUE,
        resp, (u32)off);
}

static const char *acl_egress_probe_status(
    int exec_status, const hal_acl_egress_probe_result *probe) {
    if (!probe)
        return "invalid";
    if (exec_status == 0 && probe->ok)
        return "pass";
    if (exec_status == 0 && probe->unsupported)
        return "unsupported";
    return "fail";
}

static void send_acl_egress_probe_xml(
    nl_conn *conn, u64 request_id, int exec_status,
    const hal_acl_egress_probe_result *probe) {
    char detail[256];
    char resp[1536];
    char src_mac[32];
    char dst_mac[32];
    int off;
    bool accepted = exec_status == 0 && probe &&
                    (probe->ok || probe->unsupported);

    xml_escape_attr(probe ? probe->detail : "missing result",
                    detail, sizeof(detail));
    snprintf(src_mac, sizeof(src_mac),
             "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             probe ? (unsigned long long)((probe->src_mac >> 40) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->src_mac >> 32) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->src_mac >> 24) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->src_mac >> 16) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->src_mac >> 8) & 0xff) : 0ULL,
             probe ? (unsigned long long)(probe->src_mac & 0xff) : 0ULL);
    snprintf(dst_mac, sizeof(dst_mac),
             "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             probe ? (unsigned long long)((probe->dst_mac >> 40) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->dst_mac >> 32) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->dst_mac >> 24) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->dst_mac >> 16) & 0xff) : 0ULL,
             probe ? (unsigned long long)((probe->dst_mac >> 8) & 0xff) : 0ULL,
             probe ? (unsigned long long)(probe->dst_mac & 0xff) : 0ULL);

    off = snprintf(resp, sizeof(resp),
        "<acl-egress-probe status=\"%s\" port=\"%d\" "
        "acl=\"%d\" rule=\"%d\" src-mac=\"%s\" dst-mac=\"%s\" "
        "unsupported=\"%s\" create-status=\"%d\" "
        "pre-rule-status=\"%d\" port-status=\"%d\" "
        "rule-status=\"%d\" compile-status=\"%d\" "
        "apply-status=\"%d\" read-status=\"%d\" "
        "cleanup-status=\"%d\" delete-acl-status=\"%d\" "
        "packets=\"%llu\" octets=\"%llu\" detail=\"%s\"/>\n",
        acl_egress_probe_status(exec_status, probe),
        probe ? probe->port : 0,
        probe ? probe->acl : 0,
        probe ? probe->rule : 0,
        src_mac,
        dst_mac,
        probe && probe->unsupported ? "true" : "false",
        probe ? probe->create_status : 0,
        probe ? probe->pre_rule_status : 0,
        probe ? probe->port_status : 0,
        probe ? probe->rule_status : 0,
        probe ? probe->compile_status : 0,
        probe ? probe->apply_status : 0,
        probe ? probe->read_status : 0,
        probe ? probe->cleanup_status : 0,
        probe ? probe->delete_acl_status : 0,
        probe ? (unsigned long long)probe->packets : 0ULL,
        probe ? (unsigned long long)probe->octets : 0ULL,
        detail);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;
    (void)hal_rpc_send_payload(conn, request_id,
                               accepted ? 0 : NL_ERR_INVALID_VALUE,
        resp, (u32)off);
}

static const char *acl_general_allocator_status(
    nl_rpc_method method, int exec_status,
    const hal_acl_general_allocator_result *allocator) {
    if (!allocator)
        return "invalid";
    if (exec_status == 0 && allocator->ok) {
        if ((method == NL_SWITCHD_ACL_GENERAL_ALLOCATOR_READBACK ||
             method == NL_SWITCHD_ACL_GENERAL_ALLOCATOR_ROLLBACK) &&
            !allocator->active)
            return "empty";
        return "ok";
    }
    if (method == NL_SWITCHD_ACL_GENERAL_ALLOCATOR_READBACK)
        return "mismatch";
    if (method == NL_SWITCHD_ACL_GENERAL_ALLOCATOR_ROLLBACK)
        return "out-of-sync";
    return "blocked";
}

static void send_acl_general_allocator_xml(
    nl_conn *conn, u64 request_id, nl_rpc_method method, int exec_status,
    const hal_acl_general_allocator_result *allocator) {
    char detail[256];
    char resp[4096];
    const char *tag = method == NL_SWITCHD_ACL_GENERAL_ALLOCATOR_APPLY ?
                      "acl-general-allocator-apply" :
                      method == NL_SWITCHD_ACL_GENERAL_ALLOCATOR_READBACK ?
                      "acl-general-allocator-readback" :
                                      "acl-general-allocator-rollback";
    int off;

    xml_escape_attr(allocator ? allocator->detail : "missing result",
                    detail, sizeof(detail));
    off = snprintf(resp, sizeof(resp),
        "<%s status=\"%s\" active=\"%s\" public-config-open=\"false\" "
        "compiler-profile=\"%s\" compiler-profile-id=\"%d\" "
        "compiler-term-count=\"%d\" "
        "ingress-acl-start=\"%d\" ingress-acl-count=\"%d\" "
        "ingress-rules-per-acl=\"%d\" ingress-policer-start=\"%d\" "
        "ingress-policer-count=\"%d\" egress-acl-start=\"%d\" "
        "egress-acl-count=\"%d\" egress-rules-per-acl=\"%d\" "
        "reserve-ingress-status=\"%d\" reserve-egress-status=\"%d\" "
        "rollback-ingress-status=\"%d\" rollback-egress-status=\"%d\" "
        "compiler-acl=\"%d\" compiler-rule=\"%d\" "
        "compiler-port=\"%d\" compiler-port-set=\"%d\" "
        "compiler-policer-rule=\"%d\" compiler-policer=\"%d\" "
        "compiler-create-status=\"%d\" compiler-rule-status=\"%d\" "
        "compiler-policer-status=\"%d\" "
        "compiler-policer-rule-status=\"%d\" "
        "compiler-compile-status=\"%d\" compiler-apply-status=\"%d\" "
        "compiler-read-status=\"%d\" "
        "compiler-condition=\"0x%llx\" compiler-action=\"0x%llx\" "
        "compiler-policer-read-status=\"%d\" "
        "compiler-cleanup-status=\"%d\" "
        "compiler-packets=\"%llu\" compiler-octets=\"%llu\" "
        "compiler-policer-packets=\"%llu\" "
        "compiler-policer-octets=\"%llu\" "
        "owner-count=\"%d\" compared=\"%d\" mismatches=\"%d\" "
        "detail=\"%s\"/>\n",
        tag, acl_general_allocator_status(method, exec_status, allocator),
        allocator && allocator->active ? "true" : "false",
        allocator ? allocator->compiler_profile : "",
        allocator ? allocator->compiler_profile_id : 0,
        allocator ? allocator->compiler_term_count : 0,
        allocator ? allocator->ingress_acl_start : 0,
        allocator ? allocator->ingress_acl_count : 0,
        allocator ? allocator->ingress_rules_per_acl : 0,
        allocator ? allocator->ingress_policer_start : 0,
        allocator ? allocator->ingress_policer_count : 0,
        allocator ? allocator->egress_acl_start : 0,
        allocator ? allocator->egress_acl_count : 0,
        allocator ? allocator->egress_rules_per_acl : 0,
        allocator ? allocator->reserve_ingress_status : 0,
        allocator ? allocator->reserve_egress_status : 0,
        allocator ? allocator->rollback_ingress_status : 0,
        allocator ? allocator->rollback_egress_status : 0,
        allocator ? allocator->compiler_acl : 0,
        allocator ? allocator->compiler_rule : 0,
        allocator ? allocator->compiler_port : 0,
        allocator ? allocator->compiler_port_set : 0,
        allocator ? allocator->compiler_policer_rule : 0,
        allocator ? allocator->compiler_policer : 0,
        allocator ? allocator->compiler_create_status : 0,
        allocator ? allocator->compiler_rule_status : 0,
        allocator ? allocator->compiler_policer_status : 0,
        allocator ? allocator->compiler_policer_rule_status : 0,
        allocator ? allocator->compiler_compile_status : 0,
        allocator ? allocator->compiler_apply_status : 0,
        allocator ? allocator->compiler_read_status : 0,
        allocator ? (unsigned long long)allocator->compiler_condition : 0ULL,
        allocator ? (unsigned long long)allocator->compiler_action : 0ULL,
        allocator ? allocator->compiler_policer_read_status : 0,
        allocator ? allocator->compiler_cleanup_status : 0,
        allocator ? (unsigned long long)allocator->compiler_packets : 0ULL,
        allocator ? (unsigned long long)allocator->compiler_octets : 0ULL,
        allocator ?
            (unsigned long long)allocator->compiler_policer_packets : 0ULL,
        allocator ?
            (unsigned long long)allocator->compiler_policer_octets : 0ULL,
        allocator ? allocator->owner_count : 0,
        allocator ? allocator->compared : 0,
        allocator ? allocator->mismatches : 0,
        detail);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(resp))
        off = (int)sizeof(resp) - 1;
    (void)hal_rpc_send_payload(
        conn, request_id,
        (exec_status == 0 && allocator && allocator->ok) ?
            0 : NL_ERR_INVALID_VALUE,
        resp, (u32)off);
}

static void sync_port_admin_cache(struct sdk_context *ctx, int port, int mode) {
    int effective_mode = hal_port_effective_admin_mode(mode);
    bool admin_up = effective_mode == FM_PORT_MODE_UP;

    sdk_port_cache_set(ctx, port, admin_up ? 1 : 0, admin_up ? -2 : 0, -1);
}

static void sync_apply_plan_port_cache(struct sdk_context *ctx,
                                       const l2_apply_plan *plan) {
    if (!ctx || !plan)
        return;

    for (int i = 0; i < plan->n_steps; i++) {
        const l2_apply_step *step = &plan->steps[i];
        if (step->type == L2_STEP_PORT_SET_ADMIN)
            sync_port_admin_cache(ctx, step->port, step->admin_mode);
        else if (step->type == L2_STEP_PORT_SET_SPEED)
            sdk_port_cache_set(ctx, step->port, -2, -2, step->speed);
    }
}

static void sync_rollback_plan_port_cache(struct sdk_context *ctx,
                                          const l2_apply_plan *plan) {
    if (!ctx || !plan ||
        plan->original_n_steps != plan->n_steps)
        return;

    for (int i = 0; i < plan->original_n_steps; i++) {
        const l2_apply_step *step = &plan->original_steps[i];
        const l2_apply_step *restored = &plan->steps[i];
        int port = restored->port > 0 ?
            restored->port : step->port;

        if (step->type == L2_STEP_PORT_SET_ADMIN &&
            step->pre_admin.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
            sync_port_admin_cache(
                ctx, port, step->pre_admin.admin_mode);
        } else if (step->type == L2_STEP_PORT_SET_SPEED &&
                   step->pre_speed_valid) {
            sdk_port_cache_set(
                ctx, port, -2, -2, step->pre_speed);
        }
    }
}

static int run_l3_runtime_op(struct sdk_context *ctx, struct sdk_op *op,
                             struct sdk_result *result, int kind,
                             const char *text, bool acknowledged, u64 tx_id,
                             int hold_sec, const char *router_mac,
                             int priority) {
    if (!ctx || !ctx->exec || !op || !result)
        return -1;
    bool runtime = op->runtime;
    u64 issued_at = op->issued_at;
    memset(op, 0, sizeof(*op));
    op->runtime = runtime;
    op->issued_at = issued_at;
    op->type = SDK_OP_L3_RUNTIME;
    op->args.l3_runtime.kind = kind;
    op->args.l3_runtime.text = text;
    op->args.l3_runtime.acknowledged = acknowledged;
    op->args.l3_runtime.live_readback = true;
    op->args.l3_runtime.tx_id = tx_id;
    op->args.l3_runtime.hold_sec = hold_sec;
    if (router_mac)
        snprintf(op->args.l3_runtime.router_mac,
                 sizeof(op->args.l3_runtime.router_mac), "%s", router_mac);
    return sdk_exec_with_prio(ctx->exec, op, result, priority, 30000);
}

static void hal_rpc_dispatch_inner(struct sdk_context *ctx, nl_conn *conn,
                                   nl_msg_hdr *msg) {
    const nl_rpc_contract *contract;
    struct sdk_result result;
    struct sdk_op op;
    const char *payload;

    if (!msg) {
        NL_LOG_WARN("switchd: refusing null rpc request");
        return;
    }

    contract = nl_rpc_contract_lookup(NL_DAEMON_SWITCHD, msg->method);
    if (!contract ||
        !nl_rpc_contract_payload_valid(
            contract->request_format, msg->payload, msg->payload_len,
            contract->max_request_len)) {
        NL_LOG_WARN("switchd: invalid contract payload method=%u payload=%u",
                    msg->method, msg->payload_len);
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return;
    }

    if ((contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED) &&
        msg->tx_id == 0) {
        nl_send_response(conn, msg->request_id, NL_ERR_TX_ID_REQUIRED);
        return;
    }

    if (fm10k_native_profile() && !sdk_native_rpc_supported(msg->method)) {
        nl_send_response(conn, msg->request_id, NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }
    bool native_replay = fm10k_native_ready() && msg->daemon_id == NL_DAEMON_CONFIGD &&
        (msg->method == NL_SWITCHD_L2_PLAN_APPLY || msg->method == NL_SWITCHD_L2_PLAN_ROLLBACK ||
         msg->method == NL_SWITCHD_COMMIT_MARK_SUCCESS || msg->method == NL_SWITCHD_COMMIT_MARK_FAILED ||
         msg->method == NL_SWITCHD_FM10K_BIND);
    if (fm10k_native_profile() && !fm10k_native_bound() &&
        !sdk_native_rpc_observable(msg->method) && !native_replay) {
        nl_send_response(conn, msg->request_id, NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }

    /* nl_msg_alloc() and nl_recv() guarantee this sentinel byte. */
    payload = (const char *)msg->payload;
    memset(&result, 0, sizeof(result));
    const u64 request_issued_at = nl_port_scope_clock();
    sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);

    if (msg->method == NL_SWITCHD_FM10K_BIND) {
        struct { u32 schema, reserved; u64 generation; } request;
        if (!ctx || !ctx->hw_tracker || !pfe_ready_for_rpc(ctx) ||
            msg->payload_len != sizeof(request)) {
            nl_send_response(conn, msg->request_id, NL_ERR_PFE_DOWN);
            return;
        }
        memcpy(&request, msg->payload, sizeof(request));
        int rc = request.schema == 1 && !request.reserved ?
            hw_state_tracker_begin_l2_mutation(ctx->hw_tracker) : NL_ERR_INVALID_VALUE;
        if (!rc) {
            rc = fm10k_native_bind(request.generation, msg->tx_id);
            hw_state_tracker_end_l2_mutation(ctx->hw_tracker);
        }
        nl_send_response(conn, msg->request_id, rc);
        return;
    }

    if (msg->method == NL_SWITCHD_FM10K_BOARD_GET) {
        char response[8192];
        if (msg->payload_len && strcmp(payload, "contract") != 0) {
            nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
            return;
        }
        int length = fm10k_native_cache(response, sizeof(response));
        if (length < 0) nl_send_response(conn, msg->request_id, NL_ERR_SDK_CALL_FAILED);
        else (void)hal_rpc_send_payload(conn, msg->request_id, 0, response, (u32)length);
        return;
    }
    if (msg->method == NL_SWITCHD_FM10K_CONFIG_GET) {
        if (!ctx || !ctx->exec || !fm10k_native_profile()) {
            nl_send_response(conn, msg->request_id, NL_ERR_PFE_DOWN);
            return;
        }
        op.type = SDK_OP_FM10K_CONFIG_GET;
        int rc = sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_READBACK, 3000);
        if (rc || result.status) nl_send_response(conn, msg->request_id, NL_ERR_SDK_CALL_FAILED);
        else (void)hal_rpc_send_payload(conn, msg->request_id, 0,
            &result.data.fm10k_config, (u32)sizeof(result.data.fm10k_config));
        return;
    }
    if (msg->method == NL_SWITCHD_FM10K_FAN_MANUAL) {
        int pwm, seconds;
        char extra;
        if (!fm10k_native_bound() || !ctx || !ctx->exec) {
            (void)hal_rpc_send_text(conn, msg->request_id, NL_ERR_CAPABILITY_INSUFFICIENT,
                "FM10840 board HAL is not fully bound; manual PWM is unavailable");
            return;
        }
        if (sscanf(payload, "%3d %2d %c", &pwm, &seconds, &extra) != 2 ||
            pwm < 25 || pwm > 100 || seconds < 1 || seconds > 60) {
            nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
            return;
        }
        op.type = SDK_OP_FM10K_FAN_MANUAL;
        op.args.fm10k_fan.pwm = pwm;
        op.args.fm10k_fan.seconds = seconds;
        int rc = sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_CONFIG_CHANGE, 3000);
        if (rc || result.status) {
            nl_send_response(conn, msg->request_id, NL_ERR_SDK_CALL_FAILED);
            return;
        }
        char response[160];
        snprintf(response, sizeof(response), "{\"pwm_percent\":%d,\"expires_at\":%.6f}",
                 pwm, result.data.fm10k_fan.expires_at);
        (void)hal_rpc_send_text(conn, msg->request_id, 0, response);
        return;
    }

    if (msg->method == NL_SWITCHD_PFE_STATUS_GET) {
        send_pfe_status(ctx, conn, msg);
        return;
    }

    if (msg->method == NL_SWITCHD_SFLOW_BATCH_GET) {
        nl_sflow_batch_request_v1 request;
        nl_sflow_batch_response_v1 *response;
        size_t expected_size;
        int rc;

        if (msg->payload_len != sizeof(request)) {
            nl_send_response(
                conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
            return;
        }
        memset(&request, 0, sizeof(request));
        memcpy(&request, msg->payload, sizeof(request));
        response = calloc(1, sizeof(*response));
        if (!response) {
            nl_send_response(
                conn, msg->request_id, NL_ERR_CAPABILITY_INSUFFICIENT);
            return;
        }

        rc = sflow_capture_drain(&request, response);
        if (rc != SFLOW_CAPTURE_DRAIN_OK) {
            free(response);
            nl_send_response(
                conn, msg->request_id,
                rc == SFLOW_CAPTURE_DRAIN_BUSY ?
                    NL_ERR_RPC_BUSY :
                    NL_ERR_INVALID_VALUE);
            return;
        }

        expected_size = offsetof(
            nl_sflow_batch_response_v1, samples) +
            (size_t)response->sample_count *
                sizeof(response->samples[0]);
        if (response->sample_count > NL_SFLOW_V1_BATCH_MAX ||
            response->size != expected_size ||
            response->size > sizeof(*response)) {
            free(response);
            nl_send_response(
                conn, msg->request_id,
                NL_ERR_CAPABILITY_INSUFFICIENT);
            return;
        }
        (void)hal_rpc_send_payload(
            conn, msg->request_id, 0, response, response->size);
        free(response);
        return;
    }

    if (msg->method == NL_SWITCHD_SDK_RUNTIME_GET) {
        char resp[32768];
        int n = hal_sdk_runtime_format(ctx, resp, sizeof(resp));

        (void)hal_rpc_send_payload(conn, msg->request_id, 0,
                                   resp, (u32)n);
        return;
    }

    if (msg->method == NL_SWITCHD_FM10K_EYE_GET || msg->method == NL_SWITCHD_FM10K_EYE_CONTROL) {
        if (!fm10k_native_profile() || !ctx || !ctx->exec || strlen(payload) >= sizeof(op.args.fm10k_eye.command)) {
            nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
            return;
        }
        op.type = msg->method == NL_SWITCHD_FM10K_EYE_GET ? SDK_OP_FM10K_EYE_GET : SDK_OP_FM10K_EYE_CONTROL;
        memcpy(op.args.fm10k_eye.command, payload, strlen(payload) + 1);
        int rc = sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_READBACK, 5000);
        if (rc || result.status) nl_send_response(conn, msg->request_id, NL_ERR_SDK_CALL_FAILED);
        else (void)hal_rpc_send_text(conn, msg->request_id, 0, result.data.fm10k_phy.response);
        return;
    }

    if (msg->method == NL_SWITCHD_PORT_SNAPSHOT_GET && strncmp(payload, "phy-port=", 9) == 0) {
        int port = fm10k_phy_port_parse(payload + 9);
        if (!fm10k_native_profile() || port < 0 || !ctx || !ctx->exec) {
            nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
            return;
        }
        op.type = SDK_OP_FM10K_PHY_GET;
        op.args.port.port = port;
        int rc = sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_READBACK, 5000);
        if (rc || result.status) nl_send_response(conn, msg->request_id, NL_ERR_SDK_CALL_FAILED);
        else (void)hal_rpc_send_text(conn, msg->request_id, 0, result.data.fm10k_phy.response);
        return;
    }

    if (msg->method == NL_SWITCHD_PORT_SNAPSHOT_GET) {
        char resp[65536] = {0};
        size_t off = 0;
        bool truncated = false;
        bool include_counters = strstr(payload, "counters=1") != NULL;
        u64 started_ms;
        u64 finished_ms;
        int rc;

        op.type = SDK_OP_GET_PORT_SNAPSHOT;
        op.args.port_snapshot.include_counters = include_counters;
        for (int i = 0; i < ctx->num_cardinal_ports &&
             op.args.port_snapshot.n_ports < NETLAB_PORT_SNAPSHOT_MAX; i++) {
            int port = ctx->cardinal_ports[i];

            if (port <= 0 || !nl_ifid_is_user_port(port) ||
                nl_ifid_is_cpu_port(port))
                continue;
            op.args.port_snapshot.ports[
                op.args.port_snapshot.n_ports++] = port;
        }
        started_ms = monotonic_ms();
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                include_counters ? SDK_PRIO_COUNTER :
                                    SDK_PRIO_READBACK,
                                5000);
        finished_ms = monotonic_ms();
        if (rc != 0) {
            (void)hal_rpc_send_text(
                conn, msg->request_id, NL_ERR_DAEMON_UNREACHABLE,
                "<port-snapshot status=\"unavailable\"/>");
            return;
        }

        const hal_port_snapshot *snapshot = &result.data.port_snapshot;
        append_rpc_text(
            resp, sizeof(resp), &off, &truncated,
            "<port-snapshot status=\"%s\" generation=\"%llu\" "
            "sampled-monotonic-ms=\"%llu\" duration-ms=\"%llu\" "
            "ports=\"%d\" state-failures=\"%d\" "
            "counter-failures=\"%d\" counters=\"%s\">\n",
            snapshot->state_failures == 0 &&
                snapshot->counter_failures == 0 ? "ok" : "degraded",
            (unsigned long long)snapshot->generation,
            (unsigned long long)snapshot->sampled_monotonic_ms,
            (unsigned long long)(finished_ms >= started_ms ?
                finished_ms - started_ms : 0),
            snapshot->n_ports, snapshot->state_failures,
            snapshot->counter_failures,
            snapshot->counters_included ? "true" : "false");
        for (int i = 0; i < snapshot->n_ports; i++) {
            const hal_port_snapshot_entry *entry = &snapshot->ports[i];
            const char *admin = entry->state_status != 0 ? "unknown" :
                entry->state.mode == 0 ? "up" : "down";
            const char *link = entry->state_status != 0 ? "unknown" :
                port_link_state_name(entry->state.state);

            append_rpc_text(
                resp, sizeof(resp), &off, &truncated,
                "  <port id=\"%d\" state-status=\"%d\" "
                "counter-status=\"%d\" admin=\"%s\" link=\"%s\" "
                "speed=\"%d\" ethernet-mode=\"%s\" mtu=\"%d\" "
                "max-frame=\"%d\" pvid=\"%d\"",
                entry->port, entry->state_status, entry->counters_status,
                admin, link, entry->state.speed,
                hal_port_ethernet_mode_name(entry->state.ethernet_mode),
                entry->state.mtu,
                entry->state.max_frame, entry->state.pvid);
            if (fm10k_native_profile() && entry->state_status == 0) {
                /* Already captured by the SDK owner. Preserve raw mode and
                 * lane words for link diagnosis without additional SDK reads.
                 * In IES 4.3.2 info[0] bit 5 is synthetic, not PCS alignment. */
                append_rpc_text(resp, sizeof(resp), &off, &truncated,
                    " sdk-mode-raw=\"%d\" sdk-state-raw=\"%d\" sdk-info-raw=\"",
                    entry->state.mode, entry->state.state);
                for (int lane = 0; lane < NETLAB_PORT_STATE_INFO_SLOTS; ++lane)
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                        "%s%u", lane ? "," : "",
                        (unsigned)entry->state.info[lane]);
                append_rpc_text(resp, sizeof(resp), &off, &truncated, "\"");
            }
            if (snapshot->counters_included) {
                const hal_port_counters *c = &entry->counters;

                append_rpc_text(
                    resp, sizeof(resp), &off, &truncated,
                    " rx-bytes=\"%llu\" tx-bytes=\"%llu\" "
                    "rx-packets=\"%llu\" tx-packets=\"%llu\" "
                    "rx-ucast-packets=\"%llu\" rx-mcast-packets=\"%llu\" "
                    "rx-bcast-packets=\"%llu\" tx-ucast-packets=\"%llu\" "
                    "tx-mcast-packets=\"%llu\" tx-bcast-packets=\"%llu\" "
                    "rx-errors=\"%llu\" tx-errors=\"%llu\" "
                    "rx-drops=\"%llu\" tx-drops=\"%llu\" "
                    "rx-fcs-errors=\"%llu\" rx-symbol-errors=\"%llu\" "
                    "rx-frame-size-errors=\"%llu\" "
                    "rx-pause-packets=\"%llu\" tx-pause-packets=\"%llu\" "
                    "rx-pfc-packets=\"%llu\" tx-pfc-packets=\"%llu\" "
                    "rx-congestion-drops=\"%llu\" tx-congestion-drops=\"%llu\" "
                    "stp-drops=\"%llu\" vlan-tag-drops=\"%llu\" "
                    "security-violations=\"%llu\" "
                    "flood-control-drops=\"%llu\" "
                    "policer-drops=\"%llu\" ttl-drops=\"%llu\"",
                    (unsigned long long)c->rx_bytes,
                    (unsigned long long)c->tx_bytes,
                    (unsigned long long)c->rx_pkts,
                    (unsigned long long)c->tx_pkts,
                    (unsigned long long)c->rx_ucast_pkts,
                    (unsigned long long)c->rx_mcast_pkts,
                    (unsigned long long)c->rx_bcast_pkts,
                    (unsigned long long)c->tx_ucast_pkts,
                    (unsigned long long)c->tx_mcast_pkts,
                    (unsigned long long)c->tx_bcast_pkts,
                    (unsigned long long)c->rx_errors,
                    (unsigned long long)c->tx_errors,
                    (unsigned long long)c->rx_drops,
                    (unsigned long long)c->tx_drops,
                    (unsigned long long)c->rx_fcs_errors,
                    (unsigned long long)c->rx_symbol_errors,
                    (unsigned long long)c->rx_frame_size_errors,
                    (unsigned long long)c->rx_pause_pkts,
                    (unsigned long long)c->tx_pause_pkts,
                    (unsigned long long)c->rx_pfc_pkts,
                    (unsigned long long)c->tx_pfc_pkts,
                    (unsigned long long)c->rx_congestion_drops,
                    (unsigned long long)c->tx_congestion_drops,
                    (unsigned long long)c->stp_drops,
                    (unsigned long long)c->vlan_tag_drops,
                    (unsigned long long)c->security_violations,
                    (unsigned long long)c->flood_control_drops,
                    (unsigned long long)c->policer_drops,
                    (unsigned long long)c->ttl_drops);
            }
            append_rpc_text(resp, sizeof(resp), &off, &truncated, "/>\n");
        }
        append_rpc_text(resp, sizeof(resp), &off, &truncated,
                        "</port-snapshot>\n");
        (void)hal_rpc_send_payload(
            conn, msg->request_id,
            truncated ? NL_ERR_CAPABILITY_INSUFFICIENT : 0,
            resp, (u32)off);
        return;
    }

    if (msg->method == NL_SWITCHD_PORT_MIRRORING_GET) {
        char resp[4096];
        size_t off = 0;
        bool truncated = false;
        const hal_mirror_state *state;

        op.type = SDK_OP_GET_MIRROR_STATE;
        sdk_exec_with_prio(ctx->exec, &op, &result,
                           SDK_PRIO_READBACK, 10000);
        if (result.status != 0) {
            (void)hal_rpc_send_text(
                conn, msg->request_id, NL_ERR_INVALID_VALUE,
                "<port-mirroring status=\"readback-failed\"/>");
            return;
        }
        state = &result.data.mirror_state;
        append_rpc_text(resp, sizeof(resp), &off, &truncated,
                        "<port-mirroring session-capacity=\"1\">\n");
        if (state->exists) {
            append_rpc_text(
                resp, sizeof(resp), &off, &truncated,
                "  <session group=\"%d\" destination-port=\"%d\" source-count=\"%d\">\n",
                state->group, state->destination_port, state->n_sources);
            for (int i = 0; i < state->n_sources; i++) {
                append_rpc_text(
                    resp, sizeof(resp), &off, &truncated,
                    "    <source port=\"%d\" direction=\"%s\"/>\n",
                    state->source_ports[i],
                    mirror_direction_name(state->source_directions[i]));
            }
            append_rpc_text(resp, sizeof(resp), &off, &truncated,
                            "  </session>\n");
        }
        append_rpc_text(resp, sizeof(resp), &off, &truncated,
                        "</port-mirroring>\n");
        (void)hal_rpc_send_payload(
            conn, msg->request_id,
            truncated ? NL_ERR_INVALID_VALUE : 0, resp, (u32)off);
        return;
    }

    if (msg->method == NL_SWITCHD_L2_MULTICAST_OWNER_GET) {
        char resp[NETLAB_L2_MCAST_OWNER_MAX];
        int rc;

        op.type = SDK_OP_GET_L2_MCAST_OWNER;
        op.args.l2_mcast_owner.buf = resp;
        op.args.l2_mcast_owner.buf_size = sizeof(resp);
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                SDK_PRIO_READBACK, 10000);
        (void)hal_rpc_send_text(
            conn, msg->request_id,
            rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
            rc == 0 ? resp :
                "<multicast-owner status=\"unavailable\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_TX_DRY_RUN) {
        char resp[1024];
        int rc;

        rc = l3_transaction_dry_run_parse(payload, resp, sizeof(resp));
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp);
        return;
    }

    if (msg->method == NL_SWITCHD_L3_TX_APPLY) {
        char resp[8192];
        int rc;

        rc = l3_transaction_hidden_apply(payload, msg->tx_id,
                                         resp, sizeof(resp));
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp);
        return;
    }

    if (msg->method == NL_SWITCHD_L3_TX_READBACK) {
        char offline_resp[32768];
        const char *resp;
        bool live_readback = pfe_ready_for_rpc(ctx);
        int rc;

        if (live_readback) {
            rc = run_l3_runtime_op(
                ctx, &op, &result, HAL_L3_RUNTIME_HIDDEN_READBACK,
                NULL, false, msg->tx_id, 0, NULL, SDK_PRIO_READBACK);
            resp = result.data.l3_runtime.response;
        } else {
            rc = l3_transaction_hidden_readback(
                0, false, offline_resp, sizeof(offline_resp));
            resp = offline_resp;
        }

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                rc == 0 ? resp :
                                    "<l3-transaction-readback status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_TX_ROLLBACK) {
        char resp[8192];
        int rc = l3_transaction_hidden_rollback(msg->tx_id,
                                                resp, sizeof(resp));

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp);
        return;
    }

    if (msg->method == NL_SWITCHD_L3_SHADOW_MISMATCH_PROBE) {
        char resp[4096];
        int rc;

        rc = l3_transaction_shadow_mismatch_probe(payload, resp,
                                                  sizeof(resp));
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp);
        return;
    }

    if (msg->method == NL_SWITCHD_L3_FAILURE_PROBE) {
        char resp[4096];
        int rc;

        rc = l3_transaction_failure_probe(payload, resp, sizeof(resp));
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp);
        return;
    }

    /* Observation startup intentionally has no L2 commit capability. Only
     * explicit read methods may use its initialized SDK/executor. */
    bool observation_read = fm10k_startup_observe() && fm10k_native_profile() &&
        sdk_native_observation_readable(ctx, msg->method);
    if (!pfe_ready_for_rpc(ctx) && !observation_read) {
        NL_LOG_WARN("switchd: method=%d rejected while PFE status=%s",
                    msg->method,
                    ctx ? nl_pfe_status_str(&ctx->pfe_cap)
                        : nl_pfe_status_str(&g_pfe_cap));
        nl_send_response(conn, msg->request_id, NL_ERR_PFE_DOWN);
        return;
    }

    if (msg->method == NL_SWITCHD_L3_SDK_READBACK_PROBE) {
        const char *resp;
        int rc;

        op.type = SDK_OP_L3_SDK_READBACK_PROBE;
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                SDK_PRIO_READBACK, 30000);
        resp = result.data.l3_sdk_readback.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                rc == 0 && resp[0] ? resp :
                                    "<l3-sdk-readback-probe status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_SDK_WRITE_CANARY) {
        const char *resp;
        bool ack = strstr(payload,
                          "ack=NETLAB_ENABLE_L3_SDK_WRITE_CANARY") != NULL;
        int rc;

        op.type = SDK_OP_L3_SDK_WRITE_CANARY;
        op.args.l3_sdk_canary.acknowledged = ack;
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                SDK_PRIO_CONFIG_CHANGE, 30000);
        resp = result.data.l3_sdk_canary.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-sdk-write-canary status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_SFLOW_LIVE_PROBE) {
        char blocked[256];
        const char *resp;
        int port;
        int rc;

        if (!parse_sflow_live_probe_payload(
                payload, msg->payload_len, &port) ||
            !active_inventory_has_port(ctx, port)) {
            (void)snprintf(
                blocked, sizeof(blocked),
                "<sflow-live-probe status=\"blocked\" "
                "reason=\"exact-ack-and-port-required\" "
                "tx-id=\"%llu\"/>",
                (unsigned long long)msg->tx_id);
            (void)hal_rpc_send_text(
                conn, msg->request_id, NL_ERR_INVALID_VALUE,
                blocked);
            return;
        }

        op.type = SDK_OP_SFLOW_LIVE_PROBE;
        op.args.sflow_probe.port = port;
        op.args.sflow_probe.acknowledged = true;
        op.args.sflow_probe.tx_id = msg->tx_id;
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                SDK_PRIO_CONFIG_CHANGE, 30000);
        resp = result.data.sflow_probe.response;
        (void)hal_rpc_send_text(
            conn, msg->request_id,
            rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
            resp[0] ? resp :
                "<sflow-live-probe status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_RIF_LIVE_PROBE) {
        const char *tx_text;
        const char *resp;
        bool ack;
        int rc;

        ack = strstr(payload,
                     "ack=NETLAB_ENABLE_L3_RIF_LIVE_PROBE") != NULL;
        tx_text = payload;
        if (strncmp(payload, "ack=", 4) == 0) {
            const char *line_end = strchr(payload, '\n');
            tx_text = line_end ? line_end + 1 : "";
        }
        rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_RIF_LIVE_PROBE,
            tx_text, ack, msg->tx_id, 0, NULL, SDK_PRIO_CONFIG_CHANGE);
        resp = result.data.l3_runtime.response;
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-rif-live-probe status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_ARP_LIVE_PROBE) {
        const char *tx_text;
        const char *resp;
        bool ack;
        int rc;

        ack = strstr(payload,
                     "ack=NETLAB_ENABLE_L3_ARP_LIVE_PROBE") != NULL;
        tx_text = payload;
        if (strncmp(payload, "ack=", 4) == 0) {
            const char *line_end = strchr(payload, '\n');
            tx_text = line_end ? line_end + 1 : "";
        }
        rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_ARP_LIVE_PROBE,
            tx_text, ack, msg->tx_id, 0, NULL, SDK_PRIO_CONFIG_CHANGE);
        resp = result.data.l3_runtime.response;
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-arp-live-probe status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_ECMP_LIVE_PROBE) {
        const char *tx_text;
        const char *resp;
        bool ack;
        int rc;

        ack = strstr(payload,
                     "ack=NETLAB_ENABLE_L3_ECMP_LIVE_PROBE") != NULL;
        tx_text = payload;
        if (strncmp(payload, "ack=", 4) == 0) {
            const char *line_end = strchr(payload, '\n');
            tx_text = line_end ? line_end + 1 : "";
        }
        rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_ECMP_LIVE_PROBE,
            tx_text, ack, msg->tx_id, 0, NULL, SDK_PRIO_CONFIG_CHANGE);
        resp = result.data.l3_runtime.response;
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-ecmp-live-probe status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_ROUTE_LIVE_PROBE) {
        const char *tx_text;
        const char *resp;
        char router_mac[32];
        bool ack;
        int hold_sec;
        int rc;

        ack = strstr(payload,
                     "ack=NETLAB_ENABLE_L3_ROUTE_LIVE_PROBE") != NULL;
        hold_sec = payload_int(payload, "hold-sec", 0);
        (void)payload_word(payload, "router-mac", router_mac,
                           sizeof(router_mac));
        tx_text = payload;
        if (strncmp(payload, "ack=", 4) == 0) {
            const char *line_end = strchr(payload, '\n');
            tx_text = line_end ? line_end + 1 : "";
        }
        rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_ROUTE_LIVE_PROBE,
            tx_text, ack, msg->tx_id, hold_sec,
            router_mac[0] ? router_mac : NULL, SDK_PRIO_CONFIG_CHANGE);
        resp = result.data.l3_runtime.response;
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-route-live-probe status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_PERSISTENT_APPLY) {
        const char *tx_text;
        const char *resp;
        bool ack;
        int rc;

        ack = strstr(payload,
                     "ack=NETLAB_ENABLE_L3_PERSISTENT_OWNER") != NULL;
        tx_text = payload;
        if (strncmp(payload, "ack=", 4) == 0) {
            const char *line_end = strchr(payload, '\n');
            tx_text = line_end ? line_end + 1 : "";
        }
        rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_PERSISTENT_APPLY,
            tx_text, ack, msg->tx_id, 0, NULL, SDK_PRIO_CONFIG_CHANGE);
        resp = result.data.l3_runtime.response;
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-persistent-owner-apply "
                                    "status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_PERSISTENT_READBACK) {
        const char *resp;
        int rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_PERSISTENT_READBACK,
            NULL, false, msg->tx_id, 0, NULL, SDK_PRIO_READBACK);

        resp = result.data.l3_runtime.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                rc == 0 ? resp :
                                    "<l3-persistent-owner-readback "
                                    "status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_L3_PERSISTENT_ROLLBACK) {
        const char *resp;
        bool ack = strstr(payload,
                          "ack=NETLAB_ENABLE_L3_PERSISTENT_OWNER") != NULL;
        int rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_PERSISTENT_ROLLBACK,
            NULL, ack, msg->tx_id, 0, NULL, SDK_PRIO_CONFIG_CHANGE);

        resp = result.data.l3_runtime.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<l3-persistent-owner-rollback "
                                    "status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_RPD_FIB_APPLY) {
        char resp[65536] = {0};
        int rc;

        op.type = SDK_OP_L3_FIB_BATCH_APPLY;
        op.args.l3_fib_batch.text = payload;
        op.args.l3_fib_batch.tx_id = msg->tx_id;
        op.args.l3_fib_batch.resp = resp;
        op.args.l3_fib_batch.resp_size = sizeof(resp);
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                SDK_PRIO_CONFIG_CHANGE, 30000);
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<fib-batch-apply status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_BEGIN ||
        msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_PART ||
        msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_COMMIT ||
        msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_ABORT) {
        char resp[65536] = {0};
        const char *fallback;
        int rc;

        if (msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_BEGIN) {
            op.type = SDK_OP_L3_FIB_SNAPSHOT_BEGIN;
            fallback = "<fib-snapshot-begin status=\"invalid\"/>";
        } else if (msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_PART) {
            op.type = SDK_OP_L3_FIB_SNAPSHOT_PART;
            fallback = "<fib-snapshot-part status=\"invalid\"/>";
        } else if (msg->method == NL_SWITCHD_RPD_FIB_SNAPSHOT_COMMIT) {
            op.type = SDK_OP_L3_FIB_SNAPSHOT_COMMIT;
            fallback = "<fib-snapshot-commit status=\"invalid\"/>";
        } else {
            op.type = SDK_OP_L3_FIB_SNAPSHOT_ABORT;
            fallback = "<fib-snapshot-abort status=\"invalid\"/>";
        }
        op.args.l3_fib_batch.text = payload;
        op.args.l3_fib_batch.tx_id = msg->tx_id;
        op.args.l3_fib_batch.resp = resp;
        op.args.l3_fib_batch.resp_size = sizeof(resp);
        rc = sdk_exec_with_prio(ctx->exec, &op, &result,
                                SDK_PRIO_CONFIG_CHANGE, 30000);
        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp : fallback);
        return;
    }

    if (msg->method == NL_SWITCHD_RPD_FIB_READBACK) {
        const char *resp;
        int rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_FIB_READBACK,
            NULL, false, msg->tx_id, 0, NULL, SDK_PRIO_READBACK);

        resp = result.data.l3_runtime.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                rc == 0 ? resp :
                                    "<fib-readback status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_RPD_FIB_RECONCILE) {
        const char *resp;
        int rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_FIB_RECONCILE,
            NULL, false, msg->tx_id, 0, NULL, SDK_PRIO_READBACK);

        resp = result.data.l3_runtime.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                rc == 0 ? resp :
                                    "<fib-reconcile status=\"invalid\"/>");
        return;
    }

    if (msg->method == NL_SWITCHD_RPD_FIB_ROLLBACK) {
        const char *resp;
        int rc = run_l3_runtime_op(
            ctx, &op, &result, HAL_L3_RUNTIME_FIB_ROLLBACK,
            NULL, false, msg->tx_id, 0, NULL, SDK_PRIO_CONFIG_CHANGE);

        resp = result.data.l3_runtime.response;

        (void)hal_rpc_send_text(conn, msg->request_id,
                                rc == 0 ? 0 : NL_ERR_INVALID_VALUE,
                                resp[0] ? resp :
                                    "<fib-rollback-tx status=\"invalid\"/>");
        return;
    }

    switch (msg->method) {
        case NL_SWITCHD_PORT_SET_ADMIN: { // HAL_PORT_SET_ADMIN
            int port = 0, mode = 0;
            nl_port_entry entry;
            if (!payload_int_range(payload, "port", 1, INT_MAX, &port) ||
                !payload_int_range(payload, "mode", 0, 1, &mode) ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_PORT_SET_ADMIN;
            op.args.port.port = port;
            op.args.port.mode = mode;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 30000);
            if (result.status == 0)
                sync_port_admin_cache(ctx, port, mode);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_PORT_GET_STATE: { // HAL_PORT_GET_STATE — safe cached response
            int rport = 0;
            if (msg->payload_len > 0)
                sscanf(payload, "port=%d", &rport);
            if (rport <= 0 && msg->payload_len > 0)
                rport = atoi(payload);
            int admin = -1, link = -1, speed = 0;
            bool known = (sdk_port_cache_get(ctx, rport, &admin, &link, &speed) == 0);
            const char *admin_str = admin == 1 ? "UP" :
                                    admin == 0 ? "DOWN" : "?";
            const char *link_str = link == 1 ? "UP" :
                                   link == 0 ? "DOWN" : "?";
            char resp[128];
            snprintf(resp, sizeof(resp), "port=%d admin=%s link=%s speed=%d",
                     rport, known ? admin_str : "invalid",
                     known ? link_str : "invalid", speed);
            (void)hal_rpc_send_text(conn, msg->request_id,
                                    known ? 0 : -1, resp);
            break;
        }
        case NL_SWITCHD_PORT_SPEED_GET: { // hardware speed/interface-mode read-back
            int rport = 0;
            char resp[128];

            if (!payload_int_range(payload, "port", 1, INT_MAX, &rport) ||
                !nl_ifid_is_user_port(rport)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_GET_PORT_STATE;
            op.args.port.port = rport;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 3000);
            snprintf(resp, sizeof(resp),
                     "port=%d speed=%d ethernet-mode=%s",
                     rport, result.status == 0 ?
                         result.data.port_state.speed : 0,
                     result.status == 0 ?
                         hal_port_ethernet_mode_name(
                             result.data.port_state.ethernet_mode) :
                         "unknown");
            (void)hal_rpc_send_text(conn, msg->request_id, result.status,
                                    resp);
            break;
        }
        case NL_SWITCHD_PORT_MTU_GET: { // HAL_PORT_GET_MTU — hardware read-back
            int rport = 0;
            int mtu = 0;
            int max_frame = 0;
            int pvid = 0;
            char resp[128];

            if (msg->payload_len > 0)
                sscanf(payload, "port=%d", &rport);
            if (rport <= 0 && msg->payload_len > 0)
                rport = atoi(payload);
            if (rport <= 0) {
                nl_send_response(conn, msg->request_id, -1);
                break;
            }

            op.type = SDK_OP_GET_PORT_STATE;
            op.args.port.port = rport;
            op.args.port.configuration_only = true;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 3000);
            if (result.status == 0) {
                mtu = result.data.port_state.mtu;
                max_frame = result.data.port_state.max_frame;
                pvid = result.data.port_state.pvid;
            }
            snprintf(resp, sizeof(resp),
                     "port=%d mtu=%d max-frame=%d pvid=%d",
                     rport, mtu, max_frame, pvid);
            (void)hal_rpc_send_text(conn, msg->request_id, result.status,
                                    resp);
            break;
        }
        case NL_SWITCHD_VLAN_CREATE: { // HAL_VLAN_CREATE
            int vid = 0;
            if (!parse_payload_int_range(payload, 1, 4094, &vid)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_VLAN_CREATE;
            op.args.vlan.vid = (u16)vid;
            int st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                        SDK_PRIO_CONFIG_CHANGE, 10000);
            if (st == 71) st = 0; // FM_ERR_VLAN_ALREADY_EXISTS is OK
            nl_send_response(conn, msg->request_id, st);
            break;
        }
        case NL_SWITCHD_VLAN_DELETE: { // HAL_VLAN_DELETE
            int vid = 0;
            if (!parse_payload_int_range(payload, 1, 4094, &vid)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_VLAN_DELETE;
            op.args.vlan.vid = (u16)vid;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 30000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_VLAN_ADD_PORT: { // HAL_VLAN_ADD_PORT
            int vid = 0, port = 0, tagged = 0;
            int consumed = -1;
            nl_port_entry entry;
            if (sscanf(payload, "%d %d %d %n",
                       &vid, &port, &tagged, &consumed) != 3 ||
                !payload_fully_consumed(payload, consumed) ||
                vid < 1 || vid > 4094 || port <= 0 ||
                (tagged != 0 && tagged != 1) ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_VLAN_ADD_PORT;
            op.args.vlan.vid = (u16)vid;
            op.args.vlan.port = port;
            op.args.vlan.tagged = (tagged != 0);
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 30000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_COMMIT_MARK_SUCCESS: {
            u64 tx_id = 0;
            if (!parse_tx_id_payload(payload, &tx_id) ||
                tx_id != msg->tx_id) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            /* Finalization can read LAG/ACL hardware and retire SDK-owned
             * snapshots, so it must use the same owner as apply/rollback. */
            op.type = SDK_OP_COMMIT_MARK_SUCCESS;
            op.args.commit.tracker = ctx->hw_tracker;
            op.args.commit.tx_id = tx_id;
            sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_CONFIG_CHANGE, 30000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_COMMIT_MARK_FAILED: { // HAL_COMMIT_MARK_FAILED
            u64 tx_id = 0;
            if (!parse_tx_id_payload(payload, &tx_id) ||
                tx_id != msg->tx_id) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_COMMIT_MARK_FAILED;
            op.args.commit.tracker = ctx->hw_tracker;
            op.args.commit.tx_id = tx_id;
            sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_CONFIG_CHANGE, 30000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_PORT_COUNTERS_GET: { // HAL_GET_PORT_COUNTERS — via executor
            int port = 0;
            if (!parse_payload_int_range(payload, 1, INT_MAX, &port) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_GET_COUNTERS;
            op.args.port.port = port;
            sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_READBACK, 10000);
            char resp[2048];
            if (result.status == 0) {
                snprintf(resp, sizeof(resp),
                         "<counters port=\"%d\">"
                         "<rx-bytes>%lu</rx-bytes><tx-bytes>%lu</tx-bytes>"
                         "<rx-packets>%lu</rx-packets><tx-packets>%lu</tx-packets>"
                         "<rx-ucast-packets>%lu</rx-ucast-packets>"
                         "<rx-mcast-packets>%lu</rx-mcast-packets>"
                         "<rx-bcast-packets>%lu</rx-bcast-packets>"
                         "<tx-ucast-packets>%lu</tx-ucast-packets>"
                         "<tx-mcast-packets>%lu</tx-mcast-packets>"
                         "<tx-bcast-packets>%lu</tx-bcast-packets>"
                         "<rx-errors>%lu</rx-errors>"
                         "<tx-errors>%lu</tx-errors>"
                         "<rx-drops>%lu</rx-drops>"
                         "<tx-drops>%lu</tx-drops>"
                         "<rx-fcs-errors>%lu</rx-fcs-errors>"
                         "<rx-symbol-errors>%lu</rx-symbol-errors>"
                         "<rx-frame-size-errors>%lu</rx-frame-size-errors>"
                         "<rx-pause-packets>%lu</rx-pause-packets>"
                         "<tx-pause-packets>%lu</tx-pause-packets>"
                         "<stp-drops>%lu</stp-drops>"
                         "<vlan-tag-drops>%lu</vlan-tag-drops>"
                         "<security-violations>%lu</security-violations>"
                         "<flood-control-drops>%lu</flood-control-drops>"
                         "<policer-drops>%lu</policer-drops>"
                         "<ttl-drops>%lu</ttl-drops>"
                         "</counters>",
                         port,
                         result.data.counters.rx_bytes,
                         result.data.counters.tx_bytes,
                         result.data.counters.rx_pkts,
                         result.data.counters.tx_pkts,
                         result.data.counters.rx_ucast_pkts,
                         result.data.counters.rx_mcast_pkts,
                         result.data.counters.rx_bcast_pkts,
                         result.data.counters.tx_ucast_pkts,
                         result.data.counters.tx_mcast_pkts,
                         result.data.counters.tx_bcast_pkts,
                         result.data.counters.rx_errors,
                         result.data.counters.tx_errors,
                         result.data.counters.rx_drops,
                         result.data.counters.tx_drops,
                         result.data.counters.rx_fcs_errors,
                         result.data.counters.rx_symbol_errors,
                         result.data.counters.rx_frame_size_errors,
                         result.data.counters.rx_pause_pkts,
                         result.data.counters.tx_pause_pkts,
                         result.data.counters.stp_drops,
                         result.data.counters.vlan_tag_drops,
                         result.data.counters.security_violations,
                         result.data.counters.flood_control_drops,
                         result.data.counters.policer_drops,
                         result.data.counters.ttl_drops);
            } else {
                snprintf(resp, sizeof(resp), "<counters port=\"%d\" error=\"%d\"/>", port, result.status);
            }
            (void)hal_rpc_send_text(conn, msg->request_id,
                                    result.status, resp);
            break;
        }
        case NL_SWITCHD_PORT_COUNTERS_RESET: { // HAL_RESET_PORT_COUNTERS — via executor
            int port = 0;
            if (!parse_payload_int_range(payload, 1, INT_MAX, &port) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_RESET_COUNTERS;
            op.args.port.port = port;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_COUNTER, 10000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_XCVR_INFO_GET: { // HAL_GET_XCVR_INFO — via executor
            int port = 0;
            if (msg->payload_len > 0) port = atoi(payload);
            op.type = SDK_OP_GET_XCVR;
            op.args.port.port = port;
            sdk_exec_with_prio(ctx->exec, &op, &result, SDK_PRIO_READBACK, 10000);
            char resp[2048];
            if (result.status == 0) {
                int lane_count = result.data.xcvr.lane_count;
                if (lane_count < 0) lane_count = 0;
                if (lane_count > NETLAB_XCVR_MAX_LANES)
                    lane_count = NETLAB_XCVR_MAX_LANES;
                int off = snprintf(resp, sizeof(resp),
                                   "<xcvr port=\"%d\">"
                                   "<present>%d</present><type>%d</type>"
                                   "<dom-valid>%d</dom-valid>"
                                   "<lane-count>%d</lane-count>"
                                   "<temp>%.1f</temp><voltage>%.4f</voltage>"
                                   "<tx-bias>%.2f</tx-bias>"
                                   "<tx-power>%.4f</tx-power>"
                                   "<rx-power>%.4f</rx-power>",
                                   port,
                                   result.data.xcvr.present,
                                   result.data.xcvr.type,
                                   result.data.xcvr.dom_valid,
                                   lane_count,
                                   result.data.xcvr.temp,
                                   result.data.xcvr.voltage,
                                   result.data.xcvr.tx_bias,
                                   result.data.xcvr.tx_power,
                                   result.data.xcvr.rx_power);
                if (off < 0) off = 0;
                if (off >= (int)sizeof(resp)) off = (int)sizeof(resp) - 1;
                for (int i = 0; i < lane_count; i++) {
                    int n = snprintf(resp + off, sizeof(resp) - (size_t)off,
                                     "<lane id=\"%d\">"
                                     "<tx-bias>%.2f</tx-bias>"
                                     "<tx-power>%.4f</tx-power>"
                                     "<rx-power>%.4f</rx-power>"
                                     "</lane>",
                                     i + 1,
                                     result.data.xcvr.lane[i].tx_bias,
                                     result.data.xcvr.lane[i].tx_power,
                                     result.data.xcvr.lane[i].rx_power);
                    if (n < 0) break;
                    if (n >= (int)(sizeof(resp) - (size_t)off)) {
                        off = (int)sizeof(resp) - 1;
                        break;
                    }
                    off += n;
                }
                snprintf(resp + off, sizeof(resp) - (size_t)off, "</xcvr>");
            } else {
                snprintf(resp, sizeof(resp), "<xcvr port=\"%d\" error=\"%d\"/>", port, result.status);
            }
            (void)hal_rpc_send_text(conn, msg->request_id, 0, resp);
            break;
        }
        case NL_SWITCHD_OPTICS_MUX_PROBE: { // HAL_OPTICS_MUX_PROBE — read-only operator probe
            char resp[65536];
            size_t off = 0;
            bool truncated = false;
            int bus = 0;
            int mux_addr = 0x58;
            int branches[NETLAB_OPTICS_MUX_MAX_BRANCHES] = {0x01, 0x02};
            nl_board_profile board;

            memset(&board, 0, sizeof(board));
            if (nl_platform_board_get(&board)) {
                bus = board.i2c_bus;
                mux_addr = board.mux_addr;
                branches[0] = board.fci_mux[0];
                branches[1] = board.fci_mux[1];
            }

            if (payload[0]) {
                int parsed_bus = 0;
                int parsed_mux = 0;
                if (sscanf(payload, "bus=%i mux=%i", &parsed_bus,
                           &parsed_mux) == 2) {
                    bus = parsed_bus;
                    mux_addr = parsed_mux;
                }
            }

            op.type = SDK_OP_OPTICS_MUX_PROBE;
            op.args.optics_mux_probe.bus = bus;
            op.args.optics_mux_probe.mux_addr = mux_addr;
            op.args.optics_mux_probe.branch[0] = branches[0];
            op.args.optics_mux_probe.branch[1] = branches[1];
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_PLATFORM_POLL, 30000);
            if (result.status != 0 ||
                !result.data.optics_mux_probe.complete) {
                snprintf(resp, sizeof(resp),
                         "<optics-mux-probe error=\"%d\"/>",
                         result.status != 0 ? result.status : -EIO);
                (void)hal_rpc_send_text(conn, msg->request_id,
                                        NL_ERR_SDK_CALL_FAILED, resp);
                break;
            }

            hal_optics_mux_probe_result *probe =
                &result.data.optics_mux_probe;
            append_rpc_text(resp, sizeof(resp), &off, &truncated,
                            "<optics-mux-probe bus=\"%d\" mux=\"0x%02x\" "
                            "control-before=\"0x%02x\" "
                            "restore-status=\"%d\" complete=\"true\" "
                            "generation=\"%llu\" sampled-monotonic-ms=\"%llu\">",
                            probe->bus, probe->mux_addr,
                            probe->control_before >= 0 ?
                                probe->control_before : 0,
                            probe->restore_status,
                            (unsigned long long)probe->generation,
                            (unsigned long long)probe->sampled_monotonic_ms);
            for (int b = 0; b < probe->branch_count; b++) {
                hal_optics_mux_branch_dump *branch = &probe->branch[b];
                append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                "<branch value=\"0x%02x\" "
                                "select-status=\"%d\" "
                                "control-after=\"0x%02x\">",
                                branch->mux_value, branch->select_status,
                                branch->control_after >= 0 ?
                                    branch->control_after : 0);
                append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                "<scan start=\"0x%02x\" count=\"%d\">",
                                branch->scan_start, branch->scan_count);
                for (int i = 0; i < branch->scan_count; i++) {
                    int addr = branch->scan_start + i;
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                    "<dev addr=\"0x%02x\" status=\"%d\"/>",
                                    addr, branch->scan_status[i]);
                }
                append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                "</scan>");
                for (int a = 0; a < branch->addr_count; a++) {
                    hal_optics_mux_addr_dump *dump = &branch->addr[a];
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                    "<addr value=\"0x%02x\" page=\"%d\" "
                                    "offset=\"%d\" status=\"%d\" "
                                    "length=\"%d\">",
                                    dump->addr, dump->page, dump->offset,
                                    dump->status, dump->length);
                    for (int i = 0; i < dump->length; i++)
                        append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                        "%02x", dump->bytes[i]);
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                    "</addr>");
                }
                append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                "</branch>");
            }
            append_rpc_text(resp, sizeof(resp), &off, &truncated,
                            "<truncated>%d</truncated>"
                            "</optics-mux-probe>", truncated ? 1 : 0);
            (void)hal_rpc_send_text(conn, msg->request_id, 0, resp);
            break;
        }
        case NL_SWITCHD_FAN_SPEED_GET: { // HAL_GET_FAN_SPEED
            int fan_id = 0;
            if (msg->payload_len > 0) fan_id = atoi(payload);
            char resp[64];
            snprintf(resp, sizeof(resp),
                     "<fan id=\"%d\" status=\"unsupported\"/>", fan_id);
            (void)hal_rpc_send_text(conn, msg->request_id,
                                    NL_ERR_UNSUPPORTED_FEATURE, resp);
            break;
        }
        case NL_SWITCHD_TEMPERATURE_GET: { // HAL_GET_TEMPERATURE
            float temp_c = 0.0f;
            int st;
            char resp[128];

            op.type = SDK_OP_GET_SWITCH_SENSORS;
            op.args.switch_sensors.first = 0;
            op.args.switch_sensors.count = 1;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_PLATFORM_POLL, 2000);
            st = result.status;
            if (st == 0) {
                st = -1;
                for (int i = 0; i < result.data.switch_sensors.n_sensors; i++) {
                    if (result.data.switch_sensors.sensor[i].index == 0 &&
                        result.data.switch_sensors.sensor[i].valid) {
                        temp_c = result.data.switch_sensors.sensor[i].value;
                        st = 0;
                        break;
                    }
                }
            }
            if (st == 0) {
                snprintf(resp, sizeof(resp),
                         "<temperature source=\"switch-asic\" unit=\"celsius\">"
                         "%.1f</temperature>", temp_c);
            } else {
                snprintf(resp, sizeof(resp),
                         "<temperature source=\"switch-asic\" error=\"%d\"/>",
                         st);
            }
            (void)hal_rpc_send_text(conn, msg->request_id, 0, resp);
            break;
        }
        case NL_SWITCHD_SWITCH_SENSORS_GET: { // HAL_GET_SWITCH_SENSORS: SBUS digital sensors
            struct sdk_result *sample;
            char resp[8192];
            int off;
            int status = 0;

            sample = calloc(1, sizeof(*sample));
            if (!sample) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_CAPABILITY_INSUFFICIENT);
                break;
            }
            memset(&result, 0, sizeof(result));
            for (int sensor = 0; sensor < NETLAB_SWITCH_SENSOR_MAX; sensor++) {
                sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                memset(sample, 0, sizeof(*sample));
                op.type = SDK_OP_GET_SWITCH_SENSORS;
                op.args.switch_sensors.first = sensor;
                op.args.switch_sensors.count = 1;
                status = sdk_exec_with_prio(
                    ctx->exec, &op, sample,
                    SDK_PRIO_PLATFORM_POLL, 2000);
                if (status != 0)
                    break;
                if (sample->data.switch_sensors.n_sensors > 0 &&
                    result.data.switch_sensors.n_sensors <
                        NETLAB_SWITCH_SENSOR_MAX) {
                    int target = result.data.switch_sensors.n_sensors++;

                    result.data.switch_sensors.sensor[target] =
                        sample->data.switch_sensors.sensor[0];
                }
            }
            free(sample);
            result.status = status;
            result.sdk_status = status;
            off = hal_rpc_format_switch_sensors(&result, resp, sizeof(resp));
            send_formatted_rpc_response(conn, msg->request_id, result.status,
                                        resp, sizeof(resp), off);
            break;
        }
        case NL_SWITCHD_BOARD_ENV_GET: { // Internal read-only board I2C sampling
            struct sdk_result *sample;
            char resp[32768];
            nl_board_profile board;
            static const int sample_count = 4;
            int branches[sample_count];
            int status = 0;
            int off;

            if (pthread_mutex_trylock(&g_board_env_rpc_lock) != 0) {
                snprintf(resp, sizeof(resp),
                         "<board-environment status=\"%d\" "
                         "source=\"board-i2c\" error=\"request-in-progress\"/>",
                         -EBUSY);
                (void)hal_rpc_send_text(conn, msg->request_id, -EBUSY, resp);
                break;
            }
            memset(&board, 0, sizeof(board));
            memset(&result, 0, sizeof(result));
            if (!nl_platform_board_get(&board)) {
                snprintf(resp, sizeof(resp),
                         "<board-environment status=\"-1\" "
                         "source=\"board-i2c\" error=\"board-contract-missing\"/>");
                (void)hal_rpc_send_text(conn, msg->request_id, -1, resp);
                pthread_mutex_unlock(&g_board_env_rpc_lock);
                break;
            }
            sample = calloc(1, sizeof(*sample));
            if (!sample) {
                snprintf(resp, sizeof(resp),
                         "<board-environment status=\"%d\" "
                         "source=\"board-i2c\" error=\"out-of-memory\"/>",
                         -ENOMEM);
                (void)hal_rpc_send_text(conn, msg->request_id, -ENOMEM,
                                        resp);
                pthread_mutex_unlock(&g_board_env_rpc_lock);
                break;
            }
            snprintf(result.data.board_env.board_model,
                     sizeof(result.data.board_env.board_model), "%s",
                     board.model);
            result.data.board_env.bus = board.i2c_bus;
            result.data.board_env.mux_addr = board.mux_addr;
            result.data.board_env.mux_before = -1;
            result.data.board_env.restore_status = 0;
            branches[0] = board.fci_mux[0];
            branches[1] = board.fci_mux[1];
            branches[2] = board.environment_mux;
            branches[3] = board.power_mux;

            for (int sample_index = 0; sample_index < sample_count;
                 sample_index++) {
                hal_board_env_result *src;
                hal_board_env_result *dst = &result.data.board_env;

                sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                memset(sample, 0, sizeof(*sample));
                op.type = SDK_OP_BOARD_ENV_GET;
                op.args.board_env.sample = sample_index;
                op.args.board_env.bus = board.i2c_bus;
                op.args.board_env.mux_addr = board.mux_addr;
                op.args.board_env.branch = branches[sample_index];
                op.args.board_env.cpld_ram_addr = board.cpld_ram_addr;
                op.args.board_env.reset_gpio_addr = board.reset_gpio_addr;
                status = sdk_exec_with_prio(
                    ctx->exec, &op, sample,
                    SDK_PRIO_PLATFORM_POLL, 3000);
                if (status != 0) {
                    dst->sample_failures++;
                    break;
                }
                src = &sample->data.board_env;
                dst->sample_count += src->sample_count;
                dst->sample_failures += src->sample_failures;
                if (dst->mux_before < 0)
                    dst->mux_before = src->mux_before;
                if (src->restore_status != 0)
                    dst->restore_status = src->restore_status;
                for (int i = 0; i < src->sensor_count &&
                     dst->sensor_count < NETLAB_BOARD_ENV_MAX_SENSORS; i++)
                    dst->sensor[dst->sensor_count++] = src->sensor[i];
                for (int i = 0; i < src->responder_count &&
                     dst->responder_count <
                         NETLAB_BOARD_ENV_MAX_RESPONDERS; i++)
                    dst->responder[dst->responder_count++] =
                        src->responder[i];
            }
            free(sample);
            result.status = status;
            result.sdk_status = status;
            off = hal_rpc_format_board_env(&result, resp, sizeof(resp));
            send_formatted_rpc_response(conn, msg->request_id, result.status,
                                        resp, sizeof(resp), off);
            pthread_mutex_unlock(&g_board_env_rpc_lock);
            break;
        }
        case NL_SWITCHD_PORT_GET_INVENTORY: { // HAL_GET_PORT_INVENTORY
            char resp[16384];
            size_t off = 0;
            bool truncated = false;
            int n = ctx->num_cardinal_ports;

            if (n < 0) n = 0;
            if (n > 64) n = 64;

            append_rpc_text(resp, sizeof(resp), &off, &truncated, "<ports>");
            for (int i = 0; i < n; i++) {
                nl_port_entry entry;
                if (nl_ifid_get_by_logical_port(ctx->cardinal_ports[i],
                                                 &entry)) {
                    append_rpc_text(
                        resp, sizeof(resp), &off, &truncated,
                        "<port id=\"%d\" mode=\"%d\" "
                        "name=\"%s\" role=\"%s\" "
                        "speed=\"%llu\" flags=\"%u\"/>",
                        ctx->cardinal_ports[i], -1,
                        entry.canonical_name, entry.role,
                        (unsigned long long)entry.default_speed,
                        entry.flags);
                } else {
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                    "<port id=\"%d\" mode=\"%d\"/>",
                                    ctx->cardinal_ports[i], -1);
                }
            }
            append_rpc_text(resp, sizeof(resp), &off, &truncated,
                            "</ports>");

            if (truncated)
                (void)hal_rpc_send_text(conn, msg->request_id,
                                        NL_ERR_CAPABILITY_INSUFFICIENT,
                                        "port inventory response truncated");
            else
                (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                           (u32)off);
            break;
        }
        case NL_SWITCHD_PVID_SET: { // HAL_PVID_SET
            int port = 0, vid = 0;
            nl_port_entry entry;
            if (!payload_int_range(payload, "port", 1, INT_MAX, &port) ||
                !payload_int_range(payload, "vid", 1, 4094, &vid) ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_PVID_SET;
            op.args.vlan.port = port;
            op.args.vlan.vid = (u16)vid;
            int st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                        SDK_PRIO_CONFIG_CHANGE, 10000);
            nl_send_response(conn, msg->request_id, st);
            NL_LOG_INFO("PVID set: port=%d vid=%d st=%d", port, vid, st);
            break;
        }
        case NL_SWITCHD_VLAN_GET_STATE: { // HAL_VLAN_GET_STATE — read-back via executor
            int vid = 0;
            if (msg->payload_len > 0)
                sscanf(payload, "vid=%d", &vid);
            if (vid <= 0 && msg->payload_len > 0)
                vid = atoi(payload);

            op.type = SDK_OP_GET_VLAN_STATE;
            op.args.vlan.vid = (u16)vid;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 10000);

            char resp[64];
            snprintf(resp, sizeof(resp), "vlan=%d exists=%d",
                     vid, result.status == 0 && result.data.vlan_state.exists);
            (void)hal_rpc_send_text(conn, msg->request_id, result.status,
                                    resp);
            break;
        }
        case NL_SWITCHD_PORT_MODE_SET: { // HAL_PORT_MODE_SET
            char mode_str[16];
            int port = 0, vid = 0;
            int consumed = -1;
            nl_port_entry entry;
            memset(mode_str, 0, sizeof(mode_str));
            if (sscanf(payload, "port=%d mode=%15s vid=%d %n",
                       &port, mode_str, &vid, &consumed) != 3 ||
                !payload_fully_consumed(payload, consumed) ||
                port <= 0 || vid < 0 || vid > 4094 ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            int st = -1;
            // tolerate VLAN already exists (common across test scenarios)
            if (strcmp(mode_str, "access") == 0 && vid > 0) {
                op.type = SDK_OP_VLAN_CREATE;
                op.args.vlan.vid = (u16)vid;
                st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                        SDK_PRIO_CONFIG_CHANGE, 10000);
                if (st == 71) st = 0; // FM_ERR_VLAN_ALREADY_EXISTS is OK
                if (st == 0) {
                    sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                    memset(&result, 0, sizeof(result));
                    op.type = SDK_OP_PVID_SET;
                    op.args.vlan.port = port;
                    op.args.vlan.vid = (u16)vid;
                    st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                            SDK_PRIO_CONFIG_CHANGE, 10000);
                }
                if (st == 0) {
                    sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                    memset(&result, 0, sizeof(result));
                    op.type = SDK_OP_VLAN_ADD_PORT;
                    op.args.vlan.vid = (u16)vid;
                    op.args.vlan.port = port;
                    op.args.vlan.tagged = false;
                    st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                            SDK_PRIO_CONFIG_CHANGE, 10000);
                }
                NL_LOG_INFO("port mode=access: port=%d vid=%d", port, vid);
            } else if (strcmp(mode_str, "trunk") == 0) {
                op.type = SDK_OP_PVID_SET;
                op.args.vlan.port = port;
                op.args.vlan.vid = (u16)vid;
                st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                        SDK_PRIO_CONFIG_CHANGE, 10000);
                NL_LOG_INFO("port mode=trunk: port=%d native-vid=%d", port, vid);
            } else if (strcmp(mode_str, "hybrid") == 0 && vid > 0) {
                op.type = SDK_OP_PVID_SET;
                op.args.vlan.port = port;
                op.args.vlan.vid = (u16)vid;
                st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                        SDK_PRIO_CONFIG_CHANGE, 10000);
                if (st == 0) {
                    sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                    memset(&result, 0, sizeof(result));
                    op.type = SDK_OP_VLAN_CREATE;
                    op.args.vlan.vid = (u16)vid;
                    st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                            SDK_PRIO_CONFIG_CHANGE, 10000);
                    if (st == 71) st = 0; // VLAN already exists
                }
                if (st == 0) {
                    sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                    memset(&result, 0, sizeof(result));
                    op.type = SDK_OP_VLAN_ADD_PORT;
                    op.args.vlan.vid = (u16)vid;
                    op.args.vlan.port = port;
                    op.args.vlan.tagged = false;
                    st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                            SDK_PRIO_CONFIG_CHANGE, 10000);
                }
                NL_LOG_INFO("port mode=hybrid: port=%d native-vid=%d", port, vid);
            } else {
                NL_LOG_ERR("port mode: unknown mode=%s or invalid vid=%d", mode_str, vid);
            }

            // After port mode config succeeds, set STP forwarding + parser
            if (st == 0 && vid > 0) {
                sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                memset(&result, 0, sizeof(result));
                op.type = SDK_OP_VLAN_STP_SET;
                op.args.vlan.vid = (u16)vid;
                op.args.vlan.port = port;
                op.args.vlan.stp_state = 3; // FM_STP_STATE_FORWARDING
                int stp_st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                                 SDK_PRIO_CONFIG_CHANGE, 10000);
                if (stp_st != 0) {
                    NL_LOG_WARN("port mode: STP set failed port=%d err=%d", port, stp_st);
                    st = stp_st;
                }

                if (st == 0) {
                    sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
                    memset(&result, 0, sizeof(result));
                    op.type = SDK_OP_PORT_PARSER_SET;
                    op.args.port.port = port;
                    op.args.port.speed = 2; // FM_PORT_PARSER_STOP_AFTER_L4
                    int prs_st = sdk_exec_with_prio(ctx->exec, &op, &result,
                                                     SDK_PRIO_CONFIG_CHANGE, 10000);
                    if (prs_st != 0) {
                        NL_LOG_WARN("port mode: parser set failed port=%d err=%d", port, prs_st);
                        st = prs_st;
                    }
                }
            }
            nl_send_response(conn, msg->request_id, st);
            break;
        }
        case NL_SWITCHD_PACKET_RX_POLL: { // HAL_PACKET_RX_POLL — direct poll (P4, not via executor)
            u8 buf[2048];
            int n = hal_packet_rx_poll(ctx->sw, buf, sizeof(buf));
            if (n <= 0) {
                nl_send_response(conn, msg->request_id, 0);
                break;
            }
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, buf, (u32)n);
            break;
        }
        case NL_SWITCHD_PACKET_RX_POLL_META: { // HAL_PACKET_RX_POLL_META — port/vlan header + frame
            u8 buf[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];
            int src_port = 0;
            int vlan = 0;
            u64 captured_at = 0;
            int n = hal_packet_rx_poll_stamped(ctx->sw, buf + NL_PACKET_EVENT_HEADER,
                                            NETLAB_PACKET_IO_MAX,
                                            &src_port, &vlan, &captured_at);
            if (n <= 0) {
                nl_send_response(conn, msg->request_id, 0);
                break;
            }
            n = nl_packet_event_encode(buf, sizeof(buf), src_port, vlan, captured_at,
                                        buf + NL_PACKET_EVENT_HEADER, n);
            if (n < 0) { nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE); break; }
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, buf,
                                       (u32)n);
            break;
        }
        case NL_SWITCHD_LAG_GET_ALL: { // HAL_LAG_GET_ALL
            op.type = SDK_OP_LAG_GET_ALL;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 10000);
            if (result.status) {
                nl_send_response(conn, msg->request_id, result.status); break;
            }
            char resp[SWITCHD_LAG_XML_BUFFER_SIZE] = {0};
            size_t off = 0;
            bool truncated = false;
            if (fm10k_native_profile())
                append_rpc_text(resp, sizeof(resp), &off, &truncated,
                    "<lags native-generation=\"%016llx\">\n",
                    (unsigned long long)fm10k_native_generation());
            else
                append_rpc_text(resp, sizeof(resp), &off, &truncated, "<lags>\n");
            for (int i = 0; i < result.data.lag_list.n_lags &&
                 i < NETLAB_MAX_AE; i++) {
                const hal_lag_readback_entry *entry =
                    &result.data.lag_list.lag[i];

                {
                    int readback_status = entry->logical_port_status ?
                        entry->logical_port_status : entry->member_status;
                    char ifname[16];
                    if (entry->ae_id >= 0)
                        snprintf(ifname, sizeof(ifname), "ae%d", entry->ae_id);
                    else
                        snprintf(ifname, sizeof(ifname), "unmapped");
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                        "  <lag ae=\"%d\" name=\"%s\" id=\"%d\" logical-port=\"%d\">\n",
                        entry->ae_id, ifname, entry->lag_id,
                        entry->logical_port);
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                        "    <member-readback status=\"%s\" code=\"%d\"/>\n",
                        readback_status ? "error" : "ok", readback_status);
                    if (fm10k_native_profile())
                        append_rpc_text(resp, sizeof(resp), &off, &truncated,
                            "    <qos-readback status=\"%s\" code=\"%d\" trust=\"%d\" default-priority=\"%d\"/>\n",
                            entry->qos_status ? "error" : "ok", entry->qos_status,
                            entry->qos_trust, entry->qos_default_priority);
                    for (int member = 0; !readback_status && member < entry->n_members; member++) {
                        append_rpc_text(resp, sizeof(resp), &off, &truncated,
                            "    <member port=\"%d\"/>\n",
                            entry->members[member]);
                        if (truncated)
                            break;
                    }
                    append_rpc_text(resp, sizeof(resp), &off, &truncated,
                                    "  </lag>\n");
                }
                if (truncated)
                    break;
            }
            append_rpc_text(resp, sizeof(resp), &off, &truncated, "</lags>\n");
            if (truncated) {
                NL_LOG_WARN("LAG XML response truncated at %zu bytes", off);
                nl_send_response(conn, msg->request_id, NL_ERR_CAPABILITY_INSUFFICIENT); break;
            }
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_LAG_DEL_PORT:
        case NL_SWITCHD_LAG_ADD_PORT: {
            int lag_id = 0, port = 0;
            uint64_t generation = 0;
            nl_port_entry entry;
            if (!nl_lag_runtime_request_parse(payload, fm10k_native_profile(),
                                             &lag_id, &port, &generation) ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = msg->method == NL_SWITCHD_LAG_ADD_PORT ?
                SDK_OP_LAG_ADD_PORT : SDK_OP_LAG_DEL_PORT;
            op.args.lag.lag_id = lag_id;
            op.args.lag.port = port;
            op.args.lag.native_generation = generation;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 30000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_PACKET_TX: { // HAL_PACKET_TX — via executor
            int tx_port = 0;
            const u8 *raw = msg->payload;
            u32 frame_len;
            int header = 2, vlan = 0;
            u64 issued_at = 0;
            if (msg->payload_len >= 8 && !memcmp(raw, "NLPKT001", 8))
                header = nl_packet_event_decode(raw, (int)msg->payload_len, &tx_port, &vlan, &issued_at);
            else if (msg->payload_len >= 2)
                tx_port = ((int)raw[0] << 8) | raw[1];

            if (header <= 0 || msg->payload_len <= (u32)header ||
                msg->payload_len > (u32)(NETLAB_PACKET_IO_MAX + header) || tx_port <= 0) {
                NL_LOG_WARN("packet tx invalid payload_len=%u max=%u",
                            msg->payload_len,
                            (u32)(NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER));
                result.status = -1;
            } else {
                frame_len = msg->payload_len - (u32)header;
                NL_LOG_DBG("packet tx request port=%d len=%u",
                           tx_port, frame_len);
                op.type = SDK_OP_PACKET_TX;
                op.issued_at = issued_at;
                op.args.pkt_tx.port = tx_port;
                op.args.pkt_tx.len = (int)frame_len;
                memcpy(op.args.pkt_tx.data, raw + header, frame_len);
                sdk_exec_with_prio(ctx->exec, &op, &result,
                                   SDK_PRIO_CONTROL_PACKET, 10000);
                if (result.status != 0) {
                    NL_LOG_WARN("packet tx failed port=%d len=%u status=%d",
                                tx_port, frame_len, result.status);
                }
            }
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_STP_SNAPSHOT_PAGE_GET: {
            nl_stp_snapshot_page_request request = {0};
            u8 *resp = NULL;
            u64 invalidation_generation = 0;
            int encoded = -1;

            if (nl_stp_snapshot_page_request_decode(
                    msg->payload, msg->payload_len, &request) != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_MALFORMED_REQUEST);
                break;
            }
            resp = malloc(NETLAB_MAX_MSG);
            if (!resp) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_CAPABILITY_INSUFFICIENT);
                break;
            }
            if (request.generation == 0) {
                pthread_mutex_lock(&g_stp_snapshot_rpc_lock);
                invalidation_generation =
                    g_stp_snapshot_invalidation_generation;
                pthread_mutex_unlock(&g_stp_snapshot_rpc_lock);

                op.type = SDK_OP_GET_STP_TABLE;
                sdk_exec_with_prio(ctx->exec, &op, &result,
                                   SDK_PRIO_READBACK, 10000);
                if (result.status != 0 ||
                    !result.data.stp_table.complete) {
                    nl_stp_snapshot_reset(&result.data.stp_table);
                    free(resp);
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_SDK_CALL_FAILED);
                    break;
                }
                pthread_mutex_lock(&g_stp_snapshot_rpc_lock);
                if (invalidation_generation ==
                    g_stp_snapshot_invalidation_generation) {
                    nl_stp_snapshot_reset(&g_stp_snapshot_rpc_cache);
                    g_stp_snapshot_rpc_cache = result.data.stp_table;
                    result.data.stp_table.entries = NULL;
                    encoded = nl_stp_snapshot_page_encode(
                        &g_stp_snapshot_rpc_cache, 0,
                        resp, NETLAB_MAX_MSG);
                }
                pthread_mutex_unlock(&g_stp_snapshot_rpc_lock);
                nl_stp_snapshot_reset(&result.data.stp_table);
            } else {
                pthread_mutex_lock(&g_stp_snapshot_rpc_lock);
                if (g_stp_snapshot_rpc_cache.complete &&
                    request.generation ==
                        g_stp_snapshot_rpc_cache.generation &&
                    request.offset <=
                        g_stp_snapshot_rpc_cache.total_entries) {
                    encoded = nl_stp_snapshot_page_encode(
                        &g_stp_snapshot_rpc_cache, request.offset,
                        resp, NETLAB_MAX_MSG);
                }
                pthread_mutex_unlock(&g_stp_snapshot_rpc_lock);
            }
            if (encoded <= 0)
                (void)hal_rpc_send_text(
                    conn, msg->request_id, NL_ERR_COMMIT_CONFLICT,
                    "STP snapshot generation changed");
            else
                (void)hal_rpc_send_payload(conn, msg->request_id, 0,
                                           resp, (u32)encoded);
            free(resp);
            break;
        }
        case NL_SWITCHD_STP_RUNTIME_SET: { // HAL_RUNTIME_STP_SET — operational guard override
            int vid = 0, port = 0, state = 0;
            int consumed = -1;
            if (sscanf(payload, "vid=%d port=%d state=%d %n",
                       &vid, &port, &state, &consumed) != 3 ||
                !payload_fully_consumed(payload, consumed) ||
                vid < 1 || vid > 4094 || port <= 0 ||
                state < 0 || state > 4) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_RUNTIME_STP_SET;
            op.args.vlan.vid = (u16)vid;
            op.args.vlan.port = port;
            op.args.vlan.stp_state = state;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 10000);
            if (result.status == 0) {
                NL_LOG_NOTICE("runtime STP override: vlan=%d port=%d state=%d",
                              vid, port, state);
            } else {
                NL_LOG_WARN("runtime STP override failed: vlan=%d port=%d state=%d err=%d",
                            vid, port, state, result.status);
            }
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_MAC_SNAPSHOT_GET: {
            u8 *response = NULL;
            int response_len = -1;

            op.type = SDK_OP_GET_MAC_TABLE;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 10000);
            if (result.status == 0) {
                response = malloc(NETLAB_MAX_MSG);
                if (response)
                    response_len = nl_mac_snapshot_encode(
                        &result.data.mac_table, response, NETLAB_MAX_MSG);
                if (response_len < 0)
                    result.status = NL_ERR_CAPABILITY_INSUFFICIENT;
            }
            if (result.status == 0)
                (void)hal_rpc_send_payload(conn, msg->request_id, 0,
                                           response, (u32)response_len);
            else
                (void)hal_rpc_send_text(
                    conn, msg->request_id, result.status,
                    result.error_msg ? result.error_msg :
                    "complete MAC snapshot unavailable");
            free(response);
            nl_mac_snapshot_reset(&result.data.mac_table);
            break;
        }
        case NL_SWITCHD_ACL_COUNTER_SNAPSHOT_GET: {
            nl_acl_counter_query *query = NULL;
            u8 *response = NULL;
            size_t response_size;
            int response_len = -1;
            int exec_status;

            query = calloc(1, sizeof(*query));
            if (!query) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_CAPABILITY_INSUFFICIENT);
                break;
            }
            if (nl_acl_counter_query_decode(
                    msg->payload, msg->payload_len, query) != 0) {
                free(query);
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_MALFORMED_REQUEST);
                break;
            }
            response_size =
                nl_acl_counter_snapshot_wire_size(query->n_entries);
            response = response_size > 0 ? malloc(response_size) : NULL;
            if (!response) {
                free(query);
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_CAPABILITY_INSUFFICIENT);
                break;
            }

            op.type = SDK_OP_GET_ACL_COUNTER_SNAPSHOT;
            op.args.acl_counter_query = query;
            exec_status = sdk_exec_with_prio(
                ctx->exec, &op, &result, SDK_PRIO_COUNTER, 10000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (result.status == 0 &&
                result.data.acl_counter_snapshot.complete &&
                result.data.acl_counter_snapshot.n_entries ==
                    query->n_entries) {
                response_len = nl_acl_counter_snapshot_encode(
                    &result.data.acl_counter_snapshot,
                    response, response_size);
            }
            if (result.status == 0 && response_len > 0) {
                (void)hal_rpc_send_payload(conn, msg->request_id, 0,
                                           response, (u32)response_len);
            } else {
                (void)hal_rpc_send_text(
                    conn, msg->request_id,
                    result.status != 0 ? result.status :
                                         NL_ERR_SDK_CALL_FAILED,
                    "complete ACL counter snapshot unavailable");
            }
            free(response);
            free(query);
            break;
        }
        case NL_SWITCHD_PFE_RESOURCES_GET: { // HAL_GET_PFE_RESOURCES
            char resp[8192];
            int off;

            op.type = SDK_OP_GET_PFE_RESOURCES;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 30000);
            off = hal_rpc_format_pfe_resources(&result, resp, sizeof(resp));
            send_formatted_rpc_response(conn, msg->request_id, result.status,
                                        resp, sizeof(resp), off);
            break;
        }
        case NL_SWITCHD_MAC_EVENTS_GET: { // HAL_GET_MAC_UPDATE_EVENTS
            const size_t resp_size = 240 * 1024;
            char *resp = calloc(1, resp_size);
            int off = 0;

            if (!resp) {
                nl_send_response(conn, msg->request_id, NL_ERR);
                break;
            }
            off = sdk_mac_update_ring_format(resp, resp_size);
            (void)hal_rpc_send_payload(conn, msg->request_id, 0,
                                       resp, (u32)off);
            free(resp);
            break;
        }
        case NL_SWITCHD_SWITCH_CONFIG_GET: { // HAL_GET_SWITCH_CONFIG: ASIC runtime read-back
            char resp[32768];
            int off;

            op.type = SDK_OP_GET_SWITCH_CONFIG;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 30000);
            off = hal_rpc_format_switch_config(&result, resp, sizeof(resp));
            send_formatted_rpc_response(conn, msg->request_id, result.status,
                                        resp, sizeof(resp), off);
            break;
        }
        case NL_SWITCHD_CONTROL_PLANE_PROTECTION_GET: { // HAL_GET_CONTROL_PLANE_PROTECTION
            char resp[8192];
            int off;

            op.type = SDK_OP_GET_CONTROL_PLANE_PROTECTION;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 30000);
            off = hal_rpc_format_control_plane_protection(&result, resp,
                                                          sizeof(resp));
            send_formatted_rpc_response(conn, msg->request_id, result.status,
                                        resp, sizeof(resp), off);
            break;
        }
        case NL_SWITCHD_L2_RATE_LIMIT_GET: { // HAL_GET_STORM_CONTROL / HAL_GET_*_RATE_LIMIT
            bool ingress_rate_limit =
                strncmp(payload, "ingress-rate-limit", 18) == 0;
            bool egress_rate_limit =
                strncmp(payload, "egress-rate-limit", 17) == 0;
            char resp[4096];
            int off = 0;
            int exec_status;

            if (egress_rate_limit) {
                op.args.qos_readback.kind =
                    HAL_QOS_READBACK_EGRESS_RATE_LIMIT;
            } else if (ingress_rate_limit) {
                op.args.qos_readback.kind =
                    HAL_QOS_READBACK_INGRESS_RATE_LIMIT;
            } else {
                op.args.qos_readback.kind =
                    HAL_QOS_READBACK_STORM_CONTROL;
            }
            op.type = SDK_OP_GET_QOS_READBACK;
            exec_status = sdk_exec_with_prio(
                ctx->exec, &op, &result, SDK_PRIO_READBACK, 30000);

            if (egress_rate_limit) {
                off = hal_rpc_format_egress_rate_limit(
                    result.data.qos_readback.entries.egress_rate_limit,
                    result.data.qos_readback.n_entries, resp, sizeof(resp));
            } else {
                off = ingress_rate_limit ?
                    hal_rpc_format_ingress_rate_limit(
                        result.data.qos_readback.entries.storm_control,
                        result.data.qos_readback.n_entries,
                        resp, sizeof(resp)) :
                    hal_rpc_format_storm_control(
                        result.data.qos_readback.entries.storm_control,
                        result.data.qos_readback.n_entries,
                        resp, sizeof(resp));
            }
            send_formatted_rpc_response(conn, msg->request_id, exec_status,
                                        resp, sizeof(resp), off);
            break;
        }
        case NL_SWITCHD_COS_GET: { // HAL_GET_CLASS_OF_SERVICE
            bool dscp = strcmp(payload, "dscp-map") == 0;
            bool forwarding = strncmp(payload, "forwarding", 10) == 0;
            bool flow_control = strncmp(payload, "flow-control", 12) == 0;
            bool scheduler = strncmp(payload, "scheduler", 9) == 0;
            bool queues = strncmp(payload, "queues", 6) == 0;
            bool watermarks = strncmp(payload, "watermarks", 10) == 0;
            char resp[65536];
            int off;
            int exec_status;

            if (dscp) {
                op.args.qos_readback.kind = HAL_QOS_READBACK_DSCP_MAP;
            } else if (flow_control) {
                op.args.qos_readback.kind = HAL_QOS_READBACK_FLOW_CONTROL;
            } else if (forwarding) {
                op.args.qos_readback.kind = HAL_QOS_READBACK_PRIORITY_MAP;
            } else if (scheduler) {
                op.args.qos_readback.kind = HAL_QOS_READBACK_SCHEDULERS;
            } else if (queues) {
                op.args.qos_readback.kind = HAL_QOS_READBACK_QUEUES;
            } else if (watermarks) {
                op.args.qos_readback.kind = HAL_QOS_READBACK_WATERMARKS;
            } else {
                op.args.qos_readback.kind = HAL_QOS_READBACK_INTERFACES;
            }
            op.type = SDK_OP_GET_QOS_READBACK;
            exec_status = sdk_exec_with_prio(
                ctx->exec, &op, &result, SDK_PRIO_READBACK, 30000);

            if (dscp) {
                off = hal_rpc_format_qos_dscp_map(
                    result.data.qos_readback.entries.dscp_map,
                    result.data.qos_readback.n_entries, resp, sizeof(resp));
            } else if (flow_control) {
                off = hal_rpc_format_qos_flow_control(
                    &result.data.qos_readback.flow_control_global,
                    result.data.qos_readback.entries.flow_control,
                    result.data.qos_readback.n_entries,
                    resp, sizeof(resp));
            } else if (forwarding) {
                off = hal_rpc_format_qos_priority_map(
                    result.data.qos_readback.entries.priority_map,
                    result.data.qos_readback.n_entries,
                    resp, sizeof(resp));
            } else if (scheduler) {
                off = hal_rpc_format_qos_scheduler(
                    result.data.qos_readback.entries.schedulers,
                    result.data.qos_readback.n_entries,
                    resp, sizeof(resp));
            } else if (queues) {
                off = hal_rpc_format_qos_queues(
                    result.data.qos_readback.entries.queues,
                    result.data.qos_readback.n_entries,
                    resp, sizeof(resp));
            } else if (watermarks) {
                off = hal_rpc_format_qos_watermarks(
                    &result.data.qos_readback.watermark_global,
                    result.data.qos_readback.entries.watermarks,
                    result.data.qos_readback.n_entries,
                    resp, sizeof(resp));
            } else {
                off = hal_rpc_format_qos_interfaces(
                    result.data.qos_readback.entries.interfaces,
                    result.data.qos_readback.n_entries,
                    resp, sizeof(resp));
            }
            send_formatted_rpc_response(conn, msg->request_id, exec_status,
                                        resp, sizeof(resp), off);
            break;
        }
        case NL_SWITCHD_L2_SECURITY_COUNTERS_GET: { // HAL_GET_L2_SECURITY_USER_FILTER_COUNTERS
            int vid = payload_int(payload, "vid", 0);
            int port = payload_int(payload, "port", 0);
            char field[32] = {0};
            char mac_text[32] = {0};
            u8 mac[NL_MAC_ADDR_LEN] = {0};
            int mac_kind = L2_SECURITY_MAC_SOURCE;
            const char *match = "source-mac";
            const char *state = "missing";
            int exec_status;
            char resp[256];
            int off;

            if (!payload_word(payload, "field", field, sizeof(field)))
                (void)payload_word(payload, "match", field, sizeof(field));
            if (strcmp(field, "destination") == 0 ||
                strcmp(field, "destination-mac") == 0) {
                mac_kind = L2_SECURITY_MAC_DESTINATION;
                match = "destination-mac";
            } else if (field[0] &&
                       strcmp(field, "source") != 0 &&
                       strcmp(field, "source-mac") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            if (vid < 1 || vid > 4094 || port <= 0 ||
                !nl_ifid_is_user_port(port) ||
                !payload_word(payload, "mac", mac_text, sizeof(mac_text)) ||
                !nl_platform_parse_mac(mac_text, mac)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            op.type = SDK_OP_GET_L2_SECURITY_USER_FILTER_COUNTERS;
            op.args.l2_security_counter.vid = (u16)vid;
            op.args.l2_security_counter.port = port;
            op.args.l2_security_counter.mac_kind = mac_kind;
            memcpy(op.args.l2_security_counter.mac, mac, sizeof(mac));
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_COUNTER, 10000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;

            if (result.status != 0)
                state = "unavailable";
            else if (result.data.l2_security_counter.found)
                state = "installed";

            off = snprintf(resp, sizeof(resp),
                "<l2-security-user-filter vid=\"%d\" port=\"%d\" "
                "match=\"%s\" mac=\"%02x:%02x:%02x:%02x:%02x:%02x\" "
                "table=\"%d\" flow=\"%d\" state=\"%s\" "
                "packets=\"%llu\" octets=\"%llu\"/>\n",
                vid, port, match,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                result.data.l2_security_counter.table,
                result.data.l2_security_counter.flow,
                state,
                (unsigned long long)result.data.l2_security_counter.packets,
                (unsigned long long)result.data.l2_security_counter.octets);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_IPV4_ACL_COUNTERS_GET: { // HAL_GET_INGRESS_IPV4_ACL_COUNTERS
            hal_ingress_ipv4_acl_match *m = &op.args.ingress_ipv4_acl;
            const char *state = "missing";
            char src_ip[32];
            char dst_ip[32];
            char src_mask[32];
            char dst_mask[32];
            char src_port_range[32];
            char dst_port_range[32];
            char action[16] = "";
            struct in_addr addr;
            int exec_status;
            char resp[256];
            int off;

            m->vid = payload_int(payload, "vid", 0);
            m->port = payload_int(payload, "port", 0);
            if (payload_word(payload, "src-ip", src_ip, sizeof(src_ip))) {
                if (inet_pton(AF_INET, src_ip, &addr) != 1) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                m->has_src_ip = true;
                m->src_ip = ntohl(addr.s_addr);
                if (payload_word(payload, "src-mask", src_mask,
                                 sizeof(src_mask))) {
                    if (inet_pton(AF_INET, src_mask, &addr) != 1) {
                        nl_send_response(conn, msg->request_id,
                                         NL_ERR_INVALID_VALUE);
                        break;
                    }
                    m->src_ip_mask = ntohl(addr.s_addr);
                } else {
                    m->src_ip_mask = 0xffffffffU;
                }
                m->has_src_ip_mask = true;
            }
            if (payload_word(payload, "dst-ip", dst_ip, sizeof(dst_ip))) {
                if (inet_pton(AF_INET, dst_ip, &addr) != 1) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                m->has_dst_ip = true;
                m->dst_ip = ntohl(addr.s_addr);
                if (payload_word(payload, "dst-mask", dst_mask,
                                 sizeof(dst_mask))) {
                    if (inet_pton(AF_INET, dst_mask, &addr) != 1) {
                        nl_send_response(conn, msg->request_id,
                                         NL_ERR_INVALID_VALUE);
                        break;
                    }
                    m->dst_ip_mask = ntohl(addr.s_addr);
                } else {
                    m->dst_ip_mask = 0xffffffffU;
                }
                m->has_dst_ip_mask = true;
            }
            m->protocol = payload_int(payload, "proto", -1);
            if (m->protocol >= 0)
                m->has_protocol = true;
            m->dscp = payload_int(payload, "dscp", -1);
            if (m->dscp >= 0)
                m->has_dscp = true;
            m->ecn = payload_int(payload, "ecn", -1);
            if (m->ecn >= 0)
                m->has_ecn = true;
            m->src_port = payload_int(payload, "src-port", -1);
            if (m->src_port >= 0)
                m->has_src_port = true;
            m->dst_port = payload_int(payload, "dst-port", -1);
            if (m->dst_port >= 0)
                m->has_dst_port = true;
            if (payload_word(payload, "src-port-range",
                             src_port_range,
                             sizeof(src_port_range))) {
                if (!parse_port_range_text(src_port_range,
                                           &m->src_port_start,
                                           &m->src_port_end)) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                m->has_src_port_range = true;
            }
            if (payload_word(payload, "dst-port-range",
                             dst_port_range,
                             sizeof(dst_port_range))) {
                if (!parse_port_range_text(dst_port_range,
                                           &m->dst_port_start,
                                           &m->dst_port_end)) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                m->has_dst_port_range = true;
            }
            m->tcp_flags = payload_int(payload, "tcp-flags", -1);
            if (m->tcp_flags >= 0) {
                m->has_tcp_flags = true;
                m->tcp_flags_mask = 63;
                m->has_tcp_flags_mask = true;
            }
            {
                int parsed_tcp_flags_mask =
                    payload_int(payload, "tcp-flags-mask", -1);
                if (parsed_tcp_flags_mask >= 0) {
                    m->tcp_flags_mask = parsed_tcp_flags_mask;
                    m->has_tcp_flags_mask = true;
                }
            }
            if (payload_word(payload, "action", action, sizeof(action))) {
                if (strcmp(action, "count") == 0)
                    m->count_only = true;
                else if (strcmp(action, "drop") != 0) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
            }

            if (m->vid < 1 || m->vid > 4094 || m->port <= 0 ||
                !nl_ifid_is_user_port(m->port) ||
                (!m->has_src_ip && !m->has_dst_ip && !m->has_protocol &&
                 !m->has_dscp && !m->has_ecn &&
                 !m->has_src_port && !m->has_dst_port &&
                 !m->has_src_port_range && !m->has_dst_port_range &&
                 !m->has_tcp_flags) ||
                (m->has_src_ip &&
                 (!m->has_src_ip_mask ||
                  (m->src_ip_mask == 0xffffffffU &&
                   (m->src_ip == 0 || m->src_ip == 0xffffffffU)))) ||
                (m->has_dst_ip &&
                 (!m->has_dst_ip_mask ||
                 (m->dst_ip_mask == 0xffffffffU &&
                  (m->dst_ip == 0 || m->dst_ip == 0xffffffffU)))) ||
                (m->has_protocol &&
                 (m->protocol < 0 || m->protocol > 255)) ||
                (m->has_dscp && (m->dscp < 0 || m->dscp > 63)) ||
                (m->has_ecn && (m->ecn < 0 || m->ecn > 3)) ||
                (m->has_src_port &&
                 (m->src_port < 0 || m->src_port > 65535)) ||
                (m->has_dst_port &&
                 (m->dst_port < 0 || m->dst_port > 65535)) ||
                (m->has_src_port_range &&
                 (m->src_port_start < 0 ||
                  m->src_port_start > m->src_port_end ||
                  m->src_port_end > 65535)) ||
                (m->has_dst_port_range &&
                 (m->dst_port_start < 0 ||
                  m->dst_port_start > m->dst_port_end ||
                  m->dst_port_end > 65535)) ||
                (m->has_src_port && m->has_src_port_range) ||
                (m->has_dst_port && m->has_dst_port_range) ||
                ((m->has_src_port || m->has_dst_port ||
                  m->has_src_port_range || m->has_dst_port_range) &&
                 (!m->has_protocol ||
                  (m->protocol != 6 && m->protocol != 17))) ||
                (m->has_tcp_flags &&
                 (m->tcp_flags < 0 || m->tcp_flags > 63 ||
                  !m->has_protocol || m->protocol != 6)) ||
                (m->has_tcp_flags_mask &&
                 (m->tcp_flags_mask < 1 || m->tcp_flags_mask > 63)) ||
                (m->has_tcp_flags_mask && !m->has_tcp_flags) ||
                (m->has_tcp_flags && m->has_tcp_flags_mask &&
                 ((m->tcp_flags & ~m->tcp_flags_mask) != 0))) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            op.type = SDK_OP_GET_INGRESS_IPV4_ACL_COUNTERS;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_COUNTER, 10000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (result.status != 0)
                state = "unavailable";
            else if (result.data.ingress_ipv4_acl_counter.found)
                state = "installed";

            off = snprintf(resp, sizeof(resp),
                "<ingress-ipv4-acl vid=\"%d\" port=\"%d\" "
                "table=\"%d\" flow=\"%d\" state=\"%s\" "
                "packets=\"%llu\" octets=\"%llu\"/>\n",
                m->vid, m->port,
                result.data.ingress_ipv4_acl_counter.table,
                result.data.ingress_ipv4_acl_counter.flow,
                state,
                (unsigned long long)
                    result.data.ingress_ipv4_acl_counter.packets,
                (unsigned long long)
                    result.data.ingress_ipv4_acl_counter.octets);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_EGRESS_ACL_COUNTERS_GET: { // HAL_GET_EGRESS_ACL_COUNTERS
            const char *state = "unavailable";
            int port = payload_int(payload, "port", 0);
            int exec_status;
            char resp[192];
            int off;

            if (port <= 0 || !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            op.type = SDK_OP_GET_EGRESS_ACL_COUNTERS;
            op.args.egress_acl_counter.port = port;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_COUNTER, 10000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (result.status == 0 && result.data.egress_acl_counter.found)
                state = "installed";

            off = snprintf(resp, sizeof(resp),
                "<egress-acl port=\"%d\" state=\"%s\" "
                "packets=\"%llu\" octets=\"%llu\"/>\n",
                port, state,
                (unsigned long long)
                    result.data.egress_acl_counter.packets,
                (unsigned long long)
                    result.data.egress_acl_counter.octets);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_ACL_POLICER_COUNTERS_GET: { // HAL_GET_ACL_POLICER_COUNTERS
            hal_acl_policer_owner_result *owner =
                &result.data.acl_policer_owner;
            const char *state = "unavailable";
            char dst_mac_text[32] = {0};
            char dst_mac_norm[32] = {0};
            u8 dst_mac[6] = {0};
            u64 dst_mac_u64 = 0;
            int port = payload_int(payload, "port", 0);
            int rate_kbps = payload_int(payload, "rate-kbps", 0);
            int burst_bytes = payload_int(payload, "burst-bytes", 0);
            int exec_status;
            char resp[320];
            int off;

            if (port <= 0 || !nl_ifid_is_user_port(port) ||
                rate_kbps <= 0 || burst_bytes <= 0 ||
                !payload_word(payload, "dst-mac", dst_mac_text,
                              sizeof(dst_mac_text)) ||
                !nl_platform_parse_mac(dst_mac_text, dst_mac) ||
                (dst_mac[0] & 0x01)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            for (int i = 0; i < 6; i++)
                dst_mac_u64 = (dst_mac_u64 << 8) | dst_mac[i];
            snprintf(dst_mac_norm, sizeof(dst_mac_norm),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     dst_mac[0], dst_mac[1], dst_mac[2],
                     dst_mac[3], dst_mac[4], dst_mac[5]);

            op.type = SDK_OP_GET_ACL_POLICER_COUNTERS;
            op.args.acl_policer_owner.port = port;
            op.args.acl_policer_owner.dst_mac = dst_mac_u64;
            op.args.acl_policer_owner.rate_kbps = rate_kbps;
            op.args.acl_policer_owner.burst_bytes = burst_bytes;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_COUNTER, 10000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (result.status == 0 && owner->active && owner->ok)
                state = "installed";
            else if (result.status == 0 && !owner->active && owner->ok)
                state = "absent";
            else if (owner->active)
                state = "mismatch";

            off = snprintf(resp, sizeof(resp),
                "<acl-policer port=\"%d\" dst-mac=\"%s\" "
                "state=\"%s\" packets=\"%llu\" octets=\"%llu\" "
                "rate-kbps=\"%d\" burst-bytes=\"%d\" "
                "rate-readback=\"%d\" burst-readback=\"%d\" "
                "read-status=\"%d\" policer-read-status=\"%d\" "
                "mismatches=\"%d\"/>\n",
                port, dst_mac_norm, state,
                (unsigned long long)owner->packets,
                (unsigned long long)owner->octets,
                rate_kbps, burst_bytes,
                owner->rate_readback, owner->burst_readback,
                owner->read_status, owner->policer_read_status,
                owner->mismatches);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_ACL_INDEPENDENT_COUNTERS_GET: { // HAL_GET_ACL_INDEPENDENT_COUNTERS
            hal_acl_independent_args *args = &op.args.acl_independent;
            hal_acl_independent_result *owner =
                &result.data.acl_independent;
            const char *state = "unavailable";
            char group[NETLAB_ACL_INDEPENDENT_NAME_MAX] = {0};
            char term[NETLAB_ACL_INDEPENDENT_NAME_MAX] = {0};
            char family[NETLAB_ACL_INDEPENDENT_FAMILY_MAX] = {0};
            char action[NETLAB_ACL_INDEPENDENT_ACTION_MAX] = {0};
            char mac_text[32] = {0};
            char range_text[32] = {0};
            u8 mac[6] = {0};
            u32 ip = 0;
            int slot = payload_int(payload, "slot", -1);
            int vid = payload_int(payload, "vid", 0);
            int port = payload_int(payload, "port", 0);
            int value;
            int range_start;
            int range_end;
            int exec_status;
            char resp[512];
            int off;

            if (slot < 0 || slot >= 32 || vid <= 0 || vid > 4094 ||
                port <= 0 || !nl_ifid_is_user_port(port) ||
                !payload_word(payload, "group", group, sizeof(group)) ||
                !payload_word(payload, "term", term, sizeof(term)) ||
                !payload_word(payload, "family", family, sizeof(family))) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            (void)payload_word(payload, "action", action, sizeof(action));
            if (!action[0])
                snprintf(action, sizeof(action), "drop");

            memset(args, 0, sizeof(*args));
            args->slot = slot;
            args->vid = vid;
            args->port = port;
            snprintf(args->group, sizeof(args->group), "%s", group);
            snprintf(args->term, sizeof(args->term), "%s", term);
            snprintf(args->family, sizeof(args->family), "%s", family);
            snprintf(args->action, sizeof(args->action), "%s", action);
            args->inet_match.vid = vid;
            args->inet_match.port = port;
            args->rate_kbps = payload_int(payload, "rate-kbps", 0);
            args->burst_bytes = payload_int(payload, "burst-bytes", 0);

            if (payload_word(payload, "src-mac", mac_text,
                             sizeof(mac_text)) &&
                nl_platform_parse_mac(mac_text, mac) && (mac[0] & 0x01) == 0) {
                args->has_src_mac = true;
                args->src_mac = mac_bytes_to_u64(mac);
            }
            if (payload_word(payload, "dst-mac", mac_text,
                             sizeof(mac_text)) &&
                nl_platform_parse_mac(mac_text, mac) && (mac[0] & 0x01) == 0) {
                args->has_dst_mac = true;
                args->dst_mac = mac_bytes_to_u64(mac);
            }
            if (payload_ipv4(payload, "src-ip", &ip)) {
                args->inet_match.has_src_ip = true;
                args->inet_match.src_ip = ip;
                args->inet_match.has_src_ip_mask = true;
                if (payload_ipv4(payload, "src-mask", &ip))
                    args->inet_match.src_ip_mask = ip;
                else
                    args->inet_match.src_ip_mask = 0xffffffffU;
            }
            if (payload_ipv4(payload, "dst-ip", &ip)) {
                args->inet_match.has_dst_ip = true;
                args->inet_match.dst_ip = ip;
                args->inet_match.has_dst_ip_mask = true;
                if (payload_ipv4(payload, "dst-mask", &ip))
                    args->inet_match.dst_ip_mask = ip;
                else
                    args->inet_match.dst_ip_mask = 0xffffffffU;
            }
            value = payload_int(payload, "dscp", -1);
            if (value >= 0) {
                args->inet_match.has_dscp = true;
                args->inet_match.dscp = value;
            }
            value = payload_int(payload, "proto", -1);
            if (value >= 0) {
                args->inet_match.has_protocol = true;
                args->inet_match.protocol = value;
            }
            value = payload_int(payload, "src-port", -1);
            if (value >= 0) {
                args->inet_match.has_src_port = true;
                args->inet_match.src_port = value;
            }
            value = payload_int(payload, "dst-port", -1);
            if (value >= 0) {
                args->inet_match.has_dst_port = true;
                args->inet_match.dst_port = value;
            }
            if (payload_word(payload, "src-port-range", range_text,
                             sizeof(range_text)) &&
                parse_port_range_text(range_text, &range_start, &range_end)) {
                args->inet_match.has_src_port_range = true;
                args->inet_match.src_port_start = range_start;
                args->inet_match.src_port_end = range_end;
            }
            if (payload_word(payload, "dst-port-range", range_text,
                             sizeof(range_text)) &&
                parse_port_range_text(range_text, &range_start, &range_end)) {
                args->inet_match.has_dst_port_range = true;
                args->inet_match.dst_port_start = range_start;
                args->inet_match.dst_port_end = range_end;
            }
            value = payload_int(payload, "tcp-flags", -1);
            if (value >= 0) {
                args->inet_match.has_tcp_flags = true;
                args->inet_match.tcp_flags = value;
            }
            value = payload_int(payload, "tcp-flags-mask", -1);
            if (value >= 0) {
                args->inet_match.has_tcp_flags_mask = true;
                args->inet_match.tcp_flags_mask = value;
            }

            op.type = SDK_OP_GET_ACL_INDEPENDENT_COUNTERS;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_COUNTER, 10000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (result.status == 0 && owner->active && owner->ok)
                state = "installed";
            else if (result.status == 0 && !owner->active && owner->ok)
                state = "absent";
            else if (owner->active)
                state = "mismatch";

            off = snprintf(resp, sizeof(resp),
                "<acl-independent group=\"%s\" term=\"%s\" family=\"%s\" "
                "slot=\"%d\" port=\"%d\" vid=\"%d\" state=\"%s\" "
                "acl=\"%d\" rule=\"%d\" policer=\"%d\" port-set=\"%d\" "
                "packets=\"%llu\" octets=\"%llu\" read-status=\"%d\" "
                "mismatches=\"%d\"/>\n",
                group, term, family, slot, port, vid, state,
                owner->acl, owner->rule, owner->policer, owner->port_set,
                (unsigned long long)owner->packets,
                (unsigned long long)owner->octets,
                owner->read_status, owner->mismatches);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_ACL_POLICER_PROBE: { // HAL_ACL_POLICER_PROBE
            hal_acl_policer_probe_result *probe =
                &result.data.acl_policer_probe;
            char detail[256];
            char resp[1024];
            int rate_kbps = payload_int(payload, "rate-kbps", 1000);
            int burst_bytes = payload_int(payload, "burst-bytes", 65536);
            int port = payload_int(payload, "port", 0);
            int exec_status;
            int off;

            if (port <= 0 || !nl_ifid_is_user_port(port) ||
                rate_kbps <= 0 || burst_bytes <= 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_POLICER_PROBE;
            op.args.acl_policer_probe.port = port;
            op.args.acl_policer_probe.rate_kbps = rate_kbps;
            op.args.acl_policer_probe.burst_bytes = burst_bytes;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;

            xml_escape_attr(probe->detail, detail, sizeof(detail));
            off = snprintf(resp, sizeof(resp),
                "<acl-policer-probe status=\"%s\" port=\"%d\" "
                "acl=\"%d\" rule=\"%d\" policer=\"%d\" port-set=\"%d\" "
                "rate-kbps=\"%d\" burst-bytes=\"%d\" "
                "create-status=\"%d\" rule-status=\"%d\" "
                "compile-status=\"%d\" apply-status=\"%d\" "
                "read-status=\"%d\" cleanup-status=\"%d\" "
                "packets=\"%llu\" octets=\"%llu\" detail=\"%s\"/>\n",
                (result.status == 0 && probe->ok) ? "pass" : "fail",
                probe->port, probe->acl, probe->rule, probe->policer,
                probe->port_set, probe->rate_kbps, probe->burst_bytes,
                probe->create_status, probe->rule_status,
                probe->compile_status, probe->apply_status,
                probe->read_status, probe->cleanup_status,
                (unsigned long long)probe->packets,
                (unsigned long long)probe->octets, detail);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_ACL_POLICER_OWNER_APPLY: { // HAL_ACL_POLICER_OWNER_APPLY
            hal_acl_policer_owner_result *owner =
                &result.data.acl_policer_owner;
            char ack[64] = {0};
            char dst_mac_text[32] = {0};
            u8 dst_mac[6] = {0};
            u64 dst_mac_u64 = 0;
            int rate_kbps = payload_int(payload, "rate-kbps", 1000);
            int burst_bytes = payload_int(payload, "burst-bytes", 65536);
            int port = payload_int(payload, "port", 0);
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_ACL_POLICER_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            if (port <= 0 || !nl_ifid_is_user_port(port) ||
                rate_kbps <= 0 || burst_bytes <= 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            if (payload_word(payload, "dst-mac", dst_mac_text,
                             sizeof(dst_mac_text))) {
                if (!nl_platform_parse_mac(dst_mac_text, dst_mac) ||
                    (dst_mac[0] & 0x01)) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                for (int i = 0; i < 6; i++)
                    dst_mac_u64 = (dst_mac_u64 << 8) | dst_mac[i];
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_POLICER_OWNER_APPLY;
            op.args.acl_policer_owner.port = port;
            op.args.acl_policer_owner.dst_mac = dst_mac_u64;
            op.args.acl_policer_owner.rate_kbps = rate_kbps;
            op.args.acl_policer_owner.burst_bytes = burst_bytes;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_policer_owner_xml(conn, msg->request_id, msg->method,
                                       result.status, owner);
            break;
        }
        case NL_SWITCHD_ACL_POLICER_OWNER_READBACK: { // HAL_ACL_POLICER_OWNER_READBACK
            hal_acl_policer_owner_result *owner =
                &result.data.acl_policer_owner;
            int exec_status;

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_POLICER_OWNER_READBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_READBACK, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_policer_owner_xml(conn, msg->request_id, msg->method,
                                       result.status, owner);
            break;
        }
        case NL_SWITCHD_ACL_POLICER_OWNER_ROLLBACK: { // HAL_ACL_POLICER_OWNER_ROLLBACK
            hal_acl_policer_owner_result *owner =
                &result.data.acl_policer_owner;
            char ack[64] = {0};
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_ACL_POLICER_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_POLICER_OWNER_ROLLBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_policer_owner_xml(conn, msg->request_id, msg->method,
                                       result.status, owner);
            break;
        }
        case NL_SWITCHD_ACL_EGRESS_PROBE: { // HAL_ACL_EGRESS_PROBE
            hal_acl_egress_probe_result *probe =
                &result.data.acl_egress_probe;
            char ack[64] = {0};
            char src_mac_text[32] = {0};
            char dst_mac_text[32] = {0};
            u8 src_mac[6] = {0};
            u8 dst_mac[6] = {0};
            u64 src_mac_u64 = 0;
            u64 dst_mac_u64 = 0;
            int port = payload_int(payload, "port", 0);
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_ACL_EGRESS_PROBE") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            if (port <= 0 || !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            if (payload_word(payload, "src-mac", src_mac_text,
                             sizeof(src_mac_text))) {
                if (!nl_platform_parse_mac(src_mac_text, src_mac) ||
                    (src_mac[0] & 0x01)) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                for (int i = 0; i < 6; i++)
                    src_mac_u64 = (src_mac_u64 << 8) | src_mac[i];
            }
            if (payload_word(payload, "dst-mac", dst_mac_text,
                             sizeof(dst_mac_text))) {
                if (!nl_platform_parse_mac(dst_mac_text, dst_mac) ||
                    (dst_mac[0] & 0x01)) {
                    nl_send_response(conn, msg->request_id,
                                     NL_ERR_INVALID_VALUE);
                    break;
                }
                for (int i = 0; i < 6; i++)
                    dst_mac_u64 = (dst_mac_u64 << 8) | dst_mac[i];
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_EGRESS_PROBE;
            op.args.acl_egress_probe.port = port;
            op.args.acl_egress_probe.src_mac = src_mac_u64;
            op.args.acl_egress_probe.dst_mac = dst_mac_u64;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_egress_probe_xml(conn, msg->request_id,
                                      result.status, probe);
            break;
        }
        case NL_SWITCHD_ACL_GENERAL_ALLOCATOR_APPLY: { // HAL_ACL_GENERAL_ALLOCATOR_APPLY
            hal_acl_general_allocator_result *allocator =
                &result.data.acl_general_allocator;
            char ack[64] = {0};
            char profile[64] = {0};
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_ACL_GENERAL_ALLOCATOR") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            (void)payload_word(payload, "profile", profile,
                               sizeof(profile));
            if (profile[0] != '\0' &&
                strcmp(profile, "ingress-count-and-policer") != 0 &&
                strcmp(profile, "ethernet-count") != 0 &&
                strcmp(profile, "inet-count") != 0 &&
                strcmp(profile, "inet-count-and-policer") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_GENERAL_ALLOCATOR_APPLY;
            if (strlen(profile) >=
                sizeof(op.args.acl_general_allocator.profile)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            memcpy(op.args.acl_general_allocator.profile, profile,
                   strlen(profile) + 1);
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_general_allocator_xml(conn, msg->request_id,
                                           msg->method, result.status,
                                           allocator);
            break;
        }
        case NL_SWITCHD_ACL_GENERAL_ALLOCATOR_READBACK: { // HAL_ACL_GENERAL_ALLOCATOR_READBACK
            hal_acl_general_allocator_result *allocator =
                &result.data.acl_general_allocator;
            int exec_status;

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_GENERAL_ALLOCATOR_READBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_READBACK, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_general_allocator_xml(conn, msg->request_id,
                                           msg->method, result.status,
                                           allocator);
            break;
        }
        case NL_SWITCHD_ACL_GENERAL_ALLOCATOR_ROLLBACK: { // HAL_ACL_GENERAL_ALLOCATOR_ROLLBACK
            hal_acl_general_allocator_result *allocator =
                &result.data.acl_general_allocator;
            char ack[64] = {0};
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_ACL_GENERAL_ALLOCATOR") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_ACL_GENERAL_ALLOCATOR_ROLLBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_acl_general_allocator_xml(conn, msg->request_id,
                                           msg->method, result.status,
                                           allocator);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_PROBE: { // HAL_QOS_QUEUE_PROBE
            hal_qos_queue_probe_result *probe =
                &result.data.qos_queue_probe;
            char detail[256];
            char ack[64] = {0};
            char max_text[32];
            char resp[1024];
            int port = payload_int(payload, "port", 0);
            int queue_id = payload_int(payload, "queue-id", 7);
            int traffic_class = payload_int(payload, "traffic-class",
                                            queue_id);
            int min_bw_mbps = payload_int(payload, "min-bw-mbps", 0);
            int max_bw_mbps = payload_int(payload, "max-bw-mbps", -1);
            int exec_status;
            int off;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_QUEUE_PROBE") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            if (port <= 0 || !nl_ifid_is_user_port(port) ||
                queue_id < 0 || queue_id >= HAL_QOS_MAX_TRAFFIC_CLASSES ||
                traffic_class < 0 ||
                traffic_class >= HAL_QOS_MAX_TRAFFIC_CLASSES ||
                min_bw_mbps < 0 || min_bw_mbps > 100000 ||
                (max_bw_mbps > 0 && max_bw_mbps < min_bw_mbps) ||
                max_bw_mbps > 100000) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_PROBE;
            op.args.qos_queue_probe.port = port;
            op.args.qos_queue_probe.queue_id = queue_id;
            op.args.qos_queue_probe.traffic_class = traffic_class;
            op.args.qos_queue_probe.min_bw_mbps = (u64)min_bw_mbps;
            op.args.qos_queue_probe.max_bw_default =
                max_bw_mbps <= 0 ? 1 : 0;
            op.args.qos_queue_probe.max_bw_mbps =
                max_bw_mbps <= 0 ? 0 : (u64)max_bw_mbps;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;

            xml_escape_attr(probe->detail, detail, sizeof(detail));
            if (probe->max_bw_default)
                snprintf(max_text, sizeof(max_text), "default");
            else
                snprintf(max_text, sizeof(max_text), "%llu",
                         (unsigned long long)probe->max_bw_mbps);
            off = snprintf(resp, sizeof(resp),
                "<qos-queue-probe status=\"%s\" port=\"%d\" "
                "queue-id=\"%d\" traffic-class=\"%d\" "
                "min-bw-mbps=\"%llu\" max-bw-mbps=\"%s\" "
                "pre-status=\"%d\" add-status=\"%d\" "
                "set-tc-status=\"%d\" set-min-status=\"%d\" "
                "set-max-status=\"%d\" read-status=\"%d\" "
                "delete-status=\"%d\" post-read-status=\"%d\" "
                "cleanup-status=\"%d\" post-present=\"%d\" "
                "detail=\"%s\"/>\n",
                (result.status == 0 && probe->ok) ? "pass" : "fail",
                probe->port, probe->queue_id, probe->traffic_class,
                (unsigned long long)probe->min_bw_mbps, max_text,
                probe->pre_status, probe->add_status,
                probe->set_tc_status, probe->set_min_status,
                probe->set_max_status, probe->read_status,
                probe->delete_status, probe->post_read_status,
                probe->cleanup_status, probe->post_present, detail);
            if (off < 0)
                off = 0;
            if (off >= (int)sizeof(resp))
                off = (int)sizeof(resp) - 1;
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)off);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_OWNER_APPLY: { // HAL_QOS_QUEUE_OWNER_APPLY
            hal_qos_queue_owner_result *owner =
                &result.data.qos_queue_owner;
            char ack[64] = {0};
            int port = payload_int(payload, "port", 0);
            int queue_id = payload_int(payload, "queue-id", 7);
            int traffic_class = payload_int(payload, "traffic-class",
                                            queue_id);
            int min_bw_mbps = payload_int(payload, "min-bw-mbps", 0);
            int max_bw_mbps = payload_int(payload, "max-bw-mbps", -1);
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_QUEUE_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_OWNER_APPLY;
            op.args.qos_queue_owner.port = port;
            op.args.qos_queue_owner.queue_id = queue_id;
            op.args.qos_queue_owner.traffic_class = traffic_class;
            op.args.qos_queue_owner.min_bw_mbps = (u64)min_bw_mbps;
            op.args.qos_queue_owner.max_bw_default =
                max_bw_mbps <= 0 ? 1 : 0;
            op.args.qos_queue_owner.max_bw_mbps =
                max_bw_mbps <= 0 ? 0 : (u64)max_bw_mbps;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_queue_owner_xml(conn, msg->request_id, msg->method,
                                     result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_OWNER_READBACK: { // HAL_QOS_QUEUE_OWNER_READBACK
            hal_qos_queue_owner_result *owner =
                &result.data.qos_queue_owner;
            int exec_status;

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_OWNER_READBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_READBACK, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_queue_owner_xml(conn, msg->request_id, msg->method,
                                     result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_OWNER_ROLLBACK: { // HAL_QOS_QUEUE_OWNER_ROLLBACK
            hal_qos_queue_owner_result *owner =
                &result.data.qos_queue_owner;
            char ack[64] = {0};
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_QUEUE_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_OWNER_ROLLBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_queue_owner_xml(conn, msg->request_id, msg->method,
                                     result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY: { // HAL_QOS_QUEUE_PROFILE_OWNER_APPLY
            hal_qos_queue_profile_owner_result *owner =
                &result.data.qos_queue_profile_owner;
            char ack[64] = {0};
            bool queue_id_seen[HAL_QOS_QUEUE_PROFILE_MAX_QUEUES] = {false};
            bool valid = true;
            int port;
            int queue_count;
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_QUEUE_PROFILE_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            if (!payload_int_range(payload, "port", 1, INT_MAX, &port) ||
                !nl_ifid_is_user_port(port) ||
                !payload_int_range(
                    payload, "queue-count", 1,
                    HAL_QOS_QUEUE_PROFILE_MAX_QUEUES, &queue_count)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_PROFILE_OWNER_APPLY;
            op.args.qos_queue_profile_owner.port = port;
            op.args.qos_queue_profile_owner.queue_count = queue_count;
            for (int i = 0; i < queue_count; i++) {
                char key[32];
                int queue_id;
                int traffic_class;
                int min_bw_mbps;
                int max_bw_mbps = 0;
                bool max_bw_default;

                snprintf(key, sizeof(key), "queue%d-id", i);
                if (!payload_int_range(payload, key, 0,
                                       HAL_QOS_QUEUE_PROFILE_MAX_QUEUES - 1,
                                       &queue_id) ||
                    queue_id_seen[queue_id]) {
                    valid = false;
                    break;
                }
                queue_id_seen[queue_id] = true;
                snprintf(key, sizeof(key), "queue%d-tc", i);
                if (!payload_int_range(payload, key, 0,
                                       HAL_QOS_MAX_TRAFFIC_CLASSES - 1,
                                       &traffic_class)) {
                    valid = false;
                    break;
                }
                snprintf(key, sizeof(key), "queue%d-min-bw-mbps", i);
                if (!payload_int_range(payload, key, 0, 100000,
                                       &min_bw_mbps)) {
                    valid = false;
                    break;
                }
                snprintf(key, sizeof(key), "queue%d-max-bw-mbps", i);
                max_bw_default = payload_key_value(payload, key) == NULL;
                if (!max_bw_default &&
                    (!payload_int_range(payload, key, 1, 100000,
                                        &max_bw_mbps) ||
                     max_bw_mbps < min_bw_mbps)) {
                    valid = false;
                    break;
                }
                op.args.qos_queue_profile_owner.queue[i].queue_id =
                    queue_id;
                op.args.qos_queue_profile_owner.queue[i].traffic_class =
                    traffic_class;
                op.args.qos_queue_profile_owner.queue[i].min_bw_mbps =
                    (u64)min_bw_mbps;
                op.args.qos_queue_profile_owner.queue[i].max_bw_default =
                    max_bw_default ? 1 : 0;
                op.args.qos_queue_profile_owner.queue[i].max_bw_mbps =
                    max_bw_default ? 0 : (u64)max_bw_mbps;
            }
            if (!valid) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_queue_profile_owner_xml(
                conn, msg->request_id, msg->method, result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_READBACK: { // HAL_QOS_QUEUE_PROFILE_OWNER_READBACK
            hal_qos_queue_profile_owner_result *owner =
                &result.data.qos_queue_profile_owner;
            int exec_status;

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_PROFILE_OWNER_READBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_READBACK, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_queue_profile_owner_xml(
                conn, msg->request_id, msg->method, result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_ROLLBACK: { // HAL_QOS_QUEUE_PROFILE_OWNER_ROLLBACK
            hal_qos_queue_profile_owner_result *owner =
                &result.data.qos_queue_profile_owner;
            char ack[64] = {0};
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_QUEUE_PROFILE_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_QUEUE_PROFILE_OWNER_ROLLBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_queue_profile_owner_xml(
                conn, msg->request_id, msg->method, result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY: { // HAL_QOS_WATERMARK_OWNER_APPLY
            hal_qos_watermark_owner_result *owner =
                &result.data.qos_watermark_owner;
            char ack[64] = {0};
            char scope_text[32] = {0};
            char attr_text[64] = {0};
            int port = payload_int(payload, "port", 0);
            int index = payload_int(payload, "index", 0);
            int value = payload_int(payload, "value", -1);
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_WATERMARK_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            (void)payload_word(payload, "scope", scope_text,
                               sizeof(scope_text));
            (void)payload_word(payload, "attr", attr_text, sizeof(attr_text));

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_WATERMARK_OWNER_APPLY;
            op.args.qos_watermark_owner.scope =
                qos_watermark_scope_from_text(scope_text);
            op.args.qos_watermark_owner.port = port;
            op.args.qos_watermark_owner.attr =
                qos_watermark_attr_from_text(attr_text);
            op.args.qos_watermark_owner.index = index;
            op.args.qos_watermark_owner.value = value;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_watermark_owner_xml(
                conn, msg->request_id, msg->method, result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_WATERMARK_OWNER_READBACK: { // HAL_QOS_WATERMARK_OWNER_READBACK
            hal_qos_watermark_owner_result *owner =
                &result.data.qos_watermark_owner;
            int exec_status;

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_WATERMARK_OWNER_READBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_READBACK, 30000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_watermark_owner_xml(
                conn, msg->request_id, msg->method, result.status, owner);
            break;
        }
        case NL_SWITCHD_QOS_WATERMARK_OWNER_ROLLBACK: { // HAL_QOS_WATERMARK_OWNER_ROLLBACK
            hal_qos_watermark_owner_result *owner =
                &result.data.qos_watermark_owner;
            char ack[64] = {0};
            int exec_status;

            if (!payload_word(payload, "ack", ack, sizeof(ack)) ||
                strcmp(ack, "NETLAB_ENABLE_QOS_WATERMARK_OWNER") != 0) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            sdk_rpc_op_init(&op, msg->daemon_id, request_issued_at);
            memset(&result, 0, sizeof(result));
            op.type = SDK_OP_QOS_WATERMARK_OWNER_ROLLBACK;
            exec_status = sdk_exec_with_prio(ctx->exec, &op, &result,
                                             SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            send_qos_watermark_owner_xml(
                conn, msg->request_id, msg->method, result.status, owner);
            break;
        }
        case NL_SWITCHD_DYNAMIC_MAC_CLEAR: { // HAL_CLEAR_DYNAMIC_MAC_TABLE
            int port = payload_int(payload, "port", 0);
            int vid = payload_int(payload, "vid", 0);
            if ((payload_key_value(payload, "port") &&
                 !payload_int_range(payload, "port", 0, INT_MAX, &port)) ||
                (payload_key_value(payload, "vid") &&
                 !payload_int_range(payload, "vid", 0, 4094, &vid)) ||
                (port > 0 && !nl_ifid_is_user_port(port))) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_CLEAR_DYNAMIC_MAC_TABLE;
            op.args.vlan.port = port;
            op.args.vlan.vid = (u16)vid;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 10000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_PORT_ADMIN_OVERRIDE: { // HAL_RUNTIME_PORT_ADMIN_OVERRIDE
            int port = 0;
            int mode = -1;
            nl_port_entry entry;
            if (!payload_int_range(payload, "port", 1, INT_MAX, &port) ||
                !payload_int_range(payload, "mode", 0, 1, &mode) ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_PORT_SET_ADMIN;
            op.args.port.port = port;
            op.args.port.mode = mode;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 30000);
            if (result.status == 0)
                sync_port_admin_cache(ctx, port, mode);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_PORT_SECURITY_ACTION: { // HAL_RUNTIME_PORT_SECURITY
            int port = 0;
            int enable = payload_int(payload, "enable", 0);
            int strict = payload_int(payload, "strict", 0);
            char action[32] = {0};
            int sdk_action = FM_PORT_SECURITY_ACTION_DROP;
            nl_port_entry entry;

            (void)payload_word(payload, "action", action, sizeof(action));
            if (strcmp(action, "restrict") == 0)
                sdk_action = FM_PORT_SECURITY_ACTION_EVENT;
            else if (strcmp(action, "trap") == 0)
                sdk_action = FM_PORT_SECURITY_ACTION_TRAP;
            else if (strcmp(action, "drop") == 0 || !action[0])
                sdk_action = FM_PORT_SECURITY_ACTION_DROP;
            else {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }

            if (!payload_int_range(payload, "port", 1, INT_MAX, &port) ||
                (payload_key_value(payload, "enable") &&
                 !payload_int_range(payload, "enable", 0, 1, &enable)) ||
                (payload_key_value(payload, "strict") &&
                 !payload_int_range(payload, "strict", 0, 1, &strict)) ||
                !nl_ifid_get_by_logical_port(port, &entry) ||
                !nl_ifid_is_user_port(port)) {
                nl_send_response(conn, msg->request_id,
                                 NL_ERR_INVALID_VALUE);
                break;
            }
            op.type = SDK_OP_PORT_SECURITY_SET;
            op.args.port_security.port = port;
            op.args.port_security.enable = enable ? 1 : 0;
            op.args.port_security.action = sdk_action;
            op.args.port_security.strict = strict ? 1 : 0;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_CONFIG_CHANGE, 10000);
            nl_send_response(conn, msg->request_id, result.status);
            break;
        }
        case NL_SWITCHD_MAC_AGING_GET: { // HAL_GET_MAC_AGING_TIME
            op.type = SDK_OP_GET_MAC_AGING_TIME;
            sdk_exec_with_prio(ctx->exec, &op, &result,
                               SDK_PRIO_READBACK, 10000);
            char resp[64];
            int n = snprintf(resp, sizeof(resp), "aging-time=%d\n",
                             result.status == 0 ?
                             result.data.mac_aging.seconds : -1);
            (void)hal_rpc_send_payload(conn, msg->request_id, 0, resp,
                                       (u32)n);
            break;
        }
        case NL_SWITCHD_L2_PLAN_APPLY: { // HAL_APPLY_L2_PLAN — typed text plan via executor
            l2_apply_plan *parsed_plan;
            l2_apply_plan *plan;
            bool persistent =
                msg->daemon_id == NL_DAEMON_CONFIGD;
            int n_steps;
            int exec_status;
            int tracker_status = 0;

            parsed_plan = calloc(1, sizeof(*parsed_plan));
            if (!parsed_plan) {
                nl_send_response(conn, msg->request_id, NL_ERR);
                break;
            }
            l2_apply_plan_init(parsed_plan);
            plan = parsed_plan;
            n_steps = l2_plan_parse(payload, parsed_plan);
            if (n_steps <= 0) {
                NL_LOG_ERR("method 40: plan parse failed (n_steps=%d)", n_steps);
                nl_send_response(
                    conn, msg->request_id, NL_ERR_INVALID_VALUE);
                l2_apply_plan_reset(parsed_plan);
                free(parsed_plan);
                break;
            }
            parsed_plan->tx_id = msg->tx_id;
            if (persistent) {
                tracker_status = hw_state_tracker_reserve_l2(
                    ctx->hw_tracker, msg->tx_id, parsed_plan, &plan);
                if (tracker_status != 0) {
                    nl_send_response(
                        conn, msg->request_id, tracker_status);
                    l2_apply_plan_reset(parsed_plan);
                    free(parsed_plan);
                    break;
                }
                l2_apply_plan_reset(parsed_plan);
                free(parsed_plan);
                parsed_plan = NULL;
            }

            op.type = SDK_OP_APPLY_L2_PLAN;
            op.args.apply_plan = plan;
            exec_status = sdk_exec_with_prio(
                ctx->exec, &op, &result,
                SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (persistent) {
                tracker_status = hw_state_tracker_finish_l2_apply(
                    ctx->hw_tracker, msg->tx_id, result.status);
                if (tracker_status != 0)
                    result.status = tracker_status;
            }
            if (result.status == 0)
                sync_apply_plan_port_cache(ctx, plan);
            // Send structured response
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "<apply-result status=\"%d\" steps=\"%d\" "
                     "tx-id=\"%016lx\" persistent=\"%s\"/>",
                     result.status, n_steps, msg->tx_id,
                     persistent ? "true" : "false");
            (void)hal_rpc_send_text(conn, msg->request_id, result.status,
                                    resp);
            if (parsed_plan) {
                l2_apply_plan_reset(parsed_plan);
                free(parsed_plan);
            }
            break;
        }
        case NL_SWITCHD_L2_PLAN_ROLLBACK: {
            l2_apply_plan *plan = NULL;
            bool already_rolled_back = false;
            int exec_status;
            int tracker_status;
            int restored_steps = 0;
            char resp[512];

            tracker_status = hw_state_tracker_begin_l2_rollback(
                ctx->hw_tracker, msg->tx_id, &plan,
                &already_rolled_back);
            if (tracker_status != 0) {
                nl_send_response(
                    conn, msg->request_id, tracker_status);
                break;
            }
            if (already_rolled_back) {
                snprintf(
                    resp, sizeof(resp),
                    "<l2-plan-rollback status=\"ok\" "
                    "tx-id=\"%016lx\" idempotent=\"true\" "
                    "sdk-write=\"live\" sdk-readback=\"live\"/>",
                    msg->tx_id);
                (void)hal_rpc_send_text(
                    conn, msg->request_id, 0, resp);
                break;
            }
            if (!plan) {
                nl_send_response(
                    conn, msg->request_id,
                    NL_ERR_PRE_STATE_MISSING);
                break;
            }

            op.type = SDK_OP_ROLLBACK_L2_PLAN;
            op.args.apply_plan = plan;
            exec_status = sdk_exec_with_prio(
                ctx->exec, &op, &result,
                SDK_PRIO_CONFIG_CHANGE, 60000);
            if (exec_status != 0 && result.status == 0)
                result.status = exec_status;
            if (result.status == 0) {
                restored_steps = plan->n_steps;
                sync_rollback_plan_port_cache(ctx, plan);
            }
            tracker_status = hw_state_tracker_finish_l2_rollback(
                ctx->hw_tracker, msg->tx_id, result.status);
            if (tracker_status != 0)
                result.status = tracker_status;
            snprintf(
                resp, sizeof(resp),
                "<l2-plan-rollback status=\"%s\" "
                "tx-id=\"%016lx\" restored=\"%d\" "
                "mismatches=\"%d\" sdk-write=\"live\" "
                "sdk-readback=\"live\"/>",
                result.status == 0 ? "ok" : "failed",
                msg->tx_id,
                result.status == 0 ? restored_steps : 0,
                result.status == 0 ? 0 : 1);
            (void)hal_rpc_send_text(
                conn, msg->request_id, result.status, resp);
            break;
        }
        case NL_SWITCHD_PFE_STATUS_GET: { // PFE capability status
            send_pfe_status(ctx, conn, msg);
            break;
        }
        default:
            NL_LOG_WARN("unknown rpc method=%u payload_len=%u",
                        msg->method, msg->payload_len);
            nl_send_response(conn, msg->request_id, -1);
            break;
    }
}
