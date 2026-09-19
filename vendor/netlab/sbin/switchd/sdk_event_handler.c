#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/event.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <fm_sdk.h>
#include <api/fm_api_event_types.h>

#define EVENT_QUEUE_SIZE 4096

static sdk_event_t g_event_queue_buf[EVENT_QUEUE_SIZE];
static int g_event_queue_head = 0;
static int g_event_queue_tail = 0;
static pthread_mutex_t g_event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_event_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_publisher_thread;
static bool g_publisher_running = false;
static bool g_publisher_thread_started = false;
static bool g_publisher_joining = false;
static sdk_event_stats_t g_event_stats;

typedef struct {
    unsigned long seq;
    time_t ts;
    int sw;
    int event;
    int reason;
    int index;
    int vlan;
    int port;
    int age;
    int locked;
    int valid;
    int addr_type;
    u64 mac;
} sdk_mac_update_record_t;

static sdk_mac_update_record_t
    g_mac_update_ring[NETLAB_MAC_UPDATE_RING_MAX];
static unsigned long g_mac_update_next_seq = 1;

static const char *mac_update_event_name(int event) {
    switch (event) {
        case FM_EVENT_ENTRY_EMPTY: return "empty";
        case FM_EVENT_ENTRY_LEARNED: return "learned";
        case FM_EVENT_ENTRY_AGED: return "aged";
        case FM_EVENT_ENTRY_MEMORY_ERROR: return "memory-error";
        default: return "unknown";
    }
}

static void mac_to_text(u64 mac, char *buf, size_t len) {
    snprintf(buf, len, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             (unsigned long long)((mac >> 40) & 0xff),
             (unsigned long long)((mac >> 32) & 0xff),
             (unsigned long long)((mac >> 24) & 0xff),
             (unsigned long long)((mac >> 16) & 0xff),
             (unsigned long long)((mac >> 8) & 0xff),
             (unsigned long long)(mac & 0xff));
}

void sdk_mac_update_ring_record(int sw, int event, int reason,
                                int index, int vlan, int port,
                                int age, int locked, int valid,
                                int addr_type, u64 mac) {
    sdk_mac_update_record_t *rec;
    unsigned long seq;

    pthread_mutex_lock(&g_event_lock);
    seq = g_mac_update_next_seq++;
    rec = &g_mac_update_ring[(seq - 1) % NETLAB_MAC_UPDATE_RING_MAX];
    memset(rec, 0, sizeof(*rec));
    rec->seq = seq;
    rec->ts = time(NULL);
    rec->sw = sw;
    rec->event = event;
    rec->reason = reason;
    rec->index = index;
    rec->vlan = vlan;
    rec->port = port;
    rec->age = age;
    rec->locked = locked;
    rec->valid = valid;
    rec->addr_type = addr_type;
    rec->mac = mac;
    pthread_mutex_unlock(&g_event_lock);
}

int sdk_mac_update_ring_format(char *buf, size_t buf_size) {
    unsigned long next_seq;
    unsigned long count;
    unsigned long start_seq;
    bool truncated = false;
    int off = 0;

    if (!buf || buf_size == 0)
        return 0;

    pthread_mutex_lock(&g_event_lock);
    next_seq = g_mac_update_next_seq;
    count = next_seq > 1 ? next_seq - 1 : 0;
    if (count > NETLAB_MAC_UPDATE_RING_MAX)
        count = NETLAB_MAC_UPDATE_RING_MAX;
    start_seq = next_seq - count;

    off += snprintf(buf + off, buf_size - (size_t)off,
                    "<mac-update-events latest-seq=\"%lu\" count=\"%lu\">\n",
                    next_seq > 1 ? next_seq - 1 : 0, count);
    for (unsigned long seq = start_seq; seq < next_seq; seq++) {
        const sdk_mac_update_record_t *rec =
            &g_mac_update_ring[(seq - 1) % NETLAB_MAC_UPDATE_RING_MAX];
        char mac[18];
        char line[320];
        int n;

        if (off < 0 || (size_t)off >= buf_size)
            break;
        if (rec->seq != seq)
            continue;
        mac_to_text(rec->mac, mac, sizeof(mac));
        n = snprintf(line, sizeof(line),
                     "  <event seq=\"%lu\" time=\"%ld\" sw=\"%d\" "
                     "type=\"%s\" event=\"%d\" reason=\"%d\" "
                     "index=\"%d\" vlan=\"%d\" port=\"%d\" "
                     "mac=\"%s\" age=\"%d\" locked=\"%d\" "
                     "valid=\"%d\" addr-type=\"%d\"/>\n",
                     rec->seq, (long)rec->ts, rec->sw,
                     mac_update_event_name(rec->event), rec->event,
                     rec->reason, rec->index, rec->vlan, rec->port,
                     mac, rec->age, rec->locked, rec->valid,
                     rec->addr_type);
        if (n < 0)
            continue;
        if ((size_t)n >= sizeof(line)) {
            truncated = true;
            break;
        }
        if ((size_t)off + (size_t)n + 64 >= buf_size) {
            truncated = true;
            break;
        }
        memcpy(buf + off, line, (size_t)n);
        off += n;
    }
    if (truncated && (size_t)off + 16 < buf_size)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        "  <truncated/>\n");
    if (off > 0 && (size_t)off < buf_size)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        "</mac-update-events>\n");
    else if (buf_size > 0)
        buf[buf_size - 1] = '\0';
    pthread_mutex_unlock(&g_event_lock);
    return off > 0 ? off : 0;
}

static int find_port_index(struct sdk_context *ctx, int port) {
    if (!ctx) return -1;
    for (int i = 0; i < ctx->num_cardinal_ports && i < 64; i++) {
        if (ctx->cardinal_ports[i] == port)
            return i;
    }
    return -1;
}

static void update_last_event_detail_locked(const sdk_event_t *evt) {
    g_event_stats.last_port = evt->detail_port;
    g_event_stats.last_vlan = evt->detail_vlan;
    g_event_stats.last_lane = evt->detail_lane;
    g_event_stats.last_mac = evt->detail_mac;
    g_event_stats.last_status = evt->detail_status;
    g_event_stats.last_temperature = evt->detail_temperature;
    g_event_stats.last_crm_id = evt->detail_crm_id;
    g_event_stats.last_fibm_retries = evt->detail_fibm_retries;
    g_event_stats.last_parity_type = evt->detail_parity_type;
    g_event_stats.last_parity_severity = evt->detail_parity_severity;
    g_event_stats.last_parity_area = evt->detail_parity_area;
    g_event_stats.last_parity_status = evt->detail_parity_status;
    g_event_stats.last_parity_sram = evt->detail_parity_sram;
    g_event_stats.last_logical_first = evt->detail_logical_first;
    g_event_stats.last_logical_count = evt->detail_logical_count;
    g_event_stats.last_logical_pep_id = evt->detail_logical_pep_id;
    g_event_stats.last_logical_pep_port = evt->detail_logical_pep_port;
    g_event_stats.last_logical_created = evt->detail_logical_created;
    g_event_stats.last_platform_type = evt->detail_platform_type;
    g_event_stats.last_software_events = evt->detail_software_events;
    g_event_stats.last_switch_slot = evt->detail_switch_slot;
    g_event_stats.last_arp_sip = evt->detail_arp_sip;
    g_event_stats.last_arp_dip = evt->detail_arp_dip;
    g_event_stats.last_arp_ipv6 = evt->detail_arp_ipv6;
    g_event_stats.last_egress_port = evt->detail_egress_port;
}

void sdk_port_cache_reset(struct sdk_context *ctx) {
    if (!ctx) return;
    for (int i = 0; i < 64; i++) {
        ctx->port_admin_state[i] = -1;
        ctx->port_link_state[i] = -1;
        ctx->port_speed[i] = 0;
    }
}

void sdk_port_cache_set(struct sdk_context *ctx, int port,
                        int admin_state, int link_state, int speed) {
    int idx = find_port_index(ctx, port);
    if (idx < 0) return;
    if (admin_state >= -1)
        ctx->port_admin_state[idx] = admin_state;
    if (link_state >= -1)
        ctx->port_link_state[idx] = link_state;
    if (speed >= 0)
        ctx->port_speed[idx] = speed;
}

int sdk_port_cache_get(struct sdk_context *ctx, int port,
                       int *admin_state, int *link_state, int *speed) {
    int idx = find_port_index(ctx, port);
    if (idx < 0) return -1;
    if (admin_state) *admin_state = ctx->port_admin_state[idx];
    if (link_state) *link_state = ctx->port_link_state[idx];
    if (speed) *speed = ctx->port_speed[idx];
    return 0;
}

static void update_event_stats_locked(const sdk_event_t *evt) {
    if (!evt)
        return;
    g_event_stats.total++;
    g_event_stats.last_event = evt->event;
    update_last_event_detail_locked(evt);
    switch (evt->event) {
        case FM_EVENT_PORT:
            g_event_stats.port++;
            break;
        case FM_EVENT_TABLE_UPDATE:
            g_event_stats.table_updates++;
            g_event_stats.table_entries +=
                (unsigned long)evt->table_update_count;
            g_event_stats.table_learned +=
                (unsigned long)evt->table_update_learned;
            g_event_stats.table_aged +=
                (unsigned long)evt->table_update_aged;
            g_event_stats.table_errors +=
                (unsigned long)evt->table_update_errors;
            break;
        case FM_EVENT_SECURITY:
            g_event_stats.security++;
            break;
        case FM_EVENT_PLATFORM:
            g_event_stats.platform++;
            break;
        case FM_EVENT_PARITY_ERROR:
            g_event_stats.parity_errors++;
            break;
        case FM_EVENT_LOGICAL_PORT:
            g_event_stats.logical_port++;
            break;
        case FM_EVENT_CABLE_MISMATCH:
            g_event_stats.cable_mismatch++;
            break;
        case FM_EVENT_OVER_TEMP:
            g_event_stats.over_temp++;
            break;
        case FM_EVENT_SWITCH_REMOVED:
        case FM_EVENT_SWITCH_UP:
        case FM_EVENT_SWITCH_DOWN:
            g_event_stats.switch_events++;
            break;
        case FM_EVENT_FRAME:
            g_event_stats.frame++;
            break;
        case FM_EVENT_SOFTWARE:
            g_event_stats.software++;
            break;
        case FM_EVENT_FIBM_THRESHOLD:
            g_event_stats.fibm_threshold++;
            break;
        case FM_EVENT_CRM:
            g_event_stats.crm++;
            break;
        case FM_EVENT_ARP:
            g_event_stats.arp++;
            break;
        case FM_EVENT_PURGE_SCAN_COMPLETE:
            g_event_stats.purge_scan_complete++;
            break;
        case FM_EVENT_EGRESS_TIMESTAMP:
            g_event_stats.egress_timestamp++;
            break;
        case FM_EVENT_PACKET_ENQUEUED:
            g_event_stats.packet_enqueued++;
            break;
        default:
            g_event_stats.unsupported++;
            g_event_stats.last_unsupported_event = evt->event;
            break;
    }
}

void sdk_event_stats_snapshot(sdk_event_stats_t *out) {
    if (!out)
        return;
    pthread_mutex_lock(&g_event_lock);
    *out = g_event_stats;
    pthread_mutex_unlock(&g_event_lock);
}

static void update_port_event_cache(struct sdk_context *ctx, sdk_event_t *evt) {
    if (!ctx || !evt) return;
    fm_eventPort pe;
    memset(&pe, 0, sizeof(pe));
    memcpy(&pe, evt->port_event,
           sizeof(pe) < sizeof(evt->port_event) ? sizeof(pe) : sizeof(evt->port_event));

    int link_state = -1;
    if (pe.linkStatus == FM_PORT_STATUS_LINK_UP)
        link_state = 1;
    else if (pe.linkStatus == FM_PORT_STATUS_LINK_DOWN)
        link_state = 0;

    if (pe.port > 0 && link_state != -1)
        sdk_port_cache_set(ctx, (int)pe.port, -2, link_state, -1);
}

void sdk_event_queue_push(sdk_event_t *evt) {
    pthread_mutex_lock(&g_event_lock);
    int next = (g_event_queue_head + 1) % EVENT_QUEUE_SIZE;
    if (next != g_event_queue_tail) {
        update_event_stats_locked(evt);
        g_event_queue_buf[g_event_queue_head] = *evt;
        g_event_queue_head = next;
        pthread_cond_signal(&g_event_cond);
    } else {
        g_event_stats.queue_drops++;
    }
    pthread_mutex_unlock(&g_event_lock);
}

static bool sdk_event_queue_pop(sdk_event_t *evt) {
    bool available = false;

    if (!evt)
        return false;
    memset(evt, 0, sizeof(*evt));
    pthread_mutex_lock(&g_event_lock);
    while (g_event_queue_head == g_event_queue_tail && g_publisher_running)
        pthread_cond_wait(&g_event_cond, &g_event_lock);
    if (g_publisher_running &&
        g_event_queue_head != g_event_queue_tail) {
        *evt = g_event_queue_buf[g_event_queue_tail];
        g_event_queue_tail = (g_event_queue_tail + 1) % EVENT_QUEUE_SIZE;
        available = true;
    }
    pthread_mutex_unlock(&g_event_lock);
    return available;
}

static void *event_publisher_thread(void *arg) {
    struct sdk_context *ctx = (struct sdk_context *)arg;
    nl_event_bus *bus = nl_eventbus_create(7, (u64)time(NULL));
    (void)ctx;

    for (;;) {
        sdk_event_t evt;

        if (!sdk_event_queue_pop(&evt))
            break;
        if (evt.event == 0)
            continue;

        switch (evt.event) {
            case FM_EVENT_PORT:
                update_port_event_cache(ctx, &evt);
                nl_eventbus_publish(bus, "ev.port.link",
                                    evt.port_event,
                                    sizeof(evt.port_event));
                break;
            case FM_EVENT_TABLE_UPDATE:
                nl_eventbus_publish(bus, "ev.mac.table-update",
                                    &evt, sizeof(evt));
                break;
            case FM_EVENT_SECURITY:
                nl_eventbus_publish(bus, "ev.security",
                                    &evt, sizeof(evt));
                break;
            case FM_EVENT_PLATFORM:
                nl_eventbus_publish(bus, "ev.platform",
                                    &evt, sizeof(evt));
                break;
            case FM_EVENT_PARITY_ERROR:
            case FM_EVENT_LOGICAL_PORT:
            case FM_EVENT_CABLE_MISMATCH:
            case FM_EVENT_OVER_TEMP:
            case FM_EVENT_SWITCH_REMOVED:
            case FM_EVENT_SWITCH_UP:
            case FM_EVENT_SWITCH_DOWN:
            case FM_EVENT_FRAME:
            case FM_EVENT_SOFTWARE:
            case FM_EVENT_FIBM_THRESHOLD:
            case FM_EVENT_CRM:
            case FM_EVENT_ARP:
            case FM_EVENT_PURGE_SCAN_COMPLETE:
            case FM_EVENT_EGRESS_TIMESTAMP:
            case FM_EVENT_PACKET_ENQUEUED:
                nl_eventbus_publish(bus, "ev.platform",
                                    &evt, sizeof(evt));
                break;
            default:
                break;
        }
    }
    nl_eventbus_destroy(bus);
    return NULL;
}

int sdk_event_publisher_start(struct sdk_context *ctx) {
    int rc;

    pthread_mutex_lock(&g_event_lock);
    while (g_publisher_joining)
        pthread_cond_wait(&g_event_cond, &g_event_lock);
    if (g_publisher_thread_started) {
        pthread_mutex_unlock(&g_event_lock);
        return 0;
    }
    g_publisher_running = true;
    rc = pthread_create(&g_publisher_thread, NULL,
                        event_publisher_thread, ctx);
    if (rc != 0) {
        g_publisher_running = false;
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }
    g_publisher_thread_started = true;
    pthread_mutex_unlock(&g_event_lock);
    return 0;
}

void sdk_event_publisher_stop(void) {
    pthread_t thread;

    pthread_mutex_lock(&g_event_lock);
    while (g_publisher_joining)
        pthread_cond_wait(&g_event_cond, &g_event_lock);
    if (!g_publisher_thread_started) {
        g_publisher_running = false;
        pthread_mutex_unlock(&g_event_lock);
        return;
    }
    g_publisher_running = false;
    g_publisher_joining = true;
    thread = g_publisher_thread;
    pthread_cond_broadcast(&g_event_cond);
    pthread_mutex_unlock(&g_event_lock);

    (void)pthread_join(thread, NULL);

    pthread_mutex_lock(&g_event_lock);
    g_publisher_thread_started = false;
    g_publisher_joining = false;
    g_event_queue_tail = g_event_queue_head;
    pthread_cond_broadcast(&g_event_cond);
    pthread_mutex_unlock(&g_event_lock);
}
