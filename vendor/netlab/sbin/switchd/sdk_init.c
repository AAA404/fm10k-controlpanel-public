/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "fm10k_board_runtime.h"
#include "fm10k_startup.h"
#include "netlab/interface_id.h"
#include "sdk_event_barrier.h"
#include "sflow_capture.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <fm_sdk.h>
#include <api/fm_api_event_types.h>
#include <api/fm_api_portset.h>
#include <api/fm_api_trigger.h>
#include <common/fm_bitarray.h>
#include <common/fm_property.h>
#include <platforms/common/packet/generic-rawsocket/fm_generic_rawsocket.h>
#include <platforms/libertyTrail/platform_app_api.h>

extern void hal_packet_capture_direct(fm_eventPktRecv *event);

#define NETLAB_TRIGGER_GROUP_CONTROL_MAC 20000
#define NETLAB_TRIGGER_RULE_CONTROL_MAC  0
#define NETLAB_PORT_RETRAIN_MAX 256
#define NETLAB_PORT_RETRAIN_PASSES 3
#define NETLAB_PORT_RETRAIN_WAIT_US 1000000
#define NETLAB_PORT_RECOVERY_DEFAULT_PORTS "1,2,3"
#define NETLAB_PORT_RECOVERY_WINDOW_SEC 120
#define NETLAB_PORT_RECOVERY_INTERVAL_SEC 2
#define NETLAB_PORT_RECOVERY_ACTION_INTERVAL_SEC 10
#define NETLAB_PORT_RECOVERY_MAX_ATTEMPTS 8
#define NETLAB_PORT_RECOVERY_UNKNOWN_GRACE_POLLS 3
#define NETLAB_RAW_SOCKET_MIN_MTU 1518

static sem_t g_switch_ready_sem;
static bool g_sem_inited = false;
static time_t g_port_recovery_started[NETLAB_PORT_RETRAIN_MAX];
static time_t g_port_recovery_last_poll = 0;
static int g_port_recovery_attempts[NETLAB_PORT_RETRAIN_MAX];
static int g_port_recovery_unknown_polls[NETLAB_PORT_RETRAIN_MAX];
static time_t g_port_recovery_last_attempt[NETLAB_PORT_RETRAIN_MAX];
static pthread_mutex_t g_port_recovery_lock = PTHREAD_MUTEX_INITIALIZER;

static bool env_truthy(const char *name);
static int sdk_context_cleanup_resources(struct sdk_context *ctx);
static bool sdk_port_recovery_candidate(int port);

/*
 * Cold SDK initialization has no persistent port before-image yet: it is
 * constructing the hardware baseline that config replay will subsequently
 * replace.  The exact runtime admin/XCVR transaction requires the platform
 * profile topology and transaction before-images to be established and
 * therefore cannot own this bootstrap phase. Keep this authority explicit and
 * limited to initial bringup; runtime recovery and all RPC writes use the
 * exact HAL transaction.
 */
static int sdk_bootstrap_port_admin_up(fm_int sw, fm_int port) {
    fm_bool present = FALSE;
    fm_status status;

    status = fmPlatformXcvrIsPresent(sw, port, &present);
    if (status == FM_OK && present) {
        (void)fmPlatformXcvrEnableLpMode(sw, port, FALSE);
        status = fmPlatformXcvrEnable(sw, port, TRUE);
        if (status == FM_OK)
            NL_LOG_INFO("port %d: bootstrap transceiver enabled", (int)port);
        else
            NL_LOG_WARN(
                "port %d: bootstrap transceiver enable failed: %s",
                (int)port, fmErrorMsg(status));
    }

    status = fmSetPortState(sw, port, FM_PORT_STATE_UP, 0);
    if (status != FM_OK) {
        NL_LOG_ERR("bootstrap fmSetPortState(sw=%d, port=%d): %s",
                   (int)sw, (int)port, fmErrorMsg(status));
        return -1;
    }
    return 0;
}

static bool prepare_rawsocket_netdev_mtu(const char *ifname) {
    struct ifreq ifr;
    int fd;
    int original_mtu;

    if (!ifname || ifname[0] == '\0' || strlen(ifname) >= IFNAMSIZ) {
        NL_LOG_ERR("raw packet socket netdev name is invalid");
        return false;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        NL_LOG_ERR("raw packet socket MTU probe failed for %s: %s",
                   ifname, strerror(errno));
        return false;
    }
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, strlen(ifname) + 1);
    if (ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
        NL_LOG_ERR("raw packet socket MTU read failed for %s: %s",
                   ifname, strerror(errno));
        close(fd);
        return false;
    }
    original_mtu = ifr.ifr_mtu;
    if (original_mtu < NETLAB_RAW_SOCKET_MIN_MTU) {
        ifr.ifr_mtu = NETLAB_RAW_SOCKET_MIN_MTU;
        if (ioctl(fd, SIOCSIFMTU, &ifr) != 0) {
            NL_LOG_ERR("raw packet socket MTU set failed for %s: %s",
                       ifname, strerror(errno));
            close(fd);
            return false;
        }
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, ifname, strlen(ifname) + 1);
        if (ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
            NL_LOG_ERR("raw packet socket MTU verify failed for %s: %s",
                       ifname, strerror(errno));
            close(fd);
            return false;
        }
    }
    close(fd);
    if (ifr.ifr_mtu < NETLAB_RAW_SOCKET_MIN_MTU) {
        NL_LOG_ERR("raw packet socket MTU is too small for full Ethernet "
                   "frames: iface=%s mtu=%d required=%d",
                   ifname, ifr.ifr_mtu, NETLAB_RAW_SOCKET_MIN_MTU);
        return false;
    }
    NL_LOG_INFO("raw packet socket MTU ready: iface=%s original=%d current=%d",
                ifname, original_mtu, ifr.ifr_mtu);
    return true;
}
static int env_int_range(const char *name, int default_value,
                         int min_value, int max_value);

static void init_sdk_event(sdk_event_t *evt, fm_int event, fm_int sw) {
    memset(evt, 0, sizeof(*evt));
    evt->event = (int)event;
    evt->sw = (int)sw;
    evt->detail_port = -1;
    evt->detail_vlan = -1;
    evt->detail_lane = -1;
    evt->detail_mac = -1;
    evt->detail_status = -1;
    evt->detail_temperature = -1;
    evt->detail_crm_id = -1;
    evt->detail_fibm_retries = -1;
    evt->detail_parity_type = -1;
    evt->detail_parity_severity = -1;
    evt->detail_parity_area = -1;
    evt->detail_parity_status = -1;
    evt->detail_parity_sram = -1;
    evt->detail_logical_first = -1;
    evt->detail_logical_count = -1;
    evt->detail_logical_pep_id = -1;
    evt->detail_logical_pep_port = -1;
    evt->detail_logical_created = -1;
    evt->detail_platform_type = -1;
    evt->detail_software_events = -1;
    evt->detail_switch_slot = -1;
    evt->detail_arp_sip = -1;
    evt->detail_arp_dip = -1;
    evt->detail_arp_ipv6 = -1;
    evt->detail_egress_port = -1;
}

static void configure_mac_event_properties(void) {
    fm_bool enabled = TRUE;
    fm_status st;

    st = fmSetApiProperty(FM_AAK_API_MA_EVENT_ON_STATIC_ADDR,
                          FM_AAT_API_MA_EVENT_ON_STATIC_ADDR, &enabled);
    if (st != FM_OK)
        NL_LOG_WARN("failed to enable static MAC update events: %s",
                    fmErrorMsg(st));
    st = fmSetApiProperty(FM_AAK_API_MA_EVENT_ON_DYNAMIC_ADDR,
                          FM_AAT_API_MA_EVENT_ON_DYNAMIC_ADDR, &enabled);
    if (st != FM_OK)
        NL_LOG_WARN("failed to enable dynamic MAC update events: %s",
                    fmErrorMsg(st));
    st = fmSetApiProperty(FM_AAK_API_MA_EVENT_ON_ADDR_CHANGE,
                          FM_AAT_API_MA_EVENT_ON_ADDR_CHANGE, &enabled);
    if (st != FM_OK)
        NL_LOG_WARN("failed to enable MAC change events: %s", fmErrorMsg(st));
}

static bool configure_event_delivery_properties(void) {
    fm_bool direct = FALSE;
    fm_bool observed = TRUE;
    fm_status st;

    st = fmSetApiProperty(
        FM_AAK_API_PACKET_RX_DIRECT_ENQUEUEING,
        FM_AAT_API_PACKET_RX_DIRECT_ENQUEUEING, &direct);
    if (st != FM_OK) {
        NL_LOG_ERR(
            "failed to disable direct SDK packet-event enqueueing: %s",
            fmErrorMsg(st));
        return false;
    }
    st = fmGetApiProperty(
        FM_AAK_API_PACKET_RX_DIRECT_ENQUEUEING,
        FM_AAT_API_PACKET_RX_DIRECT_ENQUEUEING, &observed);
    if (st != FM_OK || observed != FALSE) {
        NL_LOG_ERR(
            "SDK packet-event FIFO boundary is not active: status=%s "
            "direct=%d",
            fmErrorMsg(st), (int)observed);
        return false;
    }
    return true;
}

static int fm_state_to_link(fm_int state) {
    switch ((int)state) {
        case 0: return 1;  // FM_PORT_STATE_UP as returned by fmGetPortState()
        case 1: case 2: case 4: case 5: case 7:
            return 0;
        default:
            return -1;
    }
}

static const char *fm_port_state_name(fm_int state) {
    switch ((int)state) {
        case 0: return "UP";
        case 1: return "ADMIN_DOWN";
        case 2: return "PWRDOWN";
        case 3: return "BIST";
        case 4: return "REMOTE_FAULT";
        case 5: return "DOWN";
        case 6: return "PARTIALLY_UP";
        case 7: return "LOCAL_FAULT";
        case 8: return "DFE_TUNING";
        default: return "?";
    }
}

static fm_status sdk_refresh_port_state(struct sdk_context *ctx, fm_int sw,
                                        fm_int port, int *link_state,
                                        const char *prefix) {
    fm_int rd_mode = 0;
    fm_int rd_state = 0;
    fm_int rd_info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    fm_status rst = fmGetPortState(sw, port, &rd_mode, &rd_state, rd_info);

    if (rst != FM_OK) {
        sdk_port_cache_set(ctx, (int)port, 1, -1, 0);
        if (prefix)
            NL_LOG_INFO("%sport %d: initialized", prefix, (int)port);
        return rst;
    }

    fm_uint32 sp = 0;
    if (fmGetPortAttribute(sw, port, FM_PORT_SPEED, &sp) != FM_OK)
        sp = 0;
    int link = fm_state_to_link(rd_state);
    sdk_port_cache_set(ctx, (int)port,
                       ((int)rd_mode == 0) ? 1 : 0,
                       link,
                       (int)sp);
    if (link_state)
        *link_state = link;
    if (prefix)
        NL_LOG_INFO("%sport %d: admin=%s link=%s", prefix, (int)port,
                    fm_port_state_name(rd_mode),
                    fm_port_state_name(rd_state));
    return FM_OK;
}

static fm_status sdk_set_wide_egress_mask(fm_int sw, fm_int ingress_port,
                                          const fm_int *ports,
                                          fm_int n_ports) {
    fm_bitArray expected = {0};
    fm_bitArray observed = {0};
    fm_status status;
    fm_status cleanup_status;
    fm_int bit_count = 0;
    bool expected_created = false;
    bool observed_created = false;

    if (!ports || n_ports <= 0)
        return FM_ERR_INVALID_VALUE;
    for (fm_int i = 0; i < n_ports; i++) {
        if (ports[i] < 0)
            return FM_ERR_INVALID_VALUE;
        if (ports[i] >= bit_count)
            bit_count = ports[i] + 1;
    }

    status = fmCreateBitArray(&expected, bit_count);
    if (status != FM_OK)
        return status;
    expected_created = true;
    status = fmCreateBitArray(&observed, bit_count);
    if (status != FM_OK)
        goto out;
    observed_created = true;

    for (fm_int i = 0; i < n_ports; i++) {
        status = fmSetBitArrayBit(&expected, ports[i], TRUE);
        if (status != FM_OK)
            goto out;
    }
    status = fmSetPortAttribute(sw, ingress_port, FM_PORT_MASK_WIDE,
                                &expected);
    if (status != FM_OK)
        goto out;
    status = fmGetPortAttribute(sw, ingress_port, FM_PORT_MASK_WIDE,
                                &observed);
    if (status == FM_OK && !fmCompareBitArrays(&expected, &observed))
        status = FM_ERR_INVALID_VALUE;

out:
    if (observed_created) {
        cleanup_status = fmDeleteBitArray(&observed);
        if (status == FM_OK && cleanup_status != FM_OK)
            status = cleanup_status;
    }
    if (expected_created) {
        cleanup_status = fmDeleteBitArray(&expected);
        if (status == FM_OK && cleanup_status != FM_OK)
            status = cleanup_status;
    }
    return status;
}

static void sdk_retrain_present_ports(struct sdk_context *ctx, fm_int sw,
                                      const fm_int *ports, int n_ports) {
    if (!ctx || !ports || n_ports <= 0)
        return;

    for (int pass = 1; pass <= NETLAB_PORT_RETRAIN_PASSES; pass++) {
        bool any_down = false;

        usleep(NETLAB_PORT_RETRAIN_WAIT_US);
        for (int i = 0; i < n_ports; i++) {
            int link = -1;
            fm_int port = ports[i];
            fm_status rst = sdk_refresh_port_state(ctx, sw, port, &link, NULL);
            if (rst != FM_OK || link == 1)
                continue;

            any_down = true;
            NL_LOG_INFO("  port %d: link not up after init pass %d, retraining",
                        (int)port, pass);
            (void)sdk_bootstrap_port_admin_up(sw, port);
        }
        if (!any_down)
            return;
    }
}

static void sdk_port_recovery_state_reset(void) {
    pthread_mutex_lock(&g_port_recovery_lock);
    memset(g_port_recovery_started, 0,
           sizeof(g_port_recovery_started));
    g_port_recovery_last_poll = 0;
    memset(g_port_recovery_attempts, 0, sizeof(g_port_recovery_attempts));
    memset(g_port_recovery_unknown_polls, 0,
           sizeof(g_port_recovery_unknown_polls));
    memset(g_port_recovery_last_attempt, 0,
           sizeof(g_port_recovery_last_attempt));
    pthread_mutex_unlock(&g_port_recovery_lock);
}

static bool port_list_contains(const char *list, int port) {
    const char *p = list;

    if (!list || !list[0])
        return false;

    while (*p) {
        char *end = NULL;
        long value;

        while (*p == ',' || isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;

        value = strtol(p, &end, 10);
        if (end == p) {
            p++;
            continue;
        }
        if (value == port)
            return true;
        p = end;
    }
    return false;
}

static bool sdk_port_recovery_candidate(int port) {
    const char *ports = getenv("NETLAB_SWITCHD_PORT_RECOVERY_PORTS");

    if (ports && ports[0])
        return port_list_contains(ports, port);
    if (env_truthy("NETLAB_SWITCHD_RECOVER_ALL_USER_PORTS"))
        return true;
    return port_list_contains(NETLAB_PORT_RECOVERY_DEFAULT_PORTS, port);
}

void sdk_port_recovery_poll(struct sdk_context *ctx) {
    time_t now;

    /* The reference recovery policy predates EPL groups and their optical
     * mask ownership. Native retraining uses the explicit port transaction. */
    if (fm10k_native_profile() || !ctx || !ctx->initialized || env_truthy("NETLAB_SWITCHD_DISABLE_PORT_RECOVERY"))
        return;

    pthread_mutex_lock(&g_port_recovery_lock);
    now = time(NULL);
    if (g_port_recovery_last_poll != 0 &&
        now - g_port_recovery_last_poll < NETLAB_PORT_RECOVERY_INTERVAL_SEC) {
        pthread_mutex_unlock(&g_port_recovery_lock);
        return;
    }
    g_port_recovery_last_poll = now;

    for (int i = 0; i < ctx->num_cardinal_ports; i++) {
        int port = ctx->cardinal_ports[i];
        int admin = -1, link = -1, speed = 0;
        fm_status rst;

        if (port <= 0 || port >= NETLAB_PORT_RETRAIN_MAX)
            continue;
        if (!nl_ifid_is_user_port(port) || !sdk_port_recovery_candidate(port))
            continue;

        rst = sdk_refresh_port_state(ctx, ctx->sw, (fm_int)port, &link, NULL);
        if (rst != FM_OK)
            continue;
        if (sdk_port_cache_get(ctx, port, &admin, &link, &speed) != 0)
            continue;
        if (link == 1) {
            g_port_recovery_started[port] = 0;
            g_port_recovery_attempts[port] = 0;
            g_port_recovery_unknown_polls[port] = 0;
            g_port_recovery_last_attempt[port] = 0;
            continue;
        }
        if (admin != 1) {
            g_port_recovery_started[port] = 0;
            g_port_recovery_attempts[port] = 0;
            g_port_recovery_unknown_polls[port] = 0;
            g_port_recovery_last_attempt[port] = 0;
            continue;
        }
        if (g_port_recovery_started[port] == 0)
            g_port_recovery_started[port] = now;
        if (now - g_port_recovery_started[port] >
                NETLAB_PORT_RECOVERY_WINDOW_SEC)
            continue;
        if (g_port_recovery_last_attempt[port] != 0 &&
            now - g_port_recovery_last_attempt[port] <
                NETLAB_PORT_RECOVERY_ACTION_INTERVAL_SEC)
            continue;
        if (link < 0) {
            g_port_recovery_unknown_polls[port]++;
            if (g_port_recovery_unknown_polls[port] <=
                    NETLAB_PORT_RECOVERY_UNKNOWN_GRACE_POLLS)
                continue;
            NL_LOG_NOTICE(
                "port %d: transitional link state persisted for %d polls",
                port, g_port_recovery_unknown_polls[port]);
            g_port_recovery_unknown_polls[port] = 0;
        } else {
            g_port_recovery_unknown_polls[port] = 0;
        }
        if (g_port_recovery_attempts[port] >= NETLAB_PORT_RECOVERY_MAX_ATTEMPTS)
            continue;

        g_port_recovery_attempts[port]++;
        g_port_recovery_last_attempt[port] = now;
        NL_LOG_NOTICE("port %d: admin-up/link-down exact retrain attempt %d",
                      port, g_port_recovery_attempts[port]);
        if (hal_port_retrain(ctx->sw, port) == 0)
            sdk_port_cache_set(ctx, port, 1, -1, -1);
        else
            NL_LOG_ERR("port %d: exact recovery retrain attempt %d failed",
                       port, g_port_recovery_attempts[port]);
    }
    pthread_mutex_unlock(&g_port_recovery_lock);
}

void sdk_port_recovery_stats_snapshot(struct sdk_context *ctx,
                                      sdk_port_recovery_stats *stats) {
    time_t now = time(NULL);

    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    stats->enabled = ctx && ctx->initialized &&
        !env_truthy("NETLAB_SWITCHD_DISABLE_PORT_RECOVERY");
    stats->window_seconds = NETLAB_PORT_RECOVERY_WINDOW_SEC;
    stats->max_attempts = NETLAB_PORT_RECOVERY_MAX_ATTEMPTS;
    if (!ctx)
        return;

    pthread_mutex_lock(&g_port_recovery_lock);
    stats->last_poll_age = g_port_recovery_last_poll ?
        (long)(now - g_port_recovery_last_poll) : -1L;
    for (int i = 0; i < ctx->num_cardinal_ports &&
         stats->n_ports < NETLAB_PORT_SNAPSHOT_MAX; i++) {
        int port = ctx->cardinal_ports[i];
        sdk_port_recovery_entry *entry;

        if (port <= 0 || port >= NETLAB_PORT_RETRAIN_MAX ||
            !nl_ifid_is_user_port(port) ||
            !sdk_port_recovery_candidate(port))
            continue;
        entry = &stats->ports[stats->n_ports++];
        entry->port = port;
        entry->attempts = g_port_recovery_attempts[port];
        entry->unknown_polls = g_port_recovery_unknown_polls[port];
        entry->last_attempt_age = g_port_recovery_last_attempt[port] ?
            (long)(now - g_port_recovery_last_attempt[port]) : -1L;
        entry->episode_elapsed_seconds = g_port_recovery_started[port] ?
            (long)(now - g_port_recovery_started[port]) : -1L;
        entry->window_expired = g_port_recovery_started[port] &&
            now - g_port_recovery_started[port] >
                NETLAB_PORT_RECOVERY_WINDOW_SEC;
        entry->exhausted = entry->window_expired ||
            entry->attempts >= NETLAB_PORT_RECOVERY_MAX_ATTEMPTS;
    }
    pthread_mutex_unlock(&g_port_recovery_lock);
}

static void event_handler(fm_int event, fm_int sw, void *ptr) {
    sdk_event_t evt;

    if (event == FM_EVENT_SFLOW_PKT_RECV) {
        sflow_capture_handle_event((int)sw, (fm_eventPktRecv *)ptr);
        return;
    }
    if (sdk_event_barrier_handle((int)event, ptr))
        return;

    init_sdk_event(&evt, event, sw);

    switch (event) {
        case FM_EVENT_SWITCH_INSERTED:
            if (g_sem_inited) sem_post(&g_switch_ready_sem);
            break;
        case FM_EVENT_PKT_RECV: {
            fm_eventPktRecv *pkt_info = (fm_eventPktRecv *)ptr;
            fm_status free_st;
            if (!pkt_info || !pkt_info->pkt) break;
            NL_LOG_DBG("pkt recv: port=%d vlan=%d first-chunk-len=%d",
                        pkt_info->srcPort, pkt_info->vlan,
                        ((fm_buffer *)pkt_info->pkt)->len);
            hal_packet_capture_direct(pkt_info);
            free_st = fmFreeBufferChain(sw, (fm_buffer *)pkt_info->pkt);
            if (free_st != FM_OK)
                NL_LOG_WARN("failed to free packet rx buffer chain: %s",
                            fmErrorMsg(free_st));
            pkt_info->pkt = NULL;
            break;
        }
        case FM_EVENT_PORT:
            if (ptr) {
                fm_eventPort *port = (fm_eventPort *)ptr;
                memcpy(evt.port_event, ptr,
                       sizeof(evt.port_event) < 128 ? sizeof(evt.port_event) : 128);
                evt.detail_port = (int)port->port;
                evt.detail_status = (int)port->linkStatus;
                evt.detail_mac = (int)port->mac;
                evt.detail_lane = (int)port->lane;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_TABLE_UPDATE:
            if (ptr) {
                fm_eventTableUpdateBurst *burst =
                    (fm_eventTableUpdateBurst *)ptr;
                evt.table_update_count = (int)burst->numUpdates;
                if (burst->updates) {
                    fm_uint32 limit = burst->numUpdates;
                    if (limit > 4096)
                        limit = 4096;
                    for (fm_uint32 i = 0; i < limit; i++) {
                        fm_eventTableUpdate *update = &burst->updates[i];
                        sdk_mac_update_ring_record(
                            (int)sw, (int)update->event,
                            (int)update->reason, (int)update->index,
                            (int)update->vlanID, (int)update->port,
                            (int)update->age, (int)update->locked,
                            (int)update->valid, (int)update->addrType,
                            (u64)update->macAddress);
                        if (update->event == FM_EVENT_ENTRY_LEARNED)
                            evt.table_update_learned++;
                        else if (update->event == FM_EVENT_ENTRY_AGED)
                            evt.table_update_aged++;
                        else if (update->event != FM_EVENT_ENTRY_EMPTY)
                            evt.table_update_errors++;
                    }
                }
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_SECURITY:
            if (ptr) {
                fm_eventSecurity *sec = (fm_eventSecurity *)ptr;
                evt.detail_port = (int)sec->port;
                evt.detail_vlan = (int)sec->vlan;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_PARITY_ERROR:
            if (ptr) {
                fm_eventParityError *perr = (fm_eventParityError *)ptr;
                evt.detail_parity_type = (int)perr->errType;
                evt.detail_parity_severity = (int)perr->paritySeverity;
                evt.detail_parity_area = (int)perr->memoryArea;
                evt.detail_parity_status = (int)perr->parityStatus;
                evt.detail_parity_sram = (int)perr->sramNo;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_LOGICAL_PORT:
            if (ptr) {
                fm_eventLogicalPort *lp = (fm_eventLogicalPort *)ptr;
                evt.detail_logical_first = (int)lp->firstPort;
                evt.detail_logical_count = (int)lp->numberOfPorts;
                evt.detail_logical_pep_id = (int)lp->pepId;
                evt.detail_logical_pep_port = (int)lp->pepLogicalPort;
                evt.detail_logical_created = (int)lp->portCreated;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_CABLE_MISMATCH:
            if (ptr) {
                fm_eventCableMismatch *cable = (fm_eventCableMismatch *)ptr;
                evt.detail_port = (int)cable->port;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_OVER_TEMP:
            if (ptr) {
                fm_eventOverTemp *temp = (fm_eventOverTemp *)ptr;
                evt.detail_temperature = (int)temp->temperature;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_SOFTWARE:
            if (ptr) {
                fm_eventSoftware *sw_evt = (fm_eventSoftware *)ptr;
                evt.detail_software_events = (int)sw_evt->activeEvents;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_SWITCH_REMOVED:
            if (ptr) {
                fm_eventSwitchRemoved *removed = (fm_eventSwitchRemoved *)ptr;
                evt.detail_switch_slot = (int)removed->slot;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_PLATFORM:
            if (ptr) {
                fm_eventPlatform *platform = (fm_eventPlatform *)ptr;
                evt.detail_platform_type = (int)platform->type;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_FIBM_THRESHOLD:
            if (ptr) {
                fm_eventFibm *fibm = (fm_eventFibm *)ptr;
                evt.detail_fibm_retries = (int)fibm->retries;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_CRM:
            if (ptr) {
                fm_eventCrm *crm = (fm_eventCrm *)ptr;
                evt.detail_crm_id = (int)crm->crmID;
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_ARP:
            if (ptr) {
                fm_eventArp *arp = (fm_eventArp *)ptr;
                evt.detail_arp_sip = (int)arp->arpRedirectSip.addr[0];
                evt.detail_arp_dip = (int)arp->arpRedirectDip.addr[0];
                evt.detail_arp_ipv6 = (int)(arp->arpRedirectSip.isIPv6 ||
                                            arp->arpRedirectDip.isIPv6);
            }
            sdk_event_queue_push(&evt);
            break;
        case FM_EVENT_EGRESS_TIMESTAMP:
            if (ptr) {
                fm_eventTimestamp *ts_event = (fm_eventTimestamp *)ptr;
                evt.detail_egress_port = (int)ts_event->egressPort;
            }
            sdk_event_queue_push(&evt);
            break;
        default: {
            static int seen_events[256];
            static int n_seen = 0;
            int found = 0;
            for (int i = 0; i < n_seen; i++)
                if (seen_events[i] == (int)event) { found = 1; break; }
            if (!found && n_seen < 256) {
                seen_events[n_seen++] = (int)event;
                NL_LOG_DBG("sdk event: 0x%x (%d)", (int)event, (int)event);
            }
            sdk_event_queue_push(&evt);
            break;
        }
    }
}

static bool inventory_has_port(const int *ports, int n_ports, int port) {
    if (!ports || n_ports <= 0 || port <= 0)
        return false;
    for (int i = 0; i < n_ports; i++)
        if (ports[i] == port)
            return true;
    return false;
}

static fm_status configure_control_mac_rx_trap(fm_int sw,
                                               const int *inventory_ports,
                                               int n_inventory_ports) {
    fm_status st;
    fm_int portset = FM_PORT_SET_NONE;
    fm_triggerCondition cond;
    fm_triggerAction action;
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    int n_entries;
    int n_external = 0;

    st = fmCreatePortSet(sw, &portset);
    if (st != FM_OK && st != FM_ERR_ALREADY_EXISTS)
        return st;

    n_entries = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_entries; i++) {
        if ((entries[i].flags & NL_PORT_FLAG_EXTERNAL) == 0 ||
            entries[i].logical_port <= 0)
            continue;
        if (!inventory_has_port(inventory_ports, n_inventory_ports,
                                entries[i].logical_port))
            continue;
        st = fmAddPortSetPort(sw, portset, (fm_int)entries[i].logical_port);
        if (st != FM_OK && st != FM_ERR_ALREADY_EXISTS)
            return st;
        n_external++;
    }
    if (n_external == 0)
        return FM_ERR_INVALID_PORT;

    st = fmCreateTrigger(sw, NETLAB_TRIGGER_GROUP_CONTROL_MAC,
                         NETLAB_TRIGGER_RULE_CONTROL_MAC);
    if (st != FM_OK && st != FM_ERR_ALREADY_EXISTS)
        return st;

    st = fmInitTriggerCondition(sw, &cond);
    if (st != FM_OK)
        return st;
    cond.cfg.HAMask = FM_TRIGGER_HA_SWITCH_RESERVED_MAC;
    cond.cfg.rxPortset = portset;
    cond.cfg.matchFtypeMask = FM_TRIGGER_FTYPE_NORMAL;

    st = fmInitTriggerAction(sw, &action);
    if (st != FM_OK)
        return st;
    action.cfg.trapAction = FM_TRIGGER_TRAP_ACTION_TRAP;

    st = fmSetTriggerAction(sw, NETLAB_TRIGGER_GROUP_CONTROL_MAC,
                            NETLAB_TRIGGER_RULE_CONTROL_MAC, &action);
    if (st != FM_OK)
        return st;
    return fmSetTriggerCondition(sw, NETLAB_TRIGGER_GROUP_CONTROL_MAC,
                                 NETLAB_TRIGGER_RULE_CONTROL_MAC, &cond);
}

static bool copy_rawsocket_netdev_name(char *out, size_t out_size,
                                       const char *name) {
    size_t length;

    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    if (!name || !name[0])
        return false;
    length = strnlen(name, IFNAMSIZ);
    if (length == IFNAMSIZ || length >= out_size)
        return false;
    memcpy(out, name, length + 1U);
    return true;
}

static bool discover_rawsocket_netdev(char *out, size_t out_size) {
    const char *env = getenv("NETLAB_RAW_SOCKET_IFACE");
    DIR *uio_dir;
    struct dirent *uio_ent;

    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    if (env && env[0])
        return copy_rawsocket_netdev_name(out, out_size, env);

    uio_dir = opendir("/sys/class/uio");
    if (!uio_dir)
        return false;
    while ((uio_ent = readdir(uio_dir)) != NULL) {
        char net_path[512];
        DIR *net_dir;
        struct dirent *net_ent;

        if (uio_ent->d_name[0] == '.')
            continue;
        snprintf(net_path, sizeof(net_path),
                 "/sys/class/uio/%s/device/net", uio_ent->d_name);
        net_dir = opendir(net_path);
        if (!net_dir)
            continue;
        while ((net_ent = readdir(net_dir)) != NULL) {
            if (net_ent->d_name[0] == '.')
                continue;
            if (!copy_rawsocket_netdev_name(
                    out, out_size, net_ent->d_name)) {
                closedir(net_dir);
                closedir(uio_dir);
                return false;
            }
            closedir(net_dir);
            closedir(uio_dir);
            return true;
        }
        closedir(net_dir);
    }
    closedir(uio_dir);
    return false;
}

static bool env_truthy(const char *name) {
    const char *value = getenv(name);

    if (!value || !value[0])
        return false;
    return strcmp(value, "1") == 0 ||
           strcmp(value, "true") == 0 ||
           strcmp(value, "yes") == 0 ||
           strcmp(value, "on") == 0;
}

static int env_int_range(const char *name, int default_value,
                         int min_value, int max_value) {
    const char *value = getenv(name);
    char *end = NULL;
    long parsed;

    if (!value || !value[0])
        return default_value;
    parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0')
        return default_value;
    if (parsed < min_value)
        return min_value;
    if (parsed > max_value)
        return max_value;
    return (int)parsed;
}

static fm_status set_reserved_mac_action(fm_int sw, fm_int index,
                                         fm_int action) {
    fm_reservedMacCfg mac;

    memset(&mac, 0, sizeof(mac));
    mac.index = index;
    mac.action = action;
    return fmSetSwitchAttribute(sw, FM_SWITCH_RESERVED_MAC_CFG, &mac);
}

static void configure_ffu_slice_allocation(fm_int sw) {
    nl_ffu_slice_allocation profile;
    fm_ffuSliceAllocations alloc;
    fm_status st;

    if (!nl_platform_ffu_slices(&profile))
        return;

    memset(&alloc, 0, sizeof(alloc));
    st = fmGetSwitchAttribute(sw, FM_FFU_SLICE_ALLOCATIONS, &alloc);
    if (st != FM_OK) {
        NL_LOG_WARN("FFU slice allocation read-back failed before profile apply: %s",
                    fmErrorMsg(st));
        return;
    }

    alloc.ipv4UnicastFirstSlice = profile.ipv4_uc_first;
    alloc.ipv4UnicastLastSlice = profile.ipv4_uc_last;
    alloc.ipv4MulticastFirstSlice = profile.ipv4_mc_first;
    alloc.ipv4MulticastLastSlice = profile.ipv4_mc_last;
    alloc.ipv6UnicastFirstSlice = profile.ipv6_uc_first;
    alloc.ipv6UnicastLastSlice = profile.ipv6_uc_last;
    alloc.ipv6MulticastFirstSlice = profile.ipv6_mc_first;
    alloc.ipv6MulticastLastSlice = profile.ipv6_mc_last;
    alloc.aclFirstSlice = profile.acl_first;
    alloc.aclLastSlice = profile.acl_last;
    alloc.cVlanFirstSlice = profile.cvlan_first;
    alloc.cVlanLastSlice = profile.cvlan_last;
    alloc.bstRoutingFirstSlice = profile.bst_routing_first;
    alloc.bstRoutingLastSlice = profile.bst_routing_last;

    st = fmSetSwitchAttribute(sw, FM_FFU_SLICE_ALLOCATIONS, &alloc);
    if (st != FM_OK) {
        NL_LOG_WARN("FFU slice allocation profile apply failed: %s "
                    "(acl=%d-%d ipv4-uc=%d-%d ipv6-uc=%d-%d)",
                    fmErrorMsg(st), profile.acl_first, profile.acl_last,
                    profile.ipv4_uc_first, profile.ipv4_uc_last,
                    profile.ipv6_uc_first, profile.ipv6_uc_last);
        return;
    }

    NL_LOG_INFO("FFU slice allocation applied: acl=%d-%d ipv4-uc=%d-%d "
                "ipv4-mc=%d-%d ipv6-uc=%d-%d ipv6-mc=%d-%d",
                profile.acl_first, profile.acl_last,
                profile.ipv4_uc_first, profile.ipv4_uc_last,
                profile.ipv4_mc_first, profile.ipv4_mc_last,
                profile.ipv6_uc_first, profile.ipv6_uc_last,
                profile.ipv6_mc_first, profile.ipv6_mc_last);
}

int sdk_bringup(struct sdk_context **out) {
    struct sdk_context *ctx;
    fm_status st;
    bool cleanup_unproven = false;

    if (!out)
        return -1;
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -1;
    ctx->sw = 0;
    *out = ctx;

    /* An explicit observation deployment may initialize only after fresh
     * identity and exclusive-ownership checks. It never enters the reference
     * all-ports-UP bootstrap or advertises the full configuration contract. */
    nl_platform_identity panel_identity;
    nl_board_profile panel_board;
    if ((nl_platform_identity_get(&panel_identity) &&
         nl_fm10k_profile_known(panel_identity.chassis_name)) ||
        (nl_platform_board_get(&panel_board) &&
         strcmp(panel_board.asic, "FM10840") == 0)) {
        if (!nl_platform_identity_get(&panel_identity) ||
            fm10k_startup_check(panel_identity.chassis_name, ctx->pfe_cap.init_error,
                               sizeof(ctx->pfe_cap.init_error))) {
            NL_LOG_CRIT("%s", ctx->pfe_cap.init_error);
            goto fail;
        }
    }

    if (!g_sem_inited) {
        if (sem_init(&g_switch_ready_sem, 0, 0) != 0) {
            snprintf(
                ctx->pfe_cap.init_error,
                sizeof(ctx->pfe_cap.init_error),
                "switch-ready semaphore: %s", strerror(errno));
            goto fail;
        }
        g_sem_inited = true;
    }

    NL_LOG_INFO("SDK bringup step 1: fmOSInitialize");
    st = fmOSInitialize();
    if (st != FM_OK) {
        NL_LOG_ERR("fmOSInitialize failed: %s", fmErrorMsg(st));
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "fmOSInitialize: %s", fmErrorMsg(st));
        /*
         * fmOSInitialize marks its process-global state initialized before
         * every subordinate initializer has completed.  There is no public
         * rollback API for a partial failure, so this process cannot safely
         * continue as a retryable PFE_DOWN shell.
         */
        cleanup_unproven = true;
        goto fail;
    }

    configure_mac_event_properties();
    if (!configure_event_delivery_properties()) {
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "packet event FIFO boundary");
        goto fail;
    }

    sflow_capture_init();
    ctx->capture_started = true;
    sdk_event_barrier_init();
    NL_LOG_INFO("SDK bringup step 2: fmInitialize (registers event handler)");
    st = fmInitialize(event_handler);
    if (st != FM_OK) {
        NL_LOG_ERR("fmInitialize failed: %s", fmErrorMsg(st));
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "fmInitialize: %s", fmErrorMsg(st));
        /*
         * The pinned SDK does not roll back every partial fmInitialize
         * milestone on error.  Without a successful registration there is no
         * safe public event-drain path, so this process must exit rather than
         * advertise a long-lived PFE_DOWN shell.
         */
        cleanup_unproven = true;
        goto fail;
    }
    ctx->event_delivery_started = true;
    /*
     * fmInitialize loads platform/API property files after the pre-init
     * check above.  Pin the FIFO setting again before switch packet handling
     * can snapshot it; otherwise a configured direct path would bypass the
     * global/local queues used by the shutdown sentinel.
     */
    if (!configure_event_delivery_properties()) {
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "post-initialize packet event FIFO boundary");
        cleanup_unproven = true;
        goto fail;
    }
    NL_LOG_INFO("SDK fmInitialize complete");

    int switch_ready_timeout =
        env_int_range("NETLAB_SDK_SWITCH_READY_TIMEOUT", 90, 5, 300);
    NL_LOG_INFO("SDK bringup step 3: wait for switch event (%ds timeout)",
                switch_ready_timeout);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += switch_ready_timeout;

    int sem_ret = sem_timedwait(&g_switch_ready_sem, &ts);
    if (sem_ret != 0) {
        NL_LOG_ERR("SDK switch_ready timeout (%ds) - no switch detected?",
                   switch_ready_timeout);
        ctx->pfe_cap.sdk_initialized = false;
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "SDK_INIT_TIMEOUT");
        goto fail;
    }

    fm_int main_sw = 0;
    NL_LOG_INFO("SDK bringup step 4: fmSetSwitchState(UP)");
    ctx->switch_state_touched = true;
    st = fmSetSwitchState(main_sw, TRUE);
    if (st != FM_OK) {
        NL_LOG_ERR("fmSetSwitchState failed: %s", fmErrorMsg(st));
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "fmSetSwitchState: %s", fmErrorMsg(st));
        goto fail;
    }
    ctx->switch_up = true;

    if (fm10k_startup_validated()) {
        fm_int ports[64], count = 0;
        if (fmGetCardinalPortList(main_sw, &count, ports, 64) != FM_OK || count < 24 || count > 64) {
            snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error), "native fixed-slot inventory unavailable");
            goto fail;
        }
        ctx->num_cardinal_ports = count;
        for (int i = 0; i < count; ++i) ctx->cardinal_ports[i] = ports[i];
        sdk_port_cache_reset(ctx);
        if (sdk_executor_init(&ctx->exec, ctx->sw) || hw_state_tracker_init(&ctx->hw_tracker) != NL_OK) {
            snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error), "native executor initialization failed");
            goto fail;
        }
        struct sdk_op boot = {.type = SDK_OP_FM10K_BOOTSTRAP_CLOSED};
        struct sdk_result result = {0};
        if (sdk_exec_with_prio(ctx->exec, &boot, &result, SDK_PRIO_CONFIG_CHANGE, 120000) || result.status) {
            snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error), "native closed-port/fan baseline failed");
            goto fail;
        }
        if (fm10k_startup_control()) {
            char raw_netdev[64];
            if (!discover_rawsocket_netdev(raw_netdev, sizeof(raw_netdev)) ||
                !prepare_rawsocket_netdev_mtu(raw_netdev)) {
                snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error), "native CPU network device unavailable");
                goto fail;
            }
            struct sdk_op control = {.type = SDK_OP_FM10K_CONTROL_INIT};
            control.args.fm10k_control.ctx = ctx;
            snprintf(control.args.fm10k_control.netdev, sizeof(control.args.fm10k_control.netdev), "%s", raw_netdev);
            if (sdk_exec_with_prio(ctx->exec, &control, &result, SDK_PRIO_CONFIG_CHANGE, 120000) || result.status) {
                snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error), "native L2/CPU bootstrap failed");
                goto fail;
            }
        }
        ctx->initialized = true;
        ctx->pfe_cap.sdk_initialized = true;
        ctx->pfe_cap.switch_enabled = true;
        ctx->pfe_cap.port_inventory_ok = true;
        ctx->pfe_cap.readback_verify_ok = true;
        ctx->pfe_cap.transceiver_i2c_ok = true;
        NL_LOG_NOTICE("FM10840 %s startup verified; autonomous fan curve active",
                      fm10k_startup_control() ? "control: closed data ports, waiting for configd replay" :
                      fm10k_startup_basic100g() ? "basic100g: six 100G test ports UP, VLAN1 untagged" : "observation: 24 data slots closed");
        return 0;
    }

    configure_ffu_slice_allocation(main_sw);

    // Start raw packet socket for fmSendPacketDirected support.
    char raw_netdev[64];
    if (env_truthy("NETLAB_DISABLE_RAW_PACKET_SOCKET")) {
        NL_LOG_WARN("raw packet socket disabled by NETLAB_DISABLE_RAW_PACKET_SOCKET");
        st = FM_ERR_INVALID_ARGUMENT;
    } else if (discover_rawsocket_netdev(raw_netdev, sizeof(raw_netdev))) {
        NL_LOG_INFO("raw packet socket netdev: %s", raw_netdev);
        if (!prepare_rawsocket_netdev_mtu(raw_netdev))
            st = FM_ERR_INVALID_ARGUMENT;
        else {
            st = fmRawPacketSocketHandlingInitialize(main_sw, FALSE,
                                                      raw_netdev);
            if (st != FM_OK) {
                NL_LOG_CRIT(
                    "raw packet socket partial initialization cannot be "
                    "safely unwound: %s", fmErrorMsg(st));
                snprintf(
                    ctx->pfe_cap.init_error,
                    sizeof(ctx->pfe_cap.init_error),
                    "fmRawPacketSocketHandlingInitialize: %s",
                    fmErrorMsg(st));
                cleanup_unproven = true;
                goto fail;
            }
        }
    } else {
        NL_LOG_WARN("raw packet socket netdev not discovered");
        st = FM_ERR_INVALID_ARGUMENT;
    }
    bool packet_io_ok = true;
    bool port_programming_ok = true;
    bool vlan_programming_ok = true;
    bool pvid_programming_ok = true;
    bool vlan_mode_programming_ok = true;
    bool readback_verify_ok = true;
    bool counters_ok = false;
    bool transceiver_i2c_ok = false;
    int counter_probe_port = -1;
    int counter_probe_failures = 0;
    fm_int retrain_ports[NETLAB_PORT_RETRAIN_MAX];
    int n_retrain_ports = 0;
    if (st != FM_OK) {
        NL_LOG_WARN("raw packet socket init failed: %s", fmErrorMsg(st));
        packet_io_ok = false;
    } else {
        NL_LOG_INFO("raw packet socket initialized");
        ctx->raw_socket_started = true;
    }

    NL_LOG_INFO("SDK bringup step 5: port inventory");
    fm_int numPorts = 0;
    fm_int portList[256];
    st = fmGetCardinalPortList(main_sw, &numPorts, portList, 256);
    if (st != FM_OK) {
        NL_LOG_ERR("fmGetCardinalPortList failed: %s", fmErrorMsg(st));
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "fmGetCardinalPortList: %s", fmErrorMsg(st));
        goto fail;
    }
    {
        nl_platform_identity ident;
        if (nl_platform_identity_get(&ident) && ident.model[0])
            NL_LOG_INFO("SDK detected %d ports on %s", numPorts, ident.model);
        else
            NL_LOG_INFO("SDK detected %d ports", numPorts);
    }

    ctx->num_cardinal_ports = (int)numPorts;
    if (ctx->num_cardinal_ports < 0) ctx->num_cardinal_ports = 0;
    if (ctx->num_cardinal_ports > 64) ctx->num_cardinal_ports = 64;
    for (int i = 0; i < ctx->num_cardinal_ports; i++)
        ctx->cardinal_ports[i] = (int)portList[i];
    sdk_port_cache_reset(ctx);
    sdk_port_recovery_state_reset();
    ctx->pfe_cap.port_inventory_ok = true;
    ctx->pfe_cap.switch_enabled = true;

    // Send control-plane link-local multicast to CPU without bridging it.
    {
        fm_status s = configure_control_mac_rx_trap(main_sw,
                                                    ctx->cardinal_ports,
                                                    ctx->num_cardinal_ports);
        fm_int control_action = FM_RES_MAC_ACTION_SWITCH;
        if (s == FM_OK)
            NL_LOG_INFO("control MAC external RX trap trigger enabled");
        else {
            NL_LOG_WARN("control MAC external RX trap trigger failed: %s; using TRAP",
                        fmErrorMsg(s));
            control_action = FM_RES_MAC_ACTION_TRAP;
            packet_io_ok = false;
        }

        s = set_reserved_mac_action(main_sw, 0x00, control_action);
        if (s == FM_OK)
            NL_LOG_INFO("BPDU CPU handling enabled: 01:80:c2:00:00:00 -> %s",
                        control_action == FM_RES_MAC_ACTION_SWITCH ?
                        "SWITCH+EXT-TRAP" : "TRAP");
        else
            NL_LOG_WARN("BPDU CPU trap failed: %s", fmErrorMsg(s));

        s = set_reserved_mac_action(main_sw, 0x0E, control_action);
        if (s == FM_OK)
            NL_LOG_INFO("LLDP CPU handling enabled: 01:80:c2:00:00:0e -> %s",
                        control_action == FM_RES_MAC_ACTION_SWITCH ?
                        "SWITCH+EXT-TRAP" : "TRAP");
        else {
            NL_LOG_WARN("LLDP CPU trap failed: %s", fmErrorMsg(s));
            packet_io_ok = false;
        }

        s = set_reserved_mac_action(main_sw, 0x02, control_action);
        if (s == FM_OK)
            NL_LOG_INFO("LACP CPU handling enabled: 01:80:c2:00:00:02 -> %s",
                        control_action == FM_RES_MAC_ACTION_SWITCH ?
                        "SWITCH+EXT-TRAP" : "TRAP");
        else {
            NL_LOG_WARN("LACP CPU trap failed: %s", fmErrorMsg(s));
            packet_io_ok = false;
        }
    }

    if (hal_control_plane_init(main_sw) == 0)
        NL_LOG_INFO("control-plane protection initialized");
    else {
        NL_LOG_WARN("control-plane protection initialization incomplete");
        packet_io_ok = false;
    }

    // Dynamic LAG mode forwards LACP PDUs to the application; lacpd owns
    // the protocol state machine and switchd only provides packet I/O.
    {
        fm_int mode = FM_MODE_DYNAMIC;
        fm_status s = fmSetSwitchAttribute(main_sw, FM_LAG_MODE, &mode);
        if (s == FM_OK)
            NL_LOG_INFO("LACP mode: dynamic (PDUs to lacpd)");
        else
            NL_LOG_WARN("LACP mode set failed: %s", fmErrorMsg(s));
    }

    // Per basic.c example: create default VLAN and init all ports
    NL_LOG_INFO("SDK bringup step 6: create default VLAN + init ports");
    st = fmCreateVlan(main_sw, 1);
    if (st != FM_OK && st != FM_ERR_VLAN_ALREADY_EXISTS) {
        NL_LOG_ERR("fmCreateVlan(1) failed: %s", fmErrorMsg(st));
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "fmCreateVlan(1): %s", fmErrorMsg(st));
        goto fail;
    }

    for (int i = 0; i < (int)numPorts; i++) {
        fm_int port = portList[i];

        // Skip CPU port and PCIe ports — they don't need link init
        fm_bool isPcie = FALSE;
        fmIsPciePort(main_sw, port, &isPcie);
        fm_bool isSpecial = FALSE;
        fmIsSpecialPort(main_sw, port, &isSpecial);
        if (isPcie) {
            NL_LOG_INFO("  port %d: PCIe port%s, skipping link init",
                        port, isSpecial ? "/special" : "");
            sdk_port_cache_set(ctx, (int)port, -1, -1, 0);
            continue;
        }
        if (isSpecial)
            NL_LOG_INFO("  port %d: special port, will init anyway", port);

        if (!counters_ok) {
            fm_portCounters cnt;
            memset(&cnt, 0, sizeof(cnt));
            fm_status cs = fmGetPortCounters(main_sw, port, &cnt);
            if (cs == FM_OK) {
                counters_ok = true;
                counter_probe_port = (int)port;
            } else if (counter_probe_failures++ == 0) {
                NL_LOG_WARN("  port %d: counter read probe failed: %s",
                            port, fmErrorMsg(cs));
            }
        }

        fm_bool present = FALSE;
        fm_status xs = fmPlatformXcvrIsPresent(main_sw, port, &present);
        if (xs == FM_OK)
            transceiver_i2c_ok = true;
        else
            NL_LOG_WARN("  port %d: transceiver presence probe failed: %s",
                        port, fmErrorMsg(xs));
        if ((xs != FM_OK || present) && sdk_port_recovery_candidate(port) &&
                n_retrain_ports < NETLAB_PORT_RETRAIN_MAX)
            retrain_ports[n_retrain_ports++] = port;

        // 7a: Port admin UP (brings SerDes out of power-down)
        if (sdk_bootstrap_port_admin_up(main_sw, port) != 0) {
            NL_LOG_WARN("  port %d: admin up failed", port);
            port_programming_ok = false;
            sdk_port_cache_set(ctx, (int)port, 0, 0, 0);
            continue;
        }
        sdk_port_cache_set(ctx, (int)port, 1, -1, 0);

        // 7b: Add to default VLAN (untagged)
        st = fmAddVlanPort(main_sw, 1, port, FALSE);
        if (st != FM_OK) {
            NL_LOG_WARN("  port %d: fmAddVlanPort failed: %s",
                        port, fmErrorMsg(st));
            vlan_programming_ok = false;
        }

        // 7c: STP FORWARDING — required for traffic to flow
        st = fmSetVlanPortState(main_sw, 1, port, FM_STP_STATE_FORWARDING);
        if (st != FM_OK) {
            NL_LOG_WARN("  port %d: fmSetVlanPortState(FWD) failed: %s",
                        port, fmErrorMsg(st));
            vlan_mode_programming_ok = false;
        }
        else {
            // Verify STP state was actually set
            fm_int chk_stp;
            fm_status chk = fmGetVlanPortState(main_sw, 1, port, &chk_stp);
            if (chk == FM_OK)
                NL_LOG_INFO("  port %d: VLAN 1 STP state=%d", port, (int)chk_stp);
        }

        // 7d: PVID = 1
        fm_uint32 pv = 1;
        st = fmSetPortAttribute(main_sw, port, FM_PORT_DEF_VLAN, &pv);
        if (st != FM_OK) {
            NL_LOG_WARN("  port %d: PVID set failed: %s",
                        port, fmErrorMsg(st));
            pvid_programming_ok = false;
        }

        // 7f: Parser level — required for L3 routing, optional for L2
        fm_uint32 parser = FM_PORT_PARSER_STOP_AFTER_L4;
        st = fmSetPortAttribute(main_sw, port, FM_PORT_PARSER, &parser);
        if (st != FM_OK) {
            NL_LOG_WARN("  port %d: parser set failed: %s",
                        port, fmErrorMsg(st));
            vlan_mode_programming_ok = false;
        }

        // FM10000 requires the wide logical-port mask. Build it from the
        // authoritative SDK inventory and prove the exact write by read-back.
        st = sdk_set_wide_egress_mask(main_sw, port, portList, numPorts);
        if (st != FM_OK) {
            NL_LOG_WARN("  port %d: wide egress mask apply/read-back failed: %s",
                        port, fmErrorMsg(st));
            vlan_mode_programming_ok = false;
            readback_verify_ok = false;
        }

        // Read back and log link state with human-readable strings
        if (sdk_refresh_port_state(ctx, main_sw, port, NULL, "  ") != FM_OK)
            readback_verify_ok = false;
    }

    sdk_retrain_present_ports(ctx, main_sw, retrain_ports, n_retrain_ports);

    if (counters_ok)
        NL_LOG_INFO("port counter read probe OK on port %d", counter_probe_port);
    else
        NL_LOG_WARN("port counter read probe failed on all non-PCIe ports");

    if (sdk_executor_init(&ctx->exec, ctx->sw) != 0) {
        NL_LOG_ERR("sdk_executor_init failed");
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "sdk_executor_init");
        goto fail;
    }
    if (hw_state_tracker_init(&ctx->hw_tracker) != NL_OK) {
        NL_LOG_ERR("hw_state_tracker_init failed");
        snprintf(ctx->pfe_cap.init_error, sizeof(ctx->pfe_cap.init_error),
                 "hw_state_tracker_init");
        goto fail;
    }

    ctx->initialized = true;
    ctx->pfe_cap.sdk_initialized = true;
    ctx->pfe_cap.port_programming_ok = port_programming_ok;
    ctx->pfe_cap.vlan_programming_ok = vlan_programming_ok;
    ctx->pfe_cap.pvid_programming_ok = pvid_programming_ok;
    ctx->pfe_cap.vlan_mode_programming_ok = vlan_mode_programming_ok;
    ctx->pfe_cap.readback_verify_ok = readback_verify_ok;
    ctx->pfe_cap.counters_ok = counters_ok;
    ctx->pfe_cap.packet_io_ok = packet_io_ok;
    ctx->pfe_cap.transceiver_i2c_ok = transceiver_i2c_ok;

    {
        nl_platform_identity ident;
        if (nl_platform_identity_get(&ident) && ident.model[0])
            NL_LOG_NOTICE("SDK bringup complete: %s ready with %d ports",
                          ident.model, numPorts);
        else
            NL_LOG_NOTICE("SDK bringup complete: switch ready with %d ports",
                          numPorts);
    }
    return 0;

fail:
    ctx->initialized = false;
    /*
     * The pinned raw-socket destroy API closes the descriptor but does not
     * join its listener thread.  A failed bringup after successful raw
     * initialization therefore requires process exit even when best-effort
     * resource teardown below succeeds.
     */
    if (ctx->raw_socket_started)
        cleanup_unproven = true;
    if (sdk_context_cleanup_resources(ctx) != 0) {
        cleanup_unproven = true;
    }
    ctx->cleanup_failed = cleanup_unproven;
    if (cleanup_unproven)
        NL_LOG_CRIT(
            "SDK bringup unwind could not prove complete resource cleanup");
    return -1;
}

static int sdk_context_cleanup_resources(struct sdk_context *ctx) {
    fm_status st;
    bool capture_transition = false;

    if (!ctx)
        return 0;
    ctx->initialized = false;
    ctx->pfe_cap.sdk_initialized = false;
    sdk_executor_shutdown(&ctx->exec);

    /*
     * Close publication first, then cross both pinned-SDK FIFO queues with a
     * software sentinels.  The second handler acknowledgement proves every
     * callback and event release older than the first sentinel has completed;
     * only then can capture and the final event mask be completed.
     */
    if (ctx->capture_started) {
        sflow_capture_shutdown_begin();
        capture_transition = true;
    }
    if (ctx->event_delivery_started &&
        sdk_event_barrier_drain(ctx->sw, ctx->switch_up) != 0) {
        if (capture_transition)
            sflow_capture_shutdown_cancel();
        NL_LOG_CRIT(
            "SDK teardown blocked: event FIFO barrier did not complete");
        return -1;
    }
    if (capture_transition) {
        if (sflow_capture_shutdown_wait() != 0) {
            NL_LOG_CRIT(
                "SDK teardown blocked: capture ownership did not quiesce");
            return -1;
        }
        ctx->capture_started = false;
    }
    if (ctx->event_delivery_started) {
        if (sdk_event_barrier_stop() != 0) {
            NL_LOG_CRIT(
                "SDK teardown blocked: final event mask failed");
            return -1;
        }
        ctx->event_delivery_started = false;
    }

    if (ctx->raw_socket_started) {
        st = fmRawPacketSocketDestroy(ctx->sw);
        if (st != FM_OK) {
            NL_LOG_CRIT(
                "SDK raw packet socket cleanup failed: %s",
                fmErrorMsg(st));
            return -1;
        }
        ctx->raw_socket_started = false;
        ctx->pfe_cap.packet_io_ok = false;
    }
    if (ctx->switch_state_touched) {
        st = fmSetSwitchState(ctx->sw, FALSE);
        if (st != FM_OK) {
            NL_LOG_CRIT(
                "SDK switch-down cleanup failed: %s", fmErrorMsg(st));
            return -1;
        }
        ctx->switch_state_touched = false;
        ctx->switch_up = false;
        ctx->pfe_cap.switch_enabled = false;
    }
    hw_state_tracker_destroy(&ctx->hw_tracker);
    ctx->cleanup_failed = false;
    return 0;
}

int sdk_shutdown(struct sdk_context *ctx) {
    if (!ctx)
        return 0;
    NL_LOG_INFO("SDK shutdown");
    if (sdk_context_cleanup_resources(ctx) != 0) {
        ctx->cleanup_failed = true;
        return -1;
    }
    free(ctx);
    return 0;
}

/* Called only by the SDK executor after the board's closed-port and fan
 * bootstrap. Data-port enable, VLAN membership and protocol configuration
 * are supplied later by configd's complete, versioned replay. */
int sdk_fm10k_control_initialize(struct sdk_context *ctx, const char *netdev) {
    if (!ctx || !ctx->exec || !netdev || !*netdev || ctx->sw != 0 ||
        !fm10k_startup_control() || fm10k_native_ready() || ctx->raw_socket_started ||
        ctx->num_cardinal_ports < 24 || ctx->num_cardinal_ports > 64)
        return NL_ERR_INVALID_VALUE;
    fm_int sw = ctx->sw;
    fm_status status;
#define CONTROL_CHECK(call) do { status = (call); if (status != FM_OK) { \
    NL_LOG_ERR("native control bootstrap: %s: %s", #call, fmErrorMsg(status)); \
    return NL_ERR_SDK_CALL_FAILED; } } while (0)
    configure_ffu_slice_allocation(sw);
    /* Control bootstrap still holds all external ports closed. Use the
     * board's stable unicast identity for hardware-generated PAUSE/PFC. */
    u8 pause_mac_bytes[NL_MAC_ADDR_LEN];
    fm_macaddr pause_mac = 0, actual_pause_mac = 0;
    if (!nl_platform_system_mac(pause_mac_bytes) || (pause_mac_bytes[0] & 1))
        return NL_ERR_INVALID_VALUE;
    for (int i = 0; i < NL_MAC_ADDR_LEN; i++) pause_mac = (pause_mac << 8) | pause_mac_bytes[i];
    if (!pause_mac) return NL_ERR_INVALID_VALUE;
    CONTROL_CHECK(fmSetSwitchAttribute(sw, FM_SWITCH_PAUSE_SMAC, &pause_mac));
    CONTROL_CHECK(fmGetSwitchAttribute(sw, FM_SWITCH_PAUSE_SMAC, &actual_pause_mac));
    if (pause_mac != actual_pause_mac) return NL_ERR_READBACK_MISMATCH;
    CONTROL_CHECK(hal_qos_roce_buffer_ready(sw));
    /* Record even a failed partial raw-socket attempt for the SDK shutdown
     * path, whose listener thread cannot safely be reused in this process. */
    ctx->raw_socket_started = true;
    CONTROL_CHECK(fmRawPacketSocketHandlingInitialize(sw, FALSE, (char *)netdev));
    CONTROL_CHECK(configure_control_mac_rx_trap(sw, ctx->cardinal_ports, ctx->num_cardinal_ports));
    CONTROL_CHECK(set_reserved_mac_action(sw, 0x00, FM_RES_MAC_ACTION_SWITCH));
    CONTROL_CHECK(set_reserved_mac_action(sw, 0x0e, FM_RES_MAC_ACTION_SWITCH));
    CONTROL_CHECK(set_reserved_mac_action(sw, 0x02, FM_RES_MAC_ACTION_SWITCH));
    if (hal_control_plane_init(sw) != 0) return NL_ERR_SDK_CALL_FAILED;
    fm_int lag_mode = FM_MODE_DYNAMIC, actual_lag = -1;
    CONTROL_CHECK(fmSetSwitchAttribute(sw, FM_LAG_MODE, &lag_mode));
    CONTROL_CHECK(fmGetSwitchAttribute(sw, FM_LAG_MODE, &actual_lag));
    if (actual_lag != lag_mode) return NL_ERR_READBACK_MISMATCH;
    status = fmCreateVlan(sw, 1);
    if (status != FM_OK && status != FM_ERR_VLAN_ALREADY_EXISTS) return NL_ERR_SDK_CALL_FAILED;
    fm_int members[64], count = 0;
    CONTROL_CHECK(fmGetVlanPortList(sw, 1, &count, members, 64));
    if (count < 0 || count > 64) return NL_ERR_READBACK_MISMATCH;
    for (int i = 0; i < count; ++i)
        if (members[i] >= 1 && members[i] <= 24)
            CONTROL_CHECK(fmDeleteVlanPort(sw, 1, members[i]));
    count = 0;
    CONTROL_CHECK(fmGetVlanPortList(sw, 1, &count, members, 64));
    if (count < 0 || count > 64) return NL_ERR_READBACK_MISMATCH;
    for (int i = 0; i < count; ++i)
        if (members[i] >= 1 && members[i] <= 24) return NL_ERR_READBACK_MISMATCH;
    for (fm_int port = 1; port <= 24; ++port) {
        fm_uint32 pvid = 1, actual = 0;
        CONTROL_CHECK(fmSetPortAttribute(sw, port, FM_PORT_DEF_VLAN, &pvid));
        CONTROL_CHECK(fmGetPortAttribute(sw, port, FM_PORT_DEF_VLAN, &actual));
        if (actual != pvid) return NL_ERR_READBACK_MISMATCH;
        fm_uint32 parser = FM_PORT_PARSER_STOP_AFTER_L4;
        CONTROL_CHECK(fmSetPortAttribute(sw, port, FM_PORT_PARSER, &parser));
        CONTROL_CHECK(fmGetPortAttribute(sw, port, FM_PORT_PARSER, &actual));
        if (actual != parser) return NL_ERR_READBACK_MISMATCH;
        CONTROL_CHECK(sdk_set_wide_egress_mask(sw, port, ctx->cardinal_ports, ctx->num_cardinal_ports));
    }
    fm_portCounters counters;
    memset(&counters, 0, sizeof(counters));
    CONTROL_CHECK(fmGetPortCounters(sw, 1, &counters));
    ctx->pfe_cap.port_programming_ok = true;
    ctx->pfe_cap.vlan_programming_ok = true;
    ctx->pfe_cap.pvid_programming_ok = true;
    ctx->pfe_cap.vlan_mode_programming_ok = true;
    ctx->pfe_cap.readback_verify_ok = true;
    ctx->pfe_cap.counters_ok = true;
    ctx->pfe_cap.packet_io_ok = true;
    return fm10k_native_mark_ready();
#undef CONTROL_CHECK
}
