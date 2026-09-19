/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/port_scope.h"
#include <fm_sdk.h>
#include <api/fm_api_pkt.h>
#include <api/fm_api_buffer.h>
#include <api/fm_api_event_types.h>
#include <platform_buffer_defs.h>
#include <string.h>
#include <pthread.h>

// Packet TX path
int hal_packet_tx(int sw, int port, const u8 *data, int len) {
    fm_buffer *head = NULL;
    fm_buffer *tail = NULL;
    int offset = 0;

    if (!data || len <= 0 || len > NETLAB_PACKET_IO_MAX) {
        return -1;
    }

    {
        fm_int mode = -1;
        fm_int state = -1;
        fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
        fm_status pst = fmGetPortState((fm_int)sw, (fm_int)port,
                                       &mode, &state, info);
        if (pst == FM_OK && ((int)mode != 0 || (int)state != 0)) {
            NL_LOG_DBG("packet tx skipped: port=%d mode=%d state=%d",
                       port, (int)mode, (int)state);
            return -1;
        }
    }

    while (offset < len) {
        fm_buffer *buf = fmAllocateBuffer(sw);
        int chunk_len = len - offset;
        fm_uint32 *dst;

        if (!buf) {
            if (head) fmFreeBufferChain(sw, head);
            return -1;
        }

        if (chunk_len > FM_BUFFER_SIZE_BYTES) chunk_len = FM_BUFFER_SIZE_BYTES;
        dst = fmGetBufferDataPtr(buf);
        if (!dst || fmSetBufferDataLength(buf, chunk_len) != FM_OK) {
            fmFreeBuffer(sw, buf);
            if (head) fmFreeBufferChain(sw, head);
            return -1;
        }

        memcpy((u8 *)dst, data + offset, (size_t)chunk_len);
        buf->next = NULL;
        if (tail) tail->next = buf;
        else head = buf;
        tail = buf;
        offset += chunk_len;
    }

    fm_int portList[1];
    portList[0] = (fm_int)port;

    fm_status st = fmSendPacketDirected((fm_int)sw, portList, 1, head);
    if (st != FM_OK) {
        NL_LOG_WARN("fmSendPacketDirected port=%d len=%d: %s", port, len, fmErrorMsg(st));
        fmFreeBufferChain(sw, head);
        return -1;
    }
    return 0;
}

// --- Packet RX capture ring buffer ---

#define PKT_RX_BUF_COUNT 256
#define PKT_RX_BUF_SIZE  NETLAB_PACKET_IO_MAX

typedef struct {
    u8    data[PKT_RX_BUF_SIZE];
    int   len;
    int   src_port;
    int   vlan;
    u64   captured_at;
    bool  valid;
} pkt_rx_slot;

static pkt_rx_slot g_pkt_rx[PKT_RX_BUF_COUNT];
static int g_pkt_rx_write = 0;
static int g_pkt_rx_read = 0;
static pthread_mutex_t g_pkt_rx_lock = PTHREAD_MUTEX_INITIALIZER;

// Direct: SDK passes fm_eventPktRecv* as ptr, not wrapped in fm_event*
void hal_packet_capture_direct(fm_eventPktRecv *pkt_info) {
    u8 frame[PKT_RX_BUF_SIZE];
    int copy_len = 0;
    fm_buffer *buf;

    if (!pkt_info || !pkt_info->pkt) return;
    u64 captured_at = nl_port_scope_clock();

    for (buf = (fm_buffer *)pkt_info->pkt; buf; buf = buf->next) {
        if (!buf->data || buf->len <= 0 ||
            buf->len > PKT_RX_BUF_SIZE - copy_len) {
            NL_LOG_WARN("packet capture rejected invalid buffer chain: "
                        "port=%d vlan=%d captured=%d chunk=%d max=%d",
                        pkt_info->srcPort, pkt_info->vlan, copy_len,
                        buf->len, PKT_RX_BUF_SIZE);
            return;
        }
        memcpy(frame + copy_len, (u8 *)buf->data, (size_t)buf->len);
        copy_len += buf->len;
    }

    if (!nl_port_scope_packet_enter(pkt_info->srcPort, captured_at)) return;
    pthread_mutex_lock(&g_pkt_rx_lock);
    int next = (g_pkt_rx_write + 1) % PKT_RX_BUF_COUNT;
    if (next != g_pkt_rx_read) {
        pkt_rx_slot *slot = &g_pkt_rx[g_pkt_rx_write];
        memcpy(slot->data, frame, (size_t)copy_len);
        slot->len = copy_len;
        slot->src_port = pkt_info->srcPort;
        slot->vlan = pkt_info->vlan;
        slot->captured_at = captured_at;
        slot->valid = true;
        g_pkt_rx_write = next;
    }
    pthread_mutex_unlock(&g_pkt_rx_lock);
    nl_port_scope_leave(pkt_info->srcPort);
    NL_LOG_DBG("packet captured: port=%d vlan=%d len=%d", pkt_info->srcPort, pkt_info->vlan, copy_len);
}

// Legacy wrapper
void hal_packet_capture(fm_event *event) {
    fm_eventPktRecv *pkt_info = &event->info.fpPktEvent;
    if (!pkt_info->pkt) return;
    hal_packet_capture_direct(pkt_info);
}

// RPC poll: returns length of dequeued packet, or 0 if empty
int hal_packet_rx_poll(int sw, u8 *buf, int buf_size) {
    return hal_packet_rx_poll_stamped(sw, buf, buf_size, NULL, NULL, NULL);
}

int hal_packet_rx_poll_meta(int sw, u8 *buf, int buf_size,
                            int *src_port, int *vlan) {
    return hal_packet_rx_poll_stamped(sw, buf, buf_size, src_port, vlan, NULL);
}

int hal_packet_rx_poll_stamped(int sw, u8 *buf, int buf_size,
                               int *src_port, int *vlan, u64 *captured_at) {
    (void)sw;
    if (!buf || buf_size <= 0) return -1;
    pthread_mutex_lock(&g_pkt_rx_lock);
    while (g_pkt_rx_read != g_pkt_rx_write) {
        pkt_rx_slot *head = &g_pkt_rx[g_pkt_rx_read];
        if (nl_port_scope_packet_enter(head->src_port, head->captured_at)) break;
        head->valid = false;
        g_pkt_rx_read = (g_pkt_rx_read + 1) % PKT_RX_BUF_COUNT;
    }
    if (g_pkt_rx_read == g_pkt_rx_write) {
        pthread_mutex_unlock(&g_pkt_rx_lock);
        return 0;
    }

    pkt_rx_slot *slot = &g_pkt_rx[g_pkt_rx_read];
    int copy_len = slot->len;
    if (copy_len > buf_size) copy_len = buf_size;
    memcpy(buf, slot->data, copy_len);
    if (src_port) *src_port = slot->src_port;
    if (vlan) *vlan = slot->vlan;
    if (captured_at) *captured_at = slot->captured_at;
    int source = slot->src_port;
    slot->valid = false;
    g_pkt_rx_read = (g_pkt_rx_read + 1) % PKT_RX_BUF_COUNT;
    pthread_mutex_unlock(&g_pkt_rx_lock);
    nl_port_scope_leave(source);
    return copy_len;
}
