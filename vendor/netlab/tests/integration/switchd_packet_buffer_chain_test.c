#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/hal_packet.c"

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...)
{
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

static int check_chain_capture(void)
{
    u8 first[1024];
    u8 second[490];
    u8 received[NETLAB_PACKET_IO_MAX];
    fm_buffer tail = {0};
    fm_buffer head = {0};
    fm_eventPktRecv event = {0};
    int src_port = -1;
    int vlan = -1;
    int len;
    int i;

    for (i = 0; i < (int)sizeof(first); i++) first[i] = (u8)(i & 0xff);
    for (i = 0; i < (int)sizeof(second); i++) second[i] = (u8)(0xa0 + i % 31);

    tail.data = (fm_uint32 *)second;
    tail.len = (int)sizeof(second);
    head.data = (fm_uint32 *)first;
    head.len = (int)sizeof(first);
    head.next = &tail;
    event.pkt = &head;
    event.srcPort = 3;
    event.vlan = 4094;

    hal_packet_capture_direct(&event);
    len = hal_packet_rx_poll_meta(0, received, sizeof(received),
                                  &src_port, &vlan);
    if (len != (int)(sizeof(first) + sizeof(second)) ||
        src_port != 3 || vlan != 4094 ||
        memcmp(received, first, sizeof(first)) != 0 ||
        memcmp(received + sizeof(first), second, sizeof(second)) != 0) {
        fprintf(stderr, "chain capture mismatch: len=%d port=%d vlan=%d\n",
                len, src_port, vlan);
        return 1;
    }
    return 0;
}

static int check_oversize_chain_rejected(void)
{
    u8 chunk[1024] = {0};
    u8 extra = 0;
    u8 received[NETLAB_PACKET_IO_MAX];
    fm_buffer third = {0};
    fm_buffer second = {0};
    fm_buffer first = {0};
    fm_eventPktRecv event = {0};

    third.data = (fm_uint32 *)&extra;
    third.len = 1;
    second.data = (fm_uint32 *)chunk;
    second.len = (int)sizeof(chunk);
    second.next = &third;
    first.data = (fm_uint32 *)chunk;
    first.len = (int)sizeof(chunk);
    first.next = &second;
    event.pkt = &first;

    hal_packet_capture_direct(&event);
    if (hal_packet_rx_poll(0, received, sizeof(received)) != 0) {
        fprintf(stderr, "oversize chain was partially captured\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    if (check_chain_capture() != 0) return 1;
    if (check_oversize_chain_rejected() != 0) return 1;
    puts("PASS: switchd reconstructs chained SDK packet buffers");
    return 0;
}
