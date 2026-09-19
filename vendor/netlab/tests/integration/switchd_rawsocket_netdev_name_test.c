#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../sbin/switchd/sdk_init.c"

static int g_failed;

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failed++;
}

int main(void) {
    struct {
        char name[4];
        unsigned char guard[8];
    } small;
    char output[64];
    char longest_valid[IFNAMSIZ];
    char oversized[IFNAMSIZ + 1U];
    bool guard_ok = true;

    memset(longest_valid, 'n', sizeof(longest_valid) - 1U);
    longest_valid[sizeof(longest_valid) - 1U] = '\0';
    memset(oversized, 'x', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';

    memset(output, 0xa5, sizeof(output));
    expect("ordinary raw-socket netdev name copies exactly",
           copy_rawsocket_netdev_name(
               output, sizeof(output), "fm0") &&
           strcmp(output, "fm0") == 0);
    memset(output, 0xa5, sizeof(output));
    expect("IFNAMSIZ minus one name is accepted",
           copy_rawsocket_netdev_name(
               output, IFNAMSIZ, longest_valid) &&
           strcmp(output, longest_valid) == 0);

    memset(output, 0xa5, sizeof(output));
    expect("IFNAMSIZ name fails closed",
           !copy_rawsocket_netdev_name(
               output, sizeof(output), oversized) &&
           output[0] == '\0');
    memset(&small, 0xa5, sizeof(small));
    expect("undersized netdev output fails closed",
           !copy_rawsocket_netdev_name(
               small.name, sizeof(small.name), "fm10") &&
           small.name[0] == '\0');
    for (size_t i = 0; i < sizeof(small.guard); i++)
        if (small.guard[i] != 0xa5)
            guard_ok = false;
    expect("undersized netdev output preserves canary", guard_ok);

    expect("null raw-socket netdev name is rejected",
           !copy_rawsocket_netdev_name(
               output, sizeof(output), NULL) &&
           output[0] == '\0');
    expect("zero-sized raw-socket output is rejected",
           !copy_rawsocket_netdev_name(output, 0, "fm0"));

    expect("valid raw-socket environment override is exact",
           setenv("NETLAB_RAW_SOCKET_IFACE", "fm0", 1) == 0 &&
           discover_rawsocket_netdev(output, sizeof(output)) &&
           strcmp(output, "fm0") == 0);
    memset(output, 0xa5, sizeof(output));
    expect("oversized environment override fails closed",
           setenv("NETLAB_RAW_SOCKET_IFACE", oversized, 1) == 0 &&
           !discover_rawsocket_netdev(output, sizeof(output)) &&
           output[0] == '\0');
    (void)unsetenv("NETLAB_RAW_SOCKET_IFACE");

    if (g_failed != 0) {
        printf("FAIL: %d raw-socket netdev-name checks failed\n",
               g_failed);
        return 1;
    }
    printf("PASS: raw-socket netdev names are complete or rejected\n");
    return 0;
}
