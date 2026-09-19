#include "../vendor/netlab/sbin/l2d/l2_hw_probe.c"
#include "../vendor/netlab/sbin/l2d/l2d_switchd.h"
#include <assert.h>

static const char present[] = "<multicast-owner status=\"ok\"><group id=\"7\" vlan=\"100\" mac=\"01:00:5e:01:01:01\">"
    "<listener port=\"1\" vlan=\"100\"/><listener port=\"5\" vlan=\"100\"/></group>"
    "<summary groups=\"1\" listeners=\"2\"/></multicast-owner>";
static const char empty[] = "<multicast-owner><summary groups=\"0\" listeners=\"0\"/></multicast-owner>";
static const char *reply = present;
static int calls, failure, returned_size;

const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    (void)name; return fallback;
}
int nl_rpc_call_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                  nl_rpc_method method, u64 tx, const u8 *payload, int length,
                  u8 *out, int capacity, int timeout, s32 *error) {
    (void)path; (void)tx; (void)payload; (void)timeout;
    assert(caller == NL_DAEMON_L2D && service == NL_DAEMON_SWITCHD &&
           method == NL_SWITCHD_L2_MULTICAST_OWNER_GET && !length);
    ++calls; *error = failure;
    if (returned_size) return returned_size;
    size_t size = strlen(reply);
    assert(size < (size_t)capacity);
    memcpy(out, reply, size);
    return (int)size;
}
static void replace_once(char *text, const char *from, const char *to) {
    char *at = strstr(text, from); assert(at);
    size_t before = strlen(from), after = strlen(to), tail = strlen(at + before) + 1;
    memmove(at + after, at + before, tail); memcpy(at, to, after);
}
int main(void) {
    assert(nl_mcast_readback_valid(present, strlen(present)));
    assert(nl_mcast_readback_valid(empty, strlen(empty)));
    assert(!nl_mcast_readback_valid(present, strlen(present) - 1));
    const char *bad[] = {"", "<multicast-owner/>", "<multicast-owner status=\"unavailable\"/>",
        "<multicast-owner><summary groups=\"1\" listeners=\"0\"/></multicast-owner>",
        "<multicast-owner><summary groups=\"0\" listeners=\"0\"/></multicast-owner>junk"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(!nl_mcast_readback_valid(bad[i], strlen(bad[i])));
    const char *changes[][2] = {
        {"listeners=\"2\"", "listeners=\"1\""}, {"groups=\"1\"", "groups=\"99\""},
        {"id=\"7\"", "id=\"0\""}, {"id=\"7\"", "id=\"999999999999999999999999\""},
        {"port=\"5\"", "port=\"1\""}, {"port=\"5\"", "port=\"25\""},
        {"vlan=\"100\"", "vlan=\"0100\""}, {"mac=\"01", "mac=\"00"},
        {"port=\"5\" vlan=\"100\"", "port=\"5\" vlan=\"200\""},
        {"</group>", "</group><unknown/>"}, {"</multicast-owner>", ""},
    };
    for (unsigned i = 0; i < sizeof(changes) / sizeof(changes[0]); ++i) {
        char text[1024]; strcpy(text, present); replace_once(text, changes[i][0], changes[i][1]);
        assert(!nl_mcast_readback_valid(text, strlen(text)));
    }
    char duplicate[2048]; strcpy(duplicate, present);
    const char *second = "<group id=\"8\" vlan=\"100\" mac=\"01:00:5e:01:01:01\"><listener port=\"9\" vlan=\"100\"/></group>";
    char insert[512]; snprintf(insert, sizeof(insert), "%s<summary", second);
    replace_once(duplicate, "<summary", insert);
    replace_once(duplicate, "groups=\"1\" listeners=\"2\"", "groups=\"2\" listeners=\"3\"");
    assert(!nl_mcast_readback_valid(duplicate, strlen(duplicate)));
    replace_once(duplicate, "01:00:5e:01:01:01", "01:00:5e:01:01:02");
    assert(nl_mcast_readback_valid(duplicate, strlen(duplicate)));

    cfg_igmp_listener_intent entry = {.vid = 100, .port.hw_port = 1, .mac = {1, 0, 0x5e, 1, 1, 1}};
    char error[256], output[4096];
    l2_hw_probe_begin(true);
    assert(!l2_hw_igmp_listener_missing(&entry));
    entry.port.hw_port = 9; assert(l2_hw_igmp_listener_missing(&entry));
    assert(calls == 1 && l2_hw_probe_finish(error, sizeof(error)) && !g_probe_state.multicast.text);
    reply = "<multicast-owner status=\"unavailable\"/>";
    l2_hw_probe_begin(true);
    assert(!l2_hw_igmp_listener_missing(&entry));
    assert(!l2_hw_igmp_listener_missing(&entry));
    assert(calls == 2 && !l2_hw_probe_finish(error, sizeof(error)));
    reply = empty;
    l2_hw_probe_begin(true);
    assert(l2_hw_igmp_listener_missing(&entry));
    assert(calls == 3 && l2_hw_probe_finish(error, sizeof(error)));
    assert(l2d_switchd_get_multicast_owner("fixture", output, sizeof(output)) == (int)strlen(empty));
    reply = "<multicast-owner><summary groups=\"0\" listeners=\"0\"/>";
    assert(l2d_switchd_get_multicast_owner("fixture", output, sizeof(output)) < 0 && !output[0]);
    reply = empty; failure = 1;
    assert(l2d_switchd_get_multicast_owner("fixture", output, sizeof(output)) < 0 && !output[0]);
    failure = 0; returned_size = sizeof(output);
    assert(l2d_switchd_get_multicast_owner("fixture", output, sizeof(output)) < 0 && !output[0]);
    puts("Multicast complete-reply contract, plan cache and runtime rejection passed");
    return 0;
}
