#include "../vendor/netlab/sbin/l2d/igmp_snooping.c"
#include <assert.h>

static int adds, deletes;
static bool fail_delete;
static int fail_add_port, fail_delete_port;
static bool fail_add_before, fail_delete_after;
static bool present[25];
bool nl_ifid_is_user_port(int port) { return port >= 1 && port <= 24; }
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    (void)name;
    return fallback;
}
int l2d_switchd_apply_igmp_listener(const char *socket_path, bool add, int vid,
                                  int port, const char *group, u64 txid) {
    (void)socket_path; (void)txid;
    assert(vid == 100 && port >= 1 && port <= 24 &&
           (!strcmp(group, "239.1.1.1") || !strcmp(group, "239.129.1.1")));
    if (add) ++adds;
    else ++deletes;
    bool failure = add ? fail_add_port == port : fail_delete || fail_delete_port == port;
    if (failure && (add ? fail_add_before : !fail_delete_after)) return -1;
    present[port] = add;
    return failure ? -1 : 0;
}

static const char *snapshot(void) {
    static char text[2048];
    int off = snprintf(text, sizeof(text),
        "<multicast-owner><group id=\"1\" vlan=\"100\" mac=\"01:00:5e:01:01:01\">");
    for (int port = 1; port <= 24; ++port) if (present[port])
        off += snprintf(text + off, sizeof(text) - (size_t)off, "<listener port=\"%d\" vlan=\"100\"/>", port);
    snprintf(text + off, sizeof(text) - (size_t)off, "</group></multicast-owner>");
    return text;
}
int main(void) {
    assert(nl_port_scope_init("igmp-test") == 0);
    memset(&g_igmp, 0, sizeof(g_igmp));
    assert(pthread_mutex_init(&g_igmp.lock, NULL) == 0);
    g_igmp.enabled = true;
    g_igmp.membership_timeout = 260;
    g_igmp.vlans[0] = 100;
    g_igmp.n_vlans = 1;
    g_igmp.scopes[0] = (igmp_vlan_port_scope){.vid = 100, .port = 1};
    g_igmp.n_scopes = 1;
    const u8 mac[6] = {1, 0, 0x5e, 1, 1, 1};
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    assert(adds == 1 && g_igmp.runtime.dynamic[0].used);
    time_t deadline = g_igmp.runtime.dynamic[0].expires_at;
    process_leave(100, 1, 0xef010101);
    assert(g_igmp.runtime.dynamic[0].used && g_igmp.runtime.dynamic[0].expires_at == deadline && deletes == 0);
    g_igmp.scopes[0].fast_leave = true;
    fail_delete = true;
    process_leave(100, 1, 0xef010101);
    assert(g_igmp.runtime.dynamic[0].used && deletes == 1 && g_igmp.apply_failures == 1);
    fail_delete = false;
    process_leave(100, 1, 0xef010101);
    assert(!g_igmp.runtime.dynamic[0].used && deletes == 2);
    /* A static listener sharing the MAC keeps the actual hardware key. */
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    g_igmp.static_members[0].vid = 100;
    g_igmp.static_members[0].port.hw_port = 1;
    memcpy(g_igmp.static_members[0].mac, mac, 6);
    g_igmp.n_static_members = 1;
    process_leave(100, 1, 0xef010101);
    assert(!g_igmp.runtime.dynamic[0].used && deletes == 2);
    memset(g_igmp.static_members, 0, sizeof(g_igmp.static_members));
    g_igmp.n_static_members = 0;
    memset(present, 0, sizeof(present));
    g_igmp.scopes[1] = (igmp_vlan_port_scope){.vid = 100, .port = 5, .mrouter = true};
    g_igmp.scopes[2] = (igmp_vlan_port_scope){.vid = 200, .port = 13, .mrouter = true};
    g_igmp.vlans[1] = 200; g_igmp.n_vlans = 2; g_igmp.n_scopes = 3;
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    assert(present[1] && present[5] && !present[13]);
    assert(igmp_snooping_dynamic_hardware_key_present(100, 5, mac));
    int before_adds = adds;
    process_report(100, 1, "239.129.1.1", 0xef810101, mac);
    assert(adds == before_adds); /* One MAC owner for two IPv4 aliases. */
    process_leave(100, 1, 0xef010101);
    assert(present[1] && present[5]);

    g_igmp.scopes[1].port = 9;
    fail_delete_port = 5;
    sync_router_groups_locked(NULL, IGMP_ROUTER_WRITE_BUDGET);
    assert(present[5] && present[9] && g_igmp.runtime.router_groups[0].uncertain_ports);
    fail_delete_port = 0;
    sync_router_groups_locked(NULL, IGMP_ROUTER_WRITE_BUDGET);
    assert(!present[5] && present[9] && present[1]);
    assert(nl_port_scope_begin(99, 1U << 8, 100) == 0);
    process_leave(100, 1, 0xef810101);
    assert(!present[1] && present[9] && g_igmp.runtime.router_groups[0].used);
    assert(nl_port_scope_end(99) == 0);
    sync_router_groups_locked(NULL, IGMP_ROUTER_WRITE_BUDGET);
    assert(!present[9] && !g_igmp.runtime.router_groups[0].used);

    /* A failed add can have reached hardware. Retain it for cleanup even
     * when the receiver leaves before a retry has succeeded. */
    fail_add_port = 9;
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    assert(present[9] && !(g_igmp.runtime.router_groups[0].applied_ports & (1U << 8)));
    assert(g_igmp.runtime.router_groups[0].uncertain_ports & (1U << 8));
    fail_add_port = 0;
    process_leave(100, 1, 0xef010101);
    assert(!present[1] && !present[9] && !g_igmp.runtime.router_groups[0].used);

    g_igmp.scopes[1] = (igmp_vlan_port_scope){.vid = 100, .port = 5};
    g_igmp.n_scopes = 2;
    present[13] = true; /* Unrelated membership is never adopted or deleted. */
    fail_add_port = 1;
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    assert(present[1] && g_igmp.runtime.dynamic[0].used && g_igmp.runtime.dynamic[0].pending);
    before_adds = adds;
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(!g_igmp.runtime.dynamic[0].pending && adds == before_adds); /* Lost reply, verified applied. */
    fail_add_port = 0;
    process_leave(100, 1, 0xef010101);
    assert(!present[1] && !g_igmp.runtime.dynamic[0].used);

    fail_add_port = 1; fail_add_before = true;
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    process_report(100, 1, "239.129.1.1", 0xef810101, mac);
    assert(!present[1] && g_igmp.runtime.dynamic[0].pending && g_igmp.runtime.dynamic[1].pending);
    before_adds = adds;
    assert(!nl_port_scope_begin(100, 1, 100));
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(adds == before_adds && g_igmp.runtime.dynamic[0].pending);
    assert(!nl_port_scope_end(100));
    fail_add_port = 0; fail_add_before = false;
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(adds == before_adds + 1 && present[1]); /* One retry per MAC key, not per IPv4 alias. */
    assert(!g_igmp.runtime.dynamic[0].pending && !g_igmp.runtime.dynamic[1].pending);
    process_leave(100, 1, 0xef010101);
    assert(present[1]);
    process_leave(100, 1, 0xef810101);
    assert(!present[1]);

    /* Delete can succeed before its reply is lost. Expiry must not re-add
     * the retiring key in the reconciliation phase of that same tick. */
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    g_igmp.runtime.dynamic[0].expires_at = igmp_clock_seconds() - 1;
    fail_delete = fail_delete_after = true;
    expire_dynamic_members_locked(igmp_clock_seconds());
    assert(!present[1] && g_igmp.runtime.dynamic[0].retiring && g_igmp.runtime.dynamic[0].pending);
    before_adds = adds;
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(!present[1] && adds == before_adds);
    fail_delete = fail_delete_after = false;
    expire_dynamic_members_locked(igmp_clock_seconds());
    assert(!g_igmp.runtime.dynamic[0].used && !present[1]);

    /* A fresh report can cancel pending removal and legitimately restore it. */
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    fail_delete = fail_delete_after = true;
    process_leave(100, 1, 0xef010101);
    assert(g_igmp.runtime.dynamic[0].retiring && !present[1]);
    fail_delete = fail_delete_after = false;
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
    assert(!g_igmp.runtime.dynamic[0].retiring && g_igmp.runtime.dynamic[0].pending);
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(present[1] && !g_igmp.runtime.dynamic[0].pending);
    process_leave(100, 1, 0xef010101);
    assert(present[13] && !present[1]);

    /* Missing hardware after restart is replayed in bounded, fair batches. */
    memset(present, 0, sizeof(present));
    present[24] = true;
    for (int i = 0; i < 17; ++i) {
        g_igmp.scopes[i] = (igmp_vlan_port_scope){.vid = 100, .port = i + 1};
        g_igmp.runtime.dynamic[i] = (igmp_dynamic_member){.used = true, .vid = 100, .port = i + 1,
            .group = "239.1.1.1", .group_ip = 0xef010101, .expires_at = igmp_clock_seconds() + 260};
        memcpy(g_igmp.runtime.dynamic[i].mac, mac, 6);
    }
    g_igmp.n_scopes = 17; g_igmp.dynamic_cursor = 0;
    before_adds = adds;
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(adds == before_adds + 16 && !present[17] && g_igmp.runtime.dynamic[16].pending);
    sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
    assert(adds == before_adds + 17 && present[17] && present[24]);
    pthread_mutex_destroy(&g_igmp.lock);
    puts("IGMP: uncertain receiver/router ownership, no resurrection after expiry, aliases, pause and bounded replay passed");
    return 0;
}
