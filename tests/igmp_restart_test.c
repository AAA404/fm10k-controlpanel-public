#include "../vendor/netlab/sbin/l2d/igmp_snooping.c"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>

static char hardware_path[1024], lease_path[1024];
static bool present[25];
static unsigned additions[25], deletions[25];
static int crash_add, crash_delete;
static time_t lease(bool write_lease);

bool nl_ifid_is_user_port(int port) { return port >= 1 && port <= 24; }
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    (void)name; return fallback;
}
static void save_hardware(void) {
    FILE *file = fopen(hardware_path, "wb");
    assert(file && fwrite(present, sizeof(present), 1, file) == 1);
    assert(fflush(file) == 0 && fsync(fileno(file)) == 0 && fclose(file) == 0);
}
int l2d_switchd_apply_igmp_listener(const char *socket_path, bool add, int vid,
                                 int port, const char *group, u64 txid) {
    (void)socket_path; (void)group;
    assert(vid == 100 && port > 0 && port < 24 && txid);
    present[port] = add;
    if (add) ++additions[port]; else ++deletions[port];
    save_hardware();
    /* Terminate the process after the mock SDK mutation and before its RPC
     * reply. No shutdown callback or post-write checkpoint can run. */
    if ((add && crash_add == port) || (!add && crash_delete == port)) {
        if (add) lease(true);
        _exit(add ? 42 : 43);
    }
    return 0;
}
static const char *snapshot(void) {
    static char text[2048];
    int off = snprintf(text, sizeof(text),
        "<multicast-owner><group id=\"1\" vlan=\"100\" mac=\"01:00:5e:01:01:01\">");
    for (int port = 1; port <= 24; ++port) if (present[port])
        off += snprintf(text + off, sizeof(text) - (size_t)off,
                        "<listener port=\"%d\" vlan=\"100\"/>", port);
    snprintf(text + off, sizeof(text) - (size_t)off, "</group></multicast-owner>");
    return text;
}
static time_t lease(bool write_lease) {
    FILE *file = fopen(lease_path, write_lease ? "w" : "r");
    assert(file);
    long long value = (long long)g_igmp.runtime.dynamic[0].expires_at;
    if (write_lease) assert(fprintf(file, "%lld\n", value) > 0);
    else assert(fscanf(file, "%lld", &value) == 1);
    assert(fclose(file) == 0);
    return (time_t)value;
}
static void report(void) {
    const u8 mac[6] = {1, 0, 0x5e, 1, 1, 1};
    process_report(100, 1, "239.1.1.1", 0xef010101, mac);
}
int main(int argc, char **argv) {
    assert(argc == 3);
    char state_dir[1024], scope_dir[1024];
    snprintf(state_dir, sizeof(state_dir), "%s/state", argv[1]);
    snprintf(scope_dir, sizeof(scope_dir), "%s/scopes", argv[1]);
    snprintf(hardware_path, sizeof(hardware_path), "%s/hardware.bin", argv[1]);
    snprintf(lease_path, sizeof(lease_path), "%s/lease", argv[1]);
    assert(!setenv("NETLAB_IGMP_STATE_DIR", state_dir, 1));
    assert(!setenv("NETLAB_PORT_SCOPE_DIR", scope_dir, 1));
    assert(!setenv("NETLAB_FM10K_NATIVE", "1", 1));
    assert(!nl_port_scope_init("igmp-restart-test"));
    assert(!pthread_mutex_init(&g_igmp.lock, NULL));
    g_igmp.enabled = true; g_igmp.membership_timeout = 260;
    g_igmp.vlans[0] = 100; g_igmp.n_vlans = 1;
    g_igmp.scopes[0] = (igmp_vlan_port_scope){.vid = 100, .port = 1, .fast_leave = true};
    g_igmp.scopes[1] = (igmp_vlan_port_scope){.vid = 100, .port = 5, .mrouter = true};
    g_igmp.n_scopes = 2;
    FILE *hardware = fopen(hardware_path, "rb");
    if (hardware) { assert(fread(present, sizeof(present), 1, hardware) == 1); fclose(hardware); }
    else { present[24] = true; save_hardware(); }
    if (!strcmp(argv[2], "corrupt")) {
        int dir = open(state_dir, O_RDONLY | O_DIRECTORY);
        assert(dir >= 0);
        int fd = openat(dir, "ownership.v1", O_WRONLY | O_TRUNC);
        assert(fd >= 0 && write(fd, "partial\n", 8) == 8);
        close(fd); close(dir);
        assert(igmp_state_open(&g_igmp_store, &g_igmp.runtime) == -1);
        assert(!g_igmp.runtime.dynamic[0].used && present[1] && present[24]);
        return 0;
    }
    assert(!igmp_state_open(&g_igmp_store, &g_igmp.runtime));
    if (!strcmp(argv[2], "crash-add")) {
        crash_add = 1;
        report();
        assert(!"Expected the lost ADD reply to terminate the process");
    } else if (!strcmp(argv[2], "recover-add-crash-delete")) {
        assert(present[1] && g_igmp.runtime.dynamic[0].used && g_igmp.runtime.dynamic[0].pending);
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false));
        u64 sequence = g_igmp.runtime.tx_sequence;
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        assert(!g_igmp.runtime.dynamic[0].pending && !additions[1]);
        sync_router_groups_locked(snapshot(), IGMP_ROUTER_WRITE_BUDGET);
        assert(present[5] && additions[5] == 1 && g_igmp.runtime.tx_sequence > sequence);
        crash_delete = 1;
        process_leave(100, 1, 0xef010101);
        assert(!"Expected the lost DELETE reply to terminate the process");
    } else if (!strcmp(argv[2], "recover-delete")) {
        assert(!present[1] && present[5] && g_igmp.runtime.dynamic[0].retiring);
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false));
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        assert(!additions[1]);
        expire_dynamic_members_locked(igmp_clock_seconds());
        sync_router_groups_locked(snapshot(), IGMP_ROUTER_WRITE_BUDGET);
        assert(!g_igmp.runtime.dynamic[0].used && !g_igmp.runtime.router_groups[0].used);
        assert(!present[1] && !present[5] && present[24]);
        assert(deletions[1] == 1 && deletions[5] == 1 && !additions[1]);
    } else if (!strcmp(argv[2], "router-crash-add")) {
        crash_add = 5; report();
        assert(!"Expected router ADD to terminate the process");
    } else if (!strcmp(argv[2], "router-recover")) {
        assert(present[1] && present[5] && g_igmp.runtime.router_groups[0].uncertain_ports == (1U << 4));
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false));
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        sync_router_groups_locked(snapshot(), IGMP_ROUTER_WRITE_BUDGET);
        assert(!additions[1] && !additions[5] && !g_igmp.runtime.router_groups[0].uncertain_ports);
        process_leave(100, 1, 0xef010101);
        assert(!present[1] && !present[5] && present[24]);
    } else if (!strcmp(argv[2], "aliases-prepare")) {
        report();
        const u8 mac[6] = {1, 0, 0x5e, 1, 1, 1};
        process_report(100, 1, "239.129.1.1", 0xef810101, mac);
        _exit(0);
    } else if (!strcmp(argv[2], "aliases-recover")) {
        assert(g_igmp.runtime.dynamic[0].used && g_igmp.runtime.dynamic[1].used);
        assert(!memcmp(g_igmp.runtime.dynamic[0].mac, g_igmp.runtime.dynamic[1].mac, 6));
        assert(g_igmp.runtime.dynamic[0].group_ip != g_igmp.runtime.dynamic[1].group_ip);
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        assert(!additions[1]);
        g_igmp.n_static_members = 1;
        g_igmp.static_members[0].vid = 100; g_igmp.static_members[0].port.hw_port = 1;
        memcpy(g_igmp.static_members[0].mac, g_igmp.runtime.dynamic[0].mac, 6);
        process_leave(100, 1, 0xef010101);
        process_leave(100, 1, 0xef810101);
        assert(present[1] && !present[5] && present[24] && !deletions[1]);
    } else if (!strcmp(argv[2], "expire-prepare")) {
        report();
        g_igmp.runtime.dynamic[0].expires_at = igmp_clock_seconds() - 1;
        assert(checkpoint_locked());
        lease(true);
        _exit(0);
    } else if (!strcmp(argv[2], "expire-recover")) {
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false));
        expire_dynamic_members_locked(igmp_clock_seconds());
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        sync_router_groups_locked(snapshot(), IGMP_ROUTER_WRITE_BUDGET);
        assert(!present[1] && !present[5] && present[24] && !additions[1]);
    } else if (!strcmp(argv[2], "failed-checkpoint")) {
        assert(checkpoint_locked()); /* Install an empty durable image. */
        int directory = g_igmp_store.directory;
        g_igmp_store.directory = -1;
        report();
        assert(g_igmp.checkpoint_error && !present[1] && !present[5] && !additions[1]);
        g_igmp_store.directory = directory;
        _exit(0); /* Unsaved intent never reached hardware. */
    } else if (!strcmp(argv[2], "recover-empty")) {
        assert(!g_igmp.runtime.dynamic[0].used && !g_igmp.runtime.router_groups[0].used);
        assert(!present[1] && !present[5] && present[24]);
    } else if (!strcmp(argv[2], "pause-prepare")) {
        report(); lease(true);
        assert(!nl_port_scope_begin(123, 1, 100));
        resume_listener_timers(1, 10);
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false) + 10);
        _exit(0); /* Timer checkpoint exists; the scope is still held. */
    } else if (!strcmp(argv[2], "pause-recover")) {
        assert(nl_port_scope_paused(1));
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false) + 10);
        resume_listener_timers(1, 10);
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false) + 10);
        resume_listener_timers(1, 12);
        assert(g_igmp.runtime.dynamic[0].expires_at == lease(false) + 12);
        assert(!nl_port_scope_end(123));
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        sync_router_groups_locked(snapshot(), IGMP_ROUTER_WRITE_BUDGET);
        assert(!additions[1] && !additions[5] && present[24]);
    } else if (!strcmp(argv[2], "new-boot-prepare")) {
        report();
        strcpy(g_igmp_store.boot_id, "00000000-0000-0000-0000-000000000000");
        g_igmp_store.has_fingerprint = false;
        assert(checkpoint_locked());
        _exit(0);
    } else if (!strcmp(argv[2], "new-boot-recover")) {
        assert(!g_igmp.runtime.dynamic[0].used && !g_igmp.runtime.router_groups[0].used);
        sync_dynamic_members_locked(snapshot(), IGMP_MEMBER_WRITE_BUDGET);
        sync_router_groups_locked(snapshot(), IGMP_ROUTER_WRITE_BUDGET);
        assert(present[1] && present[5] && present[24]); /* Unknown hardware is not adopted or deleted. */
        assert(!additions[1] && !deletions[1]);
    } else if (!strcmp(argv[2], "lock")) {
        igmp_state_store other;
        igmp_runtime_image *image = calloc(1, sizeof(*image));
        assert(image && igmp_state_open(&other, image) == -1);
        free(image);
        assert(checkpoint_locked());
        u64 saves = g_igmp_store.saves;
        assert(checkpoint_locked() && g_igmp_store.saves == saves);
    } else assert(!"Unknown phase");
    assert(checkpoint_locked());
    igmp_state_close(&g_igmp_store);
    pthread_mutex_destroy(&g_igmp.lock);
    puts("IGMP restart phase passed");
    return 0;
}
