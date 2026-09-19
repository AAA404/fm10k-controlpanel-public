#define main lacpd_daemon_entry
#include "../vendor/netlab/sbin/lacpd/main.c"
#undef main
#include <assert.h>

static const char *active_path;
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
void nl_config_file_path(char *out, size_t capacity, const char *name) {
    assert(!strcmp(name, "active.conf")); snprintf(out, capacity, "%s", active_path);
}
static void negotiate(lacp_lag *lag) {
    for (int i = 0; i < lag->n_members; ++i) {
        lacp_member *member = &lag->members[i];
        member->link_up = member->hw_attached = member->partner_valid = true;
        member->last_rx = nl_monotonic_seconds(); member->rx_pdus = 42;
        member->partner = (lacp_info){.system_priority = 32768, .system_mac = {2,0,0,0,0,2},
            .key = 99, .port_priority = 32768, .port = (u16)member->port,
            .state = LACP_STATE_AGGREGATION | LACP_STATE_SYNC};
        member->partner_view_of_us = (lacp_info){.system_priority = g_lacp.system_priority,
            .key = lag_actor_key(lag), .port_priority = member_actor_port_priority(member), .port = (u16)member->port};
        memcpy(member->partner_view_of_us.system_mac, g_lacp.actor_mac, 6);
    }
}
int main(int argc, char **argv) {
    assert(argc == 4 && nl_ifid_resolver_init(NULL) == NL_OK && !nl_port_scope_init("lacpd"));
    load_system_mac(g_actor_mac); memcpy(g_lacp.actor_mac, g_actor_mac, 6);
    active_path = argv[1]; assert(load_config_locked(true));
    g_lacp.native_hw_valid = true; /* This fixture isolates configuration reload. */
    for (int ae = 0; ae < 3; ++ae) {
        lacp_lag *lag = &g_lacp.lags[ae]; assert(lag->configured && lag->n_members == 2);
        lag->lag_id = ae + 1; lag->logical_port = 100 + ae;
        negotiate(lag);
        assert(member_oper_up(lag, &lag->members[0], nl_monotonic_seconds()));
    }
    unsigned changed = (unsigned)strtoul(argv[3], NULL, 16);
    active_path = argv[2]; assert(load_config_locked(true));
    for (int ae = 0; ae < 3; ++ae) {
        lacp_lag *lag = &g_lacp.lags[ae];
        for (int i = 0; i < lag->n_members; ++i) {
            lacp_member *member = &lag->members[i];
            if (changed & (1U << ae)) {
                assert(!member->partner_valid && !member->hw_attached);
                assert(!member_oper_up(lag, member, nl_monotonic_seconds()));
                assert(!(actor_state(lag, member, nl_monotonic_seconds()) & LACP_STATE_DISTRIBUTING));
            } else {
                assert(member->partner_valid && member->hw_attached && member->rx_pdus == 42);
                assert(member_oper_up(lag, member, nl_monotonic_seconds()));
            }
        }
        negotiate(lag);
        assert(member_oper_up(lag, &lag->members[0], nl_monotonic_seconds()));
    }
    puts("LACP reload: changed groups renegotiate and unchanged groups retain their runtime state");
    return 0;
}
