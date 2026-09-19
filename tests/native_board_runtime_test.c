/* Production cache path before the first SDK poll. No SDK process or bus is
 * initialized; unused hardware functions are discarded by the fixture linker. */
#include "../vendor/netlab/sbin/switchd/fm10k_board_runtime.c"
#include "../hardware/native/fm10k_monitor.c"
#include <assert.h>

static const char *configured_profile;
static fm_rootPlatform platform;
static fm_platformCfgSwitch switch_config;
static fm_platformCfgPort port_config[30];
fm_rootPlatform *fmRootPlatform = &platform;
bool nl_platform_identity_get(nl_platform_identity *out) {
    if (!configured_profile) return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->chassis_name, sizeof(out->chassis_name), "%s", configured_profile);
    return true;
}
bool nl_platform_board_get(nl_board_profile *out) {
    memset(out, 0, sizeof(*out));
    return false;
}
int main(void) {
    char output[4096];
    const char *profiles[] = {"sil001-hw4-b0", "sil001-hw5-a11"};
    for (unsigned i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i) {
        configured_profile = profiles[i];
        assert(fm10k_native_profile() && !fm10k_native_bound());
        assert(fm10k_native_cache(output, sizeof(output)) > 0);
        assert(strstr(output, profiles[i]) && strstr(output, "\"board_hal\":\"unbound\""));
        assert(strstr(output, "\"celsius\":null") && !g_bus.attached);
    }
    configured_profile = "unknown-board";
    assert(!fm10k_native_profile() && !fm10k_native_bound());
    assert(fm10k_native_cache(output, sizeof(output)) > 0 && strstr(output, "\"profile\":\"unknown\""));
    configured_profile = "sil001-hw5-a11";
    platform.cfg.numSwitches = 1;
    assert(!fm10k_native_aux_port(0, 28));
    platform.cfg.switches = &switch_config;
    switch_config.ports = port_config;
    platform.cfg.switches[0].numPorts = 30;
    for (int port = 28; port <= 29; ++port) {
        fm_platformCfgPort *p = &platform.cfg.switches[0].ports[port];
        p->port = p->portIdx = port;
        p->portType = FM_PLAT_PORT_TYPE_TUNNEL; p->tunnel = port - 28;
        assert(fm10k_native_aux_port(0, port));
        p->portType = FM_PLAT_PORT_TYPE_EPL;
        assert(!fm10k_native_aux_port(0, port));
    }
    assert(!fm10k_native_aux_port(0, 1) && !fm10k_native_aux_port(1, 28));
    configured_profile = NULL;
    assert(fm10k_native_cache(output, sizeof(output)) > 0 && strstr(output, "\"profile\":\"unknown\""));
    assert(!g_bus.attached);
    puts("profile-specific pending cache does not initialize or bind hardware");
    return 0;
}
