/* Exercise the production readiness/bind state with no SDK or bus attached.
 * Only the completed-bootstrap prerequisite is supplied by this fixture. */
#include "../vendor/netlab/sbin/switchd/fm10k_board_runtime.c"
#include "../hardware/native/fm10k_monitor.c"
#include <assert.h>

static bool control;
bool fm10k_startup_control(void) { return control; }
bool nl_platform_identity_get(nl_platform_identity *out) {
    memset(out, 0, sizeof(*out));
    strcpy(out->chassis_name, "sil001-hw5-a11");
    return true;
}
bool nl_platform_board_get(nl_board_profile *out) {
    memset(out, 0, sizeof(*out));
    return false;
}
static void *foreign_thread(void *unused) {
    (void)unused;
    assert(fm10k_native_mark_ready() == FM10K_INVALID);
    return NULL;
}
int main(void) {
    char json[8192];
    assert(!nl_port_scope_init("lifecycle-fixture"));
    assert(!fm10k_native_ready() && !fm10k_native_bound());
    assert(fm10k_native_mark_ready() == FM10K_INVALID);
    control = true;
    g_bus.attached = true;
    g_bus.owner = pthread_self();
    assert(fm10k_native_mark_ready() == FM10K_INVALID);
    g_monitor.fan.curve_valid = true;
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, foreign_thread, NULL));
    assert(!pthread_join(thread, NULL));
    assert(!fm10k_native_mark_ready());
    u64 generation = atomic_load(&g_native_generation);
    assert(generation && fm10k_native_ready() && !fm10k_native_bound());
    assert(fm10k_native_mark_ready() == FM10K_INVALID);
    assert(fm10k_native_bind(generation ^ 1U, 42) != 0);
    assert(fm10k_native_bind(generation, 0) != 0);
    assert(!nl_port_scope_begin(42, 15, 100));
    assert(fm10k_native_bind(generation, 42) != 0);
    assert(!nl_port_scope_end(42));
    assert(!fm10k_native_bind(generation, 42) && fm10k_native_bound());
    assert(fm10k_native_cache(json, sizeof(json)) > 0);
    assert(strstr(json, "\"board_hal\":\"bound\"") && strstr(json, "\"native_ready\":true"));
    /* A new SDK lifetime cannot reuse a previous readiness acknowledgement. */
    atomic_store(&g_native_bound, false);
    atomic_store(&g_native_generation, 0);
    assert(!fm10k_native_mark_ready());
    u64 replacement = atomic_load(&g_native_generation);
    assert(replacement != generation);
    assert(fm10k_native_bind(generation, 42) != 0 && !fm10k_native_bound());
    assert(!fm10k_native_bind(replacement, 43));
    puts("native lifecycle: bootstrap prerequisite, owner thread, leases and SDK epoch verified");
    return 0;
}
