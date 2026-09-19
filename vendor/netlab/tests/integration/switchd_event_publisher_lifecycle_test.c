#include "netlab/hal.h"
#include "netlab/event.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static int test_create_calls;
static int test_fail_next_create;

static int test_pthread_create(pthread_t *thread,
                               const pthread_attr_t *attr,
                               void *(*start_routine)(void *),
                               void *arg) {
    test_create_calls++;
    if (test_fail_next_create) {
        test_fail_next_create = 0;
        return EAGAIN;
    }
    return pthread_create(thread, attr, start_routine, arg);
}

#define pthread_create test_pthread_create
#include "../../sbin/switchd/sdk_event_handler.c"
#undef pthread_create

static int test_bus_token;

nl_event_bus *nl_eventbus_create(u64 publisher_id, u64 epoch) {
    (void)publisher_id;
    (void)epoch;
    return (nl_event_bus *)&test_bus_token;
}

void nl_eventbus_destroy(nl_event_bus *bus) {
    (void)bus;
}

nl_status nl_eventbus_publish(nl_event_bus *bus, const char *topic,
                              void *data, u32 len) {
    (void)bus;
    (void)topic;
    (void)data;
    (void)len;
    return NL_OK;
}

static int check(const char *name, int ok) {
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    return ok ? 0 : 1;
}

static void *stop_publisher(void *arg) {
    (void)arg;
    sdk_event_publisher_stop();
    return NULL;
}

int main(void) {
    struct sdk_context ctx;
    pthread_t stop_a;
    pthread_t stop_b;
    int stop_a_rc;
    int stop_b_rc;
    int failed = 0;

    memset(&ctx, 0, sizeof(ctx));

    test_fail_next_create = 1;
    failed += check(
        "publisher propagates pthread_create failure",
        sdk_event_publisher_start(&ctx) == -1 && test_create_calls == 1);
    sdk_event_publisher_stop();
    sdk_event_publisher_stop();
    failed += check(
        "stop is safe after failed start",
        !g_publisher_running && !g_publisher_thread_started &&
        !g_publisher_joining);

    failed += check(
        "publisher starts after a prior create failure",
        sdk_event_publisher_start(&ctx) == 0 && test_create_calls == 2);
    failed += check(
        "duplicate start does not create a second thread",
        sdk_event_publisher_start(&ctx) == 0 && test_create_calls == 2);
    sdk_event_publisher_stop();
    sdk_event_publisher_stop();
    failed += check(
        "repeated stop never joins an uncreated thread",
        !g_publisher_running && !g_publisher_thread_started &&
        !g_publisher_joining);

    failed += check(
        "publisher can restart after a complete stop",
        sdk_event_publisher_start(&ctx) == 0 && test_create_calls == 3);
    sdk_event_publisher_stop();
    failed += check(
        "restart-stop returns to a clean lifecycle state",
        !g_publisher_running && !g_publisher_thread_started &&
        !g_publisher_joining);

    failed += check(
        "publisher starts for concurrent stop coverage",
        sdk_event_publisher_start(&ctx) == 0 && test_create_calls == 4);
    stop_a_rc = pthread_create(&stop_a, NULL, stop_publisher, NULL);
    stop_b_rc = pthread_create(&stop_b, NULL, stop_publisher, NULL);
    failed += check(
        "concurrent stop callers start",
        stop_a_rc == 0 && stop_b_rc == 0);
    if (stop_a_rc == 0)
        (void)pthread_join(stop_a, NULL);
    if (stop_b_rc == 0)
        (void)pthread_join(stop_b, NULL);
    sdk_event_publisher_stop();
    failed += check(
        "concurrent stop callers share one join safely",
        !g_publisher_running && !g_publisher_thread_started &&
        !g_publisher_joining);

    return failed ? 1 : 0;
}
