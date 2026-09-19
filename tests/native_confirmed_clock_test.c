#include "netlab/journal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static time_t wall = 1700000000, monotonic = 1000;
static bool clock_failed;
time_t __wrap_time(time_t *out) { if (out) *out = wall; return wall; }
int __real_clock_gettime(clockid_t clock, struct timespec *out);
int __wrap_clock_gettime(clockid_t clock, struct timespec *out) {
    if (clock != CLOCK_MONOTONIC) return __real_clock_gettime(clock, out);
    if (clock_failed) { errno = EIO; return -1; }
    out->tv_sec = monotonic; out->tv_nsec = 0; return 0;
}

int main(int argc, char **argv) {
    assert(argc == 3 && !setenv("NETLAB_JOURNAL_DIR", argv[1], 1));
    nl_commit_confirmed c = {0}, actual = {0};
    nl_commit_journal journal;
    if (!strcmp(argv[2], "create")) {
        nl_journal_migration_stats stats;
        assert(nl_journal_initialize_v2(16, &stats) == NL_OK);
        assert(nl_journal_create(1, 0, "0000000000000000000000000000000000000000000000000000000000000000") == NL_OK);
        assert(nl_journal_set_confirmed_intent_monotonic(1, 0, wall + 60, 60) == NL_OK);
        assert(nl_journal_get(1, &journal) == NL_OK && journal.confirm_monotonic_deadline == 1060);
        c.tx_id = 1; c.confirm_deadline = journal.confirm_deadline;
        c.confirm_monotonic_deadline = journal.confirm_monotonic_deadline;
        memcpy(c.confirm_boot_id, journal.confirm_boot_id, sizeof(c.confirm_boot_id));
        assert(strlen(c.confirm_boot_id) == 36 && nl_confirmed_save(&c) == NL_OK);
        for (int shift = -1; shift <= 1; shift += 2) {
            wall = 1700000000 + shift * 86400;
            assert(nl_confirmed_load(&actual) == NL_OK && actual.state == NL_CONFIRM_AWAITING);
            assert(nl_confirmed_remaining_seconds(&actual) == 60);
            assert(nl_confirmed_display_deadline(&actual) == wall + 60);
        }
        puts("confirmed clock: NTP forward/backward corrections keep the original window");
        return 0;
    }
    assert(!strcmp(argv[2], "resume"));
    wall = 1900000000; monotonic = 1020;
    assert(nl_journal_get(1, &journal) == NL_OK && journal.confirm_monotonic_deadline == 1060);
    assert(nl_confirmed_load(&c) == NL_OK && c.state == NL_CONFIRM_AWAITING);
    assert(c.confirm_monotonic_deadline == journal.confirm_monotonic_deadline &&
           !strcmp(c.confirm_boot_id, journal.confirm_boot_id));
    assert(nl_confirmed_remaining_seconds(&c) == 40);
    assert(nl_confirmed_display_deadline(&c) == wall + 40);
    actual = c; actual.confirm_boot_id[0] = actual.confirm_boot_id[0] == '0' ? '1' : '0';
    assert(nl_confirmed_remaining_seconds(&actual) == 0); /* A different boot cannot retain an unconfirmed change. */
    clock_failed = true;
    assert(nl_confirmed_remaining_seconds(&c) < 0 && nl_confirmed_load(&actual) != NL_OK);
    assert(nl_confirmed_load_readonly(&actual) == NL_OK && actual.state == NL_CONFIRM_AWAITING);
    clock_failed = false; monotonic = 1060;
    assert(nl_confirmed_remaining_seconds(&c) == 0);
    assert(nl_confirmed_load(&actual) == NL_OK && actual.state == NL_TIMED_OUT);
    assert(actual.confirm_deadline == 1700000060);
    actual = c; actual.confirm_boot_id[0] = '#';
    assert(nl_confirmed_save(&actual) != NL_OK);
    actual = c; actual.confirm_monotonic_deadline = 0;
    assert(nl_confirmed_save(&actual) != NL_OK);
    /* Existing records without clock metadata keep their original format. */
    nl_commit_confirmed legacy = {.tx_id = 2, .confirm_deadline = wall + 20};
    assert(nl_confirmed_save(&legacy) == NL_OK && nl_confirmed_load(&actual) == NL_OK);
    assert(!actual.confirm_monotonic_deadline && !actual.confirm_boot_id[0]);
    assert(nl_confirmed_remaining_seconds(&actual) == 20);
    puts("confirmed clock: process restart, expiry, boot change, clock failure and legacy compatibility passed");
    return 0;
}
