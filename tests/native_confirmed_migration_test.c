#include "netlab/journal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char path[1024];

static void write_record(const char *text) {
    FILE *file = fopen(path, "wb");
    assert(file && fwrite(text, 1, strlen(text), file) == strlen(text));
    assert(fclose(file) == 0);
}

static void unchanged(const char *text) {
    char buffer[1024] = {0};
    FILE *file = fopen(path, "rb");
    assert(file);
    assert(fread(buffer, 1, sizeof(buffer), file) == strlen(text));
    assert(fclose(file) == 0 && strcmp(buffer, text) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(setenv("NETLAB_JOURNAL_DIR", argv[1], 1) == 0);
    snprintf(path, sizeof(path), "%s/confirmed.json", argv[1]);
    bool migrated = true;
    assert(nl_confirmed_migrate_legacy_terminal_sentinel(&migrated) == NL_OK && !migrated);
    const char *states[] = {"CONFIRMED", "AWAITING_CONFIRM", "TIMED_OUT"};
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
        char record[512];
        snprintf(record, sizeof(record),
                 "{\n  \"tx_id\": \"0x000000000000001b\",\n"
                 "  \"confirm_deadline\": 1,\n"
                 "  \"previous_commit_id\": \"0x000000000000001a\",\n"
                 "  \"state\": \"%s\"\n}\n", states[i]);
        write_record(record);
        migrated = true;
        assert(nl_confirmed_migrate_legacy_terminal_sentinel(&migrated) == NL_OK && !migrated);
        unchanged(record);  /* Expired pending records are never advanced here. */
        nl_commit_confirmed current;
        assert(nl_confirmed_load_readonly(&current) == NL_OK && current.tx_id == 27);
    }
    const char legacy[] = "{\n  \"tx_id\": \"0x0000000000000000\",\n"
        "  \"confirm_deadline\": 0,\n  \"previous_commit_id\": \"0x0000000000000000\",\n"
        "  \"state\": \"TIMED_OUT\"\n}\n";
    write_record(legacy);
    assert(nl_confirmed_migrate_legacy_terminal_sentinel(&migrated) == NL_OK && migrated);
    assert(access(path, F_OK) != 0);
    const char *invalid[] = {"", "{broken", "{}", "{\"tx_id\": 0, \"confirm_deadline\": 1, \"previous_commit_id\": 0, \"state\": \"CONFIRMED\"}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        write_record(invalid[i]);
        assert(nl_confirmed_migrate_legacy_terminal_sentinel(&migrated) != NL_OK && !migrated);
        unchanged(invalid[i]);
    }
    assert(unlink(path) == 0);
    assert(symlink("missing-authority", path) == 0);
    assert(nl_confirmed_migrate_legacy_terminal_sentinel(&migrated) != NL_OK && !migrated);
    struct stat metadata;
    assert(lstat(path, &metadata) == 0 && S_ISLNK(metadata.st_mode));
    assert(unlink(path) == 0);
    puts("confirmed record migration: current authority preserved; only exact legacy sentinel removed");
    return 0;
}
