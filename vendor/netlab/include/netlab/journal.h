/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_JOURNAL_H
#define NETLAB_JOURNAL_H

#include "types.h"
#include <stddef.h>

#define NL_TX_ID_STR_LEN 32
#define NL_JOURNAL_DIR   "/var/lib/netlab/journal"
#define NL_CONFIG_DIR    "/var/lib/netlab"
#define NL_JOURNAL_SCHEMA_VERSION 2
#define NL_JOURNAL_RETENTION_DEFAULT 512

const char *nl_config_dir(void);
const char *nl_journal_dir(void);
void nl_config_file_path(char *buf, size_t size, const char *name);
void nl_journal_file_path(char *buf, size_t size, const char *name);

typedef enum {
    NL_JOURNAL_PREPARED            = 0,
    NL_JOURNAL_APPLYING            = 1,
    NL_JOURNAL_VERIFYING           = 2,
    NL_JOURNAL_VERIFY_OK           = 3,
    NL_JOURNAL_HW_MARKED_COMMITTED = 4,
    NL_JOURNAL_COMMITTED           = 5,
    NL_JOURNAL_FAILED_ROLLED_BACK  = 6,
    NL_JOURNAL_HW_OUT_OF_SYNC      = 7,
    NL_JOURNAL_RECONCILED_TO_ACTIVE = 8,
} nl_journal_state;

typedef struct {
    u32     schema_version;
    u64     tx_id;
    u64     base_commit_id;
    char    candidate_hash[65];
    nl_journal_state state;
    char    plan[4096];           // serialized apply plan
    char    applied_steps[4096];  // completed steps (JSON array)
    char    rollback_steps[4096]; // undo ops (JSON array)
    u64     resulting_commit_id;
    bool    commit_confirmed;
    s64     confirm_deadline;
    u64     confirm_previous_commit_id;
    s64     started_at;
    s64     updated_at;
    bool    legacy_malformed_state;
    s64     confirm_monotonic_deadline;
    char    confirm_boot_id[37];
} nl_commit_journal;

typedef struct {
    bool   migrated;
    u64    scanned;
    u64    unresolved;
    u64    retained_terminal;
    u64    removed_terminal;
} nl_journal_migration_stats;

// Journal CRUD
nl_status nl_journal_create(u64 tx_id, u64 base_commit_id,
                            const char *candidate_hash);
nl_status nl_journal_set_plan(u64 tx_id, const char *plan_json);
nl_status nl_journal_update_state(u64 tx_id, nl_journal_state state);
nl_status nl_journal_append_applied(u64 tx_id, const char *step_json);
nl_status nl_journal_append_rollback(u64 tx_id, const char *step_json);
nl_status nl_journal_set_resulting_commit(u64 tx_id, u64 commit_id);
nl_status nl_journal_set_confirmed_intent(
    u64 tx_id, u64 previous_commit_id, s64 deadline);
nl_status nl_journal_set_confirmed_intent_monotonic(
    u64 tx_id, u64 previous_commit_id, s64 deadline, s64 seconds);
nl_status nl_journal_get(u64 tx_id, nl_commit_journal *j);

// Crash recovery
nl_status nl_journal_initialize_v2(size_t retention_limit,
                                   nl_journal_migration_stats *stats);
nl_status nl_journal_scan_unresolved(nl_commit_journal *journals,
                                     int *count, int max);
nl_status nl_journal_scan(nl_commit_journal *journals, int *count, int max);
nl_status nl_journal_recover(nl_commit_journal *j);
nl_status nl_journal_persist_state(u64 tx_id, nl_journal_state state);

// Commit confirmed persistence
typedef struct {
    u64     tx_id;
    s64     confirm_deadline;
    u64     previous_commit_id;
    enum { NL_CONFIRM_AWAITING, NL_CONFIRMED, NL_TIMED_OUT } state;
    s64     confirm_monotonic_deadline;
    char    confirm_boot_id[37];
} nl_commit_confirmed;

nl_status nl_confirmed_save(nl_commit_confirmed *c);
/*
 * Remove only the canonical zero-valued TIMED_OUT sentinel emitted by the
 * legacy writer.  Current confirmed records remain subject to strict parsing.
 */
nl_status nl_confirmed_migrate_legacy_terminal_sentinel(bool *migrated);
/* Parse only; unlike nl_confirmed_load(), do not advance an expired record. */
nl_status nl_confirmed_load_readonly(nl_commit_confirmed *c);
nl_status nl_confirmed_load(nl_commit_confirmed *c);
/* Negative means the clock could not be verified; never treat that as expiry.
 * New records expire across a system reboot; same-boot daemon restarts keep
 * the original monotonic deadline. Old records retain their UTC semantics. */
s64 nl_confirmed_remaining_seconds(const nl_commit_confirmed *c);
s64 nl_confirmed_display_deadline(const nl_commit_confirmed *c);

// tx_id persistence
nl_status nl_tx_id_save(u64 tx_id);
nl_status nl_tx_id_load(u64 *tx_id);

/*
 * Transaction attempts and committed configuration generations are different
 * authorities.  tx_counter is the durable pointer to the active immutable
 * snapshot.  tx_sequence only reserves never-reused transaction IDs, including
 * attempts that later roll back.
 */
nl_status nl_tx_sequence_next(u64 minimum, u64 *tx_id);

#endif
