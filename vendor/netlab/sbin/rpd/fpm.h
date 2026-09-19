#ifndef RPD_FPM_H
#define RPD_FPM_H

#include "netlab/l3_capacity.h"
#include "netlab/types.h"
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>

#define RPD_FPM_DEFAULT_PORT 2620
#define RPD_FPM_HEADER_LEN 4
#define RPD_FPM_MAX_MESSAGE 65535
#define RPD_FPM_NH_CACHE_MAX NL_L3_DYNAMIC_MAX_UNIQUE_NEXTHOPS
#define RPD_FPM_NH_TEXT_MAX 1024
#define RPD_FPM_PENDING_MAX 8192
#define RPD_FPM_PENDING_BYTES_MAX (16U * 1024U * 1024U)
#define RPD_FPM_PEER_PATH_MAX 4096

enum {
    RPD_FPM_APPLY_AUTHORITY_REJECTED = -2,
    RPD_FPM_DECODE_ERROR = -1,
    RPD_FPM_DECODE_OK = 0,
    RPD_FPM_DECODE_DEFERRED = 1,
    RPD_FPM_DECODE_IGNORED = 2,
};

struct rpd_fpm_pending_frame;

typedef struct {
    pid_t pid;
    uid_t uid;
    u64 starttime;
    u64 generation;
    char executable[RPD_FPM_PEER_PATH_MAX];
} rpd_fpm_peer_authority;

typedef struct {
    pid_t pid;
    uid_t uid;
    u64 starttime;
    u64 socket_inode;
    u64 authority_generation;
    char executable[RPD_FPM_PEER_PATH_MAX];
} rpd_fpm_peer_identity;

typedef int (*rpd_fpm_authority_fn)(void *ctx,
                                    rpd_fpm_peer_authority *authority,
                                    char *err, size_t err_size);

typedef int (*rpd_fpm_apply_fn)(void *ctx,
                                const rpd_fpm_peer_identity *peer,
                                const char *payload,
                                int payload_len, char *err,
                                size_t err_size);

typedef struct {
    bool active;
    u32 id;
    char nexthops[RPD_FPM_NH_TEXT_MAX];
} rpd_fpm_nh_cache_entry;

typedef struct {
    bool enabled;
    bool thread_started;
    bool stop_requested;
    int listen_fd;
    int client_fd;
    int port;
    uid_t expected_peer_uid;
    char expected_peer_executable[RPD_FPM_PEER_PATH_MAX];
    pid_t last_peer_pid;
    uid_t last_peer_uid;
    u64 last_peer_starttime;
    u64 last_peer_socket_inode;
    u64 last_authority_generation;
    char last_peer_process_handle[16];
    char last_peer_executable[RPD_FPM_PEER_PATH_MAX];
    char status[32];
    char last_error[160];
    time_t last_connect;
    time_t last_frame;
    u64 connections;
    u64 peer_auth_failures;
    u64 peer_revalidations;
    u64 frames;
    u64 route_updates;
    u64 decode_errors;
    u64 ignored_updates;
    u64 deferred_updates;
    u64 deferred_replays;
    u64 deferred_drops;
    u64 apply_errors;
    u64 nh_cache_updates;
    u64 nh_cache_resets;
    u64 nh_cache_hits;
    u64 nh_cache_misses;
    u32 pending_frames;
    u64 pending_bytes;
    struct rpd_fpm_pending_frame *pending_head;
    struct rpd_fpm_pending_frame *pending_tail;
    rpd_fpm_nh_cache_entry nh_cache[RPD_FPM_NH_CACHE_MAX];
    pthread_t thread;
    pthread_mutex_t lock;
    rpd_fpm_authority_fn authority;
    void *authority_ctx;
    rpd_fpm_apply_fn apply;
    void *apply_ctx;
} rpd_fpm_listener;

void rpd_fpm_init(rpd_fpm_listener *fpm);
int rpd_fpm_start(rpd_fpm_listener *fpm, int port,
                  rpd_fpm_authority_fn authority, void *authority_ctx,
                  rpd_fpm_apply_fn apply, void *apply_ctx,
                  char *err, size_t err_size);
void rpd_fpm_stop(rpd_fpm_listener *fpm);
void rpd_fpm_destroy(rpd_fpm_listener *fpm);
int rpd_fpm_decode_message(const u8 *msg, size_t msg_len,
                           char *out, size_t out_size,
                           char *err, size_t err_size);
int rpd_fpm_decode_message_stateful(rpd_fpm_listener *fpm,
                                    const u8 *msg, size_t msg_len,
                                    char *out, size_t out_size,
                                    bool *cache_only,
                                    char *err, size_t err_size);
int rpd_fpm_append_xml(rpd_fpm_listener *fpm, char *buf,
                       size_t buf_size, size_t *off);

#endif
