#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include "vault.h"
#include "multi_stream.h"

/* --- App state (shared across request handlers) --- */

typedef struct {
    /* Session */
    char     session_token[64];
    int      has_session;

    /* Vault state */
    char     master_password[VAULT_PASSWORD_MAX];
    vault_t  vault;
    int      is_unlocked;
    uint8_t  current_dek[32];
    int      has_dek;
    char     entropy_source[16];

    /* Auto-lock */
    uint64_t auto_lock_minutes;
    uint64_t last_activity;  /* unix timestamp */

    /* Entropy rotation state */
    uint64_t key_epoch;
    uint64_t frames_processed;
    size_t   pool_depth;
    int      rotation_running;
    int      has_traffic_entropy;
    uint8_t  latest_entropy[32];

    /* Visualizer v2: last two camera/stream frames the rotation daemon
     * processed (current + previous). Heap-owned raw RGB pixel bytes; the
     * rotation daemon writes them under `lock`, GET /api/visualizer/frame
     * reads them. NULL until the first frame is consumed. */
    uint8_t *viz_frame_current;
    size_t   viz_frame_current_len;
    uint32_t viz_frame_current_w;
    uint32_t viz_frame_current_h;
    uint64_t viz_frame_current_seq;
    uint8_t *viz_frame_previous;
    size_t   viz_frame_previous_len;
    uint32_t viz_frame_previous_w;
    uint32_t viz_frame_previous_h;
    uint64_t viz_frame_previous_seq;

    /* Thread safety */
    pthread_mutex_t lock;

    /* Rotation thread control */
    int      rotation_stop;
    pthread_t rotation_thread;

    /* Stream config */
    stream_config_t stream_config;

    /* Multi-stream manager. Owns the per-stream forwarder threads and the
     * shared bounded MPSC ring the rotation daemon consumes from. Created
     * once at app_state_init() (capacity 256 — matches Rust's
     * tokio::mpsc::channel at multi_stream.rs:51); freed in web_server_start()
     * after the rotation daemon has joined. NULL on allocation failure;
     * rotation_daemon and the stream handlers both tolerate NULL.
     *
     * Wire-up arrives in stages: stage 1 (current) ships the module + ring;
     * stage 2 (this commit) makes rotation_daemon consume from it; stage 3
     * routes handle_add_stream/handle_list_streams/handle_remove_stream
     * through the manager and flips /api/build/info traffic_entropy:true. */
    multi_stream_manager_t *msm;

    /* Rate limit for /api/auth/unlock (REMEDIATION_PLAN.md §8). Process-
     * lifetime only — restart clears, single-user localhost service so no
     * per-IP table needed. Sliding window of 5 failure timestamps; when all
     * 5 fall within 60 s the lockout below is armed for 30 s (override at
     * startup via env var TC_UNLOCK_LOCKOUT_S, used by the test suite). */
    uint64_t unlock_failures[5];        /* unix-seconds, 0 = empty slot */
    int      unlock_failure_count;      /* slots populated, capped at 5 */
    uint64_t unlock_lockout_until;      /* unix-seconds; 0 = no lockout */
} app_state_t;

/* Initialize app state */
void app_state_init(app_state_t *state);

/* Touch activity timestamp */
void app_state_touch(app_state_t *state);

/* Check if auto-lock has expired. Returns 1 if locked. */
int app_state_check_auto_lock(app_state_t *state);

/* Validate session token from Authorization header. Returns 1 if valid. */
int validate_session(app_state_t *state, const char *auth_header);

/* Start the web server on the given port. Blocks. */
int web_server_start(app_state_t *state, int port);

#endif
