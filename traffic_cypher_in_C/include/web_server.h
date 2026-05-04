#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include "vault.h"

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

    /* Thread safety */
    pthread_mutex_t lock;

    /* Rotation thread control */
    int      rotation_stop;
    pthread_t rotation_thread;

    /* Stream config */
    stream_config_t stream_config;
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
