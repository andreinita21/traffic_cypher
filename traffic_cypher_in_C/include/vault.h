#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>
#include <stdint.h>

#define VAULT_MAX_ENTRIES     256
#define VAULT_MAX_TAGS        16
#define VAULT_MAX_HISTORY     10
#define VAULT_LABEL_MAX       256
#define VAULT_PASSWORD_MAX    512
#define VAULT_FIELD_MAX       1024
#define VAULT_ID_LEN          37  /* UUID + null */
#define VAULT_MAX_STREAMS     16

/* --- Data types --- */

typedef struct {
    char     password[VAULT_PASSWORD_MAX];
    uint64_t changed_at;
} password_history_entry_t;

typedef struct {
    char     id[VAULT_ID_LEN];
    char     label[VAULT_LABEL_MAX];
    char     website[VAULT_FIELD_MAX];
    char     username[VAULT_FIELD_MAX];
    char     password[VAULT_PASSWORD_MAX];
    char     totp_secret[VAULT_FIELD_MAX];
    char     notes[VAULT_FIELD_MAX];
    char     tags[VAULT_MAX_TAGS][VAULT_LABEL_MAX];
    int      tag_count;
    password_history_entry_t history[VAULT_MAX_HISTORY];
    int      history_count;
    uint64_t created_at;
    uint64_t updated_at;
} vault_entry_t;

typedef struct {
    vault_entry_t entries[VAULT_MAX_ENTRIES];
    int           entry_count;
} vault_t;

/* --- Stream config --- */

typedef struct {
    char url[VAULT_FIELD_MAX];
    char label[VAULT_LABEL_MAX];
    int  enabled;
} stream_entry_t;

typedef struct {
    uint64_t auto_lock_minutes;
} vault_settings_t;

typedef struct {
    stream_entry_t streams[VAULT_MAX_STREAMS];
    int            stream_count;
    char           default_stream[VAULT_FIELD_MAX];
    vault_settings_t settings;
} stream_config_t;

/* --- Unlocked vault result --- */

typedef struct {
    vault_t  vault;
    uint8_t  dek[32];
    char     entropy_source[16];
} unlocked_vault_t;

/* --- Vault operations --- */

void vault_init(vault_t *v);
void vault_add_or_update(vault_t *v, const vault_entry_t *entry);
const vault_entry_t *vault_get_by_id(const vault_t *v, const char *id);
const vault_entry_t *vault_get_by_label(const vault_t *v, const char *label);
int  vault_delete_by_id(vault_t *v, const char *id);

/* Create a new entry with auto-generated ID and timestamps */
void vault_entry_new(vault_entry_t *entry,
                     const char *label, const char *website,
                     const char *username, const char *password,
                     const char *totp_secret, const char *notes);

/* --- JSON serialization --- */
char *vault_entry_to_json(const vault_entry_t *e);
char *vault_to_json(const vault_t *v);

/* --- Envelope encryption --- */

int  load_vault(const char *master_password, unlocked_vault_t *result);
int  save_vault(const vault_t *vault, const char *master_password,
                const uint8_t dek[32], const char *entropy_source);
int  rotate_dek(const vault_t *vault, const char *master_password,
                const uint8_t new_dek[32], const char *entropy_source);

/* --- DEK generation --- */

void generate_dek_from_traffic(const uint8_t *traffic_entropy, size_t len, uint8_t out[32]);
void generate_dek_from_os(uint8_t out[32]);
void generate_password_vault(size_t length, char *out);

/* --- Stream config --- */

void stream_config_default(stream_config_t *config);
int  load_stream_config(stream_config_t *config);
int  save_stream_config(const stream_config_t *config);

/* --- Helpers --- */

uint64_t unix_now(void);
const char *vault_path(void);
const char *stream_config_path(void);

#endif
