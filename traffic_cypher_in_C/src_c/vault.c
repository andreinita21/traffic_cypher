#include "vault.h"
#include "hex_utils.h"
#include "str_buf.h"
#include "uuid_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>     /* fsync, unlink */
#include <openssl/opensslv.h>

/* Argon2id support requires OpenSSL 3.2 — EVP_KDF_fetch("ARGON2ID") is
 * not present in 3.0/3.1. macOS Homebrew openssl@3 is well past this
 * threshold; Linux distros that ship 3.0/3.1 need an upgraded openssl-dev
 * package (CI builds 3.3 from source — see .github/workflows/ci.yml).
 * The check sits above the OpenSSL includes that require 3.2 (e.g.
 * <openssl/thread.h>) so the error reaches the user before a header-not-found.
 * A libargon2 fallback is intentionally NOT shipped — that's a separate
 * (deferred) change. */
#if OPENSSL_VERSION_NUMBER < 0x30200000L
#error "Traffic Cypher (C) requires OpenSSL 3.2+ for Argon2id (EVP_KDF). Install/upgrade openssl3."
#endif

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/thread.h>     /* OSSL_set_max_threads (3.2+) */

/* On-disk format constants for vault file v3. The Rust implementation
 * persists exactly the same numbers — KAT in test_fixtures/argon2id_kek_kat.json
 * is the cross-impl contract. */
#define ARGON2ID_M_COST 65536u  /* 64 MiB */
#define ARGON2ID_T_COST 3u
#define ARGON2ID_P_COST 1u

/* We use a minimal JSON approach: manually build/parse JSON strings.
   For a production system, use cJSON. This keeps the build dependency-free. */

uint64_t unix_now(void) {
    return (uint64_t)time(NULL);
}

const char *vault_path(void) {
    static char path[1024];
    const char *custom = getenv("TRAFFIC_CYPHER_VAULT_PATH");
    if (custom) {
        strncpy(path, custom, sizeof(path) - 1);
        return path;
    }
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(path, sizeof(path), "%s/.traffic_cypher_vault.json", home);
    return path;
}

const char *stream_config_path(void) {
    static char path[1024];
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(path, sizeof(path), "%s/.traffic_cypher_streams.json", home);
    return path;
}

/* Atomically write `data` to `final_path` using the tmp+fsync+rename pattern.
 *
 * Writes to a sibling "<final_path>.tmp" first, fflush+fsync so the bytes hit
 * the disk, then rename(2) over the target. rename is atomic on POSIX, so a
 * crash or power loss leaves either the old file intact or the new file fully
 * written — never a half-written target.
 *
 * On any failure the tmp file is unlinked so we don't leave orphans behind.
 * Returns 0 on success, -1 on any failure.
 */
static int atomic_write_file(const char *final_path, const char *data) {
    char tmp_path[1024];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path) >= (int)sizeof(tmp_path)) {
        return -1;
    }

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        return -1;
    }
    if (fputs(data, fp) == EOF) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fclose(fp) != 0) {
        unlink(tmp_path);
        return -1;
    }
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

/* --- Vault operations --- */

void vault_init(vault_t *v) {
    memset(v, 0, sizeof(*v));
}

void vault_entry_new(vault_entry_t *entry,
                     const char *label, const char *website,
                     const char *username, const char *password,
                     const char *totp_secret, const char *notes) {
    memset(entry, 0, sizeof(*entry));
    uuid_v4(entry->id);
    if (label) strncpy(entry->label, label, VAULT_LABEL_MAX - 1);
    if (website) strncpy(entry->website, website, VAULT_FIELD_MAX - 1);
    if (username) strncpy(entry->username, username, VAULT_FIELD_MAX - 1);
    if (password) strncpy(entry->password, password, VAULT_PASSWORD_MAX - 1);
    if (totp_secret) strncpy(entry->totp_secret, totp_secret, VAULT_FIELD_MAX - 1);
    if (notes) strncpy(entry->notes, notes, VAULT_FIELD_MAX - 1);
    entry->created_at = unix_now();
    entry->updated_at = unix_now();
}

void vault_add_or_update(vault_t *v, const vault_entry_t *entry) {
    /* Check if entry with same ID exists */
    for (int i = 0; i < v->entry_count; i++) {
        if (strcmp(v->entries[i].id, entry->id) == 0) {
            /* Update: push old password to history if changed */
            vault_entry_t *existing = &v->entries[i];
            if (strcmp(existing->password, entry->password) != 0) {
                if (existing->history_count < VAULT_MAX_HISTORY) {
                    password_history_entry_t *h = &existing->history[existing->history_count++];
                    strncpy(h->password, existing->password, VAULT_PASSWORD_MAX - 1);
                    h->changed_at = unix_now();
                } else {
                    /* Shift history, drop oldest */
                    memmove(&existing->history[0], &existing->history[1],
                            (VAULT_MAX_HISTORY - 1) * sizeof(password_history_entry_t));
                    password_history_entry_t *h = &existing->history[VAULT_MAX_HISTORY - 1];
                    strncpy(h->password, existing->password, VAULT_PASSWORD_MAX - 1);
                    h->changed_at = unix_now();
                }
            }
            /* Copy new data but preserve history and created_at */
            uint64_t created = existing->created_at;
            int hcount = existing->history_count;
            password_history_entry_t hist[VAULT_MAX_HISTORY];
            memcpy(hist, existing->history, sizeof(hist));
            memcpy(existing, entry, sizeof(vault_entry_t));
            existing->created_at = created;
            existing->history_count = hcount;
            memcpy(existing->history, hist, sizeof(hist));
            existing->updated_at = unix_now();
            return;
        }
    }
    /* New entry */
    if (v->entry_count < VAULT_MAX_ENTRIES) {
        memcpy(&v->entries[v->entry_count], entry, sizeof(vault_entry_t));
        v->entry_count++;
    }
}

const vault_entry_t *vault_get_by_id(const vault_t *v, const char *id) {
    for (int i = 0; i < v->entry_count; i++) {
        if (strcmp(v->entries[i].id, id) == 0) return &v->entries[i];
    }
    return NULL;
}

const vault_entry_t *vault_get_by_label(const vault_t *v, const char *label) {
    for (int i = 0; i < v->entry_count; i++) {
        if (strcmp(v->entries[i].label, label) == 0) return &v->entries[i];
    }
    return NULL;
}

int vault_delete_by_id(vault_t *v, const char *id) {
    for (int i = 0; i < v->entry_count; i++) {
        if (strcmp(v->entries[i].id, id) == 0) {
            memmove(&v->entries[i], &v->entries[i + 1],
                    (v->entry_count - i - 1) * sizeof(vault_entry_t));
            v->entry_count--;
            return 1;
        }
    }
    return 0;
}

/* --- JSON serialization (minimal, hand-written) --- */

/* Append a JSON string literal: opening quote, escaped body, closing quote. */
static void sb_append_jstr(str_buf *sb, const char *raw) {
    sb_append(sb, "\"");
    sb_append_json_escaped(sb, raw ? raw : "");
    sb_append(sb, "\"");
}

/* Append a JSON value for a possibly-empty field: "..." when non-empty, else
 * the bare keyword null. Matches the pre-migration emit semantics where empty
 * website/username/totp_secret/notes serialize as null. */
static void sb_append_jstr_or_null(str_buf *sb, const char *raw) {
    if (raw && raw[0]) {
        sb_append_jstr(sb, raw);
    } else {
        sb_append(sb, "null");
    }
}

/* Append a full vault_entry JSON object to `sb`. Public callers wrap this via
 * vault_entry_to_json (heap string) or use it directly to avoid the N+1 large
 * allocations during list/array serialization. */
static void vault_entry_append_json(const vault_entry_t *e, str_buf *sb) {
    sb_append(sb, "{\"id\":\"");
    sb_append(sb, e->id);
    sb_append(sb, "\",\"label\":");
    sb_append_jstr(sb, e->label);
    sb_append(sb, ",\"website\":");
    sb_append_jstr_or_null(sb, e->website);
    sb_append(sb, ",\"username\":");
    sb_append_jstr_or_null(sb, e->username);
    sb_append(sb, ",\"password\":");
    sb_append_jstr(sb, e->password);
    sb_append(sb, ",\"totp_secret\":");
    sb_append_jstr_or_null(sb, e->totp_secret);
    sb_append(sb, ",\"notes\":");
    sb_append_jstr_or_null(sb, e->notes);

    sb_append(sb, ",\"tags\":[");
    for (int i = 0; i < e->tag_count; i++) {
        if (i > 0) sb_append(sb, ",");
        sb_append_jstr(sb, e->tags[i]);
    }
    sb_append(sb, "],\"password_history\":[");
    for (int i = 0; i < e->history_count; i++) {
        if (i > 0) sb_append(sb, ",");
        sb_append(sb, "{\"password\":");
        sb_append_jstr(sb, e->history[i].password);
        sb_appendf(sb, ",\"changed_at\":%llu}",
                   (unsigned long long)e->history[i].changed_at);
    }
    sb_appendf(sb, "],\"created_at\":%llu,\"updated_at\":%llu}",
               (unsigned long long)e->created_at,
               (unsigned long long)e->updated_at);
}

/* Serialize a vault_entry to JSON. Returns heap-allocated string (or NULL on
 * OOM). Caller free()s. */
char *vault_entry_to_json(const vault_entry_t *e) {
    str_buf sb;
    sb_init(&sb, 1024);
    vault_entry_append_json(e, &sb);
    return sb_release(&sb, NULL);
}

/* Serialize full vault to JSON. Returns heap-allocated string (or NULL on
 * OOM). Caller free()s. */
char *vault_to_json(const vault_t *v) {
    str_buf sb;
    sb_init(&sb, 4096);
    sb_append(&sb, "{\"entries\":[");
    for (int i = 0; i < v->entry_count; i++) {
        if (i > 0) sb_append(&sb, ",");
        vault_entry_append_json(&v->entries[i], &sb);
    }
    sb_append(&sb, "]}");
    return sb_release(&sb, NULL);
}

/* --- Minimal JSON parsing helpers --- */

/* Find a JSON string value by key. Returns heap-allocated string or NULL. */
static char *json_get_string(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *start = strstr(json, search);
    if (!start) {
        /* Try with space after colon */
        snprintf(search, sizeof(search), "\"%s\": \"", key);
        start = strstr(json, search);
        if (!start) return NULL;
    }
    start = strchr(start + strlen(key) + 2, '"');
    if (!start) return NULL;
    start++; /* skip opening quote */

    /* Find end (handling escapes) */
    size_t len = 0;
    const char *p = start;
    while (*p && !(*p == '"' && *(p-1) != '\\')) {
        p++;
        len++;
    }

    char *result = (char *)malloc(len + 1);
    /* Unescape */
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '\\' && i + 1 < len) {
            switch (start[i + 1]) {
                case '"': result[j++] = '"'; i++; break;
                case '\\': result[j++] = '\\'; i++; break;
                case 'n': result[j++] = '\n'; i++; break;
                case 'r': result[j++] = '\r'; i++; break;
                case 't': result[j++] = '\t'; i++; break;
                default: result[j++] = start[i]; break;
            }
        } else {
            result[j++] = start[i];
        }
    }
    result[j] = '\0';
    return result;
}

/* Find a JSON integer value by key */
static uint64_t json_get_uint64(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *start = strstr(json, search);
    if (!start) return 0;
    start += strlen(search);
    while (*start == ' ') start++;
    return strtoull(start, NULL, 10);
}

static int json_get_int(const char *json, const char *key) {
    return (int)json_get_uint64(json, key);
}

/* Parse vault entries from JSON. Very simplified parser. */
static int parse_vault_entries(const char *json, vault_t *v) {
    const char *entries_start = strstr(json, "\"entries\":[");
    if (!entries_start) return -1;
    entries_start = strchr(entries_start, '[');
    if (!entries_start) return -1;
    entries_start++;

    v->entry_count = 0;

    /* Find each entry object */
    const char *p = entries_start;
    while (*p && v->entry_count < VAULT_MAX_ENTRIES) {
        /* Find next '{' */
        while (*p && *p != '{' && *p != ']') p++;
        if (*p == ']' || !*p) break;

        /* Find matching '}' accounting for nesting */
        const char *obj_start = p;
        int depth = 0;
        int in_string = 0;
        do {
            if (!in_string) {
                if (*p == '{') depth++;
                else if (*p == '}') depth--;
                else if (*p == '"') in_string = 1;
            } else {
                if (*p == '"' && *(p-1) != '\\') in_string = 0;
            }
            p++;
        } while (depth > 0 && *p);

        /* Extract object substring */
        size_t obj_len = (size_t)(p - obj_start);
        char *obj = (char *)malloc(obj_len + 1);
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        vault_entry_t *e = &v->entries[v->entry_count];
        memset(e, 0, sizeof(*e));

        char *val;
        if ((val = json_get_string(obj, "id"))) { strncpy(e->id, val, VAULT_ID_LEN - 1); free(val); }
        if ((val = json_get_string(obj, "label"))) { strncpy(e->label, val, VAULT_LABEL_MAX - 1); free(val); }
        if ((val = json_get_string(obj, "website"))) { strncpy(e->website, val, VAULT_FIELD_MAX - 1); free(val); }
        if ((val = json_get_string(obj, "username"))) { strncpy(e->username, val, VAULT_FIELD_MAX - 1); free(val); }
        if ((val = json_get_string(obj, "password"))) { strncpy(e->password, val, VAULT_PASSWORD_MAX - 1); free(val); }
        if ((val = json_get_string(obj, "totp_secret"))) { strncpy(e->totp_secret, val, VAULT_FIELD_MAX - 1); free(val); }
        if ((val = json_get_string(obj, "notes"))) { strncpy(e->notes, val, VAULT_FIELD_MAX - 1); free(val); }
        e->created_at = json_get_uint64(obj, "created_at");
        e->updated_at = json_get_uint64(obj, "updated_at");

        /* Parse tags array (simplified) */
        const char *tags_start = strstr(obj, "\"tags\":[");
        if (tags_start) {
            tags_start = strchr(tags_start, '[') + 1;
            while (*tags_start && *tags_start != ']' && e->tag_count < VAULT_MAX_TAGS) {
                if (*tags_start == '"') {
                    tags_start++;
                    const char *tag_end = tags_start;
                    while (*tag_end && *tag_end != '"') tag_end++;
                    size_t tag_len = (size_t)(tag_end - tags_start);
                    if (tag_len < VAULT_LABEL_MAX) {
                        memcpy(e->tags[e->tag_count], tags_start, tag_len);
                        e->tags[e->tag_count][tag_len] = '\0';
                        e->tag_count++;
                    }
                    tags_start = tag_end + 1;
                } else {
                    tags_start++;
                }
            }
        }

        /* Parse password_history (simplified) */
        const char *hist_start = strstr(obj, "\"password_history\":[");
        if (hist_start) {
            hist_start = strchr(hist_start, '[') + 1;
            while (*hist_start && *hist_start != ']' && e->history_count < VAULT_MAX_HISTORY) {
                if (*hist_start == '{') {
                    const char *hobj = hist_start;
                    int hd = 1;
                    hist_start++;
                    while (*hist_start && hd > 0) {
                        if (*hist_start == '{') hd++;
                        if (*hist_start == '}') hd--;
                        hist_start++;
                    }
                    size_t hlen = (size_t)(hist_start - hobj);
                    char *hstr = (char *)malloc(hlen + 1);
                    memcpy(hstr, hobj, hlen);
                    hstr[hlen] = '\0';

                    char *hpw = json_get_string(hstr, "password");
                    if (hpw) {
                        strncpy(e->history[e->history_count].password, hpw, VAULT_PASSWORD_MAX - 1);
                        free(hpw);
                    }
                    e->history[e->history_count].changed_at = json_get_uint64(hstr, "changed_at");
                    e->history_count++;
                    free(hstr);
                } else {
                    hist_start++;
                }
            }
        }

        free(obj);
        v->entry_count++;
    }
    return 0;
}

/* --- HKDF helper using OpenSSL EVP --- */

static int hkdf_derive(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

/* --- Envelope encryption --- */

/* Legacy v2 KDF: HKDF-SHA256. No work factor; readable only because we still
 * need to open existing v2 vaults so they can be auto-upgraded to v3. */
static void derive_kek_hkdf(const char *master_password,
                            const uint8_t *salt, size_t salt_len,
                            uint8_t kek[32]) {
    hkdf_derive((const uint8_t *)master_password, strlen(master_password),
                salt, salt_len,
                (const uint8_t *)"traffic-cypher-kek-v2", 21,
                kek, 32);
}

/* Current v3 KDF: Argon2id via OpenSSL 3.2+ EVP_KDF. Parameters are
 * persisted in the vault file (kdf_m_cost / kdf_t_cost / kdf_p_cost) so a
 * future parameter bump never bricks an existing file.
 *
 * Returns 0 on success, -1 on failure. On failure `kek` is left zeroed. */
static int derive_kek_argon2id(const char *master_password,
                               const uint8_t *salt, size_t salt_len,
                               uint32_t m_cost, uint32_t t_cost, uint32_t p_cost,
                               uint8_t kek[32]) {
    memset(kek, 0, 32);

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return -1;

    /* OpenSSL's Argon2 EVP_KDF expects:
     *   - OSSL_KDF_PARAM_PASSWORD       : the password bytes
     *   - OSSL_KDF_PARAM_SALT           : the salt bytes
     *   - OSSL_KDF_PARAM_ITER           : t_cost (passes)
     *   - OSSL_KDF_PARAM_THREADS        : p_cost (parallelism lanes)
     *   - OSSL_KDF_PARAM_ARGON2_MEMCOST : m_cost in KiB
     *
     * KAT (`test_fixtures/argon2id_kek_kat.json`) was generated against the
     * RustCrypto `argon2` crate v0.5 with Algorithm::Argon2id /
     * Version::V0x13. OpenSSL defaults to v1.3 / argon2id, matching the
     * Rust side byte-for-byte. */
    OSSL_PARAM params[6];
    size_t pwd_len = strlen(master_password);
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, (void *)master_password, pwd_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[idx++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ITER, &t_cost);
    params[idx++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_THREADS, &p_cost);
    params[idx++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ARGON2_MEMCOST, &m_cost);
    params[idx++] = OSSL_PARAM_construct_end();

    /* OpenSSL refuses THREADS > the global max-threads cap. Raise it
     * defensively — we only ever ask for 1 lane today, but the cap can be
     * surprisingly low on minimal builds. Best-effort; failure is fine for
     * p_cost == 1. */
    (void)OSSL_set_max_threads(NULL, p_cost);

    if (EVP_KDF_derive(ctx, kek, 32, params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        return -1;
    }
    EVP_KDF_CTX_free(ctx);
    return 0;
}

void generate_dek_from_traffic(const uint8_t *traffic_entropy, size_t len, uint8_t out[32]) {
    uint8_t os_salt[32];
    RAND_bytes(os_salt, 32);
    hkdf_derive(traffic_entropy, len, os_salt, 32,
                (const uint8_t *)"traffic-cypher-dek-v2", 21, out, 32);
}

void generate_dek_from_os(uint8_t out[32]) {
    uint8_t ikm[64], salt[32];
    RAND_bytes(ikm, 64);
    RAND_bytes(salt, 32);
    hkdf_derive(ikm, 64, salt, 32,
                (const uint8_t *)"traffic-cypher-dek-os-v2", 24, out, 32);
}

/* AES-256-GCM encrypt */
static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *plaintext, size_t pt_len,
                            uint8_t *nonce_out, uint8_t **ciphertext_out, size_t *ct_len_out) {
    RAND_bytes(nonce_out, 12);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    /* Allocate output: plaintext + 16 bytes for GCM tag */
    *ciphertext_out = (uint8_t *)malloc(pt_len + 16);
    int out_len = 0, final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_out) != 1 ||
        EVP_EncryptUpdate(ctx, *ciphertext_out, &out_len, plaintext, (int)pt_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, *ciphertext_out + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        return -1;
    }

    *ct_len_out = (size_t)(out_len + final_len);

    /* Append GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, *ciphertext_out + *ct_len_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        return -1;
    }
    *ct_len_out += 16;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* AES-256-GCM decrypt */
static int aes_gcm_decrypt(const uint8_t *key, const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *nonce, uint8_t **plaintext_out, size_t *pt_len_out) {
    if (ct_len < 16) return -1;

    size_t data_len = ct_len - 16;
    const uint8_t *tag = ciphertext + data_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    *plaintext_out = (uint8_t *)malloc(data_len + 1);
    int out_len = 0, final_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, *plaintext_out, &out_len, ciphertext, (int)data_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, *plaintext_out + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        return -1;
    }

    *pt_len_out = (size_t)(out_len + final_len);
    (*plaintext_out)[*pt_len_out] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* --- Load / Save vault --- */

int load_vault(const char *master_password, unlocked_vault_t *result) {
    memset(result, 0, sizeof(*result));
    vault_init(&result->vault);

    const char *path = vault_path();
    FILE *fp = fopen(path, "r");
    if (!fp) {
        /* First time: generate DEK from OS entropy */
        generate_dek_from_os(result->dek);
        strcpy(result->entropy_source, "os");
        return 0;
    }

    /* Read entire file */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *contents = (char *)malloc(file_size + 1);
    fread(contents, 1, file_size, fp);
    contents[file_size] = '\0';
    fclose(fp);

    /* Determine version. Anything that isn't 2 or 3 is a hard error —
     * silently coercing future formats would corrupt vaults written by
     * newer builds. */
    int version = json_get_int(contents, "version");
    if (version != 2 && version != 3) {
        fprintf(stderr,
                "load_vault: unsupported vault version %d (this build "
                "understands v2 and v3)\n", version);
        free(contents);
        return -1;
    }

    /* Parse JSON fields shared between v2 and v3. */
    char *kek_salt_hex = json_get_string(contents, "kek_salt");
    char *wdn_hex = json_get_string(contents, "wrapped_dek_nonce");
    char *wd_hex = json_get_string(contents, "wrapped_dek");
    char *vn_hex = json_get_string(contents, "vault_nonce");
    char *vc_hex = json_get_string(contents, "vault_ciphertext");
    char *esrc = json_get_string(contents, "entropy_source");

    /* v3-only fields. For v2 these are unused and remain at defaults. */
    char *kdf_name = NULL;
    uint32_t m_cost = ARGON2ID_M_COST, t_cost = ARGON2ID_T_COST, p_cost = ARGON2ID_P_COST;
    if (version == 3) {
        kdf_name = json_get_string(contents, "kdf");
        m_cost = (uint32_t)json_get_uint64(contents, "kdf_m_cost");
        t_cost = (uint32_t)json_get_uint64(contents, "kdf_t_cost");
        p_cost = (uint32_t)json_get_uint64(contents, "kdf_p_cost");
        if (!kdf_name || strcmp(kdf_name, "argon2id") != 0) {
            fprintf(stderr,
                    "load_vault: vault v3 declares unsupported KDF '%s' "
                    "(expected 'argon2id')\n", kdf_name ? kdf_name : "(null)");
            free(kek_salt_hex); free(wdn_hex); free(wd_hex);
            free(vn_hex); free(vc_hex); free(esrc); free(kdf_name);
            free(contents);
            return -1;
        }
        if (m_cost == 0 || t_cost == 0 || p_cost == 0) {
            fprintf(stderr,
                    "load_vault: v3 file has zero/missing Argon2id params "
                    "(m=%u t=%u p=%u)\n", m_cost, t_cost, p_cost);
            free(kek_salt_hex); free(wdn_hex); free(wd_hex);
            free(vn_hex); free(vc_hex); free(esrc); free(kdf_name);
            free(contents);
            return -1;
        }
    }
    free(contents);

    if (!kek_salt_hex || !wdn_hex || !wd_hex || !vn_hex || !vc_hex) {
        free(kek_salt_hex); free(wdn_hex); free(wd_hex);
        free(vn_hex); free(vc_hex); free(esrc); free(kdf_name);
        return -1;
    }

    /* Decode hex */
    uint8_t kek_salt[32];
    int ks_len = hex_decode(kek_salt_hex, kek_salt, 32);
    free(kek_salt_hex);

    uint8_t wdn[12];
    int wdn_len = hex_decode(wdn_hex, wdn, 12);
    free(wdn_hex);

    size_t wd_max = strlen(wd_hex) / 2;
    uint8_t *wrapped_dek = (uint8_t *)malloc(wd_max);
    int wd_len = hex_decode(wd_hex, wrapped_dek, wd_max);
    free(wd_hex);

    uint8_t vault_nonce[12];
    int vn_len = hex_decode(vn_hex, vault_nonce, 12);
    free(vn_hex);

    size_t vc_max = strlen(vc_hex) / 2;
    uint8_t *vault_ct = (uint8_t *)malloc(vc_max);
    int vc_len = hex_decode(vc_hex, vault_ct, vc_max);
    free(vc_hex);

    if (ks_len < 0 || wdn_len != 12 || wd_len < 0 || vn_len != 12 || vc_len < 0) {
        free(wrapped_dek); free(vault_ct); free(esrc); free(kdf_name);
        return -1;
    }

    /* Step 1: Derive KEK. Version 2 → HKDF (microseconds); version 3 →
     * Argon2id with the params we just parsed. */
    uint8_t kek[32];
    if (version == 2) {
        derive_kek_hkdf(master_password, kek_salt, (size_t)ks_len, kek);
        fprintf(stderr,
                "load_vault: loaded v2 vault — will auto-upgrade to v3 "
                "(Argon2id) on next save\n");
    } else {
        if (derive_kek_argon2id(master_password, kek_salt, (size_t)ks_len,
                                m_cost, t_cost, p_cost, kek) != 0) {
            fprintf(stderr, "load_vault: Argon2id derivation failed\n");
            free(wrapped_dek); free(vault_ct); free(esrc); free(kdf_name);
            return -1;
        }
    }
    free(kdf_name);

    /* Step 2: Unwrap DEK */
    uint8_t *dek_plain = NULL;
    size_t dek_plain_len = 0;
    if (aes_gcm_decrypt(kek, wrapped_dek, (size_t)wd_len, wdn, &dek_plain, &dek_plain_len) != 0 ||
        dek_plain_len != 32) {
        free(wrapped_dek); free(vault_ct); free(esrc); free(dek_plain);
        return -1;
    }
    memcpy(result->dek, dek_plain, 32);
    free(dek_plain);
    free(wrapped_dek);

    /* Step 3: Decrypt vault data */
    uint8_t *vault_plain = NULL;
    size_t vault_plain_len = 0;
    if (aes_gcm_decrypt(result->dek, vault_ct, (size_t)vc_len, vault_nonce,
                         &vault_plain, &vault_plain_len) != 0) {
        free(vault_ct); free(esrc);
        return -1;
    }
    free(vault_ct);

    /* Parse vault JSON */
    parse_vault_entries((const char *)vault_plain, &result->vault);
    free(vault_plain);

    if (esrc) {
        strncpy(result->entropy_source, esrc, sizeof(result->entropy_source) - 1);
        free(esrc);
    } else {
        strcpy(result->entropy_source, "os");
    }

    return 0;
}

int save_vault(const vault_t *vault, const char *master_password,
               const uint8_t dek[32], const char *entropy_source) {
    /* Generate fresh KEK salt — random per save so a future password change
     * can't accidentally produce a deterministic re-derivation collision. */
    uint8_t kek_salt[32];
    RAND_bytes(kek_salt, 32);

    /* Derive KEK with Argon2id at the current parameters. Slow (~300 ms);
     * the cost is what makes a stolen vault hard to brute-force offline. */
    uint8_t kek[32];
    if (derive_kek_argon2id(master_password, kek_salt, 32,
                            ARGON2ID_M_COST, ARGON2ID_T_COST, ARGON2ID_P_COST,
                            kek) != 0) {
        fprintf(stderr, "save_vault: Argon2id derivation failed\n");
        return -1;
    }

    /* Wrap the DEK */
    uint8_t wrap_nonce[12];
    uint8_t *wrapped_dek = NULL;
    size_t wrapped_dek_len = 0;
    if (aes_gcm_encrypt(kek, dek, 32, wrap_nonce, &wrapped_dek, &wrapped_dek_len) != 0)
        return -1;

    /* Serialize vault to JSON */
    char *vault_json = vault_to_json(vault);
    if (!vault_json) {
        free(wrapped_dek);
        return -1;
    }
    size_t vj_len = strlen(vault_json);

    /* Encrypt vault data */
    uint8_t vault_nonce[12];
    uint8_t *vault_ct = NULL;
    size_t vault_ct_len = 0;
    if (aes_gcm_encrypt(dek, (const uint8_t *)vault_json, vj_len,
                         vault_nonce, &vault_ct, &vault_ct_len) != 0) {
        free(vault_json); free(wrapped_dek);
        return -1;
    }
    free(vault_json);

    /* Hex encode all fields */
    char *kek_salt_hex = (char *)malloc(65);
    hex_encode(kek_salt, 32, kek_salt_hex);

    char *wrap_nonce_hex = (char *)malloc(25);
    hex_encode(wrap_nonce, 12, wrap_nonce_hex);

    char *wrapped_dek_hex = (char *)malloc(wrapped_dek_len * 2 + 1);
    hex_encode(wrapped_dek, wrapped_dek_len, wrapped_dek_hex);

    char *vault_nonce_hex = (char *)malloc(25);
    hex_encode(vault_nonce, 12, vault_nonce_hex);

    char *vault_ct_hex = (char *)malloc(vault_ct_len * 2 + 1);
    hex_encode(vault_ct, vault_ct_len, vault_ct_hex);

    /* Build output JSON. Always v3 — see REMEDIATION_PLAN.md #4. */
    size_t out_size = 768 + strlen(kek_salt_hex) + strlen(wrap_nonce_hex) +
                      strlen(wrapped_dek_hex) + strlen(vault_nonce_hex) + strlen(vault_ct_hex);
    char *out_json = (char *)malloc(out_size);
    snprintf(out_json, out_size,
        "{\n"
        "  \"version\": 3,\n"
        "  \"kdf\": \"argon2id\",\n"
        "  \"kdf_m_cost\": %u,\n"
        "  \"kdf_t_cost\": %u,\n"
        "  \"kdf_p_cost\": %u,\n"
        "  \"kek_salt\": \"%s\",\n"
        "  \"wrapped_dek_nonce\": \"%s\",\n"
        "  \"wrapped_dek\": \"%s\",\n"
        "  \"vault_nonce\": \"%s\",\n"
        "  \"vault_ciphertext\": \"%s\",\n"
        "  \"entropy_source\": \"%s\",\n"
        "  \"updated_at\": %llu\n"
        "}",
        ARGON2ID_M_COST, ARGON2ID_T_COST, ARGON2ID_P_COST,
        kek_salt_hex, wrap_nonce_hex, wrapped_dek_hex,
        vault_nonce_hex, vault_ct_hex, entropy_source,
        (unsigned long long)unix_now());

    /* Write to file atomically: tmp + fsync + rename. */
    int write_rc = atomic_write_file(vault_path(), out_json);

    free(out_json); free(kek_salt_hex); free(wrap_nonce_hex);
    free(wrapped_dek_hex); free(vault_nonce_hex); free(vault_ct_hex);
    free(wrapped_dek); free(vault_ct);

    return write_rc;
}

int rotate_dek(const vault_t *vault, const char *master_password,
               const uint8_t new_dek[32], const char *entropy_source) {
    return save_vault(vault, master_password, new_dek, entropy_source);
}

void generate_password_vault(size_t length, char *out) {
    static const char charset[] =
        "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";
    int charset_len = (int)(sizeof(charset) - 1);

    uint8_t *rand_bytes = (uint8_t *)malloc(length);
    RAND_bytes(rand_bytes, (int)length);

    for (size_t i = 0; i < length; i++) {
        out[i] = charset[rand_bytes[i] % charset_len];
    }
    out[length] = '\0';
    free(rand_bytes);
}

/* --- Stream config --- */

void stream_config_default(stream_config_t *config) {
    memset(config, 0, sizeof(*config));
    strncpy(config->default_stream,
            "https://www.youtube.com/watch?v=rs2be3mqryo",
            VAULT_FIELD_MAX - 1);
    config->settings.auto_lock_minutes = 5;
}

int load_stream_config(stream_config_t *config) {
    stream_config_default(config);

    const char *path = stream_config_path();
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *contents = (char *)malloc(file_size + 1);
    fread(contents, 1, file_size, fp);
    contents[file_size] = '\0';
    fclose(fp);

    config->settings.auto_lock_minutes = json_get_uint64(contents, "auto_lock_minutes");
    if (config->settings.auto_lock_minutes == 0) config->settings.auto_lock_minutes = 5;

    char *ds = json_get_string(contents, "default_stream");
    if (ds) {
        strncpy(config->default_stream, ds, VAULT_FIELD_MAX - 1);
        free(ds);
    }

    /* Parse streams array (simplified) */
    const char *streams_start = strstr(contents, "\"streams\":[");
    if (streams_start) {
        streams_start = strchr(streams_start, '[') + 1;
        while (*streams_start && *streams_start != ']' && config->stream_count < VAULT_MAX_STREAMS) {
            if (*streams_start == '{') {
                const char *obj_start = streams_start;
                int depth = 1;
                streams_start++;
                while (*streams_start && depth > 0) {
                    if (*streams_start == '{') depth++;
                    if (*streams_start == '}') depth--;
                    streams_start++;
                }
                size_t obj_len = (size_t)(streams_start - obj_start);
                char *obj = (char *)malloc(obj_len + 1);
                memcpy(obj, obj_start, obj_len);
                obj[obj_len] = '\0';

                char *url = json_get_string(obj, "url");
                char *label = json_get_string(obj, "label");
                stream_entry_t *se = &config->streams[config->stream_count];
                memset(se, 0, sizeof(*se));
                if (url) { strncpy(se->url, url, VAULT_FIELD_MAX - 1); free(url); }
                if (label) { strncpy(se->label, label, VAULT_LABEL_MAX - 1); free(label); }

                /* Check enabled field */
                const char *en = strstr(obj, "\"enabled\":");
                if (en) {
                    en += 10;
                    while (*en == ' ') en++;
                    se->enabled = (*en == 't') ? 1 : 0;
                } else {
                    se->enabled = 1;
                }
                free(obj);
                config->stream_count++;
            } else {
                streams_start++;
            }
        }
    }

    free(contents);
    return 0;
}

int save_stream_config(const stream_config_t *config) {
    str_buf sb;
    sb_init(&sb, 1024);

    sb_append(&sb, "{\n  \"streams\": [\n");
    for (int i = 0; i < config->stream_count; i++) {
        sb_append(&sb, "    {\"url\": \"");
        sb_append_json_escaped(&sb, config->streams[i].url);
        sb_append(&sb, "\", \"label\": \"");
        sb_append_json_escaped(&sb, config->streams[i].label);
        sb_append(&sb, "\", \"enabled\": ");
        sb_append(&sb, config->streams[i].enabled ? "true" : "false");
        sb_append(&sb, "}");
        if (i < config->stream_count - 1) sb_append(&sb, ",");
        sb_append(&sb, "\n");
    }
    sb_append(&sb, "  ],\n  \"default_stream\": \"");
    sb_append_json_escaped(&sb, config->default_stream);
    sb_appendf(&sb, "\",\n  \"settings\": {\"auto_lock_minutes\": %llu}\n}",
               (unsigned long long)config->settings.auto_lock_minutes);

    char *buf = sb_release(&sb, NULL);
    if (!buf) return -1;
    int write_rc = atomic_write_file(stream_config_path(), buf);
    free(buf);
    return write_rc;
}
