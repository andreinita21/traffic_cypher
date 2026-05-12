#include "web_server.h"
#include "vault.h"
#include "hex_utils.h"
#include "uuid_gen.h"
#include "password_gen.h"
#include "totp.h"
#include "key_rotation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Embedded frontend files */
extern const char _binary_frontend_index_html_start[];
extern const char _binary_frontend_index_html_end[];
extern const char _binary_frontend_app_js_start[];
extern const char _binary_frontend_app_js_end[];
extern const char _binary_frontend_style_css_start[];
extern const char _binary_frontend_style_css_end[];

/* We'll load these at runtime instead of embedding */
static char *frontend_index = NULL;
static size_t frontend_index_len = 0;
static char *frontend_js = NULL;
static size_t frontend_js_len = 0;
static char *frontend_css = NULL;
static size_t frontend_css_len = 0;

static void load_frontend_file(const char *path, char **out, size_t *out_len) {
    FILE *fp = fopen(path, "r");
    if (!fp) { *out = NULL; *out_len = 0; return; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    *out = (char *)malloc((size_t)sz + 1);
    *out_len = fread(*out, 1, (size_t)sz, fp);
    (*out)[*out_len] = '\0';
    fclose(fp);
}

void app_state_init(app_state_t *state) {
    memset(state, 0, sizeof(*state));
    pthread_mutex_init(&state->lock, NULL);
    state->auto_lock_minutes = 5;
    state->last_activity = (uint64_t)time(NULL);
    strcpy(state->entropy_source, "os");
}

void app_state_touch(app_state_t *state) {
    state->last_activity = (uint64_t)time(NULL);
}

int app_state_check_auto_lock(app_state_t *state) {
    uint64_t now = (uint64_t)time(NULL);
    uint64_t elapsed = now - state->last_activity;
    return elapsed > state->auto_lock_minutes * 60;
}

int validate_session(app_state_t *state, const char *auth_header) {
    if (!auth_header || !state->has_session) return 0;

    /* Expect "Bearer <token>" */
    if (strncmp(auth_header, "Bearer ", 7) != 0) return 0;
    const char *token = auth_header + 7;

    if (strcmp(token, state->session_token) != 0) return 0;

    /* Check auto-lock */
    if (app_state_check_auto_lock(state)) {
        state->has_session = 0;
        state->is_unlocked = 0;
        state->has_dek = 0;
        return 0;
    }

    app_state_touch(state);
    return 1;
}

/* --- Minimal HTTP request parsing --- */

typedef struct {
    char method[16];
    char path[2048];
    char auth_header[256];
    char content_type[128];
    char *body;
    size_t body_len;
    int content_length;
} http_request_t;

typedef struct {
    int status;
    const char *status_text;
    char content_type[128];
    char *body;
    size_t body_len;
} http_response_t;

static int parse_request(int fd, http_request_t *req) {
    memset(req, 0, sizeof(*req));

    /* Read the full request (headers + body) */
    char buf[65536];
    size_t total_read = 0;
    size_t header_end = 0;
    int found_header_end = 0;

    while (total_read < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total_read, sizeof(buf) - 1 - total_read);
        if (n <= 0) break;
        total_read += (size_t)n;
        buf[total_read] = '\0';

        /* Check for end of headers */
        if (!found_header_end) {
            char *hend = strstr(buf, "\r\n\r\n");
            if (hend) {
                header_end = (size_t)(hend - buf) + 4;
                found_header_end = 1;

                /* Check Content-Length */
                char *cl = strcasestr(buf, "Content-Length:");
                if (cl) {
                    req->content_length = atoi(cl + 15);
                    /* Check if we have the full body */
                    size_t body_read = total_read - header_end;
                    if ((int)body_read >= req->content_length) break;
                } else {
                    break; /* No body expected */
                }
            }
        } else {
            size_t body_read = total_read - header_end;
            if ((int)body_read >= req->content_length) break;
        }
    }

    if (total_read == 0) return -1;

    /* Parse request line */
    sscanf(buf, "%15s %2047s", req->method, req->path);

    /* Extract headers */
    char *auth = strcasestr(buf, "Authorization:");
    if (auth) {
        auth += 14;
        while (*auth == ' ') auth++;
        char *eol = strstr(auth, "\r\n");
        if (eol) {
            size_t len = (size_t)(eol - auth);
            if (len >= sizeof(req->auth_header)) len = sizeof(req->auth_header) - 1;
            memcpy(req->auth_header, auth, len);
            req->auth_header[len] = '\0';
        }
    }

    /* Extract body */
    if (found_header_end && req->content_length > 0) {
        size_t body_available = total_read - header_end;
        size_t body_len = (body_available < (size_t)req->content_length)
                          ? body_available : (size_t)req->content_length;
        req->body = (char *)malloc(body_len + 1);
        memcpy(req->body, buf + header_end, body_len);
        req->body[body_len] = '\0';
        req->body_len = body_len;
    }

    return 0;
}

static void send_response(int fd, http_response_t *resp) {
    char header[4096];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n",
        resp->status, resp->status_text, resp->content_type, resp->body_len);

    write(fd, header, (size_t)header_len);
    if (resp->body && resp->body_len > 0) {
        write(fd, resp->body, resp->body_len);
    }
}

static void send_json(int fd, int status, const char *status_text, const char *json) {
    http_response_t resp;
    resp.status = status;
    resp.status_text = status_text;
    strcpy(resp.content_type, "application/json");
    resp.body = (char *)json;
    resp.body_len = strlen(json);
    send_response(fd, &resp);
}

static void send_error(int fd, int status, const char *status_text, const char *msg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    send_json(fd, status, status_text, buf);
}

static void send_unauthorized(int fd) {
    send_error(fd, 401, "Unauthorized", "Not authenticated");
}

/* --- Minimal JSON field extraction from request body --- */

static char *json_body_get_string(const char *body, const char *key) {
    if (!body) return NULL;
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *pos = strstr(body, search);
    if (!pos) return NULL;
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos == 'n' && strncmp(pos, "null", 4) == 0) return NULL;
    if (*pos != '"') return NULL;
    pos++;
    const char *end = pos;
    while (*end && !(*end == '"' && *(end-1) != '\\')) end++;
    size_t len = (size_t)(end - pos);
    char *result = (char *)malloc(len + 1);
    memcpy(result, pos, len);
    result[len] = '\0';
    return result;
}

/*
 * Parse a JSON string array under `key` into `out`, returning the count parsed.
 *
 *   missing key      → 0
 *   null             → 0
 *   too many tags    → -1 (caller should respond 400)
 *   malformed        → stop at the malformed element, return what was parsed
 *
 * Tag values are truncated at VAULT_LABEL_MAX - 1 chars (consistent with the
 * strncpy idiom used for every other field). Handles backslash-escape
 * continuation (\\") inside string values the same way json_body_get_string
 * does — a quote preceded by an unescaped backslash does not terminate.
 */
static int json_body_get_string_array(const char *body, const char *key,
                                      char out[][VAULT_LABEL_MAX],
                                      int max_entries) {
    if (!body) return 0;
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *pos = strstr(body, search);
    if (!pos) return 0;
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos == 'n' && strncmp(pos, "null", 4) == 0) return 0;
    if (*pos != '[') return 0;
    pos++;

    int count = 0;
    while (*pos) {
        while (*pos == ' ' || *pos == '\t' || *pos == ',' || *pos == '\n' || *pos == '\r') pos++;
        if (*pos == ']') return count;
        if (*pos != '"') {
            /* Malformed element — stop parsing here. */
            return count;
        }
        pos++;
        const char *end = pos;
        while (*end && !(*end == '"' && *(end - 1) != '\\')) end++;
        if (!*end) return count;

        if (count >= max_entries) return -1;

        size_t len = (size_t)(end - pos);
        if (len > VAULT_LABEL_MAX - 1) len = VAULT_LABEL_MAX - 1;
        memcpy(out[count], pos, len);
        out[count][len] = '\0';
        count++;
        pos = end + 1;
    }
    return count;
}

static int json_body_get_int(const char *body, const char *key, int default_val) {
    if (!body) return default_val;
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *pos = strstr(body, search);
    if (!pos) return default_val;
    pos += strlen(search);
    while (*pos == ' ') pos++;
    return atoi(pos);
}

static int json_body_get_bool(const char *body, const char *key, int default_val) {
    if (!body) return default_val;
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *pos = strstr(body, search);
    if (!pos) return default_val;
    pos += strlen(search);
    while (*pos == ' ') pos++;
    if (*pos == 't') return 1;
    if (*pos == 'f') return 0;
    return default_val;
}

/* --- Save vault helper --- */

static int save_vault_with_state(app_state_t *state) {
    if (!state->has_dek) return -1;
    return save_vault(&state->vault, state->master_password,
                      state->current_dek, state->entropy_source);
}

/* --- Route handlers --- */

static void handle_unlock(int fd, app_state_t *state, http_request_t *req) {
    char *master_pw = json_body_get_string(req->body, "master_password");
    if (!master_pw) {
        send_error(fd, 400, "Bad Request", "Missing master_password");
        return;
    }

    unlocked_vault_t unlocked;
    if (load_vault(master_pw, &unlocked) != 0) {
        send_error(fd, 401, "Unauthorized", "Failed to unlock vault — wrong master password?");
        free(master_pw);
        return;
    }

    pthread_mutex_lock(&state->lock);

    /* Store session */
    uuid_v4(state->session_token);
    state->has_session = 1;
    strncpy(state->master_password, master_pw, VAULT_PASSWORD_MAX - 1);
    memcpy(&state->vault, &unlocked.vault, sizeof(vault_t));
    state->is_unlocked = 1;
    memcpy(state->current_dek, unlocked.dek, 32);
    state->has_dek = 1;
    strncpy(state->entropy_source, unlocked.entropy_source, sizeof(state->entropy_source) - 1);
    app_state_touch(state);

    /* Load stream config */
    load_stream_config(&state->stream_config);
    state->auto_lock_minutes = state->stream_config.settings.auto_lock_minutes;

    /* Start rotation daemon */
    state->rotation_stop = 0;
    pthread_create(&state->rotation_thread, NULL, rotation_daemon, state);

    char resp_buf[512];
    snprintf(resp_buf, sizeof(resp_buf),
             "{\"token\":\"%s\",\"entry_count\":%d,\"entropy_source\":\"%s\"}",
             state->session_token, state->vault.entry_count, state->entropy_source);

    pthread_mutex_unlock(&state->lock);
    free(master_pw);

    send_json(fd, 200, "OK", resp_buf);
}

static void handle_lock(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    /* Stop rotation daemon */
    state->rotation_stop = 1;
    pthread_mutex_unlock(&state->lock);

    if (state->rotation_running) {
        pthread_join(state->rotation_thread, NULL);
    }

    pthread_mutex_lock(&state->lock);
    state->has_session = 0;
    memset(state->master_password, 0, sizeof(state->master_password));
    vault_init(&state->vault);
    state->is_unlocked = 0;
    state->has_dek = 0;
    memset(state->current_dek, 0, 32);
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 200, "OK", "{\"status\":\"locked\"}");
}

static void handle_auth_status(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);
    int unlocked = state->is_unlocked;
    if (unlocked && app_state_check_auto_lock(state)) {
        state->has_session = 0;
        state->is_unlocked = 0;
        state->has_dek = 0;
        unlocked = 0;
    }
    pthread_mutex_unlock(&state->lock);

    char buf[64];
    snprintf(buf, sizeof(buf), "{\"unlocked\":%s}", unlocked ? "true" : "false");
    send_json(fd, 200, "OK", buf);
}

static void handle_verify_password(int fd, app_state_t *state, http_request_t *req) {
    char *pw = json_body_get_string(req->body, "master_password");
    if (!pw) {
        send_error(fd, 400, "Bad Request", "Missing master_password");
        return;
    }

    pthread_mutex_lock(&state->lock);
    int valid = (strcmp(state->master_password, pw) == 0);
    pthread_mutex_unlock(&state->lock);
    free(pw);

    char buf[32];
    snprintf(buf, sizeof(buf), "{\"valid\":%s}", valid ? "true" : "false");
    send_json(fd, 200, "OK", buf);
}

static void handle_list_credentials(int fd, app_state_t *state, http_request_t *req) {
    pthread_mutex_lock(&state->lock);

    /* Check for query parameter ?q= */
    char *q_param = NULL;
    char *qmark = strchr(req->path, '?');
    if (qmark) {
        char *q_start = strstr(qmark, "q=");
        if (q_start) {
            q_start += 2;
            char *q_end = strchr(q_start, '&');
            size_t qlen = q_end ? (size_t)(q_end - q_start) : strlen(q_start);
            q_param = (char *)malloc(qlen + 1);
            memcpy(q_param, q_start, qlen);
            q_param[qlen] = '\0';
        }
    }

    /* Build JSON array */
    size_t buf_size = 64 + state->vault.entry_count * 16384;
    char *buf = (char *)malloc(buf_size);
    strcpy(buf, "[");
    int first = 1;

    for (int i = 0; i < state->vault.entry_count; i++) {
        const vault_entry_t *e = &state->vault.entries[i];

        /* Simple search filter */
        if (q_param && q_param[0]) {
            char q_lower[256];
            strncpy(q_lower, q_param, sizeof(q_lower) - 1);
            for (char *p = q_lower; *p; p++) *p = (char)tolower((unsigned char)*p);

            char label_lower[VAULT_LABEL_MAX];
            strncpy(label_lower, e->label, sizeof(label_lower) - 1);
            for (char *p = label_lower; *p; p++) *p = (char)tolower((unsigned char)*p);

            if (!strstr(label_lower, q_lower)) continue;
        }

        if (!first) strcat(buf, ",");
        char *ej = vault_entry_to_json(e);
        strcat(buf, ej);
        free(ej);
        first = 0;
    }
    strcat(buf, "]");

    pthread_mutex_unlock(&state->lock);
    free(q_param);

    send_json(fd, 200, "OK", buf);
    free(buf);
}

static void handle_get_credential(int fd, app_state_t *state, const char *id) {
    pthread_mutex_lock(&state->lock);
    const vault_entry_t *e = vault_get_by_id(&state->vault, id);
    if (!e) {
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 404, "Not Found", "Credential not found");
        return;
    }
    char *json = vault_entry_to_json(e);
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 200, "OK", json);
    free(json);
}

static void handle_create_credential(int fd, app_state_t *state, http_request_t *req) {
    char *label = json_body_get_string(req->body, "label");
    if (!label) {
        send_error(fd, 400, "Bad Request", "Missing label");
        return;
    }

    char *website = json_body_get_string(req->body, "website");
    char *username = json_body_get_string(req->body, "username");
    char *password = json_body_get_string(req->body, "password");
    char *totp_secret = json_body_get_string(req->body, "totp_secret");
    char *notes = json_body_get_string(req->body, "notes");
    int gen_pw = json_body_get_bool(req->body, "generate_password", 0);
    int pw_len = json_body_get_int(req->body, "password_length", 24);

    char gen_buf[512];
    if (gen_pw) {
        password_options_t opts;
        password_options_default(&opts);
        opts.length = (size_t)pw_len;
        password_generate(&opts, gen_buf);
        free(password);
        password = strdup(gen_buf);
    }

    vault_entry_t entry;
    vault_entry_new(&entry, label, website, username,
                    password ? password : "", totp_secret, notes);

    /* Parse optional tags array.  vault_add_or_update copies entry by value,
     * so tags must be populated before the call. */
    int nt = json_body_get_string_array(req->body, "tags", entry.tags, VAULT_MAX_TAGS);
    if (nt < 0) {
        free(label); free(website); free(username);
        free(password); free(totp_secret); free(notes);
        send_error(fd, 400, "Bad Request", "Too many tags (max 16)");
        return;
    }
    entry.tag_count = nt;

    pthread_mutex_lock(&state->lock);
    vault_add_or_update(&state->vault, &entry);
    save_vault_with_state(state);
    const vault_entry_t *saved = vault_get_by_id(&state->vault, entry.id);
    char *json = saved ? vault_entry_to_json(saved) : strdup("{\"error\":\"not found\"}");
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 201, "Created", json);
    free(json);
    free(label); free(website); free(username);
    free(password); free(totp_secret); free(notes);
}

static void handle_update_credential(int fd, app_state_t *state, const char *id, http_request_t *req) {
    pthread_mutex_lock(&state->lock);

    vault_entry_t *e = NULL;
    for (int i = 0; i < state->vault.entry_count; i++) {
        if (strcmp(state->vault.entries[i].id, id) == 0) {
            e = &state->vault.entries[i];
            break;
        }
    }
    if (!e) {
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 404, "Not Found", "Credential not found");
        return;
    }

    char *val;
    if ((val = json_body_get_string(req->body, "label"))) {
        strncpy(e->label, val, VAULT_LABEL_MAX - 1); free(val);
    }
    if ((val = json_body_get_string(req->body, "website"))) {
        strncpy(e->website, val, VAULT_FIELD_MAX - 1); free(val);
    }
    if ((val = json_body_get_string(req->body, "username"))) {
        strncpy(e->username, val, VAULT_FIELD_MAX - 1); free(val);
    }
    if ((val = json_body_get_string(req->body, "password"))) {
        /* Push old to history */
        if (e->history_count < VAULT_MAX_HISTORY) {
            strncpy(e->history[e->history_count].password, e->password, VAULT_PASSWORD_MAX - 1);
            e->history[e->history_count].changed_at = unix_now();
            e->history_count++;
        }
        strncpy(e->password, val, VAULT_PASSWORD_MAX - 1);
        free(val);
    }
    if ((val = json_body_get_string(req->body, "totp_secret"))) {
        strncpy(e->totp_secret, val, VAULT_FIELD_MAX - 1); free(val);
    }
    if ((val = json_body_get_string(req->body, "notes"))) {
        strncpy(e->notes, val, VAULT_FIELD_MAX - 1); free(val);
    }

    /* Tags use PATCH semantic: key absent → keep existing; key present (even
     * as []) → replace.  Matches the Rust handler's Option<Vec<String>>. */
    if (strstr(req->body, "\"tags\":")) {
        char new_tags[VAULT_MAX_TAGS][VAULT_LABEL_MAX];
        int nt = json_body_get_string_array(req->body, "tags", new_tags, VAULT_MAX_TAGS);
        if (nt < 0) {
            pthread_mutex_unlock(&state->lock);
            send_error(fd, 400, "Bad Request", "Too many tags (max 16)");
            return;
        }
        memset(e->tags, 0, sizeof(e->tags));
        memcpy(e->tags, new_tags, sizeof(new_tags));
        e->tag_count = nt;
    }

    e->updated_at = unix_now();

    save_vault_with_state(state);
    char *json = vault_entry_to_json(e);
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 200, "OK", json);
    free(json);
}

static void handle_delete_credential(int fd, app_state_t *state, const char *id) {
    pthread_mutex_lock(&state->lock);
    if (!vault_delete_by_id(&state->vault, id)) {
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 404, "Not Found", "Credential not found");
        return;
    }
    save_vault_with_state(state);
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 200, "OK", "{\"status\":\"deleted\"}");
}

static void handle_get_totp(int fd, app_state_t *state, const char *id) {
    pthread_mutex_lock(&state->lock);
    const vault_entry_t *e = vault_get_by_id(&state->vault, id);
    if (!e) {
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 404, "Not Found", "Credential not found");
        return;
    }
    if (!e->totp_secret[0]) {
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 400, "Bad Request", "No TOTP secret configured");
        return;
    }

    char code[8];
    uint32_t remaining;
    char secret_copy[VAULT_FIELD_MAX];
    strncpy(secret_copy, e->totp_secret, sizeof(secret_copy) - 1);
    pthread_mutex_unlock(&state->lock);

    if (totp_generate(secret_copy, code, &remaining) != 0) {
        send_error(fd, 500, "Internal Server Error", "TOTP generation failed");
        return;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "{\"code\":\"%s\",\"seconds_remaining\":%u}", code, remaining);
    send_json(fd, 200, "OK", buf);
}

static void handle_generate_password(int fd, http_request_t *req) {
    int length = json_body_get_int(req->body, "length", 24);
    int uppercase = json_body_get_bool(req->body, "uppercase", 1);
    int lowercase = json_body_get_bool(req->body, "lowercase", 1);
    int digits = json_body_get_bool(req->body, "digits", 1);
    int symbols = json_body_get_bool(req->body, "symbols", 1);

    password_options_t opts;
    opts.length = (size_t)length;
    opts.uppercase = uppercase;
    opts.lowercase = lowercase;
    opts.digits = digits;
    opts.symbols = symbols;

    char pw[512];
    password_generate(&opts, pw);
    password_strength_t strength = password_calculate_strength(pw);

    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"password\":\"%s\",\"strength\":{\"entropy_bits\":%.2f,"
             "\"level\":\"%s\",\"charset_size\":%d,\"length\":%zu}}",
             pw, strength.entropy_bits, strength.level, strength.charset_size, strength.length);
    send_json(fd, 200, "OK", buf);
}

static void handle_rotate_key(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    uint8_t new_dek[32];
    const char *source;
    if (state->has_traffic_entropy) {
        generate_dek_from_traffic(state->latest_entropy, 32, new_dek);
        source = "traffic";
    } else {
        generate_dek_from_os(new_dek);
        source = "os";
    }

    rotate_dek(&state->vault, state->master_password, new_dek, source);
    memcpy(state->current_dek, new_dek, 32);
    strncpy(state->entropy_source, source, sizeof(state->entropy_source) - 1);

    pthread_mutex_unlock(&state->lock);

    char buf[128];
    snprintf(buf, sizeof(buf), "{\"status\":\"rotated\",\"entropy_source\":\"%s\"}", source);
    send_json(fd, 200, "OK", buf);
}

static void handle_get_status(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{\"rotation\":{\"key_epoch\":%llu,\"frames_processed\":%llu,"
        "\"pool_depth\":%zu,\"is_running\":%s,\"has_traffic_entropy\":%s},"
        "\"stream_count\":%d,\"streams\":[],\"entry_count\":%d,"
        "\"entropy_source\":\"%s\"}",
        (unsigned long long)state->key_epoch,
        (unsigned long long)state->frames_processed,
        state->pool_depth,
        state->rotation_running ? "true" : "false",
        state->has_traffic_entropy ? "true" : "false",
        state->stream_config.stream_count,
        state->vault.entry_count,
        state->entropy_source);

    pthread_mutex_unlock(&state->lock);
    send_json(fd, 200, "OK", buf);
}

static void handle_entropy_snapshot(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    char entropy_hex[65];
    if (state->has_traffic_entropy) {
        hex_encode(state->latest_entropy, 32, entropy_hex);
    } else {
        strcpy(entropy_hex, "0000000000000000");
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"key_epoch\":%llu,\"frames_processed\":%llu,"
        "\"pool_depth\":%zu,\"has_traffic_entropy\":%s,"
        "\"is_running\":%s,\"entropy_source\":\"%s\","
        "\"latest_key_hex\":\"%s\"}",
        (unsigned long long)state->key_epoch,
        (unsigned long long)state->frames_processed,
        state->pool_depth,
        state->has_traffic_entropy ? "true" : "false",
        state->rotation_running ? "true" : "false",
        state->entropy_source, entropy_hex);

    pthread_mutex_unlock(&state->lock);
    send_json(fd, 200, "OK", buf);
}

static void handle_get_settings(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    char buf[4096];
    snprintf(buf, sizeof(buf),
        "{\"auto_lock_minutes\":%llu,\"streams\":[",
        (unsigned long long)state->auto_lock_minutes);

    for (int i = 0; i < state->stream_config.stream_count; i++) {
        char entry_buf[2048];
        snprintf(entry_buf, sizeof(entry_buf),
                 "%s{\"url\":\"%s\",\"label\":\"%s\",\"enabled\":%s}",
                 i > 0 ? "," : "",
                 state->stream_config.streams[i].url,
                 state->stream_config.streams[i].label,
                 state->stream_config.streams[i].enabled ? "true" : "false");
        strcat(buf, entry_buf);
    }
    strcat(buf, "]}");

    pthread_mutex_unlock(&state->lock);
    send_json(fd, 200, "OK", buf);
}

static void handle_update_settings(int fd, app_state_t *state, http_request_t *req) {
    int mins = json_body_get_int(req->body, "auto_lock_minutes", -1);

    pthread_mutex_lock(&state->lock);
    if (mins > 0) {
        state->auto_lock_minutes = (uint64_t)mins;
        state->stream_config.settings.auto_lock_minutes = (uint64_t)mins;
        save_stream_config(&state->stream_config);
    }
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 200, "OK", "{\"status\":\"updated\"}");
}

static void handle_add_stream(int fd, app_state_t *state, http_request_t *req) {
    char *url = json_body_get_string(req->body, "url");
    char *label = json_body_get_string(req->body, "label");
    if (!url || !label) {
        free(url); free(label);
        send_error(fd, 400, "Bad Request", "Missing url or label");
        return;
    }

    /* We still persist the config so the user's stream list survives across
     * restarts — Rust users on the same machine read the same file and will
     * benefit from ingestion. But the C daemon itself does not open the
     * stream, so we respond 501 to be honest about it. See /api/build/info. */
    pthread_mutex_lock(&state->lock);
    if (state->stream_config.stream_count < VAULT_MAX_STREAMS) {
        stream_entry_t *se = &state->stream_config.streams[state->stream_config.stream_count];
        memset(se, 0, sizeof(*se));
        strncpy(se->url, url, VAULT_FIELD_MAX - 1);
        strncpy(se->label, label, VAULT_LABEL_MAX - 1);
        se->enabled = 1;
        state->stream_config.stream_count++;
        save_stream_config(&state->stream_config);
    }
    pthread_mutex_unlock(&state->lock);

    send_json(fd, 501, "Not Implemented",
              "{\"error\":\"Stream ingestion not implemented in this build; "
              "OS entropy only. See /api/build/info\"}");
    free(url); free(label);
}

static void handle_remove_stream(int fd, app_state_t *state, int index) {
    pthread_mutex_lock(&state->lock);
    if (index >= 0 && index < state->stream_config.stream_count) {
        memmove(&state->stream_config.streams[index],
                &state->stream_config.streams[index + 1],
                ((size_t)state->stream_config.stream_count - (size_t)index - 1) * sizeof(stream_entry_t));
        state->stream_config.stream_count--;
        save_stream_config(&state->stream_config);
        pthread_mutex_unlock(&state->lock);
        send_json(fd, 200, "OK", "{\"status\":\"removed\"}");
    } else {
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 400, "Bad Request", "Stream index out of range");
    }
}

static void handle_list_streams(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);
    /* The C build does not implement stream ingestion yet. We still list the
     * configured streams (so the UI shows what the user configured and so the
     * config persists for parity with the Rust build), but every entry is
     * Disabled and reports zero frames. See /api/build/info. */
    char buf[8192] = "[";
    for (int i = 0; i < state->stream_config.stream_count; i++) {
        char entry_buf[2048];
        snprintf(entry_buf, sizeof(entry_buf),
                 "%s{\"url\":\"%s\",\"label\":\"%s\",\"status\":\"Disabled\","
                 "\"frames_captured\":0,"
                 "\"note\":\"OS entropy only in C build; see /api/build/info\"}",
                 i > 0 ? "," : "",
                 state->stream_config.streams[i].url,
                 state->stream_config.streams[i].label);
        strcat(buf, entry_buf);
    }
    strcat(buf, "]");
    pthread_mutex_unlock(&state->lock);
    send_json(fd, 200, "OK", buf);
}

static void handle_build_info(int fd) {
    /* Honest build descriptor. No auth required — the frontend needs this at
     * page load to decide whether to render the OS-only banner. */
    send_json(fd, 200, "OK",
              "{\"build\":\"c\",\"traffic_entropy\":false,"
              "\"note\":\"OS entropy only; see README\"}");
}

/* --- Request router --- */

static void handle_request(int fd, app_state_t *state, http_request_t *req) {
    /* CORS preflight */
    if (strcmp(req->method, "OPTIONS") == 0) {
        send_json(fd, 200, "OK", "{}");
        return;
    }

    /* Static files */
    if (strcmp(req->method, "GET") == 0) {
        if (strcmp(req->path, "/") == 0) {
            if (frontend_index) {
                http_response_t resp = {200, "OK", "text/html", frontend_index, frontend_index_len};
                send_response(fd, &resp);
            } else {
                send_error(fd, 404, "Not Found", "Frontend not found");
            }
            return;
        }
        if (strcmp(req->path, "/app.js") == 0) {
            if (frontend_js) {
                http_response_t resp = {200, "OK", "application/javascript", frontend_js, frontend_js_len};
                send_response(fd, &resp);
            }
            return;
        }
        if (strcmp(req->path, "/style.css") == 0) {
            if (frontend_css) {
                http_response_t resp = {200, "OK", "text/css", frontend_css, frontend_css_len};
                send_response(fd, &resp);
            }
            return;
        }
    }

    /* API routes - check auth for protected routes */
    (void)0; /* auth checked per-route below */

    /* Public routes that don't need auth */
    if (strcmp(req->path, "/api/auth/unlock") == 0 && strcmp(req->method, "POST") == 0) {
        handle_unlock(fd, state, req);
        return;
    }
    if (strcmp(req->path, "/api/auth/status") == 0 && strcmp(req->method, "GET") == 0) {
        handle_auth_status(fd, state);
        return;
    }
    /* Build descriptor — no auth, mirrors Rust /api/build/info */
    if (strcmp(req->path, "/api/build/info") == 0 && strcmp(req->method, "GET") == 0) {
        handle_build_info(fd);
        return;
    }

    /* All other API routes need auth */
    if (strncmp(req->path, "/api/", 5) == 0) {
        pthread_mutex_lock(&state->lock);
        int valid = validate_session(state, req->auth_header);
        pthread_mutex_unlock(&state->lock);

        if (!valid) {
            send_unauthorized(fd);
            return;
        }
    }

    /* Auth routes */
    if (strcmp(req->path, "/api/auth/lock") == 0 && strcmp(req->method, "POST") == 0) {
        handle_lock(fd, state);
        return;
    }
    if (strcmp(req->path, "/api/auth/verify-password") == 0 && strcmp(req->method, "POST") == 0) {
        handle_verify_password(fd, state, req);
        return;
    }

    /* Credentials */
    if (strcmp(req->path, "/api/credentials") == 0 || strncmp(req->path, "/api/credentials?", 17) == 0) {
        if (strcmp(req->method, "GET") == 0) {
            handle_list_credentials(fd, state, req);
            return;
        }
        if (strcmp(req->method, "POST") == 0) {
            handle_create_credential(fd, state, req);
            return;
        }
    }

    /* /api/credentials/<id> or /api/credentials/<id>/totp */
    if (strncmp(req->path, "/api/credentials/", 17) == 0) {
        const char *rest = req->path + 17;
        char id[64];
        const char *slash = strchr(rest, '/');
        if (slash) {
            size_t id_len = (size_t)(slash - rest);
            if (id_len >= sizeof(id)) id_len = sizeof(id) - 1;
            memcpy(id, rest, id_len);
            id[id_len] = '\0';

            if (strcmp(slash, "/totp") == 0 && strcmp(req->method, "GET") == 0) {
                handle_get_totp(fd, state, id);
                return;
            }
        } else {
            strncpy(id, rest, sizeof(id) - 1);
            id[sizeof(id) - 1] = '\0';
            /* Strip query string */
            char *q = strchr(id, '?');
            if (q) *q = '\0';
        }

        if (strcmp(req->method, "GET") == 0) {
            handle_get_credential(fd, state, id);
            return;
        }
        if (strcmp(req->method, "PUT") == 0) {
            handle_update_credential(fd, state, id, req);
            return;
        }
        if (strcmp(req->method, "DELETE") == 0) {
            handle_delete_credential(fd, state, id);
            return;
        }
    }

    /* Password generator */
    if (strcmp(req->path, "/api/generate-password") == 0 && strcmp(req->method, "POST") == 0) {
        handle_generate_password(fd, req);
        return;
    }

    /* Key rotation */
    if (strcmp(req->path, "/api/rotate-key") == 0 && strcmp(req->method, "POST") == 0) {
        handle_rotate_key(fd, state);
        return;
    }

    /* Streams */
    if (strcmp(req->path, "/api/streams") == 0) {
        if (strcmp(req->method, "GET") == 0) {
            handle_list_streams(fd, state);
            return;
        }
        if (strcmp(req->method, "POST") == 0) {
            handle_add_stream(fd, state, req);
            return;
        }
    }
    if (strncmp(req->path, "/api/streams/", 13) == 0) {
        int idx = atoi(req->path + 13);
        if (strcmp(req->method, "DELETE") == 0) {
            handle_remove_stream(fd, state, idx);
            return;
        }
    }

    /* Status & entropy */
    if (strcmp(req->path, "/api/status") == 0 && strcmp(req->method, "GET") == 0) {
        handle_get_status(fd, state);
        return;
    }
    if (strcmp(req->path, "/api/entropy-snapshot") == 0 && strcmp(req->method, "GET") == 0) {
        handle_entropy_snapshot(fd, state);
        return;
    }

    /* Settings */
    if (strcmp(req->path, "/api/settings") == 0) {
        if (strcmp(req->method, "GET") == 0) {
            handle_get_settings(fd, state);
            return;
        }
        if (strcmp(req->method, "PUT") == 0) {
            handle_update_settings(fd, state, req);
            return;
        }
    }

    send_error(fd, 404, "Not Found", "Route not found");
}

/* --- Main server loop --- */

int web_server_start(app_state_t *state, int port) {
    /* Load frontend files */
    load_frontend_file("frontend/index.html", &frontend_index, &frontend_index_len);
    load_frontend_file("frontend/app.js", &frontend_js, &frontend_js_len);
    load_frontend_file("frontend/style.css", &frontend_css, &frontend_css_len);

    if (!frontend_index) {
        fprintf(stderr, "[WARN] Could not load frontend/index.html\n");
    }

    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 32) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    fprintf(stderr, "[INFO] Listening on http://127.0.0.1:%d\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        http_request_t req;
        if (parse_request(client_fd, &req) == 0) {
            handle_request(client_fd, state, &req);
        }
        free(req.body);
        close(client_fd);
    }

    close(server_fd);
    free(frontend_index);
    free(frontend_js);
    free(frontend_css);
    return 0;
}
