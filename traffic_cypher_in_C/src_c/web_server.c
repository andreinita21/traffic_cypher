#include "web_server.h"
#include "vault.h"
#include "hex_utils.h"
#include "base64_utils.h"
#include "str_buf.h"
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
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* --- HTTP worker pool (see #7b) ---
 *
 * A fixed pool of POOL_WORKERS threads consumes accepted client fds from a
 * bounded circular queue.  The accept loop is single-threaded and pushes
 * onto the queue; if the queue is full the accept loop responds with a
 * canned 503 + close instead of blocking (blocking would re-introduce the
 * single-threaded DoS that this pool is meant to remove).
 *
 * Worker count of 4 is enough to absorb the typical localhost UI workload
 * without producing surprise concurrency between long-running handlers
 * (vault save, KDF, etc).  Queue cap of 32 matches the listen backlog.
 */
#define POOL_WORKERS 4
#define QUEUE_CAP    32

typedef struct {
    int             fds[QUEUE_CAP];
    size_t          head;
    size_t          tail;
    size_t          size;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} fdq_t;

/* Cap request bodies at 8 MiB. The C PM is a localhost-only service for a
 * single user, so this is generous; the cap exists to prevent an unauthenticated
 * caller from flooding the heap by lying about Content-Length. */
#define MAX_BODY_BYTES (8 * 1024 * 1024)

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
static char *frontend_phone = NULL;
static size_t frontend_phone_len = 0;

/* --- Pool / shutdown file-scope state (see worker pool block above) --- */
static volatile sig_atomic_t server_running = 1;
static int                   server_fd_global = -1;
static fdq_t                 g_queue;
static pthread_t             g_workers[POOL_WORKERS];
static int                   g_workers_started = 0;
static app_state_t          *g_state = NULL;

static void fdq_init(fdq_t *q) {
    q->head = q->tail = q->size = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

/* Try to push fd onto the queue without blocking. Returns 0 on success,
 * -1 if the queue is full. */
static int fdq_try_push(fdq_t *q, int fd) {
    pthread_mutex_lock(&q->mutex);
    if (q->size >= QUEUE_CAP) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    q->fds[q->tail] = fd;
    q->tail = (q->tail + 1) % QUEUE_CAP;
    q->size++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

/* Pop fd; blocks until one is available or server_running becomes 0.
 * Returns -1 if shutting down with empty queue. */
static int fdq_pop(fdq_t *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->size == 0 && server_running) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    if (q->size == 0) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    int fd = q->fds[q->head];
    q->head = (q->head + 1) % QUEUE_CAP;
    q->size--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return fd;
}

/* --- Constant-time string compare for session tokens (see #7b) ---
 *
 * `strcmp` short-circuits on the first mismatching byte, leaking a
 * comparison-time timing signal.  With the worker pool, an attacker can run
 * many concurrent unlock attempts and measure response timing to brute-force
 * a session token byte-by-byte.  Always compare every byte up to a fixed
 * cap (session_token is 64 bytes per web_server.h).
 *
 * Both inputs are NUL-terminated and the volatile accumulator prevents the
 * compiler from re-introducing the early exit. */
static int ct_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strnlen(a, 64);
    size_t lb = strnlen(b, 64);
    if (la != lb) return 0;
    volatile unsigned char acc = 0;
    for (size_t i = 0; i < la; i++) {
        acc |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return acc == 0;
}

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

    /* Ring capacity 256 matches Rust's tokio::mpsc::channel(256) at
     * multi_stream.rs:51. msm_new returns NULL on OOM; rotation_daemon and
     * the (future) stream handlers tolerate NULL. */
    state->msm = msm_new(256);
    if (!state->msm) {
        fprintf(stderr, "[WARN] msm_new failed — stream ingestion disabled\n");
    }
}

void app_state_touch(app_state_t *state) {
    state->last_activity = (uint64_t)time(NULL);
}

int app_state_check_auto_lock(app_state_t *state) {
    uint64_t now = (uint64_t)time(NULL);
    uint64_t elapsed = now - state->last_activity;
    return elapsed > state->auto_lock_minutes * 60;
}

/* Caller must hold state->lock. With the worker pool added in #7b, multiple
 * threads can race to read/write has_session, session_token, last_activity,
 * is_unlocked and has_dek. Every other handler already takes state->lock —
 * making this lock-required at the only call site (handle_request) keeps the
 * diff small and the contract explicit.
 *
 * The token compare uses ct_eq() to remove the timing side-channel that
 * becomes exploitable once concurrent requests are possible. */
int validate_session_locked(app_state_t *state, const char *auth_header) {
    if (!auth_header || !state->has_session) return 0;

    /* Expect "Bearer <token>" */
    if (strncmp(auth_header, "Bearer ", 7) != 0) return 0;
    const char *token = auth_header + 7;

    if (!ct_eq(token, state->session_token)) return 0;

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

/* Public entry point kept for ABI compatibility. Acquires state->lock itself.
 * Callers that already hold state->lock MUST use validate_session_locked. */
int validate_session(app_state_t *state, const char *auth_header) {
    pthread_mutex_lock(&state->lock);
    int valid = validate_session_locked(state, auth_header);
    pthread_mutex_unlock(&state->lock);
    return valid;
}

/* --- Minimal HTTP request parsing --- */

typedef struct {
    char method[16];
    char path[2048];
    char auth_header[256];
    char x_upload_token[128];  /* X-Upload-Token header (phone-camera frame POST) */
    char content_type[128];
    char *body;
    size_t body_len;
    long long content_length;
} http_request_t;

typedef struct {
    int status;
    const char *status_text;
    char content_type[128];
    char *body;
    size_t body_len;
} http_response_t;

/* Read headers + body from `fd` into req.
 *
 * Returns:
 *    0  ok
 *   -1  read failed / client disconnected before any bytes
 *   -2  Content-Length declared > MAX_BODY_BYTES (caller should send 413)
 *
 * Strategy: keep a 64 KiB scratch buffer for headers (and any prefix of body
 * that already arrived). After we know Content-Length, if the body fits in
 * scratch we copy it out; otherwise we malloc(content_length + 1) and stream
 * the remainder directly into that.
 */
static int parse_request(int fd, http_request_t *req) {
    memset(req, 0, sizeof(*req));

    char buf[65536];
    size_t total_read = 0;
    size_t header_end = 0;
    int found_header_end = 0;
    int have_cl = 0;

    while (total_read < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total_read, sizeof(buf) - 1 - total_read);
        if (n <= 0) break;
        total_read += (size_t)n;
        buf[total_read] = '\0';

        if (!found_header_end) {
            char *hend = strstr(buf, "\r\n\r\n");
            if (hend) {
                header_end = (size_t)(hend - buf) + 4;
                found_header_end = 1;

                /* Parse Content-Length with strtoll so we can distinguish
                 * absent / negative / huge from a real length. */
                char *cl = strcasestr(buf, "Content-Length:");
                if (cl) {
                    char *endp = NULL;
                    errno = 0;
                    long long v = strtoll(cl + 15, &endp, 10);
                    if (errno != 0 || endp == cl + 15 || v < 0) {
                        /* Unparseable or negative — treat as no body. */
                        req->content_length = 0;
                    } else {
                        req->content_length = v;
                        have_cl = 1;
                    }
                    /* Reject oversize early; don't try to stream-read it. */
                    if (req->content_length > MAX_BODY_BYTES) {
                        return -2;
                    }
                    /* If the body already fits in scratch, we're done. */
                    size_t body_read = total_read - header_end;
                    if ((long long)body_read >= req->content_length) break;
                } else {
                    break; /* No body expected */
                }
            }
        } else {
            size_t body_read = total_read - header_end;
            if ((long long)body_read >= req->content_length) break;
        }
    }

    if (total_read == 0) return -1;

    /* Parse request line */
    sscanf(buf, "%15s %2047s", req->method, req->path);

    /* Extract Authorization header */
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

    /* Extract X-Upload-Token header (phone-camera frame auth, NEXT_STEPS Phase B) */
    char *xut = strcasestr(buf, "X-Upload-Token:");
    if (xut) {
        xut += 15;
        while (*xut == ' ') xut++;
        char *eol = strstr(xut, "\r\n");
        if (eol) {
            size_t len = (size_t)(eol - xut);
            if (len >= sizeof(req->x_upload_token)) len = sizeof(req->x_upload_token) - 1;
            memcpy(req->x_upload_token, xut, len);
            req->x_upload_token[len] = '\0';
        }
    }

    /* Extract body */
    if (found_header_end && req->content_length > 0) {
        size_t body_available = (total_read > header_end) ? (total_read - header_end) : 0;
        size_t need = (size_t)req->content_length;

        if (need <= body_available) {
            /* Body fully in scratch already. */
            req->body = (char *)malloc(need + 1);
            if (!req->body) return -1;
            memcpy(req->body, buf + header_end, need);
            req->body[need] = '\0';
            req->body_len = need;
        } else if (have_cl) {
            /* Body partially read: stream the remainder directly into a
             * sized heap buffer using sb_reserve + sb_advance, so we never
             * walk into the 64 KiB scratch overflow path. */
            str_buf sb;
            sb_init(&sb, 0);
            if (sb_reserve(&sb, need + 1) != 0) {
                sb_free(&sb);
                return -1;
            }
            /* Copy what we already have. */
            memcpy(sb.data, buf + header_end, body_available);
            sb_advance(&sb, body_available);

            while (sb.len < need) {
                size_t want = need - sb.len;
                ssize_t n = read(fd, sb.data + sb.len, want);
                if (n <= 0) break; /* truncated — return what we got */
                sb_advance(&sb, (size_t)n);
            }
            size_t body_len = 0;
            char *body = sb_release(&sb, &body_len);
            if (!body) return -1;
            req->body = body;
            req->body_len = body_len;
        }
    }

    return 0;
}

/* write(2) on a socket may write fewer bytes than requested, especially for
 * large bodies (the Visualizer v2 endpoint serves ~600 KB of base64 frame
 * pixels). Loop until the whole buffer is sent or the connection breaks. */
static void write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            break;  /* peer closed / fatal error — nothing more we can do */
        }
        off += (size_t)n;
    }
}

/* Route-match a path, tolerating a trailing ?query so cache-busting asset
 * URLs (e.g. /app.js?v=2) still reach the static-file handlers. */
static int path_is(const char *path, const char *route) {
    size_t n = strlen(route);
    return strncmp(path, route, n) == 0 && (path[n] == '\0' || path[n] == '?');
}

static void send_response(int fd, http_response_t *resp) {
    char header[4096];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: http://127.0.0.1:9876\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "\r\n",
        resp->status, resp->status_text, resp->content_type, resp->body_len);

    write_all(fd, header, (size_t)header_len);
    if (resp->body && resp->body_len > 0) {
        write_all(fd, resp->body, resp->body_len);
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

/* Send a 429 Too Many Requests with a Retry-After header. The base
 * send_response builds headers from a static format string and has no slot
 * for one-off headers, so we inline the response here for the rate-limit
 * path. Body is the same {"error":"..."} envelope clients already parse. */
static void send_rate_limited(int fd, uint64_t retry_after_secs) {
    char body[256];
    int body_len = snprintf(body, sizeof(body),
        "{\"error\":\"Too many failed unlock attempts; retry after %llu s\"}",
        (unsigned long long)retry_after_secs);

    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Retry-After: %llu\r\n"
        "Access-Control-Allow-Origin: http://127.0.0.1:9876\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n",
        body_len, (unsigned long long)retry_after_secs);

    write(fd, header, (size_t)header_len);
    write(fd, body, (size_t)body_len);
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

/* Rate-limit window/lockout for /api/auth/unlock — see REMEDIATION_PLAN.md §8.
 * Lockout is overridable at startup via TC_UNLOCK_LOCKOUT_S (default 30 s) so
 * the test suite can drive this without sleeping a full 31 s. */
#define UNLOCK_WINDOW_SECS 60
#define UNLOCK_FAIL_LIMIT  5

static uint64_t unlock_lockout_secs(void) {
    const char *env = getenv("TC_UNLOCK_LOCKOUT_S");
    if (env && *env) {
        long v = strtol(env, NULL, 10);
        if (v > 0 && v < 86400) return (uint64_t)v;
    }
    return 30;
}

/* Returns seconds-remaining if a lockout is active right now, else 0.
 * On expiry, clears BOTH the lockout AND the failure ring — punishment
 * served, fresh window. Otherwise a single post-cooldown wrong attempt
 * would re-arm the lockout because the stale timestamps still sit within
 * the 60 s window. Caller must hold state->lock. */
static uint64_t unlock_lockout_remaining_locked(app_state_t *state, uint64_t now) {
    if (state->unlock_lockout_until == 0) return 0;
    if (now < state->unlock_lockout_until) {
        return state->unlock_lockout_until - now;
    }
    state->unlock_lockout_until = 0;
    for (int i = 0; i < UNLOCK_FAIL_LIMIT; i++) state->unlock_failures[i] = 0;
    state->unlock_failure_count = 0;
    return 0;
}

/* Record a failed unlock at `now`. If the 5-slot ring is full and all entries
 * lie within UNLOCK_WINDOW_SECS of `now`, arm the lockout. Caller holds lock. */
static void record_unlock_failure_locked(app_state_t *state, uint64_t now) {
    /* Overwrite the oldest slot (smallest timestamp; 0 counts as oldest). */
    int oldest = 0;
    for (int i = 1; i < UNLOCK_FAIL_LIMIT; i++) {
        if (state->unlock_failures[i] < state->unlock_failures[oldest]) {
            oldest = i;
        }
    }
    state->unlock_failures[oldest] = now;
    if (state->unlock_failure_count < UNLOCK_FAIL_LIMIT) {
        state->unlock_failure_count++;
    }

    if (state->unlock_failure_count >= UNLOCK_FAIL_LIMIT) {
        int all_in_window = 1;
        for (int i = 0; i < UNLOCK_FAIL_LIMIT; i++) {
            uint64_t t = state->unlock_failures[i];
            if (t == 0 || (now - t) > UNLOCK_WINDOW_SECS) { all_in_window = 0; break; }
        }
        if (all_in_window) {
            state->unlock_lockout_until = now + unlock_lockout_secs();
        }
    }
}

static void reset_unlock_rate_state_locked(app_state_t *state) {
    for (int i = 0; i < UNLOCK_FAIL_LIMIT; i++) state->unlock_failures[i] = 0;
    state->unlock_failure_count = 0;
    state->unlock_lockout_until = 0;
}

#ifdef ENABLE_TRAFFIC_ENTROPY
/* Heap-allocated snapshot of the persisted stream list, handed off from the
 * unlock handler to the replay pthread. The handler owns state->stream_config
 * (which it reads under state->lock); we copy the slots we need into our own
 * heap buffer so the replay thread can iterate without holding the state lock
 * across multi-second yt-dlp calls. */
typedef struct {
    multi_stream_manager_t *msm;
    int                     count;
    stream_entry_t          streams[VAULT_MAX_STREAMS];
} stream_replay_snapshot_t;

/* Why a detached thread: msm_add_stream is synchronous and calls yt-dlp +
 * starts ffmpeg per entry (~2-5 s each). Replaying inline from handle_unlock
 * would stall the HTTP response by 30+ s for a full 16-stream config. */
static void *stream_replay_main(void *arg) {
    stream_replay_snapshot_t *snap = (stream_replay_snapshot_t *)arg;
    if (snap && snap->msm) {
        for (int i = 0; i < snap->count; i++) {
            const stream_entry_t *se = &snap->streams[i];
            if (!se->enabled) continue;
            (void)msm_add_stream(snap->msm, se->url, se->label);
        }
    }
    free(snap);
    return NULL;
}

/* Snapshot the persisted streams under the lock, then launch a detached
 * pthread that re-registers each one with the manager. The thread frees the
 * snapshot on exit. Returns 0 on success, -1 on allocation / pthread failure
 * (in which case the snapshot is freed before return and unlock proceeds
 * without replay). Caller must hold state->lock. */
static int spawn_stream_replay_locked(app_state_t *state) {
    if (!state->msm || state->stream_config.stream_count == 0) {
        return 0;
    }
    stream_replay_snapshot_t *snap = malloc(sizeof(*snap));
    if (!snap) {
        return -1;
    }
    snap->msm = state->msm;
    snap->count = state->stream_config.stream_count;
    if (snap->count > VAULT_MAX_STREAMS) snap->count = VAULT_MAX_STREAMS;
    memcpy(snap->streams, state->stream_config.streams,
           (size_t)snap->count * sizeof(stream_entry_t));

    pthread_t tid;
    if (pthread_create(&tid, NULL, stream_replay_main, snap) != 0) {
        free(snap);
        return -1;
    }
    pthread_detach(tid);
    return 0;
}
#endif

static void handle_unlock(int fd, app_state_t *state, http_request_t *req) {
    char *master_pw = json_body_get_string(req->body, "master_password");
    if (!master_pw) {
        send_error(fd, 400, "Bad Request", "Missing master_password");
        return;
    }

    /* Rate-limit gate — during lockout, every unlock attempt (right or wrong)
     * returns 429 without touching load_vault. */
    pthread_mutex_lock(&state->lock);
    uint64_t now = (uint64_t)time(NULL);
    uint64_t remaining = unlock_lockout_remaining_locked(state, now);
    pthread_mutex_unlock(&state->lock);
    if (remaining > 0) {
        send_rate_limited(fd, remaining);
        free(master_pw);
        return;
    }

    /* Snapshot whether a vault file existed *before* load_vault — load_vault
     * silently generates a fresh DEK when the file is missing (first-run
     * path) but doesn't write the file. We persist it ourselves below so
     * /api/auth/status reports vault_exists=true on the very next refresh.
     * Without this, a brand-new user who hasn't added a credential yet would
     * be shown the first-setup screen again after every reload. */
    int was_first_run = (access(vault_path(), F_OK) != 0);

    unlocked_vault_t unlocked;
    if (load_vault(master_pw, &unlocked) != 0) {
        pthread_mutex_lock(&state->lock);
        record_unlock_failure_locked(state, (uint64_t)time(NULL));
        pthread_mutex_unlock(&state->lock);
        send_error(fd, 401, "Unauthorized", "Failed to unlock vault — wrong master password?");
        free(master_pw);
        return;
    }

    pthread_mutex_lock(&state->lock);

    /* Successful unlock — reset rate-limit window. */
    reset_unlock_rate_state_locked(state);

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

#ifdef ENABLE_TRAFFIC_ENTROPY
    if (spawn_stream_replay_locked(state) != 0) {
        fprintf(stderr, "warning: failed to spawn stream replay thread; "
                        "persisted streams will not auto-register\n");
    }
#endif

    /* Start rotation daemon */
    state->rotation_stop = 0;
    pthread_create(&state->rotation_thread, NULL, rotation_daemon, state);

    /* First-time setup: persist the empty vault now so the next /auth/status
     * probe sees vault_exists=true. Without this, a refresh before any
     * credential write would route back to the first-setup screen. */
    if (was_first_run) {
        if (save_vault_with_state(state) != 0) {
            fprintf(stderr, "warning: first-run save_vault failed; "
                            "vault file will appear only after the first "
                            "credential write\n");
        }
    }

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

    /* vault_exists drives first-setup vs unlock UI on the frontend. Use
     * access() so we don't try to parse a half-written file. */
    int vault_exists = (access(vault_path(), F_OK) == 0) ? 1 : 0;

    char buf[96];
    snprintf(buf, sizeof(buf), "{\"unlocked\":%s,\"vault_exists\":%s}",
             unlocked ? "true" : "false",
             vault_exists ? "true" : "false");
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

    /* Build JSON array using a growing buffer — no per-entry escape limits and
     * no fixed total cap. */
    str_buf sb;
    sb_init(&sb, 4096);
    sb_append(&sb, "[");
    int first = 1;

    for (int i = 0; i < state->vault.entry_count; i++) {
        const vault_entry_t *e = &state->vault.entries[i];

        if (q_param && q_param[0]) {
            char q_lower[256];
            strncpy(q_lower, q_param, sizeof(q_lower) - 1);
            q_lower[sizeof(q_lower) - 1] = '\0';
            for (char *p = q_lower; *p; p++) *p = (char)tolower((unsigned char)*p);

            char label_lower[VAULT_LABEL_MAX];
            strncpy(label_lower, e->label, sizeof(label_lower) - 1);
            label_lower[sizeof(label_lower) - 1] = '\0';
            for (char *p = label_lower; *p; p++) *p = (char)tolower((unsigned char)*p);

            if (!strstr(label_lower, q_lower)) continue;
        }

        if (!first) sb_append(&sb, ",");
        char *ej = vault_entry_to_json(e);
        if (ej) { sb_append(&sb, ej); free(ej); }
        first = 0;
    }
    sb_append(&sb, "]");

    pthread_mutex_unlock(&state->lock);
    free(q_param);

    char *buf = sb_release(&sb, NULL);
    if (!buf) {
        send_error(fd, 500, "Internal Server Error", "list serialization failed");
        return;
    }
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

/* Visualizer v2 endpoint. Serves the last two camera/stream frames the
 * rotation daemon processed (current + previous) as base64 RGB bytes so the
 * dashboard can recompute the entropy pipeline in-browser. Mirrors the Rust
 * GET /api/visualizer/frame. has_frame:false until the first frame lands. */
static void handle_visualizer_frame(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    /* Copy frame pointers/dims out under the lock, then release it before
     * the (potentially large) base64 encode + serialization. The pixel
     * buffers themselves are only freed by the rotation daemon, which holds
     * the lock when it does so — so we duplicate them here to be safe
     * against a concurrent daemon stop. */
    size_t cur_len = state->viz_frame_current_len;
    size_t prev_len = state->viz_frame_previous_len;
    uint8_t *cur = NULL, *prev = NULL;
    if (state->viz_frame_current && cur_len > 0) {
        cur = (uint8_t *)malloc(cur_len);
        if (cur) memcpy(cur, state->viz_frame_current, cur_len);
    }
    if (state->viz_frame_previous && prev_len > 0) {
        prev = (uint8_t *)malloc(prev_len);
        if (prev) memcpy(prev, state->viz_frame_previous, prev_len);
    }
    uint32_t w = state->viz_frame_current_w;
    uint32_t h = state->viz_frame_current_h;
    uint64_t seq = state->viz_frame_current_seq;
    char entropy_source[16];
    strncpy(entropy_source, state->entropy_source, sizeof(entropy_source) - 1);
    entropy_source[sizeof(entropy_source) - 1] = '\0';
    int has_frame = (cur != NULL);

    pthread_mutex_unlock(&state->lock);

    str_buf sb;
    sb_init(&sb, has_frame ? cur_len * 2 + 512 : 256);

    if (!has_frame) {
        sb_appendf(&sb,
            "{\"width\":0,\"height\":0,\"sequence\":0,"
            "\"current\":null,\"previous\":null,\"has_frame\":false,"
            "\"entropy_source\":\"%s\"}",
            entropy_source);
    } else {
        sb_appendf(&sb,
            "{\"width\":%u,\"height\":%u,\"sequence\":%llu,\"current\":\"",
            w, h, (unsigned long long)seq);

        /* base64_encode needs ((len+2)/3)*4 + 1 bytes of output room. */
        size_t cur_b64_cap = ((cur_len + 2) / 3) * 4 + 1;
        char *cur_b64 = (char *)malloc(cur_b64_cap);
        if (cur_b64) {
            base64_encode(cur, cur_len, cur_b64);
            sb_append(&sb, cur_b64);
            free(cur_b64);
        }

        sb_append(&sb, "\",\"previous\":");
        if (prev) {
            size_t prev_b64_cap = ((prev_len + 2) / 3) * 4 + 1;
            char *prev_b64 = (char *)malloc(prev_b64_cap);
            if (prev_b64) {
                base64_encode(prev, prev_len, prev_b64);
                sb_append(&sb, "\"");
                sb_append(&sb, prev_b64);
                sb_append(&sb, "\"");
                free(prev_b64);
            } else {
                sb_append(&sb, "null");
            }
        } else {
            sb_append(&sb, "null");
        }

        sb_appendf(&sb, ",\"has_frame\":true,\"entropy_source\":\"%s\"}",
                   entropy_source);
    }

    free(cur);
    free(prev);

    char *buf = sb_release(&sb, NULL);
    if (!buf) {
        send_error(fd, 500, "Internal Server Error",
                   "visualizer frame serialization failed");
        return;
    }
    send_json(fd, 200, "OK", buf);
    free(buf);
}

static void handle_get_settings(int fd, app_state_t *state) {
    pthread_mutex_lock(&state->lock);

    str_buf sb;
    sb_init(&sb, 256);
    sb_appendf(&sb, "{\"auto_lock_minutes\":%llu,\"streams\":[",
               (unsigned long long)state->auto_lock_minutes);
    for (int i = 0; i < state->stream_config.stream_count; i++) {
        if (i > 0) sb_append(&sb, ",");
        sb_append(&sb, "{\"url\":\"");
        sb_append_json_escaped(&sb, state->stream_config.streams[i].url);
        sb_append(&sb, "\",\"label\":\"");
        sb_append_json_escaped(&sb, state->stream_config.streams[i].label);
        sb_append(&sb, "\",\"enabled\":");
        sb_append(&sb, state->stream_config.streams[i].enabled ? "true" : "false");
        sb_append(&sb, "}");
    }
    sb_append(&sb, "]}");

    pthread_mutex_unlock(&state->lock);

    char *buf = sb_release(&sb, NULL);
    if (!buf) {
        send_error(fd, 500, "Internal Server Error", "settings serialization failed");
        return;
    }
    send_json(fd, 200, "OK", buf);
    free(buf);
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

#ifdef ENABLE_TRAFFIC_ENTROPY
    /* Route through the multi_stream manager. msm_add_stream is async: it
     * reserves a slot synchronously, then spawns a prep pthread that does
     * yt-dlp resolve + ffmpeg start in the background. We respond 202
     * Accepted with status:"connecting" and the slot index — the operator
     * polls GET /api/streams to observe the slot transitioning to Active or
     * Failed. msm_add_stream still returns -1 synchronously for
     * slot-exhaustion or allocation failure. */
    int msm_index = -1;
    if (state->msm) {
        msm_index = msm_add_stream(state->msm, url, label);
    }
    if (msm_index < 0) {
        send_error(fd, 503, "Service Unavailable",
                   "no free stream slot (max 16) or manager unavailable");
        free(url); free(label);
        return;
    }

    /* Persist alongside the MSM registration so the config survives restart. */
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

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"connecting\",\"index\":%d}", msm_index);
    send_json(fd, 202, "Accepted", resp);
#else
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
#endif
    free(url); free(label);
}

static void handle_remove_stream(int fd, app_state_t *state, int index) {
#ifdef ENABLE_TRAFFIC_ENTROPY
    /* The `index` arrives from the URL as the *compacted* position in the
     * list returned by GET /streams (msm_get_statuses skips inactive slots,
     * so a hole in `msm->slots[]` makes raw and compacted indices diverge).
     * Translate first; without this the wrong slot was being removed —
     * "Stream index out of range" if the compacted tail went past the last
     * raw slot, and silent mis-removal otherwise. */
    int raw_idx = state->msm ? msm_active_index_to_slot(state->msm, index) : -1;

    /* Snapshot the URL *before* removing from MSM so we can later identify
     * the matching stream_config entry by URL (phone slots aren't persisted,
     * so an index-based config removal mis-targets when phone and ffmpeg
     * slots are interleaved). */
    char removed_url[VAULT_FIELD_MAX] = {0};
    if (raw_idx >= 0) {
        stream_status_t snap[VAULT_MAX_STREAMS];
        int n = msm_get_statuses(state->msm, snap, VAULT_MAX_STREAMS);
        if (index >= 0 && index < n) {
            strncpy(removed_url, snap[index].url, sizeof(removed_url) - 1);
        }
    }

    int msm_rc = (raw_idx >= 0) ? msm_remove_stream(state->msm, raw_idx) : -1;

    /* Find the matching stream_config entry by URL (phone slots have no
     * config entry, so this naturally no-ops for them). */
    int touched_config = 0;
    pthread_mutex_lock(&state->lock);
    if (removed_url[0]) {
        for (int i = 0; i < state->stream_config.stream_count; i++) {
            if (strcmp(state->stream_config.streams[i].url, removed_url) == 0) {
                memmove(&state->stream_config.streams[i],
                        &state->stream_config.streams[i + 1],
                        ((size_t)state->stream_config.stream_count - (size_t)i - 1) * sizeof(stream_entry_t));
                state->stream_config.stream_count--;
                save_stream_config(&state->stream_config);
                touched_config = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&state->lock);

    if (msm_rc == 0 || touched_config) {
        send_json(fd, 200, "OK", "{\"status\":\"removed\"}");
    } else {
        send_error(fd, 400, "Bad Request", "Stream index out of range");
    }
#else
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
#endif
}

#ifdef ENABLE_TRAFFIC_ENTROPY
static const char *stream_state_str(stream_state_t s) {
    switch (s) {
        case STREAM_CONNECTING: return "Connecting";
        case STREAM_ACTIVE:     return "Active";
        case STREAM_FAILED:     return "Failed";
        case STREAM_STOPPED:    return "Stopped";
        default:                return "Unknown";
    }
}
#endif

static void handle_list_streams(int fd, app_state_t *state) {
    str_buf sb;
    sb_init(&sb, 512);
    sb_append(&sb, "[");
#ifdef ENABLE_TRAFFIC_ENTROPY
    /* Read live state from the multi_stream manager. */
    stream_status_t statuses[VAULT_MAX_STREAMS];
    int n = state->msm ? msm_get_statuses(state->msm, statuses, VAULT_MAX_STREAMS) : 0;
    uint64_t now_unix = (uint64_t)time(NULL);
    const uint64_t STALE_AFTER_SEC = 3;
    for (int i = 0; i < n; i++) {
        if (i > 0) sb_append(&sb, ",");
        sb_append(&sb, "{\"url\":\"");
        sb_append_json_escaped(&sb, statuses[i].url);
        sb_append(&sb, "\",\"label\":\"");
        sb_append_json_escaped(&sb, statuses[i].label);
        sb_append(&sb, "\",\"status\":\"");
        sb_append(&sb, stream_state_str(statuses[i].status));
        sb_append(&sb, "\",\"frames_captured\":");
        char num[32];
        snprintf(num, sizeof(num), "%llu", (unsigned long long)statuses[i].frames_captured);
        sb_append(&sb, num);
        sb_append(&sb, ",\"kind\":\"");
        sb_append(&sb, statuses[i].kind == SLOT_PHONE ? "phone" : "ffmpeg");
        sb_append(&sb, "\",\"enabled\":");
        sb_append(&sb, statuses[i].enabled ? "true" : "false");
        /* Liveness: `live` is true iff a frame arrived within the last
         * STALE_AFTER_SEC seconds. `seconds_idle` is the operator-facing
         * delta from `now`. Dashboard uses both to flip the row's status
         * text from "Active" to "Idle" without losing the underlying
         * status semantics. */
        uint64_t last = statuses[i].last_frame_unix;
        int is_live = (last != 0 && now_unix >= last && (now_unix - last) <= STALE_AFTER_SEC);
        sb_append(&sb, ",\"live\":");
        sb_append(&sb, is_live ? "true" : "false");
        sb_append(&sb, ",\"seconds_idle\":");
        if (last == 0) {
            sb_append(&sb, "null");
        } else {
            snprintf(num, sizeof(num), "%llu",
                     (unsigned long long)(now_unix >= last ? now_unix - last : 0));
            sb_append(&sb, num);
        }
        sb_append(&sb, "}");
    }
#else
    pthread_mutex_lock(&state->lock);
    /* The C build does not implement stream ingestion yet. We still list the
     * configured streams (so the UI shows what the user configured and so the
     * config persists for parity with the Rust build), but every entry is
     * Disabled and reports zero frames. See /api/build/info. */
    for (int i = 0; i < state->stream_config.stream_count; i++) {
        if (i > 0) sb_append(&sb, ",");
        sb_append(&sb, "{\"url\":\"");
        sb_append_json_escaped(&sb, state->stream_config.streams[i].url);
        sb_append(&sb, "\",\"label\":\"");
        sb_append_json_escaped(&sb, state->stream_config.streams[i].label);
        sb_append(&sb,
            "\",\"status\":\"Disabled\","
            "\"frames_captured\":0,"
            "\"note\":\"OS entropy only in C build; see /api/build/info\"}");
    }
    pthread_mutex_unlock(&state->lock);
#endif
    sb_append(&sb, "]");

    char *buf = sb_release(&sb, NULL);
    if (!buf) {
        send_error(fd, 500, "Internal Server Error", "stream list serialization failed");
        return;
    }
    send_json(fd, 200, "OK", buf);
    free(buf);
}

#ifdef ENABLE_TRAFFIC_ENTROPY
/* --- Phone-camera entropy source (NEXT_STEPS.md Phase B) ---
 *
 * Two endpoints, both public (no Bearer auth):
 *
 *   POST /api/streams/phone        — register a phone slot; returns
 *                                     {"index":N,"upload_token":"<64-hex>"}.
 *                                     Trust model: anyone on the network
 *                                     can register, but cannot push frames
 *                                     without the token. Max 16 slots; a
 *                                     malicious actor can DoS by filling
 *                                     them all (operator-fixable via DELETE).
 *
 *   POST /api/streams/phone/{N}/frame
 *                                  — push one PPM frame for slot N. Requires
 *                                     X-Upload-Token header (constant-time
 *                                     compared against the slot's token).
 *                                     Body: raw P6 PPM bytes.
 */

/* Minimal PPM parser: extracts width, height, and offset-of-pixel-bytes from
 * the binary P6 header. Returns 0 on success; -1 if malformed.
 *
 * We don't reuse frame_capture_read's parser because that one reads from a
 * FILE*; here the data is already in a memory buffer. */
static int parse_ppm_header(const uint8_t *buf, size_t buf_len,
                            uint32_t *width, uint32_t *height, size_t *pixel_off) {
    if (buf_len < 11) return -1;            /* "P6\n1 1\n255\n" min */
    if (buf[0] != 'P' || buf[1] != '6') return -1;
    /* Walk past whitespace + comments after "P6", then parse W H, then maxval,
     * then a single whitespace, then pixels. */
    size_t i = 2;
    int tokens[3] = {0, 0, 0};
    int t = 0;
    while (t < 3 && i < buf_len) {
        /* skip whitespace */
        while (i < buf_len && (buf[i] == ' ' || buf[i] == '\n' ||
                               buf[i] == '\r' || buf[i] == '\t')) i++;
        /* skip comment line */
        if (i < buf_len && buf[i] == '#') {
            while (i < buf_len && buf[i] != '\n') i++;
            continue;
        }
        /* parse decimal */
        int v = 0;
        int seen_digit = 0;
        while (i < buf_len && buf[i] >= '0' && buf[i] <= '9') {
            v = v * 10 + (buf[i] - '0');
            seen_digit = 1;
            if (v > 65535) return -1;  /* unreasonably large */
            i++;
        }
        if (!seen_digit) return -1;
        tokens[t++] = v;
    }
    if (t != 3) return -1;
    /* One whitespace byte separates the maxval from the pixel data. */
    if (i >= buf_len) return -1;
    i++;
    *width     = (uint32_t)tokens[0];
    *height    = (uint32_t)tokens[1];
    *pixel_off = i;
    return 0;
}

static void handle_register_phone(int fd, app_state_t *state, http_request_t *req) {
    char *label = json_body_get_string(req->body, "label");
    if (!label || label[0] == '\0') {
        free(label);
        send_error(fd, 400, "Bad Request", "Missing or empty label");
        return;
    }

    char token_hex[65];
    int idx = -1;
    if (state->msm) {
        idx = msm_register_phone(state->msm, label, token_hex);
    }
    free(label);

    if (idx < 0) {
        send_error(fd, 503, "Service Unavailable",
                   "no free stream slot (max 16) or manager unavailable");
        return;
    }

    /* Persist nothing to stream_config: phone slots are ephemeral by design
     * (tokens don't survive a restart, so the phone must re-pair anyway). */
    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"index\":%d,\"upload_token\":\"%s\"}", idx, token_hex);
    send_json(fd, 202, "Accepted", resp);
}

/* POST /api/streams/phone/{N}/frame */
static void handle_phone_frame(int fd, app_state_t *state, int idx, http_request_t *req) {
    if (!req->body || req->body_len == 0) {
        send_error(fd, 400, "Bad Request", "empty body");
        return;
    }
    if (req->x_upload_token[0] == '\0') {
        send_error(fd, 401, "Unauthorized", "X-Upload-Token header required");
        return;
    }

    uint32_t w = 0, h = 0;
    size_t pixel_off = 0;
    if (parse_ppm_header((const uint8_t *)req->body, req->body_len,
                          &w, &h, &pixel_off) != 0) {
        send_error(fd, 415, "Unsupported Media Type",
                   "body must be a P6 PPM frame");
        return;
    }
    size_t pixel_len = req->body_len - pixel_off;
    if (pixel_len != (size_t)w * (size_t)h * 3) {
        send_error(fd, 400, "Bad Request",
                   "PPM pixel data length does not match width*height*3");
        return;
    }

    int rc = msm_push_phone_frame(state->msm, idx, req->x_upload_token,
                                  (const uint8_t *)req->body + pixel_off,
                                  pixel_len, w, h);
    if (rc == 0) {
        send_json(fd, 204, "No Content", "");
        return;
    }
    if (rc == -2) {
        send_error(fd, 403, "Forbidden", "upload token mismatch");
        return;
    }
    if (rc == -3) {
        send_error(fd, 503, "Service Unavailable", "manager shutting down");
        return;
    }
    send_error(fd, 400, "Bad Request", "invalid slot or frame");
}
#endif /* ENABLE_TRAFFIC_ENTROPY */

static void handle_build_info(int fd) {
    /* Honest build descriptor. No auth required — the frontend needs this at
     * page load to decide whether to render the OS-only banner. */
#ifdef ENABLE_TRAFFIC_ENTROPY
    send_json(fd, 200, "OK",
              "{\"build\":\"c\",\"traffic_entropy\":true}");
#else
    send_json(fd, 200, "OK",
              "{\"build\":\"c\",\"traffic_entropy\":false,"
              "\"note\":\"OS entropy only; see README\"}");
#endif
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
        if (path_is(req->path, "/")) {
            if (frontend_index) {
                http_response_t resp = {200, "OK", "text/html", frontend_index, frontend_index_len};
                send_response(fd, &resp);
            } else {
                send_error(fd, 404, "Not Found", "Frontend not found");
            }
            return;
        }
        if (path_is(req->path, "/app.js")) {
            if (frontend_js) {
                http_response_t resp = {200, "OK", "application/javascript", frontend_js, frontend_js_len};
                send_response(fd, &resp);
            }
            return;
        }
        if (path_is(req->path, "/style.css")) {
            if (frontend_css) {
                http_response_t resp = {200, "OK", "text/css", frontend_css, frontend_css_len};
                send_response(fd, &resp);
            }
            return;
        }
        if (path_is(req->path, "/phone.html")) {
            if (frontend_phone) {
                http_response_t resp = {200, "OK", "text/html", frontend_phone, frontend_phone_len};
                send_response(fd, &resp);
            } else {
                send_error(fd, 404, "Not Found", "Phone page not found");
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

#ifdef ENABLE_TRAFFIC_ENTROPY
    /* Phone-camera entropy endpoints (no Bearer auth — see handle_register_phone
     * trust model comment). The frame POST is authenticated via X-Upload-Token
     * which is checked inside the handler via constant-time compare. */
    if (strcmp(req->path, "/api/streams/phone") == 0 && strcmp(req->method, "POST") == 0) {
        handle_register_phone(fd, state, req);
        return;
    }
    /* Match /api/streams/phone/{N}/frame */
    if (strncmp(req->path, "/api/streams/phone/", 19) == 0 &&
        strcmp(req->method, "POST") == 0) {
        const char *tail = req->path + 19;
        char *endp = NULL;
        long idx = strtol(tail, &endp, 10);
        if (endp != tail && *endp == '/' && strcmp(endp, "/frame") == 0 &&
            idx >= 0 && idx < VAULT_MAX_STREAMS) {
            handle_phone_frame(fd, state, (int)idx, req);
            return;
        }
    }
#endif

    /* All other API routes need auth */
    if (strncmp(req->path, "/api/", 5) == 0) {
        pthread_mutex_lock(&state->lock);
        int valid = validate_session_locked(state, req->auth_header);
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
        const char *tail = req->path + 13;
        char *endp = NULL;
        long idx = strtol(tail, &endp, 10);
        if (endp != tail && idx >= 0 && idx < VAULT_MAX_STREAMS) {
            /* /api/streams/{N} — DELETE removes the slot. */
            if (*endp == '\0' && strcmp(req->method, "DELETE") == 0) {
                handle_remove_stream(fd, state, (int)idx);
                return;
            }
#ifdef ENABLE_TRAFFIC_ENTROPY
            /* /api/streams/{N}/enable | /disable — operator toggles whether
             * the rotation daemon picks frames from this slot. The
             * underlying capture or phone-frame intake keeps running so the
             * toggle is instant; flipping back ON resumes contribution on
             * the next captured frame.
             *
             * `idx` here is the compacted active-list position from GET
             * /streams; translate to raw slot index before calling
             * msm_set_enabled (same divergence as handle_remove_stream). */
            if ((strcmp(endp, "/enable") == 0 || strcmp(endp, "/disable") == 0)
                && strcmp(req->method, "POST") == 0) {
                int want_enabled = (strcmp(endp, "/enable") == 0);
                int raw_idx = state->msm
                    ? msm_active_index_to_slot(state->msm, (int)idx)
                    : -1;
                int rc = (raw_idx >= 0)
                    ? msm_set_enabled(state->msm, raw_idx, want_enabled)
                    : -1;
                if (rc == 0) {
                    char resp[96];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"%s\",\"index\":%ld}",
                             want_enabled ? "enabled" : "disabled", idx);
                    send_json(fd, 200, "OK", resp);
                } else {
                    send_error(fd, 400, "Bad Request",
                               "stream slot out of range or empty");
                }
                return;
            }
#endif
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
    /* Visualizer v2 — last two processed camera/stream frames. */
    if (strcmp(req->path, "/api/visualizer/frame") == 0 && strcmp(req->method, "GET") == 0) {
        handle_visualizer_frame(fd, state);
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

/* --- Worker pool + graceful shutdown (see #7b) --- */

/* Canned 503 used when the queue is full. accept thread writes this and
 * closes the fd; workers don't see overflowed requests. */
static const char k_busy_response[] =
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 27\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"server busy\"}\n";

static void *worker_main(void *arg) {
    app_state_t *state = (app_state_t *)arg;
    while (1) {
        int client_fd = fdq_pop(&g_queue);
        if (client_fd < 0) break;  /* shutdown */

        /* Apply per-connection r/w timeouts inside the worker. With the
         * pool, multiple workers each apply their own timeouts; the old
         * single-threaded accept-then-handle path is gone. */
        struct timeval tv;
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        http_request_t req;
        int pr = parse_request(client_fd, &req);
        if (pr == 0) {
            handle_request(client_fd, state, &req);
        } else if (pr == -2) {
            /* Body exceeded MAX_BODY_BYTES — canned 413 and close. We
             * intentionally do not stream-read the body. */
            static const char payload_too_large[] =
                "HTTP/1.1 413 Payload Too Large\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 35\r\n"
                "Access-Control-Allow-Origin: http://127.0.0.1:9876\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"Request body too large\"}\n";
            (void)!write(client_fd, payload_too_large, sizeof(payload_too_large) - 1);
        }
        free(req.body);
        close(client_fd);
    }
    return NULL;
}

static void shutdown_signal_handler(int sig) {
    (void)sig;
    server_running = 0;
    if (server_fd_global >= 0) {
        /* Wake the accept() loop. shutdown() is async-signal-safe. */
        shutdown(server_fd_global, SHUT_RDWR);
    }
}

/* --- Main server loop --- */

int web_server_start(app_state_t *state, int port) {
    /* Load frontend files */
    load_frontend_file("frontend/index.html", &frontend_index, &frontend_index_len);
    load_frontend_file("frontend/app.js", &frontend_js, &frontend_js_len);
    load_frontend_file("frontend/style.css", &frontend_css, &frontend_css_len);
    /* phone.html is optional — missing on the OS-only build, present on the
     * traffic-entropy build. NEXT_STEPS.md Phase B. */
    load_frontend_file("frontend/phone.html", &frontend_phone, &frontend_phone_len);

    if (!frontend_index) {
        fprintf(stderr, "[WARN] Could not load frontend/index.html\n");
    }

    signal(SIGPIPE, SIG_IGN);

    /* Install SIGINT / SIGTERM handlers so graceful shutdown wakes accept()
     * and joins workers before returning. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdown_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* deliberately *not* SA_RESTART — we want accept() to
                       * return with EINTR when the signal arrives. */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind address is 127.0.0.1 by default — exposing the daemon on a LAN
     * means the unlock endpoint, phone-camera endpoints, and all credential
     * routes are reachable from any host that can route to this machine.
     * Operators that explicitly want LAN access can set TC_BIND_ADDR=0.0.0.0
     * (or a specific interface address). Per-IP rate limiting on /api/auth
     * /unlock is in place (#8), but you still want network-level isolation
     * if the daemon is reachable from untrusted hosts. */
    const char *bind_str = getenv("TC_BIND_ADDR");
    if (!bind_str || !*bind_str) bind_str = "127.0.0.1";
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, bind_str, &addr.sin_addr) != 1) {
        fprintf(stderr, "[ERROR] invalid TC_BIND_ADDR=%s (expected IPv4 dotted-decimal)\n", bind_str);
        close(server_fd);
        return -1;
    }
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

    server_fd_global = server_fd;
    g_state = state;

    /* Spawn worker pool BEFORE the accept loop.
     *
     * macOS pthreads default to 512 KB. handle_request inlines several
     * handlers and parse_request carries a 64 KB read buffer plus
     * vault_entry_t (~14 KB) and similar stack-allocated structs in the
     * credential handlers; the worker's worst-case frame size after
     * inlining can run several MB. Reserve 8 MB to match the main-thread
     * default and to give headroom for future handler growth. */
    fdq_init(&g_queue);
    pthread_attr_t worker_attr;
    pthread_attr_init(&worker_attr);
    pthread_attr_setstacksize(&worker_attr, 8 * 1024 * 1024);
    for (int i = 0; i < POOL_WORKERS; i++) {
        if (pthread_create(&g_workers[i], &worker_attr, worker_main, state) != 0) {
            perror("pthread_create worker");
            /* Best-effort: tear down whatever started. */
            server_running = 0;
            pthread_cond_broadcast(&g_queue.not_empty);
            for (int j = 0; j < i; j++) pthread_join(g_workers[j], NULL);
            pthread_attr_destroy(&worker_attr);
            close(server_fd);
            return -1;
        }
    }
    pthread_attr_destroy(&worker_attr);
    g_workers_started = 1;

    fprintf(stderr, "[INFO] Listening on http://%s:%d (workers=%d, queue=%d)\n",
            bind_str, port, POOL_WORKERS, QUEUE_CAP);

    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!server_running) break;
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        if (!server_running) {
            close(client_fd);
            break;
        }

        /* Hand off to a worker via the bounded queue. If full, do NOT block
         * (which would reproduce the original DoS); send a canned 503 and
         * close inline. The accept loop stays responsive. */
        if (fdq_try_push(&g_queue, client_fd) != 0) {
            (void)write(client_fd, k_busy_response, sizeof(k_busy_response) - 1);
            close(client_fd);
        }
    }

    /* --- Graceful shutdown --- */
    fprintf(stderr, "[INFO] Shutting down: draining workers...\n");

    /* Stop accepting new connections. */
    close(server_fd);
    server_fd_global = -1;

    /* Wake any idle workers so they observe server_running == 0. */
    pthread_mutex_lock(&g_queue.mutex);
    pthread_cond_broadcast(&g_queue.not_empty);
    pthread_mutex_unlock(&g_queue.mutex);

    if (g_workers_started) {
        for (int i = 0; i < POOL_WORKERS; i++) {
            pthread_join(g_workers[i], NULL);
        }
        g_workers_started = 0;
    }

    /* Drain any fds left in the queue (workers may have exited before they
     * drained — rare, but cheap to handle). */
    pthread_mutex_lock(&g_queue.mutex);
    while (g_queue.size > 0) {
        int fd = g_queue.fds[g_queue.head];
        g_queue.head = (g_queue.head + 1) % QUEUE_CAP;
        g_queue.size--;
        close(fd);
    }
    pthread_mutex_unlock(&g_queue.mutex);

    /* Now stop the rotation daemon, if it's running. */
    pthread_mutex_lock(&state->lock);
    int rotation_was_running = state->rotation_running;
    state->rotation_stop = 1;
    pthread_mutex_unlock(&state->lock);
    if (rotation_was_running) {
        pthread_join(state->rotation_thread, NULL);
    }

    /* Tear down the multi_stream manager last — rotation_daemon was the
     * consumer; with it joined no other thread reads state->msm. msm_free
     * SIGTERMs every forwarder + joins them before freeing the ring. */
    if (state->msm) {
        msm_free(state->msm);
        state->msm = NULL;
    }

    free(frontend_index);
    free(frontend_js);
    free(frontend_css);
    return 0;
}
