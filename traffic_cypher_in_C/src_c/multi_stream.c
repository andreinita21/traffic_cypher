#include "multi_stream.h"
#include "stream_ingestion.h"
#include "frame_sampler.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------------
 * Internal types
 * ----------------------------------------------------------------------*/

/* One queued (stream_index, frame) pair. */
typedef struct {
    int     stream_index;
    frame_t frame;
} ring_item_t;

/*
 * Bounded MPSC ring. Producers (per-stream forwarder threads) block on
 * `not_full` when capacity is reached; consumer (msm_pick_random_frame) is
 * non-blocking via msm_ring_try_pop. `closing` is set during msm_free so
 * producers can wake up and exit cleanly.
 */
typedef struct {
    ring_item_t    *items;
    size_t          capacity;
    size_t          head;       /* next write slot */
    size_t          tail;       /* next read slot */
    size_t          count;
    int             closing;
    pthread_mutex_t lock;
    pthread_cond_t  not_full;
} msm_ring_t;

typedef struct {
    char            url[VAULT_FIELD_MAX];
    char            label[VAULT_LABEL_MAX];
    stream_state_t  status;
    uint64_t        frames_captured;

    /*
     * `active`           1 if this slot is in use (CONNECTING/ACTIVE/FAILED/STOPPED).
     *                     0 means the slot is free and reusable by add_stream.
     * `cancel_requested` set by msm_remove_stream so the prep pthread can
     *                     abort early between yt-dlp resolve and ffmpeg start,
     *                     without remove having to interrupt those externals.
     * `prep_joined`      1 once the prep pthread has been joined.
     * `forwarder_joined` 1 once the forwarder pthread has been joined.
     */
    int             active;
    int             cancel_requested;
    int             prep_joined;
    int             forwarder_joined;

    /*
     * Two distinct pthreads can be associated with a slot:
     *
     *   prep_thread       transient. Runs resolve_stream_url + frame_capture_start
     *                      asynchronously after msm_add_stream returns. Exits as
     *                      soon as the forwarder has been spawned (or the slot
     *                      failed / was cancelled). Joinable so msm_remove_stream
     *                      and msm_free can wait on it.
     *   forwarder_thread  long-lived. Set by the prep thread once frame capture
     *                      is up. Reads frames from the ffmpeg pipe and pushes
     *                      them into the shared ring. 0 until set.
     *
     * Splitting the two means msm_add_stream returns immediately with a
     * CONNECTING slot index — the HTTP handler no longer blocks ~2-5 s on
     * yt-dlp. Auto-replay on unlock can fan out all 16 saved streams in
     * parallel.
     */
    pthread_t       prep_thread;
    pthread_t       forwarder_thread;

    /*
     * `capture_pid` is the ffmpeg child PID, set by the prep thread after
     * frame_capture_start succeeds. msm_remove_stream SIGTERMs this PID under
     * the manager mutex to unblock fread() inside the forwarder, which then
     * exits its read loop. Set to 0 once the forwarder has called
     * frame_capture_stop (so a late remove() doesn't kill an unrelated PID
     * that's been recycled).
     */
    pid_t           capture_pid;
} stream_slot_t;

struct multi_stream_manager {
    pthread_mutex_t lock;
    msm_ring_t      ring;
    stream_slot_t   slots[VAULT_MAX_STREAMS];
};

/* ------------------------------------------------------------------------
 * Ring buffer
 * ----------------------------------------------------------------------*/

static int ring_init(msm_ring_t *r, size_t capacity) {
    r->items = (ring_item_t *)calloc(capacity, sizeof(ring_item_t));
    if (!r->items) return -1;
    r->capacity = capacity;
    r->head = 0;
    r->tail = 0;
    r->count = 0;
    r->closing = 0;
    if (pthread_mutex_init(&r->lock, NULL) != 0) {
        free(r->items);
        return -1;
    }
    if (pthread_cond_init(&r->not_full, NULL) != 0) {
        pthread_mutex_destroy(&r->lock);
        free(r->items);
        return -1;
    }
    return 0;
}

static void ring_close(msm_ring_t *r) {
    pthread_mutex_lock(&r->lock);
    r->closing = 1;
    pthread_cond_broadcast(&r->not_full);
    pthread_mutex_unlock(&r->lock);
}

static void ring_free(msm_ring_t *r) {
    /* Drain any remaining items so we don't leak their frame->data. */
    while (r->count > 0) {
        ring_item_t *it = &r->items[r->tail];
        if (it->frame.data) free(it->frame.data);
        r->tail = (r->tail + 1) % r->capacity;
        r->count--;
    }
    pthread_cond_destroy(&r->not_full);
    pthread_mutex_destroy(&r->lock);
    free(r->items);
    r->items = NULL;
}

/*
 * Blocking push. Takes ownership of frame->data. Returns 0 on success, -1 if
 * the ring was closed before the slot freed (caller should free frame->data).
 */
static int ring_push(msm_ring_t *r, int stream_index, const frame_t *frame) {
    pthread_mutex_lock(&r->lock);
    while (r->count == r->capacity && !r->closing) {
        pthread_cond_wait(&r->not_full, &r->lock);
    }
    if (r->closing) {
        pthread_mutex_unlock(&r->lock);
        return -1;
    }
    r->items[r->head].stream_index = stream_index;
    r->items[r->head].frame = *frame;
    r->head = (r->head + 1) % r->capacity;
    r->count++;
    pthread_mutex_unlock(&r->lock);
    return 0;
}

/*
 * Non-blocking pop. Returns 0 and fills *out_index + *out_frame on success
 * (caller takes ownership of out_frame->data); returns -1 when empty.
 */
static int ring_try_pop(msm_ring_t *r, int *out_index, frame_t *out_frame) {
    pthread_mutex_lock(&r->lock);
    if (r->count == 0) {
        pthread_mutex_unlock(&r->lock);
        return -1;
    }
    *out_index = r->items[r->tail].stream_index;
    *out_frame = r->items[r->tail].frame;
    r->tail = (r->tail + 1) % r->capacity;
    r->count--;
    pthread_cond_signal(&r->not_full);
    pthread_mutex_unlock(&r->lock);
    return 0;
}

/* ------------------------------------------------------------------------
 * Forwarder thread
 * ----------------------------------------------------------------------*/

typedef struct {
    multi_stream_manager_t *msm;
    int                     slot_index;
    char                   *resolved_url;  /* heap; freed by thread */
    frame_capture_t        *capture;       /* owned by thread */
} forwarder_arg_t;

static void *forwarder_main(void *arg_) {
    forwarder_arg_t *arg = (forwarder_arg_t *)arg_;
    multi_stream_manager_t *msm = arg->msm;
    int idx = arg->slot_index;
    frame_capture_t *capture = arg->capture;

    /* Status transition CONNECTING → ACTIVE is published here, not in the
     * prep thread, so a get_statuses() call between prep finishing and the
     * first frame arriving sees ACTIVE (matches Rust's "spawned task = stream
     * active" semantics). capture_pid was already published by prep before
     * we were created. */
    pthread_mutex_lock(&msm->lock);
    msm->slots[idx].status = STREAM_ACTIVE;
    pthread_mutex_unlock(&msm->lock);

    /* Main read loop. frame_capture_read blocks on fread; SIGTERM to the
     * ffmpeg child closes the pipe, fread returns 0, frame_capture_read
     * returns -1, and we exit. */
    while (1) {
        frame_t frame;
        memset(&frame, 0, sizeof(frame));

        if (frame_capture_read(capture, &frame) != 0) {
            /* EOF or read error — capture is done. */
            break;
        }

        if (ring_push(&msm->ring, idx, &frame) != 0) {
            /* Ring is closing — drop this frame and exit. */
            free(frame.data);
            break;
        }
    }

    /* Stop the capture (closes pipe, SIGTERMs child if alive, frees handle). */
    frame_capture_stop(capture);

    pthread_mutex_lock(&msm->lock);
    msm->slots[idx].capture_pid = 0;
    if (msm->slots[idx].status != STREAM_FAILED) {
        msm->slots[idx].status = STREAM_STOPPED;
    }
    pthread_mutex_unlock(&msm->lock);

    free(arg->resolved_url);
    free(arg);
    return NULL;
}

/* ------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------*/

multi_stream_manager_t *msm_new(size_t ring_capacity) {
    if (ring_capacity == 0) return NULL;

    multi_stream_manager_t *msm =
        (multi_stream_manager_t *)calloc(1, sizeof(multi_stream_manager_t));
    if (!msm) return NULL;

    if (pthread_mutex_init(&msm->lock, NULL) != 0) {
        free(msm);
        return NULL;
    }
    if (ring_init(&msm->ring, ring_capacity) != 0) {
        pthread_mutex_destroy(&msm->lock);
        free(msm);
        return NULL;
    }
    /* All slots zero-initialized by calloc: active=0, status=STREAM_CONNECTING,
     * which is fine because active=0 means "ignore status". */
    return msm;
}

static int find_free_slot_locked(multi_stream_manager_t *msm) {
    for (int i = 0; i < VAULT_MAX_STREAMS; i++) {
        if (!msm->slots[i].active) return i;
    }
    return -1;
}

/* ------------------------------------------------------------------------
 * Prep thread — runs the slow synchronous setup (yt-dlp + ffmpeg) off the
 * caller's thread so msm_add_stream returns in microseconds instead of
 * seconds. See REMEDIATION_PROGRESS.md 2026-05-13 "stage 5 async refactor".
 * ----------------------------------------------------------------------*/

typedef struct {
    multi_stream_manager_t *msm;
    int                     slot_index;
    char                    url[VAULT_FIELD_MAX];
} prep_arg_t;

static void *prep_main(void *arg_) {
    prep_arg_t *arg = (prep_arg_t *)arg_;
    multi_stream_manager_t *msm = arg->msm;
    int idx = arg->slot_index;

    char            *resolved      = NULL;
    frame_capture_t *capture       = NULL;
    forwarder_arg_t *fwd_arg       = NULL;
    int              forwarder_up  = 0;

    /* Phase 1: yt-dlp resolve (~2-5 s). */
    resolved = resolve_stream_url(arg->url);
    if (!resolved) goto done;

    /* Cancel check between blocking calls so a remove issued during resolve
     * stops here instead of marching on through ffmpeg start. */
    pthread_mutex_lock(&msm->lock);
    int cancelled = msm->slots[idx].cancel_requested;
    pthread_mutex_unlock(&msm->lock);
    if (cancelled) goto done;

    /* Phase 2: ffmpeg start (~1 s). */
    capture = frame_capture_start(resolved);
    if (!capture) goto done;

    pthread_mutex_lock(&msm->lock);
    cancelled = msm->slots[idx].cancel_requested;
    pthread_mutex_unlock(&msm->lock);
    if (cancelled) goto done;

    /* Phase 3: spawn the long-lived forwarder. */
    fwd_arg = (forwarder_arg_t *)calloc(1, sizeof(*fwd_arg));
    if (!fwd_arg) goto done;
    fwd_arg->msm          = msm;
    fwd_arg->slot_index   = idx;
    fwd_arg->resolved_url = resolved;
    fwd_arg->capture      = capture;

    pthread_t fwd_tid;
    if (pthread_create(&fwd_tid, NULL, forwarder_main, fwd_arg) != 0) goto done;

    /* Publish capture_pid + forwarder_thread atomically so msm_remove_stream
     * sees a coherent (pid, tid) pair if it fires the instant we exit. */
    pthread_mutex_lock(&msm->lock);
    msm->slots[idx].capture_pid      = frame_capture_pid(capture);
    msm->slots[idx].forwarder_thread = fwd_tid;
    pthread_mutex_unlock(&msm->lock);

    /* Ownership transferred to the forwarder. */
    forwarder_up = 1;
    resolved = NULL;
    capture  = NULL;
    fwd_arg  = NULL;

done:
    if (!forwarder_up) {
        if (capture)  frame_capture_stop(capture);
        free(resolved);
        free(fwd_arg);
        pthread_mutex_lock(&msm->lock);
        if (msm->slots[idx].active) {
            msm->slots[idx].status = STREAM_FAILED;
        }
        pthread_mutex_unlock(&msm->lock);
    }
    free(arg);
    return NULL;
}

int msm_add_stream(multi_stream_manager_t *msm, const char *url, const char *label) {
    if (!msm || !url || !label) return -1;

    /* Reserve a slot so a concurrent get_statuses() sees STREAM_CONNECTING
     * immediately. All slow work happens in the prep pthread. */
    pthread_mutex_lock(&msm->lock);
    int idx = find_free_slot_locked(msm);
    if (idx < 0) {
        pthread_mutex_unlock(&msm->lock);
        return -1;
    }
    stream_slot_t *slot = &msm->slots[idx];
    memset(slot, 0, sizeof(*slot));
    slot->active = 1;
    slot->status = STREAM_CONNECTING;
    strncpy(slot->url, url, sizeof(slot->url) - 1);
    strncpy(slot->label, label, sizeof(slot->label) - 1);
    pthread_mutex_unlock(&msm->lock);

    prep_arg_t *arg = (prep_arg_t *)calloc(1, sizeof(*arg));
    if (!arg) {
        pthread_mutex_lock(&msm->lock);
        slot->status = STREAM_FAILED;
        pthread_mutex_unlock(&msm->lock);
        return -1;
    }
    arg->msm        = msm;
    arg->slot_index = idx;
    strncpy(arg->url, url, sizeof(arg->url) - 1);

    pthread_t prep_tid;
    if (pthread_create(&prep_tid, NULL, prep_main, arg) != 0) {
        free(arg);
        pthread_mutex_lock(&msm->lock);
        slot->status = STREAM_FAILED;
        pthread_mutex_unlock(&msm->lock);
        return -1;
    }

    pthread_mutex_lock(&msm->lock);
    slot->prep_thread = prep_tid;
    pthread_mutex_unlock(&msm->lock);

    return idx;
}

int msm_remove_stream(multi_stream_manager_t *msm, int index) {
    if (!msm) return -1;
    if (index < 0 || index >= VAULT_MAX_STREAMS) return -1;

    pthread_mutex_lock(&msm->lock);
    stream_slot_t *slot = &msm->slots[index];
    if (!slot->active) {
        pthread_mutex_unlock(&msm->lock);
        return -1;
    }

    /* Set cancel_requested so the prep pthread (if still resolving) bails out
     * between blocking calls instead of marching on to ffmpeg + forwarder.
     * Snapshot the thread handles + pid under the lock. */
    slot->cancel_requested = 1;
    pthread_t prep_tid = slot->prep_thread;
    int       prep_joined = slot->prep_joined;
    pthread_mutex_unlock(&msm->lock);

    /* Join the prep pthread first. Worst case it's still inside yt-dlp; we
     * wait for that to finish (no clean way to interrupt the external child).
     * After this join returns, slot->forwarder_thread is in its final state:
     * either set (prep got far enough to spawn the forwarder), or 0 (prep
     * failed early or saw the cancel flag). */
    if (!prep_joined && prep_tid != 0) {
        pthread_join(prep_tid, NULL);
    }

    /* Now read the forwarder handle + pid under the lock — they're stable
     * because the only writer (prep) has exited. */
    pthread_mutex_lock(&msm->lock);
    slot->prep_joined = 1;
    pid_t      cap_pid    = slot->capture_pid;
    pthread_t  fwd_tid    = slot->forwarder_thread;
    int        fwd_joined = slot->forwarder_joined;
    pthread_mutex_unlock(&msm->lock);

    if (cap_pid > 0) {
        kill(cap_pid, SIGTERM);
    }
    if (!fwd_joined && fwd_tid != 0) {
        pthread_join(fwd_tid, NULL);
    }

    pthread_mutex_lock(&msm->lock);
    slot->forwarder_joined = 1;
    slot->active           = 0;
    slot->cancel_requested = 0;
    slot->capture_pid      = 0;
    slot->prep_thread      = 0;
    slot->forwarder_thread = 0;
    /* Leave url/label populated for the small window before a fresh
     * add_stream reuses the slot — get_statuses() looks at `active`. */
    pthread_mutex_unlock(&msm->lock);

    return 0;
}

int msm_update_stream(multi_stream_manager_t *msm, int index,
                      const char *label, const char *url) {
    if (!msm) return -1;
    if (index < 0 || index >= VAULT_MAX_STREAMS) return -1;
    pthread_mutex_lock(&msm->lock);
    stream_slot_t *slot = &msm->slots[index];
    if (!slot->active) {
        pthread_mutex_unlock(&msm->lock);
        return -1;
    }
    if (label) {
        memset(slot->label, 0, sizeof(slot->label));
        strncpy(slot->label, label, sizeof(slot->label) - 1);
    }
    if (url) {
        memset(slot->url, 0, sizeof(slot->url));
        strncpy(slot->url, url, sizeof(slot->url) - 1);
    }
    pthread_mutex_unlock(&msm->lock);
    return 0;
}

int msm_pick_random_frame(multi_stream_manager_t *msm, frame_t *out) {
    if (!msm || !out) return -1;

    /* Drain. We keep at most one (the newest) frame per stream index, freeing
     * the older ones — matches Rust's "by_stream...frames.pop()". */
    frame_t latest[VAULT_MAX_STREAMS];
    int     have[VAULT_MAX_STREAMS];
    memset(latest, 0, sizeof(latest));
    memset(have, 0, sizeof(have));

    int drained_any = 0;
    while (1) {
        int     drained_index = -1;
        frame_t drained_frame;
        memset(&drained_frame, 0, sizeof(drained_frame));
        if (ring_try_pop(&msm->ring, &drained_index, &drained_frame) != 0) break;
        drained_any = 1;

        if (drained_index < 0 || drained_index >= VAULT_MAX_STREAMS) {
            /* Should not happen, but defensively free. */
            free(drained_frame.data);
            continue;
        }

        /* Count the capture for the slot, even if we end up discarding the
         * frame because a newer one arrived from the same stream. */
        pthread_mutex_lock(&msm->lock);
        if (msm->slots[drained_index].active) {
            msm->slots[drained_index].frames_captured++;
        }
        pthread_mutex_unlock(&msm->lock);

        if (have[drained_index]) {
            /* Replace older with newer; free the older. */
            free(latest[drained_index].data);
        }
        latest[drained_index] = drained_frame;
        have[drained_index] = 1;
    }

    if (!drained_any) return -1;

    /* Collect indices that have a frame. */
    int  indices[VAULT_MAX_STREAMS];
    int  ncand = 0;
    for (int i = 0; i < VAULT_MAX_STREAMS; i++) {
        if (have[i]) indices[ncand++] = i;
    }
    if (ncand == 0) return -1;

    /*
     * Pick uniformly at random. rand() seeded once at first call. The cypher
     * itself does not derive from this pick — entropy_extractor hashes the
     * frame pixels — so a deterministic PRNG is fine here, matches the
     * unbiased semantics of Rust's rand::thread_rng().gen_range(...). For a
     * fully crypto-quality pick the existing OpenSSL RAND_bytes is one call
     * away; left as a follow-up if/when this becomes load-bearing.
     */
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        seeded = 1;
    }
    int chosen = (ncand == 1) ? indices[0] : indices[rand() % ncand];

    /* Transfer chosen to caller; free the rest. */
    for (int i = 0; i < VAULT_MAX_STREAMS; i++) {
        if (have[i] && i != chosen) free(latest[i].data);
    }
    *out = latest[chosen];
    return 0;
}

int msm_get_statuses(multi_stream_manager_t *msm, stream_status_t *out, int max) {
    if (!msm || !out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&msm->lock);
    for (int i = 0; i < VAULT_MAX_STREAMS && n < max; i++) {
        if (!msm->slots[i].active) continue;
        memset(&out[n], 0, sizeof(out[n]));
        memcpy(out[n].url, msm->slots[i].url, sizeof(out[n].url));
        memcpy(out[n].label, msm->slots[i].label, sizeof(out[n].label));
        out[n].status = msm->slots[i].status;
        out[n].frames_captured = msm->slots[i].frames_captured;
        n++;
    }
    pthread_mutex_unlock(&msm->lock);
    return n;
}

int msm_stream_count(multi_stream_manager_t *msm) {
    if (!msm) return 0;
    int n = 0;
    pthread_mutex_lock(&msm->lock);
    for (int i = 0; i < VAULT_MAX_STREAMS; i++) {
        if (msm->slots[i].active) n++;
    }
    pthread_mutex_unlock(&msm->lock);
    return n;
}

void msm_free(multi_stream_manager_t *msm) {
    if (!msm) return;

    /* Close the ring first — any forwarder blocked on ring_push wakes up
     * with -1 and exits. */
    ring_close(&msm->ring);

    /* Collect prep + forwarder tids for every active slot, mark them all
     * cancel_requested + SIGTERM the captures, then drop the lock so the
     * prep threads can transition through their cancel checks while we wait
     * to join. We join in two passes (prep first, then forwarder) so prep
     * has a chance to publish forwarder_thread before we read it. */
    pthread_t prep_to_join[VAULT_MAX_STREAMS];
    int       n_prep = 0;

    pthread_mutex_lock(&msm->lock);
    for (int i = 0; i < VAULT_MAX_STREAMS; i++) {
        stream_slot_t *s = &msm->slots[i];
        if (!s->active) continue;
        s->cancel_requested = 1;
        if (s->capture_pid > 0) {
            kill(s->capture_pid, SIGTERM);
        }
        if (!s->prep_joined && s->prep_thread != 0) {
            prep_to_join[n_prep++] = s->prep_thread;
            s->prep_joined = 1;
        }
    }
    pthread_mutex_unlock(&msm->lock);

    for (int i = 0; i < n_prep; i++) {
        pthread_join(prep_to_join[i], NULL);
    }

    /* Prep is fully retired now — forwarder_thread fields are stable. */
    pthread_t fwd_to_join[VAULT_MAX_STREAMS];
    int       n_fwd = 0;

    pthread_mutex_lock(&msm->lock);
    for (int i = 0; i < VAULT_MAX_STREAMS; i++) {
        stream_slot_t *s = &msm->slots[i];
        if (!s->active) continue;
        if (!s->forwarder_joined && s->forwarder_thread != 0) {
            fwd_to_join[n_fwd++] = s->forwarder_thread;
            s->forwarder_joined = 1;
        }
    }
    pthread_mutex_unlock(&msm->lock);

    for (int i = 0; i < n_fwd; i++) {
        pthread_join(fwd_to_join[i], NULL);
    }

    ring_free(&msm->ring);
    pthread_mutex_destroy(&msm->lock);
    free(msm);
}

/* ------------------------------------------------------------------------
 * Test-only seams (compiled only when -DENABLE_MSM_TEST_API is set; never
 * in the production binary).
 * ----------------------------------------------------------------------*/
#ifdef ENABLE_MSM_TEST_API
int msm_test_push_frame(multi_stream_manager_t *msm, int stream_index, frame_t *frame) {
    if (!msm || !frame) return -1;
    return ring_push(&msm->ring, stream_index, frame);
}

int msm_test_register_slot(multi_stream_manager_t *msm, const char *url, const char *label) {
    if (!msm || !url || !label) return -1;
    pthread_mutex_lock(&msm->lock);
    int idx = find_free_slot_locked(msm);
    if (idx < 0) {
        pthread_mutex_unlock(&msm->lock);
        return -1;
    }
    stream_slot_t *slot = &msm->slots[idx];
    memset(slot, 0, sizeof(*slot));
    slot->active = 1;
    slot->status = STREAM_ACTIVE;
    slot->prep_joined      = 1;  /* No real threads spawned in test mode. */
    slot->forwarder_joined = 1;
    strncpy(slot->url, url, sizeof(slot->url) - 1);
    strncpy(slot->label, label, sizeof(slot->label) - 1);
    pthread_mutex_unlock(&msm->lock);
    return idx;
}

size_t msm_test_ring_count(multi_stream_manager_t *msm) {
    if (!msm) return 0;
    pthread_mutex_lock(&msm->ring.lock);
    size_t n = msm->ring.count;
    pthread_mutex_unlock(&msm->ring.lock);
    return n;
}
#endif /* ENABLE_MSM_TEST_API */
