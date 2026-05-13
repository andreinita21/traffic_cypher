#ifndef MULTI_STREAM_H
#define MULTI_STREAM_H

/*
 * Multi-stream manager — C port of traffic_cypher_in_Rust/src/multi_stream.rs.
 *
 * Stage 1 of REMEDIATION_PLAN.md #1a: header + module + bounded MPSC ring +
 * per-stream forwarder pthread + statuses query. The web_server.c wiring and
 * the rotation_daemon rewrite (consumer side) land in follow-up commits — at
 * which point ENABLE_TRAFFIC_ENTROPY flips the build from #1b "honest relabel"
 * (OS entropy only, /api/build/info reports traffic_entropy:false) to the full
 * design from REMEDIATION_PLAN.md line 332.
 *
 * The module is *always* compiled into the production binary (the symbols
 * exist regardless of feature flag) so future wiring is a one-liner; the
 * feature flag only gates the rotation_daemon's choice of consumer.
 */

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "frame_sampler.h"
#include "vault.h"  /* VAULT_MAX_STREAMS, VAULT_FIELD_MAX, VAULT_LABEL_MAX */

typedef enum {
    STREAM_CONNECTING = 0,
    STREAM_ACTIVE     = 1,
    STREAM_FAILED     = 2,
    STREAM_STOPPED    = 3
} stream_state_t;

/* Snapshot of a single stream slot. Returned by msm_get_statuses(). */
typedef struct {
    char           url[VAULT_FIELD_MAX];
    char           label[VAULT_LABEL_MAX];
    stream_state_t status;
    uint64_t       frames_captured;
} stream_status_t;

typedef struct multi_stream_manager multi_stream_manager_t;

/*
 * Allocate a new manager with a shared bounded MPSC ring of `ring_capacity`
 * items. The Rust side uses `tokio::mpsc::channel(256)`; pass 256 to match.
 * Returns NULL on allocation failure or zero capacity.
 */
multi_stream_manager_t *msm_new(size_t ring_capacity);

/*
 * Stop every stream, join every forwarder thread, drain the ring, free
 * everything. Safe to call with NULL.
 */
void                    msm_free(multi_stream_manager_t *msm);

/*
 * Resolve `url` via stream_ingestion::resolve_stream_url(), start an ffmpeg
 * capture pipeline, spawn a forwarder pthread that pushes each captured frame
 * into the shared ring tagged with the slot index, and return the slot index.
 *
 * Blocks until URL resolution + ffmpeg start complete (Rust's add_stream is
 * `.await`; semantics match). The forwarder runs until either the stream is
 * removed, the capture pipe closes (ffmpeg died), or the ring is closed.
 *
 * Returns -1 on any error (no free slot, resolve failure, ffmpeg failed, etc.)
 * — the slot is marked STREAM_FAILED and remains in the list so the operator
 * can see the failed entry in get_statuses().
 */
int  msm_add_stream(multi_stream_manager_t *msm, const char *url, const char *label);

/*
 * Cancel the stream at slot `index`: SIGTERM the ffmpeg child (which closes
 * the read pipe and unblocks frame_capture_read), pthread_join the forwarder,
 * release the slot. Subsequent slots are NOT renumbered — the slot is marked
 * STOPPED and reused by the next add_stream that finds it.
 *
 * Returns 0 on success, -1 if `index` is out of range or the slot is empty.
 */
int  msm_remove_stream(multi_stream_manager_t *msm, int index);

/*
 * Update label/url metadata for a slot. Does NOT restart capture (matches
 * Rust's update_stream).
 *   - Pass NULL for `label` or `url` to leave that field unchanged.
 * Returns 0 on success, -1 on out-of-range / empty slot.
 */
int  msm_update_stream(multi_stream_manager_t *msm, int index,
                       const char *label, const char *url);

/*
 * Non-blocking: drain every available (stream_index, frame_t) tuple from the
 * shared ring, group by stream_index, pick one stream_index uniformly at
 * random, return the most recent frame from that stream. Frames from the
 * other drained streams are released. Returns 0 and fills *out on success;
 * returns -1 if no frames were available. Caller owns out->data on success.
 *
 * NB: this is the consumer the rewritten rotation_daemon will call once a
 * second. It mirrors Rust's pick_random_frame() at multi_stream.rs:217.
 */
int  msm_pick_random_frame(multi_stream_manager_t *msm, frame_t *out);

/*
 * Fill `out` with up to `max` stream_status_t entries, in slot order. Returns
 * the number written. Idempotent and read-only modulo a brief lock.
 */
int  msm_get_statuses(multi_stream_manager_t *msm, stream_status_t *out, int max);

/* Number of slots currently in use (CONNECTING/ACTIVE/FAILED/STOPPED). */
int  msm_stream_count(multi_stream_manager_t *msm);

#ifdef ENABLE_MSM_TEST_API
/*
 * Test-only seams. Compiled into msm_test (Makefile target) but never into
 * the production binary. Mirror of the ENABLE_FUZZ_API pattern in vault.c.
 *
 *   msm_test_push_frame:    enqueue (slot_index, frame) without going
 *                            through the real forwarder. The frame is moved
 *                            into the ring — caller transfers ownership of
 *                            frame->data.
 *   msm_test_register_slot: register a fake slot WITHOUT resolving a URL or
 *                            starting ffmpeg. Returns slot index.
 *   msm_test_ring_count:    current item count in the shared ring.
 */
int    msm_test_push_frame(multi_stream_manager_t *msm, int stream_index, frame_t *frame);
int    msm_test_register_slot(multi_stream_manager_t *msm, const char *url, const char *label);
size_t msm_test_ring_count(multi_stream_manager_t *msm);
#endif

#endif /* MULTI_STREAM_H */
