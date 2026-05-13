#include "key_rotation.h"
#include "crypto_derivation.h"
#include "system_entropy_mixer.h"
#include "entropy_pool.h"
#include "entropy_extractor.h"
#include "multi_stream.h"
#include "frame_sampler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>

/*
 * Entropy collection daemon.
 *
 * Mirrors traffic_cypher_in_Rust/src/key_rotation.rs::start_rotation_daemon:
 * once per second, attempt to pick a frame from the multi-stream manager.
 *
 *   - If a frame is obtained, extract entropy from the pixel data (full-frame
 *     SHA-256 + delta-from-previous + 8x8 block hashes), push into the rolling
 *     pool, mix with OS entropy, derive the next chained key, and mark
 *     has_traffic_entropy=1.
 *   - Otherwise, fall back to RAND_bytes-only (matches the previous daemon's
 *     behaviour). has_traffic_entropy is NOT cleared once set, matching the
 *     Rust daemon's monotonic semantics.
 *
 * The msm pointer is captured once at daemon start. NULL is tolerated — the
 * fallback path is identical to the pre-#1a behaviour, so a non-existent or
 * empty stream manager keeps the C build OS-only with zero surprises.
 */
void *rotation_daemon(void *arg) {
    app_state_t *state = (app_state_t *)arg;

    fprintf(stderr, "[INFO] Entropy collection daemon starting\n");

    pthread_mutex_lock(&state->lock);
    state->rotation_running = 1;
    multi_stream_manager_t *msm = state->msm;
    pthread_mutex_unlock(&state->lock);

    entropy_pool_t pool;
    entropy_pool_init(&pool, 8);

    uint8_t  previous_key[32];
    int      has_previous = 0;
    uint8_t *previous_frame_data = NULL;
    size_t   previous_frame_data_len = 0;
    uint64_t epoch = 0;

    while (1) {
        sleep(1);

        pthread_mutex_lock(&state->lock);
        if (state->rotation_stop) {
            pthread_mutex_unlock(&state->lock);
            break;
        }
        pthread_mutex_unlock(&state->lock);

        frame_t frame;
        memset(&frame, 0, sizeof(frame));
        int got_frame = (msm && msm_pick_random_frame(msm, &frame) == 0);

        uint8_t new_key[32];

        if (got_frame) {
            /* Traffic path: full per-Rust entropy pipeline. */
            extracted_entropy_t extracted = extract_entropy(
                frame.data, frame.data_len,
                previous_frame_data, previous_frame_data_len,
                frame.width, frame.height);

            /* Pool takes ownership of extracted.entropy_bytes. */
            entropy_pool_push(&pool, extracted.entropy_bytes, extracted.entropy_len);

            uint8_t pool_digest[32];
            entropy_pool_digest(&pool, pool_digest);

            uint8_t mixed[32];
            mix_entropy(pool_digest, mixed);

            derive_key(mixed,
                       has_previous ? previous_key : NULL,
                       has_previous ? 32 : 0,
                       32, new_key);

            /* Rotate previous_frame_data — current frame's pixels become the
             * delta basis for the next tick. */
            free(previous_frame_data);
            previous_frame_data     = frame.data;
            previous_frame_data_len = frame.data_len;
            frame.data = NULL;  /* ownership transferred */
        } else {
            /* OS-entropy-only fallback. Identical to the pre-#1a daemon. */
            uint8_t os_seed[32];
            RAND_bytes(os_seed, 32);

            uint8_t mixed[32];
            mix_entropy(os_seed, mixed);

            derive_key(mixed,
                       has_previous ? previous_key : NULL,
                       has_previous ? 32 : 0,
                       32, new_key);
        }

        epoch++;
        memcpy(previous_key, new_key, 32);
        has_previous = 1;

        /* Also keep a copy of the chained key in the pool so the pool digest
         * cascades across ticks even when no frames are flowing (matches the
         * previous daemon's "pool_data = memcpy(new_key)" pattern). */
        uint8_t *pool_chain = (uint8_t *)malloc(32);
        if (pool_chain) {
            memcpy(pool_chain, new_key, 32);
            entropy_pool_push(&pool, pool_chain, 32);
        }

        pthread_mutex_lock(&state->lock);
        memcpy(state->latest_entropy, new_key, 32);
        state->key_epoch = epoch;
        state->pool_depth = entropy_pool_len(&pool);
        if (got_frame) {
            state->frames_processed++;
            /* Monotonic once set, matching Rust at key_rotation.rs:138. */
            state->has_traffic_entropy = 1;
        }
        pthread_mutex_unlock(&state->lock);
    }

    free(previous_frame_data);

    pthread_mutex_lock(&state->lock);
    state->rotation_running = 0;
    pthread_mutex_unlock(&state->lock);

    entropy_pool_free(&pool);
    fprintf(stderr, "[INFO] Entropy collection daemon stopped at epoch %llu\n",
            (unsigned long long)epoch);
    return NULL;
}
