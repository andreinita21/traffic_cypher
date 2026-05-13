/*
 * Unit test for src_c/multi_stream.c. Exercises the bounded MPSC ring and the
 * pick_random_frame / get_statuses paths *without* spawning ffmpeg or
 * resolving live URLs, via the ENABLE_MSM_TEST_API seams.
 *
 * Build:   make -C traffic_cypher_in_C msm_test
 * Run:     ./traffic_cypher_in_C/msm_test
 * CI:      tests/29_multi_stream_unit.sh wires both.
 */

/* ENABLE_MSM_TEST_API is set by the Makefile target. */
#include "multi_stream.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fails = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, (msg)); \
        g_fails++; \
    } else { \
        fprintf(stdout, "  PASS: %s\n", (msg)); \
    } \
} while (0)

/* Synthesize a frame_t whose data is N bytes of `b`. Caller owns frame.data
 * until it's pushed (the ring takes ownership), or until pick returns it. */
static frame_t make_frame(size_t n, uint8_t b, uint64_t seq) {
    frame_t f;
    memset(&f, 0, sizeof(f));
    f.width = 1;
    f.height = (uint32_t)n;
    f.data = (uint8_t *)malloc(n ? n : 1);
    f.data_len = n;
    f.sequence = seq;
    memset(f.data, b, n);
    return f;
}

/* ------------------------------------------------------------------------
 * Test 1: msm_new / msm_free smoke
 * ----------------------------------------------------------------------*/
static void t_new_free(void) {
    fprintf(stdout, "==> t_new_free\n");
    multi_stream_manager_t *m = msm_new(8);
    CHECK(m != NULL, "msm_new(8) returns non-NULL");
    CHECK(msm_stream_count(m) == 0, "fresh manager has zero streams");
    CHECK(msm_test_ring_count(m) == 0, "fresh ring is empty");
    msm_free(m);
    /* Free + NULL should be safe. */
    msm_free(NULL);
}

/* ------------------------------------------------------------------------
 * Test 2: msm_new rejects zero capacity
 * ----------------------------------------------------------------------*/
static void t_zero_capacity(void) {
    fprintf(stdout, "==> t_zero_capacity\n");
    CHECK(msm_new(0) == NULL, "msm_new(0) returns NULL");
}

/* ------------------------------------------------------------------------
 * Test 3: ring push/pop ordering + count
 * ----------------------------------------------------------------------*/
static void t_ring_fifo(void) {
    fprintf(stdout, "==> t_ring_fifo\n");
    multi_stream_manager_t *m = msm_new(4);
    CHECK(m != NULL, "msm_new(4)");

    /* Register one slot so the frame counter updates. */
    int idx = msm_test_register_slot(m, "http://x.example/a", "a");
    CHECK(idx == 0, "register slot 0");

    /* Push three frames into the same slot. */
    for (int i = 0; i < 3; i++) {
        frame_t f = make_frame(8, (uint8_t)('A' + i), (uint64_t)i + 1);
        CHECK(msm_test_push_frame(m, idx, &f) == 0, "push succeeds");
    }
    CHECK(msm_test_ring_count(m) == 3, "ring count == 3 after three pushes");

    /* Pick drains everything and returns the latest from the single stream. */
    frame_t out;
    memset(&out, 0, sizeof(out));
    CHECK(msm_pick_random_frame(m, &out) == 0, "pick succeeds when frames present");
    CHECK(out.data != NULL, "picked frame has data");
    CHECK(out.data[0] == 'C', "picked frame is the *latest* of three pushes");
    CHECK(out.sequence == 3, "picked frame sequence == 3");
    free(out.data);

    /* After pick, ring is drained. */
    CHECK(msm_test_ring_count(m) == 0, "ring drained after pick");
    CHECK(msm_pick_random_frame(m, &out) == -1, "pick on empty ring returns -1");

    /* Counter saw all three frames flow through. */
    stream_status_t statuses[VAULT_MAX_STREAMS];
    int n = msm_get_statuses(m, statuses, VAULT_MAX_STREAMS);
    CHECK(n == 1, "get_statuses returns 1");
    CHECK(statuses[0].frames_captured == 3, "frames_captured == 3");

    msm_free(m);
}

/* ------------------------------------------------------------------------
 * Test 4: multi-slot, pick chooses *some* slot, frees the rest
 * ----------------------------------------------------------------------*/
static void t_multi_slot_pick(void) {
    fprintf(stdout, "==> t_multi_slot_pick\n");
    multi_stream_manager_t *m = msm_new(16);
    int a = msm_test_register_slot(m, "u-a", "label-a");
    int b = msm_test_register_slot(m, "u-b", "label-b");
    int c = msm_test_register_slot(m, "u-c", "label-c");
    CHECK(a == 0 && b == 1 && c == 2, "three slots register in order");

    /* Push one frame per slot. */
    frame_t fa = make_frame(4, 'a', 1);
    frame_t fb = make_frame(4, 'b', 1);
    frame_t fc = make_frame(4, 'c', 1);
    msm_test_push_frame(m, a, &fa);
    msm_test_push_frame(m, b, &fb);
    msm_test_push_frame(m, c, &fc);

    frame_t out;
    memset(&out, 0, sizeof(out));
    CHECK(msm_pick_random_frame(m, &out) == 0, "pick succeeds across three slots");
    CHECK(out.data != NULL, "picked frame has data");
    int marker = out.data[0];
    CHECK(marker == 'a' || marker == 'b' || marker == 'c',
          "picked frame came from one of the three slots");
    free(out.data);
    CHECK(msm_test_ring_count(m) == 0, "all three frames were drained");

    /* All three slots counted one frame even though only one was returned. */
    stream_status_t s[VAULT_MAX_STREAMS];
    int n = msm_get_statuses(m, s, VAULT_MAX_STREAMS);
    CHECK(n == 3, "three slots in statuses");
    int sum = 0;
    for (int i = 0; i < n; i++) sum += (int)s[i].frames_captured;
    CHECK(sum == 3, "each of the three slots saw one frame counted");

    msm_free(m);
}

/* ------------------------------------------------------------------------
 * Test 5: bounded ring blocks producer; close wakes it
 * ----------------------------------------------------------------------*/
typedef struct {
    multi_stream_manager_t *m;
    int                    slot;
    int                    n_pushed;
    int                    last_push_rc;
} producer_ctx_t;

static void *producer_thread(void *arg) {
    producer_ctx_t *p = (producer_ctx_t *)arg;
    for (int i = 0; i < 10; i++) {
        frame_t f = make_frame(2, (uint8_t)i, (uint64_t)i);
        int rc = msm_test_push_frame(p->m, p->slot, &f);
        p->last_push_rc = rc;
        if (rc != 0) {
            /* ring is closing — free the data we owned. */
            free(f.data);
            break;
        }
        p->n_pushed++;
    }
    return NULL;
}

static void t_backpressure_and_close(void) {
    fprintf(stdout, "==> t_backpressure_and_close\n");
    multi_stream_manager_t *m = msm_new(3);  /* tiny ring */
    int s = msm_test_register_slot(m, "u", "l");

    producer_ctx_t p = { m, s, 0, 0 };
    pthread_t tid;
    pthread_create(&tid, NULL, producer_thread, &p);

    /* Give producer time to fill the ring and block on push #4. */
    usleep(50 * 1000);
    CHECK(p.n_pushed == 3, "producer pushed exactly 3 frames before blocking");
    CHECK(msm_test_ring_count(m) == 3, "ring is at capacity");

    /* msm_free closes the ring, which should unblock the producer. */
    msm_free(m);
    pthread_join(tid, NULL);
    CHECK(p.last_push_rc == -1, "blocked push returned -1 after ring closed");
}

int main(void) {
    fprintf(stdout, "msm_test: multi_stream unit suite\n\n");

    t_new_free();
    t_zero_capacity();
    t_ring_fifo();
    t_multi_slot_pick();
    t_backpressure_and_close();

    fprintf(stdout, "\n");
    if (g_fails == 0) {
        fprintf(stdout, "msm_test: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "msm_test: %d FAILURES\n", g_fails);
    return 1;
}
