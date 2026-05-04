#ifndef FRAME_SAMPLER_H
#define FRAME_SAMPLER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* A single captured frame */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t *data;       /* raw RGB pixel bytes (caller must free) */
    size_t   data_len;
    uint64_t sequence;
} frame_t;

/* Opaque handle for the frame capture pipeline */
typedef struct frame_capture frame_capture_t;

/*
 * Start ffmpeg frame capture from stream_url.
 * Returns a capture handle, or NULL on error.
 * Frames can be read with frame_capture_read().
 */
frame_capture_t *frame_capture_start(const char *stream_url);

/*
 * Read the next frame. Blocks until a frame is available or EOF.
 * Returns 0 on success, -1 on error/EOF.
 * Caller must free frame->data when done.
 */
int frame_capture_read(frame_capture_t *cap, frame_t *frame);

/* Stop capture and free resources. */
void frame_capture_stop(frame_capture_t *cap);

/* Get the ffmpeg child PID for cleanup. */
pid_t frame_capture_pid(const frame_capture_t *cap);

#endif
