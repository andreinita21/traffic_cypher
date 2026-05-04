#ifndef ENTROPY_EXTRACTOR_H
#define ENTROPY_EXTRACTOR_H

#include <stddef.h>
#include <stdint.h>

/* Metrics about frame-to-frame visual variation */
typedef struct {
    double changed_pixel_ratio; /* 0.0 to 1.0 */
    double mean_pixel_delta;
    int    has_metrics;         /* 1 if metrics are valid */
} entropy_metrics_t;

/* Result of extracting entropy from a frame */
typedef struct {
    uint8_t         *entropy_bytes;
    size_t           entropy_len;
    entropy_metrics_t metrics;
} extracted_entropy_t;

/*
 * Extract entropy from a frame's raw RGB pixel data.
 * Caller must free result.entropy_bytes.
 *
 *   current_data:  raw RGB pixels
 *   current_len:   byte count
 *   previous_data: previous frame (NULL if first)
 *   previous_len:  byte count of previous
 *   width, height: frame dimensions
 */
extracted_entropy_t extract_entropy(const uint8_t *current_data, size_t current_len,
                                    const uint8_t *previous_data, size_t previous_len,
                                    uint32_t width, uint32_t height);

#endif
