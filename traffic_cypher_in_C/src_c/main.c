/*
 * Traffic Cypher CLI — Derive cryptographic keys from live traffic stream entropy
 *
 * Usage: traffic-cypher -u <youtube_url> [-f hex|base64] [-k <key_length>]
 *                       [--debug-frames] [--show-metrics]
 */

#include "crypto_derivation.h"
#include "entropy_extractor.h"
#include "entropy_pool.h"
#include "frame_sampler.h"
#include "stream_ingestion.h"
#include "system_entropy_mixer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void print_banner(void) {
    printf("\n"
        "+==========================================================+\n"
        "|                                                          |\n"
        "|     T R A F F I C   C Y P H E R                         |\n"
        "|                                                          |\n"
        "|   Turning live city motion into rotating crypto keys     |\n"
        "|                                                          |\n"
        "+==========================================================+\n"
        "\n");
}

static void save_debug_frame(const frame_t *frame) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./debug_frames/frame_%06llu.ppm",
             (unsigned long long)frame->sequence);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Failed to save debug frame %s\n", filename);
        return;
    }
    fprintf(fp, "P6\n%u %u\n255\n", frame->width, frame->height);
    fwrite(frame->data, 1, frame->data_len, fp);
    fclose(fp);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -u <url> [options]\n"
        "  -u, --url <url>           YouTube livestream URL\n"
        "  -f, --format <hex|base64> Output format (default: hex)\n"
        "  -k, --key-length <N>      Key length in bytes (default: 32)\n"
        "  --debug-frames            Save sampled frames to ./debug_frames/\n"
        "  --show-metrics            Show entropy variability metrics\n"
        "  -h, --help                Show this help\n",
        prog);
}

int main(int argc, char **argv) {
    const char *url = NULL;
    const char *format = "hex";
    int key_length = 32;
    int debug_frames = 0;
    int show_metrics = 0;

    static struct option long_options[] = {
        {"url",           required_argument, 0, 'u'},
        {"format",        required_argument, 0, 'f'},
        {"key-length",    required_argument, 0, 'k'},
        {"debug-frames",  no_argument,       0, 'd'},
        {"show-metrics",  no_argument,       0, 'm'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:f:k:dmh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u': url = optarg; break;
            case 'f': format = optarg; break;
            case 'k': key_length = atoi(optarg); break;
            case 'd': debug_frames = 1; break;
            case 'm': show_metrics = 1; break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!url) {
        fprintf(stderr, "Error: --url is required\n");
        print_usage(argv[0]);
        return 1;
    }

    print_banner();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (debug_frames) {
        mkdir("./debug_frames", 0755);
        fprintf(stderr, "[INFO] Debug frames will be saved to ./debug_frames/\n");
    }

    /* Step 1: Resolve the YouTube livestream URL */
    fprintf(stderr, "[INFO] Resolving livestream URL...\n");
    char *stream_url = resolve_stream_url(url);
    if (!stream_url) {
        fprintf(stderr, "[ERROR] Failed to resolve stream URL\n");
        return 1;
    }

    /* Step 2: Start frame capture */
    frame_capture_t *cap = frame_capture_start(stream_url);
    free(stream_url);
    if (!cap) {
        fprintf(stderr, "[ERROR] Failed to start frame capture\n");
        return 1;
    }

    fprintf(stderr, "[INFO] Pipeline started — generating keys every second\n");
    fprintf(stderr, "[INFO] Press Ctrl+C to stop\n\n");

    /* Step 3: Main processing loop */
    entropy_pool_t pool;
    entropy_pool_init(&pool, 8);

    uint8_t *previous_frame_data = NULL;
    size_t previous_frame_len = 0;
    uint8_t previous_key[256];
    int has_previous_key = 0;
    uint64_t frame_count = 0;

    while (g_running) {
        frame_t frame;
        if (frame_capture_read(cap, &frame) != 0) {
            fprintf(stderr, "[WARN] Frame stream ended\n");
            break;
        }

        /* Extract entropy */
        extracted_entropy_t extracted = extract_entropy(
            frame.data, frame.data_len,
            previous_frame_data, previous_frame_len,
            frame.width, frame.height);

        /* Print metrics if requested */
        if (show_metrics && extracted.metrics.has_metrics) {
            fprintf(stderr, "  Metrics: changed=%.1f%%, mean_delta=%.2f\n",
                    extracted.metrics.changed_pixel_ratio * 100.0,
                    extracted.metrics.mean_pixel_delta);
        }

        /* Feed into entropy pool */
        entropy_pool_push(&pool, extracted.entropy_bytes, extracted.entropy_len);
        /* Note: pool takes ownership of entropy_bytes */

        uint8_t pool_digest[32];
        entropy_pool_digest(&pool, pool_digest);

        /* Mix with system entropy */
        uint8_t mixed_seed[32];
        mix_entropy(pool_digest, mixed_seed);

        /* Derive key */
        uint8_t key[256];
        derive_key(mixed_seed,
                   has_previous_key ? previous_key : NULL,
                   has_previous_key ? (size_t)key_length : 0,
                   (size_t)key_length, key);

        /* Format output */
        char formatted[1024];
        if (strcmp(format, "base64") == 0) {
            format_base64(key, (size_t)key_length, formatted);
        } else {
            format_hex(key, (size_t)key_length, formatted);
        }

        /* Timestamp */
        uint64_t timestamp = (uint64_t)time(NULL);

        printf("[%llu] Frame #%4llu | Pool depth: %zu | Key: %s\n",
               (unsigned long long)timestamp,
               (unsigned long long)frame.sequence,
               entropy_pool_len(&pool),
               formatted);
        fflush(stdout);

        /* Save debug frame if requested */
        if (debug_frames) {
            save_debug_frame(&frame);
        }

        /* Update state */
        free(previous_frame_data);
        previous_frame_data = frame.data;
        previous_frame_len = frame.data_len;
        memcpy(previous_key, key, (size_t)key_length);
        has_previous_key = 1;
        frame_count++;
    }

    /* Cleanup */
    printf("\n");
    fprintf(stderr, "[INFO] Shutting down gracefully...\n");
    frame_capture_stop(cap);
    entropy_pool_free(&pool);
    free(previous_frame_data);
    fprintf(stderr, "[INFO] Goodbye! Generated keys from %llu frames.\n",
            (unsigned long long)frame_count);

    return 0;
}
