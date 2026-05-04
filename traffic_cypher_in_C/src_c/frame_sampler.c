#include "frame_sampler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

struct frame_capture {
    FILE   *fp;
    pid_t   pid;
    int     pipe_fd;
    uint64_t sequence;
};

frame_capture_t *frame_capture_start(const char *stream_url) {
    fprintf(stderr, "[INFO] Starting ffmpeg frame capture at 1 FPS\n");

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        /* Child: redirect stdout to pipe */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Redirect stderr to /dev/null for cleaner output */
        FILE *devnull = fopen("/dev/null", "w");
        if (devnull) {
            dup2(fileno(devnull), STDERR_FILENO);
            fclose(devnull);
        }

        execlp("ffmpeg", "ffmpeg",
            "-reconnect", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "5",
            "-i", stream_url,
            "-vf", "fps=1,scale=320:240",
            "-f", "image2pipe",
            "-vcodec", "ppm",
            "-an",
            "-loglevel", "error",
            "pipe:1",
            (char *)NULL);

        perror("execlp ffmpeg");
        _exit(127);
    }

    /* Parent */
    close(pipefd[1]);

    frame_capture_t *cap = (frame_capture_t *)calloc(1, sizeof(frame_capture_t));
    cap->pipe_fd = pipefd[0];
    cap->fp = fdopen(pipefd[0], "r");
    cap->pid = pid;
    cap->sequence = 0;

    if (!cap->fp) {
        perror("fdopen");
        close(pipefd[0]);
        free(cap);
        return NULL;
    }

    return cap;
}

/* Read exactly n bytes from file stream */
static int read_exact(FILE *fp, uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        size_t r = fread(buf + total, 1, n - total, fp);
        if (r == 0) return -1; /* EOF or error */
        total += r;
    }
    return 0;
}

int frame_capture_read(frame_capture_t *cap, frame_t *frame) {
    if (!cap || !cap->fp) return -1;

    /* Read PPM header: "P6\n<width> <height>\n<maxval>\n" */
    char header_line[256];

    /* Line 1: "P6" */
    if (!fgets(header_line, sizeof(header_line), cap->fp)) return -1;
    /* Skip comment lines */
    while (header_line[0] == '#') {
        if (!fgets(header_line, sizeof(header_line), cap->fp)) return -1;
    }
    if (strncmp(header_line, "P6", 2) != 0) return -1;

    /* Line 2: "<width> <height>" (may have comments before) */
    if (!fgets(header_line, sizeof(header_line), cap->fp)) return -1;
    while (header_line[0] == '#') {
        if (!fgets(header_line, sizeof(header_line), cap->fp)) return -1;
    }
    uint32_t w = 0, h = 0;
    if (sscanf(header_line, "%u %u", &w, &h) != 2) return -1;

    /* Line 3: maxval */
    if (!fgets(header_line, sizeof(header_line), cap->fp)) return -1;
    while (header_line[0] == '#') {
        if (!fgets(header_line, sizeof(header_line), cap->fp)) return -1;
    }

    /* Read pixel data */
    size_t pixel_bytes = (size_t)w * h * 3;
    uint8_t *data = (uint8_t *)malloc(pixel_bytes);
    if (!data) return -1;

    if (read_exact(cap->fp, data, pixel_bytes) < 0) {
        free(data);
        return -1;
    }

    cap->sequence++;
    frame->width = w;
    frame->height = h;
    frame->data = data;
    frame->data_len = pixel_bytes;
    frame->sequence = cap->sequence;

    return 0;
}

void frame_capture_stop(frame_capture_t *cap) {
    if (!cap) return;
    if (cap->fp) {
        fclose(cap->fp);
        cap->fp = NULL;
    }
    if (cap->pid > 0) {
        kill(cap->pid, SIGTERM);
    }
    free(cap);
}

pid_t frame_capture_pid(const frame_capture_t *cap) {
    return cap ? cap->pid : 0;
}
