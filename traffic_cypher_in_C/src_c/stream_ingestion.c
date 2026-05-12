#include "stream_ingestion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

char *resolve_stream_url(const char *youtube_url) {
    /* Input validation: reject NULL, empty, control bytes, and non-http(s) URLs. */
    if (!youtube_url || youtube_url[0] == '\0') {
        fprintf(stderr, "[ERROR] resolve_stream_url: URL is NULL or empty\n");
        return NULL;
    }
    for (const unsigned char *p = (const unsigned char *)youtube_url; *p; ++p) {
        if (*p < 0x20) {
            fprintf(stderr, "[ERROR] resolve_stream_url: URL contains control byte\n");
            return NULL;
        }
    }
    if (strncmp(youtube_url, "http://", 7) != 0 &&
        strncmp(youtube_url, "https://", 8) != 0) {
        fprintf(stderr, "[ERROR] resolve_stream_url: URL must start with http:// or https://\n");
        return NULL;
    }

    /* Check for local ./yt-dlp first */
    const char *yt_dlp = "yt-dlp";
    struct stat st;
    if (stat("./yt-dlp", &st) == 0) {
        yt_dlp = "./yt-dlp";
        fprintf(stderr, "[INFO] Using local yt-dlp binary\n");
    } else {
        fprintf(stderr, "[WARN] Local yt-dlp not found, falling back to system PATH\n");
    }

    fprintf(stderr, "[INFO] Resolving stream URL with yt-dlp: %s\n", youtube_url);

    /* Fixed-position argv: shell never sees the URL, so injection is structurally impossible.
     * "--" stops yt-dlp from interpreting a URL that begins with '-' as an option. */
    char *argv[] = {
        (char *)yt_dlp,
        "-g",
        "-f",
        "best",
        "--no-warnings",
        "--",
        (char *)youtube_url,
        NULL
    };

    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) < 0) {
        fprintf(stderr, "[ERROR] pipe(out) failed: %s\n", strerror(errno));
        return NULL;
    }
    if (pipe(err_pipe) < 0) {
        fprintf(stderr, "[ERROR] pipe(err) failed: %s\n", strerror(errno));
        close(out_pipe[0]);
        close(out_pipe[1]);
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[ERROR] fork failed: %s\n", strerror(errno));
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return NULL;
    }

    if (pid == 0) {
        /* Child: wire write ends to stdout/stderr, close read ends, exec. */
        close(out_pipe[0]);
        close(err_pipe[0]);
        if (dup2(out_pipe[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(err_pipe[1], STDERR_FILENO) < 0) _exit(127);
        close(out_pipe[1]);
        close(err_pipe[1]);
        execvp(yt_dlp, argv);
        _exit(127);
    }

    /* Parent: close write ends, drain both pipes. */
    close(out_pipe[1]);
    close(err_pipe[1]);

    /* Growable stdout buffer. Using read() directly (not fread) because we own the fd
     * lifecycle, want partial reads to be handled explicitly, and avoid pulling in a
     * FILE* layer just to discard it. */
    size_t out_cap = 4096;
    size_t out_len = 0;
    char *out_buf = (char *)malloc(out_cap);
    if (!out_buf) {
        fprintf(stderr, "[ERROR] malloc failed for stdout buffer\n");
        close(out_pipe[0]);
        close(err_pipe[0]);
        int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return NULL;
    }

    for (;;) {
        if (out_len + 1 >= out_cap) {
            size_t new_cap = out_cap * 2;
            char *grown = (char *)realloc(out_buf, new_cap);
            if (!grown) {
                fprintf(stderr, "[ERROR] realloc failed for stdout buffer\n");
                free(out_buf);
                close(out_pipe[0]);
                close(err_pipe[0]);
                int status;
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
                return NULL;
            }
            out_buf = grown;
            out_cap = new_cap;
        }
        ssize_t n = read(out_pipe[0], out_buf + out_len, out_cap - out_len - 1);
        if (n > 0) {
            out_len += (size_t)n;
        } else if (n == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else {
            fprintf(stderr, "[ERROR] read(stdout) failed: %s\n", strerror(errno));
            free(out_buf);
            close(out_pipe[0]);
            close(err_pipe[0]);
            int status;
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return NULL;
        }
    }
    out_buf[out_len] = '\0';
    close(out_pipe[0]);

    /* Fixed 8192-byte stderr drain (truncate beyond that). */
    char err_buf[8192];
    size_t err_len = 0;
    for (;;) {
        if (err_len >= sizeof(err_buf) - 1) {
            /* Buffer full: drain remainder to /dev/null so child doesn't block. */
            char sink[1024];
            ssize_t n = read(err_pipe[0], sink, sizeof(sink));
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                break;
            }
            continue;
        }
        ssize_t n = read(err_pipe[0], err_buf + err_len, sizeof(err_buf) - 1 - err_len);
        if (n > 0) {
            err_len += (size_t)n;
        } else if (n == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    err_buf[err_len] = '\0';
    close(err_pipe[0]);

    /* Reap child with EINTR retry. */
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "[ERROR] waitpid failed: %s\n", strerror(errno));
            free(out_buf);
            return NULL;
        }
    }

    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        fprintf(stderr, "[ERROR] yt-dlp exited with error%s%s\n",
                err_len > 0 ? ": " : "",
                err_len > 0 ? err_buf : "");
        free(out_buf);
        return NULL;
    }

    if (out_len == 0) {
        free(out_buf);
        fprintf(stderr, "[ERROR] yt-dlp returned no output. Is the stream live?\n");
        return NULL;
    }

    /* Keep only the first line (yt-dlp -g may emit multiple URLs). */
    char *nl = strchr(out_buf, '\n');
    if (nl) *nl = '\0';

    /* Trim trailing whitespace */
    size_t len = strlen(out_buf);
    while (len > 0 && (out_buf[len-1] == '\n' || out_buf[len-1] == '\r' || out_buf[len-1] == ' ')) {
        out_buf[--len] = '\0';
    }

    if (len == 0) {
        free(out_buf);
        fprintf(stderr, "[ERROR] yt-dlp returned an empty URL. Is the stream live?\n");
        return NULL;
    }

    fprintf(stderr, "[INFO] Resolved direct stream URL (%zu chars)\n", len);
    return out_buf;
}
