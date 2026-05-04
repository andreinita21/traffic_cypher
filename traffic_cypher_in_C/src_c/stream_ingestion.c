#include "stream_ingestion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

char *resolve_stream_url(const char *youtube_url) {
    /* Check for local ./yt-dlp first */
    const char *yt_dlp = "yt-dlp";
    struct stat st;
    if (stat("./yt-dlp", &st) == 0) {
        yt_dlp = "./yt-dlp";
        fprintf(stderr, "[INFO] Using local yt-dlp binary\n");
    } else {
        fprintf(stderr, "[WARN] Local yt-dlp not found, falling back to system PATH\n");
    }

    /* Build command: yt-dlp -g -f best --no-warnings <url> */
    size_t cmd_len = strlen(yt_dlp) + strlen(youtube_url) + 64;
    char *cmd = (char *)malloc(cmd_len);
    snprintf(cmd, cmd_len, "%s -g -f best --no-warnings '%s' 2>/dev/null", yt_dlp, youtube_url);

    fprintf(stderr, "[INFO] Resolving stream URL with yt-dlp: %s\n", youtube_url);

    FILE *fp = popen(cmd, "r");
    free(cmd);
    if (!fp) {
        fprintf(stderr, "[ERROR] Failed to run yt-dlp. Is it installed?\n");
        return NULL;
    }

    char *url = (char *)malloc(4096);
    if (!fgets(url, 4096, fp)) {
        pclose(fp);
        free(url);
        fprintf(stderr, "[ERROR] yt-dlp returned no output. Is the stream live?\n");
        return NULL;
    }

    int status = pclose(fp);
    if (status != 0) {
        free(url);
        fprintf(stderr, "[ERROR] yt-dlp exited with error\n");
        return NULL;
    }

    /* Trim trailing whitespace */
    size_t len = strlen(url);
    while (len > 0 && (url[len-1] == '\n' || url[len-1] == '\r' || url[len-1] == ' ')) {
        url[--len] = '\0';
    }

    if (len == 0) {
        free(url);
        fprintf(stderr, "[ERROR] yt-dlp returned an empty URL. Is the stream live?\n");
        return NULL;
    }

    fprintf(stderr, "[INFO] Resolved direct stream URL (%zu chars)\n", len);
    return url;
}
