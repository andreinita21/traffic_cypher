#ifndef STREAM_INGESTION_H
#define STREAM_INGESTION_H

/*
 * Resolve a YouTube livestream URL into a direct video stream URL using yt-dlp.
 * Returns a heap-allocated string (caller must free), or NULL on error.
 */
char *resolve_stream_url(const char *youtube_url);

#endif
