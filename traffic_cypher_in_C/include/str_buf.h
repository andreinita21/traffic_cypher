#ifndef STR_BUF_H
#define STR_BUF_H

#include <stddef.h>
#include <stdarg.h>

/* A growing byte buffer. Doubling growth, sticky error flag.
   After any sb_* call returns nonzero (or sb->err is set), the buffer is in
   an error state; further appends are no-ops and the buffer is safe to free. */
typedef struct {
    char  *data;   /* NUL-terminated when len > 0 and !err */
    size_t len;    /* bytes excluding NUL */
    size_t cap;    /* allocated bytes (>= len + 1, or 0 before first reserve) */
    int    err;    /* 0 = ok, non-zero = OOM or invalid op */
} str_buf;

/* Initialize. initial_cap may be 0 — first append allocates a minimum of 64. */
void   sb_init(str_buf *sb, size_t initial_cap);

/* Append a C string. Returns 0 on ok, -1 on error (also sets sb->err). */
int    sb_append(str_buf *sb, const char *s);

/* Append the first n bytes of s. */
int    sb_append_n(str_buf *sb, const char *s, size_t n);

/* printf-style append. */
int    sb_appendf(str_buf *sb, const char *fmt, ...)
       __attribute__((format(printf, 2, 3)));

/* Append `raw` as a JSON-escaped string (does NOT include the surrounding
   quotes — caller wraps with sb_append("\"") + sb_append_json_escaped(...) +
   sb_append("\"") if they want a JSON string literal). Handles \" \\ \n \r
   \t and \uXXXX for bytes < 0x20. */
int    sb_append_json_escaped(str_buf *sb, const char *raw);

/* Release ownership of the heap buffer. *out_len = sb->len. Caller frees().
   Resets sb to a fresh state. Returns NULL on error (sb->err set). */
char  *sb_release(str_buf *sb, size_t *out_len);

/* Free without releasing. Idempotent. */
void   sb_free(str_buf *sb);

#endif
