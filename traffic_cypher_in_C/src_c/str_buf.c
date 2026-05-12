/* str_buf.c — growing byte buffer with sticky error flag.
 *
 * Design notes:
 *   - Doubling growth: cap = max(cap * 2, len + need + 1, 64).
 *   - Sticky error: once sb->err is set, all sb_* calls become no-ops returning
 *     -1. Callers can chain many appends and check sb->err once at the end.
 *   - On allocation failure, the heap buffer is freed and sb->data is reset to
 *     NULL so the struct is safe to sb_free() again.
 */

#include "str_buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SB_MIN_CAP 64

/* Ensure sb->cap is at least `need_total` bytes (len + new + NUL is the
 * caller's responsibility). Returns 0 on ok, -1 on error (sets sb->err). */
int sb_reserve(str_buf *sb, size_t need_total)
{
    if (sb->err) {
        return -1;
    }
    if (sb->cap >= need_total) {
        return 0;
    }

    size_t new_cap = sb->cap ? sb->cap : SB_MIN_CAP;
    while (new_cap < need_total) {
        /* Guard against size_t overflow on doubling. */
        if (new_cap > ((size_t)-1) / 2) {
            new_cap = need_total;
            break;
        }
        new_cap *= 2;
    }
    if (new_cap < SB_MIN_CAP) {
        new_cap = SB_MIN_CAP;
    }

    char *p = (char *)realloc(sb->data, new_cap);
    if (!p) {
        free(sb->data);
        sb->data = NULL;
        sb->len  = 0;
        sb->cap  = 0;
        sb->err  = 1;
        return -1;
    }
    sb->data = p;
    sb->cap  = new_cap;
    return 0;
}

void sb_init(str_buf *sb, size_t initial_cap)
{
    sb->data = NULL;
    sb->len  = 0;
    sb->cap  = 0;
    sb->err  = 0;
    if (initial_cap > 0) {
        (void)sb_reserve(sb, initial_cap);
    }
}

void sb_advance(str_buf *sb, size_t n)
{
    if (sb->err || n == 0) {
        return;
    }
    /* Caller is responsible for having reserved len + n + 1; if not, mark err. */
    if (sb->cap < sb->len + n + 1) {
        sb->err = 1;
        return;
    }
    sb->len += n;
    sb->data[sb->len] = '\0';
}

int sb_append_n(str_buf *sb, const char *s, size_t n)
{
    if (sb->err) {
        return -1;
    }
    if (n == 0) {
        /* Still NUL-terminate if we have a buffer, but don't force allocation. */
        if (sb->cap > 0 && sb->data) {
            sb->data[sb->len] = '\0';
        }
        return 0;
    }
    /* Overflow guard: len + n + 1 must not wrap. */
    if (n > ((size_t)-1) - sb->len - 1) {
        sb->err = 1;
        free(sb->data);
        sb->data = NULL;
        sb->len  = 0;
        sb->cap  = 0;
        return -1;
    }
    if (sb_reserve(sb, sb->len + n + 1) != 0) {
        return -1;
    }
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
    return 0;
}

int sb_append(str_buf *sb, const char *s)
{
    if (sb->err) {
        return -1;
    }
    return sb_append_n(sb, s, strlen(s));
}

int sb_appendf(str_buf *sb, const char *fmt, ...)
{
    if (sb->err) {
        return -1;
    }

    char scratch[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);

    if (n < 0) {
        sb->err = 1;
        return -1;
    }

    if ((size_t)n < sizeof(scratch)) {
        /* Fit in scratch; just append. */
        return sb_append_n(sb, scratch, (size_t)n);
    }

    /* Overflowed scratch: grow and vsnprintf directly into the buffer. */
    size_t need = (size_t)n;
    if (need > ((size_t)-1) - sb->len - 1) {
        sb->err = 1;
        free(sb->data);
        sb->data = NULL;
        sb->len  = 0;
        sb->cap  = 0;
        return -1;
    }
    if (sb_reserve(sb, sb->len + need + 1) != 0) {
        return -1;
    }

    va_start(ap, fmt);
    int n2 = vsnprintf(sb->data + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    if (n2 < 0 || (size_t)n2 != need) {
        sb->err = 1;
        return -1;
    }
    sb->len += (size_t)n2;
    /* vsnprintf already wrote the NUL. */
    return 0;
}

int sb_append_json_escaped(str_buf *sb, const char *raw)
{
    if (sb->err) {
        return -1;
    }
    if (!raw) {
        return 0;
    }

    /* Process byte by byte. Coalesce passthrough runs into a single
     * sb_append_n() to keep this cheap. */
    const unsigned char *p = (const unsigned char *)raw;
    const unsigned char *run = p;

    while (*p) {
        unsigned char c = *p;
        const char *esc = NULL;
        char u_buf[7]; /* "\u00XX" + NUL */

        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default:
                if (c < 0x20) {
                    snprintf(u_buf, sizeof(u_buf), "\\u00%02x", c);
                    esc = u_buf;
                }
                break;
        }

        if (esc) {
            if (p > run) {
                if (sb_append_n(sb, (const char *)run, (size_t)(p - run)) != 0) {
                    return -1;
                }
            }
            if (sb_append(sb, esc) != 0) {
                return -1;
            }
            ++p;
            run = p;
        } else {
            ++p;
        }
    }

    if (p > run) {
        if (sb_append_n(sb, (const char *)run, (size_t)(p - run)) != 0) {
            return -1;
        }
    }
    return 0;
}

char *sb_release(str_buf *sb, size_t *out_len)
{
    if (sb->err) {
        if (out_len) {
            *out_len = 0;
        }
        /* Defensive: ensure no dangling pointer is held. */
        free(sb->data);
        sb->data = NULL;
        sb->len  = 0;
        sb->cap  = 0;
        return NULL;
    }

    char *ret = sb->data;
    if (out_len) {
        *out_len = sb->len;
    }

    /* If nothing was ever appended, return NULL (documented). */
    if (!ret) {
        sb->len = 0;
        sb->cap = 0;
        sb->err = 0;
        return NULL;
    }

    /* Guarantee NUL-termination of released buffer. sb_append_n maintains
     * this invariant on every successful append, but a 0-length release of
     * a reserved-only buffer still needs the NUL. */
    if (sb->cap > sb->len) {
        ret[sb->len] = '\0';
    }

    sb->data = NULL;
    sb->len  = 0;
    sb->cap  = 0;
    sb->err  = 0;
    return ret;
}

void sb_free(str_buf *sb)
{
    if (!sb) {
        return;
    }
    free(sb->data);
    sb->data = NULL;
    sb->len  = 0;
    sb->cap  = 0;
    sb->err  = 0;
}
