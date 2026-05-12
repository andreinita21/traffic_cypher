/* test_str_buf.c — self-contained unit test for str_buf.
 * Sticky-error simulation: manually set sb.err = 1 (no need for a real OOM,
 * which is flaky under overcommit). Exercises the same path callers see. */
#include "str_buf.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    /* 1. Empty init -> release returns NULL (documented). */
    {
        str_buf sb; sb_init(&sb, 0);
        size_t n = 999;
        char *p = sb_release(&sb, &n);
        assert(p == NULL && n == 0);
        sb_free(&sb);
    }

    /* 2. Single append. */
    {
        str_buf sb; sb_init(&sb, 0);
        assert(sb_append(&sb, "hello") == 0);
        assert(sb.len == 5 && strcmp(sb.data, "hello") == 0);
        sb_free(&sb);
    }

    /* 3. Many appends grow correctly: 1000 x "x". */
    {
        str_buf sb; sb_init(&sb, 0);
        for (int i = 0; i < 1000; ++i) assert(sb_append_n(&sb, "x", 1) == 0);
        assert(sb.len == 1000 && sb.data[1000] == '\0');
        for (int i = 0; i < 1000; ++i) assert(sb.data[i] == 'x');
        sb_free(&sb);
    }

    /* 4. sb_appendf: number, multiple args, and long format that overflows scratch. */
    {
        str_buf sb; sb_init(&sb, 0);
        assert(sb_appendf(&sb, "n=%d", 42) == 0);
        assert(sb_appendf(&sb, " %s=%d", "k", 7) == 0);
        assert(strcmp(sb.data, "n=42 k=7") == 0);
        str_buf big; sb_init(&big, 0);
        assert(sb_appendf(&big, "%0500d", 1) == 0);
        assert(big.len == 500 && big.data[500] == '\0');
        sb_free(&sb); sb_free(&big);
    }

    /* 5. sb_append_json_escaped. */
    {
        struct { const char *in, *want; } cases[] = {
            { "hello", "hello" }, { "\"", "\\\"" }, { "\\", "\\\\" },
            { "\n", "\\n" }, { "\r", "\\r" }, { "\t", "\\t" },
            { "\x01", "\\u0001" },
            { "a\"b\\c\nd\re\tf\x01g", "a\\\"b\\\\c\\nd\\re\\tf\\u0001g" },
        };
        for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
            str_buf sb; sb_init(&sb, 0);
            assert(sb_append_json_escaped(&sb, cases[i].in) == 0);
            assert(strcmp(sb.data ? sb.data : "", cases[i].want) == 0);
            sb_free(&sb);
        }
    }

    /* 6. Sticky error: setting err makes subsequent ops no-ops returning -1. */
    {
        str_buf sb; sb_init(&sb, 0);
        assert(sb_append(&sb, "before") == 0);
        sb.err = 1;
        assert(sb_append(&sb, "after") == -1);
        assert(sb_append_n(&sb, "after", 5) == -1);
        assert(sb_appendf(&sb, "%d", 1) == -1);
        assert(sb_append_json_escaped(&sb, "x") == -1);
        size_t n = 1234;
        assert(sb_release(&sb, &n) == NULL && n == 0);
        sb_free(&sb);
    }

    /* 7. Release: NUL-terminated, correct out_len, sb reusable after release. */
    {
        str_buf sb; sb_init(&sb, 0);
        assert(sb_append(&sb, "abc") == 0);
        size_t n = 0;
        char *p = sb_release(&sb, &n);
        assert(p && n == 3 && p[3] == '\0' && strcmp(p, "abc") == 0);
        free(p);
        assert(sb.data == NULL && sb.len == 0 && sb.cap == 0 && sb.err == 0);
        sb_init(&sb, 0);
        assert(sb_append(&sb, "xyz") == 0 && strcmp(sb.data, "xyz") == 0);
        sb_free(&sb);
    }

    /* 8. sb_reserve + sb_advance: caller writes directly into the buffer tail
     * and commits the byte count. Mirrors the request-body streaming path in
     * web_server.c::parse_request. */
    {
        str_buf sb; sb_init(&sb, 0);
        assert(sb_reserve(&sb, 16) == 0);
        assert(sb.cap >= 16 && sb.len == 0);
        memcpy(sb.data + sb.len, "hello", 5);
        sb_advance(&sb, 5);
        assert(sb.len == 5 && sb.data[5] == '\0' && strcmp(sb.data, "hello") == 0);
        memcpy(sb.data + sb.len, " world", 6);
        sb_advance(&sb, 6);
        assert(sb.len == 11 && strcmp(sb.data, "hello world") == 0);
        sb_free(&sb);

        /* sb_advance under sticky err is a no-op. */
        str_buf bad; sb_init(&bad, 0);
        bad.err = 1;
        sb_advance(&bad, 10); /* must not crash */
        sb_free(&bad);
    }
    return 0;
}
