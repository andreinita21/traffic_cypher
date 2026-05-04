#include "base64_utils.h"
#include <string.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const uint8_t *data, size_t len, char *out) {
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[j++] = b64_table[(data[i] >> 2) & 0x3F];
        out[j++] = b64_table[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
        out[j++] = b64_table[((data[i+1] & 0x0F) << 2) | ((data[i+2] >> 6) & 0x03)];
        out[j++] = b64_table[data[i+2] & 0x3F];
    }
    if (i < len) {
        out[j++] = b64_table[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[j++] = b64_table[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
            out[j++] = b64_table[((data[i+1] & 0x0F) << 2)];
        } else {
            out[j++] = b64_table[((data[i] & 0x03) << 4)];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *b64, uint8_t *out, size_t out_max) {
    size_t len = strlen(b64);
    size_t j = 0;
    for (size_t i = 0; i < len; i += 4) {
        int a = b64_val(b64[i]);
        int b = (i+1 < len) ? b64_val(b64[i+1]) : 0;
        int c = (i+2 < len && b64[i+2] != '=') ? b64_val(b64[i+2]) : -1;
        int d = (i+3 < len && b64[i+3] != '=') ? b64_val(b64[i+3]) : -1;

        if (a < 0 || b < 0) return -1;
        if (j >= out_max) return -1;
        out[j++] = (uint8_t)((a << 2) | (b >> 4));
        if (c >= 0 && j < out_max) {
            out[j++] = (uint8_t)(((b & 0x0F) << 4) | (c >> 2));
        }
        if (d >= 0 && j < out_max) {
            out[j++] = (uint8_t)(((c & 0x03) << 6) | d);
        }
    }
    return (int)j;
}

static int b32_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int base32_decode(const char *b32, uint8_t *out, size_t out_max) {
    size_t len = strlen(b32);
    size_t j = 0;
    int buffer = 0;
    int bits_in_buffer = 0;

    for (size_t i = 0; i < len; i++) {
        if (b32[i] == '=' || b32[i] == ' ') continue;
        int val = b32_val(b32[i]);
        if (val < 0) return -1;

        buffer = (buffer << 5) | val;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            if (j >= out_max) return -1;
            out[j++] = (uint8_t)((buffer >> bits_in_buffer) & 0xFF);
        }
    }
    return (int)j;
}
