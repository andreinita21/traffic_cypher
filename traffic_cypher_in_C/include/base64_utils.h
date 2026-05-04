#ifndef BASE64_UTILS_H
#define BASE64_UTILS_H

#include <stddef.h>
#include <stdint.h>

/* Encode binary data to base64. out must be at least ((len+2)/3)*4 + 1 bytes. */
void base64_encode(const uint8_t *data, size_t len, char *out);

/* Decode base64 to binary. Returns decoded length, or -1 on error. */
int base64_decode(const char *b64, uint8_t *out, size_t out_max);

/* Base32 decode (for TOTP secrets). Returns decoded length or -1. */
int base32_decode(const char *b32, uint8_t *out, size_t out_max);

#endif
