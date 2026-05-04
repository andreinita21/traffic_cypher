#include "totp.h"
#include "base64_utils.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

int totp_generate(const char *secret_base32, char *code_out, uint32_t *seconds_remaining) {
    /* Decode base32 secret */
    uint8_t secret[128];
    int secret_len = base32_decode(secret_base32, secret, sizeof(secret));
    if (secret_len < 0) return -1;

    /* Get current time step (30-second intervals) */
    uint64_t now = (uint64_t)time(NULL);
    uint64_t time_step = now / 30;

    /* Convert time_step to big-endian 8 bytes */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(time_step & 0xFF);
        time_step >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t hmac_result[20];
    unsigned int hmac_len = 20;
    HMAC(EVP_sha1(), secret, secret_len, msg, 8, hmac_result, &hmac_len);

    /* Dynamic truncation */
    int offset = hmac_result[19] & 0x0F;
    uint32_t code =
        ((uint32_t)(hmac_result[offset] & 0x7F) << 24) |
        ((uint32_t)(hmac_result[offset + 1]) << 16) |
        ((uint32_t)(hmac_result[offset + 2]) << 8) |
        ((uint32_t)(hmac_result[offset + 3]));

    code = code % 1000000;

    snprintf(code_out, 7, "%06u", code);
    *seconds_remaining = 30 - (uint32_t)(now % 30);

    return 0;
}

int totp_generate_secret(char *out, size_t out_max) {
    /* Generate 20 random bytes and base32-encode them */
    uint8_t raw[20];
    RAND_bytes(raw, 20);

    static const char b32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t j = 0;
    int buffer = 0, bits_in_buffer = 0;

    for (int i = 0; i < 20 && j < out_max - 1; i++) {
        buffer = (buffer << 8) | raw[i];
        bits_in_buffer += 8;
        while (bits_in_buffer >= 5 && j < out_max - 1) {
            bits_in_buffer -= 5;
            out[j++] = b32_chars[(buffer >> bits_in_buffer) & 0x1F];
        }
    }
    out[j] = '\0';
    return (int)j;
}
