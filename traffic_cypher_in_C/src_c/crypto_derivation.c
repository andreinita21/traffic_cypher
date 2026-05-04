#include "crypto_derivation.h"
#include "hex_utils.h"
#include "base64_utils.h"

#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

int derive_key(const uint8_t mixed_seed[32],
               const uint8_t *previous_key, size_t prev_key_len,
               size_t key_length, uint8_t *out) {
    /* Salt: previous key or 32 zero bytes */
    uint8_t default_salt[32];
    memset(default_salt, 0, 32);
    const uint8_t *salt = previous_key ? previous_key : default_salt;
    size_t salt_len = previous_key ? prev_key_len : 32;

    /* Info: "traffic-cypher-v1" + timestamp */
    uint64_t ts = (uint64_t)time(NULL);
    uint8_t info[32];
    size_t info_len = 0;
    memcpy(info, "traffic-cypher-v1", 17);
    info_len = 17;
    memcpy(info + info_len, &ts, sizeof(ts));
    info_len += sizeof(ts);

    /* HKDF using OpenSSL EVP */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, mixed_seed, 32) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t out_len = key_length;
    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

void format_hex(const uint8_t *key, size_t key_len, char *out) {
    hex_encode(key, key_len, out);
}

void format_base64(const uint8_t *key, size_t key_len, char *out) {
    base64_encode(key, key_len, out);
}
