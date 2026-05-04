#ifndef CRYPTO_DERIVATION_H
#define CRYPTO_DERIVATION_H

#include <stddef.h>
#include <stdint.h>

/*
 * Derive a cryptographic key using HKDF-SHA256.
 *   mixed_seed:   32-byte IKM
 *   previous_key: previous key used as salt (NULL for first key)
 *   prev_key_len: length of previous_key (0 if NULL)
 *   key_length:   desired output key length
 *   out:          output buffer (must be at least key_length bytes)
 * Returns 0 on success, -1 on error.
 */
int derive_key(const uint8_t mixed_seed[32],
               const uint8_t *previous_key, size_t prev_key_len,
               size_t key_length, uint8_t *out);

/* Format key as hex string. out must be at least key_len*2+1 bytes. */
void format_hex(const uint8_t *key, size_t key_len, char *out);

/* Format key as base64 string. out must be at least ((key_len+2)/3)*4+1 bytes. */
void format_base64(const uint8_t *key, size_t key_len, char *out);

#endif
