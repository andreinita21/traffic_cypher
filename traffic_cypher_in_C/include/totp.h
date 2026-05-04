#ifndef TOTP_H
#define TOTP_H

#include <stddef.h>
#include <stdint.h>

/*
 * Generate a TOTP code from a base32-encoded secret.
 *   secret_base32: the base32-encoded secret string
 *   code_out:      buffer for the 6-digit code string (at least 7 bytes)
 *   seconds_remaining: output for seconds until next code
 * Returns 0 on success, -1 on error.
 */
int totp_generate(const char *secret_base32, char *code_out, uint32_t *seconds_remaining);

/*
 * Generate a new random TOTP secret (base32 encoded).
 * out must be at least 33 bytes. Returns the secret length.
 */
int totp_generate_secret(char *out, size_t out_max);

#endif
