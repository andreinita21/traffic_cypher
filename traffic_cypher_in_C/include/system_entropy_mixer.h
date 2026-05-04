#ifndef SYSTEM_ENTROPY_MIXER_H
#define SYSTEM_ENTROPY_MIXER_H

#include <stdint.h>

/*
 * Mix the pool digest with OS entropy and current timestamp.
 * Returns a 32-byte mixed seed: SHA-256(pool_digest || os_entropy || timestamp_nanos)
 */
void mix_entropy(const uint8_t pool_digest[32], uint8_t out[32]);

#endif
