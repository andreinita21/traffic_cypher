#include "system_entropy_mixer.h"

#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void mix_entropy(const uint8_t pool_digest[32], uint8_t out[32]) {
    /* 32 bytes of OS entropy */
    uint8_t os_entropy[32];
    RAND_bytes(os_entropy, 32);

    /* Current timestamp in nanoseconds */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t nanos = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    /* SHA-256(pool_digest || os_entropy || timestamp) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pool_digest, 32);
    EVP_DigestUpdate(ctx, os_entropy, 32);
    EVP_DigestUpdate(ctx, &nanos, sizeof(nanos));

    unsigned int md_len;
    EVP_DigestFinal_ex(ctx, out, &md_len);
    EVP_MD_CTX_free(ctx);
}
