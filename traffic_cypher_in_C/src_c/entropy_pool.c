#include "entropy_pool.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void entropy_pool_init(entropy_pool_t *pool, size_t capacity) {
    memset(pool, 0, sizeof(*pool));
    if (capacity > ENTROPY_POOL_MAX_CAPACITY)
        capacity = ENTROPY_POOL_MAX_CAPACITY;
    pool->capacity = capacity;
    pool->count = 0;
    pool->head = 0;
}

void entropy_pool_free(entropy_pool_t *pool) {
    for (size_t i = 0; i < pool->count; i++) {
        size_t idx = (pool->head + i) % pool->capacity;
        free(pool->entries[idx]);
        pool->entries[idx] = NULL;
    }
    pool->count = 0;
}

void entropy_pool_push(entropy_pool_t *pool, uint8_t *data, size_t len) {
    if (pool->count >= pool->capacity) {
        /* Evict oldest */
        free(pool->entries[pool->head]);
        pool->entries[pool->head] = data;
        pool->entry_lens[pool->head] = len;
        pool->head = (pool->head + 1) % pool->capacity;
    } else {
        size_t idx = (pool->head + pool->count) % pool->capacity;
        pool->entries[idx] = data;
        pool->entry_lens[idx] = len;
        pool->count++;
    }
}

void entropy_pool_digest(const entropy_pool_t *pool, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    for (size_t i = 0; i < pool->count; i++) {
        size_t idx = (pool->head + i) % pool->capacity;
        EVP_DigestUpdate(ctx, pool->entries[idx], pool->entry_lens[idx]);
    }

    unsigned int md_len;
    EVP_DigestFinal_ex(ctx, out, &md_len);
    EVP_MD_CTX_free(ctx);
}

size_t entropy_pool_len(const entropy_pool_t *pool) {
    return pool->count;
}
