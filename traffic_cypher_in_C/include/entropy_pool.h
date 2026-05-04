#ifndef ENTROPY_POOL_H
#define ENTROPY_POOL_H

#include <stddef.h>
#include <stdint.h>

#define ENTROPY_POOL_MAX_CAPACITY 64

typedef struct {
    uint8_t *entries[ENTROPY_POOL_MAX_CAPACITY];
    size_t   entry_lens[ENTROPY_POOL_MAX_CAPACITY];
    size_t   capacity;
    size_t   count;
    size_t   head; /* index of oldest entry */
} entropy_pool_t;

/* Initialize pool with given capacity (max ENTROPY_POOL_MAX_CAPACITY) */
void entropy_pool_init(entropy_pool_t *pool, size_t capacity);

/* Free all allocated memory in the pool */
void entropy_pool_free(entropy_pool_t *pool);

/* Push new entropy, evicting oldest if full. Takes ownership of data. */
void entropy_pool_push(entropy_pool_t *pool, uint8_t *data, size_t len);

/* Produce a 32-byte SHA-256 digest of the entire pool */
void entropy_pool_digest(const entropy_pool_t *pool, uint8_t out[32]);

/* Number of entries in the pool */
size_t entropy_pool_len(const entropy_pool_t *pool);

#endif
