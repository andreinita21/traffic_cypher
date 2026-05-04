#include "key_rotation.h"
#include "crypto_derivation.h"
#include "system_entropy_mixer.h"
#include "entropy_pool.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>

void *rotation_daemon(void *arg) {
    app_state_t *state = (app_state_t *)arg;

    fprintf(stderr, "[INFO] Entropy collection daemon starting\n");

    pthread_mutex_lock(&state->lock);
    state->rotation_running = 1;
    pthread_mutex_unlock(&state->lock);

    entropy_pool_t pool;
    entropy_pool_init(&pool, 8);

    uint8_t previous_key[32];
    int has_previous = 0;
    uint64_t epoch = 0;

    while (1) {
        sleep(1);

        pthread_mutex_lock(&state->lock);
        if (state->rotation_stop) {
            pthread_mutex_unlock(&state->lock);
            break;
        }
        pthread_mutex_unlock(&state->lock);

        /* Generate entropy from OS */
        uint8_t os_seed[32];
        RAND_bytes(os_seed, 32);

        uint8_t mixed[32];
        mix_entropy(os_seed, mixed);

        uint8_t new_key[32];
        derive_key(mixed,
                   has_previous ? previous_key : NULL,
                   has_previous ? 32 : 0,
                   32, new_key);

        epoch++;
        memcpy(previous_key, new_key, 32);
        has_previous = 1;

        /* Push entropy into pool */
        uint8_t *pool_data = (uint8_t *)malloc(32);
        memcpy(pool_data, new_key, 32);
        entropy_pool_push(&pool, pool_data, 32);

        /* Update state */
        pthread_mutex_lock(&state->lock);
        memcpy(state->latest_entropy, new_key, 32);
        state->key_epoch = epoch;
        state->pool_depth = entropy_pool_len(&pool);
        state->has_traffic_entropy = 1;
        pthread_mutex_unlock(&state->lock);
    }

    pthread_mutex_lock(&state->lock);
    state->rotation_running = 0;
    pthread_mutex_unlock(&state->lock);

    entropy_pool_free(&pool);
    fprintf(stderr, "[INFO] Entropy collection daemon stopped at epoch %llu\n",
            (unsigned long long)epoch);
    return NULL;
}
