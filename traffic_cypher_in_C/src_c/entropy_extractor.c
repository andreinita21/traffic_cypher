#include "entropy_extractor.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int md_len;
    EVP_DigestFinal_ex(ctx, out, &md_len);
    EVP_MD_CTX_free(ctx);
}

extracted_entropy_t extract_entropy(const uint8_t *current_data, size_t current_len,
                                    const uint8_t *previous_data, size_t previous_len,
                                    uint32_t width, uint32_t height) {
    extracted_entropy_t result;
    memset(&result, 0, sizeof(result));

    /* Max size: 32 (full hash) + 32 (delta hash) + 64*32 (spatial) = 2112 */
    size_t max_entropy = 32 + 32 + 64 * 32;
    result.entropy_bytes = (uint8_t *)malloc(max_entropy);
    result.entropy_len = 0;

    /* 1. Full-frame hash */
    uint8_t full_hash[32];
    sha256_hash(current_data, current_len, full_hash);
    memcpy(result.entropy_bytes + result.entropy_len, full_hash, 32);
    result.entropy_len += 32;

    /* 2. Inter-frame delta hash + metrics */
    if (previous_data && previous_len > 0) {
        size_t min_len = current_len < previous_len ? current_len : previous_len;
        uint8_t *delta = (uint8_t *)malloc(min_len);
        uint64_t changed_pixels = 0;
        uint64_t total_delta = 0;

        for (size_t i = 0; i < min_len; i++) {
            delta[i] = current_data[i] ^ previous_data[i];
            if (delta[i] != 0) changed_pixels++;
            int16_t diff = (int16_t)current_data[i] - (int16_t)previous_data[i];
            total_delta += (uint64_t)(diff < 0 ? -diff : diff);
        }

        uint8_t delta_hash[32];
        sha256_hash(delta, min_len, delta_hash);
        memcpy(result.entropy_bytes + result.entropy_len, delta_hash, 32);
        result.entropy_len += 32;

        result.metrics.has_metrics = 1;
        result.metrics.changed_pixel_ratio = (double)changed_pixels / (double)min_len;
        result.metrics.mean_pixel_delta = (double)total_delta / (double)min_len;

        free(delta);
    }

    /* 3. Spatial block hashes (8x8 grid) */
    uint32_t grid_cols = 8, grid_rows = 8;
    uint32_t block_w = width / grid_cols;
    uint32_t block_h = height / grid_rows;

    if (block_w > 0 && block_h > 0) {
        for (uint32_t row = 0; row < grid_rows; row++) {
            for (uint32_t col = 0; col < grid_cols; col++) {
                EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

                for (uint32_t y = row * block_h; y < (row + 1) * block_h; y++) {
                    size_t line_start = (size_t)(y * width * 3 + col * block_w * 3);
                    size_t line_end = line_start + (size_t)(block_w * 3);
                    if (line_end <= current_len) {
                        EVP_DigestUpdate(ctx, current_data + line_start, block_w * 3);
                    }
                }

                uint8_t block_hash[32];
                unsigned int md_len;
                EVP_DigestFinal_ex(ctx, block_hash, &md_len);
                EVP_MD_CTX_free(ctx);

                memcpy(result.entropy_bytes + result.entropy_len, block_hash, 32);
                result.entropy_len += 32;
            }
        }
    }

    return result;
}
