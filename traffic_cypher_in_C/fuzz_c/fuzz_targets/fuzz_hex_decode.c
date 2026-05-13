/*
 * Fuzz target — REMEDIATION_PLAN.md Week 4+ #10d.
 *
 * Drives hex_decode() from src_c/hex_utils.c. libFuzzer hands us an
 * arbitrary buffer; we copy it into a NUL-terminated string (hex_decode
 * uses strlen()) and feed it through. AddressSanitizer catches any
 * read/write outside the output bounds or any malformed-length confusion.
 *
 * Build & run with:
 *   make -C traffic_cypher_in_C fuzz_hex_decode
 *   traffic_cypher_in_C/fuzz_c/fuzz_hex_decode \
 *       traffic_cypher_in_C/fuzz_c/corpus/hex_decode \
 *       -max_total_time=60
 */
#include "hex_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Bound the input so a pathological case can't time out a single
     * iteration. 8 KiB is well above any realistic hex-encoded field
     * we'd ever decode (the largest is the vault ciphertext). */
    if (size > 8192) return 0;

    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    /* Output bound matches the largest real consumer (vault ciphertext).
     * Anything bigger is rejected by hex_decode itself. */
    uint8_t out[4096];
    (void)hex_decode(buf, out, sizeof(out));

    free(buf);
    return 0;
}
