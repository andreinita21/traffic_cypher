/*
 * Fuzz target — REMEDIATION_PLAN.md Week 4+ #10d.
 *
 * Drives vault.c's static parse_vault_entries() through the
 * fuzz_parse_vault_entries() wrapper (compiled in only with
 * -DENABLE_FUZZ_API). This walks the whole user-controlled file format,
 * so it's the highest-payoff C fuzz target — it nests JSON parsing,
 * strstr scans, escape handling, and bounded copies into VAULT_*_MAX
 * sized fields.
 */
#include "vault.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int fuzz_parse_vault_entries(const char *json, vault_t *v);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* The vault file cap is 8 MiB (parse_request body limit). Most
     * realistic vault files are <100 KiB; a 256 KiB upper bound keeps
     * libFuzzer iterations fast while still exercising long inputs. */
    if (size > 256 * 1024) return 0;

    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    /* vault_t is large (~3 MiB worth of fixed-size arrays); place it on
     * the heap so each iteration's stack stays small under ASan. */
    vault_t *v = (vault_t *)calloc(1, sizeof(*v));
    if (v) {
        (void)fuzz_parse_vault_entries(buf, v);
    }

    free(v);
    free(buf);
    return 0;
}
