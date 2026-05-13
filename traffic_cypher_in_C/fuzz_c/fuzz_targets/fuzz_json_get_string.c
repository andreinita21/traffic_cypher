/*
 * Fuzz target — REMEDIATION_PLAN.md Week 4+ #10d.
 *
 * Drives vault.c's static json_get_string() through the
 * fuzz_json_get_string() wrapper (compiled in only when ENABLE_FUZZ_API is
 * defined — see src_c/vault.c). libFuzzer's input is copied into a
 * NUL-terminated string (the parser relies on strstr/strchr).
 *
 * We fuzz against three different keys per iteration so the substring-search
 * paths and the optional `"\"key\": \""` (space-after-colon) fallback both
 * see traffic.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Declared in src_c/vault.c, gated by -DENABLE_FUZZ_API. */
extern char *fuzz_json_get_string(const char *json, const char *key);

static void try_key(const char *json, const char *key) {
    char *v = fuzz_json_get_string(json, key);
    free(v);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 64 * 1024) return 0;

    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    try_key(buf, "label");
    try_key(buf, "password");
    try_key(buf, "vault_ciphertext");

    free(buf);
    return 0;
}
