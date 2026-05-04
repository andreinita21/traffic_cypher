/*
 * Benchmark harness for traffic_cypher_in_C
 * Tests: crypto primitives, entropy extraction, vault ops, password gen, TOTP
 * Outputs JSON results for comparison with Rust benchmarks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <mach/mach.h>

#include "crypto_derivation.h"
#include "entropy_extractor.h"
#include "entropy_pool.h"
#include "system_entropy_mixer.h"
#include "password_gen.h"
#include "totp.h"
#include "vault.h"
#include "hex_utils.h"

/* ---- timing helpers ---- */

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static size_t get_rss_bytes(void) {
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &count) == KERN_SUCCESS) {
        return info.resident_size;
    }
    return 0;
}

typedef struct {
    const char *name;
    double      min_us;
    double      max_us;
    double      avg_us;
    double      median_us;
    int         iterations;
} bench_result_t;

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static bench_result_t run_bench(const char *name, void (*fn)(void), int warmup, int iters) {
    /* warmup */
    for (int i = 0; i < warmup; i++) fn();

    double *times = (double *)malloc(iters * sizeof(double));
    double total = 0;

    for (int i = 0; i < iters; i++) {
        double start = now_us();
        fn();
        double end = now_us();
        times[i] = end - start;
        total += times[i];
    }

    qsort(times, iters, sizeof(double), cmp_double);

    bench_result_t r;
    r.name = name;
    r.min_us = times[0];
    r.max_us = times[iters - 1];
    r.avg_us = total / iters;
    r.median_us = times[iters / 2];
    r.iterations = iters;

    free(times);
    return r;
}

/* ---- benchmark functions ---- */

/* 1. HKDF key derivation */
static void bench_hkdf(void) {
    uint8_t seed[32], out[32];
    memset(seed, 0xAB, 32);
    derive_key(seed, NULL, 0, 32, out);
}

/* 2. SHA-256 via entropy extractor (full frame hash) */
static uint8_t *g_frame_data = NULL;
static uint8_t *g_prev_frame = NULL;
#define FRAME_W 320
#define FRAME_H 240
#define FRAME_SIZE (FRAME_W * FRAME_H * 3)

static void bench_entropy_extract_single(void) {
    extracted_entropy_t e = extract_entropy(g_frame_data, FRAME_SIZE, NULL, 0, FRAME_W, FRAME_H);
    free(e.entropy_bytes);
}

/* 3. Entropy extraction with delta (inter-frame) */
static void bench_entropy_extract_delta(void) {
    extracted_entropy_t e = extract_entropy(g_frame_data, FRAME_SIZE,
                                            g_prev_frame, FRAME_SIZE,
                                            FRAME_W, FRAME_H);
    free(e.entropy_bytes);
}

/* 4. Entropy pool push + digest */
static entropy_pool_t g_pool;
static int g_pool_counter = 0;

static void bench_entropy_pool_cycle(void) {
    uint8_t *data = (uint8_t *)malloc(32);
    memset(data, (uint8_t)(g_pool_counter++ & 0xFF), 32);
    entropy_pool_push(&g_pool, data, 32);

    uint8_t digest[32];
    entropy_pool_digest(&g_pool, digest);
}

/* 5. System entropy mixing */
static void bench_entropy_mix(void) {
    uint8_t pool_digest[32], out[32];
    memset(pool_digest, 0xCD, 32);
    mix_entropy(pool_digest, out);
}

/* 6. Password generation (24 chars) */
static void bench_password_gen(void) {
    char pw[128];
    password_options_t opts;
    password_options_default(&opts);
    opts.length = 24;
    password_generate(&opts, pw);
}

/* 7. Password strength calculation */
static void bench_password_strength(void) {
    password_strength_t s = password_calculate_strength("Tr@ff1c_Cyph3r!Str0ng_P@ss2024");
    (void)s;
}

/* 8. TOTP generation */
static void bench_totp(void) {
    char code[8];
    uint32_t remaining;
    totp_generate("JBSWY3DPEHPK3PXP", code, &remaining);
}

/* 9. Vault entry creation */
static void bench_vault_entry_create(void) {
    vault_entry_t entry;
    vault_entry_new(&entry, "BenchService", "https://bench.example.com",
                    "benchuser", "BenchP@ssw0rd!", "JBSWY3DPEHPK3PXP",
                    "Benchmark test entry");
}

/* 10. Vault add + lookup + delete cycle */
static vault_t g_vault;

static void bench_vault_crud(void) {
    vault_init(&g_vault);

    vault_entry_t entry;
    vault_entry_new(&entry, "CRUDTest", "https://crud.test",
                    "user", "pass", NULL, NULL);

    vault_add_or_update(&g_vault, &entry);
    vault_get_by_id(&g_vault, entry.id);
    vault_delete_by_id(&g_vault, entry.id);
}

/* 11. Vault JSON serialization (10 entries) */
static vault_t g_ser_vault;

static void bench_vault_serialize(void) {
    char *json = vault_to_json(&g_ser_vault);
    free(json);
}

/* 12. Vault save + load cycle (envelope encryption round-trip) */
static void bench_vault_save_load(void) {
    vault_t small_vault;
    vault_init(&small_vault);

    vault_entry_t entry;
    vault_entry_new(&entry, "SaveLoadTest", "https://test.com",
                    "user", "SecureP@ss!", NULL, "Test notes");
    vault_add_or_update(&small_vault, &entry);

    uint8_t dek[32];
    generate_dek_from_os(dek);

    save_vault(&small_vault, "benchmark_master_password_2024", dek, "os");

    unlocked_vault_t result;
    load_vault("benchmark_master_password_2024", &result);
}

/* 13. DEK generation from OS entropy */
static void bench_dek_gen_os(void) {
    uint8_t dek[32];
    generate_dek_from_os(dek);
}

/* 14. DEK generation from traffic entropy */
static void bench_dek_gen_traffic(void) {
    uint8_t traffic[64], dek[32];
    memset(traffic, 0xEF, 64);
    generate_dek_from_traffic(traffic, 64, dek);
}

/* 15. Hex encoding */
static void bench_hex_encode(void) {
    uint8_t data[256];
    char out[513];
    memset(data, 0xAB, 256);
    hex_encode(data, 256, out);
}

/* 16. Vault search (linear scan over 100 entries) */
static vault_t g_search_vault;

static void bench_vault_search(void) {
    /* Search by non-existent ID to force full scan */
    vault_get_by_id(&g_search_vault, "00000000-0000-0000-0000-000000000000");
}

/* 17. Full pipeline: extract -> pool -> mix -> derive */
static void bench_full_pipeline(void) {
    extracted_entropy_t e = extract_entropy(g_frame_data, FRAME_SIZE,
                                            g_prev_frame, FRAME_SIZE,
                                            FRAME_W, FRAME_H);

    entropy_pool_t pool;
    entropy_pool_init(&pool, 8);
    entropy_pool_push(&pool, e.entropy_bytes, e.entropy_len);

    uint8_t digest[32];
    entropy_pool_digest(&pool, digest);

    uint8_t mixed[32];
    mix_entropy(digest, mixed);

    uint8_t key[32];
    derive_key(mixed, NULL, 0, 32, key);

    entropy_pool_free(&pool);
}

/* ---- main ---- */

static void print_result(const bench_result_t *r, int is_last) {
    printf("    {\n");
    printf("      \"name\": \"%s\",\n", r->name);
    printf("      \"iterations\": %d,\n", r->iterations);
    printf("      \"min_us\": %.2f,\n", r->min_us);
    printf("      \"max_us\": %.2f,\n", r->max_us);
    printf("      \"avg_us\": %.2f,\n", r->avg_us);
    printf("      \"median_us\": %.2f\n", r->median_us);
    printf("    }%s\n", is_last ? "" : ",");
}

int main(void) {
    size_t rss_start = get_rss_bytes();

    /* Setup frame data */
    g_frame_data = (uint8_t *)malloc(FRAME_SIZE);
    g_prev_frame = (uint8_t *)malloc(FRAME_SIZE);
    for (int i = 0; i < FRAME_SIZE; i++) {
        g_frame_data[i] = (uint8_t)(i % 256);
        g_prev_frame[i] = (uint8_t)((i + 50) % 256);
    }

    /* Setup entropy pool */
    entropy_pool_init(&g_pool, 8);

    /* Setup serialization vault with 10 entries */
    vault_init(&g_ser_vault);
    for (int i = 0; i < 10; i++) {
        vault_entry_t e;
        char label[64], website[128], user[64], pw[64], notes[128];
        snprintf(label, sizeof(label), "Service_%d", i);
        snprintf(website, sizeof(website), "https://service%d.example.com", i);
        snprintf(user, sizeof(user), "user_%d", i);
        snprintf(pw, sizeof(pw), "P@ssw0rd_%d_Str0ng!", i);
        snprintf(notes, sizeof(notes), "Notes for service %d with some extra text", i);
        vault_entry_new(&e, label, website, user, pw, "JBSWY3DPEHPK3PXP", notes);
        char tag[32];
        snprintf(tag, sizeof(tag), "tag%d", i % 3);
        strncpy(e.tags[0], tag, VAULT_LABEL_MAX - 1);
        e.tag_count = 1;
        vault_add_or_update(&g_ser_vault, &e);
    }

    /* Setup search vault with 100 entries */
    vault_init(&g_search_vault);
    for (int i = 0; i < 100; i++) {
        vault_entry_t e;
        char label[64];
        snprintf(label, sizeof(label), "SearchService_%d", i);
        vault_entry_new(&e, label, NULL, NULL, "pass", NULL, NULL);
        vault_add_or_update(&g_search_vault, &e);
    }

    /* Use temp vault path for save/load benchmarks */
    setenv("TRAFFIC_CYPHER_VAULT_PATH", "/tmp/bench_vault_c.json", 1);

    double total_start = now_us();

    /* --- Run benchmarks --- */
    #define WARMUP 5
    #define FAST_ITERS 10000
    #define MED_ITERS  1000
    #define SLOW_ITERS 100

    bench_result_t results[17];
    int n = 0;

    results[n++] = run_bench("hkdf_derive_key",          bench_hkdf,                 WARMUP, FAST_ITERS);
    results[n++] = run_bench("entropy_extract_single",    bench_entropy_extract_single, WARMUP, MED_ITERS);
    results[n++] = run_bench("entropy_extract_delta",     bench_entropy_extract_delta, WARMUP, MED_ITERS);
    results[n++] = run_bench("entropy_pool_push_digest",  bench_entropy_pool_cycle,    WARMUP, FAST_ITERS);
    results[n++] = run_bench("entropy_mix",               bench_entropy_mix,           WARMUP, FAST_ITERS);
    results[n++] = run_bench("password_generate_24",      bench_password_gen,          WARMUP, FAST_ITERS);
    results[n++] = run_bench("password_strength_calc",    bench_password_strength,     WARMUP, FAST_ITERS);
    results[n++] = run_bench("totp_generate",             bench_totp,                  WARMUP, FAST_ITERS);
    results[n++] = run_bench("vault_entry_create",        bench_vault_entry_create,    WARMUP, FAST_ITERS);
    results[n++] = run_bench("vault_crud_cycle",          bench_vault_crud,            WARMUP, MED_ITERS);
    results[n++] = run_bench("vault_serialize_10",        bench_vault_serialize,       WARMUP, MED_ITERS);
    results[n++] = run_bench("vault_save_load_cycle",     bench_vault_save_load,       WARMUP, SLOW_ITERS);
    results[n++] = run_bench("dek_generate_os",           bench_dek_gen_os,            WARMUP, MED_ITERS);
    results[n++] = run_bench("dek_generate_traffic",      bench_dek_gen_traffic,       WARMUP, MED_ITERS);
    results[n++] = run_bench("hex_encode_256b",           bench_hex_encode,            WARMUP, FAST_ITERS);
    results[n++] = run_bench("vault_search_100_entries",  bench_vault_search,          WARMUP, FAST_ITERS);
    results[n++] = run_bench("full_entropy_pipeline",     bench_full_pipeline,         WARMUP, MED_ITERS);

    double total_end = now_us();
    size_t rss_end = get_rss_bytes();

    /* --- Output JSON --- */
    printf("{\n");
    printf("  \"implementation\": \"C\",\n");
    printf("  \"total_time_ms\": %.2f,\n", (total_end - total_start) / 1000.0);
    printf("  \"memory_rss_bytes\": %zu,\n", rss_end);
    printf("  \"memory_rss_mb\": %.2f,\n", rss_end / (1024.0 * 1024.0));
    printf("  \"memory_delta_bytes\": %zu,\n", rss_end > rss_start ? rss_end - rss_start : 0);
    printf("  \"benchmarks\": [\n");

    for (int i = 0; i < n; i++) {
        print_result(&results[i], i == n - 1);
    }

    printf("  ]\n");
    printf("}\n");

    /* Cleanup */
    free(g_frame_data);
    free(g_prev_frame);
    entropy_pool_free(&g_pool);
    unlink("/tmp/bench_vault_c.json");

    return 0;
}
