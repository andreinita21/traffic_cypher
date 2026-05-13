//! Benchmark harness for traffic_cypher (Rust)
//! Outputs JSON results for comparison with C benchmarks

use std::time::Instant;

use traffic_cypher::{
    crypto_derivation, entropy_extractor, entropy_pool, password_gen, system_entropy_mixer, totp,
    vault,
};

// ---- timing helpers ----

struct BenchResult {
    name: &'static str,
    iterations: usize,
    min_us: f64,
    max_us: f64,
    avg_us: f64,
    median_us: f64,
}

fn run_bench(name: &'static str, warmup: usize, iters: usize, mut f: impl FnMut()) -> BenchResult {
    for _ in 0..warmup {
        f();
    }

    let mut times = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed().as_secs_f64() * 1_000_000.0;
        times.push(elapsed);
    }

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let total: f64 = times.iter().sum();
    BenchResult {
        name,
        iterations: iters,
        min_us: times[0],
        max_us: times[iters - 1],
        avg_us: total / iters as f64,
        median_us: times[iters / 2],
    }
}

// reason: libc::mach_task_self_ was deprecated in favour of the `mach2` crate,
// but adding a new dependency is out of scope. Suppress on macOS only — the
// other platform branches don't use the deprecated symbol.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn get_rss_bytes() -> usize {
    // macOS: use mach task_info.
    unsafe {
        let mut info: libc::mach_task_basic_info_data_t = std::mem::zeroed();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info_data_t>()
            / std::mem::size_of::<libc::natural_t>()) as u32;
        let kr = libc::task_info(
            libc::mach_task_self_,
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as *mut i32,
            &mut count,
        );
        if kr == 0 {
            info.resident_size as usize
        } else {
            0
        }
    }
}

#[cfg(target_os = "linux")]
fn get_rss_bytes() -> usize {
    // Linux: /proc/self/statm fields are page counts: size, resident, ...
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let resident_pages = s
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    resident_pages * page_size
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_rss_bytes() -> usize {
    0
}

const FRAME_W: u32 = 320;
const FRAME_H: u32 = 240;
const FRAME_SIZE: usize = (FRAME_W * FRAME_H * 3) as usize;

const WARMUP: usize = 5;
const FAST_ITERS: usize = 10_000;
const MED_ITERS: usize = 1_000;
const SLOW_ITERS: usize = 100;

fn main() {
    let rss_start = get_rss_bytes();

    // Setup frame data
    let frame_data: Vec<u8> = (0..FRAME_SIZE).map(|i| (i % 256) as u8).collect();
    let prev_frame: Vec<u8> = (0..FRAME_SIZE).map(|i| ((i + 50) % 256) as u8).collect();

    let total_start = Instant::now();

    let mut results: Vec<BenchResult> = Vec::new();

    // 1. HKDF key derivation
    results.push(run_bench("hkdf_derive_key", WARMUP, FAST_ITERS, || {
        let seed = [0xABu8; 32];
        let _ = crypto_derivation::derive_key(&seed, None, 32);
    }));

    // 2. Entropy extraction (single frame)
    {
        let fd = frame_data.clone();
        results.push(run_bench(
            "entropy_extract_single",
            WARMUP,
            MED_ITERS,
            || {
                let _ = entropy_extractor::extract_entropy(&fd, None, FRAME_W, FRAME_H);
            },
        ));
    }

    // 3. Entropy extraction with delta
    {
        let fd = frame_data.clone();
        let pf = prev_frame.clone();
        results.push(run_bench(
            "entropy_extract_delta",
            WARMUP,
            MED_ITERS,
            || {
                let _ = entropy_extractor::extract_entropy(&fd, Some(&pf), FRAME_W, FRAME_H);
            },
        ));
    }

    // 4. Entropy pool push + digest
    {
        let mut pool = entropy_pool::EntropyPool::new(8);
        let mut counter = 0u8;
        results.push(run_bench(
            "entropy_pool_push_digest",
            WARMUP,
            FAST_ITERS,
            || {
                let data = vec![counter; 32];
                counter = counter.wrapping_add(1);
                pool.push(data);
                let _ = pool.digest();
            },
        ));
    }

    // 5. System entropy mixing
    results.push(run_bench("entropy_mix", WARMUP, FAST_ITERS, || {
        let digest = [0xCDu8; 32];
        let _ = system_entropy_mixer::mix_entropy(&digest);
    }));

    // 6. Password generation (24 chars)
    results.push(run_bench(
        "password_generate_24",
        WARMUP,
        FAST_ITERS,
        || {
            let opts = password_gen::PasswordOptions::default();
            let _ = password_gen::generate(&opts);
        },
    ));

    // 7. Password strength calculation
    results.push(run_bench(
        "password_strength_calc",
        WARMUP,
        FAST_ITERS,
        || {
            let _ = password_gen::calculate_strength("Tr@ff1c_Cyph3r!Str0ng_P@ss2024");
        },
    ));

    // 8. TOTP generation
    results.push(run_bench("totp_generate", WARMUP, FAST_ITERS, || {
        let _ = totp::generate_totp("JBSWY3DPEHPK3PXP");
    }));

    // 9. Vault entry creation
    results.push(run_bench("vault_entry_create", WARMUP, FAST_ITERS, || {
        let _ = vault::VaultEntry::new(
            "BenchService".to_string(),
            Some("https://bench.example.com".to_string()),
            Some("benchuser".to_string()),
            "BenchP@ssw0rd!".to_string(),
            Some("JBSWY3DPEHPK3PXP".to_string()),
            Some("Benchmark test entry".to_string()),
            vec![],
        );
    }));

    // 10. Vault CRUD cycle
    results.push(run_bench("vault_crud_cycle", WARMUP, MED_ITERS, || {
        let mut v = vault::Vault::default();
        let entry = vault::VaultEntry::new(
            "CRUDTest".to_string(),
            Some("https://crud.test".to_string()),
            Some("user".to_string()),
            "pass".to_string(),
            None,
            None,
            vec![],
        );
        let id = entry.id.clone();
        v.add_or_update(entry);
        let _ = v.get_by_id(&id);
        v.delete_by_id(&id);
    }));

    // 11. Vault JSON serialization (10 entries)
    {
        let mut ser_vault = vault::Vault::default();
        for i in 0..10 {
            let e = vault::VaultEntry::new(
                format!("Service_{}", i),
                Some(format!("https://service{}.example.com", i)),
                Some(format!("user_{}", i)),
                format!("P@ssw0rd_{}_Str0ng!", i),
                Some("JBSWY3DPEHPK3PXP".to_string()),
                Some(format!("Notes for service {} with some extra text", i)),
                vec![format!("tag{}", i % 3)],
            );
            ser_vault.add_or_update(e);
        }

        results.push(run_bench("vault_serialize_10", WARMUP, MED_ITERS, || {
            let _ = serde_json::to_string(&ser_vault).unwrap();
        }));
    }

    // 12. Vault save + load cycle
    {
        std::env::set_var("TRAFFIC_CYPHER_VAULT_PATH", "/tmp/bench_vault_rust.json");
        results.push(run_bench(
            "vault_save_load_cycle",
            WARMUP,
            SLOW_ITERS,
            || {
                let mut small_vault = vault::Vault::default();
                let entry = vault::VaultEntry::new(
                    "SaveLoadTest".to_string(),
                    Some("https://test.com".to_string()),
                    Some("user".to_string()),
                    "SecureP@ss!".to_string(),
                    None,
                    Some("Test notes".to_string()),
                    vec![],
                );
                small_vault.add_or_update(entry);

                let dek = vault::generate_dek_from_os();
                vault::save_vault(&small_vault, "benchmark_master_password_2024", &dek, "os")
                    .unwrap();
                let _ = vault::load_vault("benchmark_master_password_2024").unwrap();
            },
        ));
        let _ = std::fs::remove_file("/tmp/bench_vault_rust.json");
    }

    // 13. DEK generation from OS entropy
    results.push(run_bench("dek_generate_os", WARMUP, MED_ITERS, || {
        let _ = vault::generate_dek_from_os();
    }));

    // 14. DEK generation from traffic entropy
    results.push(run_bench("dek_generate_traffic", WARMUP, MED_ITERS, || {
        let traffic = [0xEFu8; 64];
        let _ = vault::generate_dek_from_traffic(&traffic);
    }));

    // 15. Hex encoding
    results.push(run_bench("hex_encode_256b", WARMUP, FAST_ITERS, || {
        let data = [0xABu8; 256];
        let _ = crypto_derivation::format_hex(&data);
    }));

    // 16. Vault search (100 entries)
    {
        let mut search_vault = vault::Vault::default();
        for i in 0..100 {
            let e = vault::VaultEntry::new(
                format!("SearchService_{}", i),
                None,
                None,
                "pass".to_string(),
                None,
                None,
                vec![],
            );
            search_vault.add_or_update(e);
        }

        results.push(run_bench(
            "vault_search_100_entries",
            WARMUP,
            FAST_ITERS,
            || {
                let _ = search_vault.get_by_id("00000000-0000-0000-0000-000000000000");
            },
        ));
    }

    // 17. Full entropy pipeline
    {
        let fd = frame_data.clone();
        let pf = prev_frame.clone();
        results.push(run_bench(
            "full_entropy_pipeline",
            WARMUP,
            MED_ITERS,
            || {
                let extracted =
                    entropy_extractor::extract_entropy(&fd, Some(&pf), FRAME_W, FRAME_H);
                let mut pool = entropy_pool::EntropyPool::new(8);
                pool.push(extracted.entropy_bytes);
                let digest = pool.digest();
                let mixed = system_entropy_mixer::mix_entropy(&digest);
                let _ = crypto_derivation::derive_key(&mixed, None, 32);
            },
        ));
    }

    let total_elapsed = total_start.elapsed().as_secs_f64() * 1000.0;
    let rss_end = get_rss_bytes();

    // Output JSON
    println!("{{");
    println!("  \"implementation\": \"Rust\",");
    println!("  \"total_time_ms\": {:.2},", total_elapsed);
    println!("  \"memory_rss_bytes\": {},", rss_end);
    println!(
        "  \"memory_rss_mb\": {:.2},",
        rss_end as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  \"memory_delta_bytes\": {},",
        rss_end.saturating_sub(rss_start)
    );
    println!("  \"benchmarks\": [");

    for (i, r) in results.iter().enumerate() {
        let comma = if i < results.len() - 1 { "," } else { "" };
        println!("    {{");
        println!("      \"name\": \"{}\",", r.name);
        println!("      \"iterations\": {},", r.iterations);
        println!("      \"min_us\": {:.2},", r.min_us);
        println!("      \"max_us\": {:.2},", r.max_us);
        println!("      \"avg_us\": {:.2},", r.avg_us);
        println!("      \"median_us\": {:.2}", r.median_us);
        println!("    }}{}", comma);
    }

    println!("  ]");
    println!("}}");
}
