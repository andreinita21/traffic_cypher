// Fuzz target — REMEDIATION_PLAN.md Week 4+ #10d.
//
// Drives `traffic_cypher::vault::fuzz_parse_vault_version`, the same probe
// the public `load_vault` uses to peek at `"version"` before committing to a
// V2 / V3 struct shape. Any panic in serde_json or in our struct shape is
// reported as a libFuzzer finding.
//
// Run with: `cargo +nightly fuzz run vault_version_probe`
// Seed corpus: ../corpus/vault_version_probe/

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = traffic_cypher::vault::fuzz_parse_vault_version(data);
});
