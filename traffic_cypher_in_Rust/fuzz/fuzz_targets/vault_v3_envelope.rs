// Fuzz target — REMEDIATION_PLAN.md Week 4+ #10d.
//
// Drives `traffic_cypher::vault::fuzz_parse_vault_v3_envelope`: full V3
// struct deserialization plus hex decoding of the four envelope fields
// (wrapped_dek_nonce, wrapped_dek, vault_nonce, vault_ciphertext). The
// Argon2id derivation and AES-GCM decryption are intentionally not
// reached — they'd dominate fuzz runtime and the bugs we want to catch
// here are in the parsing layer.
//
// Run with: `cargo +nightly fuzz run vault_v3_envelope`
// Seed corpus: ../corpus/vault_v3_envelope/

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = traffic_cypher::vault::fuzz_parse_vault_v3_envelope(data);
});
