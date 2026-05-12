// One-shot helper used to generate `test_fixtures/sample_vault_v2.json` ---
// a tiny vault written in the legacy v2 (HKDF-derived KEK) format that the
// v2 -> v3 upgrade test reads back.
//
// Run with:
//   TRAFFIC_CYPHER_V2_FIXTURE_OUT=/tmp/sample_vault_v2.json \
//     cargo run --release --example make_v2_vault
//
// The crucial difference from a "fresh" v2 save is that this binary forces
// the legacy schema (no `kdf`/`kdf_m_cost`/`kdf_t_cost`/`kdf_p_cost` fields,
// `"version": 2`). After v3 lands, normal `save_vault` always writes v3, so
// we can't regenerate this fixture by running the modern binary — this
// helper is the only way to produce a real v2 file.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
struct VaultEntry {
    id: String,
    label: String,
    website: Option<String>,
    username: Option<String>,
    password: String,
    totp_secret: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    password_history: Vec<()>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Serialize)]
struct Vault {
    entries: Vec<VaultEntry>,
}

#[derive(Serialize)]
struct VaultFileV2 {
    version: u8,
    kek_salt: String,
    wrapped_dek_nonce: String,
    wrapped_dek: String,
    vault_nonce: String,
    vault_ciphertext: String,
    entropy_source: String,
    updated_at: u64,
}

fn derive_kek_hkdf(password: &str, salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut kek = [0u8; 32];
    hk.expand(b"traffic-cypher-kek-v2", &mut kek).unwrap();
    kek
}

fn main() {
    let out_path = std::env::var("TRAFFIC_CYPHER_V2_FIXTURE_OUT")
        .unwrap_or_else(|_| "test_fixtures/sample_vault_v2.json".to_string());

    let master_pw = "upgrade-fixture-pw";

    // Deterministic fixture: fixed salt/nonces/DEK so the file is reproducible.
    let kek_salt = [0x11u8; 32];
    let wrap_nonce = [0x22u8; 12];
    let vault_nonce = [0x33u8; 12];
    let dek = [0x44u8; 32];

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let vault = Vault {
        entries: vec![VaultEntry {
            id: "11111111-1111-4111-8111-111111111111".to_string(),
            label: "v2-upgrade-test".to_string(),
            website: Some("https://example.com".to_string()),
            username: Some("alice".to_string()),
            password: "v2-secret-do-not-lose".to_string(),
            totp_secret: None,
            notes: None,
            tags: vec!["legacy".to_string()],
            password_history: vec![],
            created_at: now,
            updated_at: now,
        }],
    };

    // Derive KEK with the *legacy* HKDF path.
    let kek = derive_kek_hkdf(master_pw, &kek_salt);

    // Wrap the DEK.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let wrapped_dek = cipher
        .encrypt(Nonce::from_slice(&wrap_nonce), dek.as_ref())
        .expect("wrap dek");

    // Encrypt the vault data.
    let vault_json = serde_json::to_vec(&vault).expect("serialize vault");
    let cipher_dek = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let vault_ct = cipher_dek
        .encrypt(Nonce::from_slice(&vault_nonce), vault_json.as_ref())
        .expect("encrypt vault");

    let vf = VaultFileV2 {
        version: 2,
        kek_salt: hex::encode(kek_salt),
        wrapped_dek_nonce: hex::encode(wrap_nonce),
        wrapped_dek: hex::encode(wrapped_dek),
        vault_nonce: hex::encode(vault_nonce),
        vault_ciphertext: hex::encode(vault_ct),
        entropy_source: "os".to_string(),
        updated_at: 1715520000,
    };

    let pretty = serde_json::to_string_pretty(&vf).unwrap();
    std::fs::write(&out_path, pretty).expect("write fixture");
    println!("wrote v2 fixture to {}", out_path);
    println!("master_password = {}", master_pw);
    println!("entry label = v2-upgrade-test");
    println!("entry password = v2-secret-do-not-lose");
}
