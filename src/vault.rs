use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultEntry {
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl VaultEntry {
    pub fn new(
        name: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Self {
        let now = unix_now();
        VaultEntry { name, username, password, url, notes, created_at: now, updated_at: now }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub entries: Vec<VaultEntry>,
}

impl Vault {
    /// Insert a new entry or replace an existing one with the same name.
    pub fn add_or_update(&mut self, mut entry: VaultEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.name == entry.name) {
            entry.created_at = existing.created_at; // preserve original creation time
            entry.updated_at = unix_now();
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn get(&self, name: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Returns true if an entry was removed.
    pub fn delete(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < before
    }
}

// On-disk format: all binary fields are hex-encoded.
#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

// ---------------------------------------------------------------------------
// Paths & key derivation
// ---------------------------------------------------------------------------

pub fn vault_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".traffic_cypher_vault.json")
}

fn derive_vault_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_password.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"traffic-cypher-pm-v1", &mut key).expect("HKDF expand failed");
    key
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load and decrypt the vault. Returns an empty vault if the file doesn't exist.
pub fn load_vault(master_password: &str) -> Result<Vault> {
    let path = vault_path();
    if !path.exists() {
        return Ok(Vault::default());
    }

    let contents = std::fs::read_to_string(&path).context("Failed to read vault file")?;
    let vf: VaultFile = serde_json::from_str(&contents).context("Vault file is corrupt")?;

    let salt = hex::decode(&vf.salt).context("Invalid salt")?;
    let nonce_bytes = hex::decode(&vf.nonce).context("Invalid nonce")?;
    let ciphertext = hex::decode(&vf.ciphertext).context("Invalid ciphertext")?;

    if nonce_bytes.len() != 12 {
        return Err(anyhow!("Vault nonce has wrong length"));
    }

    let key_bytes = derive_vault_key(master_password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed — wrong master password?"))?;

    serde_json::from_slice(&plaintext).context("Failed to parse vault contents")
}

/// Encrypt and save the vault to disk.
pub fn save_vault(vault: &Vault, master_password: &str) -> Result<()> {
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow!("Failed to generate salt: {}", e))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;

    let key_bytes = derive_vault_key(master_password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(vault).context("Failed to serialize vault")?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

    let vf = VaultFile {
        version: 1,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };

    let contents = serde_json::to_string_pretty(&vf).context("Failed to serialize vault file")?;
    std::fs::write(vault_path(), contents).context("Failed to write vault file")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Password generation
// ---------------------------------------------------------------------------

/// Generate a cryptographically random password of `length` printable characters.
pub fn generate_password(length: usize) -> String {
    // Charset: lower + upper + digits + symbols (avoids ambiguous chars like l/1/O/0)
    const CHARSET: &[u8] =
        b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes.iter().map(|&b| CHARSET[b as usize % CHARSET.len()] as char).collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
