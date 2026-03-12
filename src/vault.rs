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
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultEntry {
    pub id: String,
    pub label: String,
    pub website: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub totp_secret: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl VaultEntry {
    pub fn new(
        label: String,
        website: Option<String>,
        username: Option<String>,
        password: String,
        totp_secret: Option<String>,
        notes: Option<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = unix_now();
        VaultEntry {
            id: Uuid::new_v4().to_string(),
            label,
            website,
            username,
            password,
            totp_secret,
            notes,
            tags,
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub entries: Vec<VaultEntry>,
}

impl Vault {
    /// Insert a new entry or update an existing one matched by id.
    /// On update, the old password is pushed to history (max 10 entries kept).
    pub fn add_or_update(&mut self, mut entry: VaultEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.id == entry.id) {
            // Push old password to history if it changed
            if existing.password != entry.password {
                existing.password_history.push(PasswordHistoryEntry {
                    password: existing.password.clone(),
                    changed_at: unix_now(),
                });
                // Keep at most 10 history entries (drop oldest)
                while existing.password_history.len() > 10 {
                    existing.password_history.remove(0);
                }
                entry.password_history = existing.password_history.clone();
            } else {
                entry.password_history = existing.password_history.clone();
            }
            entry.created_at = existing.created_at; // preserve original creation time
            entry.updated_at = unix_now();
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Get an entry by id.
    pub fn get_by_id(&self, id: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Get an entry by label (exact match).
    pub fn get_by_label(&self, label: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.label == label)
    }

    /// Returns true if an entry was removed.
    pub fn delete(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() < before
    }

    /// Alias for delete by id.
    pub fn delete_by_id(&mut self, id: &str) -> bool {
        self.delete(id)
    }

    /// Fuzzy search across label, username, website, and tags.
    /// Returns entries where any of those fields contain the query (case-insensitive).
    pub fn search(&self, query: &str) -> Vec<&VaultEntry> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.label.to_lowercase().contains(&q)
                    || e.username
                        .as_deref()
                        .map_or(false, |u| u.to_lowercase().contains(&q))
                    || e.website
                        .as_deref()
                        .map_or(false, |w| w.to_lowercase().contains(&q))
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// On-disk format: all binary fields are hex-encoded.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
    traffic_key_epoch: u64,
}

// ---------------------------------------------------------------------------
// Stream config
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StreamEntry {
    pub url: String,
    pub label: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u64,
}

fn default_auto_lock_minutes() -> u64 {
    5
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_minutes: default_auto_lock_minutes(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StreamConfig {
    pub streams: Vec<StreamEntry>,
    pub default_stream: String,
    #[serde(default)]
    pub settings: Settings,
}

impl Default for StreamConfig {
    fn default() -> Self {
        StreamConfig {
            streams: Vec::new(),
            default_stream: "https://www.youtube.com/watch?v=rs2be3mqryo".to_string(),
            settings: Settings::default(),
        }
    }
}

pub fn stream_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".traffic_cypher_streams.json")
}

pub fn load_stream_config() -> StreamConfig {
    let path = stream_config_path();
    if !path.exists() {
        return StreamConfig::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => StreamConfig::default(),
    }
}

pub fn save_stream_config(config: &StreamConfig) -> Result<()> {
    let contents =
        serde_json::to_string_pretty(config).context("Failed to serialize stream config")?;
    std::fs::write(stream_config_path(), contents).context("Failed to write stream config")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Paths & key derivation
// ---------------------------------------------------------------------------

pub fn vault_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".traffic_cypher_vault.json")
}

/// Derive a 256-bit vault key using HKDF-SHA256.
/// Compound key derivation: if traffic_key is provided, the HKDF salt is
/// salt || traffic_key; otherwise just salt.
fn derive_vault_key(master_password: &str, salt: &[u8], traffic_key: Option<&[u8]>) -> [u8; 32] {
    let compound_salt = match traffic_key {
        Some(tk) => {
            let mut combined = Vec::with_capacity(salt.len() + tk.len());
            combined.extend_from_slice(salt);
            combined.extend_from_slice(tk);
            combined
        }
        None => salt.to_vec(),
    };
    let hk = Hkdf::<Sha256>::new(Some(&compound_salt), master_password.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"traffic-cypher-pm-v1", &mut key)
        .expect("HKDF expand failed");
    key
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load and decrypt the vault. Returns an empty vault if the file doesn't exist.
pub fn load_vault(master_password: &str, traffic_key: Option<&[u8]>) -> Result<Vault> {
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

    let key_bytes = derive_vault_key(master_password, &salt, traffic_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed — wrong master password?"))?;

    serde_json::from_slice(&plaintext).context("Failed to parse vault contents")
}

/// Encrypt and save the vault to disk.
pub fn save_vault(
    vault: &Vault,
    master_password: &str,
    traffic_key: Option<&[u8]>,
) -> Result<()> {
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow!("Failed to generate salt: {}", e))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;

    let key_bytes = derive_vault_key(master_password, &salt, traffic_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(vault).context("Failed to serialize vault")?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

    let traffic_key_epoch = unix_now();

    let vf = VaultFile {
        version: 1,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        traffic_key_epoch,
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
    bytes
        .iter()
        .map(|&b| CHARSET[b as usize % CHARSET.len()] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
