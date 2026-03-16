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
// Data types (unchanged)
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
// On-disk format v2: Envelope Encryption
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct VaultFileV2 {
    version: u8,
    /// Salt used to derive the KEK from the master password
    kek_salt: String,
    /// Nonce used when wrapping the DEK with the KEK
    wrapped_dek_nonce: String,
    /// The DEK encrypted (wrapped) with the KEK
    wrapped_dek: String,
    /// Nonce used when encrypting the vault data with the DEK
    vault_nonce: String,
    /// The vault data encrypted with the DEK
    vault_ciphertext: String,
    /// Where the DEK entropy came from
    entropy_source: String,
    /// When this vault file was last written
    updated_at: u64,
}

// ---------------------------------------------------------------------------
// Stream config (unchanged)
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
// Paths
// ---------------------------------------------------------------------------

pub fn vault_path() -> PathBuf {
    if let Ok(custom) = std::env::var("TRAFFIC_CYPHER_VAULT_PATH") {
        return PathBuf::from(custom);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".traffic_cypher_vault.json")
}

// ---------------------------------------------------------------------------
// Envelope encryption primitives
// ---------------------------------------------------------------------------

/// Derive a 256-bit Key Encryption Key (KEK) from master password + salt.
fn derive_kek(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_password.as_bytes());
    let mut kek = [0u8; 32];
    hk.expand(b"traffic-cypher-kek-v2", &mut kek)
        .expect("HKDF expand failed");
    kek
}

/// Generate a 256-bit Data Encryption Key (DEK) from traffic entropy.
pub fn generate_dek_from_traffic(traffic_entropy: &[u8]) -> [u8; 32] {
    let mut os_salt = [0u8; 32];
    getrandom::getrandom(&mut os_salt).expect("getrandom failed");
    let hk = Hkdf::<Sha256>::new(Some(&os_salt), traffic_entropy);
    let mut dek = [0u8; 32];
    hk.expand(b"traffic-cypher-dek-v2", &mut dek)
        .expect("HKDF expand failed");
    dek
}

/// Generate a 256-bit DEK from OS entropy (fallback when no traffic stream).
pub fn generate_dek_from_os() -> [u8; 32] {
    let mut ikm = [0u8; 64];
    getrandom::getrandom(&mut ikm).expect("getrandom failed");
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).expect("getrandom failed");
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut dek = [0u8; 32];
    hk.expand(b"traffic-cypher-dek-os-v2", &mut dek)
        .expect("HKDF expand failed");
    dek
}

/// Wrap (encrypt) a DEK with a KEK using AES-256-GCM.
fn wrap_dek(kek: &[u8; 32], dek: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let wrapped = cipher
        .encrypt(nonce, dek.as_ref())
        .map_err(|e| anyhow!("DEK wrapping failed: {:?}", e))?;
    Ok((wrapped, nonce_bytes))
}

/// Unwrap (decrypt) a DEK with a KEK using AES-256-GCM.
fn unwrap_dek(kek: &[u8; 32], wrapped_dek: &[u8], nonce_bytes: &[u8; 12]) -> Result<[u8; 32]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Nonce::from_slice(nonce_bytes);
    let dek_bytes = cipher
        .decrypt(nonce, wrapped_dek)
        .map_err(|_| anyhow!("Failed to unwrap DEK — wrong master password?"))?;
    if dek_bytes.len() != 32 {
        return Err(anyhow!("Unwrapped DEK has wrong length"));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    Ok(dek)
}

/// Encrypt vault data with a DEK using AES-256-GCM.
fn encrypt_vault_data(dek: &[u8; 32], vault: &Vault) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(vault).context("Failed to serialize vault")?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("Vault encryption failed: {:?}", e))?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt vault data with a DEK using AES-256-GCM.
fn decrypt_vault_data(
    dek: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vault> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Vault decryption failed — data may be corrupt"))?;
    serde_json::from_slice(&plaintext).context("Failed to parse vault contents")
}

// ---------------------------------------------------------------------------
// Public API: Load / Save / Rotate
// ---------------------------------------------------------------------------

/// Result of loading the vault: contains the decrypted vault and the unwrapped DEK.
pub struct UnlockedVault {
    pub vault: Vault,
    pub dek: [u8; 32],
    pub entropy_source: String,
}

/// Load and decrypt the vault using only the master password.
/// Returns the vault data plus the unwrapped DEK (needed for subsequent saves).
/// If no vault file exists, creates a new vault with an OS-entropy DEK.
pub fn load_vault(master_password: &str) -> Result<UnlockedVault> {
    let path = vault_path();
    if !path.exists() {
        // First time: generate a DEK from OS entropy, return empty vault
        let dek = generate_dek_from_os();
        return Ok(UnlockedVault {
            vault: Vault::default(),
            dek,
            entropy_source: "os".to_string(),
        });
    }

    let contents = std::fs::read_to_string(&path).context("Failed to read vault file")?;
    let vf: VaultFileV2 = serde_json::from_str(&contents).context("Vault file is corrupt")?;

    // Decode hex fields
    let kek_salt = hex::decode(&vf.kek_salt).context("Invalid kek_salt")?;
    let wrapped_dek_nonce_bytes = hex::decode(&vf.wrapped_dek_nonce).context("Invalid wrapped_dek_nonce")?;
    let wrapped_dek = hex::decode(&vf.wrapped_dek).context("Invalid wrapped_dek")?;
    let vault_nonce_bytes = hex::decode(&vf.vault_nonce).context("Invalid vault_nonce")?;
    let vault_ciphertext = hex::decode(&vf.vault_ciphertext).context("Invalid vault_ciphertext")?;

    if wrapped_dek_nonce_bytes.len() != 12 {
        return Err(anyhow!("wrapped_dek_nonce has wrong length"));
    }
    if vault_nonce_bytes.len() != 12 {
        return Err(anyhow!("vault_nonce has wrong length"));
    }

    let mut wdn = [0u8; 12];
    wdn.copy_from_slice(&wrapped_dek_nonce_bytes);
    let mut vn = [0u8; 12];
    vn.copy_from_slice(&vault_nonce_bytes);

    // Step 1: Derive KEK from master password + stored salt
    let kek = derive_kek(master_password, &kek_salt);

    // Step 2: Unwrap (decrypt) the DEK
    let dek = unwrap_dek(&kek, &wrapped_dek, &wdn)?;

    // Step 3: Decrypt the vault data with the DEK
    let vault = decrypt_vault_data(&dek, &vault_ciphertext, &vn)?;

    Ok(UnlockedVault {
        vault,
        dek,
        entropy_source: vf.entropy_source,
    })
}

/// Encrypt and save the vault to disk.
/// Uses the provided DEK for data encryption and wraps the DEK with a KEK
/// derived from the master password.
pub fn save_vault(
    vault: &Vault,
    master_password: &str,
    dek: &[u8; 32],
    entropy_source: &str,
) -> Result<()> {
    // Generate a fresh KEK salt
    let mut kek_salt = [0u8; 32];
    getrandom::getrandom(&mut kek_salt)
        .map_err(|e| anyhow!("Failed to generate kek_salt: {}", e))?;

    // Derive KEK
    let kek = derive_kek(master_password, &kek_salt);

    // Wrap the DEK
    let (wrapped_dek, wrapped_dek_nonce) = wrap_dek(&kek, dek)?;

    // Encrypt the vault data
    let (vault_ciphertext, vault_nonce) = encrypt_vault_data(dek, vault)?;

    let vf = VaultFileV2 {
        version: 2,
        kek_salt: hex::encode(kek_salt),
        wrapped_dek_nonce: hex::encode(wrapped_dek_nonce),
        wrapped_dek: hex::encode(wrapped_dek),
        vault_nonce: hex::encode(vault_nonce),
        vault_ciphertext: hex::encode(vault_ciphertext),
        entropy_source: entropy_source.to_string(),
        updated_at: unix_now(),
    };

    let contents = serde_json::to_string_pretty(&vf).context("Failed to serialize vault file")?;
    std::fs::write(vault_path(), contents).context("Failed to write vault file")?;
    Ok(())
}

/// Rotate the DEK: re-encrypt vault data with a new DEK, re-wrap with KEK.
/// Returns the new DEK so caller can store it in memory.
pub fn rotate_dek(
    vault: &Vault,
    master_password: &str,
    new_dek: &[u8; 32],
    entropy_source: &str,
) -> Result<()> {
    save_vault(vault, master_password, new_dek, entropy_source)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_vault_path() -> PathBuf {
        PathBuf::from("/tmp/test_traffic_cypher_vault.json")
    }

    /// Helper: override vault path for tests
    fn with_test_vault<F: FnOnce()>(f: F) {
        let path = test_vault_path();
        // Clean up before
        let _ = fs::remove_file(&path);
        // Override vault path for this test
        std::env::set_var("TRAFFIC_CYPHER_VAULT_PATH", path.to_str().unwrap());
        f();
        // Clean up after
        let _ = fs::remove_file(&path);
        std::env::remove_var("TRAFFIC_CYPHER_VAULT_PATH");
    }

    #[test]
    fn test_kek_derivation_deterministic() {
        let salt = [42u8; 32];
        let kek1 = derive_kek("mypassword", &salt);
        let kek2 = derive_kek("mypassword", &salt);
        assert_eq!(kek1, kek2);
    }

    #[test]
    fn test_kek_different_passwords() {
        let salt = [42u8; 32];
        let kek1 = derive_kek("password1", &salt);
        let kek2 = derive_kek("password2", &salt);
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn test_dek_wrap_unwrap() {
        let kek = derive_kek("testpass", &[1u8; 32]);
        let dek = generate_dek_from_os();
        let (wrapped, nonce) = wrap_dek(&kek, &dek).unwrap();
        let unwrapped = unwrap_dek(&kek, &wrapped, &nonce).unwrap();
        assert_eq!(dek, unwrapped);
    }

    #[test]
    fn test_dek_unwrap_wrong_password() {
        let kek_right = derive_kek("rightpass", &[1u8; 32]);
        let kek_wrong = derive_kek("wrongpass", &[1u8; 32]);
        let dek = generate_dek_from_os();
        let (wrapped, nonce) = wrap_dek(&kek_right, &dek).unwrap();
        let result = unwrap_dek(&kek_wrong, &wrapped, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_encrypt_decrypt() {
        let dek = generate_dek_from_os();
        let mut vault = Vault::default();
        vault.entries.push(VaultEntry::new(
            "Test".to_string(),
            Some("https://example.com".to_string()),
            Some("user@test.com".to_string()),
            "supersecret".to_string(),
            None,
            None,
            vec!["test".to_string()],
        ));

        let (ciphertext, nonce) = encrypt_vault_data(&dek, &vault).unwrap();
        let decrypted = decrypt_vault_data(&dek, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted.entries.len(), 1);
        assert_eq!(decrypted.entries[0].label, "Test");
        assert_eq!(decrypted.entries[0].password, "supersecret");
    }

    #[test]
    fn test_full_save_load_cycle() {
        with_test_vault(|| {
            let master_pw = "my_master_password";
            let dek = generate_dek_from_os();

            let mut vault = Vault::default();
            vault.entries.push(VaultEntry::new(
                "GitHub".to_string(),
                Some("https://github.com".to_string()),
                Some("dev@example.com".to_string()),
                "gh_secret_123".to_string(),
                None,
                Some("My GitHub account".to_string()),
                vec!["dev".to_string(), "code".to_string()],
            ));

            // Save
            save_vault(&vault, master_pw, &dek, "os").unwrap();

            // Load
            let unlocked = load_vault(master_pw).unwrap();
            assert_eq!(unlocked.vault.entries.len(), 1);
            assert_eq!(unlocked.vault.entries[0].label, "GitHub");
            assert_eq!(unlocked.vault.entries[0].password, "gh_secret_123");
            assert_eq!(unlocked.entropy_source, "os");

            // Verify DEK matches
            assert_eq!(unlocked.dek, dek);
        });
    }

    #[test]
    fn test_wrong_password_load_fails() {
        with_test_vault(|| {
            let dek = generate_dek_from_os();
            let vault = Vault::default();

            save_vault(&vault, "correct_password", &dek, "os").unwrap();

            let result = load_vault("wrong_password");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_dek_rotation() {
        with_test_vault(|| {
            let master_pw = "rotation_test";
            let dek1 = generate_dek_from_os();

            let mut vault = Vault::default();
            vault.entries.push(VaultEntry::new(
                "Test Entry".to_string(),
                None, None,
                "original_password".to_string(),
                None, None, vec![],
            ));

            // Save with original DEK
            save_vault(&vault, master_pw, &dek1, "os").unwrap();

            // Rotate to a new DEK
            let dek2 = generate_dek_from_os();
            assert_ne!(dek1, dek2);
            rotate_dek(&vault, master_pw, &dek2, "traffic").unwrap();

            // Load with same master password — should work with new DEK
            let unlocked = load_vault(master_pw).unwrap();
            assert_eq!(unlocked.vault.entries.len(), 1);
            assert_eq!(unlocked.vault.entries[0].password, "original_password");
            assert_eq!(unlocked.dek, dek2);
            assert_eq!(unlocked.entropy_source, "traffic");
        });
    }

    #[test]
    fn test_traffic_dek_generation() {
        let entropy = [0xAB; 64];
        let dek1 = generate_dek_from_traffic(&entropy);
        let dek2 = generate_dek_from_traffic(&entropy);
        // Each call uses a random salt, so results should differ
        assert_ne!(dek1, dek2);
        // But both should be 32 bytes
        assert_eq!(dek1.len(), 32);
        assert_eq!(dek2.len(), 32);
    }
}
