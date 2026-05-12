use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Argon2id parameters for the *current* vault format (v3).
//
// OWASP 2024 second-tier defaults: 64 MiB memory, 3 iterations, 1 lane.
// On a 2024 MacBook Pro this lands at ~250-400 ms per derivation — slow
// enough to make offline brute-force of a stolen vault infeasible, fast
// enough that an interactive unlock still feels responsive.
//
// These three values are persisted in the vault file (`kdf_m_cost` etc.),
// so a future parameter bump never bricks an existing vault: on load we
// always use the params the file itself records.
// ---------------------------------------------------------------------------
pub const ARGON2ID_M_COST: u32 = 65536; // 64 MiB
pub const ARGON2ID_T_COST: u32 = 3;
pub const ARGON2ID_P_COST: u32 = 1;

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
                        .is_some_and(|u| u.to_lowercase().contains(&q))
                    || e.website
                        .as_deref()
                        .is_some_and(|w| w.to_lowercase().contains(&q))
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// On-disk formats
//
// v2 (legacy): KEK derived via HKDF-SHA256 from the master password. No work
// factor — brute-forceable at HKDF speed. Still read for backward-compat;
// every v2 file is silently upgraded to v3 on the next save.
//
// v3 (current): KEK derived via Argon2id with parameters persisted in the
// file. Same envelope-encryption shape; only the KDF differs.
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

#[derive(Serialize, Deserialize)]
struct VaultFileV3 {
    version: u8,
    /// KDF identifier. Always "argon2id" for v3 files.
    kdf: String,
    /// Argon2id memory cost in KiB (e.g. 65536 = 64 MiB).
    kdf_m_cost: u32,
    /// Argon2id time cost / passes.
    kdf_t_cost: u32,
    /// Argon2id parallelism (lanes).
    kdf_p_cost: u32,
    /// Salt fed to Argon2id (random 32 bytes per save).
    kek_salt: String,
    wrapped_dek_nonce: String,
    wrapped_dek: String,
    vault_nonce: String,
    vault_ciphertext: String,
    entropy_source: String,
    updated_at: u64,
}

/// Minimal "what version is this?" probe before committing to a full
/// V2 or V3 deserialization. Keeps the error path predictable on
/// future bumps.
#[derive(Deserialize)]
struct VaultFileVersion {
    version: u8,
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
    atomic_write(&stream_config_path(), contents.as_bytes())
        .context("Failed to write stream config")?;
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

/// Derive a 256-bit Key Encryption Key (KEK) from master password + salt
/// using the *legacy* HKDF-SHA256 construction (vault file v2).
///
/// HKDF has no work factor — an attacker with the vault file can iterate
/// this function as fast as raw hashing. Kept only so we can still read
/// existing v2 vaults; new saves go through `derive_kek_argon2id`.
fn derive_kek_hkdf(master_password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_password.as_bytes());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"traffic-cypher-kek-v2", &mut *kek)
        .expect("HKDF expand failed");
    kek
}

/// Derive a 256-bit Key Encryption Key (KEK) from master password + salt
/// using Argon2id with the supplied work parameters (vault file v3).
///
/// Returns the KEK wrapped in `Zeroizing` so it is overwritten on drop.
/// Errors only on parameter validation failure — runtime derivation cannot
/// fail given a 32-byte output and a non-empty password.
fn derive_kek_argon2id(
    master_password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2id parameters (m={}, t={}, p={}): {}",
                             m_cost, t_cost, p_cost, e))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; 32]);
    a.hash_password_into(master_password.as_bytes(), salt, &mut *kek)
        .map_err(|e| anyhow!("Argon2id derivation failed: {}", e))?;
    Ok(kek)
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
/// Returns the DEK wrapped in `Zeroizing` so it is overwritten on drop.
/// The intermediate `Vec<u8>` returned by AES-GCM is also wrapped so its
/// backing heap allocation is zeroed before being freed.
fn unwrap_dek(
    kek: &[u8; 32],
    wrapped_dek: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Zeroizing<[u8; 32]>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Nonce::from_slice(nonce_bytes);
    let dek_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(nonce, wrapped_dek)
            .map_err(|_| anyhow!("Failed to unwrap DEK — wrong master password?"))?,
    );
    if dek_bytes.len() != 32 {
        return Err(anyhow!("Unwrapped DEK has wrong length"));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
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
/// The decrypted JSON bytes are held in a `Zeroizing<Vec<u8>>` so the
/// heap allocation is overwritten before being freed.
fn decrypt_vault_data(
    dek: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vault> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Vault decryption failed — data may be corrupt"))?,
    );
    serde_json::from_slice(plaintext.as_slice()).context("Failed to parse vault contents")
}

// ---------------------------------------------------------------------------
// Public API: Load / Save / Rotate
// ---------------------------------------------------------------------------

/// Result of loading the vault: contains the decrypted vault and the unwrapped DEK.
///
/// The `dek` field is `Zeroizing` so its bytes are overwritten on drop.
///
/// `needs_upgrade` is `true` when the file we just read was in the legacy v2
/// (HKDF-derived KEK) format. Callers don't need to do anything special —
/// the *next* `save_vault` automatically writes v3, transparently migrating
/// the user to Argon2id. The flag is exposed so the unlock site can log
/// the upgrade for the operator.
pub struct UnlockedVault {
    pub vault: Vault,
    pub dek: Zeroizing<[u8; 32]>,
    pub entropy_source: String,
    pub needs_upgrade: bool,
}

/// Load and decrypt the vault using only the master password.
///
/// Returns the vault data plus the unwrapped DEK (needed for subsequent
/// saves). If no vault file exists, creates a new vault with an
/// OS-entropy DEK.
///
/// Branches on `version`:
/// - `2` → legacy HKDF KEK derivation; `needs_upgrade` set so the next
///   save bumps the file to v3.
/// - `3` → Argon2id KEK derivation using the persisted params.
/// - anything else → hard error.
///
/// Logs the time spent in KDF at `info` level so a ~300 ms unlock pause
/// looks intentional in the operator's log, not like a hang.
pub fn load_vault(master_password: &str) -> Result<UnlockedVault> {
    let path = vault_path();
    if !path.exists() {
        // First time: generate a DEK from OS entropy, return empty vault
        let dek = Zeroizing::new(generate_dek_from_os());
        return Ok(UnlockedVault {
            vault: Vault::default(),
            dek,
            entropy_source: "os".to_string(),
            needs_upgrade: false,
        });
    }

    let contents = std::fs::read_to_string(&path).context("Failed to read vault file")?;

    // Peek at version before committing to a struct shape.
    let probe: VaultFileVersion = serde_json::from_str(&contents)
        .context("Vault file is corrupt (missing or invalid `version`)")?;

    match probe.version {
        2 => load_vault_v2(master_password, &contents),
        3 => load_vault_v3(master_password, &contents),
        other => Err(anyhow!(
            "Unsupported vault version {} (this build understands v2 and v3)",
            other
        )),
    }
}

fn load_vault_v2(master_password: &str, contents: &str) -> Result<UnlockedVault> {
    let vf: VaultFileV2 =
        serde_json::from_str(contents).context("Vault v2 file is corrupt")?;

    let kek_salt = hex::decode(&vf.kek_salt).context("Invalid kek_salt")?;
    let (wdn, vn, wrapped_dek, vault_ciphertext) = decode_envelope_fields(
        &vf.wrapped_dek_nonce,
        &vf.wrapped_dek,
        &vf.vault_nonce,
        &vf.vault_ciphertext,
    )?;

    // Legacy HKDF KEK. Microseconds — no need to time-log it.
    let kek = derive_kek_hkdf(master_password, &kek_salt);
    tracing::info!(
        "Loaded v2 vault — will auto-upgrade to v3 (Argon2id) on next save"
    );

    let dek = unwrap_dek(&kek, &wrapped_dek, &wdn)?;
    let vault = decrypt_vault_data(&dek, &vault_ciphertext, &vn)?;

    Ok(UnlockedVault {
        vault,
        dek,
        entropy_source: vf.entropy_source,
        needs_upgrade: true,
    })
}

fn load_vault_v3(master_password: &str, contents: &str) -> Result<UnlockedVault> {
    let vf: VaultFileV3 =
        serde_json::from_str(contents).context("Vault v3 file is corrupt")?;

    if vf.kdf != "argon2id" {
        return Err(anyhow!(
            "Vault v3 file declares unsupported KDF '{}' (expected 'argon2id')",
            vf.kdf
        ));
    }

    let kek_salt = hex::decode(&vf.kek_salt).context("Invalid kek_salt")?;
    let (wdn, vn, wrapped_dek, vault_ciphertext) = decode_envelope_fields(
        &vf.wrapped_dek_nonce,
        &vf.wrapped_dek,
        &vf.vault_nonce,
        &vf.vault_ciphertext,
    )?;

    // Argon2id derivation: ~250-400 ms. Timed and logged so the pause
    // visible to the user is also visible in the operator log.
    let t0 = Instant::now();
    let kek = derive_kek_argon2id(
        master_password,
        &kek_salt,
        vf.kdf_m_cost,
        vf.kdf_t_cost,
        vf.kdf_p_cost,
    )?;
    tracing::info!(
        "Deriving key... {} ms (Argon2id m={}KiB t={} p={})",
        t0.elapsed().as_millis(),
        vf.kdf_m_cost,
        vf.kdf_t_cost,
        vf.kdf_p_cost,
    );

    let dek = unwrap_dek(&kek, &wrapped_dek, &wdn)?;
    let vault = decrypt_vault_data(&dek, &vault_ciphertext, &vn)?;

    Ok(UnlockedVault {
        vault,
        dek,
        entropy_source: vf.entropy_source,
        needs_upgrade: false,
    })
}

/// Shared hex-decoding + length-validation for the four envelope fields
/// that are identical between v2 and v3.
fn decode_envelope_fields(
    wrapped_dek_nonce: &str,
    wrapped_dek: &str,
    vault_nonce: &str,
    vault_ciphertext: &str,
) -> Result<([u8; 12], [u8; 12], Vec<u8>, Vec<u8>)> {
    let wdn_bytes = hex::decode(wrapped_dek_nonce).context("Invalid wrapped_dek_nonce")?;
    let wrapped_dek = hex::decode(wrapped_dek).context("Invalid wrapped_dek")?;
    let vn_bytes = hex::decode(vault_nonce).context("Invalid vault_nonce")?;
    let vault_ciphertext = hex::decode(vault_ciphertext).context("Invalid vault_ciphertext")?;

    if wdn_bytes.len() != 12 {
        return Err(anyhow!("wrapped_dek_nonce has wrong length"));
    }
    if vn_bytes.len() != 12 {
        return Err(anyhow!("vault_nonce has wrong length"));
    }

    let mut wdn = [0u8; 12];
    wdn.copy_from_slice(&wdn_bytes);
    let mut vn = [0u8; 12];
    vn.copy_from_slice(&vn_bytes);
    Ok((wdn, vn, wrapped_dek, vault_ciphertext))
}

/// Encrypt and save the vault to disk.
///
/// Always writes the current format (v3 / Argon2id). A v2 file is therefore
/// silently upgraded the next time it is saved — no user prompt, no special
/// migration step.
///
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

    // Derive KEK via Argon2id (current params). Timed; logged so a slow save
    // is visible in the log.
    let t0 = Instant::now();
    let kek = derive_kek_argon2id(
        master_password,
        &kek_salt,
        ARGON2ID_M_COST,
        ARGON2ID_T_COST,
        ARGON2ID_P_COST,
    )?;
    tracing::info!(
        "Deriving key (save)... {} ms (Argon2id m={}KiB t={} p={})",
        t0.elapsed().as_millis(),
        ARGON2ID_M_COST,
        ARGON2ID_T_COST,
        ARGON2ID_P_COST,
    );

    // Wrap the DEK
    let (wrapped_dek, wrapped_dek_nonce) = wrap_dek(&kek, dek)?;

    // Encrypt the vault data
    let (vault_ciphertext, vault_nonce) = encrypt_vault_data(dek, vault)?;

    let vf = VaultFileV3 {
        version: 3,
        kdf: "argon2id".to_string(),
        kdf_m_cost: ARGON2ID_M_COST,
        kdf_t_cost: ARGON2ID_T_COST,
        kdf_p_cost: ARGON2ID_P_COST,
        kek_salt: hex::encode(kek_salt),
        wrapped_dek_nonce: hex::encode(wrapped_dek_nonce),
        wrapped_dek: hex::encode(wrapped_dek),
        vault_nonce: hex::encode(vault_nonce),
        vault_ciphertext: hex::encode(vault_ciphertext),
        entropy_source: entropy_source.to_string(),
        updated_at: unix_now(),
    };

    let contents = serde_json::to_string_pretty(&vf).context("Failed to serialize vault file")?;
    atomic_write(&vault_path(), contents.as_bytes()).context("Failed to write vault file")?;
    Ok(())
}

/// Atomically write `contents` to `path` using the tmp+fsync+rename pattern.
///
/// Process: write a sibling `<path>.tmp`, fsync the file (so contents hit the
/// platter, not just the page cache), then `rename` over the target.
/// `rename` is atomic on POSIX. On modern Windows (10+) `std::fs::rename`
/// also atomically replaces an existing destination, so no platform fork is
/// needed here.
///
/// If any step fails the tmp file is cleaned up on a best-effort basis so we
/// don't leave orphans behind.
fn atomic_write(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    let tmp = {
        let mut t = path.as_os_str().to_owned();
        t.push(".tmp");
        std::path::PathBuf::from(t)
    };

    let write_and_sync = || -> Result<()> {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("Failed to create tmp file {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, contents)
            .with_context(|| format!("Failed to write tmp file {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("Failed to fsync tmp file {}", tmp.display()))?;
        Ok(())
    };

    if let Err(e) = write_and_sync() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context(format!(
            "Failed to rename {} -> {}",
            tmp.display(),
            path.display()
        )));
    }
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

    /// Helper: override vault path for tests with a unique-per-test path
    /// so tests can run concurrently (cargo test runs threads by default).
    /// Note: TRAFFIC_CYPHER_VAULT_PATH is a process-global env var, so this
    /// helper still requires `--test-threads=1` for full isolation. Using a
    /// unique path per call additionally protects against stale files from
    /// previous runs.
    fn with_test_vault<F: FnOnce()>(tag: &str, f: F) {
        let path = std::env::temp_dir()
            .join(format!("test_traffic_cypher_vault_{}_{}.json",
                          tag, std::process::id()));
        // Clean up before
        let _ = fs::remove_file(&path);
        std::env::set_var("TRAFFIC_CYPHER_VAULT_PATH", path.to_str().unwrap());
        f();
        let _ = fs::remove_file(&path);
        std::env::remove_var("TRAFFIC_CYPHER_VAULT_PATH");
    }

    /// Convenience: deterministic Argon2id KEK with the current production
    /// params. Used by several wrap/unwrap tests below — keeps the test
    /// surface focused without re-typing the params each time.
    fn test_kek(password: &str, salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        derive_kek_argon2id(
            password,
            salt,
            ARGON2ID_M_COST,
            ARGON2ID_T_COST,
            ARGON2ID_P_COST,
        )
        .expect("argon2id derive")
    }

    #[test]
    fn test_kek_derivation_deterministic() {
        let salt = [42u8; 32];
        let kek1 = derive_kek_hkdf("mypassword", &salt);
        let kek2 = derive_kek_hkdf("mypassword", &salt);
        assert_eq!(kek1, kek2);
    }

    #[test]
    fn test_kek_different_passwords() {
        let salt = [42u8; 32];
        let kek1 = derive_kek_hkdf("password1", &salt);
        let kek2 = derive_kek_hkdf("password2", &salt);
        assert_ne!(kek1, kek2);
    }

    /// Argon2id KEK is deterministic given the same (password, salt, params)
    /// — this is what makes envelope decryption work.
    #[test]
    fn test_argon2id_kek_deterministic() {
        let salt = [7u8; 32];
        let kek1 = test_kek("mypassword", &salt);
        let kek2 = test_kek("mypassword", &salt);
        assert_eq!(*kek1, *kek2);
    }

    /// Argon2id is parameter-sensitive. Different t_cost MUST produce a
    /// different KEK, otherwise persisting the params is pointless.
    #[test]
    fn test_argon2id_kek_params_matter() {
        let salt = [7u8; 32];
        let kek_t3 = derive_kek_argon2id("pw", &salt, 65536, 3, 1).unwrap();
        let kek_t4 = derive_kek_argon2id("pw", &salt, 65536, 4, 1).unwrap();
        assert_ne!(*kek_t3, *kek_t4);
    }

    /// Cross-impl KAT. The expected output was pinned once with the
    /// RustCrypto `argon2 = 0.5` crate (see `examples/argon2_kat.rs`).
    /// Both Rust and C builds MUST produce this exact KEK from the inputs
    /// in `test_fixtures/argon2id_kek_kat.json` — drift between the two
    /// implementations is a cross-impl crypto regression.
    #[test]
    fn test_argon2id_kek_kat() {
        // include_str! pins the fixture into the test binary so test runs
        // don't depend on the harness's working directory.
        const FIXTURE: &str =
            include_str!("../../test_fixtures/argon2id_kek_kat.json");
        let v: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("parse KAT fixture");

        let password = v["password"].as_str().unwrap();
        let salt = hex::decode(v["salt_hex"].as_str().unwrap()).unwrap();
        let m_cost = v["m_cost"].as_u64().unwrap() as u32;
        let t_cost = v["t_cost"].as_u64().unwrap() as u32;
        let p_cost = v["p_cost"].as_u64().unwrap() as u32;
        let expected_hex = v["expected_kek_hex"].as_str().unwrap();

        let kek = derive_kek_argon2id(password, &salt, m_cost, t_cost, p_cost)
            .expect("derive");
        assert_eq!(hex::encode(&*kek), expected_hex,
            "Argon2id KEK output diverged from pinned KAT — check the argon2 \
             crate version, Algorithm/Version flags, and parameter wiring.");
    }

    #[test]
    fn test_dek_wrap_unwrap() {
        let kek = test_kek("testpass", &[1u8; 32]);
        let dek = generate_dek_from_os();
        let (wrapped, nonce) = wrap_dek(&kek, &dek).unwrap();
        let unwrapped = unwrap_dek(&kek, &wrapped, &nonce).unwrap();
        assert_eq!(dek, *unwrapped);
    }

    #[test]
    fn test_dek_unwrap_wrong_password() {
        let kek_right = test_kek("rightpass", &[1u8; 32]);
        let kek_wrong = test_kek("wrongpass", &[1u8; 32]);
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
        with_test_vault("save_load", || {
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
            assert_eq!(*unlocked.dek, dek);
        });
    }

    #[test]
    fn test_wrong_password_load_fails() {
        with_test_vault("wrong_pw", || {
            let dek = generate_dek_from_os();
            let vault = Vault::default();

            save_vault(&vault, "correct_password", &dek, "os").unwrap();

            let result = load_vault("wrong_password");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_dek_rotation() {
        with_test_vault("rotate", || {
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
            assert_eq!(*unlocked.dek, dek2);
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

    /// save_vault always writes the current format (v3 + argon2id + persisted
    /// params). If this asserts fails the schema has silently regressed.
    #[test]
    fn test_save_writes_v3() {
        with_test_vault("save_v3", || {
            let dek = generate_dek_from_os();
            save_vault(&Vault::default(), "pw", &dek, "os").unwrap();
            let contents = std::fs::read_to_string(vault_path()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&contents).unwrap();
            assert_eq!(v["version"], 3);
            assert_eq!(v["kdf"], "argon2id");
            assert_eq!(v["kdf_m_cost"], 65536);
            assert_eq!(v["kdf_t_cost"], 3);
            assert_eq!(v["kdf_p_cost"], 1);
        });
    }

    /// v2 -> v3 auto-upgrade. Loading the bundled v2 fixture must succeed,
    /// surface `needs_upgrade=true`, and saving once must rewrite the file
    /// as v3 with the same plaintext recoverable.
    #[test]
    fn test_v2_to_v3_auto_upgrade() {
        with_test_vault("v2_upgrade", || {
            // Drop the bundled v2 fixture in place.
            const V2_FIXTURE: &str =
                include_str!("../../test_fixtures/sample_vault_v2.json");
            std::fs::write(vault_path(), V2_FIXTURE).unwrap();

            // 1. Load with the right password — works through the v2 path.
            let unlocked = load_vault("upgrade-fixture-pw")
                .expect("load v2 fixture");
            assert!(unlocked.needs_upgrade, "v2 file must flag needs_upgrade");
            assert_eq!(unlocked.vault.entries.len(), 1);
            assert_eq!(unlocked.vault.entries[0].label, "v2-upgrade-test");
            assert_eq!(unlocked.vault.entries[0].password,
                       "v2-secret-do-not-lose");

            // 2. Save: writes v3.
            save_vault(&unlocked.vault, "upgrade-fixture-pw",
                       &unlocked.dek, &unlocked.entropy_source).unwrap();

            let after = std::fs::read_to_string(vault_path()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&after).unwrap();
            assert_eq!(v["version"], 3, "save must upgrade v2 -> v3");
            assert_eq!(v["kdf"], "argon2id");

            // 3. Reload (via v3 path) — content preserved.
            let reloaded = load_vault("upgrade-fixture-pw")
                .expect("reload after upgrade");
            assert!(!reloaded.needs_upgrade);
            assert_eq!(reloaded.vault.entries.len(), 1);
            assert_eq!(reloaded.vault.entries[0].password,
                       "v2-secret-do-not-lose");
        });
    }

    /// Unsupported `version` must be a hard error — neither a panic nor
    /// silent dispatch to v2/v3.
    #[test]
    fn test_unknown_version_rejected() {
        with_test_vault("bad_version", || {
            // Minimal file with a future version. Other fields are absent;
            // the version-probe step fails first, so they don't need to be
            // valid.
            std::fs::write(vault_path(),
                r#"{"version": 99, "kek_salt": "00"}"#).unwrap();
            let err = match load_vault("anything") {
                Ok(_) => panic!("expected load_vault to fail on version=99"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("Unsupported vault version 99"),
                    "got: {}", err);
        });
    }
}
