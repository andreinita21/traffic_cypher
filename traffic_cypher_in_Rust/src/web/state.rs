use crate::key_rotation::KeyRotationState;
use crate::multi_stream::MultiStreamManager;
use crate::vault::Vault;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

pub struct AppState {
    pub session_token: Arc<RwLock<Option<String>>>,
    /// The master password — wrapped in `Zeroizing` so its heap buffer is
    /// overwritten when the value is replaced or dropped.
    pub master_password: Arc<RwLock<Zeroizing<String>>>,
    pub vault: Arc<RwLock<Vault>>,
    pub is_unlocked: Arc<RwLock<bool>>,
    pub stream_manager: Arc<Mutex<MultiStreamManager>>,
    pub rotation_state: Arc<KeyRotationState>,
    pub last_activity: Arc<RwLock<Instant>>,
    pub auto_lock_minutes: Arc<RwLock<u64>>,
    pub rotation_cancel: Arc<RwLock<Option<tokio::sync::watch::Sender<bool>>>>,
    /// The unwrapped Data Encryption Key — held in memory only while unlocked.
    /// `Zeroizing<[u8; 32]>` ensures the key bytes are wiped on drop / replace.
    pub current_dek: Arc<RwLock<Option<Zeroizing<[u8; 32]>>>>,
    /// Where the current DEK's entropy came from ("traffic" or "os")
    pub entropy_source: Arc<RwLock<String>>,
    /// Sliding-window timestamps of the last 5 failed `/api/auth/unlock`
    /// attempts. When all 5 fall within 60 s, the next attempt triggers a
    /// 30 s lockout. Process-lifetime only — restart clears it.
    pub unlock_failure_times: Arc<RwLock<[Option<Instant>; 5]>>,
    /// If `Some(t)`, all unlock attempts return 429 until `Instant::now() >= t`.
    /// Set when the 5-in-60s threshold trips; cleared on success or expiry.
    pub unlock_lockout_until: Arc<RwLock<Option<Instant>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session_token: Arc::new(RwLock::new(None)),
            master_password: Arc::new(RwLock::new(Zeroizing::new(String::new()))),
            vault: Arc::new(RwLock::new(Vault::default())),
            is_unlocked: Arc::new(RwLock::new(false)),
            stream_manager: Arc::new(Mutex::new(MultiStreamManager::new())),
            rotation_state: Arc::new(KeyRotationState::new()),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            auto_lock_minutes: Arc::new(RwLock::new(5)),
            rotation_cancel: Arc::new(RwLock::new(None)),
            current_dek: Arc::new(RwLock::new(None)),
            entropy_source: Arc::new(RwLock::new("os".to_string())),
            unlock_failure_times: Arc::new(RwLock::new([None; 5])),
            unlock_lockout_until: Arc::new(RwLock::new(None)),
        }
    }

    /// Test-only constructor: points the vault at `vault_path` (a fresh
    /// `tempfile::tempdir()` per test) so HTTP integration tests in
    /// `tests/http.rs` can exercise the real `web::create_router` without
    /// clobbering the developer's `$HOME/.traffic_cypher_vault.json`.
    ///
    /// Implementation note: this sets the `TRAFFIC_CYPHER_VAULT_PATH` env
    /// var, which `vault::vault_path()` reads on every call. The simpler
    /// alternative — threading an override field through `AppState` — would
    /// require plumbing `&AppState` into the many free-function call sites
    /// in `vault.rs`, which is out of scope for this PR.
    ///
    /// THREADING CONSTRAINT: because the env var is process-global, tests
    /// using `for_test` MUST run with `--test-threads=1`. `tests/17_rust_http.sh`
    /// enforces this. This matches the existing constraint already documented
    /// on `tests/10_rust_unit_tests.sh`.
    pub fn for_test(vault_path: PathBuf) -> Self {
        // SAFETY: env vars are process-global. Tests that use this constructor
        // must run serially (see doc comment above).
        std::env::set_var("TRAFFIC_CYPHER_VAULT_PATH", &vault_path);
        Self::new()
    }

    pub async fn touch_activity(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    pub async fn check_auto_lock(&self) -> bool {
        let last = *self.last_activity.read().await;
        let timeout_mins = *self.auto_lock_minutes.read().await;
        let elapsed = Instant::now().duration_since(last);
        elapsed.as_secs() > timeout_mins * 60
    }
}
