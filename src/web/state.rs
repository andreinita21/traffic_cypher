use crate::key_rotation::KeyRotationState;
use crate::multi_stream::MultiStreamManager;
use crate::vault::Vault;

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

pub struct AppState {
    pub session_token: Arc<RwLock<Option<String>>>,
    pub master_password: Arc<RwLock<String>>,
    pub vault: Arc<RwLock<Vault>>,
    pub is_unlocked: Arc<RwLock<bool>>,
    pub stream_manager: Arc<Mutex<MultiStreamManager>>,
    pub rotation_state: Arc<KeyRotationState>,
    pub last_activity: Arc<RwLock<Instant>>,
    pub auto_lock_minutes: Arc<RwLock<u64>>,
    pub rotation_cancel: Arc<RwLock<Option<tokio::sync::watch::Sender<bool>>>>,
    /// The unwrapped Data Encryption Key — held in memory only while unlocked
    pub current_dek: Arc<RwLock<Option<[u8; 32]>>>,
    /// Where the current DEK's entropy came from ("traffic" or "os")
    pub entropy_source: Arc<RwLock<String>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session_token: Arc::new(RwLock::new(None)),
            master_password: Arc::new(RwLock::new(String::new())),
            vault: Arc::new(RwLock::new(Vault::default())),
            is_unlocked: Arc::new(RwLock::new(false)),
            stream_manager: Arc::new(Mutex::new(MultiStreamManager::new())),
            rotation_state: Arc::new(KeyRotationState::new()),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            auto_lock_minutes: Arc::new(RwLock::new(5)),
            rotation_cancel: Arc::new(RwLock::new(None)),
            current_dek: Arc::new(RwLock::new(None)),
            entropy_source: Arc::new(RwLock::new("os".to_string())),
        }
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
