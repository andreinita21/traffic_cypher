use crate::entropy_extractor;
use crate::entropy_pool::EntropyPool;
use crate::multi_stream::MultiStreamManager;
use crate::system_entropy_mixer;
use crate::crypto_derivation;
use crate::vault;

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

/// Shared state for the key rotation daemon.
pub struct KeyRotationState {
    pub current_key: Arc<RwLock<Vec<u8>>>,
    pub key_epoch: Arc<RwLock<u64>>,
    pub frames_processed: Arc<RwLock<u64>>,
    pub pool_depth: Arc<RwLock<usize>>,
    pub is_running: Arc<RwLock<bool>>,
}

impl KeyRotationState {
    pub fn new() -> Self {
        Self {
            current_key: Arc::new(RwLock::new(vec![0u8; 32])),
            key_epoch: Arc::new(RwLock::new(0)),
            frames_processed: Arc::new(RwLock::new(0)),
            pool_depth: Arc::new(RwLock::new(0)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn status(&self) -> KeyRotationStatus {
        KeyRotationStatus {
            key_epoch: *self.key_epoch.read().await,
            frames_processed: *self.frames_processed.read().await,
            pool_depth: *self.pool_depth.read().await,
            is_running: *self.is_running.read().await,
        }
    }
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct KeyRotationStatus {
    pub key_epoch: u64,
    pub frames_processed: u64,
    pub pool_depth: usize,
    pub is_running: bool,
}

/// Start the key rotation daemon. Runs every 1 second:
/// 1. Pick a random frame from multi-stream manager
/// 2. Extract entropy → feed pool → mix → derive key
/// 3. Re-encrypt vault with compound key (master_password + traffic_key)
/// 4. Update shared state
pub async fn start_rotation_daemon(
    stream_manager: Arc<Mutex<MultiStreamManager>>,
    rotation_state: Arc<KeyRotationState>,
    master_password: Arc<RwLock<String>>,
    vault_data: Arc<RwLock<vault::Vault>>,
    cancel: tokio::sync::watch::Receiver<bool>,
) {
    info!("Key rotation daemon starting");
    *rotation_state.is_running.write().await = true;

    let mut ticker = interval(Duration::from_secs(1));
    let mut pool = EntropyPool::new(8);
    let mut previous_frame_data: Option<Vec<u8>> = None;
    let mut previous_key: Option<Vec<u8>> = None;
    let mut epoch: u64 = 0;
    let mut frames_total: u64 = 0;
    let mut cancel = cancel;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Try to pick a frame from available streams
                let frame_opt = {
                    let mut mgr = stream_manager.lock().await;
                    mgr.pick_random_frame()
                };

                if let Some(frame) = frame_opt {
                    // Extract entropy from the frame
                    let extracted = entropy_extractor::extract_entropy(
                        &frame.data,
                        previous_frame_data.as_deref(),
                        frame.width,
                        frame.height,
                    );

                    // Feed entropy pool
                    pool.push(extracted.entropy_bytes);
                    let pool_digest = pool.digest();

                    // Mix with system entropy
                    let mixed_seed = system_entropy_mixer::mix_entropy(&pool_digest);

                    // Derive new key with chaining
                    let new_key = crypto_derivation::derive_key(
                        &mixed_seed,
                        previous_key.as_deref(),
                        32,
                    );

                    epoch += 1;
                    frames_total += 1;

                    // Re-encrypt vault with compound key
                    {
                        let master = master_password.read().await;
                        let v = vault_data.read().await;
                        if let Err(e) = vault::save_vault(&v, &master, Some(&new_key)) {
                            error!("Failed to re-encrypt vault: {}", e);
                        }
                    }

                    // Update shared state
                    *rotation_state.current_key.write().await = new_key.clone();
                    *rotation_state.key_epoch.write().await = epoch;
                    *rotation_state.frames_processed.write().await = frames_total;
                    *rotation_state.pool_depth.write().await = pool.len();

                    previous_frame_data = Some(frame.data);
                    previous_key = Some(new_key);

                    debug!("Key rotation epoch {} (pool depth: {})", epoch, pool.len());
                } else {
                    // No frame available — still tick the epoch using OS entropy only
                    let mut os_seed = [0u8; 32];
                    getrandom::getrandom(&mut os_seed).ok();
                    let mixed = system_entropy_mixer::mix_entropy(&os_seed);
                    let new_key = crypto_derivation::derive_key(
                        &mixed,
                        previous_key.as_deref(),
                        32,
                    );

                    epoch += 1;

                    // Re-encrypt with OS-only key if we have a previous key
                    {
                        let master = master_password.read().await;
                        let v = vault_data.read().await;
                        if let Err(e) = vault::save_vault(&v, &master, Some(&new_key)) {
                            debug!("Vault re-encrypt (OS-only): {}", e);
                        }
                    }

                    *rotation_state.current_key.write().await = new_key.clone();
                    *rotation_state.key_epoch.write().await = epoch;
                    *rotation_state.pool_depth.write().await = pool.len();

                    previous_key = Some(new_key);

                    debug!("Key rotation epoch {} (no stream frame, OS entropy only)", epoch);
                }
            }
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    info!("Key rotation daemon stopping");
                    break;
                }
            }
        }
    }

    *rotation_state.is_running.write().await = false;
    info!("Key rotation daemon stopped at epoch {}", epoch);
}
