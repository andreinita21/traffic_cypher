use crate::entropy_extractor;
use crate::entropy_pool::EntropyPool;
use crate::multi_stream::MultiStreamManager;
use crate::system_entropy_mixer;
use crate::crypto_derivation;

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, info};

/// Shared state for the key rotation daemon.
/// Now accumulates traffic entropy for on-demand DEK generation
/// instead of re-encrypting the vault every second.
pub struct KeyRotationState {
    /// Latest accumulated entropy digest from traffic streams
    pub latest_entropy: Arc<RwLock<Vec<u8>>>,
    /// How many key rotation epochs have elapsed
    pub key_epoch: Arc<RwLock<u64>>,
    /// Total frames processed from traffic streams
    pub frames_processed: Arc<RwLock<u64>>,
    /// Depth of the entropy pool
    pub pool_depth: Arc<RwLock<usize>>,
    /// Whether the daemon is actively running
    pub is_running: Arc<RwLock<bool>>,
    /// Whether we have sufficient entropy for a DEK rotation
    pub has_traffic_entropy: Arc<RwLock<bool>>,
}

impl KeyRotationState {
    pub fn new() -> Self {
        Self {
            latest_entropy: Arc::new(RwLock::new(Vec::new())),
            key_epoch: Arc::new(RwLock::new(0)),
            frames_processed: Arc::new(RwLock::new(0)),
            pool_depth: Arc::new(RwLock::new(0)),
            is_running: Arc::new(RwLock::new(false)),
            has_traffic_entropy: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn status(&self) -> KeyRotationStatus {
        KeyRotationStatus {
            key_epoch: *self.key_epoch.read().await,
            frames_processed: *self.frames_processed.read().await,
            pool_depth: *self.pool_depth.read().await,
            is_running: *self.is_running.read().await,
            has_traffic_entropy: *self.has_traffic_entropy.read().await,
        }
    }

    /// Generate a DEK from the accumulated traffic entropy.
    /// Returns None if no traffic entropy has been collected yet.
    pub async fn generate_traffic_dek(&self) -> Option<[u8; 32]> {
        let entropy = self.latest_entropy.read().await;
        if entropy.is_empty() {
            return None;
        }
        Some(crate::vault::generate_dek_from_traffic(&entropy))
    }
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct KeyRotationStatus {
    pub key_epoch: u64,
    pub frames_processed: u64,
    pub pool_depth: usize,
    pub is_running: bool,
    pub has_traffic_entropy: bool,
}

/// Start the entropy collection daemon. Runs every 1 second:
/// 1. Pick a random frame from multi-stream manager
/// 2. Extract entropy → feed pool → mix → store latest entropy
/// 3. Does NOT re-encrypt the vault — that happens on user action only
pub async fn start_rotation_daemon(
    stream_manager: Arc<Mutex<MultiStreamManager>>,
    rotation_state: Arc<KeyRotationState>,
    cancel: tokio::sync::watch::Receiver<bool>,
) {
    info!("Entropy collection daemon starting");
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

                    // Derive a key for chaining (but don't use it to encrypt vault)
                    let new_key = crypto_derivation::derive_key(
                        &mixed_seed,
                        previous_key.as_deref(),
                        32,
                    );

                    epoch += 1;
                    frames_total += 1;

                    // Store the latest mixed entropy for on-demand DEK generation
                    *rotation_state.latest_entropy.write().await = new_key.clone();
                    *rotation_state.key_epoch.write().await = epoch;
                    *rotation_state.frames_processed.write().await = frames_total;
                    *rotation_state.pool_depth.write().await = pool.len();
                    *rotation_state.has_traffic_entropy.write().await = true;

                    previous_frame_data = Some(frame.data);
                    previous_key = Some(new_key);

                    debug!("Entropy epoch {} (pool depth: {})", epoch, pool.len());
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

                    // Store OS entropy too (weaker but still useful)
                    *rotation_state.latest_entropy.write().await = new_key.clone();
                    *rotation_state.key_epoch.write().await = epoch;
                    *rotation_state.pool_depth.write().await = pool.len();

                    previous_key = Some(new_key);

                    debug!("Entropy epoch {} (no stream frame, OS entropy only)", epoch);
                }
            }
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    info!("Entropy collection daemon stopping");
                    break;
                }
            }
        }
    }

    *rotation_state.is_running.write().await = false;
    info!("Entropy collection daemon stopped at epoch {}", epoch);
}
