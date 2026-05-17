use crate::frame_sampler;
use crate::frame_sampler::Frame;
use crate::stream_ingestion;
use anyhow::{bail, Context, Result};
use rand::Rng;
use rand::RngCore;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Clone, Debug, serde::Serialize)]
pub struct StreamStatus {
    pub url: String,
    pub label: String,
    pub status: StreamState,
    pub frames_captured: u64,
    pub kind: SlotKind,
    /// Operator-controlled gate. When false, `pick_random_frame` skips
    /// frames from this slot so the rotation daemon treats it as inert.
    /// The underlying capture or phone POST loop keeps running.
    pub enabled: bool,
    /// Unix-seconds of the most recent frame that arrived for this slot.
    /// `None` if no frame has arrived yet. The web layer derives `live`
    /// and `seconds_idle` fields from this against a 3-second window;
    /// `last_frame_unix` itself is not serialised in the HTTP response
    /// (matches the C build's /api/streams JSON shape).
    #[serde(skip)]
    pub last_frame_unix: Option<u64>,
    /// Derived: whether a frame arrived within the staleness window.
    /// Populated by the HTTP layer before serialisation; not stored.
    #[serde(default)]
    pub live: bool,
    /// Derived: seconds since the most recent frame. Serialised as
    /// `null` when no frame has arrived yet, matching the C build's
    /// /api/streams JSON shape exactly.
    #[serde(default)]
    pub seconds_idle: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum StreamState {
    Connecting,
    Active,
    Failed,
    Stopped,
}

/// Constant-time comparison of two 64-character lowercase-hex strings.
/// Defeats timing side-channels on the phone upload-token check. Returns
/// `true` iff both are 64 chars long and match.
fn ct_eq_hex64(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    if aa.len() != 64 || bb.len() != 64 {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..64 {
        diff |= aa[i] ^ bb[i];
    }
    // The volatile read shape that std uses internally for similar checks
    // isn't expressible cleanly in safe Rust; the loop above is straight-line
    // and the result depends on the full byte sweep, so LLVM has no excuse
    // to insert an early exit.
    diff == 0
}

/// Errors from `push_phone_frame`. Distinguishes "not your slot" from
/// "wrong token" because the HTTP layer maps them to 400 vs 403.
#[derive(Debug)]
pub enum PhoneFrameError {
    NotFound,
    TokenMismatch,
    RingFull,
}

impl std::fmt::Display for PhoneFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PhoneFrameError::NotFound => write!(f, "slot not found or not a phone slot"),
            PhoneFrameError::TokenMismatch => write!(f, "upload token mismatch"),
            PhoneFrameError::RingFull => write!(f, "frame ring at capacity"),
        }
    }
}

impl std::error::Error for PhoneFrameError {}

/// Distinguishes how a slot's frames arrive. Mirrors the C `slot_kind_t`
/// enum. `Ffmpeg` slots have a tokio task pulling frames from a yt-dlp +
/// ffmpeg pipeline; `Phone` slots receive frames via HTTP POST from
/// `/api/streams/phone/{index}/frame` authenticated by a per-slot upload
/// token. NEXT_STEPS.md Phase B.
#[derive(Clone, Debug, serde::Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SlotKind {
    Ffmpeg,
    Phone,
}

pub struct MultiStreamManager {
    streams: Vec<StreamHandle>,
    frame_rx: mpsc::Receiver<(usize, Frame)>,
    frame_tx: mpsc::Sender<(usize, Frame)>,
}

struct StreamHandle {
    url: String,
    label: String,
    status: StreamState,
    frames_captured: u64,
    cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,
    child: Option<tokio::process::Child>,
    kind: SlotKind,
    /// Only set for `SlotKind::Phone` — 32-byte random secret that the phone
    /// client presents (as 64-char lowercase hex) in `X-Upload-Token` on
    /// every frame POST. Wiped on remove. Not exposed via `get_statuses()`.
    upload_token: Option<[u8; 32]>,
    /// Operator-controlled gate; see `StreamStatus::enabled`.
    enabled: bool,
    /// Unix-seconds of the most recent frame; see `StreamStatus::last_frame_unix`.
    last_frame_unix: Option<u64>,
}

impl Default for MultiStreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiStreamManager {
    /// Create a new MultiStreamManager with an empty stream list and a shared
    /// frame channel.
    pub fn new() -> Self {
        let (frame_tx, frame_rx) = mpsc::channel(256);
        Self {
            streams: Vec::new(),
            frame_rx,
            frame_tx,
        }
    }

    /// Add a YouTube livestream by URL. Resolves the direct stream URL via
    /// yt-dlp, starts ffmpeg frame capture, and spawns a forwarding task that
    /// tags each frame with the stream index before sending it to the shared
    /// channel.
    ///
    /// Returns the stream index on success.
    pub async fn add_stream(&mut self, url: String, label: String) -> Result<usize> {
        let index = self.streams.len();

        info!("Adding stream #{} '{}' from {}", index, label, url);

        // Mark as connecting before the async resolve
        self.streams.push(StreamHandle {
            url: url.clone(),
            label: label.clone(),
            status: StreamState::Connecting,
            frames_captured: 0,
            cancel_tx: None,
            child: None,
            kind: SlotKind::Ffmpeg,
            upload_token: None,
            enabled: true,
            last_frame_unix: None,
        });

        // 1. Resolve the YouTube URL into a direct stream URL
        let resolved_url = match stream_ingestion::resolve_stream_url(&url).await {
            Ok(u) => u,
            Err(e) => {
                error!("Failed to resolve stream URL for '{}': {}", label, e);
                self.streams[index].status = StreamState::Failed;
                return Err(e).context(format!("Failed to resolve stream '{}'", label));
            }
        };

        // 2. Create an mpsc channel for frame capture from ffmpeg
        let (capture_tx, mut capture_rx) = mpsc::channel::<Frame>(64);

        // 3. Start ffmpeg frame capture
        let child = match frame_sampler::start_frame_capture(&resolved_url, capture_tx).await {
            Ok(child) => child,
            Err(e) => {
                error!("Failed to start frame capture for '{}': {}", label, e);
                self.streams[index].status = StreamState::Failed;
                return Err(e).context(format!("Failed to start capture for '{}'", label));
            }
        };
        self.streams[index].child = Some(child);

        // 4. Create a cancellation channel for this stream
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        self.streams[index].cancel_tx = Some(cancel_tx);
        self.streams[index].status = StreamState::Active;

        // 5. Spawn a task that reads frames from the per-stream capture channel
        //    and forwards them to the shared multi-stream channel tagged with
        //    the stream index.
        let shared_tx = self.frame_tx.clone();
        let stream_label = label.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    frame_opt = capture_rx.recv() => {
                        match frame_opt {
                            Some(frame) => {
                                if shared_tx.send((index, frame)).await.is_err() {
                                    info!(
                                        "Shared channel closed, stopping forwarder for '{}'",
                                        stream_label
                                    );
                                    break;
                                }
                            }
                            None => {
                                warn!(
                                    "Frame capture channel closed for '{}'",
                                    stream_label
                                );
                                break;
                            }
                        }
                    }
                    _ = &mut cancel_rx => {
                        info!("Stream '{}' cancelled", stream_label);
                        break;
                    }
                }
            }
        });

        info!("Stream #{} '{}' is now active", index, label);
        Ok(index)
    }

    /// Stop and remove a stream by index. Sends a cancel signal to the
    /// forwarding task, kills the ffmpeg child process, then removes the
    /// entry from the vec entirely.
    pub async fn remove_stream(&mut self, index: usize) -> Result<()> {
        if index >= self.streams.len() {
            bail!(
                "Stream index {} out of range (have {})",
                index,
                self.streams.len()
            );
        }

        let handle = &mut self.streams[index];
        info!("Removing stream #{} '{}'", index, handle.label);

        // Send cancel signal; if the receiver is already gone that is fine
        if let Some(cancel_tx) = handle.cancel_tx.take() {
            let _ = cancel_tx.send(());
        }

        // Kill and reap the ffmpeg child process explicitly so we do not
        // leave orphaned processes behind.
        if let Some(mut child) = handle.child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        self.streams.remove(index);
        Ok(())
    }

    /// Update a stream's label and/or URL (metadata only — does not restart
    /// the capture pipeline).
    pub fn update_stream(
        &mut self,
        index: usize,
        label: Option<String>,
        url: Option<String>,
    ) -> Result<()> {
        if index >= self.streams.len() {
            bail!(
                "Stream index {} out of range (have {})",
                index,
                self.streams.len()
            );
        }
        let handle = &mut self.streams[index];
        if let Some(l) = label {
            handle.label = l;
        }
        if let Some(u) = url {
            handle.url = u;
        }
        Ok(())
    }

    /// Return the current status of every stream. The HTTP layer is
    /// expected to call `derive_liveness()` on each entry before
    /// serialising so the dashboard sees `live` / `seconds_idle` flags
    /// that match the C build's JSON shape.
    pub fn get_statuses(&self) -> Vec<StreamStatus> {
        self.streams
            .iter()
            .map(|h| StreamStatus {
                url: h.url.clone(),
                label: h.label.clone(),
                status: h.status.clone(),
                frames_captured: h.frames_captured,
                kind: h.kind.clone(),
                enabled: h.enabled,
                last_frame_unix: h.last_frame_unix,
                live: false,
                seconds_idle: None,
            })
            .collect()
    }

    /// Operator gate: include or exclude this slot's frames from
    /// `pick_random_frame`. The underlying capture / phone POST loop
    /// keeps running; only the rotation daemon's pick changes. Returns
    /// `Err` if the index is out of range.
    pub fn set_enabled(&mut self, index: usize, enabled: bool) -> Result<()> {
        if index >= self.streams.len() {
            bail!(
                "Stream index {} out of range (have {})",
                index,
                self.streams.len()
            );
        }
        self.streams[index].enabled = enabled;
        Ok(())
    }

    /// Non-blocking attempt to pick a random frame from the available streams.
    ///
    /// Algorithm:
    /// 1. Drain all available frames from the shared channel (non-blocking).
    /// 2. Group frames by stream index.
    /// 3. If frames are available from multiple streams, pick a random stream
    ///    index and return the latest (most recent) frame from that stream.
    /// 4. Returns `None` if no frames are available.
    pub fn pick_random_frame(&mut self) -> Option<Frame> {
        // Drain all pending frames from the channel (non-blocking)
        let mut by_stream: HashMap<usize, Vec<Frame>> = HashMap::new();

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        while let Ok((stream_index, frame)) = self.frame_rx.try_recv() {
            // Update frames_captured counter + liveness timestamp (count
            // and timestamp arrive even from disabled slots — only the
            // pick is gated).
            let enabled = if stream_index < self.streams.len() {
                self.streams[stream_index].frames_captured += 1;
                self.streams[stream_index].last_frame_unix = Some(now_unix);
                self.streams[stream_index].enabled
            } else {
                false
            };
            if !enabled {
                // Operator-disabled source — drop the frame so the
                // rotation daemon doesn't treat it as a candidate.
                continue;
            }
            by_stream.entry(stream_index).or_default().push(frame);
        }

        if by_stream.is_empty() {
            return None;
        }

        // Collect the stream indices that have frames
        let indices: Vec<usize> = by_stream.keys().copied().collect();

        // Pick a random stream
        let chosen_index = if indices.len() == 1 {
            indices[0]
        } else {
            let pick = rand::thread_rng().gen_range(0..indices.len());
            indices[pick]
        };

        // Return the latest (last) frame from the chosen stream
        by_stream
            .remove(&chosen_index)
            .and_then(|mut frames| frames.pop())
    }

    /// Register a phone-camera slot — the alternative to ffmpeg/yt-dlp
    /// ingestion. No tokio task is spawned; frames will arrive via
    /// `push_phone_frame` from the HTTP layer. Generates a 32-byte random
    /// upload token, returns `(slot_index, hex_token)`. NEXT_STEPS.md Phase B.
    pub fn register_phone(&mut self, label: String) -> (usize, String) {
        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        let token_hex = hex::encode(token);
        let index = self.streams.len();
        info!("Registering phone slot #{} '{}'", index, label);
        self.streams.push(StreamHandle {
            url: format!("phone://{}", label),
            label,
            status: StreamState::Connecting,
            frames_captured: 0,
            cancel_tx: None,
            child: None,
            kind: SlotKind::Phone,
            upload_token: Some(token),
            enabled: true,
            last_frame_unix: None,
        });
        (index, token_hex)
    }

    /// Push one frame into the shared channel for a phone slot. Validates
    /// the slot index, slot kind, and constant-time-compares the supplied
    /// hex token against the slot's upload token. First successful push
    /// transitions the slot CONNECTING → ACTIVE.
    ///
    /// Returns:
    ///   `Ok(())` on success.
    ///   `Err(PhoneFrameError::NotFound)` if `index` is out of range or the
    ///       slot is not a SlotKind::Phone.
    ///   `Err(PhoneFrameError::TokenMismatch)` on token mismatch — caller
    ///       should respond 403.
    ///   `Err(PhoneFrameError::RingFull)` if the bounded channel is at
    ///       capacity — caller can respond 503 and let the phone retry.
    pub async fn push_phone_frame(
        &mut self,
        index: usize,
        token_hex: &str,
        frame: Frame,
    ) -> std::result::Result<(), PhoneFrameError> {
        if index >= self.streams.len() {
            return Err(PhoneFrameError::NotFound);
        }
        let slot = &self.streams[index];
        if slot.kind != SlotKind::Phone {
            return Err(PhoneFrameError::NotFound);
        }
        let expected = match slot.upload_token {
            Some(t) => t,
            None => return Err(PhoneFrameError::NotFound),
        };
        let expected_hex = hex::encode(expected);
        if !ct_eq_hex64(token_hex, &expected_hex) {
            return Err(PhoneFrameError::TokenMismatch);
        }
        // CONNECTING → ACTIVE on the first successful frame; also bump
        // the liveness timestamp so the dashboard can detect when the
        // phone stops POSTing.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let slot_mut = &mut self.streams[index];
        if slot_mut.status == StreamState::Connecting {
            slot_mut.status = StreamState::Active;
        }
        slot_mut.last_frame_unix = Some(now_unix);
        // Non-blocking send so a full ring doesn't deadlock under the
        // manager mutex. The phone client retries on the next tick.
        self.frame_tx
            .try_send((index, frame))
            .map_err(|_| PhoneFrameError::RingFull)?;
        Ok(())
    }

    /// Return the number of streams (including stopped ones).
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}
