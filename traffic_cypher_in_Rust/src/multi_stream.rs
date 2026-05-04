use crate::frame_sampler::Frame;
use crate::stream_ingestion;
use crate::frame_sampler;
use anyhow::{Result, Context, bail};
use tokio::sync::mpsc;
use rand::Rng;
use tracing::{info, warn, error};
use std::collections::HashMap;

#[derive(Clone, Debug, serde::Serialize)]
pub struct StreamStatus {
    pub url: String,
    pub label: String,
    pub status: StreamState,
    pub frames_captured: u64,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum StreamState {
    Connecting,
    Active,
    Failed,
    Stopped,
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

        info!(
            "Adding stream #{} '{}' from {}",
            index, label, url
        );

        // Mark as connecting before the async resolve
        self.streams.push(StreamHandle {
            url: url.clone(),
            label: label.clone(),
            status: StreamState::Connecting,
            frames_captured: 0,
            cancel_tx: None,
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
        let _child = match frame_sampler::start_frame_capture(&resolved_url, capture_tx).await {
            Ok(child) => child,
            Err(e) => {
                error!("Failed to start frame capture for '{}': {}", label, e);
                self.streams[index].status = StreamState::Failed;
                return Err(e).context(format!("Failed to start capture for '{}'", label));
            }
        };

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
    /// forwarding task, then removes the entry from the vec entirely.
    pub fn remove_stream(&mut self, index: usize) -> Result<()> {
        if index >= self.streams.len() {
            bail!("Stream index {} out of range (have {})", index, self.streams.len());
        }

        let handle = &mut self.streams[index];
        info!("Removing stream #{} '{}'", index, handle.label);

        // Send cancel signal; if the receiver is already gone that is fine
        if let Some(cancel_tx) = handle.cancel_tx.take() {
            let _ = cancel_tx.send(());
        }

        self.streams.remove(index);
        Ok(())
    }

    /// Update a stream's label and/or URL (metadata only — does not restart
    /// the capture pipeline).
    pub fn update_stream(&mut self, index: usize, label: Option<String>, url: Option<String>) -> Result<()> {
        if index >= self.streams.len() {
            bail!("Stream index {} out of range (have {})", index, self.streams.len());
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

    /// Return the current status of every stream.
    pub fn get_statuses(&self) -> Vec<StreamStatus> {
        self.streams
            .iter()
            .map(|h| StreamStatus {
                url: h.url.clone(),
                label: h.label.clone(),
                status: h.status.clone(),
                frames_captured: h.frames_captured,
            })
            .collect()
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

        loop {
            match self.frame_rx.try_recv() {
                Ok((stream_index, frame)) => {
                    // Update frames_captured counter
                    if stream_index < self.streams.len() {
                        self.streams[stream_index].frames_captured += 1;
                    }
                    by_stream.entry(stream_index).or_default().push(frame);
                }
                Err(_) => break,
            }
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

    /// Return the number of streams (including stopped ones).
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}
