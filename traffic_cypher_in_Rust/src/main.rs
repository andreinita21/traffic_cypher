mod cli;
mod crypto_derivation;
mod entropy_extractor;
mod entropy_pool;
mod frame_sampler;
mod stream_ingestion;
mod system_entropy_mixer;

use anyhow::Result;
use clap::Parser;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use cli::Cli;
use entropy_pool::EntropyPool;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    print_banner();

    // Create debug frames directory if needed
    if args.debug_frames {
        tokio::fs::create_dir_all("./debug_frames").await?;
        info!("Debug frames will be saved to ./debug_frames/");
    }

    // Step 1: Resolve the YouTube livestream URL
    info!("Resolving livestream URL...");
    let stream_url = stream_ingestion::resolve_stream_url(&args.url).await?;

    // Step 2: Start frame capture
    let (tx, mut rx) = mpsc::channel::<frame_sampler::Frame>(4);
    let mut ffmpeg_child = frame_sampler::start_frame_capture(&stream_url, tx).await?;

    info!("Pipeline started — generating keys every second");
    info!("Press Ctrl+C to stop\n");

    // Step 3: Main processing loop
    let mut pool = EntropyPool::new(8);
    let mut previous_frame_data: Option<Vec<u8>> = None;
    let mut previous_key: Option<Vec<u8>> = None;

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            // Graceful shutdown
            _ = &mut ctrl_c => {
                println!();
                info!("Shutting down gracefully...");
                break;
            }

            // Process next frame
            frame = rx.recv() => {
                match frame {
                    Some(frame) => {
                        // Extract entropy
                        let extracted = entropy_extractor::extract_entropy(
                            &frame.data,
                            previous_frame_data.as_deref(),
                            frame.width,
                            frame.height,
                        );

                        // Print metrics if requested
                        if args.show_metrics {
                            if let Some(ref metrics) = extracted.metrics {
                                eprintln!(
                                    "  📊 Metrics: changed={:.1}%, mean_delta={:.2}",
                                    metrics.changed_pixel_ratio * 100.0,
                                    metrics.mean_pixel_delta,
                                );
                            }
                        }

                        // Feed into entropy pool
                        pool.push(extracted.entropy_bytes);
                        let pool_digest = pool.digest();

                        // Mix with system entropy
                        let mixed_seed = system_entropy_mixer::mix_entropy(&pool_digest);

                        // Derive key
                        let key = crypto_derivation::derive_key(
                            &mixed_seed,
                            previous_key.as_deref(),
                            args.key_length,
                        );

                        // Format output
                        let formatted = match args.format.as_str() {
                            "base64" => crypto_derivation::format_base64(&key),
                            _ => crypto_derivation::format_hex(&key),
                        };

                        // Timestamp
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        println!(
                            "🔑 [{}] Frame #{:>4} | Pool depth: {} | Key: {}",
                            timestamp,
                            frame.sequence,
                            pool.len(),
                            formatted,
                        );

                        // Save debug frame if requested
                        if args.debug_frames {
                            save_debug_frame(&frame).await;
                        }

                        // Update state for next iteration
                        previous_frame_data = Some(frame.data);
                        previous_key = Some(key);
                    }
                    None => {
                        warn!("Frame stream ended");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    let _ = ffmpeg_child.kill().await;
    info!("Goodbye! Generated keys from {} frames.", previous_key.map_or(0, |_| pool.len()));

    Ok(())
}

/// Save a frame as a PPM file for debugging.
async fn save_debug_frame(frame: &frame_sampler::Frame) {
    let filename = format!("./debug_frames/frame_{:06}.ppm", frame.sequence);
    let header = format!("P6\n{} {}\n255\n", frame.width, frame.height);

    let mut data = Vec::with_capacity(header.len() + frame.data.len());
    data.extend_from_slice(header.as_bytes());
    data.extend_from_slice(&frame.data);

    if let Err(e) = tokio::fs::write(&filename, &data).await {
        error!("Failed to save debug frame {}: {}", filename, e);
    }
}

fn print_banner() {
    println!(r#"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🚦  T R A F F I C   C Y P H E R  🔐                  ║
║                                                          ║
║   Turning live city motion into rotating crypto keys     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"#);
}
