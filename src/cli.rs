use clap::Parser;

/// Traffic Cypher — Derive cryptographic keys from live traffic stream entropy
#[derive(Parser, Debug, Clone)]
#[command(name = "traffic-cypher", version, about)]
pub struct Cli {
    /// YouTube livestream URL to use as entropy source
    #[arg(short, long)]
    pub url: String,

    /// Output format for derived keys
    #[arg(short, long, default_value = "hex", value_parser = ["hex", "base64"])]
    pub format: String,

    /// Key length in bytes
    #[arg(short, long, default_value_t = 32)]
    pub key_length: usize,

    /// Save sampled frames to ./debug_frames/ for inspection
    #[arg(long, default_value_t = false)]
    pub debug_frames: bool,

    /// Show entropy variability metrics for each frame
    #[arg(long, default_value_t = false)]
    pub show_metrics: bool,
}
