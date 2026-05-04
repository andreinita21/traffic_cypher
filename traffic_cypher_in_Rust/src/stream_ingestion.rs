use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::process::Command;
use tracing::{info, warn};

/// Resolve a YouTube livestream URL into a direct video stream URL using yt-dlp.
///
/// Tries the local `./yt-dlp` binary first, then falls back to searching PATH.
pub async fn resolve_stream_url(youtube_url: &str) -> Result<String> {
    let yt_dlp = find_yt_dlp()?;

    info!("Resolving stream URL with yt-dlp: {}", youtube_url);

    let output = Command::new(&yt_dlp)
        .args([
            "-g",             // print the direct URL only
            "-f", "best",     // best single format
            "--no-warnings",
            youtube_url,
        ])
        .output()
        .await
        .context("Failed to run yt-dlp. Is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("yt-dlp failed: {}", stderr.trim());
    }

    let url = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    if url.is_empty() {
        bail!("yt-dlp returned an empty URL. Is the stream live?");
    }

    info!("Resolved direct stream URL ({} chars)", url.len());
    Ok(url)
}

/// Locate yt-dlp binary: prefer local `./yt-dlp`, then system PATH.
fn find_yt_dlp() -> Result<String> {
    // Check for local binary next to the executable or in cwd
    let local = Path::new("./yt-dlp");
    if local.exists() {
        info!("Using local yt-dlp binary");
        return Ok("./yt-dlp".to_string());
    }

    // Fall back to PATH
    warn!("Local yt-dlp not found, falling back to system PATH");
    Ok("yt-dlp".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_yt_dlp_returns_something() {
        // Should not panic — returns either local or PATH version
        let result = find_yt_dlp();
        assert!(result.is_ok());
    }
}
