use anyhow::{Context, Result, bail};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// A single captured frame with its raw pixel data.
#[derive(Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>, // raw RGB pixel bytes
    pub sequence: u64,
}

/// Start ffmpeg as a subprocess reading from the resolved stream URL,
/// outputting 1 PPM frame per second to stdout.
/// Sends parsed frames through the returned channel.
pub async fn start_frame_capture(
    stream_url: &str,
    sender: mpsc::Sender<Frame>,
) -> Result<tokio::process::Child> {
    info!("Starting ffmpeg frame capture at 1 FPS");

    let mut child = Command::new("ffmpeg")
        .args([
            "-reconnect", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "5",
            "-i", stream_url,
            "-vf", "fps=1,scale=320:240",
            "-f", "image2pipe",
            "-vcodec", "ppm",
            "-an",           // no audio
            "-loglevel", "error",
            "pipe:1",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn ffmpeg. Is it installed?")?;

    let stdout = child.stdout.take()
        .context("Failed to capture ffmpeg stdout")?;

    // Spawn a task to continuously read and parse PPM frames
    tokio::spawn(async move {
        if let Err(e) = read_ppm_stream(stdout, sender).await {
            error!("Frame reader error: {}", e);
        }
    });

    Ok(child)
}

/// Read PPM (P6) frames from a byte stream.
/// PPM format: "P6\n<width> <height>\n<maxval>\n<RGB bytes>"
async fn read_ppm_stream(
    mut reader: impl AsyncReadExt + Unpin,
    sender: mpsc::Sender<Frame>,
) -> Result<()> {
    let mut sequence: u64 = 0;
    let mut buf = Vec::with_capacity(320 * 240 * 3 + 256);

    loop {
        // Read PPM header byte by byte
        let (width, height, header_len) = match read_ppm_header(&mut reader, &mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("PPM header read ended: {}", e);
                break;
            }
        };

        let pixel_bytes = (width * height * 3) as usize;
        let mut pixel_data = vec![0u8; pixel_bytes];
        reader.read_exact(&mut pixel_data).await
            .context("Failed to read PPM pixel data")?;

        sequence += 1;

        let frame = Frame {
            width,
            height,
            data: pixel_data,
            sequence,
        };

        debug!("Captured frame #{} ({}x{})", sequence, width, height);

        if sender.send(frame).await.is_err() {
            info!("Frame receiver dropped, stopping capture");
            break;
        }

        buf.clear();
    }

    Ok(())
}

/// Parse a PPM P6 header from the stream.
/// Returns (width, height, header_byte_count).
async fn read_ppm_header(
    reader: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
) -> Result<(u32, u32, usize)> {
    buf.clear();

    // Read until we have at least the header (P6\n<w> <h>\n<maxval>\n)
    // We read byte-by-byte to avoid over-reading into pixel data
    let mut newline_count = 0;
    let mut byte = [0u8; 1];

    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            bail!("EOF while reading PPM header");
        }
        buf.push(byte[0]);

        // Skip comment lines
        if byte[0] == b'\n' {
            // Check if next line is a comment
            newline_count += 1;
            if newline_count >= 3 {
                break;
            }
        }
    }

    let header = String::from_utf8_lossy(buf);
    let mut lines: Vec<&str> = header.lines().collect();

    // Filter out comment lines (starting with #)
    lines.retain(|l| !l.starts_with('#'));

    if lines.len() < 3 || lines[0].trim() != "P6" {
        bail!("Invalid PPM header: {:?}", header);
    }

    let dims: Vec<&str> = lines[1].trim().split_whitespace().collect();
    if dims.len() < 2 {
        bail!("Invalid PPM dimensions: {}", lines[1]);
    }

    let width: u32 = dims[0].parse().context("Invalid width")?;
    let height: u32 = dims[1].parse().context("Invalid height")?;

    Ok((width, height, buf.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_ppm_header() {
        // Construct a minimal PPM P6 frame
        let header = b"P6\n4 2\n255\n";
        let pixels = vec![128u8; 4 * 2 * 3]; // 4x2 RGB
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(&pixels);

        let mut cursor = &data[..];
        let mut buf = Vec::new();
        let (w, h, _) = read_ppm_header(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(w, 4);
        assert_eq!(h, 2);
    }
}
