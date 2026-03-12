use sha2::{Digest, Sha256};

/// Metrics about frame-to-frame visual variation.
#[derive(Debug, Clone)]
pub struct EntropyMetrics {
    /// Fraction of pixels that changed compared to previous frame (0.0 to 1.0)
    pub changed_pixel_ratio: f64,
    /// Mean absolute pixel delta across all channels
    pub mean_pixel_delta: f64,
}

/// Result of extracting entropy from a single frame.
pub struct ExtractedEntropy {
    /// Concatenated SHA-256 hashes forming the raw entropy
    pub entropy_bytes: Vec<u8>,
    /// Optional metrics (only if a previous frame was provided)
    pub metrics: Option<EntropyMetrics>,
}

/// Extract entropy from a frame's raw pixel data.
///
/// 1. SHA-256 of full pixel data → base entropy (32 bytes)
/// 2. If previous frame given: XOR delta → SHA-256 → inter-frame entropy (32 bytes)
/// 3. 8×8 spatial grid of block hashes → 64 × 32 = 2048 bytes of spatial entropy
///
/// Returns concatenated hashes as raw entropy.
pub fn extract_entropy(
    current_data: &[u8],
    previous_data: Option<&[u8]>,
    width: u32,
    height: u32,
) -> ExtractedEntropy {
    let mut entropy_bytes = Vec::with_capacity(32 + 32 + 64 * 32);

    // 1. Full-frame hash
    let full_hash = sha256(current_data);
    entropy_bytes.extend_from_slice(&full_hash);

    // 2. Inter-frame delta hash + metrics
    let metrics = if let Some(prev) = previous_data {
        let min_len = current_data.len().min(prev.len());
        let mut delta = vec![0u8; min_len];
        let mut changed_pixels = 0u64;
        let mut total_delta = 0u64;

        for i in 0..min_len {
            delta[i] = current_data[i] ^ prev[i];
            if delta[i] != 0 {
                changed_pixels += 1;
            }
            total_delta += (current_data[i] as i16 - prev[i] as i16).unsigned_abs() as u64;
        }

        let delta_hash = sha256(&delta);
        entropy_bytes.extend_from_slice(&delta_hash);

        let pixel_count = min_len / 3; // RGB
        Some(EntropyMetrics {
            changed_pixel_ratio: changed_pixels as f64 / min_len as f64,
            mean_pixel_delta: total_delta as f64 / min_len as f64,
        })
    } else {
        None
    };

    // 3. Spatial block hashes (8x8 grid)
    let grid_cols = 8u32;
    let grid_rows = 8u32;
    let block_w = width / grid_cols;
    let block_h = height / grid_rows;

    if block_w > 0 && block_h > 0 {
        for row in 0..grid_rows {
            for col in 0..grid_cols {
                let mut hasher = Sha256::new();
                for y in (row * block_h)..((row + 1) * block_h) {
                    let line_start = (y * width * 3 + col * block_w * 3) as usize;
                    let line_end = line_start + (block_w * 3) as usize;
                    if line_end <= current_data.len() {
                        hasher.update(&current_data[line_start..line_end]);
                    }
                }
                let block_hash = hasher.finalize();
                entropy_bytes.extend_from_slice(&block_hash);
            }
        }
    }

    ExtractedEntropy {
        entropy_bytes,
        metrics,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_different_data_different_entropy() {
        let data_a = vec![10u8; 320 * 240 * 3];
        let data_b = vec![200u8; 320 * 240 * 3];

        let ea = extract_entropy(&data_a, None, 320, 240);
        let eb = extract_entropy(&data_b, None, 320, 240);

        assert_ne!(ea.entropy_bytes, eb.entropy_bytes);
    }

    #[test]
    fn test_identical_data_same_entropy() {
        let data = vec![42u8; 320 * 240 * 3];
        let ea = extract_entropy(&data, None, 320, 240);
        let eb = extract_entropy(&data, None, 320, 240);

        assert_eq!(ea.entropy_bytes, eb.entropy_bytes);
    }

    #[test]
    fn test_inter_frame_delta_metrics() {
        let data_a = vec![100u8; 320 * 240 * 3];
        let data_b = vec![150u8; 320 * 240 * 3];

        let result = extract_entropy(&data_b, Some(&data_a), 320, 240);
        let metrics = result.metrics.unwrap();

        assert!(metrics.changed_pixel_ratio > 0.99); // all pixels changed
        assert!((metrics.mean_pixel_delta - 50.0).abs() < 0.01);
    }
}
