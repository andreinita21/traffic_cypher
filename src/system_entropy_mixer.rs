use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Mix the pool digest with local OS entropy and the current timestamp.
///
/// Returns a 32-byte mixed entropy seed:
///   SHA-256( pool_digest ‖ os_entropy ‖ timestamp_nanos )
pub fn mix_entropy(pool_digest: &[u8; 32]) -> [u8; 32] {
    // 32 bytes of OS entropy
    let mut os_entropy = [0u8; 32];
    getrandom::getrandom(&mut os_entropy)
        .expect("Failed to get OS entropy");

    // Current timestamp in nanoseconds
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
        .to_le_bytes();

    // Concatenate and hash
    let mut hasher = Sha256::new();
    hasher.update(pool_digest);
    hasher.update(&os_entropy);
    hasher.update(&timestamp);

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mix_produces_different_outputs() {
        let digest = [0u8; 32];
        let a = mix_entropy(&digest);
        // Small sleep to ensure timestamp differs
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = mix_entropy(&digest);
        // Should differ due to OS entropy + timestamp
        assert_ne!(a, b);
    }

    #[test]
    fn test_mix_output_length() {
        let digest = [42u8; 32];
        let result = mix_entropy(&digest);
        assert_eq!(result.len(), 32);
    }
}
