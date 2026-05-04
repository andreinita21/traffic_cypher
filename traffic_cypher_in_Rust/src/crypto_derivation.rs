use hkdf::Hkdf;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

/// Derive a cryptographic key using HKDF-SHA256.
///
/// - `mixed_seed`: the mixed entropy from system_entropy_mixer (IKM)
/// - `previous_key`: the previously derived key, used as salt (or None for first key)
/// - `key_length`: desired output key length in bytes
///
/// Info string includes "traffic-cypher-v1" + current Unix timestamp.
pub fn derive_key(
    mixed_seed: &[u8; 32],
    previous_key: Option<&[u8]>,
    key_length: usize,
) -> Vec<u8> {
    let salt = previous_key.unwrap_or(&[0u8; 32]);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        .to_le_bytes();

    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"traffic-cypher-v1");
    info.extend_from_slice(&timestamp);

    let hk = Hkdf::<Sha256>::new(Some(salt), mixed_seed);
    let mut okm = vec![0u8; key_length];
    hk.expand(&info, &mut okm)
        .expect("HKDF expand failed (key_length too large?)");

    okm
}

/// Format a key as hex string.
pub fn format_hex(key: &[u8]) -> String {
    hex::encode(key)
}

/// Format a key as base64 string.
pub fn format_base64(key: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_length() {
        let seed = [42u8; 32];
        let key = derive_key(&seed, None, 32);
        assert_eq!(key.len(), 32);

        let key_16 = derive_key(&seed, None, 16);
        assert_eq!(key_16.len(), 16);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];

        let key_a = derive_key(&seed_a, None, 32);
        let key_b = derive_key(&seed_b, None, 32);

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_format_hex() {
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(format_hex(&key), "deadbeef");
    }

    #[test]
    fn test_format_base64() {
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let b64 = format_base64(&key);
        assert!(!b64.is_empty());
    }
}
