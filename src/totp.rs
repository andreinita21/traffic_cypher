use anyhow::{Result, anyhow};
use totp_rs::{Algorithm, TOTP, Secret};

/// Generate a current TOTP code from a base32 secret.
/// Returns (code: String, seconds_remaining: u32)
pub fn generate_totp(secret_base32: &str) -> Result<(String, u32)> {
    let secret = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| anyhow!("Invalid TOTP secret: {}", e))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
    ).map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let code = totp.generate(time);
    let seconds_remaining = 30 - (time % 30) as u32;

    Ok((code, seconds_remaining))
}

/// Generate a new random TOTP secret (base32 encoded)
pub fn generate_secret() -> String {
    use totp_rs::Secret;
    Secret::generate_secret().to_encoded().to_string()
}
