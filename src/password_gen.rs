use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a cryptographically random password based on options
pub fn generate(opts: &PasswordOptions) -> String {
    let mut charset = Vec::new();
    if opts.lowercase { charset.extend_from_slice(b"abcdefghjkmnpqrstuvwxyz"); }
    if opts.uppercase { charset.extend_from_slice(b"ABCDEFGHJKMNPQRSTUVWXYZ"); }
    if opts.digits { charset.extend_from_slice(b"23456789"); }
    if opts.symbols { charset.extend_from_slice(b"!@#$%^&*-_=+"); }

    if charset.is_empty() {
        charset.extend_from_slice(b"abcdefghjkmnpqrstuvwxyz");
    }

    let mut bytes = vec![0u8; opts.length];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes.iter().map(|&b| charset[b as usize % charset.len()] as char).collect()
}

/// Calculate password strength in bits of entropy
pub fn calculate_strength(password: &str) -> PasswordStrength {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() { has_lower = true; }
        else if c.is_ascii_uppercase() { has_upper = true; }
        else if c.is_ascii_digit() { has_digit = true; }
        else { has_symbol = true; }
    }

    let mut charset_size = 0u32;
    if has_lower { charset_size += 26; }
    if has_upper { charset_size += 26; }
    if has_digit { charset_size += 10; }
    if has_symbol { charset_size += 32; }

    if charset_size == 0 { charset_size = 1; }

    let entropy_bits = (password.len() as f64) * (charset_size as f64).log2();

    let level = if entropy_bits < 40.0 { "weak" }
        else if entropy_bits < 60.0 { "fair" }
        else if entropy_bits < 80.0 { "good" }
        else { "strong" };

    PasswordStrength {
        entropy_bits,
        level: level.to_string(),
        charset_size,
        length: password.len(),
    }
}

#[derive(Serialize, Debug)]
pub struct PasswordStrength {
    pub entropy_bits: f64,
    pub level: String,
    pub charset_size: u32,
    pub length: usize,
}
