// Helper used once to compute the KAT pinned in
// `test_fixtures/argon2id_kek_kat.json`. Run with:
//   cargo run --release --example argon2_kat
use argon2::{Algorithm, Argon2, Params, Version};

fn main() {
    let params = Params::new(65536, 3, 1, Some(32)).expect("valid params");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(b"x", &[0u8; 32], &mut out)
        .expect("argon2id derive");
    println!("{}", hex::encode(out));
}
