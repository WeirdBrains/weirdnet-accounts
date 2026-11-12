//! Bearer tokens (sessions, email links): 32 random bytes as hex, stored only as SHA-256.

use crate::hex;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A fresh 256-bit token as 64 lowercase hex characters. Hand it to the client once.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

/// SHA-256 of a token as lowercase hex; the only form that is stored.
pub fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Constant-time comparison of two stored hashes.
pub fn hashes_equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_hex_and_hashes_are_sha256() {
        let t = random_token();
        assert_eq!(t.len(), 64);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(t, random_token());
        assert_eq!(token_hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(hashes_equal(&token_hash(&t), &token_hash(&t)));
        assert!(!hashes_equal(&token_hash("a"), &token_hash("b")));
        assert!(!hashes_equal("ab", "abc"));
    }
}
