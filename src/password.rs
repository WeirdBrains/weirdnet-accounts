//! Argon2id password hashes in PHC string format.
//!
//! Parameters are the `argon2` crate defaults (Argon2id v1.3, m = 19 MiB, t = 2, p = 1), which
//! is what TAUR has always written, so existing hashes keep verifying.

use crate::{Error, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;

/// Default minimum password length, in characters.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Hashes a password with a fresh random salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string()).map_err(|_| Error::Hash)
}

/// Checks a password against a stored PHC hash. Malformed hashes never verify.
pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok()).unwrap_or(false)
}

/// Refuses passwords shorter than `min` characters.
pub fn check_length(password: &str, min: usize) -> Result<()> {
    if password.chars().count() < min {
        return Err(Error::Invalid(format!("password must be at least {min} characters")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_and_differ_per_salt() {
        let h = hash_password("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong horse", &h));
        assert!(!verify_password("correct horse", "not a hash"));
        assert_ne!(h, hash_password("correct horse").unwrap());
    }

    #[test]
    fn length_counts_characters() {
        check_length("12345678", MIN_PASSWORD_LEN).unwrap();
        assert_eq!(check_length("1234567", 8).unwrap_err(), Error::Invalid("password must be at least 8 characters".into()));
        check_length("ééééééé€", 8).unwrap();
    }
}
