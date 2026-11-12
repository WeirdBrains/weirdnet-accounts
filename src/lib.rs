//! Account building blocks shared by WeirdBrains services (TAUR, Salty Gull).
//!
//! Storage stays with the application: this crate holds the rules and the cryptography,
//! and never opens a database.
//!
//! - [`password`]: Argon2id hashing (PHC strings) and the minimum-length rule.
//! - [`token`]: 256-bit random tokens handed out once; only their SHA-256 is stored.
//! - [`names`]: user-name and email checks.
//! - [`ratelimit`]: fixed-window per-client limits, generic over the app's request classes,
//!   with `X-Forwarded-For` honoured only from trusted proxies.
//! - [`apikeys`]: org-scoped API keys with a visible prefix, scopes, optional app and channel
//!   bindings, expiry and revocation.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod apikeys;
pub mod error;
pub mod names;
pub mod password;
pub mod ratelimit;
pub mod token;

pub use error::{Error, Result};

/// Seconds since the Unix epoch (0 if the clock is before 1970).
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
