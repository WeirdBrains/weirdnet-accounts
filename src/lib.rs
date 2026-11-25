//! Account building blocks shared by WeirdBrains services.
//!
//! The 0.1 primitives, unchanged:
//!
//! - [`password`]: Argon2id hashing (PHC strings) and the minimum-length rule.
//! - [`token`]: 256-bit random tokens handed out once; only their SHA-256 is stored.
//! - [`names`]: user-name and email checks.
//! - [`ratelimit`]: fixed-window per-client limits, generic over the app's request classes,
//!   with `X-Forwarded-For` honoured only from trusted proxies.
//! - [`apikeys`]: org-scoped API keys with a visible prefix, scopes, optional app and channel
//!   bindings, expiry and revocation.
//!
//! The multi-tenant accounts model (0.2):
//!
//! - [`account`]: accounts (tenants), members, invitations, revocations and API-key bindings.
//! - [`catalog`]: account permissions on the weirdnet-access core, and ranked role presets.
//! - [`authz`]: the [`Authorizer`](authz::Authorizer) hook: identity, account status,
//!   membership (recorded or owner-signed), then weirdnet-access `enforce::decide`.
//! - [`directory`]: [`Accounts`](directory::Accounts), the checked operations.
//! - [`store`]: the [`Store`](store::Store) interface and an in-memory store.
//! - `sqlite` (feature `sqlite`): `SqliteStore`, a SQLCipher database of its own.
//! - `net` (feature `net`): signed weirdnet-net memberships and revocations.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod account;
pub mod apikeys;
pub mod authz;
pub mod catalog;
pub mod directory;
pub mod error;
pub mod names;
#[cfg(feature = "net")]
pub mod net;
pub mod password;
pub mod ratelimit;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod store;
pub mod token;

pub use error::{Error, Result};

/// Seconds since the Unix epoch (0 if the clock is before 1970).
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
