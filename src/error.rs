//! Errors. None carry passwords, tokens or keys.

use crate::apikeys::ApiKeyError;

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Account errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Input broke a rule; the message is safe to show to the user.
    #[error("{0}")]
    Invalid(String),
    /// Password hashing failed.
    #[error("password hashing failed")]
    Hash,
    /// A rate limit was reached.
    #[error("rate limit reached")]
    RateLimited {
        /// Seconds until the client may retry (at least 1).
        retry_after: u64,
    },
    /// An API key was refused.
    #[error(transparent)]
    ApiKey(#[from] ApiKeyError),
}
