//! Account records: accounts (tenants), their members, invitations, revocations and API-key
//! bindings.
//!
//! An account belongs to one owner (a Weirdnet user id, the id weirdnet-net derives from the
//! user key). Other identities are members holding one role from the account's
//! [`RoleSet`]. One server hosts many accounts, an account has many members, and one identity
//! can belong to many accounts. Times are Unix milliseconds, as in weirdnet-net.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use weirdnet_access::RoleSet;

/// Unix time in milliseconds (0 if the clock is before 1970).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Errors from the accounts model. Messages never carry tokens or keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AccountError {
    /// Input broke a rule; the message is safe to show.
    #[error("{0}")]
    Invalid(String),
    /// No such record.
    #[error("{0} not found")]
    NotFound(&'static str),
    /// The record already exists.
    #[error("{0} already exists")]
    Exists(&'static str),
    /// The caller may not do this.
    #[error("{0}")]
    Denied(String),
    /// The store failed.
    #[error("storage: {0}")]
    Storage(String),
}

impl From<weirdnet_access::Error> for AccountError {
    fn from(e: weirdnet_access::Error) -> Self {
        match e {
            weirdnet_access::Error::Denied(m) => AccountError::Denied(m),
            other => AccountError::Invalid(other.to_string()),
        }
    }
}

/// Result alias for the accounts model.
pub type AccountResult<T> = std::result::Result<T, AccountError>;

fn check_id(what: &str, s: &str) -> AccountResult<()> {
    let ok = (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
        && s.as_bytes()[0].is_ascii_alphanumeric();
    if ok { Ok(()) } else { Err(AccountError::Invalid(format!("{what}: 1-64 of a-z 0-9 . _ -, starting with a letter or digit"))) }
}

pub(crate) fn check_user(user_id: &str) -> AccountResult<()> {
    if user_id.is_empty() || user_id.len() > 64 || user_id.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(AccountError::Invalid("user id: 1-64 characters, no spaces".into()));
    }
    Ok(())
}

pub(crate) fn random_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    crate::hex(&b)
}

/// An account id: 1-64 of `a-z 0-9 . _ -`, starting with a letter or digit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId(String);

impl AccountId {
    /// Checks `id`.
    pub fn new(id: impl Into<String>) -> AccountResult<Self> {
        let id = id.into();
        check_id("account id", &id)?;
        Ok(AccountId(id))
    }

    /// A new random id (32 hex characters).
    pub fn random() -> Self {
        AccountId(random_id())
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AccountId {
    type Error = AccountError;
    fn try_from(s: String) -> AccountResult<Self> {
        AccountId::new(s)
    }
}

impl From<AccountId> for String {
    fn from(a: AccountId) -> String {
        a.0
    }
}

/// Whether an account is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Normal.
    #[default]
    Active,
    /// Frozen: only the permissions the authorizer allows while suspended (by default
    /// reading and listing members) work, for the owner and members alike.
    Suspended,
    /// Closed: treated as not found.
    Closed,
}

impl Status {
    /// Its name.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Suspended => "suspended",
            Status::Closed => "closed",
        }
    }

    /// Parses [`as_str`](Self::as_str).
    pub fn parse(s: &str) -> AccountResult<Self> {
        match s {
            "active" => Ok(Status::Active),
            "suspended" => Ok(Status::Suspended),
            "closed" => Ok(Status::Closed),
            _ => Err(AccountError::Invalid(format!("unknown status {s:?}"))),
        }
    }
}

/// An account (tenant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Its id.
    pub id: AccountId,
    /// A display name.
    pub name: String,
    /// The owner's user id. Only the owner acts as the builtin `owner` role.
    pub owner: String,
    /// Active, suspended or closed.
    pub status: Status,
    /// The account's roles and defaults for invitees.
    pub roles: RoleSet,
    /// Created (ms).
    pub created_at_ms: i64,
    /// Last changed (ms).
    pub updated_at_ms: i64,
}

impl Account {
    /// A new active account.
    pub fn new(id: AccountId, name: &str, owner: &str, roles: RoleSet, now_ms: i64) -> AccountResult<Self> {
        check_name(name)?;
        check_user(owner)?;
        Ok(Account { id, name: name.trim().into(), owner: owner.into(), status: Status::Active, roles, created_at_ms: now_ms, updated_at_ms: now_ms })
    }
}

pub(crate) fn check_name(name: &str) -> AccountResult<()> {
    let n = name.trim();
    if n.is_empty() || n.len() > 128 || n.chars().any(char::is_control) {
        return Err(AccountError::Invalid("account name: 1-128 characters, no control characters".into()));
    }
    Ok(())
}

/// One identity's membership of an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The account.
    pub account: AccountId,
    /// The member's user id.
    pub user_id: String,
    /// The role id they hold (never the builtin owner role).
    pub role: String,
    /// Who added them (user id).
    pub added_by: String,
    /// Added or last re-admitted (ms). Revocations void memberships added at or before their
    /// `before` time.
    pub added_at_ms: i64,
    /// Optional expiry (ms).
    pub expires_at_ms: Option<i64>,
    /// The owner-signed weirdnet-net `Membership` (JSON), when the app issues one.
    #[serde(default)]
    pub signed: Option<Vec<u8>>,
}

impl Member {
    /// True while unexpired at `now_ms`.
    pub fn current(&self, now_ms: i64) -> bool {
        self.expires_at_ms.is_none_or(|e| e > now_ms)
    }
}

/// A pending invitation. The code is shown once; only its SHA-256 is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    /// Its id (random, safe to show).
    pub id: String,
    /// The account.
    pub account: AccountId,
    /// The role the invitee gets.
    pub role: String,
    /// Only this user may accept it, when set.
    pub invitee: Option<String>,
    /// Who invited (user id).
    pub created_by: String,
    /// Created (ms).
    pub created_at_ms: i64,
    /// Expires (ms).
    pub expires_at_ms: i64,
    /// SHA-256 of the code (hex).
    pub code_hash: String,
    /// Withdrawn (ms).
    pub revoked_at_ms: Option<i64>,
    /// Accepted (ms) and by whom.
    pub accepted: Option<(String, i64)>,
}

impl Invitation {
    /// True while it can still be accepted.
    pub fn open(&self, now_ms: i64) -> bool {
        self.revoked_at_ms.is_none() && self.accepted.is_none() && self.expires_at_ms > now_ms
    }
}

/// A revocation: every membership of `user_id` in `account` added at or before `before_ms`
/// is void. Re-admitting someone is adding them again later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// The account.
    pub account: AccountId,
    /// Whose memberships.
    pub user_id: String,
    /// Memberships added at or before this time (ms) are void.
    pub before_ms: i64,
    /// When it was made (ms).
    pub at_ms: i64,
    /// Who revoked (user id).
    pub by: String,
    /// A short reason for the audit trail.
    pub reason: String,
    /// The owner-signed weirdnet-net `MemberRevocation` (JSON), when the app issues one.
    #[serde(default)]
    pub signed: Option<Vec<u8>>,
}

impl Revocation {
    /// Whether this voids `m`.
    pub fn voids(&self, m: &Member) -> bool {
        self.account == m.account && self.user_id == m.user_id && m.added_at_ms <= self.before_ms
    }
}

/// Ties an API key ([`crate::apikeys::ApiKeyRecord`] id) to the identity that made it, one
/// account and a role. The key acts with the lower of that role and its maker's current role,
/// so it loses power when its maker does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBinding {
    /// The API key record id.
    pub key_id: i64,
    /// The account.
    pub account: AccountId,
    /// Who made it (user id).
    pub user_id: String,
    /// The role it acts under, at most its maker's.
    pub role: String,
    /// Created (ms).
    pub created_at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(AccountId::new("acct-1").is_ok());
        assert!(AccountId::new("Acct").is_err());
        assert!(AccountId::new("-a").is_err());
        assert!(AccountId::new("").is_err());
        assert_eq!(AccountId::random().as_str().len(), 32);
        let j = serde_json::to_string(&AccountId::new("a1").unwrap()).unwrap();
        assert_eq!(j, "\"a1\"");
        assert!(serde_json::from_str::<AccountId>("\"BAD ID\"").is_err());
    }

    #[test]
    fn status_round_trip() {
        for s in [Status::Active, Status::Suspended, Status::Closed] {
            assert_eq!(Status::parse(s.as_str()).unwrap(), s);
        }
        assert!(Status::parse("x").is_err());
    }

    #[test]
    fn revocation_voids_older_only() {
        let m = |at| Member {
            account: AccountId::new("a").unwrap(),
            user_id: "u".into(),
            role: "viewer".into(),
            added_by: "o".into(),
            added_at_ms: at,
            expires_at_ms: None,
            signed: None,
        };
        let r = Revocation {
            account: AccountId::new("a").unwrap(),
            user_id: "u".into(),
            before_ms: 10,
            at_ms: 11,
            by: "o".into(),
            reason: String::new(),
            signed: None,
        };
        assert!(r.voids(&m(10)));
        assert!(!r.voids(&m(12)));
    }
}
