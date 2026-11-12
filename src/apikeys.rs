//! Org-scoped API keys.
//!
//! A key looks like `<service>_<org>_<64 hex>` (for example `sg_weirdbrains_…`): the service
//! prefix and org stay visible so leaked keys are easy to spot and route, and the 256-bit random
//! part makes it unguessable. The key is shown once at creation; only its SHA-256 is stored.
//! Each key is bound to one org, optionally to listed apps and channels, carries scopes, and can
//! expire or be revoked instantly. Recording last use and an audit row per use is the caller's.

use crate::token::{hashes_equal, random_token, token_hash};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Characters shown from the random part in listings.
pub const DISPLAY_CHARS: usize = 8;

/// Why a key was refused. Messages never include the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiKeyError {
    /// Not a key of this service, or not found.
    #[error("invalid API key")]
    Unknown,
    /// Revoked.
    #[error("API key revoked")]
    Revoked,
    /// Past its expiry.
    #[error("API key expired")]
    Expired,
    /// Bound to a different org.
    #[error("API key is not valid for this organization")]
    WrongOrg,
    /// Lacks a scope.
    #[error("API key lacks scope {0}")]
    MissingScope(String),
    /// Not bound to this app.
    #[error("API key is not valid for this app")]
    App,
    /// Not bound to this channel.
    #[error("API key is not valid for this channel")]
    Channel,
}

/// A newly issued key. The secret is returned once; it is not `Debug` and not stored.
pub struct IssuedKey {
    secret: String,
    /// What to store: SHA-256 of the key.
    pub hash: String,
    /// What to show in listings: `<service>_<org>_<first 8 hex>…`.
    pub display: String,
}

impl IssuedKey {
    /// The full key, to show the user exactly once.
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for IssuedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedKey").field("secret", &"<redacted>").field("display", &self.display).finish()
    }
}

fn check_service(service: &str) -> Result<()> {
    if service.is_empty() || service.len() > 8 || !service.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err(Error::Invalid("API key service prefix must be 1-8 lowercase letters or digits".into()));
    }
    Ok(())
}

fn check_org(org: &str) -> Result<()> {
    if org.is_empty() || org.len() > 64 || !org.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(Error::Invalid("organization name not allowed in an API key".into()));
    }
    Ok(())
}

/// Issues a new key for `org` under a service prefix such as `sg`.
pub fn issue(service: &str, org: &str) -> Result<IssuedKey> {
    check_service(service)?;
    check_org(org)?;
    let random = random_token();
    let secret = format!("{service}_{org}_{random}");
    Ok(IssuedKey { hash: token_hash(&secret), display: format!("{service}_{org}_{}…", &random[..DISPLAY_CHARS]), secret })
}

/// The visible parts of a presented key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyParts<'a> {
    /// Service prefix.
    pub service: &'a str,
    /// Org name.
    pub org: &'a str,
}

/// Splits a presented key, checking its shape. The org may itself contain `_`.
pub fn parse(key: &str) -> Option<KeyParts<'_>> {
    let (service, rest) = key.split_once('_')?;
    let (org, random) = rest.rsplit_once('_')?;
    let shaped = random.len() == 64 && random.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    (shaped && check_service(service).is_ok() && check_org(org).is_ok()).then_some(KeyParts { service, org })
}

/// A scope such as `releases:write`: `resource:verb`, lowercase letters and `_`.
pub fn validate_scope(scope: &str) -> Result<()> {
    let ok = scope.split_once(':').is_some_and(|(r, v)| {
        let part = |s: &str| !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        part(r) && part(v)
    });
    if ok { Ok(()) } else { Err(Error::Invalid(format!("invalid scope {scope:?}; expected resource:verb"))) }
}

/// A stored key (everything but the secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    /// Storage id.
    pub id: i64,
    /// A label the user chose.
    pub name: String,
    /// The org it belongs to.
    pub org: String,
    /// SHA-256 of the key.
    pub hash: String,
    /// Listing form.
    pub display: String,
    /// Granted scopes.
    pub scopes: BTreeSet<String>,
    /// Apps it may act on; empty means every app of the org.
    #[serde(default)]
    pub apps: Vec<String>,
    /// Channels it may act on; empty means every channel.
    #[serde(default)]
    pub channels: Vec<String>,
    /// Creation time (Unix seconds).
    pub created_at: i64,
    /// Expiry (Unix seconds), if any.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Revocation time, if revoked.
    #[serde(default)]
    pub revoked_at: Option<i64>,
    /// Last use (maintained by the caller).
    #[serde(default)]
    pub last_used_at: Option<i64>,
    /// Last client address (maintained by the caller).
    #[serde(default)]
    pub last_used_ip: Option<String>,
}

/// What a request wants to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access<'a> {
    /// Org the request acts on.
    pub org: &'a str,
    /// Scope needed.
    pub scope: &'a str,
    /// App, when the request names one.
    pub app: Option<&'a str>,
    /// Channel, when the request names one.
    pub channel: Option<&'a str>,
}

impl ApiKeyRecord {
    /// Builds a record for a freshly issued key, validating scopes.
    pub fn new(id: i64, name: &str, org: &str, issued: &IssuedKey, scopes: &[&str], created_at: i64) -> Result<Self> {
        for s in scopes {
            validate_scope(s)?;
        }
        Ok(Self {
            id,
            name: name.to_owned(),
            org: org.to_owned(),
            hash: issued.hash.clone(),
            display: issued.display.clone(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            apps: Vec::new(),
            channels: Vec::new(),
            created_at,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
        })
    }

    /// Whether this record belongs to `presented` (constant-time on the hashes).
    pub fn matches(&self, presented: &str) -> bool {
        hashes_equal(&self.hash, &token_hash(presented))
    }

    /// Checks the key may perform `access` at `now`.
    pub fn authorize(&self, access: &Access<'_>, now: i64) -> std::result::Result<(), ApiKeyError> {
        if self.revoked_at.is_some_and(|t| t <= now) {
            return Err(ApiKeyError::Revoked);
        }
        if self.expires_at.is_some_and(|t| now >= t) {
            return Err(ApiKeyError::Expired);
        }
        if self.org != access.org {
            return Err(ApiKeyError::WrongOrg);
        }
        if !self.scopes.contains(access.scope) {
            return Err(ApiKeyError::MissingScope(access.scope.to_owned()));
        }
        if !self.apps.is_empty() && !access.app.is_some_and(|a| self.apps.iter().any(|x| x == a)) {
            return Err(ApiKeyError::App);
        }
        if !self.channels.is_empty() && !access.channel.is_some_and(|c| self.channels.iter().any(|x| x == c)) {
            return Err(ApiKeyError::Channel);
        }
        Ok(())
    }
}

/// Finds the record for a presented key among candidates (normally looked up by hash).
pub fn find<'a>(records: &'a [ApiKeyRecord], service: &str, presented: &str) -> std::result::Result<&'a ApiKeyRecord, ApiKeyError> {
    let parts = parse(presented).ok_or(ApiKeyError::Unknown)?;
    if parts.service != service {
        return Err(ApiKeyError::Unknown);
    }
    let hash = token_hash(presented);
    records.iter().find(|r| hashes_equal(&r.hash, &hash) && r.org == parts.org).ok_or(ApiKeyError::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(scopes: &[&str]) -> (IssuedKey, ApiKeyRecord) {
        let k = issue("sg", "weird_brains").unwrap();
        let r = ApiKeyRecord::new(1, "ci", "weird_brains", &k, scopes, 100).unwrap();
        (k, r)
    }

    fn access<'a>(scope: &'a str) -> Access<'a> {
        Access { org: "weird_brains", scope, app: Some("morph"), channel: Some("stable") }
    }

    #[test]
    fn issued_keys_are_shaped_hashed_and_redacted() {
        let k = issue("sg", "weird_brains").unwrap();
        assert!(k.secret().starts_with("sg_weird_brains_"));
        assert_eq!(k.secret().len(), "sg_weird_brains_".len() + 64);
        assert_eq!(k.hash, token_hash(k.secret()));
        assert!(k.display.ends_with('…') && !k.display.contains(&k.secret()[20..]));
        assert!(!format!("{k:?}").contains(k.secret()));
        assert_eq!(parse(k.secret()).unwrap(), KeyParts { service: "sg", org: "weird_brains" });
        assert_ne!(issue("sg", "o").unwrap().hash, issue("sg", "o").unwrap().hash);
        assert!(issue("SG", "o").is_err() && issue("sg", "bad org").is_err() && issue("", "o").is_err());
    }

    #[test]
    fn malformed_keys_do_not_parse() {
        for k in ["", "sg", "sg_org", "sg_org_abc", &format!("sg_org_{}", "G".repeat(64)), &format!("sg__{}", "a".repeat(64))] {
            assert!(parse(k).is_none(), "{k}");
        }
    }

    #[test]
    fn authorize_checks_scope_org_bindings_expiry_and_revocation() {
        let (_, mut r) = record(&["releases:write", "rollouts:manage"]);
        r.authorize(&access("releases:write"), 200).unwrap();
        assert_eq!(r.authorize(&access("rollouts:publish"), 200), Err(ApiKeyError::MissingScope("rollouts:publish".into())));
        let other = Access { org: "else", ..access("releases:write") };
        assert_eq!(r.authorize(&other, 200), Err(ApiKeyError::WrongOrg));
        r.apps = vec!["muninn".into()];
        assert_eq!(r.authorize(&access("releases:write"), 200), Err(ApiKeyError::App));
        r.apps = vec!["morph".into()];
        r.channels = vec!["beta".into()];
        assert_eq!(r.authorize(&access("releases:write"), 200), Err(ApiKeyError::Channel));
        let no_channel = Access { channel: None, ..access("releases:write") };
        assert_eq!(r.authorize(&no_channel, 200), Err(ApiKeyError::Channel));
        r.channels.clear();
        r.expires_at = Some(300);
        r.authorize(&access("releases:write"), 299).unwrap();
        assert_eq!(r.authorize(&access("releases:write"), 300), Err(ApiKeyError::Expired));
        r.revoked_at = Some(250);
        assert_eq!(r.authorize(&access("releases:write"), 260), Err(ApiKeyError::Revoked));
    }

    #[test]
    fn find_matches_by_hash_service_and_org() {
        let (k, r) = record(&["apps:read"]);
        let records = vec![r];
        assert_eq!(find(&records, "sg", k.secret()).unwrap().id, 1);
        assert!(records[0].matches(k.secret()));
        assert_eq!(find(&records, "taur", k.secret()), Err(ApiKeyError::Unknown));
        let mut forged = k.secret().to_string();
        forged.replace_range(forged.len() - 1.., if forged.ends_with('0') { "1" } else { "0" });
        assert_eq!(find(&records, "sg", &forged), Err(ApiKeyError::Unknown));
        let moved = k.secret().replacen("weird_brains", "other", 1);
        assert_eq!(find(&records, "sg", &moved), Err(ApiKeyError::Unknown));
    }

    #[test]
    fn scopes_are_validated() {
        validate_scope("rollouts:publish").unwrap();
        for bad in ["rollouts", ":x", "x:", "Releases:write", "a:b:c", "a-b:c"] {
            assert!(validate_scope(bad).is_err(), "{bad}");
        }
        let k = issue("sg", "o").unwrap();
        assert!(ApiKeyRecord::new(1, "x", "o", &k, &["bad"], 0).is_err());
        let r = ApiKeyRecord::new(1, "x", "o", &k, &["apps:read"], 0).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(k.secret()));
        assert_eq!(serde_json::from_str::<ApiKeyRecord>(&json).unwrap(), r);
    }
}
