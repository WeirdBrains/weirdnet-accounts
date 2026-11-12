//! User-name and email rules.

use crate::{Error, Result};

/// Which user names are allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamePolicy {
    /// Shortest name.
    pub min: usize,
    /// Longest name.
    pub max: usize,
    /// Allowed punctuation besides ASCII letters and digits (never first or last).
    pub punctuation: &'static str,
}

impl NamePolicy {
    /// AUR-style names: 3-16 characters of `[A-Za-z0-9._-]`, starting and ending alphanumeric.
    pub const AUR: Self = Self { min: 3, max: 16, punctuation: "._-" };

    /// Checks a name.
    pub fn validate(&self, name: &str) -> Result<()> {
        let ok = (self.min..=self.max).contains(&name.len())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || self.punctuation.contains(c))
            && name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name.ends_with(|c: char| c.is_ascii_alphanumeric());
        if ok {
            return Ok(());
        }
        let punct: Vec<String> = self.punctuation.chars().map(String::from).collect();
        Err(Error::Invalid(format!(
            "user name must be {}-{} characters of A-Z a-z 0-9 {} and start/end alphanumeric",
            self.min,
            self.max,
            punct.join(" ")
        )))
    }
}

impl Default for NamePolicy {
    fn default() -> Self {
        Self::AUR
    }
}

/// Longest email address accepted.
pub const MAX_EMAIL_LEN: usize = 254;

/// A light email check (an `@`, at most 254 bytes); returns the trimmed address. Ownership
/// is proven by the verification mail, not here.
pub fn validate_email(email: &str) -> Result<&str> {
    let email = email.trim();
    if !email.contains('@') || email.len() > MAX_EMAIL_LEN {
        return Err(Error::Invalid("invalid email address".into()));
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aur_names() {
        let p = NamePolicy::default();
        for ok in ["abc", "a.b-c_d", "A1234567890123Z9"] {
            p.validate(ok).unwrap();
        }
        for bad in ["ab", ".abc", "abc-", "a b c", "abcdefghijklmnopq", "äbc"] {
            assert!(p.validate(bad).is_err(), "{bad}");
        }
        assert_eq!(p.validate("x").unwrap_err().to_string(), "user name must be 3-16 characters of A-Z a-z 0-9 . _ - and start/end alphanumeric");
    }

    #[test]
    fn emails() {
        assert_eq!(validate_email("  a@b.c ").unwrap(), "a@b.c");
        assert!(validate_email("nope").is_err());
        assert!(validate_email(&format!("{}@b.c", "a".repeat(260))).is_err());
    }
}
