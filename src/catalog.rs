//! Account permissions on top of the weirdnet-access core, and a ranked role preset.
//!
//! Apps add their own permissions to [`catalog`] (with `Catalog::add` and `Catalog::imply`)
//! and build roles with [`tiered`] or `RoleSet::new`. Nothing here is specific to one app.

use weirdnet_access::catalog::{ALL, core};
use weirdnet_access::roles::OWNER;
use weirdnet_access::{Catalog, Result, Role, RoleSet};

/// See the account's details and settings.
pub const ACCOUNT_VIEW: &str = "account.view";
/// Change the account's name and settings.
pub const ACCOUNT_EDIT: &str = "account.edit";
/// Suspend and resume the account.
pub const ACCOUNT_SUSPEND: &str = "account.suspend";
/// Close the account (only the owner, through the builtin owner role, by default).
pub const ACCOUNT_CLOSE: &str = "account.close";
/// Read the account's audit records.
pub const AUDIT_VIEW: &str = "audit.view";
/// Create and revoke API keys bound to the account.
pub const KEYS_MANAGE: &str = "keys.manage";

/// The weirdnet-access core plus the account permissions. `account.view` is implied by
/// `account.edit`; `members.invite` by `members.role`.
pub fn catalog() -> Catalog {
    let mut c = Catalog::core();
    add_account_permissions(&mut c).expect("the account permissions are valid");
    c
}

/// Adds the account permissions to an existing catalog.
pub fn add_account_permissions(c: &mut Catalog) -> Result<()> {
    for (name, what, managing) in [
        (ACCOUNT_VIEW, "see the account's details and settings", false),
        (ACCOUNT_EDIT, "change the account's name and settings", true),
        (ACCOUNT_SUSPEND, "suspend and resume the account", true),
        (ACCOUNT_CLOSE, "close the account", true),
        (AUDIT_VIEW, "read the account's audit records", false),
        (KEYS_MANAGE, "create and revoke the account's API keys", true),
    ] {
        c.add(name, what, managing)?;
    }
    c.imply(ACCOUNT_EDIT, &[ACCOUNT_VIEW])?;
    c.imply(core::MEMBERS_ROLE, &[core::MEMBERS_INVITE])?;
    Ok(())
}

/// One role for [`tiered`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier<'a> {
    /// Its id and name (`trader`, `viewer`, ...).
    pub name: &'a str,
    /// Higher outranks lower; must be below 100 (the owner).
    pub rank: i64,
    /// Its permissions.
    pub perms: &'a [&'a str],
}

/// A ranked role set: the builtin owner (rank 100, everything) plus `tiers`. Each tier is
/// builtin, so members can't remove it. `invite` is the role invitees get by default.
///
/// For example, an app can use owner, `admin` (80), `trader` (60), `viewer` (20) and
/// `auditor` (10); see [`standard`] for a generic version.
pub fn tiered(catalog: &Catalog, tiers: &[Tier<'_>], invite: Option<&str>) -> Result<RoleSet> {
    let mut roles = vec![Role { id: OWNER.into(), name: OWNER.into(), rank: 100, perms: vec![ALL.into()], builtin: true }];
    for t in tiers {
        if t.rank >= 100 {
            return Err(weirdnet_access::Error::Denied(format!("{} must rank below the owner", t.name)));
        }
        roles.push(Role {
            id: t.name.into(),
            name: t.name.into(),
            rank: t.rank,
            perms: t.perms.iter().map(|p| p.to_string()).collect(),
            builtin: true,
        });
    }
    let mut set = RoleSet::new(catalog, roles)?;
    if let Some(i) = invite {
        if set.get(i).is_none_or(|r| r.is_owner()) {
            return Err(weirdnet_access::Error::Denied(format!("{i} is not an invitable role")));
        }
        set.invite_role = Some(i.into());
    }
    Ok(set)
}

/// Generic ranked roles over [`catalog`] (or a catalog that extends it):
///
/// | Role | Rank | Permissions |
/// |---|---|---|
/// | `owner` | 100 | everything |
/// | `admin` | 80 | everything except `account.close`, plus `admin_extra` |
/// | `member` | 50 | `read`, `members.list`, `account.view`, plus `member_extra` |
/// | `viewer` | 20 | `read`, `members.list`, `account.view` |
/// | `auditor` | 10 | `read`, `account.view`, `audit.view` |
///
/// Invitees get `viewer`. Apps that want other names (`trader` for `member`) use [`tiered`].
pub fn standard(catalog: &Catalog, member_extra: &[&str]) -> Result<RoleSet> {
    let admin: Vec<String> = catalog.all_names().into_iter().filter(|p| p != ACCOUNT_CLOSE).collect();
    let admin: Vec<&str> = admin.iter().map(String::as_str).collect();
    let mut member = vec![core::READ, core::MEMBERS_LIST, ACCOUNT_VIEW];
    member.extend(member_extra.iter().copied().filter(|p| ![core::READ, core::MEMBERS_LIST, ACCOUNT_VIEW].contains(p)));
    tiered(
        catalog,
        &[
            Tier { name: "admin", rank: 80, perms: &admin },
            Tier { name: "member", rank: 50, perms: &member },
            Tier { name: "viewer", rank: 20, perms: &[core::READ, core::MEMBERS_LIST, ACCOUNT_VIEW] },
            Tier { name: "auditor", rank: 10, perms: &[core::READ, ACCOUNT_VIEW, AUDIT_VIEW] },
        ],
        Some("viewer"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use weirdnet_access::Actor;

    #[test]
    fn standard_roles() {
        let c = catalog();
        let s = standard(&c, &[]).unwrap();
        assert_eq!(s.roles().iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["owner", "admin", "member", "viewer", "auditor"]);
        let admin = s.actor("a", "admin").unwrap();
        assert!(s.can(&c, &admin, KEYS_MANAGE));
        assert!(!s.can(&c, &admin, ACCOUNT_CLOSE));
        let viewer = s.actor("v", "viewer").unwrap();
        assert!(s.can(&c, &viewer, ACCOUNT_VIEW));
        assert!(!s.can(&c, &viewer, AUDIT_VIEW));
        let aud = s.actor("x", "auditor").unwrap();
        assert!(s.can(&c, &aud, AUDIT_VIEW));
        assert!(!s.can(&c, &aud, core::MEMBERS_LIST));
        assert!(s.can(&c, &Actor::Owner, ACCOUNT_CLOSE));
        assert_eq!(s.invite_role.as_deref(), Some("viewer"));
    }

    #[test]
    fn tiers_rank_below_owner() {
        let c = catalog();
        assert!(tiered(&c, &[Tier { name: "boss", rank: 100, perms: &[] }], None).is_err());
        assert!(tiered(&c, &[Tier { name: "x", rank: 5, perms: &["nope"] }], None).is_err());
        assert!(tiered(&c, &[Tier { name: "x", rank: 5, perms: &[] }], Some("owner")).is_err());
    }

    #[test]
    fn implications() {
        let c = catalog();
        assert!(c.implies_perm(ACCOUNT_EDIT, ACCOUNT_VIEW));
        assert!(c.implies_perm(core::MEMBERS_ROLE, core::MEMBERS_INVITE));
    }
}
