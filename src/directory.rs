//! [`Accounts`]: account, member, invitation and key-binding operations, each checked with the
//! [`Authorizer`] and the weirdnet-access rank rules (nobody grants a role at or above their
//! own, or acts on someone ranked at or above them; only the owner is the owner).

use crate::account::{
    Account, AccountError, AccountId, AccountResult, Invitation, KeyBinding, Member, Revocation, Status, check_name, check_user, random_id,
};
use crate::authz::{Admitted, Authorize, Authorizer, Caller, Request};
use crate::catalog::{ACCOUNT_CLOSE, ACCOUNT_EDIT, ACCOUNT_SUSPEND, KEYS_MANAGE};
use crate::store::Store;
use crate::token::{random_token, token_hash};
use std::sync::Arc;
use weirdnet_access::catalog::core;
use weirdnet_access::{Actor, Catalog, RoleSet};

/// Longest an invitation may stay open: 30 days.
pub const MAX_INVITE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// A new invitation and its code. The code is shown once and never stored; it isn't `Debug`.
pub struct NewInvitation {
    /// The stored record.
    pub invitation: Invitation,
    code: String,
}

impl NewInvitation {
    /// The code to hand to the invitee, exactly once.
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Debug for NewInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewInvitation").field("invitation", &self.invitation).field("code", &"<redacted>").finish()
    }
}

/// Account operations over a [`Store`]. Callers are user ids the app has already
/// authenticated (from a node cert, a session or an API key).
#[derive(Debug, Clone)]
pub struct Accounts {
    authz: Authorizer,
}

impl Accounts {
    /// Operations over `store` with `catalog` (see [`crate::catalog::catalog`]).
    pub fn new(store: Arc<dyn Store>, catalog: Catalog) -> Self {
        Accounts { authz: Authorizer::new(store, Arc::new(catalog)) }
    }

    /// Operations using an existing authorizer (and its policy).
    pub fn with_authorizer(authz: Authorizer) -> Self {
        Accounts { authz }
    }

    /// The authorizer, for service hooks.
    pub fn authorizer(&self) -> &Authorizer {
        &self.authz
    }

    fn store(&self) -> &Arc<dyn Store> {
        self.authz.store()
    }

    fn admit(&self, user: &str, account: &AccountId, perm: &str, now_ms: i64) -> AccountResult<Admitted> {
        let caller = Caller::user(user);
        Ok(self.authz.authorize(&Request { caller: &caller, account, perm, now_ms })?)
    }

    fn load(&self, id: &AccountId) -> AccountResult<Account> {
        self.store().account(id)?.ok_or(AccountError::NotFound("account"))
    }

    /// Creates an account owned by `owner`. Every role must be in the catalog.
    pub fn create(&self, owner: &str, id: AccountId, name: &str, roles: RoleSet, now_ms: i64) -> AccountResult<Account> {
        for r in roles.roles() {
            for p in &r.perms {
                self.authz.catalog().check(p)?;
            }
        }
        let a = Account::new(id, name, owner, roles, now_ms)?;
        self.store().create_account(&a)?;
        Ok(a)
    }

    /// One account, if `user` may see it (`account.view`).
    pub fn get(&self, user: &str, id: &AccountId, now_ms: i64) -> AccountResult<Account> {
        self.admit(user, id, crate::catalog::ACCOUNT_VIEW, now_ms)?;
        self.load(id)
    }

    /// The open accounts `user` owns or belongs to, with the role they hold.
    pub fn accounts_for(&self, user: &str, now_ms: i64) -> AccountResult<Vec<(Account, String)>> {
        let mut out = vec![];
        for a in self.store().accounts()? {
            if a.status == Status::Closed {
                continue;
            }
            let caller = Caller::user(user);
            if let Ok((a, f)) = self.authz.facts(&caller, &a.id, now_ms) {
                if f.is_owner {
                    out.push((a, weirdnet_access::roles::OWNER.to_string()));
                } else if let Some(r) = f.membership_role {
                    out.push((a, r));
                }
            }
        }
        Ok(out)
    }

    /// Renames an account (`account.edit`).
    pub fn rename(&self, user: &str, id: &AccountId, name: &str, now_ms: i64) -> AccountResult<Account> {
        check_name(name)?;
        self.admit(user, id, ACCOUNT_EDIT, now_ms)?;
        let mut a = self.load(id)?;
        a.name = name.trim().into();
        a.updated_at_ms = now_ms;
        self.store().update_account(&a)?;
        Ok(a)
    }

    /// Replaces an account's roles (`roles.manage`; only the owner, since a whole role set
    /// can change roles at any rank). Members whose role disappears lose access.
    pub fn set_roles(&self, user: &str, id: &AccountId, roles: RoleSet, now_ms: i64) -> AccountResult<Account> {
        let ad = self.admit(user, id, core::ROLES_MANAGE, now_ms)?;
        if ad.actor != Actor::Owner {
            return Err(AccountError::Denied("only the owner replaces the role set".into()));
        }
        for r in roles.roles() {
            for p in &r.perms {
                self.authz.catalog().check(p)?;
            }
        }
        let mut a = self.load(id)?;
        a.roles = roles;
        a.updated_at_ms = now_ms;
        self.store().update_account(&a)?;
        Ok(a)
    }

    /// Suspends, resumes or closes an account (`account.suspend`, or `account.close` to
    /// close). Only the owner acts on a suspended account; a closed account can't reopen.
    pub fn set_status(&self, user: &str, id: &AccountId, status: Status, now_ms: i64) -> AccountResult<Account> {
        let perm = if status == Status::Closed { ACCOUNT_CLOSE } else { ACCOUNT_SUSPEND };
        let caller = Caller::user(user);
        self.authz.authorize_owner_while_suspended(&Request { caller: &caller, account: id, perm, now_ms })?;
        let mut a = self.load(id)?;
        a.status = status;
        a.updated_at_ms = now_ms;
        self.store().update_account(&a)?;
        Ok(a)
    }

    fn grantable<'a>(&self, a: &'a Account, ad: &Admitted, role: Option<&str>) -> AccountResult<&'a weirdnet_access::Role> {
        let id = role.or(a.roles.invite_role.as_deref()).ok_or_else(|| AccountError::Invalid("no role given and no default".into()))?;
        let r = a.roles.get(id).ok_or_else(|| AccountError::Invalid(format!("no role {id}")))?;
        if r.is_owner() {
            return Err(AccountError::Denied("nobody joins as the owner".into()));
        }
        a.roles.check_grant(&ad.actor, r)?;
        Ok(r)
    }

    /// Invites someone (`members.invite`) to a role ranked below the inviter's (default: the
    /// account's invite role). `invitee` limits who may accept. The code is shown once.
    pub fn invite(
        &self,
        user: &str,
        id: &AccountId,
        role: Option<&str>,
        invitee: Option<&str>,
        ttl_ms: i64,
        now_ms: i64,
    ) -> AccountResult<NewInvitation> {
        if !(1..=MAX_INVITE_TTL_MS).contains(&ttl_ms) {
            return Err(AccountError::Invalid("invitations last from 1 ms to 30 days".into()));
        }
        if let Some(u) = invitee {
            check_user(u)?;
        }
        let ad = self.admit(user, id, core::MEMBERS_INVITE, now_ms)?;
        let a = self.load(id)?;
        let r = self.grantable(&a, &ad, role)?;
        let code = random_token();
        let invitation = Invitation {
            id: random_id(),
            account: a.id.clone(),
            role: r.id.clone(),
            invitee: invitee.map(Into::into),
            created_by: user.into(),
            created_at_ms: now_ms,
            expires_at_ms: now_ms + ttl_ms,
            code_hash: token_hash(&code),
            revoked_at_ms: None,
            accepted: None,
        };
        self.store().put_invitation(&invitation)?;
        Ok(NewInvitation { invitation, code })
    }

    /// An account's invitations (`members.invite`).
    pub fn invitations(&self, user: &str, id: &AccountId, now_ms: i64) -> AccountResult<Vec<Invitation>> {
        self.admit(user, id, core::MEMBERS_INVITE, now_ms)?;
        self.store().invitations(id)
    }

    /// Withdraws an open invitation (`members.invite`).
    pub fn withdraw_invitation(&self, user: &str, invitation_id: &str, now_ms: i64) -> AccountResult<Invitation> {
        let mut i = self.store().invitation(invitation_id)?.ok_or(AccountError::NotFound("invitation"))?;
        self.admit(user, &i.account, core::MEMBERS_INVITE, now_ms)?;
        if !i.open(now_ms) {
            return Err(AccountError::Invalid("the invitation is no longer open".into()));
        }
        i.revoked_at_ms = Some(now_ms);
        self.store().put_invitation(&i)?;
        Ok(i)
    }

    /// `user` accepts an invitation by its code and becomes a member. Unknown, used,
    /// withdrawn and expired codes all give the same error.
    pub fn accept(&self, user: &str, code: &str, now_ms: i64) -> AccountResult<Member> {
        check_user(user)?;
        let bad = || AccountError::Denied("invalid or expired invitation".into());
        let mut i = self.store().invitation_by_code(&token_hash(code))?.ok_or_else(bad)?;
        if !i.open(now_ms) || i.invitee.as_deref().is_some_and(|u| u != user) {
            return Err(bad());
        }
        let a = self.load(&i.account)?;
        if a.status != Status::Active {
            return Err(bad());
        }
        if a.owner == user {
            return Err(AccountError::Invalid("the owner is already in the account".into()));
        }
        if a.roles.get(&i.role).is_none_or(|r| r.is_owner()) {
            return Err(AccountError::Invalid("the invitation's role is gone".into()));
        }
        let m = Member {
            account: a.id.clone(),
            user_id: user.into(),
            role: i.role.clone(),
            added_by: i.created_by.clone(),
            added_at_ms: now_ms,
            expires_at_ms: None,
            signed: None,
        };
        i.accepted = Some((user.into(), now_ms));
        self.store().accept_invitation(&i, &m)?;
        Ok(m)
    }

    /// Adds a member directly (`members.invite`, role ranked below the adder's).
    pub fn add_member(
        &self,
        by: &str,
        id: &AccountId,
        user: &str,
        role: Option<&str>,
        expires_at_ms: Option<i64>,
        now_ms: i64,
    ) -> AccountResult<Member> {
        check_user(user)?;
        let ad = self.admit(by, id, core::MEMBERS_INVITE, now_ms)?;
        let a = self.load(id)?;
        if a.owner == user {
            return Err(AccountError::Invalid("the owner is already in the account".into()));
        }
        if let Some(old) = self.store().member(id, user)? {
            a.roles.check_over(&ad.actor, Some(&old.role))?;
        }
        let r = self.grantable(&a, &ad, role)?;
        let m = Member {
            account: a.id.clone(),
            user_id: user.into(),
            role: r.id.clone(),
            added_by: by.into(),
            added_at_ms: now_ms,
            expires_at_ms,
            signed: None,
        };
        self.store().put_member(&m)?;
        Ok(m)
    }

    /// Changes a member's role (`members.role`, both their old and new role ranked below
    /// yours). A stored signed membership is dropped, since it names the old role.
    pub fn set_role(&self, by: &str, id: &AccountId, user: &str, role: &str, now_ms: i64) -> AccountResult<Member> {
        let ad = self.admit(by, id, core::MEMBERS_ROLE, now_ms)?;
        let a = self.load(id)?;
        let mut m = self.store().member(id, user)?.ok_or(AccountError::NotFound("member"))?;
        a.roles.check_set_role(self.authz.catalog(), &ad.actor, Some(&m.role), role)?;
        m.role = role.into();
        m.signed = None;
        self.store().put_member(&m)?;
        Ok(m)
    }

    /// Removes a member (`members.kick` over someone ranked below you, or anyone leaving on
    /// their own). Records a [`Revocation`] voiding every membership issued up to now,
    /// signed ones included.
    pub fn remove_member(&self, by: &str, id: &AccountId, user: &str, reason: &str, now_ms: i64) -> AccountResult<Revocation> {
        let a = self.load(id)?;
        if by != user {
            let ad = self.admit(by, id, core::MEMBERS_KICK, now_ms)?;
            let theirs = self.store().member(id, user)?.map(|m| m.role);
            a.roles.check_kick(self.authz.catalog(), &ad.actor, theirs.as_deref())?;
        } else if a.owner == user {
            return Err(AccountError::Invalid("the owner can't leave their own account".into()));
        }
        let r = Revocation {
            account: a.id.clone(),
            user_id: user.into(),
            before_ms: now_ms,
            at_ms: now_ms,
            by: by.into(),
            reason: reason.chars().take(200).collect(),
            signed: None,
        };
        self.store().revoke_member(&r)?;
        Ok(r)
    }

    /// An account's current members (`members.list`).
    pub fn members(&self, user: &str, id: &AccountId, now_ms: i64) -> AccountResult<Vec<Member>> {
        self.admit(user, id, core::MEMBERS_LIST, now_ms)?;
        let revs = self.store().revocations(id)?;
        Ok(self.store().members(id)?.into_iter().filter(|m| m.current(now_ms) && !revs.iter().any(|r| r.voids(m))).collect())
    }

    /// Binds an API key to the account (`keys.manage`). Its role may equal but not exceed
    /// the binder's, and is never the owner role.
    pub fn bind_key(&self, user: &str, id: &AccountId, key_id: i64, role: &str, now_ms: i64) -> AccountResult<KeyBinding> {
        let ad = self.admit(user, id, KEYS_MANAGE, now_ms)?;
        let a = self.load(id)?;
        let r = a.roles.get(role).ok_or_else(|| AccountError::Invalid(format!("no role {role}")))?;
        if r.is_owner() || r.rank > ad.actor.rank() {
            return Err(AccountError::Denied("a key can't outrank its maker or be the owner".into()));
        }
        if self.store().key_binding(key_id)?.is_some() {
            return Err(AccountError::Exists("key binding"));
        }
        let b = KeyBinding { key_id, account: a.id, user_id: user.into(), role: r.id.clone(), created_at_ms: now_ms };
        self.store().put_key_binding(&b)?;
        Ok(b)
    }

    /// Removes a key binding (`keys.manage`). Revoking the key record is the app's.
    pub fn unbind_key(&self, user: &str, key_id: i64, now_ms: i64) -> AccountResult<()> {
        let b = self.store().key_binding(key_id)?.ok_or(AccountError::NotFound("key binding"))?;
        self.admit(user, &b.account, KEYS_MANAGE, now_ms)?;
        self.store().remove_key_binding(key_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{MembershipPolicy, PresentedRole, Refusal};
    use crate::catalog::{self, ACCOUNT_VIEW, AUDIT_VIEW, Tier};
    use crate::store::MemoryStore;

    const OWNER: &str = "owner-1";

    fn trading_roles(c: &Catalog) -> RoleSet {
        let all: Vec<String> = c.all_names().into_iter().filter(|p| p != ACCOUNT_CLOSE).collect();
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        catalog::tiered(
            c,
            &[
                Tier { name: "admin", rank: 80, perms: &all },
                Tier { name: "trader", rank: 60, perms: &["read", "members.list", ACCOUNT_VIEW, "orders.manual"] },
                Tier { name: "viewer", rank: 20, perms: &["read", "members.list", ACCOUNT_VIEW] },
                Tier { name: "auditor", rank: 10, perms: &["read", ACCOUNT_VIEW, AUDIT_VIEW] },
            ],
            Some("viewer"),
        )
        .unwrap()
    }

    fn setup() -> (Accounts, AccountId) {
        let mut c = catalog::catalog();
        c.add("orders.manual", "place manual orders", true).unwrap();
        let roles = trading_roles(&c);
        let acc = Accounts::new(Arc::new(MemoryStore::new()), c);
        let id = AccountId::new("desk-1").unwrap();
        acc.create(OWNER, id.clone(), "Desk", roles, 1).unwrap();
        (acc, id)
    }

    fn can(acc: &Accounts, user: &str, id: &AccountId, perm: &str, now: i64) -> Result<Admitted, Refusal> {
        let caller = Caller::user(user);
        acc.authorizer().authorize(&Request { caller: &caller, account: id, perm, now_ms: now })
    }

    #[test]
    fn many_identities_many_accounts() {
        let (acc, id) = setup();
        let id2 = AccountId::new("desk-2").unwrap();
        let c = acc.authorizer().catalog().clone();
        acc.create("owner-2", id2.clone(), "Other", trading_roles(&c), 1).unwrap();
        acc.add_member(OWNER, &id, "alice", Some("trader"), None, 2).unwrap();
        acc.add_member(OWNER, &id, "bob", Some("viewer"), None, 2).unwrap();
        acc.add_member("owner-2", &id2, "alice", Some("admin"), None, 2).unwrap();
        assert_eq!(can(&acc, "alice", &id, "orders.manual", 3).unwrap().role(), "trader");
        assert!(matches!(can(&acc, "bob", &id, "orders.manual", 3), Err(Refusal::Denied(_))));
        assert_eq!(can(&acc, OWNER, &id, ACCOUNT_CLOSE, 3).unwrap().actor, Actor::Owner);
        assert_eq!(can(&acc, "alice", &id2, catalog::KEYS_MANAGE, 3).unwrap().role(), "admin");
        // Strangers learn nothing.
        assert_eq!(can(&acc, "mallory", &id, ACCOUNT_VIEW, 3), Err(Refusal::NotFound));
        assert_eq!(can(&acc, "bob", &AccountId::new("nope").unwrap(), ACCOUNT_VIEW, 3), Err(Refusal::NotFound));
        let anon = Caller::default();
        assert_eq!(acc.authorizer().authorize(&Request { caller: &anon, account: &id, perm: "read", now_ms: 3 }), Err(Refusal::NotFound));
        let mut alice = acc.accounts_for("alice", 3).unwrap().into_iter().map(|(a, r)| (a.id.to_string(), r)).collect::<Vec<_>>();
        alice.sort();
        assert_eq!(alice, [("desk-1".to_string(), "trader".to_string()), ("desk-2".to_string(), "admin".to_string())]);
        assert_eq!(acc.members("bob", &id, 3).unwrap().len(), 2);
    }

    #[test]
    fn rank_rules() {
        let (acc, id) = setup();
        acc.add_member(OWNER, &id, "adm", Some("admin"), None, 2).unwrap();
        acc.add_member("adm", &id, "t", Some("trader"), None, 2).unwrap();
        // An admin can't make another admin or touch one.
        assert!(matches!(acc.add_member("adm", &id, "x", Some("admin"), None, 2), Err(AccountError::Denied(_))));
        acc.add_member(OWNER, &id, "adm2", Some("admin"), None, 2).unwrap();
        assert!(acc.remove_member("adm", &id, "adm2", "", 3).is_err());
        assert!(acc.set_role("adm", &id, "adm2", "viewer", 3).is_err());
        // Nobody becomes the owner through membership.
        assert!(acc.add_member(OWNER, &id, "y", Some("owner"), None, 2).is_err());
        // Traders can't invite.
        assert!(matches!(acc.invite("t", &id, None, None, 1000, 3), Err(AccountError::Denied(_))));
        acc.set_role("adm", &id, "t", "viewer", 4).unwrap();
        assert_eq!(can(&acc, "t", &id, "read", 5).unwrap().role(), "viewer");
        // Only the owner swaps the role set.
        let c = acc.authorizer().catalog().clone();
        assert!(acc.set_roles("adm", &id, catalog::standard(&c, &[]).unwrap(), 5).is_err());
        acc.set_roles(OWNER, &id, catalog::standard(&c, &[]).unwrap(), 5).unwrap();
        // adm's role still exists in the standard set; t's viewer too.
        assert_eq!(can(&acc, "adm", &id, "read", 6).unwrap().role(), "admin");
    }

    #[test]
    fn invitations() {
        let (acc, id) = setup();
        let inv = acc.invite(OWNER, &id, None, Some("carol"), 1000, 10).unwrap();
        assert!(!format!("{inv:?}").contains(inv.code()));
        assert_eq!(inv.invitation.role, "viewer");
        assert!(acc.accept("dave", inv.code(), 11).is_err());
        let m = acc.accept("carol", inv.code(), 11).unwrap();
        assert_eq!(m.role, "viewer");
        assert!(acc.accept("carol", inv.code(), 12).is_err());
        // Expired and withdrawn codes.
        let old = acc.invite(OWNER, &id, Some("trader"), None, 5, 20).unwrap();
        assert!(acc.accept("erin", old.code(), 30).is_err());
        let w = acc.invite(OWNER, &id, Some("trader"), None, 1000, 20).unwrap();
        acc.withdraw_invitation(OWNER, &w.invitation.id, 21).unwrap();
        assert!(acc.accept("erin", w.code(), 22).is_err());
        assert!(acc.accept("erin", "not-a-code", 22).is_err());
        assert_eq!(acc.invitations(OWNER, &id, 23).unwrap().len(), 3);
        assert!(acc.invite(OWNER, &id, None, None, MAX_INVITE_TTL_MS + 1, 1).is_err());
    }

    #[test]
    fn revocation_and_readmission() {
        let (acc, id) = setup();
        acc.add_member(OWNER, &id, "alice", Some("trader"), None, 2).unwrap();
        let r = acc.remove_member(OWNER, &id, "alice", "left the desk", 5).unwrap();
        assert_eq!(r.before_ms, 5);
        assert_eq!(can(&acc, "alice", &id, "read", 6), Err(Refusal::NotFound));
        acc.add_member(OWNER, &id, "alice", Some("viewer"), None, 7).unwrap();
        assert_eq!(can(&acc, "alice", &id, "read", 8).unwrap().role(), "viewer");
        // Leaving on your own; the owner can't.
        acc.remove_member("alice", &id, "alice", "", 9).unwrap();
        assert!(acc.remove_member(OWNER, &id, OWNER, "", 9).is_err());
    }

    #[test]
    fn expiry_and_signed_policy() {
        let (acc, id) = setup();
        acc.add_member(OWNER, &id, "temp", Some("viewer"), Some(10), 2).unwrap();
        assert!(can(&acc, "temp", &id, "read", 9).is_ok());
        assert_eq!(can(&acc, "temp", &id, "read", 10), Err(Refusal::NotFound));

        let signed =
            Authorizer::new(acc.authorizer().store().clone(), Arc::new(acc.authorizer().catalog().clone())).with_policy(MembershipPolicy::Signed);
        let p = PresentedRole { role: "trader".into(), issued_at_ms: 3, expires_at_ms: None };
        let caller = Caller::user("sig").with_presented(p.clone());
        let req = Request { caller: &caller, account: &id, perm: "orders.manual", now_ms: 4 };
        assert_eq!(signed.authorize(&req).unwrap().role(), "trader");
        // A recorded member without a presented membership doesn't count under Signed.
        acc.add_member(OWNER, &id, "rec", Some("viewer"), None, 2).unwrap();
        let rec = Caller::user("rec");
        assert_eq!(signed.authorize(&Request { caller: &rec, account: &id, perm: "read", now_ms: 4 }), Err(Refusal::NotFound));
        // Revocations void older signed memberships.
        acc.remove_member(OWNER, &id, "sig", "", 5).unwrap();
        assert_eq!(signed.authorize(&Request { now_ms: 6, ..req }), Err(Refusal::NotFound));
        let either = signed.clone().with_policy(MembershipPolicy::Either);
        assert!(either.authorize(&Request { caller: &rec, account: &id, perm: "read", now_ms: 4 }).is_ok());
    }

    #[test]
    fn suspension_and_closing() {
        let (acc, id) = setup();
        acc.add_member(OWNER, &id, "adm", Some("admin"), None, 2).unwrap();
        acc.set_status("adm", &id, Status::Suspended, 3).unwrap();
        assert_eq!(can(&acc, "adm", &id, "orders.manual", 4), Err(Refusal::Suspended));
        assert_eq!(can(&acc, OWNER, &id, "orders.manual", 4), Err(Refusal::Suspended));
        assert!(can(&acc, "adm", &id, ACCOUNT_VIEW, 4).is_ok());
        assert!(acc.set_status("adm", &id, Status::Active, 4).is_err());
        acc.set_status(OWNER, &id, Status::Active, 5).unwrap();
        assert!(can(&acc, "adm", &id, "orders.manual", 6).is_ok());
        assert!(acc.set_status("adm", &id, Status::Closed, 7).is_err());
        acc.set_status(OWNER, &id, Status::Closed, 7).unwrap();
        assert_eq!(can(&acc, OWNER, &id, ACCOUNT_VIEW, 8), Err(Refusal::NotFound));
        assert!(acc.accounts_for(OWNER, 8).unwrap().is_empty());
    }

    #[test]
    fn key_bindings() {
        let (acc, id) = setup();
        acc.add_member(OWNER, &id, "adm", Some("admin"), None, 2).unwrap();
        let b = acc.bind_key("adm", &id, 1, "trader", 3).unwrap();
        assert_eq!(b.role, "trader");
        assert!(acc.bind_key("adm", &id, 1, "viewer", 3).is_err());
        assert!(acc.bind_key("adm", &id, 2, "owner", 3).is_err());
        let az = acc.authorizer();
        assert_eq!(az.authorize_key(1, "orders.manual", 4).unwrap().role(), "trader");
        // The key follows its maker down.
        acc.set_role(OWNER, &id, "adm", "viewer", 5).unwrap();
        assert_eq!(az.authorize_key(1, "read", 6).unwrap().role(), "viewer");
        assert!(az.authorize_key(1, "orders.manual", 6).is_err());
        acc.remove_member(OWNER, &id, "adm", "", 7).unwrap();
        assert!(az.authorize_key(1, "read", 8).is_err());
        // Owner-made keys keep their own role.
        acc.bind_key(OWNER, &id, 3, "auditor", 9).unwrap();
        assert_eq!(az.authorize_key(3, AUDIT_VIEW, 10).unwrap().role(), "auditor");
        acc.unbind_key(OWNER, 3, 11).unwrap();
        assert!(az.authorize_key(3, AUDIT_VIEW, 12).is_err());
        assert!(az.authorize_key(99, "read", 12).is_err());
    }

    #[test]
    fn vault_style_closure_hook() {
        // A hook that takes (user, account, permission), as a vault or service hook would.
        let (acc, id) = setup();
        acc.add_member(OWNER, &id, "alice", Some("trader"), None, 2).unwrap();
        let az = acc.authorizer().clone();
        let hook = move |user: &str, perm: &str| {
            let caller = Caller::user(user);
            az.authorize(&Request { caller: &caller, account: &id, perm, now_ms: 3 }).is_ok()
        };
        assert!(hook("alice", "orders.manual"));
        assert!(!hook("alice", catalog::KEYS_MANAGE));
    }
}
