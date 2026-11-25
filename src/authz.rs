//! One authorization hook for account-scoped requests.
//!
//! [`Authorizer`] runs the weirdnet-access enforcement order for a caller, an account and a
//! permission: the caller's identity (from the node cert the app already checked), the
//! account's status, the caller's role (owner, or a current, unrevoked membership, recorded or
//! owner-signed), then `enforce::decide` with the account's [`RoleSet`](weirdnet_access::RoleSet).
//! Accounts are Private + Gated: anyone who isn't the owner or a member gets "not found", so
//! account ids don't leak.
//!
//! Service hooks call [`Authorize::authorize`] (closures work too). For a hook that takes
//! weirdnet-access `Facts` (such as an access-based vault authorizer),
//! [`Authorizer::facts`] gives them.

use crate::account::{Account, AccountError, AccountId, Status};
use crate::store::Store;
use std::sync::Arc;
use weirdnet_access::catalog::core;
use weirdnet_access::{Access, Actor, Catalog, Facts, Settings, Visibility};

/// A membership the caller presented and the app verified (for example with weirdnet-net
/// `check_presented`; the `net` feature does this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedRole {
    /// The role id it carries.
    pub role: String,
    /// When it was issued (ms).
    pub issued_at_ms: i64,
    /// When it expires (ms).
    pub expires_at_ms: Option<i64>,
}

/// Who is calling, as far as the transport and the app's checks got.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caller {
    /// The user id the caller's node cert resolves to; `None` if it didn't check out.
    pub user: Option<String>,
    /// The caller's node cert is revoked.
    pub node_revoked: bool,
    /// A verified, owner-signed membership the caller presented.
    pub presented: Option<PresentedRole>,
}

impl Caller {
    /// A caller known to be `user`.
    pub fn user(user: impl Into<String>) -> Self {
        Caller { user: Some(user.into()), ..Default::default() }
    }

    /// Adds a verified presented membership.
    pub fn with_presented(mut self, p: PresentedRole) -> Self {
        self.presented = Some(p);
        self
    }
}

/// Which memberships count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MembershipPolicy {
    /// The store's member records (the server is the authority).
    #[default]
    Recorded,
    /// Only an owner-signed membership the caller presented (the owner's key is the
    /// authority); the store's revocations still apply.
    Signed,
    /// Either.
    Either,
}

/// One authorization question.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Who.
    pub caller: &'a Caller,
    /// Which account.
    pub account: &'a AccountId,
    /// Which permission.
    pub perm: &'a str,
    /// Now (ms).
    pub now_ms: i64,
}

/// A caller let in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The account.
    pub account: AccountId,
    /// The caller's user id.
    pub user: String,
    /// The owner, or a member under a role.
    pub actor: Actor,
}

impl Admitted {
    /// The role id acted under (`owner` for the owner).
    pub fn role(&self) -> &str {
        match &self.actor {
            Actor::Member { role, .. } => &role.id,
            _ => weirdnet_access::roles::OWNER,
        }
    }
}

/// Why a caller was refused. Messages are safe to show and never carry secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// No such account, or the caller may not know it exists.
    #[error("account not found")]
    NotFound,
    /// The account is suspended and the permission isn't allowed while suspended.
    #[error("account suspended")]
    Suspended,
    /// Known, but not allowed.
    #[error("not allowed: {0}")]
    Denied(String),
    /// The store failed.
    #[error("storage: {0}")]
    Storage(String),
}

impl From<AccountError> for Refusal {
    fn from(e: AccountError) -> Self {
        match e {
            AccountError::NotFound(_) => Refusal::NotFound,
            AccountError::Denied(m) => Refusal::Denied(m),
            other => Refusal::Storage(other.to_string()),
        }
    }
}

impl From<Refusal> for AccountError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::NotFound => AccountError::NotFound("account"),
            Refusal::Suspended => AccountError::Denied("account suspended".into()),
            Refusal::Denied(m) => AccountError::Denied(m),
            Refusal::Storage(m) => AccountError::Storage(m),
        }
    }
}

/// Decides account-scoped requests.
pub trait Authorize: Send + Sync {
    /// Decide one request.
    fn authorize(&self, req: &Request<'_>) -> Result<Admitted, Refusal>;
}

impl<F> Authorize for F
where
    F: Fn(&Request<'_>) -> Result<Admitted, Refusal> + Send + Sync,
{
    fn authorize(&self, req: &Request<'_>) -> Result<Admitted, Refusal> {
        self(req)
    }
}

/// The accounts model's [`Authorize`]: store-backed, with the account's own roles.
#[derive(Clone)]
pub struct Authorizer {
    store: Arc<dyn Store>,
    catalog: Arc<Catalog>,
    policy: MembershipPolicy,
    while_suspended: Vec<String>,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorizer").field("policy", &self.policy).field("while_suspended", &self.while_suspended).finish_non_exhaustive()
    }
}

const SETTINGS: Settings = Settings { visibility: Visibility::Private, access: Access::Gated };

impl Authorizer {
    /// An authorizer over `store` and `catalog`, counting recorded memberships, allowing
    /// `read`, `members.list` and `account.view` while an account is suspended.
    pub fn new(store: Arc<dyn Store>, catalog: Arc<Catalog>) -> Self {
        Authorizer {
            store,
            catalog,
            policy: MembershipPolicy::Recorded,
            while_suspended: vec![core::READ.into(), core::MEMBERS_LIST.into(), crate::catalog::ACCOUNT_VIEW.into()],
        }
    }

    /// Which memberships count.
    pub fn with_policy(mut self, policy: MembershipPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The permissions allowed while an account is suspended.
    pub fn allow_while_suspended(mut self, perms: &[&str]) -> Self {
        self.while_suspended = perms.iter().map(|p| p.to_string()).collect();
        self
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The catalog.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The account and the weirdnet-access [`Facts`] for `caller` (identity and membership
    /// checks done). Closed or missing accounts are [`Refusal::NotFound`].
    pub fn facts(&self, caller: &Caller, account: &AccountId, now_ms: i64) -> Result<(Account, Facts), Refusal> {
        let a = self.store.account(account)?.ok_or(Refusal::NotFound)?;
        if a.status == Status::Closed {
            return Err(Refusal::NotFound);
        }
        let Some(user) = caller.user.clone() else {
            return Ok((a, Facts { node_revoked: caller.node_revoked, ..Default::default() }));
        };
        let is_owner = user == a.owner;
        let role = if is_owner || caller.node_revoked { None } else { self.member_role(&a, &user, caller, now_ms)? };
        let facts =
            Facts { trusted: is_owner || role.is_some(), user: Some(user), node_revoked: caller.node_revoked, is_owner, membership_role: role };
        Ok((a, facts))
    }

    fn member_role(&self, a: &Account, user: &str, caller: &Caller, now_ms: i64) -> Result<Option<String>, Refusal> {
        let revs = self.store.revocations(&a.id)?;
        let voided = |at: i64| revs.iter().any(|r| r.user_id == user && at <= r.before_ms);
        let recorded = || -> Result<Option<String>, Refusal> {
            Ok(self.store.member(&a.id, user)?.filter(|m| m.current(now_ms) && !voided(m.added_at_ms)).map(|m| m.role))
        };
        let signed =
            || caller.presented.as_ref().filter(|p| p.expires_at_ms.is_none_or(|e| e > now_ms) && !voided(p.issued_at_ms)).map(|p| p.role.clone());
        Ok(match self.policy {
            MembershipPolicy::Recorded => recorded()?,
            MembershipPolicy::Signed => signed(),
            MembershipPolicy::Either => match recorded()? {
                Some(r) => Some(r),
                None => signed(),
            },
        })
    }

    fn admit(&self, req: &Request<'_>, ignore_suspension: bool) -> Result<Admitted, Refusal> {
        let (a, facts) = self.facts(req.caller, req.account, req.now_ms)?;
        let decision = weirdnet_access::decide(&self.catalog, &a.roles, SETTINGS, &facts, req.perm);
        let actor = match decision {
            weirdnet_access::Decision::Allow { actor, .. } => actor,
            weirdnet_access::Decision::NotFound | weirdnet_access::Decision::JoinFirst => return Err(Refusal::NotFound),
            weirdnet_access::Decision::Denied(why) => return Err(Refusal::Denied(why.into())),
        };
        if a.status == Status::Suspended && !ignore_suspension && !self.while_suspended.iter().any(|p| self.catalog.implies_perm(p, req.perm)) {
            return Err(Refusal::Suspended);
        }
        Ok(Admitted { account: a.id, user: facts.user.unwrap_or_default(), actor })
    }

    /// [`Authorize::authorize`], also letting the owner act on a suspended account (to
    /// resume or close it).
    pub fn authorize_owner_while_suspended(&self, req: &Request<'_>) -> Result<Admitted, Refusal> {
        let ad = self.admit(req, true)?;
        let a = self.store.account(req.account)?.ok_or(Refusal::NotFound)?;
        if a.status == Status::Suspended && ad.actor != Actor::Owner {
            return Err(Refusal::Suspended);
        }
        Ok(ad)
    }

    /// Decides a request made with an API key bound by a [`KeyBinding`](crate::account::KeyBinding)
    /// (the key itself checked by [`crate::apikeys`]). The key acts with the lower-ranked of
    /// its role and its maker's current role; it stops working when its maker leaves.
    pub fn authorize_key(&self, key_id: i64, perm: &str, now_ms: i64) -> Result<Admitted, Refusal> {
        let b = self.store.key_binding(key_id)?.ok_or_else(|| Refusal::Denied("unknown API key".into()))?;
        let a = self.store.account(&b.account)?.ok_or(Refusal::NotFound)?;
        if a.status == Status::Closed {
            return Err(Refusal::NotFound);
        }
        let key_role = a.roles.get(&b.role).filter(|r| !r.is_owner()).ok_or_else(|| Refusal::Denied("the key's role is gone".into()))?;
        let role = if b.user_id == a.owner {
            key_role.clone()
        } else {
            let caller = Caller::user(b.user_id.clone());
            let maker = self.member_role(&a, &b.user_id, &caller, now_ms)?.and_then(|r| a.roles.get(&r).cloned());
            let maker = maker.ok_or_else(|| Refusal::Denied("the key's maker is no longer a member".into()))?;
            if maker.rank < key_role.rank { maker } else { key_role.clone() }
        };
        let actor = Actor::Member { user_id: b.user_id.clone(), role };
        if !a.roles.can(&self.catalog, &actor, perm) {
            return Err(Refusal::Denied("the role does not allow this".into()));
        }
        if a.status == Status::Suspended && !self.while_suspended.iter().any(|p| self.catalog.implies_perm(p, perm)) {
            return Err(Refusal::Suspended);
        }
        Ok(Admitted { account: a.id, user: b.user_id, actor })
    }
}

impl Authorize for Authorizer {
    fn authorize(&self, req: &Request<'_>) -> Result<Admitted, Refusal> {
        self.admit(req, false)
    }
}
