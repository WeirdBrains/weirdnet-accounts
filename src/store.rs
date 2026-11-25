//! The storage interface for the accounts model, and an in-memory store.
//!
//! Apps keep accounts wherever they like by implementing [`Store`] over their own schema;
//! [`MemoryStore`] serves tests and small tools, and the `sqlite` feature adds
//! `SqliteStore`, which keeps the records in a database of its own. Calls are blocking; async
//! servers run them on a blocking pool.

use crate::account::{Account, AccountError, AccountId, AccountResult, Invitation, KeyBinding, Member, Revocation};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Where accounts, members, invitations, revocations and key bindings live.
pub trait Store: Send + Sync {
    /// Adds an account; [`AccountError::Exists`] if the id is taken.
    fn create_account(&self, a: &Account) -> AccountResult<()>;
    /// Replaces an account; [`AccountError::NotFound`] if it isn't there.
    fn update_account(&self, a: &Account) -> AccountResult<()>;
    /// One account.
    fn account(&self, id: &AccountId) -> AccountResult<Option<Account>>;
    /// Every account, closed ones included, by id.
    fn accounts(&self) -> AccountResult<Vec<Account>>;

    /// Adds or replaces a member.
    fn put_member(&self, m: &Member) -> AccountResult<()>;
    /// One member.
    fn member(&self, account: &AccountId, user_id: &str) -> AccountResult<Option<Member>>;
    /// An account's members, by user id.
    fn members(&self, account: &AccountId) -> AccountResult<Vec<Member>>;
    /// Every membership a user holds, by account.
    fn memberships(&self, user_id: &str) -> AccountResult<Vec<Member>>;

    /// Adds or replaces an invitation.
    fn put_invitation(&self, i: &Invitation) -> AccountResult<()>;
    /// One invitation by id.
    fn invitation(&self, id: &str) -> AccountResult<Option<Invitation>>;
    /// One invitation by the SHA-256 of its code.
    fn invitation_by_code(&self, code_hash: &str) -> AccountResult<Option<Invitation>>;
    /// An account's invitations, newest first.
    fn invitations(&self, account: &AccountId) -> AccountResult<Vec<Invitation>>;
    /// Marks `accepted` (already updated) as accepted and adds `member`, together. Fails with
    /// [`AccountError::Denied`] if the stored invitation was accepted or withdrawn meanwhile.
    fn accept_invitation(&self, accepted: &Invitation, member: &Member) -> AccountResult<()>;

    /// Records a revocation and removes the member, together.
    fn revoke_member(&self, r: &Revocation) -> AccountResult<()>;
    /// An account's revocations, oldest first.
    fn revocations(&self, account: &AccountId) -> AccountResult<Vec<Revocation>>;

    /// Adds or replaces a key binding.
    fn put_key_binding(&self, b: &KeyBinding) -> AccountResult<()>;
    /// One key binding.
    fn key_binding(&self, key_id: i64) -> AccountResult<Option<KeyBinding>>;
    /// Removes a key binding; true if it was there.
    fn remove_key_binding(&self, key_id: i64) -> AccountResult<bool>;
    /// An account's key bindings, by key id.
    fn key_bindings(&self, account: &AccountId) -> AccountResult<Vec<KeyBinding>>;
}

#[derive(Default)]
struct Inner {
    accounts: BTreeMap<AccountId, Account>,
    members: BTreeMap<(AccountId, String), Member>,
    invitations: BTreeMap<String, Invitation>,
    revocations: Vec<Revocation>,
    keys: BTreeMap<i64, KeyBinding>,
}

/// Everything in memory (tests, tools, examples).
#[derive(Default)]
pub struct MemoryStore(Mutex<Inner>);

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> AccountResult<std::sync::MutexGuard<'_, Inner>> {
        self.0.lock().map_err(|_| AccountError::Storage("poisoned lock".into()))
    }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStore").finish_non_exhaustive()
    }
}

impl Store for MemoryStore {
    fn create_account(&self, a: &Account) -> AccountResult<()> {
        let mut g = self.lock()?;
        if g.accounts.contains_key(&a.id) {
            return Err(AccountError::Exists("account"));
        }
        g.accounts.insert(a.id.clone(), a.clone());
        Ok(())
    }

    fn update_account(&self, a: &Account) -> AccountResult<()> {
        let mut g = self.lock()?;
        match g.accounts.get_mut(&a.id) {
            Some(x) => {
                *x = a.clone();
                Ok(())
            }
            None => Err(AccountError::NotFound("account")),
        }
    }

    fn account(&self, id: &AccountId) -> AccountResult<Option<Account>> {
        Ok(self.lock()?.accounts.get(id).cloned())
    }

    fn accounts(&self) -> AccountResult<Vec<Account>> {
        Ok(self.lock()?.accounts.values().cloned().collect())
    }

    fn put_member(&self, m: &Member) -> AccountResult<()> {
        self.lock()?.members.insert((m.account.clone(), m.user_id.clone()), m.clone());
        Ok(())
    }

    fn member(&self, account: &AccountId, user_id: &str) -> AccountResult<Option<Member>> {
        Ok(self.lock()?.members.get(&(account.clone(), user_id.to_string())).cloned())
    }

    fn members(&self, account: &AccountId) -> AccountResult<Vec<Member>> {
        Ok(self.lock()?.members.values().filter(|m| &m.account == account).cloned().collect())
    }

    fn memberships(&self, user_id: &str) -> AccountResult<Vec<Member>> {
        Ok(self.lock()?.members.values().filter(|m| m.user_id == user_id).cloned().collect())
    }

    fn put_invitation(&self, i: &Invitation) -> AccountResult<()> {
        self.lock()?.invitations.insert(i.id.clone(), i.clone());
        Ok(())
    }

    fn invitation(&self, id: &str) -> AccountResult<Option<Invitation>> {
        Ok(self.lock()?.invitations.get(id).cloned())
    }

    fn invitation_by_code(&self, code_hash: &str) -> AccountResult<Option<Invitation>> {
        Ok(self.lock()?.invitations.values().find(|i| crate::token::hashes_equal(&i.code_hash, code_hash)).cloned())
    }

    fn invitations(&self, account: &AccountId) -> AccountResult<Vec<Invitation>> {
        let mut v: Vec<Invitation> = self.lock()?.invitations.values().filter(|i| &i.account == account).cloned().collect();
        v.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms).then(a.id.cmp(&b.id)));
        Ok(v)
    }

    fn accept_invitation(&self, accepted: &Invitation, member: &Member) -> AccountResult<()> {
        let mut g = self.lock()?;
        let cur = g.invitations.get(&accepted.id).ok_or(AccountError::NotFound("invitation"))?;
        if cur.accepted.is_some() || cur.revoked_at_ms.is_some() {
            return Err(AccountError::Denied("the invitation is no longer open".into()));
        }
        g.invitations.insert(accepted.id.clone(), accepted.clone());
        g.members.insert((member.account.clone(), member.user_id.clone()), member.clone());
        Ok(())
    }

    fn revoke_member(&self, r: &Revocation) -> AccountResult<()> {
        let mut g = self.lock()?;
        let key = (r.account.clone(), r.user_id.clone());
        if g.members.get(&key).is_some_and(|m| r.voids(m)) {
            g.members.remove(&key);
        }
        g.revocations.push(r.clone());
        Ok(())
    }

    fn revocations(&self, account: &AccountId) -> AccountResult<Vec<Revocation>> {
        Ok(self.lock()?.revocations.iter().filter(|r| &r.account == account).cloned().collect())
    }

    fn put_key_binding(&self, b: &KeyBinding) -> AccountResult<()> {
        self.lock()?.keys.insert(b.key_id, b.clone());
        Ok(())
    }

    fn key_binding(&self, key_id: i64) -> AccountResult<Option<KeyBinding>> {
        Ok(self.lock()?.keys.get(&key_id).cloned())
    }

    fn remove_key_binding(&self, key_id: i64) -> AccountResult<bool> {
        Ok(self.lock()?.keys.remove(&key_id).is_some())
    }

    fn key_bindings(&self, account: &AccountId) -> AccountResult<Vec<KeyBinding>> {
        Ok(self.lock()?.keys.values().filter(|k| &k.account == account).cloned().collect())
    }
}

/// Shared tests every [`Store`] implementation should pass (used by the crate's own stores).
#[cfg(test)]
pub(crate) mod conformance {
    use super::*;
    use crate::catalog;

    fn acct(id: &str) -> Account {
        let c = catalog::catalog();
        Account::new(AccountId::new(id).unwrap(), "Desk", "owner-1", catalog::standard(&c, &[]).unwrap(), 1).unwrap()
    }

    fn member(a: &str, u: &str, at: i64) -> Member {
        Member {
            account: AccountId::new(a).unwrap(),
            user_id: u.into(),
            role: "viewer".into(),
            added_by: "owner-1".into(),
            added_at_ms: at,
            expires_at_ms: None,
            signed: Some(b"{}".to_vec()),
        }
    }

    pub(crate) fn run(s: &dyn Store) {
        let a = acct("a1");
        s.create_account(&a).unwrap();
        assert_eq!(s.create_account(&a), Err(AccountError::Exists("account")));
        assert_eq!(s.account(&a.id).unwrap().as_ref(), Some(&a));
        let mut b = a.clone();
        b.name = "Renamed".into();
        b.status = crate::account::Status::Suspended;
        s.update_account(&b).unwrap();
        assert_eq!(s.account(&a.id).unwrap().unwrap().name, "Renamed");
        assert_eq!(s.update_account(&acct("zz")), Err(AccountError::NotFound("account")));
        s.create_account(&acct("a2")).unwrap();
        assert_eq!(s.accounts().unwrap().len(), 2);

        s.put_member(&member("a1", "u1", 5)).unwrap();
        s.put_member(&member("a2", "u1", 5)).unwrap();
        s.put_member(&member("a1", "u2", 5)).unwrap();
        assert_eq!(s.members(&a.id).unwrap().len(), 2);
        assert_eq!(s.memberships("u1").unwrap().len(), 2);
        assert_eq!(s.member(&a.id, "u2").unwrap().unwrap().signed.as_deref(), Some(&b"{}"[..]));

        let inv = Invitation {
            id: "i1".into(),
            account: a.id.clone(),
            role: "viewer".into(),
            invitee: None,
            created_by: "owner-1".into(),
            created_at_ms: 1,
            expires_at_ms: 100,
            code_hash: "ab".repeat(32),
            revoked_at_ms: None,
            accepted: None,
        };
        s.put_invitation(&inv).unwrap();
        assert_eq!(s.invitation("i1").unwrap().as_ref(), Some(&inv));
        assert_eq!(s.invitation_by_code(&"ab".repeat(32)).unwrap().as_ref(), Some(&inv));
        assert!(s.invitation_by_code(&"cd".repeat(32)).unwrap().is_none());
        let mut done = inv.clone();
        done.accepted = Some(("u3".into(), 7));
        s.accept_invitation(&done, &member("a1", "u3", 7)).unwrap();
        assert!(matches!(s.accept_invitation(&done, &member("a1", "u4", 7)), Err(AccountError::Denied(_))));
        assert!(s.member(&a.id, "u4").unwrap().is_none());
        assert_eq!(s.invitations(&a.id).unwrap()[0].accepted, Some(("u3".into(), 7)));

        let r = Revocation {
            account: a.id.clone(),
            user_id: "u1".into(),
            before_ms: 6,
            at_ms: 6,
            by: "owner-1".into(),
            reason: "left".into(),
            signed: None,
        };
        s.revoke_member(&r).unwrap();
        assert!(s.member(&a.id, "u1").unwrap().is_none());
        assert!(s.member(&AccountId::new("a2").unwrap(), "u1").unwrap().is_some());
        assert_eq!(s.revocations(&a.id).unwrap(), vec![r]);

        let k = KeyBinding { key_id: 9, account: a.id.clone(), user_id: "u2".into(), role: "viewer".into(), created_at_ms: 3 };
        s.put_key_binding(&k).unwrap();
        assert_eq!(s.key_binding(9).unwrap().as_ref(), Some(&k));
        assert_eq!(s.key_bindings(&a.id).unwrap().len(), 1);
        assert!(s.remove_key_binding(9).unwrap());
        assert!(!s.remove_key_binding(9).unwrap());
    }

    #[test]
    fn memory_store() {
        run(&MemoryStore::new());
    }
}
