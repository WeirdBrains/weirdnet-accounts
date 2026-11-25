//! `SqliteStore`: the accounts [`Store`] in a SQLCipher database of its own
//! ([weirdnet-storage](https://crates.io/crates/weirdnet-storage)).
//!
//! The store owns its database file and its migrations (`weirdnet_storage::migrate`, tracked
//! in that file's `schema_version` table), so it never touches an app's own schema. Give it a
//! dedicated path, such as `accounts.db` next to the app's database, and a key from the app's
//! keyring. Apps that want accounts inside their own schema implement [`Store`] instead.

use crate::account::{Account, AccountError, AccountId, AccountResult, Invitation, KeyBinding, Member, Revocation, Status};
use crate::store::Store;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use weirdnet_storage::rusqlite::{self, Connection, OptionalExtension, Row, params};
use weirdnet_storage::{RawKey, StorageError};

/// The migrations, oldest first. Version 1 is the first schema (0.2.0); later versions only
/// append.
pub const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE acct_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL,
    roles TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX acct_accounts_owner ON acct_accounts(owner);
CREATE TABLE acct_members (
    account TEXT NOT NULL REFERENCES acct_accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    added_by TEXT NOT NULL,
    added_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER,
    signed BLOB,
    PRIMARY KEY (account, user_id)
);
CREATE INDEX acct_members_user ON acct_members(user_id);
CREATE TABLE acct_invitations (
    id TEXT PRIMARY KEY NOT NULL,
    account TEXT NOT NULL REFERENCES acct_accounts(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    invitee TEXT,
    created_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    revoked_at_ms INTEGER,
    accepted_by TEXT,
    accepted_at_ms INTEGER
);
CREATE INDEX acct_invitations_account ON acct_invitations(account);
CREATE TABLE acct_revocations (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL REFERENCES acct_accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    before_ms INTEGER NOT NULL,
    at_ms INTEGER NOT NULL,
    by_user TEXT NOT NULL,
    reason TEXT NOT NULL,
    signed BLOB
);
CREATE INDEX acct_revocations_account ON acct_revocations(account, user_id);
CREATE TABLE acct_key_bindings (
    key_id INTEGER PRIMARY KEY NOT NULL,
    account TEXT NOT NULL REFERENCES acct_accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX acct_key_bindings_account ON acct_key_bindings(account);
"#];

impl From<StorageError> for AccountError {
    fn from(e: StorageError) -> Self {
        AccountError::Storage(e.to_string())
    }
}

fn sql(e: rusqlite::Error) -> AccountError {
    AccountError::Storage(e.to_string())
}

fn conv(i: usize, e: AccountError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, Box::new(e))
}

/// The accounts store in its own SQLCipher database.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Opens (creating if needed) the database at `path` with `key` (`None` for plaintext,
    /// only for tests) and applies pending migrations.
    pub fn open(path: &Path, key: Option<&RawKey>) -> AccountResult<Self> {
        Self::from_connection(weirdnet_storage::open(path, key, "accounts")?)
    }

    /// A private in-memory store (tests).
    pub fn in_memory() -> AccountResult<Self> {
        Self::from_connection(weirdnet_storage::open_in_memory()?)
    }

    /// Uses an open connection to a database dedicated to this store, migrating it.
    pub fn from_connection(mut conn: Connection) -> AccountResult<Self> {
        weirdnet_storage::migrate(&mut conn, MIGRATIONS, MIGRATIONS.len(), |_, _| Ok::<(), AccountError>(()))?;
        Ok(SqliteStore { conn: Mutex::new(conn) })
    }

    /// The applied schema version.
    pub fn schema_version(&self) -> AccountResult<i64> {
        Ok(weirdnet_storage::schema_version(&*self.lock()?)?)
    }

    /// An encrypted online copy of the database at `dest` (see `weirdnet_storage::snapshot_to`).
    pub fn snapshot_to(&self, dest: &Path, key: Option<&RawKey>) -> AccountResult<()> {
        Ok(weirdnet_storage::snapshot_to(&*self.lock()?, dest, key)?)
    }

    fn lock(&self) -> AccountResult<MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| AccountError::Storage("poisoned lock".into()))
    }
}

const ACCOUNT_COLS: &str = "id, name, owner, status, roles, created_at_ms, updated_at_ms";
const MEMBER_COLS: &str = "account, user_id, role, added_by, added_at_ms, expires_at_ms, signed";
const INVITE_COLS: &str =
    "id, account, role, invitee, created_by, created_at_ms, expires_at_ms, code_hash, revoked_at_ms, accepted_by, accepted_at_ms";
const REVOKE_COLS: &str = "account, user_id, before_ms, at_ms, by_user, reason, signed";
const KEY_COLS: &str = "key_id, account, user_id, role, created_at_ms";

fn account_id(r: &Row, i: usize) -> rusqlite::Result<AccountId> {
    AccountId::new(r.get::<_, String>(i)?).map_err(|e| conv(i, e))
}

fn account_row(r: &Row) -> rusqlite::Result<Account> {
    let status = Status::parse(&r.get::<_, String>(3)?).map_err(|e| conv(3, e))?;
    let roles = serde_json::from_str(&r.get::<_, String>(4)?).map_err(|e| conv(4, AccountError::Storage(e.to_string())))?;
    Ok(Account { id: account_id(r, 0)?, name: r.get(1)?, owner: r.get(2)?, status, roles, created_at_ms: r.get(5)?, updated_at_ms: r.get(6)? })
}

fn member_row(r: &Row) -> rusqlite::Result<Member> {
    Ok(Member {
        account: account_id(r, 0)?,
        user_id: r.get(1)?,
        role: r.get(2)?,
        added_by: r.get(3)?,
        added_at_ms: r.get(4)?,
        expires_at_ms: r.get(5)?,
        signed: r.get(6)?,
    })
}

fn invite_row(r: &Row) -> rusqlite::Result<Invitation> {
    let by: Option<String> = r.get(9)?;
    let at: Option<i64> = r.get(10)?;
    Ok(Invitation {
        id: r.get(0)?,
        account: account_id(r, 1)?,
        role: r.get(2)?,
        invitee: r.get(3)?,
        created_by: r.get(4)?,
        created_at_ms: r.get(5)?,
        expires_at_ms: r.get(6)?,
        code_hash: r.get(7)?,
        revoked_at_ms: r.get(8)?,
        accepted: by.zip(at),
    })
}

fn revoke_row(r: &Row) -> rusqlite::Result<Revocation> {
    Ok(Revocation {
        account: account_id(r, 0)?,
        user_id: r.get(1)?,
        before_ms: r.get(2)?,
        at_ms: r.get(3)?,
        by: r.get(4)?,
        reason: r.get(5)?,
        signed: r.get(6)?,
    })
}

fn key_row(r: &Row) -> rusqlite::Result<KeyBinding> {
    Ok(KeyBinding { key_id: r.get(0)?, account: account_id(r, 1)?, user_id: r.get(2)?, role: r.get(3)?, created_at_ms: r.get(4)? })
}

fn roles_json(a: &Account) -> AccountResult<String> {
    serde_json::to_string(&a.roles).map_err(|e| AccountError::Storage(e.to_string()))
}

fn write_member(c: &Connection, m: &Member) -> AccountResult<()> {
    c.execute(
        &format!("INSERT OR REPLACE INTO acct_members ({MEMBER_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
        params![m.account.as_str(), m.user_id, m.role, m.added_by, m.added_at_ms, m.expires_at_ms, m.signed],
    )
    .map_err(sql)?;
    Ok(())
}

fn write_invite(c: &Connection, i: &Invitation) -> AccountResult<()> {
    let (by, at) = i.accepted.clone().unzip();
    c.execute(
        &format!("INSERT OR REPLACE INTO acct_invitations ({INVITE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"),
        params![i.id, i.account.as_str(), i.role, i.invitee, i.created_by, i.created_at_ms, i.expires_at_ms, i.code_hash, i.revoked_at_ms, by, at],
    )
    .map_err(sql)?;
    Ok(())
}

fn many<T>(c: &Connection, q: &str, p: impl rusqlite::Params, f: fn(&Row) -> rusqlite::Result<T>) -> AccountResult<Vec<T>> {
    let mut st = c.prepare(q).map_err(sql)?;
    let rows = st.query_map(p, f).map_err(sql)?;
    rows.collect::<rusqlite::Result<Vec<T>>>().map_err(sql)
}

fn one<T>(c: &Connection, q: &str, p: impl rusqlite::Params, f: fn(&Row) -> rusqlite::Result<T>) -> AccountResult<Option<T>> {
    c.query_row(q, p, f).optional().map_err(sql)
}

impl Store for SqliteStore {
    fn create_account(&self, a: &Account) -> AccountResult<()> {
        let c = self.lock()?;
        let n = c
            .execute(
                &format!("INSERT OR IGNORE INTO acct_accounts ({ACCOUNT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                params![a.id.as_str(), a.name, a.owner, a.status.as_str(), roles_json(a)?, a.created_at_ms, a.updated_at_ms],
            )
            .map_err(sql)?;
        if n == 0 { Err(AccountError::Exists("account")) } else { Ok(()) }
    }

    fn update_account(&self, a: &Account) -> AccountResult<()> {
        let c = self.lock()?;
        let n = c
            .execute(
                "UPDATE acct_accounts SET name = ?2, owner = ?3, status = ?4, roles = ?5, created_at_ms = ?6, updated_at_ms = ?7 WHERE id = ?1",
                params![a.id.as_str(), a.name, a.owner, a.status.as_str(), roles_json(a)?, a.created_at_ms, a.updated_at_ms],
            )
            .map_err(sql)?;
        if n == 0 { Err(AccountError::NotFound("account")) } else { Ok(()) }
    }

    fn account(&self, id: &AccountId) -> AccountResult<Option<Account>> {
        one(&*self.lock()?, &format!("SELECT {ACCOUNT_COLS} FROM acct_accounts WHERE id = ?1"), [id.as_str()], account_row)
    }

    fn accounts(&self) -> AccountResult<Vec<Account>> {
        many(&*self.lock()?, &format!("SELECT {ACCOUNT_COLS} FROM acct_accounts ORDER BY id"), [], account_row)
    }

    fn put_member(&self, m: &Member) -> AccountResult<()> {
        write_member(&*self.lock()?, m)
    }

    fn member(&self, account: &AccountId, user_id: &str) -> AccountResult<Option<Member>> {
        one(
            &*self.lock()?,
            &format!("SELECT {MEMBER_COLS} FROM acct_members WHERE account = ?1 AND user_id = ?2"),
            params![account.as_str(), user_id],
            member_row,
        )
    }

    fn members(&self, account: &AccountId) -> AccountResult<Vec<Member>> {
        many(&*self.lock()?, &format!("SELECT {MEMBER_COLS} FROM acct_members WHERE account = ?1 ORDER BY user_id"), [account.as_str()], member_row)
    }

    fn memberships(&self, user_id: &str) -> AccountResult<Vec<Member>> {
        many(&*self.lock()?, &format!("SELECT {MEMBER_COLS} FROM acct_members WHERE user_id = ?1 ORDER BY account"), [user_id], member_row)
    }

    fn put_invitation(&self, i: &Invitation) -> AccountResult<()> {
        write_invite(&*self.lock()?, i)
    }

    fn invitation(&self, id: &str) -> AccountResult<Option<Invitation>> {
        one(&*self.lock()?, &format!("SELECT {INVITE_COLS} FROM acct_invitations WHERE id = ?1"), [id], invite_row)
    }

    fn invitation_by_code(&self, code_hash: &str) -> AccountResult<Option<Invitation>> {
        one(&*self.lock()?, &format!("SELECT {INVITE_COLS} FROM acct_invitations WHERE code_hash = ?1"), [code_hash], invite_row)
    }

    fn invitations(&self, account: &AccountId) -> AccountResult<Vec<Invitation>> {
        many(
            &*self.lock()?,
            &format!("SELECT {INVITE_COLS} FROM acct_invitations WHERE account = ?1 ORDER BY created_at_ms DESC, id"),
            [account.as_str()],
            invite_row,
        )
    }

    fn accept_invitation(&self, accepted: &Invitation, member: &Member) -> AccountResult<()> {
        let c = self.lock()?;
        weirdnet_storage::savepoint(&c, "acct_accept", || {
            let cur = one(&c, &format!("SELECT {INVITE_COLS} FROM acct_invitations WHERE id = ?1"), [accepted.id.as_str()], invite_row)?
                .ok_or(AccountError::NotFound("invitation"))?;
            if cur.accepted.is_some() || cur.revoked_at_ms.is_some() {
                return Err(AccountError::Denied("the invitation is no longer open".into()));
            }
            write_invite(&c, accepted)?;
            write_member(&c, member)
        })
    }

    fn revoke_member(&self, r: &Revocation) -> AccountResult<()> {
        let c = self.lock()?;
        weirdnet_storage::savepoint(&c, "acct_revoke", || {
            c.execute(
                &format!("INSERT INTO acct_revocations ({REVOKE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                params![r.account.as_str(), r.user_id, r.before_ms, r.at_ms, r.by, r.reason, r.signed],
            )
            .map_err(sql)?;
            c.execute(
                "DELETE FROM acct_members WHERE account = ?1 AND user_id = ?2 AND added_at_ms <= ?3",
                params![r.account.as_str(), r.user_id, r.before_ms],
            )
            .map_err(sql)?;
            Ok(())
        })
    }

    fn revocations(&self, account: &AccountId) -> AccountResult<Vec<Revocation>> {
        many(&*self.lock()?, &format!("SELECT {REVOKE_COLS} FROM acct_revocations WHERE account = ?1 ORDER BY seq"), [account.as_str()], revoke_row)
    }

    fn put_key_binding(&self, b: &KeyBinding) -> AccountResult<()> {
        self.lock()?
            .execute(
                &format!("INSERT OR REPLACE INTO acct_key_bindings ({KEY_COLS}) VALUES (?1, ?2, ?3, ?4, ?5)"),
                params![b.key_id, b.account.as_str(), b.user_id, b.role, b.created_at_ms],
            )
            .map_err(sql)?;
        Ok(())
    }

    fn key_binding(&self, key_id: i64) -> AccountResult<Option<KeyBinding>> {
        one(&*self.lock()?, &format!("SELECT {KEY_COLS} FROM acct_key_bindings WHERE key_id = ?1"), [key_id], key_row)
    }

    fn remove_key_binding(&self, key_id: i64) -> AccountResult<bool> {
        Ok(self.lock()?.execute("DELETE FROM acct_key_bindings WHERE key_id = ?1", [key_id]).map_err(sql)? > 0)
    }

    fn key_bindings(&self, account: &AccountId) -> AccountResult<Vec<KeyBinding>> {
        many(&*self.lock()?, &format!("SELECT {KEY_COLS} FROM acct_key_bindings WHERE account = ?1 ORDER BY key_id"), [account.as_str()], key_row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Accounts;
    use std::sync::Arc;

    #[test]
    fn conformance() {
        crate::store::conformance::run(&SqliteStore::in_memory().unwrap());
    }

    #[test]
    fn encrypted_file_reopens_and_keeps_its_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.db");
        let key = [7u8; 32];
        {
            let s = Arc::new(SqliteStore::open(&path, Some(&key)).unwrap());
            assert_eq!(s.schema_version().unwrap(), MIGRATIONS.len() as i64);
            let c = crate::catalog::catalog();
            let acc = Accounts::new(s, c.clone());
            let id = AccountId::new("a1").unwrap();
            acc.create("o", id.clone(), "Desk", crate::catalog::standard(&c, &[]).unwrap(), 1).unwrap();
            acc.add_member("o", &id, "u", Some("member"), None, 2).unwrap();
        }
        // Reopening runs no migration twice and keeps the rows; a wrong key fails.
        let s = SqliteStore::open(&path, Some(&key)).unwrap();
        assert_eq!(s.schema_version().unwrap(), MIGRATIONS.len() as i64);
        assert_eq!(s.members(&AccountId::new("a1").unwrap()).unwrap().len(), 1);
        drop(s);
        assert!(SqliteStore::open(&path, Some(&[8u8; 32])).is_err());
        let snap = dir.path().join("snap.db");
        SqliteStore::open(&path, Some(&key)).unwrap().snapshot_to(&snap, Some(&key)).unwrap();
        assert_eq!(SqliteStore::open(&snap, Some(&key)).unwrap().accounts().unwrap().len(), 1);
    }
}
