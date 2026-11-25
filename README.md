# weirdnet-accounts

Account building blocks for [Weird Brains](https://weirdbrains.com) services: the password,
token, name, rate-limit and API-key rules first extracted from TAUR, and a multi-tenant
accounts model where one server hosts many accounts, each with many identities holding
[weirdnet-access](https://crates.io/crates/weirdnet-access) roles.

## Primitives

- `password`: Argon2id hashes (PHC strings, `argon2` defaults: v1.3, m = 19 MiB, t = 2, p = 1),
  verification, and a minimum-length rule.
- `token`: 256-bit random bearer tokens (sessions, email links, invitations), stored only as
  SHA-256, with constant-time hash comparison.
- `names`: AUR-style user names (3-16 of `[A-Za-z0-9._-]`, alphanumeric at both ends) and a
  light email check.
- `ratelimit`: in-memory fixed-window limits per client and per application-defined class,
  bounded key tables, and `X-Forwarded-For` honoured only from trusted proxies (walked from the
  right so spoofed entries are ignored).
- `apikeys`: org-scoped API keys `<service>_<org>_<64 hex>` shown once and stored as SHA-256,
  with scopes (`resource:verb`), optional app and channel bindings, expiry and revocation.

## Accounts model

- `account`: `Account` (tenant) records with an owner (a Weirdnet user id), a status (active,
  suspended, closed) and the account's own `RoleSet`; `Member`, `Invitation`, `Revocation` and
  `KeyBinding` records. Times are Unix milliseconds, as in
  [weirdnet-net](https://crates.io/crates/weirdnet-net).
- `catalog`: account permissions (`account.view`, `account.edit`, `account.suspend`,
  `account.close`, `audit.view`, `keys.manage`) on top of the weirdnet-access core, a `tiered`
  role builder and a `standard` preset (owner, admin, member, viewer, auditor). Apps add their
  own permissions and role names, for example `trader`.
- `authz`: `Authorizer`, one hook for account-scoped requests. It runs the weirdnet-access
  order: the caller's identity, the account's status, the caller's role (the owner, or a
  current, unrevoked membership, either recorded by the server or owner-signed and presented),
  then `enforce::decide`. Accounts are private: anyone who isn't the owner or a member gets
  "not found". `Authorize` is implemented for closures too, and `Authorizer::facts` gives the
  weirdnet-access `Facts` for hooks that take them.
- `directory`: `Accounts`, the checked operations: create, rename, suspend, resume and close
  accounts; invite (single-use codes shown once, optionally for one user), accept and withdraw
  invitations; add members, change roles and remove members, with the rank rules (nobody grants
  a role at or above their own or acts on someone who outranks them, and only the owner is the
  owner); and bind API keys to an account. A bound key acts with the lower of its role and its
  maker's current role.
- `store`: the `Store` interface the model persists through, and `MemoryStore`.

### Features

| Feature | Adds | Pulls in |
|---|---|---|
| `sqlite` | `SqliteStore`: the accounts store in its own SQLCipher database, with versioned migrations and encrypted snapshots | [weirdnet-storage](https://crates.io/crates/weirdnet-storage) |
| `vendored-openssl` | `sqlite`, building SQLCipher's OpenSSL from source | |
| `net` | owner-signed memberships and revocations (`Membership::issue`, `MemberRevocation`), `check_presented` callers and callers from node certs | [weirdnet-net](https://crates.io/crates/weirdnet-net) |

No feature is on by default, so the primitives build with no database or network stack.

### Storage

`SqliteStore` keeps its records in a database file of its own (for example `accounts.db`,
keyed from the app's keyring) and tracks its own migrations there, so it never touches an
app's schema. Apps that want accounts inside their own database implement `Store` over their
own tables instead.

## Moving from 0.1

The 0.1 modules (`password`, `token`, `names`, `ratelimit`, `apikeys`, `error`) are unchanged:
same hashes, messages, limits and `Error` variants. Changing the requirement to `"0.2"` is the
whole migration; the accounts model is new API beside them. 0.1 shipped no storage, so there is
no data to migrate; `SqliteStore` starts at schema version 1.

See [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md). Not audited.

## License

BSD-3-Clause. Copyright Weird Brains LLC.
