# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-25

### Added

- Multi-tenant accounts model: accounts (tenants) with owners, statuses and their own
  weirdnet-access role sets; members, invitations with single-use codes, revocations and API-key
  bindings (`account`, `directory`).
- `authz::Authorizer`: one authorization hook for account-scoped requests (identity, account
  status, recorded or owner-signed membership, then weirdnet-access `enforce::decide`), with an
  `Authorize` trait that closures implement.
- `catalog`: account permissions on the weirdnet-access core, `tiered` roles and a `standard`
  preset (owner, admin, member, viewer, auditor).
- `store::Store` interface and `MemoryStore`.
- `sqlite` feature: `SqliteStore` on weirdnet-storage (SQLCipher) in its own database, with
  versioned migrations and encrypted snapshots. `vendored-openssl` builds OpenSSL from source.
- `net` feature: owner-signed weirdnet-net memberships and revocations, and callers from node
  certs or presented memberships.
- `service` feature: `ServiceAuth`, a weirdnet-service `Authorize` hook over `Authorizer`
  (account plus identity to a role from the store, presented memberships included).
- The 0.1 primitives and their `Error` are unchanged.

## [0.1.1] - 2026-11-21

### Changed

- Package metadata and docs follow the WeirdBrains public-content rules (Weird Brains LLC as the copyright holder, m3talsmith as the author, no machine details). No code or API changes.

## [0.1.0] - 2026-11-12

### Added

- Argon2id passwords, hashed bearer tokens, user-name and email rules (from TAUR).
- Generic per-client rate limits with trusted proxies (from TAUR).
- Org-scoped API keys with scopes, bindings, expiry and revocation.
