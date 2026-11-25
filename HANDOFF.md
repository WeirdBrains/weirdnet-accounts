# Handoff

Running notes for [weirdnet-accounts](https://github.com/WeirdBrains/weirdnet-accounts), newest first.

## 2026-11-25: v0.2.0 release

- What changed: releases the accounts model as 0.2.0 (minor bump: new API; the 0.1 primitives
  are unchanged). Published to [crates.io](https://crates.io/crates/weirdnet-accounts) and tagged
  [v0.2.0](https://github.com/WeirdBrains/weirdnet-accounts/releases/tag/v0.2.0).
- Commits: `6b57039` (accounts model), `41eb6d6` (docs, CI), `dd92804` (`service` feature),
  then this entry and the `release: v0.2.0` commit.
- Checks: CI passed on `dd92804` (Linux checks, macOS and Windows tests with all features); the
  release script reran fmt, clippy, tests and rustdoc before tagging.
- Not tested: as in the entry below.
- Left: nothing for this release.
- Next: docs.rs builds the [0.2.0 docs](https://docs.rs/weirdnet-accounts/0.2.0) from the upload.

## 2026-11-25: weirdnet-service hook

- What changed: a `service` feature with `ServiceAuth`, an implementation of
  [weirdnet-service](https://crates.io/crates/weirdnet-service)'s `Authorize`: it checks the
  caller's user card against the peer, maps the resource (a bare account id, or
  `<app>/account/<id>`) to an account, and lets `Authorizer` resolve account plus identity to a
  role from the store, with presented owner-signed memberships counted under the `Signed` and
  `Either` policies. The decision stays weirdnet-access `enforce::decide`; weirdnet-service's
  `MembershipAuth` remains the choice when resources live in memory rather than a `Store`.
- Commits: earlier entry's `6b57039` and `41eb6d6`, then this push.
- Checks: cargo fmt; clippy with `-D warnings` for default, `service` and all features; tests
  for default (30) and all features (34); rustdoc with `-D warnings`.
- Not tested: the hook inside a running weirdnet-service server over real streams (the test
  calls it directly with CBOR credentials).
- Left: release 0.2.0.
- Next: Cortex can pass `ServiceAuth` to its weirdnet-service server.

## 2026-11-25: accounts model for 0.2.0

- What changed: a multi-tenant accounts model beside the unchanged 0.1 primitives: accounts with
  owners, statuses and weirdnet-access role sets; members, invitations, revocations and API-key
  bindings; `authz::Authorizer` (identity, status, recorded or owner-signed membership, then
  `enforce::decide`); `directory::Accounts` with the rank rules; the `Store` interface with
  `MemoryStore`; the `sqlite` feature (`SqliteStore` on weirdnet-storage, own database,
  versioned migrations, snapshots); the `net` feature (signed memberships and revocations from
  [weirdnet-net](https://crates.io/crates/weirdnet-net)). CI adds per-feature clippy and a
  macOS and Windows test job.
- Commits: see `git log` for this entry's push (accounts model, docs and CI).
- Checks: cargo fmt; clippy with `-D warnings` for default, `sqlite`, `net` and all features;
  tests for default, no default and all features (33 with all features); rustdoc with
  `-D warnings`; `weirdnet_release.py validate`. TAUR's core crate builds and passes its tests
  against this tree with only its requirement changed to `"0.2"`.
- Not tested: macOS and Windows until CI runs them; a real multi-node presented-membership
  exchange over streams (the `net` test signs and checks in process); concurrent writers on one
  `SqliteStore` beyond its internal lock.
- Left: release 0.2.0.
- Next: services and the vault can call `Authorizer` (closures adapt it to their hooks).

## 2026-11-21: v0.1.1, public-content patch release

- What changed: v0.1.1 republishes the 0.1 line with the public-content rules applied (Weird Brains LLC as the copyright holder, m3talsmith as the author, no machine details), on top of `7fe79d4`. No code or API changes.
- Commits: `7fe79d4` and the `release: v0.1.1` commit tagged [v0.1.1](https://github.com/WeirdBrains/weirdnet-accounts/releases/tag/v0.1.1).
- Checks: cargo fmt, clippy, test and package; the packaged crate was scanned for private terms before publishing.
- Not tested: nothing beyond the crate's own test suite.
- Left: earlier versions on this line are yanked on [crates.io](https://crates.io/crates/weirdnet-accounts/versions).
- Next: nothing for this release.

