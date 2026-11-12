# weirdnet-accounts

Account building blocks for WeirdBrains services, extracted from TAUR and shared with Salty
Gull. Storage stays with the application; this crate holds the rules and the cryptography
and never opens a database.

- `password`: Argon2id hashes (PHC strings, `argon2` defaults: v1.3, m = 19 MiB, t = 2, p = 1),
  verification, and a minimum-length rule.
- `token`: 256-bit random bearer tokens (sessions, email links), stored only as SHA-256, with
  constant-time hash comparison.
- `names`: AUR-style user names (3-16 of `[A-Za-z0-9._-]`, alphanumeric at both ends) and a
  light email check.
- `ratelimit`: in-memory fixed-window limits per client and per application-defined class,
  bounded key tables, and `X-Forwarded-For` honoured only from trusted proxies (walked from the
  right so spoofed entries are ignored).
- `apikeys`: org-scoped API keys `<service>_<org>_<64 hex>` shown once and stored as SHA-256,
  with scopes (`resource:verb`), optional app and channel bindings, expiry and revocation.

Planned next (G2 follow-up): sessions, email tokens, orgs and roles, audit and moderation over a
storage trait. Roles build on `weirdnet-access`.

See [SECURITY.md](SECURITY.md). Not audited.

## License

BSD-3-Clause.
