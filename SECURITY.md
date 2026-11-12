# weirdnet-accounts security notes

Not audited.

- Passwords: Argon2id with a random salt per hash; malformed stored hashes never verify.
- Tokens and API keys: 32 bytes from the OS generator; only SHA-256 is stored; hashes are
  compared in constant time. `IssuedKey` never prints its secret, and no error carries a
  password, token or key.
- Rate limits: per-process memory only, bounded by `max_keys` per class; when the table is full,
  new clients are refused rather than active ones forgotten. A /0 trusted-proxy range is refused.
- API keys: revoked, expired, wrong-org, missing-scope, and app/channel binding checks are tested.
  Recording last use, audit rows and rate limits per key is the caller's job.
