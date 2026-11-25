# weirdnet-accounts agents

The collective `AGENTS.md` in `WeirdBrains/weirdnet-agents` is mandatory and wins on conflict.

- Keep TAUR behaviour identical when moving code here (same hashes, messages and limits). The 0.1
  modules and `Error` stay source-compatible; new errors go in `account::AccountError`.
- The accounts model persists only through `store::Store`. `SqliteStore` owns its own database
  file and migrations and never touches an app's schema; migrations only append.
- Heavy dependencies (weirdnet-storage, weirdnet-net) stay behind features; default builds pull
  neither.
- Build outside the source checkout, with `CARGO_TARGET_DIR` on a scratch disk; clean targets afterwards.
- Never log passwords, tokens, invitation codes or keys.
