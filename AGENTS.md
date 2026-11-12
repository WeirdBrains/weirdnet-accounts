# weirdnet-accounts agents

The collective `AGENTS.md` in `WeirdBrains/weirdnet-agents` is mandatory and wins on conflict.

- Keep TAUR behaviour identical when moving code here (same hashes, messages and limits).
- Build outside the source checkout, with `CARGO_TARGET_DIR` on a scratch disk; clean targets afterwards.
- Never log passwords, tokens or keys.
