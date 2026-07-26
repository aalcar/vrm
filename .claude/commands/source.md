---
description: Add a new Source implementation following project conventions
---

Add a new source: $ARGUMENTS

First, confirm this source is actually in scope. Spec §3 says do not add sources beyond
those in §6 and §7. If it isn't listed there, say so and stop — the seam exists so that
adding one is easy when it's approved, not so that sources get added casually.

If it is in scope, follow the existing conventions exactly:

- One file in `internal/sources/`, implementing `Source` (`Name()` and `Fetch()`).
- Return a `Section` with a concrete per-source `Data` struct, never a `map`.
- `StatusSkipped` (not an error) when there's no usable input from `ResolvedEntity` or a
  required credential is absent. Set `Note` explaining which.
- `StatusFailed` with a clear `Err` when the call or parse fails. Never return partial or
  silently-wrong data.
- Respect `ctx` cancellation and the per-source timeout.
- Isolate parsing in one function. Record a fixture in `testdata/` and write a test against
  it.
- Add its TTL to `cache_ttl` in config and to the spec's table, and register it in the
  `sources` config toggles.
- If it's an LLM-free source, no part of its output may be routed through a prompt.

Do not guess endpoint paths or response shapes. Confirm against real documentation or a
live call first; if you can't, stop and ask.
