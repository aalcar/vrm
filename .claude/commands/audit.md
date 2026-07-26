---
description: Audit the codebase against the spec's correctness invariants
---

Audit the current code against the invariants in CLAUDE.md and the guiding principles in
`vrm-spec.md` §2. This is a review pass — report findings, do not fix anything unless I
ask.

Check each of these specifically and report pass/fail with file:line evidence:

1. **LLM isolation** — does any deterministic value (BitSight rating, CVE record, FedRAMP
   status, CA AG entry) get passed into an LLM prompt or reconstructed from model output?
2. **Prompt separation** — are entity resolution and checklist research still separate
   functions with separate prompts and output contracts?
3. **Tri-state integrity** — is a bare `no` reachable anywhere in the research path? Does
   an uncited `yes` actually get downgraded, and is there a test proving it?
4. **Citation enforcement** — can a non-empty `Finding.Value` reach the report with zero
   citations?
5. **Fan-out isolation** — can one source's failure or timeout cancel, block, or abort any
   other source? Is an error-cancelling group used anywhere in the fan-out?
6. **Manual entry safety** — can a manual row be expired by TTL, cleared by `--no-cache`,
   or overwritten by an automated source?
7. **Skip vs. fail** — are "no input to query" and "the source errored" distinguishable in
   both the data model and the rendered report?
8. **Scraper honesty** — can a broken parser return empty results that look like a genuine
   empty result?
9. **Escaping** — is `text/template` used anywhere? Is there a test asserting a hostile
   vendor string is escaped?
10. **Secrets** — any key in `config.yaml`, any secret or auth header or full prompt
    reachable by a log line, any `.env` committed?

For anything that fails, quote the offending code and explain the failure mode in terms of
what an analyst would see — not just what the rule says.
