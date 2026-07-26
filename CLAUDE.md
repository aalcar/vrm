# CLAUDE.md

Working notes for `vrm`. The full spec is in `vrm-spec.md` — **read it before implementing
anything.** This file covers invariants, workflow, and commands; it does not restate the
spec. Where they disagree, the spec wins.

## Workflow

Build phase by phase, in spec order. **Implement one phase, meet its acceptance criteria,
then stop for review.** Do not continue into the next phase unprompted. Small commits, one
per phase or smaller.

Before saying a phase is done, run the full check (see below) and confirm each acceptance
criterion explicitly — not "looks good," but which criterion is satisfied by what.

## Commands

```bash
go build ./...          # compiles — the floor, not a pass
go vet ./...            # static checks
go test -race ./...     # ALWAYS -race; the fan-out is concurrent
gofmt -l .              # lists unformatted files; -w to fix
```

`go test -race ./...` is the default test command for this project. A test run without
`-race` proves very little here.

## Invariants

These come from the spec's guiding principles. Violating one is a bug even if tests pass.

- **Deterministic data never passes through the LLM.** Ratings, CVE records, and registry
  statuses are interpolated into the report verbatim. The model does not restate,
  summarize, or recompute them.
- **Two LLM jobs, kept separate.** Entity resolution (strict JSON) and checklist research
  (fixed fields + citations) are different functions with different prompts and output
  contracts. Never merge them into one call.
- **Tri-state, never bare `no`.** Research answers are `yes` (with citation),
  `no_evidence_found`, or `not_applicable`. "No evidence found" and "did not happen" are
  different claims and only the first is supportable.
- **Uncited claims are dropped, not displayed.** A `yes` without a citation naming this
  specific vendor is downgraded to `no_evidence_found` by the parser.
- **Partial failure is normal.** One source failing marks that section only. Never cancel
  siblings; never abort the assessment. Do not use an error-cancelling group for the
  fan-out.
- **`StatusSkipped` is a real outcome, not a failure.** Most vendors legitimately skip OSV.
  Manual sources start skipped. Do not "fix" these.
- **Manual entries are analyst data.** They live in the cache table for convenience only.
  Never expire them, never clear them on `--no-cache`, never overwrite them automatically.
- **No editorializing.** Record values and citations. Severity judgments, timelines, and
  narrative are the analyst's job, not generated output.
- **`html/template` only**, never `text/template`. Report data is externally sourced and
  must be auto-escaped.

## Hard nos

- Do not write an HTTP client for SSL Labs or Open Bug Bounty. They are manual sources by
  deliberate design (spec §7), not stubs awaiting completion.
- Do not add sources beyond those in spec §6 and §7.
- Do not build auth, TLS termination, rate limiting, batch assessment, or trend tracking.
- Do not scan or probe vendor infrastructure, directly or via a third-party scanner.
- Do not put secrets in `config.yaml`, commit `.env`, or log keys, auth headers, or full
  prompts. Secrets are env-only.
- Do not guess API endpoint paths. If the exact path isn't in the spec or the vendor's
  docs, stop and ask.

## Conventions

- Errors wrap with `%w`. No `panic` on the request path.
- `Section.Data` is a concrete per-source struct, never a `map`.
- Every source's parsing logic is isolated in one function with a fixture in `testdata/`.
- Scrapers (`fedramp.go`, `caag.go`) must distinguish "genuinely empty" from "parser
  broke." Breakage is loud: `StatusFailed` with a clear message.
- `cmd/` files stay thin — flags, env, wiring. No business logic.

## When stuck

Ask rather than guess, especially on: BitSight endpoint paths, CPE string formats, and
the shape of scraped HTML. A wrong CPE silently returns the wrong vendor's CVEs, which is
worse than a build error because nothing fails.
