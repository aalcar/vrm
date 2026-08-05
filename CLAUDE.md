# CLAUDE.md

Working notes for `vrm`. The full spec is in `vrm-spec.md` — **read it before implementing
anything.** This file covers invariants, workflow, and commands; it does not restate the
spec. Where they disagree, the spec wins.

## Workflow

Build phase by phase, in spec order. **Implement one phase, meet its acceptance criteria,
then stop for review.** Do not continue into the next phase unprompted.

Before saying a phase is done, run the full check (see below) and confirm each acceptance
criterion explicitly — not "looks good," but which criterion is satisfied by what.

**Do not run `git commit` or `git add`.** When a commit's worth of work is finished, say so
and stop; the analyst reviews and commits. Suggesting a message is welcome.

Phases 0–8 are complete. Phase 9 (caching) is next.

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
- **"Found nothing" ≠ "couldn't look."** The same distinction, outside the LLM. NVD answers
  `200 / totalResults 0` both for a clean vendor and for a CPE that does not exist, so a
  zero only means something once the CPE is confirmed against the CPE dictionary. Never let
  an unverifiable zero render as a clean result.
- **Identifiers are validated against whatever will consume them.** A CPE gets a structural
  check and a dictionary check; a package ecosystem is checked against OSV's registry list.
  Anything that fails is dropped *and reported* — a silently discarded identifier looks
  exactly like a vendor that has none.
- **Find the authoritative record before writing a scraper.** The FedRAMP listing carries
  ~5,600 `{id,csp,cso,status,…}` literals that look exactly like the product catalogue.
  They are `leveraged_systems` dependency lists and their status is stale — Okta reads
  `Unknown` there while it is actually `FedRAMP Certified`. The real records are the ~674
  `<var>.csp="…"` assignment runs. Parsing the obvious shape yields a full, plausible,
  sourced section that is wrong, and nothing fails.
- **Citations are checked against what search returned, never trusted.** The API's own
  citation blocks do not survive structured output, so research citations are model-written
  schema fields. Every one is matched against the URLs the web-search tool actually
  returned, and an unmatched URL is dropped as fabricated. Do not relax this into host-level
  or fuzzy matching.
- **Never restate one scorer's vocabulary in another's.** GitHub says MODERATE, NVD says
  MEDIUM; they are different scales and translating is laundering. OSV gives a CVSS vector,
  not a score — do not derive the number.
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

- Do not write an HTTP client for SSL Labs, Open Bug Bounty, or CVE Details. All three are
  manual sources by deliberate design (spec §7), not stubs awaiting completion. CVE Details
  moved there in Phase 4 — its API is paywalled and its reference unreachable, so a client
  could be neither verified nor exercised. `CVEDETAILS_API_KEY` no longer exists.
- Do not add sources beyond those in spec §6 and §7.
- Do not use NVD's `cpeName` parameter. It requires a concrete version and returns 404 for
  the version-agnostic CPEs resolution produces. Use `virtualMatchString`.
- Do not query OSV without an ecosystem. A name-only query is rejected with HTTP 400.
- Do not build auth, TLS termination, rate limiting, batch assessment, or trend tracking.
- Do not scan or probe vendor infrastructure, directly or via a third-party scanner.
- Do not put secrets in `config.yaml`, commit `.env`, or log keys, auth headers, or full
  prompts. Secrets are env-only.
- Do not guess API endpoint paths. If the exact path isn't in the spec or the vendor's
  docs, stop and ask.
- Do not parse the nested `{id,csp,cso,status,…}` literals on the FedRAMP page. They are
  dependency lists with stale statuses, not the catalogue. See the invariant above.
- Do not add `minLength`, `maxLength`, `minimum`, `maximum`, `minItems` > 1, or `enum` to a
  structured-outputs schema. The first five are unsupported; all of them inflate the
  compiled grammar, and the research schema already sits against its size limit — one more
  property on `locations` fails the request with HTTP 400.

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

When an API's docs are unreachable, that is an answer, not an obstacle to route around. A
source whose response shape cannot be verified should be reclassified as manual or left
undone — not written against an invented fixture, which produces code that looks tested and
is not. This is how CVE Details ended up in §7.

Every source's fixtures are **real captured responses**, sanitized, not illustrative
examples. Making the BitSight fixtures real in Phase 1 exposed two genuine bugs that
hand-written ones had hidden, and capturing the FedRAMP page in Phase 6 is the only reason
the `leveraged_systems` trap was found rather than shipped.

Adversarial fixtures — an uncited `yes`, a fabricated citation, a lawsuit with no
resolution date — are the one exception, since no real response can be waited for to
produce them. Build them as edits of a captured reply so the shape stays real, and label
them as constructed.
