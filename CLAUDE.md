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

Phases 0–9 are complete. Phase 10 (CLI rendering) is next.

**FedRAMP broke and recovered inside a day (2026-08-05).** The marketplace listing served a
39 KB client-rendered SvelteKit shell for part of that day and `fedramp` failed loudly on
every run; by the evening it was back to 4.7 MB of server-rendered HTML with 691 authoritative
`.csp="` records, and the parser works unchanged. Nothing was fixed and nothing needs fixing —
the record floor did its job in both directions. Treat this as evidence the page can change
under you at any time, not as an incident that is closed: if it fails again, find the data,
do not lower the floor.

## Commands

```bash
go build ./...          # compiles — the floor, not a pass
go vet ./...            # static checks
go test -race ./...     # ALWAYS -race; the fan-out is concurrent
gofmt -l .              # lists unformatted files; -w to fix
```

`go test -race ./...` is the default test command for this project. A test run without
`-race` proves very little here.

**Anything about LLM latency or output quality needs three runs per setting, not one.** The
same configuration has produced 33s and 278s on identical work. Single-run comparisons in
this project have twice pointed at the wrong cause.

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
- **An empty result from a source that ran is a failure, not a clean answer.** Research
  returning nothing is `StatusFailed`, the same way an unverified NVD zero and a FedRAMP
  parse below its floor are. A blank section under a green heading is the strongest claim
  the tool can make and the one it can least support.
- **Set `effort` explicitly on both LLM calls.** The default is slower and answers fewer
  fields; `medium` returned an empty checklist twice in five runs where `low` never did in
  eighteen. Never leave it to an API default nobody chose.
- **Uncited claims are dropped, not displayed.** A `yes` without a citation naming this
  specific vendor is downgraded to `no_evidence_found` by the parser.
- **Partial failure is normal.** One source failing marks that section only. Never cancel
  siblings; never abort the assessment. Do not use an error-cancelling group for the
  fan-out.
- **`StatusSkipped` is a real outcome, not a failure.** Most vendors legitimately skip OSV.
  Manual sources start skipped. Do not "fix" these.
- **Manual entries are analyst data.** They live in the cache table for convenience only.
  Never expire them, never clear them on `--no-cache`, never overwrite them automatically.
  Every read and write filters on the `manual` column, in both directions: the table holds two
  different JSON shapes and that boolean is the only thing telling them apart.
- **Only successful sections are cached.** A failure is a fact about the run, not about the
  vendor; caching one pins an upstream blip for the whole TTL — 168h for FedRAMP — and an
  analyst cannot tell a cached failure from a live one. A skip is worse: it is derived from
  the resolved entity, so it would outlive the resolution fix meant to clear it.
- **A resolution with no CPEs is never cached, on read or write.** Resolution has no error to
  gate on, so the gate is the identifier NVD needs. An empty CPE list is the one output that
  cannot be interpreted — correct for a vendor with no CPE, a bad sample for one that has
  them — and the same prompt has returned `(none)` on one call and a CPE on the next, twice
  in four consecutive runs. Caching the empty one skips NVD for 720h under a heading that
  reads like an answer. The check runs on read too, so rows written before it existed expire
  on first read instead of outliving the fix. Cost: vendors that genuinely have no CPE
  re-resolve every run. That is the trade, and it is deliberate.
- **A cached `Section.Data` must come back as its concrete type.** `json.Unmarshal` into an
  `any` yields a `map`, the renderer's type switch matches no case, and the section renders as
  a green heading with nothing under it. Decoding is table-driven per source and encoding is
  checked against the same table. Never add a source without registering its codec — a test
  enforces this, because the failure is silent.
- **A cache write gets its own context.** Fetching can consume a source's entire deadline;
  borrowing that context to record the result would make the most expensive answer in the tool
  the least likely to be cached. A cache failure warns and never fails a section.
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
