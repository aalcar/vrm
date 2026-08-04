# vrm — Vendor Risk Assessment Tool

`vrm` assesses third-party vendors for risk analysts. An analyst queries by **company**
and **service**; the tool resolves that to machine identifiers, fans out to a fixed set of data
sources, and returns a **concise, sourced risk report**.

The report is a **complete checklist**, not just the automatable subset. Categories the tool
cannot query automatically still appear as sections, marked as analyst-supplied, so nothing
silently drops off the assessment.

> `vrm` is decision-support, not a decision-maker. It surfaces sourced facts so a human
> analyst can decide. Framing, severity judgments, and narrative are the analyst's job.

**[`vrm-spec.md`](vrm-spec.md) is the source of truth.** Read it before implementing
anything. [`CLAUDE.md`](CLAUDE.md) covers invariants and workflow.

## Status

**Phases 0–7 complete**; Phase 8 (concurrent fan-out) is next. See spec §13 for the full
phased plan.

`vrm assess` today resolves a company + service to machine identifiers via the Anthropic
API, then queries every source below and prints a sourced report. The fan-out is still
sequential (Phase 8), caching is not wired (Phase 9), the renderer is deliberately plain
(Phase 10), and there is no web UI yet (Phase 11).

| Source | Keyed on | State |
|---|---|---|
| BitSight | domain | ✅ security rating, industry comparison |
| NVD | CPE 2.3 | ✅ CVEs with CVSS scores + severity counts |
| OSV | package + ecosystem | ✅ advisories for vendor-published OSS |
| FedRAMP | company name | ✅ authorization status per offering (scrape) |
| CA Attorney General | company name | ✅ California-reported breaches (scrape) |
| LLM research | company + service | ✅ fixed checklist, every claim cited |
| CVE Details / SSL Labs / Open Bug Bounty | — | ✅ manual, by design — `vrm set` |

## Setup

Requires Go 1.26+ and Docker.

```bash
docker compose up -d          # Postgres for the assessments cache (host port 5433)
cp .env.example .env          # then fill in ANTHROPIC_API_KEY and BITSIGHT_API_KEY
```

`NVD_API_KEY` is optional and worth setting: it raises NVD's rate limit from 5 to 50
requests per 30 seconds. Without it NVD still works, just slowly.

Secrets are environment-only and never belong in `config.yaml`. `.env` is gitignored;
`.env.example` is the committed template. Missing required variables fail at startup with a
clear message listing all of them.

Non-secret settings — model, source toggles, cache TTLs, timeouts — live in `config.yaml`.

## Usage

```bash
go run ./cmd/vrm assess "Okta" --service "SSO"
```

Categories that are not automatable appear as sections telling you what to check and where.
Record an answer and it renders verbatim from then on:

```bash
go run ./cmd/vrm set "Okta" --service "SSO" --source ssllabs --value "A+"
```

Entity resolution is the weakest link in the pipeline — a wrong CPE silently returns another
vendor's CVEs — so the resolved identifiers are printed above the results, and two flags let
you correct a bad mapping without editing code:

```bash
--domain okta.com                        # override the resolved domain (BitSight)
--cpe cpe:2.3:a:okta:access_gateway      # override the resolved CPEs (NVD), comma-separated
```

`--cpe` accepts the short `cpe:2.3:<part>:<vendor>:<product>` form, which is exactly what the
tool prints when it reports that a resolved CPE isn't in NVD's dictionary:

```
nvd  failed
  error: none of the resolved CPEs exist in NVD's CPE dictionary, so a zero CVE count
  would be meaningless; entity resolution likely invented them
    cpe:2.3:a:okta:single_sign-on is unknown to NVD; NVD lists these products for that
    vendor: access_gateway, active_directory_agent, advanced_server_access, ...
```

## Development

```bash
go build ./...          # compiles — the floor, not a pass
go vet ./...            # static checks
go test -race ./...     # ALWAYS -race; the fan-out is concurrent
gofmt -l .              # lists unformatted files; -w to fix
```

`go test -race ./...` is the default test command for this project. A test run without
`-race` proves very little here.

Build phase by phase in spec order. Implement one phase, meet its acceptance criteria, then
stop for review.

## Architecture

The core is a library; the interfaces are thin front-ends over it.

- `cmd/vrm` — CLI (`assess`, `set`)
- `cmd/vrmd` — web server (Go `html/template` + HTMX, SSE progress) — Phase 11
- `internal/assess` — orchestrator: resolve → fan-out → aggregate
- `internal/sources` — one file per source, all behind a common `Source` interface
- `internal/store` — Postgres cache and analyst-supplied manual entries
- `internal/report` — normalized `Report` type and CLI renderer

Data sources are a **fixed** set (spec §6 and §7). Every automated source is a passive
lookup against an existing database — `vrm` never scans or probes vendor infrastructure.
Some categories are deliberately **manual**: CVE Details, SSL Labs and Open Bug Bounty
appear as checklist sections an analyst fills in with `vrm set`, not as HTTP clients to be
written later. Adding another manual source is a `config.yaml` entry, not code.

### Two things the design keeps insisting on

**Partial failure is normal.** One source failing marks that section and nothing else; the
assessment never aborts and siblings are never cancelled. A report with a failed section is
a success. `StatusSkipped` is a first-class outcome too — most vendors publish no OSS, so
skipping OSV is correct behavior, not a gap.

**"We found nothing" and "we couldn't look" are different claims.** They render identically
if you're careless. NVD answers `200 / totalResults 0` both for a vendor with no CVEs and
for a CPE that doesn't exist, so `vrm` confirms the CPE against NVD's dictionary before
reporting a zero. The FedRAMP scrape checks how many records it parsed before reporting a
vendor as unlisted, and the CA AG scrape requires the page's own "no results" marker.
Identifiers that fail validation are dropped *and named* — a silently discarded CPE looks
exactly like a vendor that has none.

**Nothing the model asserts is taken on trust.** Research answers are checked against the
URLs the web-search tool actually returned; a citation that was never in those results is
dropped as fabricated, and a claim left without one is dropped with it. An uncited "yes" on
the two questions a model is most likely to confabulate — Kaspersky use and MOVEit
exposure — is downgraded to `no_evidence_found` rather than shown.

Deterministic data never passes through the LLM. Ratings, CVE records and registry statuses
are interpolated verbatim; the model resolves entities and researches the checklist, and
does not restate, summarize, or recompute anything the other sources returned.
