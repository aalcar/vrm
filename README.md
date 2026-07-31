# vrm — Vendor Risk Assessment Tool

`vrm` assesses third-party vendors for risk analysts. An analyst queries by **company**
+ **service**; the tool resolves that to machine identifiers, fans out to a fixed set of data
sources, and returns a **concise, sourced risk report**.

The report is a **complete checklist**, not just the automatable subset. Categories the tool
cannot query automatically still appear as sections, marked as analyst-supplied, so nothing
silently drops off the assessment.

> `vrm` is decision-support, not a decision-maker. It surfaces sourced facts so a human
> analyst can decide. Framing, severity judgments, and narrative are the analyst's job.

**[`vrm-spec.md`](vrm-spec.md) is the source of truth.** Read it before implementing
anything. [`CLAUDE.md`](CLAUDE.md) covers invariants and workflow.

## Status

Phase 0 (scaffolding) — see spec §13 for the phased plan. The CLI parses a query, loads
config, validates secrets, and connects to Postgres. No data sources are wired up yet.

## Setup

Requires Go 1.22+ and Docker.

```bash
docker compose up -d          # Postgres for the assessments cache
cp .env.example .env          # then fill in ANTHROPIC_API_KEY and BITSIGHT_API_KEY
```

Secrets are environment-only and never belong in `config.yaml`. `.env` is gitignored;
`.env.example` is the committed template. Missing required variables fail at startup with a
clear message listing all of them.

Non-secret settings — model, source toggles, cache TTLs, timeouts — live in `config.yaml`.

## Usage

```bash
go run ./cmd/vrm assess "Okta" --service "SSO"
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
Some categories are deliberately **manual**: SSL Labs and Open Bug Bounty appear as
checklist sections an analyst fills in with `vrm set`, not as HTTP clients to be written
later.
