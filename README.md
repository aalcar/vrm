# vrm — vendor risk assessment

Query a vendor by **company** and **service**. `vrm` resolves that to machine identifiers
(domain, CPE, package), queries a fixed set of sources concurrently, and returns a sourced
report — in a terminal or a browser.

The report is a complete checklist, not just the automatable part. Categories nothing can
query still appear as sections marked for an analyst to fill in, so none of them quietly
falls off the assessment.

> Decision-support, not a decision-maker. It surfaces sourced facts; severity judgments and
> narrative are the analyst's job.

## Prerequisites

- **Go 1.26+**
- **Docker** — runs the Postgres cache
- **`ANTHROPIC_API_KEY`** — entity resolution and checklist research
- **`BITSIGHT_API_KEY`** — security ratings

`NVD_API_KEY` is optional and worth setting: it lifts NVD's rate limit from 5 to 50 requests
per 30s. Without it NVD works, just slowly.

## Quick start

```bash
docker compose up -d       # Postgres on host port 5433
cp .env.example .env       # fill in ANTHROPIC_API_KEY and BITSIGHT_API_KEY
```

`DATABASE_URL` in `.env.example` already points at the compose Postgres — leave it alone
unless you're using your own.

Then either front-end:

```bash
go run ./cmd/vrm assess "Okta" --service "SSO"    # terminal
go run ./cmd/vrmd                                 # browser, http://localhost:8080
```

Both hit the same pipeline and label sections identically. A first run takes ~30s; a repeat
inside the cache TTL takes ~0.05s.

Secrets are environment-only and are never read from `config.yaml`. Missing ones fail at
startup with all of them named at once.

## CLI

```
vrm assess "<company>" --service "<service>" [flags]
vrm set    "<company>" --service "<service>" --source <name> --value "<text>"
```

| Flag | Effect |
|---|---|
| `--service` | required |
| `--domain` | override the resolved domain (BitSight) |
| `--cpe` | override the resolved CPEs (NVD), comma-separated |
| `--no-cache` | re-query automated sources; analyst entries are never cleared |
| `--full` | print every detail row instead of capping long lists |
| `--config` | config file path (default `config.yaml`) |

The report opens with the resolved identifiers, then a summary:

```
summary
  9 categories: 6 answered, 1 failed, 1 unanswered, 1 awaiting a manual check
  failed:     bitsight
  unanswered: osv
  awaiting:   ssllabs
```

`unanswered` and `awaiting manual check` are both skips underneath and mean different things:
the first is a gap in the data, the second is a task for you.

Long lists cap at ten rows and say what they held back (`… +12 more (use --full)`); the
severity counts above them always cover everything. Outcome labels are colored on a terminal
and never when redirected; `NO_COLOR` disables them.

Record a manual answer and it renders verbatim from then on:

```bash
go run ./cmd/vrm set "Okta" --service "SSO" --source ssllabs --value "A+"
```

## Web

`go run ./cmd/vrmd` serves a form and a report on `config.yaml`'s `listen` (`:8080`), or pass
`--listen`. Sections stream in over SSE as each source returns — the resolved entity first,
then a section per source as it lands, then the finished report. On a real run the entity
arrives at 6.6s, eight sources by 7.9s, and the slow research call at 30.2s.

**No auth, no TLS** — deliberately out of scope (spec §2). Run it on localhost or behind
something that provides both.

## Configuration

Non-secret settings live in `config.yaml`: models, source toggles, cache TTLs, timeouts,
manual-source definitions, listen address. Adding a manual source is a config entry, not code.

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Postgres cache |
| `ANTHROPIC_API_KEY` | yes | entity resolution, checklist research |
| `BITSIGHT_API_KEY` | yes | security ratings |
| `NVD_API_KEY` | no | raises NVD's rate limit |

## Sources

| Source | Keyed on | Returns |
|---|---|---|
| BitSight | domain | security rating, industry comparison |
| NVD | CPE 2.3 | CVEs with CVSS scores + severity counts |
| OSV | package + ecosystem | advisories for vendor-published OSS |
| FedRAMP | company name | authorization status per offering (scrape) |
| CA Attorney General | company name | California-reported breaches (scrape) |
| LLM research | company + service | fixed checklist, every claim cited |
| CVE Details, SSL Labs, Open Bug Bounty | — | manual by design — `vrm set` |

The set is fixed (spec §6, §7). Every automated source is a passive lookup against an existing
database; `vrm` never scans or probes vendor infrastructure.

**Known gap:** BitSight's company directory is global but ratings are entitlement-scoped, so a
vendor outside your subscription returns HTTP 403 with a valid key. The report says so rather
than blaming the credential.

## Development

```bash
go build ./...
go vet ./...
go test -race ./...     # always -race; the fan-out is concurrent
gofmt -l .              # -w to fix
```

[`vrm-spec.md`](vrm-spec.md) is the source of truth. [`CLAUDE.md`](CLAUDE.md) covers the
invariants — read it before changing anything under `internal/`.

## Architecture

```
cmd/vrm            CLI (assess, set)
cmd/vrmd           web server
internal/assess    the pipeline: resolve → fan out → aggregate → record
internal/sources   one file per source, behind a common Source interface
internal/store     Postgres cache and analyst-supplied manual entries
internal/report    terminal renderer + the outcome/summary logic both UIs share
internal/web       handlers, SSE stream, embedded templates
```

Both front-ends call `assess.Runner.Run`, which owns the single shared `*sources.NVD` — the
rate limiter is a field on it, and two instances would split one budget and earn a 403.

### Two things the design keeps insisting on

**Partial failure is normal.** One source failing marks that section and nothing else. The
assessment never aborts, siblings are never cancelled, and a report with a failed section is
still a success.

**"We found nothing" and "we couldn't look" are different claims,** and they render
identically if you're careless. NVD answers `200 / totalResults 0` both for a clean vendor and
for a CPE that doesn't exist — so CPEs are sourced from NVD's own dictionary rather than
composed by the model, and every one is checked for membership before it can be queried. The
FedRAMP scrape checks how many records it parsed before calling a vendor unlisted. Research
citations are matched against the URLs the search tool actually returned, and an unmatched one
is dropped as fabricated. Identifiers that fail any of this are dropped *and named* — a
silently discarded CPE looks exactly like a vendor that never had one.

Deterministic data never passes through the LLM. Ratings, CVE records and registry statuses
are interpolated verbatim; the model resolves entities and researches the checklist, and does
not restate or recompute anything another source returned.
