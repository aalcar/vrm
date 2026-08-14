# vrm — vendor risk assessment

Query a vendor by **company** and **service**. `vrm` resolves that to machine identifiers
(domain, CPE, package), queries a fixed set of sources concurrently, and returns a sourced
report in a terminal or a browser.

> Solely decision-support. It only surfaces sourced facts.

## Prerequisites

- **Go 1.26+**
- **Docker** — runs the Postgres cache
- **`ANTHROPIC_API_KEY`** — entity resolution and checklist research
- **`BITSIGHT_API_KEY`** — security ratings

`NVD_API_KEY` is optional: it lifts NVD's rate limit from 5 to 50 requests per 30s.

## Quick start

```bash
docker compose up -d       # Postgres on host port 5433
cp .env.example .env       # fill in ANTHROPIC_API_KEY and BITSIGHT_API_KEY
```

`DATABASE_URL` in `.env.example` already points at the compose Postgres

Then either front-end:

```bash
go run ./cmd/vrm assess "Okta" --service "SSO"    # terminal
go run ./cmd/vrmd                                 # browser, http://localhost:8080
```

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

The report opens with the identifiers, then a summary:

```
summary
  9 categories: 6 answered, 1 failed, 1 unanswered, 1 awaiting a manual check
  failed:     bitsight
  unanswered: osv
  awaiting:   ssllabs
```

`unanswered`: gap in data
`awaiting manual check` task for analyst

Long lists cap at ten rows (ex. `… +12 more (use --full)`)

Record a manual answer and it renders verbatim from then on:

```bash
go run ./cmd/vrm set "Okta" --service "SSO" --source ssllabs --value "A+"
```

## Web

`go run ./cmd/vrmd` serves a form and a report on `config.yaml`'s `listen` (`:8080`), or pass `--listen`. 

## Configuration

Non-secret settings live in `config.yaml`: models, source toggles, cache TTLs, timeouts,
manual-source definitions, listen address.

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
| LLM research | company + service | checklist, every claim cited |
| CVE Details, SSL Labs, Open Bug Bounty | — | manual by design — `vrm set` |

**Important:** BitSight's company directory is global but ratings are entitlement-scoped, so a
vendor outside of a subscription returns HTTP 403.

## Development

```bash
go build ./...
go vet ./...
go test -race ./...     # always -race; the fan-out is concurrent
gofmt -l .              # -w to fix
```

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
