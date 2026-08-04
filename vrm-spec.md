# vrm — Vendor Risk Assessment Tool

## Spec & Implementation Plan

> This document is the source of truth for building `vrm`. Implement it phase by phase,
> in order. Each phase has acceptance criteria — do not move to the next phase until the
> current one is met. Prefer small, reviewable commits per phase. This is an internal
> tool used by risk analysts to inform real vendor decisions; treat correctness,
> sourcing, and secret handling as first-class, not afterthoughts.

---

## 1. Overview

`vrm` assesses third-party vendors for risk analysts. One flow: an analyst queries by
**company name + service**, the tool resolves that to machine identifiers, fans out to a
fixed set of data sources, and returns a **concise, sourced risk report**.

The report is a **complete checklist**, not just the automatable subset. Categories the
tool cannot query automatically still appear as sections, marked as analyst-supplied, so
nothing silently drops off the assessment.

Two interfaces over one shared core:
- **CLI** (built first): `vrm assess "Okta" --service "SSO"`.
- **Web** (built second): a single form + report view using Go server-side templates and
  HTMX, with progress streamed over SSE as each source returns.

The core is a library; the CLI and web server are thin front-ends over it. Build the core
so the interface is swappable.

---

## 2. Guiding principles

These shape every design decision below. When in doubt, re-read them.

1. **Decision-support, not decision-maker.** The tool surfaces sourced facts so a human
   analyst can decide. It must never fabricate a risk conclusion or present an
   unverifiable claim as fact.
2. **Deterministic data never passes through the LLM.** Ratings, CVE records, and registry
   statuses come from APIs/scrapes and are interpolated into the report verbatim. The LLM
   is not allowed to restate, "summarize," or recompute them.
3. **Every fuzzy claim carries a citation.** Anything the LLM asserts must include a
   source URL. An analyst has to be able to click through and verify.
4. **The LLM does two separate, small jobs — never one big one.** (a) Entity resolution
   up front, and (b) a **fixed-checklist** research pass. Each is its own call with its
   own tightly scoped prompt and output contract. Do not build a mega-prompt.
5. **Absence of evidence is not evidence of absence.** Every yes/no research question is
   **tri-state**: `yes` (with citation), `no_evidence_found`, or `not_applicable`. There
   is no bare `no`. This is a correctness rule, not a stylistic one.
6. **Partial results beat no results.** One source failing must not kill the assessment.
   Render what succeeded; mark what failed.
7. **The tool reports; the analyst narrates.** `vrm` records what a source said. Framing,
   timelines, severity judgments, and prose commentary are the analyst's job and belong in
   their writeup, not in generated output.

---

## 3. Scope

### In scope
- Query by company name + service.
- LLM entity resolution: company/service → domains, CPE strings, packages, aliases.
- Concurrent fan-out to the automated source list in §6.
- **Manual sources** (§7): registered checklist categories an analyst fills in out of band,
  stored and replayed by the tool.
- LLM research over a **fixed checklist** of questions (§8), each answer cited.
- Normalized aggregation into one report with per-source status and citations.
- Postgres caching per (vendor, service, source) with per-source TTLs.
- CLI rendering to a concise readable report.
- Web: single form + report view (Go templates + HTMX), SSE progress streaming.

### Out of scope (leave seams, do not build)
- Auth / user accounts (assume it runs behind existing access controls).
- Multi-vendor batch assessment.
- Historical trend tracking / dashboards.
- Any write-back to external services, or ticketing integrations.
- Sources beyond those listed in §6 and §7. The `Source` interface must make adding one
  easy; do not add any.
- **Any scanning or probing of vendor infrastructure, directly or via a third-party
  scanner.** Every automated source is a passive lookup against an existing database.
  Scanning is an analyst action taken outside this tool.

---

## 4. Tech stack & conventions

- **Language:** Go 1.22 or newer.
- **Module path:** `github.com/<your-username>/vrm` — replace `<your-username>`.
- **HTTP server:** stdlib `net/http` (or `chi` for routing; nothing heavier).
- **Frontend:** Go `html/template` + HTMX (via CDN `<script>`). No JS build step.
- **DB:** Postgres via `pgx` (`github.com/jackc/pgx/v5`). Migrations as plain `.sql`
  applied on startup, or `golang-migrate`.
- **LLM:** the Anthropic Messages API. Entity resolution uses a strict-JSON prompt;
  research uses the same API **with the server-side web search tool enabled** so it can
  cite live sources. Keep both behind `sources/llm` so the provider is swappable.
- **Concurrency:** fan out with goroutines collecting into a results channel. Do **not**
  use an error-cancelling group for the fan-out — one source failing must not cancel its
  siblings. (`errgroup` is fine for bounded internal sub-tasks that should cancel together.)
- **HTML parsing** (for the scrape sources): `golang.org/x/net/html`, or `goquery` if you
  want selectors. Keep parsing logic isolated per source.
- **Templates:** `html/template` (never `text/template`) — report data comes from
  external sources and must be auto-escaped. Embed with `//go:embed`.

### Secrets & config — read carefully
- **All secrets come from environment variables. Never hardcode or commit a key.**
  - Required: `BITSIGHT_API_KEY`, `ANTHROPIC_API_KEY`, `DATABASE_URL`.
  - Optional (source degrades gracefully when absent, never crashes):
    `NVD_API_KEY` — raises NVD's rate limit from 5 to 50 requests per 30s. NVD still works
    without it, just slowly; it is not a skip condition.
- Provide a `.env.example` with placeholders. Add `.env` to `.gitignore`.
- Validate required secrets on startup; fail fast with a clear message.
- Never log secrets, auth headers, or full LLM prompts.

### Dependencies (keep minimal)
- `github.com/jackc/pgx/v5`, `golang.org/x/net/html`, `gopkg.in/yaml.v3`, an Anthropic Go
  client (or raw `net/http` against the Messages API).
- Test only: `github.com/stretchr/testify` (optional).

---

## 5. Repository layout

```
vrm/
├── cmd/
│   ├── vrm/main.go          # CLI entrypoint (assess, set)
│   └── vrmd/main.go         # web server entrypoint
├── internal/
│   ├── assess/              # orchestrator: resolve → fan-out → aggregate
│   ├── sources/
│   │   ├── source.go        # Source interface + shared types
│   │   ├── bitsight.go      # security rating              (API, licensed)
│   │   ├── nvd.go           # CVEs by CPE                  (API, free)
│   │   ├── osv.go           # OSS package vulns            (API, free)
│   │   ├── fedramp.go       # authorization status         (scrape)
│   │   ├── caag.go          # CA AG breach notifications   (scrape)
│   │   ├── manual.go        # config-driven analyst-supplied sources
│   │   └── llm.go           # entity resolution + checklist research
│   ├── store/               # Postgres cache + manual entry read/write
│   ├── report/              # normalized Report type + CLI renderer
│   └── web/
│       ├── templates/       # form.html, report.html, partials/*.html
│       ├── handlers.go
│       └── sse.go
├── migrations/
├── testdata/                # recorded API/HTML fixtures per source
├── .env.example
├── config.yaml
├── go.mod
└── README.md
```

Keep both `main.go` files thin — parse flags/env, construct the orchestrator, invoke it.

---

## 6. Automated source catalog

All automated sources implement `Source` and run concurrently after entity resolution.
**Access reality differs per source — respect the notes; they are why the design has
`StatusSkipped` and graceful degradation.**

| Source | Keyed on | Access | Notes |
|---|---|---|---|
| **BitSight** | domain | Licensed API key | Pull exact endpoints from BitSight's own API docs. Do not guess paths. A domain search is fuzzy and returns unrelated customer subdomains — prefer an exact `primary_domain` match and surface the alternatives. |
| **NVD (NIST)** | CPE 2.3 | Free CVE API 2.0; `NVD_API_KEY` optional | Query with **`virtualMatchString`, not `cpeName`** — `cpeName` requires a concrete version and 404s on the version-agnostic CPEs resolution produces. 5 req/30s without a key, 50 with. Paginate. **Zero results is ambiguous** and must be disambiguated against the CPE dictionary — see §15. |
| **OSV** | package + ecosystem | Free API (`api.osv.dev`) | Keyed on **open-source packages, not companies.** Only meaningful if the vendor publishes OSS packages; otherwise `StatusSkipped`. Do not force a vendor→package mapping. **Ecosystem is mandatory** — a name-only query is rejected with HTTP 400. Severity is a CVSS *vector*, not a score. |
| **FedRAMP Marketplace** | product / company name | **No official public API** — scrape | Read `www.fedramp.gov/marketplace/products/`. `marketplace.fedramp.gov` is now a SvelteKit shell that only redirects there, and its former `/api/v1/providers` JSON API returns **404**. The listing is ~4.7 MB of server-rendered HTML carrying the whole catalogue (674 offerings when built), so it is fetched whole and filtered locally. **Parse the per-record variable assignments, not the nested `{id,csp,cso,status,…}` literals** — those are `leveraged_systems` dependency lists whose status is stale. See §15. |
| **CA Attorney General** | company name | No API — scrape the public breach-notification list | Authoritative for breaches reported in California. Structured and reliable; a deterministic complement to LLM breach research. |

**Scrape fragility.** `fedramp.go` and `caag.go` parse HTML that will change without
notice. Each must: isolate its parsing in one function, ship with a recorded HTML fixture
in `testdata/`, and fail to `StatusFailed` with a clear message rather than returning
silently-wrong data. A scraper returning genuinely empty results and a scraper that broke
must be distinguishable.

---

## 7. Manual sources

Some assessment categories are not automatable — the available APIs are unofficial,
paywalled, too slow for a request cycle, or governed by terms that make automated
third-party use inappropriate. Rather than dropping those categories, `vrm` registers
them as **manual sources**: they appear in every report as real sections, telling the
analyst what to check by hand, and holding the recorded answer once supplied.

Current manual sources:

| Name | What the analyst does |
|---|---|
| `cvedetails` | Search the vendor on CVE Details; record CVE counts and anything NVD missed. |
| `ssllabs` | Run an SSL Labs test against the service hostname; record the grade. |
| `openbugbounty` | Search the vendor domain on Open Bug Bounty; record open/fixed counts. |

All three were dropped from automation deliberately. SSL Labs requires email registration,
its scans take minutes (poll-based, incompatible with a request-time budget), and its
free-use terms are aimed at operators testing their own infrastructure. Open Bug Bounty
exposes only an unofficial, sparsely-documented XML endpoint with no stability guarantee.
CVE Details requires a paid Business/Enterprise subscription and publishes no reachable API
reference, so a client for it could be neither verified nor exercised — its response shape
would be guesswork, and NVD already covers CVEs as the primary source. **Do not reintroduce
any of the three as an automated client.**

### Implementation

One generic type, driven entirely by config — not two bespoke stubs:

```go
// ManualSource is a checklist category an analyst fills in out of band.
// It never makes a network call.
type ManualSource struct {
    name        string
    instruction string // shown in the report when no entry exists
    url         string // where the analyst goes to perform the check
}

func (m *ManualSource) Name() string { return m.name }

// Fetch reads any recorded entry from the store. With no entry, it returns
// StatusSkipped carrying the instruction and URL so the report shows the gap.
func (m *ManualSource) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error)
```

### Storage — reuse the cache table

A manual entry is just a cache row. `assessments_cache` is already keyed on
`(company, service, source)` with a JSONB payload, so recording one needs **no new table
and no new read path** — `ManualSource.Fetch` goes through the same read-through the
automated sources use.

Two rules specific to manual entries:
- **Manual entries never expire.** TTL logic does not apply — there is no automated
  refresh that could replace them. A manual row is valid until an analyst overwrites it.
  Mark the row so TTL sweeps skip it.
- **`--no-cache` does not clear them.** Forcing a fresh assessment re-queries the automated
  sources; it must not wipe analyst-supplied data. This is an easy bug to write — do not.

### Recording an entry

```bash
vrm set "Okta" --service "SSO" --source ssllabs --value "A+"
vrm set "Okta" --service "SSO" --source openbugbounty --value "0 open / 3 fixed"
```

`--value` is free text, stored verbatim. The tool does not parse, validate, or interpret
it — per principle #7, interpretation is the analyst's. Adding a third manual source later
is a config entry, not code.

---

## 8. LLM research checklist

The research call answers a **fixed list of questions**. Not open-ended. The prompt
enumerates these fields, and the response is parsed into this struct — extra prose is
discarded, missing fields are `no_evidence_found`.

```go
type Tri string
const (
    TriYes        Tri = "yes"                // requires >=1 citation
    TriNoEvidence Tri = "no_evidence_found"   // NOT the same as "no"
    TriNA         Tri = "not_applicable"
)

type Finding struct {
    Value     string     // the claim, one or two sentences
    Citations []Citation // required whenever Value is non-empty
}

type Research struct {
    SupplierDescription   Finding   // what the company is/does
    ServiceDescription    Finding   // what the specific service is
    ServiceImplementation Finding   // how it is deployed/integrated: SaaS, on-prem,
                                    // hybrid; what data flows through it
    CyberLawsuits         []Finding // see filter rules below
    PastBreaches          []Finding // what happened, with citation
    SupplierWebsite       Finding   // canonical corporate URL
    ServiceWebsite        Finding   // product/service URL
    SecurityPage          Finding   // security page / trust center URL
    NotificationPage      Finding   // public breach/incident notification page URL
    Locations             []Finding // country; city + state when US. Supplier HQ AND
                                    // employee/operational locations, labeled as such.
    UsedKaspersky         Tri
    UsedKasperskyEvidence Finding   // populated when TriYes
    MOVEitImpacted        Tri
    MOVEitEvidence        Finding   // populated when TriYes
}
```

### Hard rules the prompt must enforce, and the parser must validate

- **Lawsuits are double-filtered.** Include an entry only if it is (a) **concluded** —
  settled, dismissed, or judged, *not* pending or merely filed — **and** (b) **directly
  about cybersecurity** — breach, data protection failure, security misrepresentation.
  General commercial, employment, IP, or antitrust litigation is excluded even if the
  company is a security vendor. Each entry must state its outcome and resolution date;
  without both, **drop the entry** — the resolution date is how "concluded" is verified,
  and is retained for that reason alone.
- **Kaspersky and MOVEit are the highest confabulation risk in the whole tool.** Both are
  famous events an LLM will pattern-match toward. A `yes` requires a citation naming this
  specific vendor. An uncited `yes` is **downgraded to `no_evidence_found` by the parser**,
  not passed through. Never emit a bare `no`.
- **Locations must be labeled** as HQ vs. operational/employee presence, and must state
  country (plus city and state when US). Do not merge them into one blob.
- **Every non-empty `Finding.Value` requires at least one citation.** A finding with a
  claim and no citation is dropped and the field is marked `no_evidence_found`.
- **No editorializing.** Findings state what a source says and link to it. No severity
  ratings, risk framing, or narrative connective tissue — the analyst writes that (§2.7).
- **Deterministic sources take precedence.** The CA AG scrape is authoritative for
  California-reported breaches. Do **not** feed its results into the research prompt to be
  "confirmed" — run them independently and render both. If the LLM reports a breach the CA
  AG list does not contain, that is informative (out-of-state / unreported), not an error.
  Surface both and let the analyst compare.

---

## 9. Core types & interfaces

```go
// package sources

type Query struct {
    Company string
    Service string
}

// ResolvedEntity is the output of LLM entity resolution — the bridge between a
// human-friendly query and the identifiers the deterministic sources need.
type ResolvedEntity struct {
    CanonicalName string
    Domains       []string // BitSight
    CPEs          []string  // CPE 2.3 strings, for NVD
    Packages      []Package // OSS packages, for OSV (usually empty)
    Aliases       []string  // subsidiaries / former names
}

// Package is one open-source package a vendor publishes. Ecosystem is not optional
// garnish: OSV rejects a name-only query outright, and the same name means different
// software in different registries.
type Package struct {
    Ecosystem string // an OSV ecosystem in OSV's capitalization: npm, PyPI, Go, Maven, …
    Name      string
}

type Status string
const (
    StatusOK      Status = "ok"
    StatusFailed  Status = "failed"   // the source errored — show the error
    StatusSkipped Status = "skipped"  // nothing to query, credential absent, or a
                                      // manual source with no recorded entry
)

type Citation struct {
    Title string
    URL   string
}

// Section is one source's normalized contribution to the report.
type Section struct {
    Source    string
    Status    Status
    Data      any        // source-specific struct (never a map)
    Citations []Citation
    Note      string     // why skipped, or the manual-check instruction + URL
    Err       string     // set when Status == StatusFailed
}

// Source is one data provider. Implementations must be safe for concurrent use and
// must respect ctx cancellation/timeouts.
type Source interface {
    Name() string
    Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error)
}
```

```go
// package assess

type Report struct {
    Query    sources.Query
    Entity   sources.ResolvedEntity // surfaced in output so a bad mapping is visible
    Sections []sources.Section      // stable, documented order
    Cached   map[string]bool
}
```

---

## 10. Assessment flow

1. **Entity resolution.** LLM call with a strict-JSON prompt: company + service →
   `ResolvedEntity`. Prompt it to return `[]` for anything it cannot determine rather than
   guessing; parse strictly and reject malformed output. This is the weakest link — a wrong
   CPE silently yields the wrong CVEs.
2. **Fan out.** All automated sources (§6), all manual sources (§7), and the research call,
   concurrently, each receiving `Query` and `ResolvedEntity`. Each checks the store first,
   calls out on miss, writes through. Collect every `Section` independently — one failure
   marks that section only. Sources with no usable input (no domain → BitSight, no CPEs →
   NVD, no packages → OSV, no recorded entry → manual) return `StatusSkipped`, not an
   error.
3. **Aggregate** into a `Report` in a stable, documented section order.
4. **Render** — CLI prints a concise report; web streams sections as they land.

---

## 11. Caching

- Table `assessments_cache` keyed by `(company, service, source)`, storing the serialized
  `Section` (JSONB), `fetched_at`, and a `manual` boolean.
- `fetched_at` exists to drive TTL expiry. It is internal bookkeeping — **do not surface
  it as content in the report.**
- Read-through / write-through. Hit → return cached `Section`, set `Cached[source]=true`.
- TTLs per source, because these signals age very differently:

```yaml
cache_ttl:
  bitsight:      24h
  nvd:           24h
  osv:           24h
  fedramp:       168h   # authorization status changes rarely
  caag:          168h   # breach list updates infrequently
  llm_research:  168h   # most expensive call in the system
  resolution:    720h   # entity mapping is near-static
  # manual sources have no TTL — see §7
```

- `--no-cache` forces fresh automated calls. It **must not** delete or bypass manual
  entries (`manual = true` rows).
- Cache entity resolution too, keyed on company+service.

---

## 12. Config schema (non-secret)

```yaml
# The two LLM jobs (§2.4) stay separate and have very different cost profiles, so each
# gets its own model. Structured outputs — which make the resolution prompt's JSON
# contract enforceable rather than merely requested — need Sonnet 5 or newer.
models:
  resolution: claude-sonnet-5
  research: claude-sonnet-5

sources:                  # toggle any automated source off wholesale
  bitsight: true
  nvd: true
  osv: true
  fedramp: true
  caag: true

manual_sources:
  - name: cvedetails
    url: https://www.cvedetails.com
    instruction: "Search the vendor; record CVE counts and anything NVD missed"
  - name: ssllabs
    url: https://www.ssllabs.com/ssltest
    instruction: "Scan the service hostname; record the grade"
  - name: openbugbounty
    url: https://www.openbugbounty.org
    instruction: "Search the vendor domain; record open/fixed counts"

cache_ttl: { ... }        # see §11

timeouts:
  per_source: 30s
  total: 90s              # ceiling, not a target; manual sources return instantly

nvd:
  results_per_cpe: 20

listen: ":8080"
```

Secrets are **not** in this file (§4). Validate config on load; reject unknown automated
source names and manual entries missing `name`.

---

## 13. Phased implementation plan

Stop after each phase's acceptance criteria for review.

### Phase 0 — Scaffolding ✅
Module init, layout, config + env loading with fail-fast validation, Postgres connection,
migration creating `assessments_cache`, graceful shutdown, `vrm assess "<company>"
--service "<x>"` printing the parsed query.
**Done when:** `go build ./...` passes, DB connects, missing required env gives a clear error.

### Phase 1 — Source interface + BitSight ✅
Define `sources` types and the `Source` interface. Implement `bitsight.go` (endpoints from
BitSight's docs). Trivial orchestrator running one source.
**Done when:** a real rating comes back for a known vendor, and an API error surfaces as
`StatusFailed` without crashing.

### Phase 2 — LLM entity resolution ✅
`llm.go` resolution function: strict-JSON prompt → parsed `ResolvedEntity` (domains, CPEs,
packages, aliases). Empty arrays for unknowns.
**Done when:** "Okta" + "SSO" yields plausible domains and ≥1 valid CPE; malformed model
output is rejected cleanly rather than propagated.

Uses the API's structured-outputs feature (`output_config.format` + `json_schema`), which
makes the strict-JSON contract guaranteed rather than merely requested. `--domain` and
`--cpe` override a bad mapping without editing code.

### Phase 3 — NVD ✅
CVE API 2.0 by resolved CPEs; normalize with severity counts; `StatusSkipped` when no CPEs;
respect rate limits and use `NVD_API_KEY` when present.
**Done when:** a vendor with known CVEs returns them with CVSS scores; no-CPE yields
`StatusSkipped`, not an error.

Also verifies each CPE against the CPE dictionary when a query returns zero results — see
§15. Metric selection prefers the newest CVSS revision, then NVD's own Primary analysis over
a CNA's Secondary, recording which.

### Phase 4 — OSV ✅
`osv.go` against `api.osv.dev` for resolved packages; `StatusSkipped` when `ent.Packages`
is empty (the common case — correct behavior, not a bug).
**Done when:** a vendor publishing OSS returns OSV results; a vendor that does not is
cleanly skipped.

CVE Details was reclassified as a manual source during this phase (§7): the API is paywalled
and its reference unreachable, so a client could be neither verified nor exercised.

### Phase 5 — Manual sources + `vrm set`
`manual.go` implementing the generic `ManualSource`, constructed from `manual_sources`
config. `vrm set` subcommand writing a manual row. Store marks manual rows TTL-exempt.
**Done when:** with no entry, `cvedetails`, `ssllabs` and `openbugbounty` render as skipped
sections showing their instruction and URL; after `vrm set`, the recorded value renders
verbatim; `--no-cache` refreshes automated sources while leaving manual entries intact.

### Phase 6 — FedRAMP + CA AG scrapes
`fedramp.go` against the current `fedramp.gov/marketplace` host; `caag.go` against the CA
AG breach list. Both with recorded fixtures in `testdata/`.
**Done when:** a known FedRAMP-authorized vendor returns its status; a vendor on the CA AG
list returns its entries; a changed page layout produces `StatusFailed` with a clear
message, not silent empty results.

### Phase 7 — LLM research checklist
Research function per §8: fixed fields, tri-state answers, citation enforcement, lawsuit
double-filter, uncited-`yes` downgrade in the parser.
**Done when:** every populated field has a working citation URL; an uncited Kaspersky or
MOVEit `yes` is demonstrably downgraded to `no_evidence_found` by a unit test.

### Phase 8 — Orchestrator fan-out
All sources concurrently after resolution. Independent error collection, per-source and
total timeouts, stable section order.
**Done when:** a full assessment completes within the total timeout, and blocking or
killing any one source still produces a report containing the rest.

### Phase 9 — Caching
`store` package, per-source TTLs, manual-row exemption, `--no-cache`.
**Done when:** a repeat assessment within TTL is visibly faster with `Cached` flags set;
`--no-cache` forces fresh automated calls and preserves manual entries.

### Phase 10 — CLI rendering
Concise terminal report: resolved entity, BitSight grade, CVE/OSV summary, FedRAMP status,
CA AG entries, manual sections (value or instruction), research checklist with inline
citations, and explicit markers for every failed/skipped source.
**Done when:** a non-author analyst can read it top to bottom without explanation, and can
tell at a glance which categories are answered, which failed, and which await a manual check.

### Phase 11 — Web UI
`cmd/vrmd`: `GET /` form, `POST /assess` runs and renders via embedded `html/template`,
HTMX swaps the report in.
**Done when:** an analyst gets the same report in the browser, with all external data
HTML-escaped.

### Phase 12 — SSE progress streaming
Orchestrator publishes an event per source completion; HTMX `sse-connect` region swaps in
partials as they land, then the full report.
**Done when:** sources appear incrementally and a slow source does not block fast ones.

---

## 14. Testing strategy

- **Unit:** resolution JSON parsing (including malformed/partial output), NVD CPE query
  construction, OSV skip logic, tri-state parsing, **citation enforcement and the
  uncited-`yes` downgrade**, lawsuit double-filter rejection, cache TTL logic, **manual-row
  TTL exemption and `--no-cache` preservation**.
- **Fixtures:** every scrape/API source gets a recorded response in `testdata/` — JSON for
  APIs, HTML for the two scrapes. Scrape parsers are tested against fixtures so layout
  drift is caught by a failing test rather than by an analyst reading an empty section.
- **Source isolation:** each external client behind a small interface; test orchestrator
  behavior against fakes covering success, failure, timeout, and skip. **Partial-failure
  behavior is the highest-value thing to cover.**
- **Template safety:** assert a vendor field containing `<script>` is escaped in the
  rendered report.
- **Race:** `go test -race`; the fan-out and cache writes are the risk areas.
- **Manual:** a handful of real vendors end to end; verify citations resolve and
  deterministic values match the upstream sources.
- Never commit real API keys in fixtures — sanitize before recording.

---

## 15. Notes for the implementer

- **Secrets discipline is a hard requirement, not a nicety.** Env-only, never logged,
  `.env` gitignored, fail-fast on missing required keys. Get this right in Phase 0.
- **`StatusSkipped` is a first-class, expected outcome.** Most vendors will skip OSV, and
  many will skip NVD for want of a registered CPE. Manual sources start skipped by
  definition. None of these are failures and none should look like failures in the report.
- **Distinguish "we looked and found nothing" from "we could not look."** These render
  identically if you are careless, and the first is a far stronger claim. NVD is the live
  example: it answers `200 / totalResults 0` both for a vendor with no CVEs and for a CPE
  that does not exist, so a zero is only meaningful once the CPE is confirmed against the
  CPE dictionary. Both live Okta runs during Phase 3 resolved to a fabricated CPE
  (`okta:okta`, then `okta:single_sign-on`; NVD's real products are `access_gateway`,
  `verify`, …), which would otherwise have rendered as a clean bill of health.
- **When scraping, find the authoritative record before writing the parser.** The FedRAMP
  listing is the live example, and it is a trap that hides in plain sight. The page carries
  ~5,600 tidy `{id:"…",csp:"…",cso:"…",status:"…"}` object literals, which look exactly like
  the product catalogue — they are `leveraged_systems` dependency lists nested inside other
  records, and their `status` is not maintained. Okta appears in them as `"Unknown"` while
  its actual marketplace status is `"FedRAMP Certified"`. The authoritative records are the
  674 runs of `<var>.csp="…"` assignments. A parser built on the obvious shape returns a
  complete, plausible, sourced section that is wrong, and nothing fails — the same class of
  error as a wrong CPE. Count what you parsed and check it against what the page should
  carry.
- **Manual sources are not stubs to be "finished later."** They are the permanent design
  for categories that should not be automated. Do not write HTTP clients for them.
- **Manual entries are analyst data, not cache.** They share a table for convenience only.
  Never expire them, never clear them on `--no-cache`, never overwrite them automatically.
- **Keep the two LLM jobs physically separate** — different functions, prompts, and output
  contracts (resolution = strict JSON; research = fixed checklist + citations). Resist any
  refactor that merges them.
- **Never launder deterministic data through the LLM.** Grades, CVE records, and registry
  statuses are interpolated as-is.
- **The tri-state rule is load-bearing.** "We found no evidence Vendor X used Kaspersky" and
  "Vendor X did not use Kaspersky" are different claims, and only the first is one this tool
  can support. Never collapse them.
- **Don't generate narrative.** Record values and citations; leave interpretation, timelines,
  and framing to the analyst's writeup.
- **Entity resolution is the weakest link.** Surface `ResolvedEntity` in the report so an
  analyst can catch a bad mapping before acting on wrong CVEs. Prompt wording alone does not
  fix it — tightening the CPE instruction with a concrete counter-example only moved the
  fabrication to a different plausible-looking token. Validate identifiers against the
  source that will consume them, and report what was dropped and why.
- **Do not restate one scorer's vocabulary in another's.** GitHub rates advisories
  MODERATE; NVD rates them MEDIUM. They are different scales from different bodies, and
  silently translating is laundering a value. Likewise, OSV supplies a CVSS *vector* rather
  than a base score — deriving the number would be recomputing a value instead of reporting
  one.
- **Partial failure is the normal case, not an edge case.** A report with a marked failed
  section is a success; an aborted assessment is a bug.
- **Scrapers rot.** Assume `fedramp.go` and `caag.go` will break; make breakage loud.

---

## 16. Picking up the work

Phases 0–4 are built. To get running:

```bash
docker compose up -d        # Postgres on host port 5433
cp .env.example .env        # fill BITSIGHT_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL
go test -race ./...         # the default test command; without -race it proves little
go run ./cmd/vrm assess "Okta" --service "SSO"
```

Phase 5 (manual sources + `vrm set`) is next. Implement one phase, meet its acceptance
criteria, confirm each one explicitly, then stop for review — do not roll into the next
phase. The analyst reviews and commits; do not run `git commit`.
