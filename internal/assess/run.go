package assess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aalcar/vrm/internal/config"
	"github.com/aalcar/vrm/internal/sources"
	"github.com/aalcar/vrm/internal/store"
)

// resolutionWriteTimeout bounds recording the resolution. Short on purpose: the mapping is
// already in hand, and a slow database must not become a slow assessment.
const resolutionWriteTimeout = 5 * time.Second

// Runner is one configured assessment pipeline: resolve, fan out, aggregate, record.
//
// # Why this is not in cmd/
//
// Two front-ends need it — the CLI and the web server — and a pipeline duplicated in two
// entrypoints drifts. It lives here rather than in a front-end because everything it does is
// business logic: which sources are enabled, when a resolution is cacheable, what an override
// supersedes. cmd/ keeps flags, env, and wiring (CLAUDE.md).
//
// # One Runner, one NVD, for the process lifetime
//
// The rate limiter is a field on *sources.NVD, so two instances mean two limiters splitting
// NVD's one five-requests-per-thirty-seconds budget and a 403 that reads like a credential
// problem. The CLI runs one assessment and could get away with building one per run; a server
// handling two requests at once could not. Building it once here makes the safe arrangement
// the only arrangement, and NVD's limiter is mutex-guarded precisely so it can be shared.
type Runner struct {
	cfg     *config.Config
	secrets *config.Secrets
	store   *store.Store
	nvd     *sources.NVD
	warn    func(error)
}

// RunnerOption configures a Runner.
type RunnerOption func(*Runner)

// WithWarner routes cache trouble somewhere visible. A cache that has quietly stopped working
// looks exactly like one that is working — the assessment is simply slower and nobody knows
// why.
func WithWarner(warn func(error)) RunnerOption {
	return func(r *Runner) { r.warn = warn }
}

// NewRunner builds the pipeline. cfg, secrets and st must all be non-nil and live for as long
// as the Runner does.
func NewRunner(cfg *config.Config, secrets *config.Secrets, st *store.Store, opts ...RunnerOption) *Runner {
	r := &Runner{cfg: cfg, secrets: secrets, store: st, warn: func(error) {}}
	for _, opt := range opts {
		opt(r)
	}
	// Nil when the source is switched off: with nvd disabled there is nothing to query and
	// nothing to check CPEs against, and resolution must be told that rather than handed a
	// client whose answers would never be read.
	if cfg.Sources[sources.SourceNVD] {
		// The key is optional — it raises NVD's rate limit rather than granting access — so
		// NVD is built whether or not one is present.
		r.nvd = sources.NewNVD(secrets.NVDAPIKey, sources.WithNVDResultsPerCPE(cfg.NVD.ResultsPerCPE))
	}
	return r
}

// Config exposes the configuration the Runner was built with, for front-ends that report it.
func (r *Runner) Config() *config.Config { return r.cfg }

// NVDKeyPresent reports credential availability without revealing anything about the value.
func (r *Runner) NVDKeyPresent() bool { return r.secrets.HasNVDKey() }

// Request is one assessment to run.
type Request struct {
	Query sources.Query

	// Domain and CPEs are analyst overrides, so a bad mapping can be corrected without
	// editing code. Empty means "use what resolution produced".
	Domain string
	CPEs   []string

	// NoCache skips the cache read for every automated source and for resolution, then
	// records what it fetched — forcing a fresh call is the point, leaving yesterday's row
	// behind is not. It clears nothing, so an analyst's manual entries cannot be caught up in
	// it (spec §11).
	NoCache bool

	// OnResolved and OnSection report progress, for a front-end that shows the assessment
	// arriving rather than waiting for all of it. Both are optional.
	//
	// Both are called from the goroutine that called Run, in order, never concurrently — so an
	// observer may write to one connection without a lock. OnResolved fires first and exactly
	// once, before any section; resolution is the weakest link in the system and there is no
	// reason to make an analyst wait for the slowest source to see the mapping everything else
	// was derived from. OnSection fires once per source, in completion order.
	OnResolved func(Result)
	OnSection  func(sources.Section)
}

// Result is one finished assessment, plus how it was arrived at.
//
// The provenance fields are not bookkeeping: entity resolution is the weakest link in the
// system, and whether a mapping was re-derived or read from a 720h-old row changes what the
// numbers under it mean.
type Result struct {
	// Query is carried here rather than read off Report, because Report is nil during the
	// OnResolved callback and every consumer needs to know what was asked either way.
	Query      sources.Query
	Report     *Report
	Resolution sources.Resolution
	// Entity is the resolved entity after overrides, which is what the sources were actually
	// given — not necessarily what the model returned.
	Entity sources.ResolvedEntity

	ResolutionCached bool
	DomainOverridden bool
	CPEsOverridden   bool
	// NoCache echoes the request. A report that re-queried everything and one that served
	// eight cached rows are different runs, and only this distinguishes them once the
	// sections have lost their markers.
	NoCache bool
}

// Run performs one complete assessment.
//
// The error return is for the things that make a report impossible — a resolution failure, a
// malformed override. A source failing is not one of them: it marks its own section and the
// assessment continues (spec §2.6).
func (r *Runner) Run(ctx context.Context, req Request) (Result, error) {
	if strings.TrimSpace(req.Query.Company) == "" {
		return Result{}, errors.New("company is required")
	}
	if strings.TrimSpace(req.Query.Service) == "" {
		return Result{}, errors.New("service is required")
	}

	// The total budget bounds the whole assessment, resolution included — it is one
	// assessment, and a run that spent its time resolving has still spent it. Every per-source
	// deadline derives from this, so they clamp to whatever remains rather than each getting a
	// fresh budget.
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeouts.Total.Duration())
	defer cancel()

	resolution, resolutionCached, err := r.resolve(ctx, req)
	if err != nil {
		// Fatal, unlike a source failure. Every deterministic source keys off the resolved
		// entity, so continuing would produce a report in which everything skipped — and that
		// reads as "nothing to report" rather than "resolution broke".
		return Result{}, err
	}

	result := Result{
		Query:            req.Query,
		Resolution:       resolution,
		Entity:           resolution.Entity,
		ResolutionCached: resolutionCached,
		DomainOverridden: strings.TrimSpace(req.Domain) != "",
		CPEsOverridden:   len(req.CPEs) > 0,
		NoCache:          req.NoCache,
	}
	if result.DomainOverridden {
		result.Entity.Domains = []string{strings.TrimSpace(req.Domain)}
	}
	if result.CPEsOverridden {
		result.Entity.CPEs = req.CPEs
	}

	// Announced before the fan-out: every section below is derived from this mapping, and a
	// wrong CPE silently returns another vendor's CVEs (spec §15). Report is still nil here,
	// which is what tells an observer this is the interim call.
	if req.OnResolved != nil {
		req.OnResolved(result)
	}

	opts := []Option{WithSourceTimeout(sources.SourceResearch, r.cfg.Timeouts.Research.Duration())}
	if req.OnSection != nil {
		opts = append(opts, WithObserver(req.OnSection))
	}
	result.Report = New(r.registerSources(req.NoCache), r.cfg.Timeouts.PerSource.Duration(), opts...).
		Run(ctx, req.Query, result.Entity)

	// After the fan-out, not before: caching the mapping is gated on what NVD made of it.
	if !resolutionCached {
		r.recordResolution(ctx, req, result)
	}
	return result, nil
}

// resolve returns the entity mapping, from cache when one is fresh, and reports which it was.
//
// Resolution is cached separately from the sources rather than through the same decorator: it
// is not a Source, it runs before the fan-out, and a failure here is fatal to the run where a
// source failure is not.
func (r *Runner) resolve(ctx context.Context, req Request) (sources.Resolution, bool, error) {
	ttl, cacheable := r.cfg.TTL(sources.ResolutionKey)

	if cacheable && !req.NoCache {
		res, hit, err := r.store.CachedResolution(ctx, req.Query.Company, req.Query.Service, ttl)
		switch {
		case err != nil:
			// A sick cache costs a slow answer, never no answer.
			r.warn(fmt.Errorf("resolution: %w", err))
		case hit:
			return res, true, nil
		}
	}

	var opts []sources.ResolverOption
	if r.nvd != nil {
		// A typed nil would satisfy the interface and panic on first use, so the check is on
		// the concrete pointer and the option is only added when there is something behind it.
		opts = append(opts, sources.WithCPEDirectory(r.nvd))
	}
	resolver := sources.NewResolver(r.secrets.AnthropicAPIKey, r.cfg.Models.Resolution, opts...)

	resCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeouts.ResolutionTimeout())
	defer cancel()

	res, err := resolver.Resolve(resCtx, req.Query)
	if err != nil {
		return res, false, err
	}
	return res, false, nil
}

// recordResolution caches a freshly resolved entity, but only once NVD has had its say.
//
// The write waits for the fan-out because the question "are these CPEs real" is answered by
// the source that consumes them, and that answer only exists after it has run. Resolving and
// caching in one step would pin the mapping before anything had checked it — which is how a
// CPE the model invented ends up as the assessment's answer for the next 720h.
func (r *Runner) recordResolution(ctx context.Context, req Request, result Result) {
	if _, cacheable := r.cfg.TTL(sources.ResolutionKey); !cacheable {
		return
	}
	// The verdict below belongs to the analyst's CPEs, not the model's. Letting an override
	// earn the model's mapping a place in the cache would cache a mapping nothing checked.
	if result.CPEsOverridden || !result.Resolution.Cacheable() {
		return
	}
	// A verdict of "invented" is the one answer that blocks the write. No verdict — NVD
	// disabled, or unable to answer this run — falls back to the presence rule: an unvalidated
	// CPE that turns out wrong produces a loud failed section on every later run, where an
	// absent one produced a silent skip.
	if verified, known := result.Report.CPEsVerified(); known && !verified {
		return
	}

	// Its own context, for the same reason a source's cache write gets one: the answer is
	// already in hand and must not be lost to the clock that bounded obtaining it.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolutionWriteTimeout)
	defer cancel()

	if err := r.store.PutResolution(writeCtx, req.Query.Company, req.Query.Service, result.Resolution); err != nil {
		r.warn(fmt.Errorf("resolution: %w", err))
	}
}

// registerSources builds the source list from config. A source toggled off in config.yaml is
// not registered at all, so it produces no section rather than a skipped one.
func (r *Runner) registerSources(noCache bool) []sources.Source {
	// cached wraps an automated source in its configured TTL. A source with no cache_ttl entry
	// comes back unwrapped, so an omitted line means "do not cache" rather than something
	// halfway.
	cached := func(src sources.Source) sources.Source {
		ttl, ok := r.cfg.TTL(src.Name())
		if !ok {
			return src
		}
		return sources.Caching(src, r.store, ttl,
			sources.WithCacheBypass(noCache),
			sources.WithCacheWarner(r.warn))
	}

	var srcs []sources.Source
	if r.cfg.Sources[sources.SourceBitSight] {
		srcs = append(srcs, cached(sources.NewBitSight(r.secrets.BitsightAPIKey)))
	}
	if r.nvd != nil {
		// Built once in NewRunner and also handed to entity resolution, so both uses share one
		// rate limiter. cfg.Sources decided whether it exists at all.
		srcs = append(srcs, cached(r.nvd))
	}
	if r.cfg.Sources[sources.SourceOSV] {
		// OSV is free and unauthenticated.
		srcs = append(srcs, cached(sources.NewOSV()))
	}
	if r.cfg.Sources[sources.SourceFedRAMP] {
		// A public listing, read passively. No credential.
		srcs = append(srcs, cached(sources.NewFedRAMP()))
	}
	if r.cfg.Sources[sources.SourceCAAG] {
		srcs = append(srcs, cached(sources.NewCAAG()))
	}
	if r.cfg.Sources[sources.SourceResearch] {
		// The second LLM job, and the only one that runs inside the fan-out. It skips itself
		// when the key is absent rather than failing the assessment.
		srcs = append(srcs, cached(
			sources.NewResearcher(r.secrets.AnthropicAPIKey, r.cfg.Models.Research)))
	}
	// Manual sources are never wrapped. They are analyst data read fresh from their own row
	// every run, and they never expire (spec §7).
	//
	// They are not toggled by cfg.Sources: they are checklist categories that must appear in
	// every report, answered or not, so that a category an analyst has yet to check never
	// silently drops off the assessment (spec §3, §7).
	for _, m := range r.cfg.ManualSources {
		srcs = append(srcs, sources.NewManual(m.Name, m.Instruction, m.URL, r.store))
	}
	return srcs
}
