// Package assess orchestrates an assessment: resolve, run every source, aggregate the
// results into one report.
//
// # Partial failure is the normal case
//
// A report with a failed section is a success; an aborted assessment is a bug (spec §15).
// One source failing, timing out, or hanging must never cancel, block, or abort another.
// That is why this package does not use an error-cancelling group anywhere — an errgroup
// would tear down every sibling the moment one source returned an error, which is exactly
// the behaviour spec §2.6 forbids.
//
// Sources run concurrently (Phase 8). The isolation model predates the concurrency —
// Phase 1 was already written so that no source could affect another — so goroutines were
// added rather than anything being undone.
package assess

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/aalcar/vrm/internal/sources"
)

// SectionOrder is the stable, documented order sections appear in a report (spec §10).
// Sources not named here are appended afterwards in registration order.
var SectionOrder = []string{
	sources.SourceBitSight,
	"nvd",
	"osv",
	// cvedetails is a manual source (config.yaml), but it stays here beside the other CVE
	// sections rather than down with the manual ones — this list is reading order, and a
	// reader comparing CVE coverage wants the three together.
	"cvedetails",
	"fedramp",
	"caag",
	"ssllabs",
	"openbugbounty",
	"llm_research",
}

// Report is one complete assessment.
type Report struct {
	Query sources.Query
	// Entity is surfaced so an analyst can spot a bad mapping before acting on results
	// derived from it (spec §15).
	Entity   sources.ResolvedEntity
	Sections []sources.Section
	Cached   map[string]bool
}

// CPEsVerified reports NVD's verdict on the CPEs entity resolution produced: whether it
// confirmed at least one, and whether it reached a verdict at all.
//
// NVD is the consumer of those identifiers, so its answer is the authoritative one — the
// alternative, re-checking the dictionary during resolution, would duplicate this logic and
// pay a second round of requests for a worse version of the same answer.
//
// known is false when NVD is disabled, skipped, or failed before it could look anything up.
// Those are absences of a verdict, not a negative one, and must not be read as either.
func (r *Report) CPEsVerified() (verified, known bool) {
	for _, s := range r.Sections {
		if s.Source != sources.SourceNVD {
			continue
		}
		res, ok := s.Data.(sources.NVDResult)
		if !ok || len(res.Queries) == 0 {
			return false, false
		}
		return res.AnyVerified(), true
	}
	return false, false
}

// Assessor runs a fixed set of sources.
type Assessor struct {
	sources          []sources.Source
	perSourceTimeout time.Duration
	// sourceTimeouts overrides the shared deadline for named sources. One budget does not
	// fit every source: a REST lookup that has not answered in 30s has failed, while the
	// research call issues a dozen web searches and legitimately takes minutes. Without an
	// override the shared timeout has to be raised to suit the slowest source, which stops
	// it doing its job for all the others.
	sourceTimeouts map[string]time.Duration
}

// Option configures an Assessor.
type Option func(*Assessor)

// WithSourceTimeout gives one source its own deadline.
func WithSourceTimeout(name string, d time.Duration) Option {
	return func(a *Assessor) {
		if d <= 0 {
			return
		}
		if a.sourceTimeouts == nil {
			a.sourceTimeouts = make(map[string]time.Duration)
		}
		a.sourceTimeouts[name] = d
	}
}

// New builds an Assessor. A non-positive timeout means no per-source deadline beyond
// whatever the caller's context carries.
func New(srcs []sources.Source, perSourceTimeout time.Duration, opts ...Option) *Assessor {
	a := &Assessor{sources: srcs, perSourceTimeout: perSourceTimeout}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// timeoutFor returns the deadline for one source.
func (a *Assessor) timeoutFor(name string) time.Duration {
	if d, ok := a.sourceTimeouts[name]; ok {
		return d
	}
	return a.perSourceTimeout
}

// Run executes every source and aggregates their sections.
//
// It returns a Report unconditionally. There is no error return: no individual source
// failure is a reason to withhold the sections that did succeed.
func (a *Assessor) Run(ctx context.Context, q sources.Query, ent sources.ResolvedEntity) *Report {
	report := &Report{
		Query:    q,
		Entity:   ent,
		Sections: make([]sources.Section, 0, len(a.sources)),
		Cached:   make(map[string]bool, len(a.sources)),
	}

	report.Sections = orderSections(a.fanOut(ctx, q, ent))

	// Folded from the sections rather than written during the fan-out: a map shared across
	// concurrent sources would be a data race, and the flag is a property of the section
	// anyway (spec §11).
	for _, s := range report.Sections {
		if s.Cached {
			report.Cached[s.Source] = true
		}
	}
	return report
}

// fanOut runs every source concurrently and collects their sections.
//
// # Why a buffered channel, and why the collector may walk away
//
// The buffer holds one result per source, so a send never blocks. That matters because the
// collector stops waiting when the budget expires: a source still running afterwards will
// eventually send, and on an unbuffered channel that send would block forever and leak the
// goroutine permanently. Buffered, the value lands unread and the goroutine exits.
//
// Walking away is the only defence against a source that ignores its context. A per-source
// context.WithTimeout cannot interrupt code that never checks Done — it can only be
// abandoned. Waiting for every goroutine would let one such source hold the whole report
// hostage, which spec §2.6 forbids.
//
// No errgroup, here or anywhere in this package: it would cancel every sibling the moment
// one source errored.
func (a *Assessor) fanOut(ctx context.Context, q sources.Query, ent sources.ResolvedEntity) []result {
	results := make([]result, 0, len(a.sources))
	reported := make(map[int]bool, len(a.sources))

	// No budget at all. Report every source without calling out: work started against a
	// dead context can only fail, and firing off requests nobody will wait for is worse
	// than not making them.
	if err := ctx.Err(); err != nil {
		return a.expireOutstanding(results, reported, err)
	}

	pending := make(chan result, len(a.sources))
	for i, src := range a.sources {
		go func() {
			// runOne contains its own panics, so a goroutine cannot take the process down.
			pending <- result{index: i, section: a.runOne(ctx, src, q, ent)}
		}()
	}

	for range a.sources {
		select {
		case r := <-pending:
			reported[r.index] = true
			results = append(results, r)

		case <-ctx.Done():
			// Collect anything already delivered before writing the rest off. A result
			// sitting in the buffer is a real answer, and select picks freely among ready
			// cases — discarding it for a timing coincidence would make the report depend
			// on which case the runtime happened to choose.
		drain:
			for {
				select {
				case r := <-pending:
					reported[r.index] = true
					results = append(results, r)
				default:
					break drain
				}
			}
			return a.expireOutstanding(results, reported, ctx.Err())
		}
	}
	return results
}

// expireOutstanding records a section for every source that has not reported.
func (a *Assessor) expireOutstanding(results []result, reported map[int]bool, err error) []result {
	for i, src := range a.sources {
		if !reported[i] {
			results = append(results, result{index: i, section: expired(src.Name(), err)})
		}
	}
	return results
}

// expired builds the section for a source that never reported inside the budget.
//
// It is a failure, not a skip. StatusSkipped means there was nothing to query — a claim
// about the vendor. This is a claim about the run, and the two must not look alike.
func expired(name string, err error) sources.Section {
	return sources.Failed(name, fmt.Errorf(
		"no result before the assessment budget expired: %w", err))
}

// result pairs a section with the registration index of the source that produced it.
//
// The index is carried rather than inferred from position. Sources not named in
// SectionOrder fall back to registration order, and once the fan-out is concurrent the
// order results arrive in is whatever the network decides — so position stops meaning
// registration and the report's tail silently reshuffles between runs.
type result struct {
	index   int
	section sources.Section
}

// runOne executes a single source under its own timeout and converts any outcome into a
// Section. A panicking source is contained here rather than taking down the assessment.
func (a *Assessor) runOne(
	ctx context.Context,
	src sources.Source,
	q sources.Query,
	ent sources.ResolvedEntity,
) (section sources.Section) {
	name := src.Name()

	defer func() {
		if r := recover(); r != nil {
			// A panic in one source must not lose the rest of the report. This is a
			// containment boundary, not the request path CLAUDE.md forbids panicking on.
			section = sources.Failed(name, fmt.Errorf("source panicked: %v", r))
		}
	}()

	srcCtx := ctx
	if timeout := a.timeoutFor(name); timeout > 0 {
		var cancel context.CancelFunc
		srcCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	section, err := src.Fetch(srcCtx, q, ent)
	if err != nil && section.Status != sources.StatusFailed {
		// A source that returned an error without marking its own section is a bug in
		// that source; record it as failed rather than trusting the section.
		section = sources.Failed(name, err)
	}
	if section.Source == "" {
		section.Source = name
	}
	return section
}

// orderSections arranges results into SectionOrder. Unknown sources follow the known ones
// in registration order, so adding a source cannot reshuffle the report.
//
// Results may arrive in any order; only the carried index decides where an unknown source
// lands.
func orderSections(results []result) []sources.Section {
	known := make(map[string]bool, len(SectionOrder))
	for _, name := range SectionOrder {
		known[name] = true
	}

	ordered := make([]sources.Section, 0, len(results))

	byIndex := slices.SortedFunc(slices.Values(results), func(a, b result) int {
		return a.index - b.index
	})

	// Named sources first, in the documented reading order. Two sources sharing a name keep
	// their registration order relative to each other.
	for _, name := range SectionOrder {
		for _, r := range byIndex {
			if r.section.Source == name {
				ordered = append(ordered, r.section)
			}
		}
	}
	for _, r := range byIndex {
		if !known[r.section.Source] {
			ordered = append(ordered, r.section)
		}
	}
	return ordered
}
