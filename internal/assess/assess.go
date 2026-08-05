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
// Phase 1 runs sources sequentially; Phase 8 makes the loop concurrent. The isolation
// model is already correct, so that change adds goroutines rather than undoing anything.
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

	results := make([]result, 0, len(a.sources))
	for i, src := range a.sources {
		results = append(results, result{index: i, section: a.runOne(ctx, src, q, ent)})
	}

	report.Sections = orderSections(results)
	return report
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
