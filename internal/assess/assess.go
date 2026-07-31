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
}

// New builds an Assessor. A non-positive timeout means no per-source deadline beyond
// whatever the caller's context carries.
func New(srcs []sources.Source, perSourceTimeout time.Duration) *Assessor {
	return &Assessor{sources: srcs, perSourceTimeout: perSourceTimeout}
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

	for _, src := range a.sources {
		report.Sections = append(report.Sections, a.runOne(ctx, src, q, ent))
	}

	sortSections(report.Sections)
	return report
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
	if a.perSourceTimeout > 0 {
		var cancel context.CancelFunc
		srcCtx, cancel = context.WithTimeout(ctx, a.perSourceTimeout)
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

// sortSections arranges sections into SectionOrder. Unknown sources keep their relative
// order and follow the known ones, so adding a source cannot reshuffle the report.
func sortSections(sections []sources.Section) {
	rank := make(map[string]int, len(SectionOrder))
	for i, name := range SectionOrder {
		rank[name] = i
	}

	ordered := make([]sources.Section, 0, len(sections))
	for _, name := range SectionOrder {
		for _, s := range sections {
			if s.Source == name {
				ordered = append(ordered, s)
			}
		}
	}
	for _, s := range sections {
		if _, known := rank[s.Source]; !known {
			ordered = append(ordered, s)
		}
	}
	copy(sections, ordered)
}
