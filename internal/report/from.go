package report

import (
	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/store"
)

// Presentation is the part of a report that depends on how it is being shown rather than on
// what was assessed: which config produced it, and what the reader asked for.
//
// Separate from assess.Result because the same assessment renders differently in a terminal
// and a browser, and neither difference is a fact about the vendor.
type Presentation struct {
	ConfigPath string
	Full       bool
	Color      bool
}

// FromResult assembles a renderable report from a finished assessment.
//
// It lives here rather than in each front-end so the two cannot drift: a field the CLI shows
// and the web UI forgets is a fact an analyst sees in one place and not the other, and the
// ones most likely to be forgotten — the cache markers, the dropped identifiers — are exactly
// the ones that change what the report means.
func FromResult(res assess.Result, r *assess.Runner, p Presentation) Report {
	cfg := r.Config()
	return Report{
		Query:            res.Report.Query,
		Entity:           res.Entity,
		Resolution:       res.Resolution,
		Sections:         res.Report.Sections,
		CacheKey:         [2]string{store.NormalizeKey(res.Report.Query.Company), store.NormalizeKey(res.Report.Query.Service)},
		DomainOverridden: res.DomainOverridden,
		CPEsOverridden:   res.CPEsOverridden,
		ResolutionCached: res.ResolutionCached,
		NoCache:          res.NoCache,
		ConfigPath:       p.ConfigPath,
		ResolutionModel:  cfg.Models.Resolution,
		ResearchModel:    cfg.Models.Research,
		AutomatedSources: cfg.EnabledSources(),
		ManualSources:    cfg.ManualNames(),
		NVDKeyPresent:    r.NVDKeyPresent(),
		Full:             p.Full,
		Color:            p.Color,
	}
}
