package report

import (
	"testing"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/config"
	"github.com/aalcar/vrm/internal/sources"
)

// TestFromResultToleratesAnUnfinishedAssessment pins a real panic.
//
// The streaming front-end renders the resolved entity from the OnResolved callback, where the
// assessment has resolved but not yet run — so Result.Report is nil. A first pass read
// Result.Report.Query here and took down the assessment it was describing, on the very first
// live request, in a handler that had already sent 200 and could not report it.
func TestFromResultToleratesAnUnfinishedAssessment(t *testing.T) {
	cfg := &config.Config{
		Models:        config.Models{Resolution: "m", Research: "m"},
		Sources:       map[string]bool{},
		ManualSources: []config.ManualSource{{Name: "ssllabs"}},
	}
	runner := assess.NewRunner(cfg, &config.Secrets{}, nil)

	interim := assess.Result{
		Query:      sources.Query{Company: "Okta", Service: "SSO"},
		Entity:     sources.ResolvedEntity{CanonicalName: "Okta, Inc."},
		Resolution: sources.Resolution{CPEOrigin: "chosen from NVD's dictionary"},
		// Report is nil: the fan-out has not run.
	}

	got := FromResult(interim, runner, Presentation{ConfigPath: "config.yaml"})

	if got.Query.Company != "Okta" {
		t.Errorf("Query.Company = %q; it must come from the Result, not from a nil Report",
			got.Query.Company)
	}
	if got.CacheKey != [2]string{"okta", "sso"} {
		t.Errorf("CacheKey = %v", got.CacheKey)
	}
	if len(got.Sections) != 0 {
		t.Errorf("an unfinished assessment produced %d sections", len(got.Sections))
	}
	// And it renders: the entity block is what the stream sends at this point.
	if len(got.Rows()) != 0 {
		t.Error("Rows() invented a row for an assessment with no sections")
	}
	if s := got.Summarize(); s.Total != 0 {
		t.Errorf("Summarize().Total = %d, want 0", s.Total)
	}
}
