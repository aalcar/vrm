// Package sources defines the common contract every data provider implements, and the
// normalized Section each one contributes to a report.
//
// # The Fetch contract
//
// Fetch always returns a usable Section. Its error return is informational — for the
// caller's logs — and the orchestrator records the Section either way. One source failing
// must never abort the assessment or its siblings (spec §2.6), so callers must not treat a
// non-nil error as a reason to stop.
//
// # Skipped is not a failure
//
// StatusSkipped is a first-class, expected outcome (spec §15): no usable input in the
// ResolvedEntity, an absent optional credential, or a manual source with no recorded
// entry. Most vendors legitimately skip OSV. Skipped must never be rendered as, or
// converted into, a failure.
package sources

import "context"

// Query is the analyst's request: a company and the specific service being assessed.
type Query struct {
	Company string
	Service string
}

// ResolvedEntity is the output of LLM entity resolution — the bridge between a
// human-friendly query and the identifiers the deterministic sources need.
//
// It is surfaced in the report on purpose: entity resolution is the weakest link in the
// system, and a wrong CPE silently yields another vendor's CVEs (spec §15).
type ResolvedEntity struct {
	CanonicalName string
	Domains       []string // BitSight
	CPEs          []string // CPE 2.3 strings, for NVD
	Packages      []string // OSS package names + ecosystem, for OSV (often empty)
	Aliases       []string // subsidiaries / former names
}

// Status is the outcome of one source's contribution.
type Status string

const (
	StatusOK     Status = "ok"
	StatusFailed Status = "failed" // the source errored — show the error
	// StatusSkipped means nothing to query, a credential was absent, or a manual source
	// has no recorded entry. It is an expected outcome, not a failure.
	StatusSkipped Status = "skipped"
)

// Citation is a source an analyst can click through and verify.
type Citation struct {
	Title string
	URL   string
}

// Section is one source's normalized contribution to the report.
type Section struct {
	Source string
	Status Status
	// Data is a concrete per-source struct, never a map, so the renderer and any future
	// consumer see a typed shape rather than an untyped bag.
	Data      any
	Citations []Citation
	Note      string // why skipped, or the manual-check instruction + URL
	Err       string // set when Status == StatusFailed
}

// Source is one data provider. Implementations must be safe for concurrent use and must
// respect ctx cancellation and timeouts.
type Source interface {
	Name() string
	Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error)
}

// OK builds a successful Section.
func OK(name string, data any, citations ...Citation) Section {
	return Section{
		Source:    name,
		Status:    StatusOK,
		Data:      data,
		Citations: citations,
	}
}

// Skipped builds a Section for a source that had nothing to do. The note explains why, so
// the report can distinguish "not applicable to this vendor" from "we failed to look".
func Skipped(name, note string) Section {
	return Section{
		Source: name,
		Status: StatusSkipped,
		Note:   note,
	}
}

// Failed builds a Section for a source that errored. Data is left nil: a failed source has
// no trustworthy value, and returning a partial one is how silently-wrong data reaches an
// analyst.
//
// Callers are responsible for ensuring err carries no credentials — it is rendered.
func Failed(name string, err error) Section {
	s := Section{
		Source: name,
		Status: StatusFailed,
	}
	if err != nil {
		s.Err = err.Error()
	}
	return s
}
