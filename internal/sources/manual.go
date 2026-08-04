package sources

import (
	"context"
	"fmt"
	"time"
)

// ManualLookup reads a recorded entry. It is the store's read path, narrowed to the one
// method a manual source needs, so the source can be tested against a fake (spec §14).
//
// The boolean reports whether an entry exists. Absence is an ordinary outcome, not an
// error: it is how a manual source knows to render its instruction instead of a value.
type ManualLookup interface {
	ManualEntry(ctx context.Context, company, service, source string) (ManualEntry, bool, error)
}

// ManualResult is the rendered form of a recorded entry.
type ManualResult struct {
	Value       string
	RecordedAt  time.Time
	Instruction string
	URL         string
}

// ManualSource is a checklist category an analyst fills in out of band (spec §7).
//
// It never makes a network call. Every field comes from config, so the three current manual
// sources are three config entries rather than three bespoke types — and adding a fourth
// stays a config entry, not code.
//
// The categories here are not stubs awaiting an HTTP client. SSL Labs requires registration
// and runs scans too slowly for a request cycle, Open Bug Bounty publishes only an
// unofficial XML endpoint, and CVE Details is paywalled with no reachable API reference.
// Do not automate any of them.
type ManualSource struct {
	name        string
	instruction string
	url         string
	lookup      ManualLookup
}

// NewManual builds a manual source from its config entry. A nil lookup is allowed: the
// source then always reports the gap, which is the honest rendering when there is no store
// to have recorded anything in.
func NewManual(name, instruction, url string, lookup ManualLookup) *ManualSource {
	return &ManualSource{name: name, instruction: instruction, url: url, lookup: lookup}
}

func (m *ManualSource) Name() string { return m.name }

// Fetch reads any recorded entry. With no entry it returns StatusSkipped carrying the
// instruction and URL, so the report shows the gap and tells the analyst how to close it.
//
// Skipped here is the expected steady state, not a failure: most assessments have no
// recorded entry for most manual sources, and rendering that as an error would bury the
// genuine failures.
func (m *ManualSource) Fetch(ctx context.Context, q Query, _ ResolvedEntity) (Section, error) {
	if m.lookup == nil {
		return Skipped(m.name, m.gap()), nil
	}

	entry, found, err := m.lookup.ManualEntry(ctx, q.Company, q.Service, m.name)
	if err != nil {
		// A store failure is not "no entry recorded". Reporting it as skipped would tell the
		// analyst to go and check something they may already have checked.
		return Failed(m.name, fmt.Errorf("read recorded entry: %w", err)), err
	}
	if !found {
		return Skipped(m.name, m.gap()), nil
	}

	return OK(m.name, ManualResult{
		Value:       entry.Value,
		RecordedAt:  entry.RecordedAt,
		Instruction: m.instruction,
		URL:         m.url,
	}), nil
}

// gap is the note shown when nothing has been recorded: what to check, and where.
func (m *ManualSource) gap() string {
	switch {
	case m.instruction != "" && m.url != "":
		return fmt.Sprintf("no entry recorded — %s (%s)", m.instruction, m.url)
	case m.instruction != "":
		return "no entry recorded — " + m.instruction
	case m.url != "":
		return "no entry recorded — see " + m.url
	default:
		return "no entry recorded"
	}
}
