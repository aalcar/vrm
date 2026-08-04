package sources

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeLookup stands in for the store. Manual sources are pure enough that a fake covers
// every branch; the real store's behaviour is covered by its own tests.
type fakeLookup struct {
	entry ManualEntry
	found bool
	err   error

	gotCompany, gotService, gotSource string
}

func (f *fakeLookup) ManualEntry(_ context.Context, company, service, source string) (ManualEntry, bool, error) {
	f.gotCompany, f.gotService, f.gotSource = company, service, source
	return f.entry, f.found, f.err
}

var manualQuery = Query{Company: "Okta", Service: "SSO"}

func TestManualSourceSkipsWithInstructionAndURL(t *testing.T) {
	src := NewManual("ssllabs", "Scan the service hostname; record the grade",
		"https://www.ssllabs.com/ssltest", &fakeLookup{})

	section, err := src.Fetch(context.Background(), manualQuery, ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Skipped is the expected steady state for a manual source, not a failure. Rendering it
	// as one would bury the genuine failures.
	if section.Status != StatusSkipped {
		t.Errorf("Status = %q, want %q", section.Status, StatusSkipped)
	}
	// The note is the whole point of the section: it has to tell the analyst what to check
	// and where, or the category is just a blank line in the report.
	for _, want := range []string{"Scan the service hostname", "https://www.ssllabs.com/ssltest"} {
		if !strings.Contains(section.Note, want) {
			t.Errorf("Note = %q, want it to contain %q", section.Note, want)
		}
	}
	if section.Err != "" {
		t.Errorf("Err = %q, want empty on a skip", section.Err)
	}
}

func TestManualSourceRendersRecordedValueVerbatim(t *testing.T) {
	recorded := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	// Free text, stored verbatim: no parsing, no validation, no interpretation (spec §7).
	const value = `A+ (0 open / 3 fixed); see ticket #4471 — "renewed 2026-07-30"`

	lookup := &fakeLookup{entry: ManualEntry{Value: value, RecordedAt: recorded}, found: true}
	src := NewManual("ssllabs", "Scan the service hostname", "https://www.ssllabs.com/ssltest", lookup)

	section, err := src.Fetch(context.Background(), manualQuery, ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if section.Status != StatusOK {
		t.Fatalf("Status = %q, want %q", section.Status, StatusOK)
	}

	result, ok := section.Data.(ManualResult)
	if !ok {
		t.Fatalf("Data is %T, want ManualResult — Section.Data is never a map", section.Data)
	}
	if result.Value != value {
		t.Errorf("Value = %q, want it byte-for-byte: %q", result.Value, value)
	}
	if !result.RecordedAt.Equal(recorded) {
		t.Errorf("RecordedAt = %v, want %v", result.RecordedAt, recorded)
	}

	// The query reaches the store unmangled; normalization is the store's job and is tested
	// there, so a second normalization here would be a silent double-transform.
	if lookup.gotCompany != "Okta" || lookup.gotService != "SSO" || lookup.gotSource != "ssllabs" {
		t.Errorf("lookup got (%q, %q, %q), want (Okta, SSO, ssllabs)",
			lookup.gotCompany, lookup.gotService, lookup.gotSource)
	}
}

func TestManualSourceFailsLoudlyOnStoreError(t *testing.T) {
	lookup := &fakeLookup{err: errors.New("connection refused")}
	src := NewManual("ssllabs", "Scan the service hostname", "https://www.ssllabs.com/ssltest", lookup)

	section, err := src.Fetch(context.Background(), manualQuery, ResolvedEntity{})
	if err == nil {
		t.Error("Fetch returned no error for a store failure")
	}
	// "The store is down" and "the analyst has not recorded anything" are different claims.
	// Reporting the first as skipped would tell an analyst to go and check something they
	// may already have checked.
	if section.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", section.Status, StatusFailed)
	}
	if !strings.Contains(section.Err, "connection refused") {
		t.Errorf("Err = %q, want it to name the underlying failure", section.Err)
	}
}

func TestManualSourceWithoutAStoreReportsTheGap(t *testing.T) {
	// A nil lookup means nothing could have been recorded, so the honest rendering is the
	// gap — not a failure, and not a silent empty section.
	src := NewManual("openbugbounty", "Search the vendor domain", "https://www.openbugbounty.org", nil)

	section, err := src.Fetch(context.Background(), manualQuery, ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if section.Status != StatusSkipped {
		t.Errorf("Status = %q, want %q", section.Status, StatusSkipped)
	}
	if !strings.Contains(section.Note, "https://www.openbugbounty.org") {
		t.Errorf("Note = %q, want it to carry the URL", section.Note)
	}
}

func TestManualSourceNeverCallsOut(t *testing.T) {
	// A manual source that made a network call would be an automated source with extra
	// steps, and all three current categories are manual by deliberate design (spec §7).
	// A cancelled context proves the point: anything doing I/O would return its error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := NewManual("cvedetails", "Search the vendor", "https://www.cvedetails.com",
		&fakeLookup{entry: ManualEntry{Value: "12 CVEs"}, found: true})

	section, err := src.Fetch(ctx, manualQuery, ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch on a cancelled context: %v", err)
	}
	if section.Status != StatusOK {
		t.Errorf("Status = %q, want %q", section.Status, StatusOK)
	}
}
