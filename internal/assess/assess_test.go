package assess

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aalcar/vrm/internal/sources"
)

// fakeSource lets a test script one source's behaviour precisely.
type fakeSource struct {
	name    string
	delay   time.Duration
	err     error
	status  sources.Status
	panics  bool
	started chan struct{}
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Fetch(ctx context.Context, q sources.Query, ent sources.ResolvedEntity) (sources.Section, error) {
	if f.started != nil {
		close(f.started)
	}
	if f.panics {
		panic("boom")
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return sources.Failed(f.name, ctx.Err()), ctx.Err()
		}
	}
	if f.err != nil {
		return sources.Failed(f.name, f.err), f.err
	}
	if f.status == sources.StatusSkipped {
		return sources.Skipped(f.name, "nothing to query"), nil
	}
	return sources.OK(f.name, "value"), nil
}

func sectionFor(t *testing.T, r *Report, name string) sources.Section {
	t.Helper()
	for _, s := range r.Sections {
		if s.Source == name {
			return s
		}
	}
	t.Fatalf("no section for %q in report (%d sections)", name, len(r.Sections))
	return sources.Section{}
}

// The highest-value behaviour in the system: a report with a failed section is a success,
// an aborted assessment is a bug (spec §15).
func TestOneFailureDoesNotAffectSiblings(t *testing.T) {
	a := New([]sources.Source{
		&fakeSource{name: "nvd", err: errors.New("upstream exploded")},
		&fakeSource{name: "osv", status: sources.StatusSkipped},
		&fakeSource{name: "caag"},
	}, time.Second)

	r := a.Run(context.Background(), sources.Query{Company: "Okta"}, sources.ResolvedEntity{})

	if len(r.Sections) != 3 {
		t.Fatalf("got %d sections, want 3 — a failure lost its siblings", len(r.Sections))
	}
	if got := sectionFor(t, r, "nvd").Status; got != sources.StatusFailed {
		t.Errorf("nvd status = %q, want failed", got)
	}
	if got := sectionFor(t, r, "osv").Status; got != sources.StatusSkipped {
		t.Errorf("osv status = %q, want skipped", got)
	}
	if got := sectionFor(t, r, "caag").Status; got != sources.StatusOK {
		t.Errorf("caag status = %q, want ok", got)
	}
}

// A source that blocks past its deadline must not consume the whole run or stop the ones
// after it.
func TestTimeoutIsPerSourceNotGlobal(t *testing.T) {
	a := New([]sources.Source{
		&fakeSource{name: "nvd", delay: time.Hour},
		&fakeSource{name: "caag"},
	}, 50*time.Millisecond)

	start := time.Now()
	r := a.Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("run took %v — the per-source timeout did not apply", elapsed)
	}
	if got := sectionFor(t, r, "nvd").Status; got != sources.StatusFailed {
		t.Errorf("timed-out source status = %q, want failed", got)
	}
	if got := sectionFor(t, r, "caag").Status; got != sources.StatusOK {
		t.Errorf("source after the slow one = %q, want ok — it was blocked or cancelled", got)
	}
}

// A panicking source is contained rather than taking the report down with it.
func TestPanicIsContained(t *testing.T) {
	a := New([]sources.Source{
		&fakeSource{name: "nvd", panics: true},
		&fakeSource{name: "caag"},
	}, time.Second)

	r := a.Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})

	sec := sectionFor(t, r, "nvd")
	if sec.Status != sources.StatusFailed {
		t.Errorf("panicking source status = %q, want failed", sec.Status)
	}
	if !strings.Contains(sec.Err, "panicked") {
		t.Errorf("Err = %q, want it to say the source panicked", sec.Err)
	}
	if got := sectionFor(t, r, "caag").Status; got != sources.StatusOK {
		t.Errorf("source after the panic = %q, want ok", got)
	}
}

// Section order must be stable regardless of registration order (spec §10).
func TestSectionOrderIsStable(t *testing.T) {
	a := New([]sources.Source{
		&fakeSource{name: "caag"},
		&fakeSource{name: "bitsight"},
		&fakeSource{name: "nvd"},
	}, time.Second)

	r := a.Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})

	var got []string
	for _, s := range r.Sections {
		got = append(got, s.Source)
	}
	if want := "bitsight,nvd,caag"; strings.Join(got, ",") != want {
		t.Errorf("section order = %v, want %s", got, want)
	}
}

func TestUnknownSourcesAppendAfterKnownOnes(t *testing.T) {
	a := New([]sources.Source{
		&fakeSource{name: "experimental"},
		&fakeSource{name: "bitsight"},
	}, time.Second)

	r := a.Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})

	if r.Sections[0].Source != "bitsight" {
		t.Errorf("first section = %q, want bitsight", r.Sections[0].Source)
	}
	if r.Sections[1].Source != "experimental" {
		t.Errorf("second section = %q, want experimental", r.Sections[1].Source)
	}
}

func TestReportSurfacesQueryAndEntity(t *testing.T) {
	// A bad entity mapping has to be visible in the report (spec §15).
	q := sources.Query{Company: "Okta", Service: "SSO"}
	ent := sources.ResolvedEntity{CanonicalName: "Okta, Inc.", Domains: []string{"okta.com"}}

	r := New(nil, time.Second).Run(context.Background(), q, ent)

	if r.Query != q {
		t.Errorf("Query = %+v, want %+v", r.Query, q)
	}
	if r.Entity.CanonicalName != ent.CanonicalName || len(r.Entity.Domains) != 1 {
		t.Errorf("Entity = %+v, want %+v", r.Entity, ent)
	}
}
