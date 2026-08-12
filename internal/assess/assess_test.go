package assess

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aalcar/vrm/internal/sources"
)

// fakeSource lets a test script one source's behaviour precisely.
type fakeSource struct {
	name   string
	delay  time.Duration
	err    error
	status sources.Status
	panics bool
	// cached marks the returned section as having come from the cache, the way the caching
	// source in internal/sources does.
	cached  bool
	started chan struct{}
	// blocks, when set, is waited on instead of any delay and is never released by the
	// source itself. It stands in for a source that ignores its context entirely.
	blocks chan struct{}

	// calls counts Fetch invocations. Atomic because the fan-out is concurrent.
	calls atomic.Int64
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Fetch(ctx context.Context, q sources.Query, ent sources.ResolvedEntity) (sources.Section, error) {
	f.calls.Add(1)
	if f.started != nil {
		close(f.started)
	}
	if f.blocks != nil {
		// Deliberately not selecting on ctx.Done(): this is the source that cannot be
		// interrupted, only abandoned.
		<-f.blocks
		return sources.OK(f.name, "value"), nil
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
	section := sources.OK(f.name, "value")
	section.Cached = f.cached
	return section, nil
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

// orderSections is tested directly because Run cannot yet produce out-of-order results —
// the loop is still sequential. Once it is concurrent, arrival order is whatever the
// network decides, and that is exactly the input this pins down.
func TestOrderSectionsIgnoresArrivalOrder(t *testing.T) {
	// Registered bitsight, experimental, nvd, other — arriving in reverse.
	results := []result{
		{index: 3, section: sources.Section{Source: "other"}},
		{index: 2, section: sources.Section{Source: "nvd"}},
		{index: 1, section: sources.Section{Source: "experimental"}},
		{index: 0, section: sources.Section{Source: "bitsight"}},
	}

	var got []string
	for _, s := range orderSections(results) {
		got = append(got, s.Source)
	}

	// Known sources take the documented reading order. The two unknown ones follow in
	// registration order — not arrival order, which here is the exact reverse.
	if want := "bitsight,nvd,experimental,other"; strings.Join(got, ",") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

func TestOrderSectionsIsDeterministic(t *testing.T) {
	// Shuffling the input must not change the output. Without a carried index this holds
	// only by accident, because slice position happens to equal registration order while
	// the loop is sequential.
	results := []result{
		{index: 0, section: sources.Section{Source: "alpha"}},
		{index: 1, section: sources.Section{Source: "caag"}},
		{index: 2, section: sources.Section{Source: "beta"}},
		{index: 3, section: sources.Section{Source: "bitsight"}},
	}
	const want = "bitsight,caag,alpha,beta"

	for _, shuffled := range [][]result{
		{results[0], results[1], results[2], results[3]},
		{results[3], results[2], results[1], results[0]},
		{results[2], results[0], results[3], results[1]},
	} {
		var got []string
		for _, s := range orderSections(shuffled) {
			got = append(got, s.Source)
		}
		if strings.Join(got, ",") != want {
			t.Errorf("order = %v, want %s", got, want)
		}
	}
}

func TestExpiredBudgetStillReportsEverySource(t *testing.T) {
	// An already-dead context is the degenerate case of running out of budget. Every source
	// still gets a section: one that is simply absent from the report is indistinguishable
	// from a category nobody needed to check.
	srcs := []*fakeSource{
		{name: "bitsight"}, {name: "nvd"}, {name: "caag"},
	}
	a := New([]sources.Source{srcs[0], srcs[1], srcs[2]}, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := a.Run(ctx, sources.Query{}, sources.ResolvedEntity{})

	if len(r.Sections) != 3 {
		t.Fatalf("got %d sections, want 3", len(r.Sections))
	}
	for _, s := range r.Sections {
		if s.Status != sources.StatusFailed {
			t.Errorf("%s status = %q, want failed", s.Source, s.Status)
		}
		// Failed, never skipped: skipped is a claim about the vendor ("nothing to query"),
		// this is a claim about the run.
		if !strings.Contains(s.Err, "budget expired") {
			t.Errorf("%s Err = %q, want it to name the expired budget", s.Source, s.Err)
		}
	}
	for _, src := range srcs {
		if n := src.calls.Load(); n != 0 {
			t.Errorf("%s was called %d times with no budget left", src.name, n)
		}
	}
}

func TestBudgetExpiryMarksOnlyTheOutstandingSource(t *testing.T) {
	// The per-source timeout is deliberately huge, so the assessment budget is the only
	// thing that can end this run.
	//
	// bitsight blocks forever and never checks its context — the source that cannot be
	// interrupted, only abandoned. Its siblings finish immediately and must keep their real
	// results: concurrency means a slow source no longer costs the fast ones their answers,
	// which is the whole point of the fan-out.
	blocked := make(chan struct{})
	defer close(blocked)

	a := New([]sources.Source{
		&fakeSource{name: "bitsight", blocks: blocked},
		&fakeSource{name: "nvd"},
		&fakeSource{name: "caag"},
	}, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	r := a.Run(ctx, sources.Query{}, sources.ResolvedEntity{})

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("run took %v — a source ignoring its context held the report hostage", elapsed)
	}
	if len(r.Sections) != 3 {
		t.Fatalf("got %d sections, want 3", len(r.Sections))
	}

	stuck := sectionFor(t, r, "bitsight")
	if stuck.Status != sources.StatusFailed {
		t.Errorf("blocked source status = %q, want failed", stuck.Status)
	}
	if !strings.Contains(stuck.Err, "budget expired") {
		t.Errorf("Err = %q, want it to name the expired budget", stuck.Err)
	}
	for _, name := range []string{"nvd", "caag"} {
		if got := sectionFor(t, r, name).Status; got != sources.StatusOK {
			t.Errorf("%s status = %q, want ok — it finished well inside the budget", name, got)
		}
	}
}

func TestSourcesRunConcurrently(t *testing.T) {
	// Four sources that each sleep well past the point where sequential execution would
	// blow the budget. Run has to come back in about one delay, not four.
	const delay = 200 * time.Millisecond
	a := New([]sources.Source{
		&fakeSource{name: "bitsight", delay: delay},
		&fakeSource{name: "nvd", delay: delay},
		&fakeSource{name: "osv", delay: delay},
		&fakeSource{name: "caag", delay: delay},
	}, time.Minute)

	start := time.Now()
	r := a.Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})
	elapsed := time.Since(start)

	// Generous bound: the point is to separate "concurrent" from "sequential" (800ms),
	// not to assert scheduling precision on a loaded CI box.
	if elapsed > 2*delay {
		t.Errorf("run took %v for 4 x %v of work — the sources ran sequentially", elapsed, delay)
	}
	for _, s := range r.Sections {
		if s.Status != sources.StatusOK {
			t.Errorf("%s status = %q, want ok", s.Source, s.Status)
		}
	}
}

func TestConcurrentRunKeepsSectionOrderStable(t *testing.T) {
	// Completion order is deliberately the reverse of reading order, and two of these are
	// not in SectionOrder at all. Repeated runs must produce the same report regardless.
	for range 20 {
		a := New([]sources.Source{
			&fakeSource{name: "zeta"},
			&fakeSource{name: "caag", delay: 2 * time.Millisecond},
			&fakeSource{name: "alpha"},
			&fakeSource{name: "bitsight", delay: 4 * time.Millisecond},
		}, time.Minute)

		r := a.Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})

		var got []string
		for _, s := range r.Sections {
			got = append(got, s.Source)
		}
		if want := "bitsight,caag,zeta,alpha"; strings.Join(got, ",") != want {
			t.Fatalf("order = %v, want %s", got, want)
		}
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

// TestReportCollectsTheCacheFlags checks the fold from sections into Report.Cached.
//
// The flag travels on each Section rather than being written to a shared map during the
// fan-out, which would be a data race. This test runs under -race with several sources
// reporting at once, so a regression to a shared map is caught here rather than
// intermittently in production.
func TestReportCollectsTheCacheFlags(t *testing.T) {
	srcs := []sources.Source{
		&fakeSource{name: "bitsight", cached: true},
		&fakeSource{name: "nvd"},
		&fakeSource{name: "caag", cached: true},
		&fakeSource{name: "osv", status: sources.StatusSkipped},
	}

	report := New(srcs, time.Second).Run(context.Background(), sources.Query{}, sources.ResolvedEntity{})

	want := map[string]bool{"bitsight": true, "caag": true}
	if !reflect.DeepEqual(report.Cached, want) {
		t.Errorf("Cached = %v, want %v", report.Cached, want)
	}

	// A section that was not cached must not appear at all. An entry set to false would read
	// as "we know this was live" in a map whose absence already means exactly that.
	if _, present := report.Cached["nvd"]; present {
		t.Error("a live section left an entry in Cached")
	}
}

// nvdSection builds an NVD section carrying one query with the given verification.
//
// The failed shape here — a Failed section that still carries its NVDResult — mirrors what
// nvd.go actually returns for an all-invented CPE set, and TestFetchNVDDistinguishesCleanFromInvented
// is what holds it to that. This fixture asserted the shape before the source produced it,
// and the gate below passed against a section the real source never returned.
func nvdSection(status sources.Status, v sources.NVDVerification) sources.Section {
	res := sources.NVDResult{Queries: []sources.NVDQuery{{
		CPE:          "cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*",
		Verification: v,
	}}}
	if status == sources.StatusFailed {
		s := sources.Failed(sources.SourceNVD, errNVDExample)
		s.Data = res
		return s
	}
	return sources.OK(sources.SourceNVD, res)
}

var errNVDExample = errors.New("none of the resolved CPEs exist in NVD's CPE dictionary")

func TestCPEsVerified(t *testing.T) {
	cases := []struct {
		name            string
		sections        []sources.Section
		verified, known bool
	}{
		{
			name:     "a CPE with CVEs is confirmed",
			sections: []sources.Section{nvdSection(sources.StatusOK, sources.NVDVerifiedByResults)},
			verified: true, known: true,
		},
		{
			// The whole point of the dictionary check: no CVEs but a real product.
			name:     "a clean CPE in the dictionary is confirmed",
			sections: []sources.Section{nvdSection(sources.StatusOK, sources.NVDVerifiedInDictionary)},
			verified: true, known: true,
		},
		{
			name:     "an invented CPE is a verdict, not an absence of one",
			sections: []sources.Section{nvdSection(sources.StatusFailed, sources.NVDUnverified)},
			verified: false, known: true,
		},
		{
			// A transport failure carries no NVDResult. It must not read as "invented".
			name:     "NVD failing before it could look is no verdict",
			sections: []sources.Section{sources.Failed(sources.SourceNVD, errNVDExample)},
			verified: false, known: false,
		},
		{
			name:     "NVD skipped is no verdict",
			sections: []sources.Section{sources.Skipped(sources.SourceNVD, "no CPEs resolved")},
			verified: false, known: false,
		},
		{
			name:     "NVD disabled is no verdict",
			sections: []sources.Section{sources.OK(sources.SourceBitSight, sources.BitSightRating{})},
			verified: false, known: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Sections: tc.sections}
			verified, known := r.CPEsVerified()
			if verified != tc.verified || known != tc.known {
				t.Errorf("CPEsVerified() = (%v, %v), want (%v, %v)",
					verified, known, tc.verified, tc.known)
			}
		})
	}
}
