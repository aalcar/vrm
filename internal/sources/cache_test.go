package sources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCache is an in-memory SectionCache. Errors are injectable because the interesting
// behaviour here is what happens when the cache misbehaves, not when it works.
type fakeCache struct {
	mu     sync.Mutex
	rows   map[string]Section
	reads  int
	writes int
	// writeCtxErr is sampled during the write rather than kept for the test to inspect
	// afterwards: record cancels its context on the way out, so a context read later is
	// always cancelled and would prove nothing.
	writeCtxErr error

	readErr  error
	writeErr error
}

func newFakeCache() *fakeCache { return &fakeCache{rows: map[string]Section{}} }

func (f *fakeCache) key(company, service, source string) string {
	return company + "\x00" + service + "\x00" + source
}

func (f *fakeCache) CachedSection(
	_ context.Context, company, service, source string, _ time.Duration,
) (Section, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.readErr != nil {
		return Section{}, false, f.readErr
	}
	section, ok := f.rows[f.key(company, service, source)]
	return section, ok, nil
}

func (f *fakeCache) PutSection(
	ctx context.Context, company, service, source string, section Section,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	f.writeCtxErr = ctx.Err()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.rows[f.key(company, service, source)] = section
	return nil
}

// countingSource records how many times it was actually asked to do work.
type countingSource struct {
	name    string
	section Section
	err     error

	mu    sync.Mutex
	calls int
}

func (c *countingSource) Name() string { return c.name }

func (c *countingSource) Fetch(context.Context, Query, ResolvedEntity) (Section, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.section, c.err
}

func (c *countingSource) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func cacheTestQuery() Query { return Query{Company: "Okta", Service: "SSO"} }

func bitsightSection() Section {
	return OK(SourceBitSight, BitSightRating{
		CompanyName: "Okta, Inc.", PrimaryDomain: "okta.com", Rating: 780,
	})
}

// TestCacheHitDoesNotCallTheSource is the acceptance criterion in miniature: a repeat
// assessment inside the TTL does not make the call again.
func TestCacheHitDoesNotCallTheSource(t *testing.T) {
	cache := newFakeCache()
	inner := &countingSource{name: SourceBitSight, section: bitsightSection()}
	src := Caching(inner, cache, time.Hour)
	q := cacheTestQuery()

	first, err := src.Fetch(context.Background(), q, ResolvedEntity{})
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if first.Cached {
		t.Error("a freshly fetched section reported itself as cached")
	}

	second, err := src.Fetch(context.Background(), q, ResolvedEntity{})
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if n := inner.count(); n != 1 {
		t.Errorf("the source was called %d times, want 1", n)
	}
	if !second.Cached {
		t.Error("the second section did not report itself as cached")
	}
	if got, ok := second.Data.(BitSightRating); !ok || got.Rating != 780 {
		t.Errorf("cached Data is %#v", second.Data)
	}
}

// TestFailuresAndSkipsAreNotCached keeps a fact about the run from becoming a fact about the
// vendor. FedRAMP's TTL is 168h; a cached failure would outlive the outage that caused it,
// and a cached skip would outlive the resolution fix that was meant to clear it.
func TestFailuresAndSkipsAreNotCached(t *testing.T) {
	for _, section := range []Section{
		Failed(SourceFedRAMP, errors.New("the listing page layout has changed")),
		Skipped(SourceFedRAMP, "no domain resolved"),
	} {
		t.Run(string(section.Status), func(t *testing.T) {
			cache := newFakeCache()
			inner := &countingSource{name: SourceFedRAMP, section: section}
			src := Caching(inner, cache, time.Hour)

			if _, err := src.Fetch(context.Background(), cacheTestQuery(), ResolvedEntity{}); err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if cache.writes != 0 {
				t.Errorf("a %s section was written to the cache", section.Status)
			}

			// And it is still fetched live next time rather than served from anywhere.
			if _, err := src.Fetch(context.Background(), cacheTestQuery(), ResolvedEntity{}); err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if n := inner.count(); n != 2 {
				t.Errorf("the source was called %d times, want 2", n)
			}
		})
	}
}

// TestBypassSkipsTheReadButStillRecords pins both halves of --no-cache. Forcing a fresh call
// is the point; leaving yesterday's row behind afterwards is not.
func TestBypassSkipsTheReadButStillRecords(t *testing.T) {
	cache := newFakeCache()
	inner := &countingSource{name: SourceBitSight, section: bitsightSection()}
	q := cacheTestQuery()

	// Prime the cache through an ordinary caching source.
	if _, err := Caching(inner, cache, time.Hour).Fetch(context.Background(), q, ResolvedEntity{}); err != nil {
		t.Fatalf("priming Fetch: %v", err)
	}
	readsAfterPriming := cache.reads

	bypassing := Caching(inner, cache, time.Hour, WithCacheBypass(true))
	section, err := bypassing.Fetch(context.Background(), q, ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if cache.reads != readsAfterPriming {
		t.Error("--no-cache read the cache")
	}
	if section.Cached {
		t.Error("--no-cache returned a section marked cached")
	}
	if n := inner.count(); n != 2 {
		t.Errorf("the source was called %d times, want 2", n)
	}
	if cache.writes != 2 {
		t.Errorf("the cache was written %d times, want 2; --no-cache must refresh, not stop writing", cache.writes)
	}
}

// TestCacheReadErrorFallsBackToALiveFetch: a sick cache costs a slow answer, never no answer.
func TestCacheReadErrorFallsBackToALiveFetch(t *testing.T) {
	cache := newFakeCache()
	cache.readErr = errors.New("connection refused")
	inner := &countingSource{name: SourceBitSight, section: bitsightSection()}

	var warned []error
	src := Caching(inner, cache, time.Hour, WithCacheWarner(func(err error) {
		warned = append(warned, err)
	}))

	section, err := src.Fetch(context.Background(), cacheTestQuery(), ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if section.Status != StatusOK {
		t.Errorf("Status = %q, want ok", section.Status)
	}
	if inner.count() != 1 {
		t.Error("the source was not called after a cache read error")
	}
	// A cache that has quietly stopped working looks exactly like one that is working.
	if len(warned) == 0 {
		t.Fatal("a cache read error passed without a warning")
	}
	if !strings.Contains(warned[0].Error(), "could not read the cache") {
		t.Errorf("warning does not say what happened: %v", warned[0])
	}
}

// TestCacheWriteErrorDoesNotFailTheSection: the answer is already in hand.
func TestCacheWriteErrorDoesNotFailTheSection(t *testing.T) {
	cache := newFakeCache()
	cache.writeErr = errors.New("disk full")
	inner := &countingSource{name: SourceBitSight, section: bitsightSection()}

	var warned []error
	src := Caching(inner, cache, time.Hour, WithCacheWarner(func(err error) {
		warned = append(warned, err)
	}))

	section, err := src.Fetch(context.Background(), cacheTestQuery(), ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch returned an error for a failed cache write: %v", err)
	}
	if section.Status != StatusOK {
		t.Errorf("Status = %q, want ok", section.Status)
	}
	if len(warned) == 0 {
		t.Error("a cache write error passed without a warning")
	}
}

// TestRecordSurvivesAnExhaustedFetchContext is the bug this design exists to avoid.
//
// Research legitimately runs for most of its budget. If the write borrowed the fetch's
// context, the most expensive result in the tool would be the one least likely to be cached —
// exactly backwards.
func TestRecordSurvivesAnExhaustedFetchContext(t *testing.T) {
	cache := newFakeCache()
	inner := &countingSource{name: SourceResearch, section: OK(SourceResearch, Research{
		SupplierDescription: Finding{Value: "an identity provider"},
	})}
	src := Caching(inner, cache, time.Hour)

	// The deadline the source ran under is already gone by the time it returns.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := src.Fetch(ctx, cacheTestQuery(), ResolvedEntity{}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cache.writes != 1 {
		t.Fatalf("the cache was written %d times, want 1", cache.writes)
	}
	if cache.writeCtxErr != nil {
		t.Errorf("the write ran on a dead context: %v", cache.writeCtxErr)
	}
}

// TestCachingIsANoOpWhenThereIsNothingToCacheWith keeps "not cached" indistinguishable from
// an unwrapped source, rather than half-wrapping one.
func TestCachingIsANoOpWhenThereIsNothingToCacheWith(t *testing.T) {
	inner := &countingSource{name: SourceBitSight, section: bitsightSection()}
	cache := newFakeCache()

	cases := map[string]Source{
		"no cache":     Caching(inner, nil, time.Hour),
		"no ttl":       Caching(inner, cache, 0),
		"negative ttl": Caching(inner, cache, -time.Hour),
		// Manual sources are analyst data read fresh every run (spec §7), so there is no
		// codec for one and nothing here to wrap.
		"manual source": Caching(&countingSource{name: "ssllabs"}, cache, time.Hour),
	}

	for name, got := range cases {
		t.Run(name, func(t *testing.T) {
			if _, wrapped := got.(*cachedSource); wrapped {
				t.Error("the source was wrapped in a cache that cannot work")
			}
		})
	}
}

// TestTheCachedFlagIsNeverPersisted stops a stored true from making every later read claim to
// be a cache hit of itself.
func TestTheCachedFlagIsNeverPersisted(t *testing.T) {
	section := bitsightSection()
	section.Cached = true

	raw, err := EncodeSection(section)
	if err != nil {
		t.Fatalf("EncodeSection: %v", err)
	}
	got, err := DecodeSection(SourceBitSight, raw)
	if err != nil {
		t.Fatalf("DecodeSection: %v", err)
	}
	if got.Cached {
		t.Error("Cached survived the round trip; it describes the run, not the vendor")
	}
}
