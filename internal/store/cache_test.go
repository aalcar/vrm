package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aalcar/vrm/internal/sources"
)

// cachedFixture is a section with something in every field that has to survive the trip.
func cachedFixture() sources.Section {
	return sources.OK(sources.SourceBitSight, sources.BitSightRating{
		CompanyName:    "Okta, Inc.",
		PrimaryDomain:  "okta.com",
		Rating:         780,
		RatingRange:    "Advanced",
		RatingDate:     "2026-08-01",
		IndustryMedian: "above",
		QueriedDomain:  "okta.com",
		Alternatives:   []string{"Auth0"},
	}, sources.Citation{Title: "BitSight", URL: "https://service.bitsighttech.com/"})
}

// backdate moves a row's fetched_at into the past, so TTL expiry can be tested at the
// boundary instead of by sleeping through it.
func backdate(t *testing.T, st *Store, company, service, source string, age time.Duration) {
	t.Helper()
	tag, err := st.pool.Exec(context.Background(),
		`UPDATE assessments_cache SET fetched_at = now() - make_interval(secs => $4)
		 WHERE company = $1 AND service = $2 AND source = $3`,
		NormalizeKey(company), NormalizeKey(service), source, age.Seconds())
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("backdate touched %d rows, want 1", tag.RowsAffected())
	}
}

func TestCachedSectionRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)
	want := cachedFixture()

	if err := st.PutSection(ctx, company, service, sources.SourceBitSight, want); err != nil {
		t.Fatalf("PutSection: %v", err)
	}

	got, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, time.Hour)
	if err != nil {
		t.Fatalf("CachedSection: %v", err)
	}
	if !hit {
		t.Fatal("a section written a moment ago did not come back")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the section\n got: %#v\nwant: %#v", got, want)
	}
	// The whole point of the codec: what comes out of Postgres is the concrete type the
	// renderer selects on, not a map.
	if _, ok := got.Data.(sources.BitSightRating); !ok {
		t.Errorf("Data is %T, want sources.BitSightRating", got.Data)
	}
}

// TestCachedSectionExpiresAtTheTTLBoundary checks both sides of the comparison. A test that
// only proved expiry would pass against a store that never returned anything.
func TestCachedSectionExpiresAtTheTTLBoundary(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	if err := st.PutSection(ctx, company, service, sources.SourceBitSight, cachedFixture()); err != nil {
		t.Fatalf("PutSection: %v", err)
	}
	backdate(t, st, company, service, sources.SourceBitSight, 2*time.Hour)

	if _, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, time.Hour); err != nil {
		t.Fatalf("CachedSection: %v", err)
	} else if hit {
		t.Error("a two-hour-old row was served under a one-hour TTL")
	}

	if _, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, 3*time.Hour); err != nil {
		t.Fatalf("CachedSection: %v", err)
	} else if !hit {
		t.Error("a two-hour-old row was not served under a three-hour TTL")
	}
}

// TestCachedSectionWithoutATTLIsAlwaysAMiss pins the non-positive case. Reading a missing
// config line as "never expires" would turn an omission into a permanent cache.
func TestCachedSectionWithoutATTLIsAlwaysAMiss(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	if err := st.PutSection(ctx, company, service, sources.SourceBitSight, cachedFixture()); err != nil {
		t.Fatalf("PutSection: %v", err)
	}

	for _, ttl := range []time.Duration{0, -time.Hour} {
		if _, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, ttl); err != nil {
			t.Fatalf("CachedSection(%v): %v", ttl, err)
		} else if hit {
			t.Errorf("a TTL of %v produced a cache hit", ttl)
		}
	}
}

func TestCachedSectionMissesWhenNothingWasStored(t *testing.T) {
	st := testStore(t)
	company, service := uniqueQuery(t, st)

	_, hit, err := st.CachedSection(context.Background(), company, service, sources.SourceNVD, time.Hour)
	if err != nil {
		t.Fatalf("CachedSection: %v", err)
	}
	if hit {
		t.Error("reported a hit for a key nothing was written to")
	}
}

// TestCachedSectionIgnoresManualRows is the discriminator test.
//
// Both populations share this table and their payloads have different shapes. Reading a
// manual row as a cached section would fail to decode at best, and at worst hand an analyst's
// free text to a renderer expecting a rating.
func TestCachedSectionIgnoresManualRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	// Deliberately recorded against an automated source name. Config keeps the two name
	// spaces apart, so this cannot happen through the CLI — which is exactly why the
	// separation needs testing here rather than being assumed.
	if err := st.SetManual(ctx, company, service, sources.SourceBitSight, "analyst note"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}

	_, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, time.Hour)
	if err != nil {
		t.Fatalf("CachedSection returned an error rather than a miss: %v", err)
	}
	if hit {
		t.Error("served an analyst's manual entry as a cached section")
	}
}

// TestPutSectionRefusesToOverwriteAManualEntry guards the one kind of data here that cannot
// be re-fetched.
func TestPutSectionRefusesToOverwriteAManualEntry(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	if err := st.SetManual(ctx, company, service, sources.SourceBitSight, "A+"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}

	err := st.PutSection(ctx, company, service, sources.SourceBitSight, cachedFixture())
	if err == nil {
		t.Fatal("an automated write landed on a manual row without complaint")
	}
	if !strings.Contains(err.Error(), "manual entry") {
		t.Errorf("error does not say why: %v", err)
	}

	entry, found, err := st.ManualEntry(ctx, company, service, sources.SourceBitSight)
	if err != nil || !found {
		t.Fatalf("manual entry did not survive: found %v, err %v", found, err)
	}
	if entry.Value != "A+" {
		t.Errorf("Value = %q, want %q", entry.Value, "A+")
	}
}

// TestPutSectionRejectsAnUncacheableSource stops a row being written that no reader can turn
// back into a section.
func TestPutSectionRejectsAnUncacheableSource(t *testing.T) {
	st := testStore(t)
	company, service := uniqueQuery(t, st)

	err := st.PutSection(context.Background(), company, service, "ssllabs",
		sources.OK("ssllabs", sources.ManualResult{Value: "A+"}))
	if err == nil {
		t.Fatal("wrote a section for a source with no codec")
	}
}

// TestCachedSectionReportsAnUnreadableRow keeps a schema change loud. Treating a row that
// will not decode as an ordinary miss would hide it behind nothing worse than a slow run.
func TestCachedSectionReportsAnUnreadableRow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	_, err := st.pool.Exec(ctx,
		`INSERT INTO assessments_cache (company, service, source, section, manual)
		 VALUES ($1, $2, $3, $4, false)`,
		NormalizeKey(company), NormalizeKey(service), sources.SourceBitSight,
		[]byte(`{"source":"bitsight","status":"ok","data":"not an object"}`))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	if _, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, time.Hour); err == nil {
		t.Errorf("an undecodable row reported hit=%v with no error", hit)
	}
}

// TestCachedSectionNormalizesTheKey keeps the cache from fragmenting into near-duplicate rows
// that never hit — which would look exactly like a cache that is simply not working.
func TestCachedSectionNormalizesTheKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	if err := st.PutSection(ctx, "  "+strings.ToUpper(company)+" ", service,
		sources.SourceBitSight, cachedFixture()); err != nil {
		t.Fatalf("PutSection: %v", err)
	}

	_, hit, err := st.CachedSection(ctx, company, service, sources.SourceBitSight, time.Hour)
	if err != nil {
		t.Fatalf("CachedSection: %v", err)
	}
	if !hit {
		t.Error("a section written under a differently-spaced name did not come back")
	}
}
