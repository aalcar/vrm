package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// devDSN matches docker-compose.yml. These credentials are dev-only and already committed
// there, so naming them here leaks nothing — it just means the manual-entry tests run
// against a `docker compose up -d` database without any environment setup.
const devDSN = "postgres://vrm:vrm@localhost:5433/vrm?sslmode=disable"

// testStore opens the development database, or skips the test when none is reachable.
//
// These tests need real Postgres: the behaviour under test is an upsert and a partial-index
// predicate, and a fake would only assert that the fake works. Skipping keeps
// `go test -race ./...` green on a machine with no Docker running, which is the default
// test command for this project.
func testStore(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = devDSN
	}

	ctx := context.Background()
	st, err := New(ctx, dsn)
	if err != nil {
		t.Skipf("no test database reachable (%v); start one with `docker compose up -d`", err)
	}
	t.Cleanup(st.Close)

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// uniqueQuery returns a company/service pair no other test run shares, so a failure cannot
// be caused by leftovers and a leftover cannot outlive the test.
func uniqueQuery(t *testing.T, st *Store) (company, service string) {
	t.Helper()
	company = fmt.Sprintf("vrm store test %d", time.Now().UnixNano())
	service = "manual entry"

	t.Cleanup(func() {
		_, err := st.pool.Exec(context.Background(),
			`DELETE FROM assessments_cache WHERE company = $1`, NormalizeKey(company))
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return company, service
}

func TestManualEntryRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	// Absent is an ordinary outcome, not an error: it is how a manual source knows to show
	// its instruction rather than a value.
	if _, found, err := st.ManualEntry(ctx, company, service, "ssllabs"); err != nil || found {
		t.Fatalf("ManualEntry before write = found %v, err %v; want false, nil", found, err)
	}

	before := time.Now().Add(-time.Second)
	if err := st.SetManual(ctx, company, service, "ssllabs", "A+"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}

	entry, found, err := st.ManualEntry(ctx, company, service, "ssllabs")
	if err != nil {
		t.Fatalf("ManualEntry: %v", err)
	}
	if !found {
		t.Fatal("ManualEntry did not find the row just written")
	}
	if entry.Value != "A+" {
		t.Errorf("Value = %q, want %q", entry.Value, "A+")
	}
	if entry.RecordedAt.Before(before) {
		t.Errorf("RecordedAt = %v, want at or after %v", entry.RecordedAt, before)
	}

	// Sources share a key space; recording one must not answer for another.
	if _, found, err := st.ManualEntry(ctx, company, service, "openbugbounty"); err != nil || found {
		t.Errorf("openbugbounty = found %v, err %v; want false, nil", found, err)
	}
}

func TestSetManualOverwrites(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	// Re-running vrm set is how an analyst corrects a recorded answer, so the second write
	// must replace the first rather than conflict or duplicate.
	if err := st.SetManual(ctx, company, service, "ssllabs", "B"); err != nil {
		t.Fatalf("first SetManual: %v", err)
	}
	if err := st.SetManual(ctx, company, service, "ssllabs", "A+"); err != nil {
		t.Fatalf("second SetManual: %v", err)
	}

	entry, found, err := st.ManualEntry(ctx, company, service, "ssllabs")
	if err != nil || !found {
		t.Fatalf("ManualEntry = found %v, err %v", found, err)
	}
	if entry.Value != "A+" {
		t.Errorf("Value = %q, want the corrected %q", entry.Value, "A+")
	}
}

func TestSetManualMarksTheRowManual(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	if err := st.SetManual(ctx, company, service, "cvedetails", "12 CVEs, 2 critical"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}

	// The manual column is what keeps TTL sweeps and --no-cache off analyst data (spec §7).
	// If it were ever written false, the entry would silently become expirable.
	var manual bool
	err := st.pool.QueryRow(ctx,
		`SELECT manual FROM assessments_cache WHERE company = $1 AND service = $2 AND source = $3`,
		NormalizeKey(company), NormalizeKey(service), "cvedetails").Scan(&manual)
	if err != nil {
		t.Fatalf("read manual column: %v", err)
	}
	if !manual {
		t.Error("manual column is false; the entry would be treated as expirable cache")
	}
}

func TestManualEntryIgnoresNonManualRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	// A cached automated row (what Phase 9 will write) shares the key space. Reading it as
	// a manual entry would render stale cache as an analyst's answer.
	_, err := st.pool.Exec(ctx,
		`INSERT INTO assessments_cache (company, service, source, section, manual)
		 VALUES ($1, $2, $3, $4, false)`,
		NormalizeKey(company), NormalizeKey(service), "bitsight", []byte(`{"value":"cached"}`))
	if err != nil {
		t.Fatalf("insert cache row: %v", err)
	}

	if _, found, err := st.ManualEntry(ctx, company, service, "bitsight"); err != nil || found {
		t.Errorf("ManualEntry read a non-manual row: found %v, err %v", found, err)
	}
}

func TestManualEntryNormalizesTheKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	company, service := uniqueQuery(t, st)

	// vrm set and vrm assess are typed by hand at different times. If either skipped
	// normalization the entry would be written to one row and read from another, which
	// looks exactly like the analyst never recorded it.
	if err := st.SetManual(ctx, "  "+strings.ToUpper(company)+" ", service, "ssllabs", "A+"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}

	entry, found, err := st.ManualEntry(ctx, company, "  "+strings.ToUpper(service)+"  ", "ssllabs")
	if err != nil || !found {
		t.Fatalf("ManualEntry = found %v, err %v; want the row written under a differently-cased key", found, err)
	}
	if entry.Value != "A+" {
		t.Errorf("Value = %q, want %q", entry.Value, "A+")
	}
}

func TestNormalizeKey(t *testing.T) {
	// company and service form two thirds of the assessments_cache primary key, so these
	// all have to collapse to the same row or the cache fragments into near-duplicates.
	tests := []struct {
		in, want string
	}{
		{"Okta", "okta"},
		{"okta", "okta"},
		{"  Okta  ", "okta"},
		{"OKTA", "okta"},
		{"Okta  Inc", "okta inc"},
		{"Okta\tInc", "okta inc"},
		{"", ""},
		{"   ", ""},
	}
	for _, tt := range tests {
		if got := NormalizeKey(tt.in); got != tt.want {
			t.Errorf("NormalizeKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNewRejectsInvalidDSNWithoutLeakingIt(t *testing.T) {
	// pgx embeds the connection string in ParseConfig errors. DATABASE_URL carries a
	// password, so the error must not repeat it back (spec §4).
	const password = "sup3rs3cr3t"
	dsn := "postgres://vrm:" + password + "@localhost:5432/vrm?sslmode=bogus-mode"

	st, err := New(context.Background(), dsn)
	if err == nil {
		st.Close()
		t.Fatal("New succeeded with an invalid DSN")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("error leaked the database password: %s", err)
	}
}

func TestCloseOnZeroValueIsSafe(t *testing.T) {
	// main defers Close, so it must tolerate a Store that never opened.
	var s *Store
	s.Close()
	(&Store{}).Close()
}
