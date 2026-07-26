package store

import (
	"context"
	"strings"
	"testing"
)

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
