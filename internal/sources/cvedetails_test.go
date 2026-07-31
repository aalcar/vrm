package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// NOTE ON THE FIXTURE
//
// testdata/cvedetails_vendor.json is CONSTRUCTED, not captured. CVE Details' API is behind
// a paid subscription and their API reference blocks automated fetching, so unlike every
// other source here the response shape is unconfirmed. These tests therefore prove that the
// parser handles the shape it was written against — not that the shape is right.
//
// The tests that actually matter today are the skip and the refusal-to-guess below: those
// cover the whole reachable surface, and they are what spec §13's phase 4 criterion asks
// for. When a real subscription is available, recapture the fixture and expect
// TestParseCVEDetailsFixture to need changes.

func newTestCVEDetails(t *testing.T, h http.HandlerFunc, apiKey string) *CVEDetails {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewCVEDetails(apiKey,
		WithCVEDetailsBaseURL(srv.URL),
		WithCVEDetailsHTTPClient(srv.Client()),
	)
}

// TestFetchCVEDetailsSkipsWithoutKey is the ordinary path: the source is optional paid
// enrichment, so most deployments skip it and nothing about that is a failure.
func TestFetchCVEDetailsSkipsWithoutKey(t *testing.T) {
	c := newTestCVEDetails(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be made without a key")
	}, "")

	sec, err := c.Fetch(context.Background(), Query{Company: "HashiCorp"},
		ResolvedEntity{CanonicalName: "HashiCorp"})
	if err != nil {
		t.Fatalf("an absent optional credential must not be an error: %v", err)
	}
	if sec.Status != StatusSkipped {
		t.Fatalf("status = %s, want skipped", sec.Status)
	}
	if !strings.Contains(sec.Note, EnvCVEDetailsKeyName) {
		t.Errorf("the note should name the missing variable: %q", sec.Note)
	}
}

// TestFetchCVEDetailsNeverBlocks: whatever this source does, it must return promptly and
// leave the rest of the assessment alone (spec §13 phase 4).
func TestFetchCVEDetailsNeverBlocks(t *testing.T) {
	c := NewCVEDetails("")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // even a dead context must not stop the skip from being returned

	sec, err := c.Fetch(ctx, Query{Company: "HashiCorp"}, ResolvedEntity{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sec.Status != StatusSkipped {
		t.Fatalf("status = %s, want skipped", sec.Status)
	}
}

// TestFetchCVEDetailsRefusesToGuessEndpoint: a key without a configured host must fail
// loudly. Quietly skipping would read as "nothing to add" when the truth is "never ran",
// and inventing a path risks parsing another vendor's records as this vendor's.
func TestFetchCVEDetailsRefusesToGuessEndpoint(t *testing.T) {
	c := NewCVEDetails("a-key-but-no-endpoint")

	sec, err := c.Fetch(context.Background(), Query{Company: "HashiCorp"},
		ResolvedEntity{CanonicalName: "HashiCorp"})
	if err == nil {
		t.Fatal("want an informational error")
	}
	if sec.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", sec.Status)
	}
	if !strings.Contains(sec.Err, "endpoint") {
		t.Errorf("error should say the endpoint is unconfigured: %q", sec.Err)
	}
	if sec.Data != nil {
		t.Error("a failed section must carry no data")
	}
}

func TestParseCVEDetailsFixture(t *testing.T) {
	summary, err := parseCVEDetails(fixture(t, "cvedetails_vendor.json"), "HashiCorp")
	if err != nil {
		t.Fatalf("parseCVEDetails: %v", err)
	}
	if summary.Vendor != "HashiCorp" {
		t.Errorf("vendor = %q", summary.Vendor)
	}
	if summary.TotalCVEs == 0 || len(summary.CVEs) == 0 {
		t.Fatalf("parsed nothing: %+v", summary)
	}
	first := summary.CVEs[0]
	if !strings.HasPrefix(first.ID, "CVE-") {
		t.Errorf("id = %q", first.ID)
	}
	if !strings.Contains(first.URL, first.ID) {
		t.Errorf("URL %q does not reference %q", first.URL, first.ID)
	}
}

func TestParseCVEDetailsRejectsMalformed(t *testing.T) {
	if _, err := parseCVEDetails([]byte(`{"results":`), "X"); err == nil {
		t.Error("truncated JSON accepted")
	}
	if _, err := parseCVEDetails([]byte(`{"results":[{"summary":"x"}]}`), "X"); err == nil {
		t.Error("result without a cveId accepted")
	}
}

func TestFetchCVEDetailsHappyPath(t *testing.T) {
	var gotAuth string
	c := newTestCVEDetails(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write(fixture(t, "cvedetails_vendor.json"))
	}, "test-key")

	sec, err := c.Fetch(context.Background(), Query{Company: "HashiCorp"},
		ResolvedEntity{CanonicalName: "HashiCorp"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sec.Status != StatusOK {
		t.Fatalf("status = %s, err = %s", sec.Status, sec.Err)
	}
	// Bearer auth per spec §6.
	if gotAuth != "Bearer test-key" {
		t.Errorf("Authorization = %q, want Bearer auth", gotAuth)
	}
	if _, ok := sec.Data.(CVEDetailsSummary); !ok {
		t.Fatalf("Data is %T, want CVEDetailsSummary", sec.Data)
	}
}

func TestFetchCVEDetailsHTTPErrorsBecomeFailed(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{http.StatusUnauthorized, EnvCVEDetailsKeyName},
		{http.StatusForbidden, EnvCVEDetailsKeyName},
		{http.StatusNotFound, "endpoint path"},
		{http.StatusTooManyRequests, "rate limit"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			c := newTestCVEDetails(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
			}, "test-key")

			sec, err := c.Fetch(context.Background(), Query{Company: "HashiCorp"},
				ResolvedEntity{CanonicalName: "HashiCorp"})
			if err == nil {
				t.Fatal("want an informational error")
			}
			if sec.Status != StatusFailed {
				t.Fatalf("status = %s, want failed", sec.Status)
			}
			if !strings.Contains(sec.Err, tt.want) {
				t.Errorf("error %q does not mention %q", sec.Err, tt.want)
			}
		})
	}
}

func TestFetchCVEDetailsNeverLeaksAPIKey(t *testing.T) {
	const canary = "canary-cvedetails-key-do-not-render"
	c := newTestCVEDetails(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token ` + canary + `"}`))
	}, canary)

	sec, err := c.Fetch(context.Background(), Query{Company: "HashiCorp"},
		ResolvedEntity{CanonicalName: "HashiCorp"})

	if strings.Contains(sec.Err, canary) {
		t.Errorf("API key leaked into Section.Err: %s", sec.Err)
	}
	if strings.Contains(sec.Note, canary) {
		t.Errorf("API key leaked into Section.Note: %s", sec.Note)
	}
	if err != nil && strings.Contains(err.Error(), canary) {
		t.Errorf("API key leaked into the error: %v", err)
	}
}
