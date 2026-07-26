package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// The fixture tests are the shape check: if BitSight changes their response, these fail
// rather than an analyst reading an empty section.

func TestParseCompanySearchFixture(t *testing.T) {
	companies, err := parseCompanySearch(fixture(t, "bitsight_search.json"))
	if err != nil {
		t.Fatalf("parseCompanySearch: %v", err)
	}
	if len(companies) != 1 {
		t.Fatalf("got %d companies, want 1", len(companies))
	}
	c := companies[0]
	if c.GUID != "123e4567-e89b-12d3-a456-426614174000" {
		t.Errorf("GUID = %q", c.GUID)
	}
	if c.Name != "Example Corp" || c.PrimaryDomain != "example.com" {
		t.Errorf("Name/PrimaryDomain = %q / %q", c.Name, c.PrimaryDomain)
	}
	if !c.IsPrimary || c.Confidence != "High" {
		t.Errorf("IsPrimary/Confidence = %v / %q", c.IsPrimary, c.Confidence)
	}
}

func TestParseRatingDetailFixture(t *testing.T) {
	r, err := parseRatingDetail(fixture(t, "bitsight_rating.json"))
	if err != nil {
		t.Fatalf("parseRatingDetail: %v", err)
	}
	if r.Rating != 750 {
		t.Errorf("Rating = %d, want 750", r.Rating)
	}
	if r.RatingRange != "advanced" || r.RatingDate != "2024-01-01" {
		t.Errorf("Range/Date = %q / %q", r.RatingRange, r.RatingDate)
	}
	if r.CompanyName != "Example Corp" || r.Industry != "Technology" {
		t.Errorf("Name/Industry = %q / %q", r.CompanyName, r.Industry)
	}
}

func TestParseRatingDetailPicksMostRecent(t *testing.T) {
	body := []byte(`{"guid":"g","name":"N","ratings":[
		{"rating_date":"2023-01-01","rating":600,"range":"basic"},
		{"rating_date":"2025-06-01","rating":800,"range":"advanced"},
		{"rating_date":"2024-01-01","rating":700,"range":"intermediate"}]}`)

	r, err := parseRatingDetail(body)
	if err != nil {
		t.Fatalf("parseRatingDetail: %v", err)
	}
	if r.Rating != 800 || r.RatingDate != "2025-06-01" {
		t.Errorf("got %d as of %s, want the most recent (800, 2025-06-01)", r.Rating, r.RatingDate)
	}
}

// A missing ratings array must be loud. Falling back to a zero rating would render "0"
// beside genuine scores with nothing to distinguish it.
func TestParseRatingDetailRejectsMissingRatings(t *testing.T) {
	if _, err := parseRatingDetail([]byte(`{"guid":"g","name":"N"}`)); err == nil {
		t.Fatal("parseRatingDetail accepted a response with no ratings")
	}
}

func TestParseCompanySearchRejectsResultWithoutGUID(t *testing.T) {
	// A result missing its guid means the shape changed; proceeding would fetch a rating
	// for an empty path.
	if _, err := parseCompanySearch([]byte(`{"count":1,"results":[{"name":"N"}]}`)); err == nil {
		t.Fatal("parseCompanySearch accepted a result with no guid")
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := parseCompanySearch([]byte(`{not json`)); err == nil {
		t.Error("parseCompanySearch accepted malformed JSON")
	}
	if _, err := parseRatingDetail([]byte(`{not json`)); err == nil {
		t.Error("parseRatingDetail accepted malformed JSON")
	}
}

// Selection must be deterministic: a different pick means a different company's rating.
func TestSelectCompanyIsDeterministic(t *testing.T) {
	tests := []struct {
		name      string
		companies []bitsightCompany
		wantGUID  string
	}{
		{
			name: "prefers primary over high confidence",
			companies: []bitsightCompany{
				{GUID: "a", Confidence: "High"},
				{GUID: "b", IsPrimary: true},
			},
			wantGUID: "b",
		},
		{
			name: "falls back to high confidence",
			companies: []bitsightCompany{
				{GUID: "a", Confidence: "Low"},
				{GUID: "b", Confidence: "High"},
			},
			wantGUID: "b",
		},
		{
			name: "falls back to the first result",
			companies: []bitsightCompany{
				{GUID: "a", Confidence: "Low"},
				{GUID: "b", Confidence: "Low"},
			},
			wantGUID: "a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run repeatedly: an accidental map iteration would show up as flakiness.
			for i := 0; i < 10; i++ {
				if got := selectCompany(tt.companies); got.GUID != tt.wantGUID {
					t.Fatalf("selectCompany = %q, want %q", got.GUID, tt.wantGUID)
				}
			}
		})
	}
}

// newTestBitSight points a BitSight source at a stub server.
func newTestBitSight(t *testing.T, h http.HandlerFunc, apiKey string) *BitSight {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewBitSight(apiKey, WithBitSightBaseURL(srv.URL), WithBitSightHTTPClient(srv.Client()))
}

func TestFetchHappyPath(t *testing.T) {
	b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/companies/search"):
			if got := r.URL.Query().Get("domain"); got != "example.com" {
				t.Errorf("search domain = %q, want example.com", got)
			}
			w.Write(fixture(t, "bitsight_search.json"))
		default:
			if !strings.HasSuffix(r.URL.Path, "/123e4567-e89b-12d3-a456-426614174000") {
				t.Errorf("rating path = %q, want the guid from the search", r.URL.Path)
			}
			w.Write(fixture(t, "bitsight_rating.json"))
		}
	}, "test-key")

	sec, err := b.Fetch(context.Background(), Query{Company: "Example"},
		ResolvedEntity{Domains: []string{"example.com"}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sec.Status != StatusOK {
		t.Fatalf("Status = %q, want ok (Err=%q)", sec.Status, sec.Err)
	}
	r, ok := sec.Data.(BitSightRating)
	if !ok {
		t.Fatalf("Data is %T, want BitSightRating", sec.Data)
	}
	if r.Rating != 750 {
		t.Errorf("Rating = %d, want 750", r.Rating)
	}
	// The queried domain is carried so a bad match is visible to an analyst.
	if r.QueriedDomain != "example.com" {
		t.Errorf("QueriedDomain = %q", r.QueriedDomain)
	}
}

func TestFetchSendsBasicAuth(t *testing.T) {
	const key = "test-token"
	var gotUser, gotPass string
	var hadAuth bool

	b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, hadAuth = r.BasicAuth()
		if strings.HasSuffix(r.URL.Path, "/companies/search") {
			w.Write(fixture(t, "bitsight_search.json"))
			return
		}
		w.Write(fixture(t, "bitsight_rating.json"))
	}, key)

	if _, err := b.Fetch(context.Background(), Query{}, ResolvedEntity{Domains: []string{"example.com"}}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !hadAuth {
		t.Fatal("no Authorization header sent")
	}
	// Token as username, empty password (bitsight-api-info.md §4).
	if gotUser != key || gotPass != "" {
		t.Errorf("basic auth = %q:%q, want %q with an empty password", gotUser, gotPass, key)
	}
}

// Skips are not failures and must not look like them.
func TestFetchSkips(t *testing.T) {
	t.Run("no domain resolved", func(t *testing.T) {
		b := NewBitSight("k")
		sec, err := b.Fetch(context.Background(), Query{}, ResolvedEntity{})
		if err != nil {
			t.Fatalf("Fetch returned an error for missing input: %v", err)
		}
		if sec.Status != StatusSkipped {
			t.Errorf("Status = %q, want skipped", sec.Status)
		}
		if sec.Note == "" {
			t.Error("skipped section has no note explaining why")
		}
	})

	t.Run("vendor not rated by BitSight", func(t *testing.T) {
		b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"count":0,"results":[]}`))
		}, "k")

		sec, err := b.Fetch(context.Background(), Query{}, ResolvedEntity{Domains: []string{"nope.example"}})
		if err != nil {
			t.Fatalf("Fetch returned an error for an unrated vendor: %v", err)
		}
		if sec.Status != StatusSkipped {
			t.Errorf("Status = %q, want skipped", sec.Status)
		}
		if !strings.Contains(sec.Note, "nope.example") {
			t.Errorf("note does not name the domain: %q", sec.Note)
		}
	})
}

// Acceptance criterion 2: an API error surfaces as StatusFailed without crashing.
func TestFetchHTTPErrorsBecomeFailed(t *testing.T) {
	tests := []struct {
		code    int
		wantErr string
	}{
		{http.StatusUnauthorized, "credentials"},
		{http.StatusForbidden, "credentials"},
		{http.StatusNotFound, "404"},
		{http.StatusTooManyRequests, "rate limit"},
		{http.StatusInternalServerError, "500"},
		{http.StatusBadGateway, "502"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
				w.Write([]byte(`{"detail":"upstream message"}`))
			}, "k")

			sec, err := b.Fetch(context.Background(), Query{}, ResolvedEntity{Domains: []string{"example.com"}})
			if err == nil {
				t.Fatal("Fetch returned no error for an HTTP failure")
			}
			if sec.Status != StatusFailed {
				t.Errorf("Status = %q, want failed", sec.Status)
			}
			if !strings.Contains(strings.ToLower(sec.Err), tt.wantErr) {
				t.Errorf("Err = %q, want it to mention %q", sec.Err, tt.wantErr)
			}
			// A failed source has no trustworthy value.
			if sec.Data != nil {
				t.Errorf("failed section carries Data = %v", sec.Data)
			}
		})
	}
}

func TestFetchMalformedResponseBecomesFailed(t *testing.T) {
	b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"count": not-json`))
	}, "k")

	sec, _ := b.Fetch(context.Background(), Query{}, ResolvedEntity{Domains: []string{"example.com"}})
	if sec.Status != StatusFailed {
		t.Errorf("Status = %q, want failed", sec.Status)
	}
}

func TestFetchTimeoutBecomesFailed(t *testing.T) {
	b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never respond
	}, "k")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	sec, err := b.Fetch(ctx, Query{}, ResolvedEntity{Domains: []string{"example.com"}})
	if err == nil {
		t.Fatal("Fetch returned no error on timeout")
	}
	if sec.Status != StatusFailed {
		t.Errorf("Status = %q, want failed", sec.Status)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error does not wrap DeadlineExceeded: %v", err)
	}
}

// The API key must never reach a rendered Section or an error. BitSight keys are licensed
// credentials, and an analyst reading a failure message should not be shown one.
func TestFetchNeverLeaksAPIKey(t *testing.T) {
	const canary = "canary-bitsight-key-do-not-render"

	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		b := newTestBitSight(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			// Some APIs echo the rejected credential back in the body.
			w.Write([]byte(`{"detail":"invalid token ` + canary + `"}`))
		}, canary)

		sec, err := b.Fetch(context.Background(), Query{}, ResolvedEntity{Domains: []string{"example.com"}})
		if strings.Contains(sec.Err, canary) {
			t.Errorf("HTTP %d: Section.Err leaked the API key: %s", code, sec.Err)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("HTTP %d: error leaked the API key: %v", code, err)
		}
		if sec.Note != "" && strings.Contains(sec.Note, canary) {
			t.Errorf("HTTP %d: Section.Note leaked the API key", code)
		}
	}
}
