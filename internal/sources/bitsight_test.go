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

// The fixtures are captured from real BitSight responses with identifying values replaced
// but the structure left exactly intact — envelope shape, full key set, and the real
// three-way ambiguity a domain search returns.

func TestParseCompanySearchFixture(t *testing.T) {
	companies, err := parseCompanySearch(fixture(t, "bitsight_search.json"))
	if err != nil {
		t.Fatalf("parseCompanySearch: %v", err)
	}
	// A real domain search returns several fuzzy matches, not one.
	if len(companies) != 3 {
		t.Fatalf("got %d companies, want 3", len(companies))
	}
	c := companies[0]
	if c.GUID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("GUID = %q", c.GUID)
	}
	if c.Name != "Example Corp" || c.PrimaryDomain != "example.com" {
		t.Errorf("Name/PrimaryDomain = %q / %q", c.Name, c.PrimaryDomain)
	}
	// The third result is an unrelated subdomain — the case selection has to reject.
	if companies[2].PrimaryDomain != "sub.example.com" {
		t.Errorf("third result domain = %q, want sub.example.com", companies[2].PrimaryDomain)
	}
}

func TestParseRatingDetailFixture(t *testing.T) {
	r, err := parseRatingDetail(fixture(t, "bitsight_rating.json"))
	if err != nil {
		t.Fatalf("parseRatingDetail: %v", err)
	}
	if r.Rating != 750 {
		t.Errorf("Rating = %d, want 750 (current_rating)", r.Rating)
	}
	if r.RatingRange != "Advanced" || r.RatingDate != "2026-07-24" {
		t.Errorf("Range/Date = %q / %q", r.RatingRange, r.RatingDate)
	}
	if r.CompanyName != "Example Corp" || r.Industry != "Technology" {
		t.Errorf("Name/Industry = %q / %q", r.CompanyName, r.Industry)
	}
	if r.IndustryMedian != "below" {
		t.Errorf("IndustryMedian = %q, want below", r.IndustryMedian)
	}
	if !strings.HasPrefix(r.ReportURL, "https://service.bitsighttech.com/") {
		t.Errorf("ReportURL = %q, want a BitSight company page", r.ReportURL)
	}
}

// current_rating is authoritative; the series only supplies the date and band.
func TestParseRatingDetailPrefersCurrentRating(t *testing.T) {
	body := []byte(`{"guid":"g","name":"N","current_rating":810,"ratings":[
		{"rating_date":"2026-01-01","rating":790,"range":"Advanced"}]}`)

	r, err := parseRatingDetail(body)
	if err != nil {
		t.Fatalf("parseRatingDetail: %v", err)
	}
	if r.Rating != 810 {
		t.Errorf("Rating = %d, want 810 from current_rating", r.Rating)
	}
	if r.RatingDate != "2026-01-01" {
		t.Errorf("RatingDate = %q, want the date from the series", r.RatingDate)
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

// A response with no rating at all must be loud. Falling back to zero would render "0"
// beside genuine scores with nothing to distinguish it.
func TestParseRatingDetailRejectsMissingRatings(t *testing.T) {
	if _, err := parseRatingDetail([]byte(`{"guid":"g","name":"N"}`)); err == nil {
		t.Fatal("parseRatingDetail accepted a response with no rating")
	}
}

// Trusting the array order would report a years-old score as current if BitSight ever
// returned the series oldest-first.
func TestParseRatingDetailSortsRatherThanTrustingOrder(t *testing.T) {
	body := []byte(`{"guid":"g","name":"N","ratings":[
		{"rating_date":"2019-01-01","rating":500,"range":"Basic"},
		{"rating_date":"2026-07-24","rating":750,"range":"Advanced"}]}`)

	r, err := parseRatingDetail(body)
	if err != nil {
		t.Fatalf("parseRatingDetail: %v", err)
	}
	if r.RatingDate != "2026-07-24" || r.RatingRange != "Advanced" {
		t.Errorf("got %s / %s, want the newest entry despite it arriving last",
			r.RatingDate, r.RatingRange)
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

// Selection must be deterministic: a different pick means a different company's rating,
// and the number would look perfectly normal either way.
func TestSelectCompany(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		companies []bitsightCompany
		wantGUID  string
		wantAlts  int
	}{
		{
			name:   "rejects a subdomain in favour of the exact domain",
			domain: "example.com",
			companies: []bitsightCompany{
				{GUID: "sub", PrimaryDomain: "sub.example.com"},
				{GUID: "exact", PrimaryDomain: "example.com"},
			},
			wantGUID: "exact",
			wantAlts: 1,
		},
		{
			name:   "keeps BitSight ordering among exact matches",
			domain: "example.com",
			companies: []bitsightCompany{
				{GUID: "first", PrimaryDomain: "example.com"},
				{GUID: "second", PrimaryDomain: "example.com"},
			},
			wantGUID: "first",
			wantAlts: 1,
		},
		{
			name:   "falls back to the first result when nothing matches exactly",
			domain: "example.com",
			companies: []bitsightCompany{
				{GUID: "a", PrimaryDomain: "other.example.net"},
				{GUID: "b", PrimaryDomain: "sub.example.com"},
			},
			wantGUID: "a",
			wantAlts: 1,
		},
		{
			name:      "domain comparison is case-insensitive",
			domain:    "Example.COM",
			companies: []bitsightCompany{{GUID: "sub", PrimaryDomain: "sub.example.com"}, {GUID: "exact", PrimaryDomain: "example.com"}},
			wantGUID:  "exact",
			wantAlts:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Repeat: an accidental map iteration would surface as flakiness.
			for i := 0; i < 10; i++ {
				got, alts := selectCompany(tt.companies, tt.domain)
				if got.GUID != tt.wantGUID {
					t.Fatalf("selectCompany = %q, want %q", got.GUID, tt.wantGUID)
				}
				if len(alts) != tt.wantAlts {
					t.Fatalf("got %d alternatives, want %d", len(alts), tt.wantAlts)
				}
			}
		})
	}
}

// The real failure this guards: searching a vendor domain returns the vendor plus
// unrelated customer subdomains, and picking one of those rates the wrong organisation.
func TestSelectCompanyAgainstRealSearchShape(t *testing.T) {
	companies, err := parseCompanySearch(fixture(t, "bitsight_search.json"))
	if err != nil {
		t.Fatalf("parseCompanySearch: %v", err)
	}
	got, alts := selectCompany(companies, "example.com")
	if got.Name != "Example Corp" {
		t.Errorf("selected %q, want Example Corp", got.Name)
	}
	if len(alts) != 2 {
		t.Errorf("got %d alternatives, want 2 so an analyst can spot a wrong pick", len(alts))
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
			if !strings.HasSuffix(r.URL.Path, "/11111111-1111-4111-8111-111111111111") {
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
	// The queried domain and the rejected candidates are carried so a bad match is
	// visible to an analyst rather than silently producing another company's rating.
	if r.QueriedDomain != "example.com" {
		t.Errorf("QueriedDomain = %q", r.QueriedDomain)
	}
	if len(r.Alternatives) != 2 {
		t.Errorf("got %d alternatives, want the 2 other search hits", len(r.Alternatives))
	}
	// BitSight's own company page is the one link an analyst can click to verify.
	if len(sec.Citations) != 1 || !strings.HasPrefix(sec.Citations[0].URL, "https://service.bitsighttech.com/") {
		t.Errorf("citations = %+v, want the BitSight company page", sec.Citations)
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
