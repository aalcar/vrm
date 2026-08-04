package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// caagServer serves one fixture per requested name and records the searches it saw.
func caagServer(t *testing.T, byName map[string]string) (*CAAG, *[]string) {
	t.Helper()
	var searched []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get(caagNameParam)
		searched = append(searched, name)

		fixture, ok := byName[name]
		if !ok {
			fixture = "caag_no_results.html"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(readFixture(t, fixture)))
	}))
	t.Cleanup(srv.Close)

	return NewCAAG(WithCAAGURL(srv.URL+"/privacy/databreach/list"),
		WithCAAGClient(srv.Client())), &searched
}

func TestCAAGParsesReportedBreaches(t *testing.T) {
	src, searched := caagServer(t, map[string]string{"T-Mobile": "caag_tmobile.html"})

	section, err := src.Fetch(context.Background(),
		Query{Company: "T-Mobile"}, ResolvedEntity{CanonicalName: "T-Mobile"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if section.Status != StatusOK {
		t.Fatalf("Status = %q (%s), want %q", section.Status, section.Err, StatusOK)
	}
	if len(*searched) != 1 || (*searched)[0] != "T-Mobile" {
		t.Errorf("searched %v, want exactly [T-Mobile]", *searched)
	}

	result, ok := section.Data.(CAAGResult)
	if !ok {
		t.Fatalf("Data is %T, want CAAGResult", section.Data)
	}
	if len(result.Entries) != 3 {
		t.Fatalf("parsed %d entries, want 3: %+v", len(result.Entries), result.Entries)
	}

	first := result.Entries[0]
	// The organization is recorded as filed, not as searched: the filter is a substring
	// match and these three rows are filed under three different names.
	if first.Organization != "T-Mobile USA" {
		t.Errorf("Organization = %q, want %q", first.Organization, "T-Mobile USA")
	}
	if len(first.BreachDates) != 1 || first.BreachDates[0] != "07/22/2021" {
		t.Errorf("BreachDates = %v, want [07/22/2021]", first.BreachDates)
	}
	if first.ReportedDate != "08/25/2021" {
		t.Errorf("ReportedDate = %q, want %q", first.ReportedDate, "08/25/2021")
	}
	// The report URL is how an analyst reads the actual notification.
	if !strings.HasPrefix(first.ReportURL, "https://oag.ca.gov/ecrime/databreach/reports/") {
		t.Errorf("ReportURL = %q, want the notification page", first.ReportURL)
	}

	names := []string{"T-Mobile USA", "T-Mobile USA, Inc.", "T-Mobile US"}
	for i, want := range names {
		if result.Entries[i].Organization != want {
			t.Errorf("entry %d organization = %q, want %q", i, result.Entries[i].Organization, want)
		}
	}
}

func TestCAAGMissingBreachDateIsNotInvented(t *testing.T) {
	src, _ := caagServer(t, map[string]string{"T-Mobile": "caag_tmobile.html"})

	section, err := src.Fetch(context.Background(),
		Query{Company: "T-Mobile"}, ResolvedEntity{CanonicalName: "T-Mobile"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	result := section.Data.(CAAGResult)

	// The third row's breach date is the literal text "n/a" — the list saying it does not
	// know. That must stay empty rather than being parsed into some stand-in date, and it
	// must not take the rest of the row down with it.
	last := result.Entries[2]
	if len(last.BreachDates) != 0 {
		t.Errorf("BreachDates = %v for a row printed as n/a, want none", last.BreachDates)
	}
	if last.ReportedDate != "12/30/2013" {
		t.Errorf("ReportedDate = %q, want the row to survive its missing breach date", last.ReportedDate)
	}
	if last.ReportURL == "" {
		t.Error("ReportURL is empty; the row was dropped by its missing breach date")
	}
}

func TestCAAGNoResultsIsCleanNotFailed(t *testing.T) {
	src, _ := caagServer(t, nil) // every search returns the no-results page

	section, err := src.Fetch(context.Background(),
		Query{Company: "Nonexistent Vendor Co"},
		ResolvedEntity{CanonicalName: "Nonexistent Vendor Co"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Most vendors have no California-reported breach. The view-empty marker is what makes
	// that a real answer rather than an unverified silence.
	if section.Status != StatusOK {
		t.Fatalf("Status = %q (%s), want %q", section.Status, section.Err, StatusOK)
	}
	if result := section.Data.(CAAGResult); len(result.Entries) != 0 {
		t.Errorf("entries = %+v, want none", result.Entries)
	}
}

func TestCAAGLayoutDriftFailsLoudly(t *testing.T) {
	// A page with neither result rows nor the empty marker is unreadable, and "no breaches
	// reported" is far too strong a claim to make from a page nobody could parse.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><div class="view-content">
			<p>The breach list has moved.</p></div></body></html>`))
	}))
	defer srv.Close()

	src := NewCAAG(WithCAAGURL(srv.URL), WithCAAGClient(srv.Client()))
	section, err := src.Fetch(context.Background(),
		Query{Company: "Okta"}, ResolvedEntity{CanonicalName: "Okta"})
	if err == nil {
		t.Error("Fetch returned no error for an unparseable page")
	}
	if section.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", section.Status, StatusFailed)
	}
	if !strings.Contains(section.Err, "layout has changed") {
		t.Errorf("Err = %q, want it to name layout drift", section.Err)
	}
	if section.Data != nil {
		t.Error("Data is set on a failed section")
	}
}

func TestCAAGDeduplicatesAcrossNames(t *testing.T) {
	// Aliases overlap, and the filter is a substring match, so the same breach comes back
	// under several searches. Reporting it three times would read as three breaches.
	src, searched := caagServer(t, map[string]string{
		"T-Mobile":     "caag_tmobile.html",
		"T-Mobile USA": "caag_tmobile.html",
	})

	section, err := src.Fetch(context.Background(),
		Query{Company: "T-Mobile"},
		ResolvedEntity{CanonicalName: "T-Mobile", Aliases: []string{"T-Mobile USA"}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(*searched) != 2 {
		t.Errorf("searched %v, want both names queried", *searched)
	}

	result := section.Data.(CAAGResult)
	if len(result.Entries) != 3 {
		t.Errorf("got %d entries, want the same 3 breaches reported once each", len(result.Entries))
	}
}

func TestCAAGOneFailedSearchFailsTheSection(t *testing.T) {
	// A partial answer here is worse than none: the entries that did come back would render
	// as the complete picture, and "no other breaches" is exactly the claim an analyst would
	// take from it.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(readFixture(t, "caag_tmobile.html")))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	src := NewCAAG(WithCAAGURL(srv.URL), WithCAAGClient(srv.Client()))
	section, err := src.Fetch(context.Background(),
		Query{Company: "T-Mobile"},
		ResolvedEntity{CanonicalName: "T-Mobile", Aliases: []string{"T-Mobile USA"}})
	if err == nil {
		t.Error("Fetch returned no error when one of two searches failed")
	}
	if section.Status != StatusFailed {
		t.Errorf("Status = %q, want %q", section.Status, StatusFailed)
	}
	if !strings.Contains(section.Err, "502") {
		t.Errorf("Err = %q, want it to carry the status code", section.Err)
	}
}

func TestCAAGBoundsTheNumberOfSearches(t *testing.T) {
	// Each name is a request against a public government site.
	src, searched := caagServer(t, nil)

	_, err := src.Fetch(context.Background(), Query{Company: "Okta"}, ResolvedEntity{
		CanonicalName: "Okta",
		Aliases:       []string{"Auth0", "Okta Security", "Okta Federal", "Okta Labs", "Okta EMEA"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(*searched) > caagMaxNames {
		t.Errorf("made %d searches, want at most %d", len(*searched), caagMaxNames)
	}
}
