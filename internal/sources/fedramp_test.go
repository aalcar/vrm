package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(body)
}

// fedrampServer serves a fixture and reports what was requested.
func fedrampServer(t *testing.T, fixture string) (*FedRAMP, *string) {
	t.Helper()
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(readFixture(t, fixture)))
	}))
	t.Cleanup(srv.Close)

	// The fixture is a trimmed capture carrying four records, so the drift floor is lowered
	// to match. The production floor is exercised by its own test below.
	return NewFedRAMP(WithFedRAMPURL(srv.URL+"/marketplace/products/"),
		WithFedRAMPClient(srv.Client()), withFedRAMPMinRecords(3)), &gotPath
}

func TestFedRAMPParsesAuthoritativeRecords(t *testing.T) {
	src, _ := fedrampServer(t, "fedramp_products.html")

	section, err := src.Fetch(context.Background(),
		Query{Company: "Okta", Service: "SSO"}, ResolvedEntity{CanonicalName: "Okta"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if section.Status != StatusOK {
		t.Fatalf("Status = %q (%s), want %q", section.Status, section.Err, StatusOK)
	}

	result, ok := section.Data.(FedRAMPResult)
	if !ok {
		t.Fatalf("Data is %T, want FedRAMPResult", section.Data)
	}
	if len(result.Offerings) != 2 {
		t.Fatalf("matched %d offerings, want Okta's 2: %+v", len(result.Offerings), result.Offerings)
	}

	byOffering := make(map[string]FedRAMPOffering, len(result.Offerings))
	for _, o := range result.Offerings {
		byOffering[o.Offering] = o
	}

	// Values are recorded in FedRAMP's own vocabulary — "FedRAMP Certified" is not restated
	// as "authorized", and LI-SaaS is never folded into Low.
	want := map[string]struct{ status, impact, id string }{
		"Okta IDaaS Regulated Cloud":             {"FedRAMP Certified", "Moderate", "F1512167750"},
		"Okta IDaaS Government High Cloud (GHC)": {"FedRAMP Certified", "High", "FR2131856836"},
	}
	for name, w := range want {
		got, found := byOffering[name]
		if !found {
			t.Errorf("offering %q missing", name)
			continue
		}
		if got.Status != w.status {
			t.Errorf("%s status = %q, want %q", name, got.Status, w.status)
		}
		if got.ImpactLevel != w.impact {
			t.Errorf("%s impact = %q, want %q", name, got.ImpactLevel, w.impact)
		}
		if got.ID != w.id {
			t.Errorf("%s id = %q, want %q", name, got.ID, w.id)
		}
		// The per-offering URL is what an analyst clicks to verify the row.
		if !strings.HasSuffix(got.URL, w.id+"/") {
			t.Errorf("%s URL = %q, want it to end in the record id", name, got.URL)
		}
	}
}

func TestFedRAMPIgnoresLeveragedSystemsEntries(t *testing.T) {
	// The page carries thousands of {id,csp,cso,status,…} literals that are dependency
	// lists, not marketplace entries, and their status is stale: the fixture contains Okta
	// inside one of them marked "Unknown" while Okta is actually FedRAMP Certified.
	//
	// This is the failure that matters, because it does not look like a failure. A parser
	// matching the nested literals returns a full, plausible, sourced section that is wrong.
	body := readFixture(t, "fedramp_products.html")
	if !strings.Contains(body, `csp:"Okta",cso:"Okta IDaaS Government High Cloud (GHC)",status:"Unknown"`) {
		t.Fatal("fixture no longer contains the stale nested Okta record this test exists for")
	}

	records, err := parseFedRAMPRecords(body, 3)
	if err != nil {
		t.Fatalf("parseFedRAMPRecords: %v", err)
	}

	for _, rec := range records {
		if rec.Provider == "Okta" && rec.Status != "FedRAMP Certified" {
			t.Errorf("Okta offering %q has status %q; the parser matched a nested "+
				"leveraged_systems entry instead of the authoritative record",
				rec.Offering, rec.Status)
		}
	}

	// Four authoritative records, not the dozens of nested literals in the same bytes.
	if len(records) != 4 {
		t.Errorf("parsed %d records, want the 4 authoritative ones", len(records))
	}
}

func TestFedRAMPLayoutDriftFailsLoudly(t *testing.T) {
	// A redesign that stops emitting records must not read as "this vendor is not
	// authorized" — that answer would be indistinguishable from a real one, for every
	// vendor at once (CLAUDE.md: breakage is loud).
	src, _ := fedrampServer(t, "fedramp_no_records.html")

	section, err := src.Fetch(context.Background(),
		Query{Company: "Okta"}, ResolvedEntity{CanonicalName: "Okta"})
	if err == nil {
		t.Error("Fetch returned no error for a page with no records")
	}
	if section.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", section.Status, StatusFailed)
	}
	if !strings.Contains(section.Err, "layout has changed") {
		t.Errorf("Err = %q, want it to name layout drift as the cause", section.Err)
	}
	if section.Data != nil {
		t.Error("Data is set on a failed section; a broken parse has no trustworthy value")
	}
}

func TestFedRAMPUnlistedVendorIsOKNotSkipped(t *testing.T) {
	src, _ := fedrampServer(t, "fedramp_products.html")

	section, err := src.Fetch(context.Background(),
		Query{Company: "Nonexistent Vendor Co"},
		ResolvedEntity{CanonicalName: "Nonexistent Vendor Co"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Most vendors are not on the marketplace. With the catalogue parsed successfully that
	// is a real, sourced answer, not a gap and not a failure.
	if section.Status != StatusOK {
		t.Fatalf("Status = %q, want %q", section.Status, StatusOK)
	}

	result := section.Data.(FedRAMPResult)
	if len(result.Offerings) != 0 {
		t.Errorf("matched %d offerings for a vendor not on the marketplace", len(result.Offerings))
	}
	// A healthy record count is what makes the empty result trustworthy rather than silent.
	if result.TotalRecords == 0 {
		t.Error("TotalRecords = 0; an empty result is only meaningful alongside a healthy parse")
	}
}

func TestFedRAMPMatchesOnAliases(t *testing.T) {
	src, _ := fedrampServer(t, "fedramp_products.html")

	// A vendor is often listed under a name the analyst did not type. The alias that
	// matched is recorded so an analyst can confirm it is the right company.
	section, err := src.Fetch(context.Background(),
		Query{Company: "Auth0"},
		ResolvedEntity{CanonicalName: "Auth0", Aliases: []string{"Okta, Inc."}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	result := section.Data.(FedRAMPResult)
	if len(result.Offerings) != 2 {
		t.Fatalf("matched %d offerings via alias, want 2", len(result.Offerings))
	}
	for _, o := range result.Offerings {
		if o.MatchedAlias != "Okta, Inc." {
			t.Errorf("MatchedAlias = %q, want the alias that matched", o.MatchedAlias)
		}
	}
}

func TestNormalizeVendorName(t *testing.T) {
	// Conservative on purpose: fold case, punctuation and corporate suffixes, nothing else.
	// Fuzzier matching would attach one company's authorization to another, which is the
	// same class of silent error as a wrong CPE.
	same := [][2]string{
		{"Okta", "Okta, Inc."},
		{"Okta Inc", "OKTA  INCORPORATED"},
		{"Netskope, Inc.", "netskope"},
		{"Monster Government Solutions", "monster government solutions"},
		{"NICE CXone", "NiCE CXone"},
	}
	for _, pair := range same {
		if a, b := normalizeVendorName(pair[0]), normalizeVendorName(pair[1]); a != b {
			t.Errorf("normalizeVendorName(%q)=%q != normalizeVendorName(%q)=%q",
				pair[0], a, pair[1], b)
		}
	}

	different := [][2]string{
		{"Okta", "Okta Federal"},
		{"Oracle", "Oracle America"},
		{"Microsoft", "Micro Focus"},
		// Stripping suffixes must never empty a name into matching everything.
		{"Group", "Holdings"},
	}
	for _, pair := range different {
		if a, b := normalizeVendorName(pair[0]), normalizeVendorName(pair[1]); a == b {
			t.Errorf("normalizeVendorName collapsed %q and %q both to %q", pair[0], pair[1], a)
		}
	}
}

func TestVendorNamesPrefersCanonicalAndDeduplicates(t *testing.T) {
	names := vendorNames(
		Query{Company: "okta"},
		ResolvedEntity{CanonicalName: "Okta, Inc.", Aliases: []string{"Auth0", "Okta"}})

	// The canonical name leads, aliases follow, and names that normalize alike appear once —
	// otherwise a single listing would be reported as several matches.
	if len(names) != 2 {
		t.Fatalf("names = %v, want the canonical name and one distinct alias", names)
	}
	if names[0] != "Okta, Inc." {
		t.Errorf("names[0] = %q, want the canonical name first", names[0])
	}
	if names[1] != "Auth0" {
		t.Errorf("names[1] = %q, want the distinct alias", names[1])
	}
}

func TestFedRAMPHTTPErrorFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	src := NewFedRAMP(WithFedRAMPURL(srv.URL), WithFedRAMPClient(srv.Client()))
	section, err := src.Fetch(context.Background(), Query{Company: "Okta"}, ResolvedEntity{})
	if err == nil {
		t.Error("Fetch returned no error for HTTP 503")
	}
	if section.Status != StatusFailed {
		t.Errorf("Status = %q, want %q", section.Status, StatusFailed)
	}
	if !strings.Contains(section.Err, "503") {
		t.Errorf("Err = %q, want it to carry the status code", section.Err)
	}
}

func TestFedRAMPProductionFloorRejectsATinyPage(t *testing.T) {
	// The default floor is what protects production, so assert it directly rather than
	// only ever exercising the lowered one the fixture needs.
	if _, err := parseFedRAMPRecords(readFixture(t, "fedramp_products.html"), fedrampMinRecords); err == nil {
		t.Error("the production floor accepted a 4-record page")
	}
}
