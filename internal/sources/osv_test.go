package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var vaultPkg = Package{Ecosystem: "Go", Name: "github.com/hashicorp/vault"}

// --- parsing against recorded fixtures ---------------------------------------

func TestParseOSVQueryFixture(t *testing.T) {
	vulns, next, err := parseOSVQuery(fixture(t, "osv_vault_go.json"), vaultPkg)
	if err != nil {
		t.Fatalf("parseOSVQuery: %v", err)
	}
	if next != "" {
		t.Errorf("next page token = %q, want empty", next)
	}
	if len(vulns) != 6 {
		t.Fatalf("parsed %d vulns, want 6", len(vulns))
	}

	byID := make(map[string]OSVVuln, len(vulns))
	for _, v := range vulns {
		byID[v.ID] = v
	}

	// Carries both CVSS_V3 and CVSS_V4: the newer revision wins, because vectors from
	// different revisions are not comparable.
	got := byID["GHSA-j6vv-vv26-rh7c"]
	if got.CVSSType != "CVSS_V4" {
		t.Errorf("CVSSType = %q, want CVSS_V4", got.CVSSType)
	}
	if !strings.HasPrefix(got.CVSSVector, "CVSS:4.0/") {
		t.Errorf("vector %q is not the v4 one", got.CVSSVector)
	}
	if got.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", got.Severity)
	}
	// The CVE alias is what cross-references this to the NVD section.
	if len(got.CVEs) != 1 || got.CVEs[0] != "CVE-2020-10661" {
		t.Errorf("CVEs = %v, want [CVE-2020-10661]", got.CVEs)
	}
	if got.URL != "https://osv.dev/vulnerability/GHSA-j6vv-vv26-rh7c" {
		t.Errorf("URL = %q", got.URL)
	}
	if got.Package != vaultPkg {
		t.Errorf("Package = %v, want %v", got.Package, vaultPkg)
	}

	// Real data: this advisory has no severity array and no database_specific.severity.
	// It must survive as an unrated advisory rather than being dropped or scored.
	unrated := byID["GO-2022-0578"]
	if unrated.ID == "" {
		t.Fatal("the advisory with no severity was dropped")
	}
	if unrated.CVSSVector != "" || unrated.Severity != "" {
		t.Errorf("invented a severity: %+v", unrated)
	}
	if len(unrated.CVEs) == 0 {
		t.Error("unrated advisory lost its CVE alias")
	}
}

// TestParseOSVQueryCleanPackage: OSV answers a clean package with a bare "{}".
func TestParseOSVQueryCleanPackage(t *testing.T) {
	vulns, next, err := parseOSVQuery(fixture(t, "osv_clean.json"), vaultPkg)
	if err != nil {
		t.Fatalf("a package with no advisories is a legitimate answer, not a parse failure: %v", err)
	}
	if len(vulns) != 0 || next != "" {
		t.Errorf("got %d vulns, token %q, want 0/empty", len(vulns), next)
	}
}

func TestParseOSVQueryRejectsMalformed(t *testing.T) {
	if _, _, err := parseOSVQuery([]byte(`{"vulns":`), vaultPkg); err == nil {
		t.Error("truncated JSON accepted")
	}
	// A shape change that drops ids must be loud, not silently render blank rows.
	if _, _, err := parseOSVQuery([]byte(`{"vulns":[{"summary":"x"}]}`), vaultPkg); err == nil {
		t.Error("advisory without an id accepted")
	}
}

// TestOSVSeverityVocabularyIsNotTranslated guards a deliberate choice: GitHub says
// MODERATE, NVD says MEDIUM, and restating one in the other's words would launder a value.
func TestOSVSeverityVocabularyIsNotTranslated(t *testing.T) {
	vulns, _, err := parseOSVQuery(fixture(t, "osv_vault_go.json"), vaultPkg)
	if err != nil {
		t.Fatalf("parseOSVQuery: %v", err)
	}
	var sawModerate bool
	for _, v := range vulns {
		if v.Severity == "MEDIUM" {
			t.Errorf("%s: MODERATE was rewritten as MEDIUM", v.ID)
		}
		if v.Severity == "MODERATE" {
			sawModerate = true
		}
	}
	if !sawModerate {
		t.Fatal("fixture no longer covers the MODERATE case")
	}
}

func TestCountOSVSeverities(t *testing.T) {
	counts := countOSVSeverities([]OSVVuln{
		{Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "MODERATE"},
		{Severity: "MEDIUM"}, {Severity: "LOW"}, {Severity: ""},
	})
	want := OSVSeverityCounts{Critical: 1, High: 1, Moderate: 2, Low: 1, Unrated: 1}
	if counts != want {
		t.Errorf("counts = %+v, want %+v", counts, want)
	}
}

func TestCVEAliases(t *testing.T) {
	got := cveAliases([]string{"BIT-vault-2021-38553", "CVE-2021-38553", "GO-2022-0620"})
	if len(got) != 1 || got[0] != "CVE-2021-38553" {
		t.Errorf("got %v, want only the CVE identifier", got)
	}
}

// --- Fetch -------------------------------------------------------------------

func newTestOSV(t *testing.T, h http.HandlerFunc) *OSV {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewOSV(WithOSVBaseURL(srv.URL), WithOSVHTTPClient(srv.Client()))
}

// TestFetchOSVSkipsWithoutPackages is the common case, not an edge case: most vendors
// publish no OSS at all.
func TestFetchOSVSkipsWithoutPackages(t *testing.T) {
	o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be made without packages")
	})

	sec, err := o.Fetch(context.Background(), Query{Company: "Wachtell"}, ResolvedEntity{})
	if err != nil {
		t.Fatalf("no packages must not be an error: %v", err)
	}
	if sec.Status != StatusSkipped {
		t.Fatalf("status = %s, want skipped", sec.Status)
	}
	if sec.Note == "" {
		t.Error("a skipped section must say why")
	}
}

func TestFetchOSVHappyPath(t *testing.T) {
	var gotBody osvQueryRequest
	o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/query" {
			t.Errorf("path = %s, want /v1/query", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.Write(fixture(t, "osv_vault_go.json"))
	})

	sec, err := o.Fetch(context.Background(), Query{Company: "HashiCorp"},
		ResolvedEntity{CanonicalName: "HashiCorp", Packages: []Package{vaultPkg}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sec.Status != StatusOK {
		t.Fatalf("status = %s, err = %s", sec.Status, sec.Err)
	}

	// Ecosystem must always be sent: OSV rejects a name-only query with HTTP 400.
	if gotBody.Package.Ecosystem != "Go" || gotBody.Package.Name != vaultPkg.Name {
		t.Errorf("request package = %+v, want the full pair", gotBody.Package)
	}

	res, ok := sec.Data.(OSVResult)
	if !ok {
		t.Fatalf("Data is %T, want OSVResult", sec.Data)
	}
	if res.TotalVulns != 6 {
		t.Errorf("TotalVulns = %d, want 6", res.TotalVulns)
	}
	if res.Severity.Critical == 0 || res.Severity.Unrated == 0 {
		t.Errorf("severity counts look wrong: %+v", res.Severity)
	}
	if len(sec.Citations) != res.TotalVulns {
		t.Errorf("got %d citations for %d vulns", len(sec.Citations), res.TotalVulns)
	}
	// Most severe first, and stable.
	if res.Vulns[0].Severity != "CRITICAL" {
		t.Errorf("first vuln severity = %q, want CRITICAL", res.Vulns[0].Severity)
	}
	if last := res.Vulns[len(res.Vulns)-1]; last.Severity != "" {
		t.Errorf("last vuln severity = %q, want the unrated one sorted last", last.Severity)
	}
}

func TestFetchOSVCleanPackageIsOKNotSkipped(t *testing.T) {
	o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "osv_clean.json"))
	})

	sec, err := o.Fetch(context.Background(), Query{Company: "Okta"},
		ResolvedEntity{Packages: []Package{{Ecosystem: "npm", Name: "@okta/okta-auth-js"}}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// "We looked and found nothing" is a different claim from "we did not look."
	if sec.Status != StatusOK {
		t.Fatalf("status = %s, want ok", sec.Status)
	}
	res := sec.Data.(OSVResult)
	if res.TotalVulns != 0 {
		t.Errorf("TotalVulns = %d, want 0", res.TotalVulns)
	}
	if len(res.Queries) != 1 || res.Queries[0].TotalVulns != 0 {
		t.Errorf("the package we checked must still be listed: %+v", res.Queries)
	}
}

func TestFetchOSVDedupesAcrossPackages(t *testing.T) {
	o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "osv_vault_go.json"))
	})

	sec, err := o.Fetch(context.Background(), Query{Company: "HashiCorp"}, ResolvedEntity{
		Packages: []Package{
			vaultPkg,
			{Ecosystem: "Go", Name: "github.com/hashicorp/consul"},
		},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	res := sec.Data.(OSVResult)
	// The same advisory affecting two packages is counted once.
	if res.TotalVulns != 6 {
		t.Errorf("TotalVulns = %d, want 6 after dedup", res.TotalVulns)
	}
	if len(res.Queries) != 2 {
		t.Errorf("both packages must be listed: %+v", res.Queries)
	}
}

func TestFetchOSVFollowsPageTokens(t *testing.T) {
	var calls int
	o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		var req osvQueryRequest
		json.Unmarshal(body, &req)

		if req.PageToken == "" {
			fmt.Fprint(w, `{"vulns":[{"id":"GHSA-page-1"}],"next_page_token":"tok"}`)
			return
		}
		if req.PageToken != "tok" {
			t.Errorf("page_token = %q, want tok", req.PageToken)
		}
		fmt.Fprint(w, `{"vulns":[{"id":"GHSA-page-2"}]}`)
	})

	sec, err := o.Fetch(context.Background(), Query{Company: "X"},
		ResolvedEntity{Packages: []Package{vaultPkg}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d requests, want 2", calls)
	}
	if res := sec.Data.(OSVResult); res.TotalVulns != 2 {
		t.Errorf("TotalVulns = %d, want 2 across both pages", res.TotalVulns)
	}
}

// TestFetchOSVPaginationIsBounded: a server always returning a token must not loop forever.
func TestFetchOSVPaginationIsBounded(t *testing.T) {
	var calls int
	o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprintf(w, `{"vulns":[{"id":"GHSA-%d"}],"next_page_token":"always"}`, calls)
	})

	sec, err := o.Fetch(context.Background(), Query{Company: "X"},
		ResolvedEntity{Packages: []Package{vaultPkg}})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls != osvMaxPages {
		t.Errorf("made %d requests, want the %d-page cap", calls, osvMaxPages)
	}
	// Truncation must be visible, not silent.
	if res := sec.Data.(OSVResult); !res.Queries[0].Truncated {
		t.Error("a truncated walk must be reported")
	}
}

func TestFetchOSVHTTPErrorsBecomeFailed(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{http.StatusBadRequest, "ecosystem"},
		{http.StatusTooManyRequests, "rate limit"},
		{http.StatusServiceUnavailable, "503"},
		{http.StatusInternalServerError, "500"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			o := newTestOSV(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
			})

			sec, err := o.Fetch(context.Background(), Query{Company: "X"},
				ResolvedEntity{Packages: []Package{vaultPkg}})
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

func TestNormalizePackage(t *testing.T) {
	tests := []struct {
		ecosystem, name string
		want            Package
		ok              bool
	}{
		{"npm", "@okta/okta-auth-js", Package{"npm", "@okta/okta-auth-js"}, true},
		// Informal spellings the model reaches for map to OSV's exact capitalization.
		{"pypi", "django", Package{"PyPI", "django"}, true},
		{"golang", "github.com/hashicorp/vault", Package{"Go", "github.com/hashicorp/vault"}, true},
		{"cargo", "serde", Package{"crates.io", "serde"}, true},
		{" NPM ", " left-pad ", Package{"npm", "left-pad"}, true},
		// Distro ecosystems are out of scope and would need a release suffix we cannot know.
		{"Debian", "openssl", Package{}, false},
		{"NotAnEcosystem", "thing", Package{}, false},
		{"npm", "", Package{}, false},
		{"", "lodash", Package{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem+"/"+tt.name, func(t *testing.T) {
			got, ok := normalizePackage(tt.ecosystem, tt.name)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tt.ok, got)
			}
			if ok && got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
