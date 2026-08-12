package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- parsing against recorded fixtures ---------------------------------------

func TestParseNVDCVEsFixture(t *testing.T) {
	page, err := parseNVDCVEs(fixture(t, "nvd_cves_okta.json"))
	if err != nil {
		t.Fatalf("parseNVDCVEs: %v", err)
	}
	if page.total != 12 {
		t.Errorf("total = %d, want 12", page.total)
	}
	if len(page.vulns) != 12 {
		t.Fatalf("parsed %d vulns, want 12", len(page.vulns))
	}

	byID := make(map[string]NVDVuln, len(page.vulns))
	for _, v := range page.vulns {
		byID[v.ID] = v
	}

	// A CVE carrying both cvssMetricV31 and cvssMetricV2: v3.1 wins on version
	// precedence, and the primary NVD scorer wins over the secondary MITRE one.
	got := byID["CVE-2021-28113"]
	if got.BaseScore != 6.7 {
		t.Errorf("CVE-2021-28113 score = %v, want 6.7 (the v3.1 score, not the v2 8.7)", got.BaseScore)
	}
	if got.Severity != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", got.Severity)
	}
	if got.CVSSVersion != "3.1" {
		t.Errorf("version = %q, want 3.1", got.CVSSVersion)
	}
	if !strings.Contains(got.ScoreSource, "Primary") || !strings.Contains(got.ScoreSource, "nvd@nist.gov") {
		t.Errorf("ScoreSource = %q, want the primary NVD analysis", got.ScoreSource)
	}
	if got.URL != "https://nvd.nist.gov/vuln/detail/CVE-2021-28113" {
		t.Errorf("URL = %q", got.URL)
	}
	if !strings.Contains(got.Description, "command injection") {
		t.Errorf("description not the English one: %q", got.Description)
	}

	// Real data: these two carry only a secondary GitHub score. They must still be
	// reported, with the source recorded so it is not mistaken for NVD's own analysis.
	for _, id := range []string{"CVE-2025-66033", "CVE-2025-67505"} {
		v := byID[id]
		if v.BaseScore == 0 {
			t.Errorf("%s: secondary-only CVE lost its score", id)
		}
		if !strings.Contains(v.ScoreSource, "Secondary") {
			t.Errorf("%s: ScoreSource = %q, want it marked Secondary", id, v.ScoreSource)
		}
	}

	// ssvcV203 appears alongside CVSS in this fixture and must not be mistaken for a score.
	if v := byID["CVE-2022-3145"]; v.CVSSVersion != "3.1" {
		t.Errorf("CVE-2022-3145 version = %q, want 3.1 (ssvcV203 must be ignored)", v.CVSSVersion)
	}
}

func TestParseNVDCVEsEmptyIsNotAnError(t *testing.T) {
	page, err := parseNVDCVEs(fixture(t, "nvd_cves_empty.json"))
	if err != nil {
		t.Fatalf("an empty result set is a legitimate answer, not a parse failure: %v", err)
	}
	if page.total != 0 || len(page.vulns) != 0 {
		t.Errorf("got total=%d vulns=%d, want 0/0", page.total, len(page.vulns))
	}
}

func TestParseNVDCPEsFixture(t *testing.T) {
	page, err := parseNVDCPEs(fixture(t, "nvd_cpes_okta_vendor.json"))
	if err != nil {
		t.Fatalf("parseNVDCPEs: %v", err)
	}
	if page.total == 0 {
		t.Fatal("totalResults lost")
	}
	// The dictionary lists one row per version; only distinct products are useful.
	tokens := CPECatalogue{Products: page.products}.Tokens()
	want := "access_gateway"
	if !containsString(tokens, want) {
		t.Errorf("products = %v, want it to contain %q", tokens, want)
	}
	// The whole point of this lookup: NVD has no product literally named "okta".
	if containsString(tokens, "okta") {
		t.Error("fixture unexpectedly contains an okta:okta product")
	}
	for i := 1; i < len(tokens); i++ {
		if tokens[i-1] > tokens[i] {
			t.Fatalf("products not sorted: %v", tokens)
		}
	}
	// The title travels with the token. It is what makes the catalogue readable when it is
	// offered to the model as a list of choices, and a token-only list resolves worse.
	for _, p := range page.products {
		if p.Title == "" {
			t.Errorf("product %q carries no English title", p.Token)
		}
	}
	// rows is what decides whether a page saw everything; totalResults counts rows on the
	// server. This fixture is a real 9-row page of a 287-row vendor, so they must differ.
	if page.rows != len(fixtureProducts(t, "nvd_cpes_okta_vendor.json")) {
		t.Errorf("rows = %d, want it to count the entries actually received", page.rows)
	}
	if page.rows >= page.total {
		t.Errorf("rows=%d total=%d: this fixture is a partial page and must read as one",
			page.rows, page.total)
	}
}

// fixtureProducts counts the raw product entries in a dictionary fixture, independently of
// the parser under test.
func fixtureProducts(t *testing.T, name string) []any {
	t.Helper()
	var resp struct {
		Products []any `json:"products"`
	}
	if err := json.Unmarshal(fixture(t, name), &resp); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return resp.Products
}

func TestParseNVDCPEsEmpty(t *testing.T) {
	page, err := parseNVDCPEs(fixture(t, "nvd_cpes_empty.json"))
	if err != nil {
		t.Fatalf("parseNVDCPEs: %v", err)
	}
	if page.total != 0 || len(page.products) != 0 {
		t.Errorf("got total=%d products=%d, want 0/0", page.total, len(page.products))
	}
}

func TestParseNVDRejectsMalformed(t *testing.T) {
	if _, err := parseNVDCVEs([]byte(`{"totalResults":`)); err == nil {
		t.Error("truncated CVE JSON accepted")
	}
	if _, err := parseNVDCPEs([]byte(`not json`)); err == nil {
		t.Error("non-JSON dictionary response accepted")
	}
	// A shape change that drops the id must be loud, not silently produce blank rows.
	body := []byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"published":"2024-01-01"}}]}`)
	if _, err := parseNVDCVEs(body); err == nil {
		t.Error("CVE entry without an id accepted")
	}
	body = []byte(`{"totalResults":1,"products":[{"cpe":{"cpeName":"garbage"}}]}`)
	if _, err := parseNVDCPEs(body); err == nil {
		t.Error("malformed cpeName accepted")
	}
}

// --- metric selection --------------------------------------------------------

func TestSelectMetricPrefersNewestVersionThenPrimary(t *testing.T) {
	primaryNVD := nvdMetric{Source: "nvd@nist.gov", Type: "Primary"}
	primaryNVD.CVSSData.BaseScore = 5

	secondary := nvdMetric{Source: "cna@example.com", Type: "Secondary"}
	secondary.CVSSData.BaseScore = 9

	otherPrimary := nvdMetric{Source: "cna@example.com", Type: "Primary"}
	otherPrimary.CVSSData.BaseScore = 7

	tests := []struct {
		name    string
		metrics map[string][]nvdMetric
		wantKey string
		wantSrc string
	}{
		{
			name: "v3.1 beats v2 even when v2 scores higher",
			metrics: map[string][]nvdMetric{
				"cvssMetricV2":  {secondary},
				"cvssMetricV31": {primaryNVD},
			},
			wantKey: "cvssMetricV31",
			wantSrc: "nvd@nist.gov",
		},
		{
			name: "v4.0 beats v3.1",
			metrics: map[string][]nvdMetric{
				"cvssMetricV31": {primaryNVD},
				"cvssMetricV40": {secondary},
			},
			wantKey: "cvssMetricV40",
			wantSrc: "cna@example.com",
		},
		{
			name: "NVD's primary wins over another primary in the same version",
			metrics: map[string][]nvdMetric{
				"cvssMetricV31": {otherPrimary, primaryNVD},
			},
			wantKey: "cvssMetricV31",
			wantSrc: "nvd@nist.gov",
		},
		{
			name: "any primary beats a secondary",
			metrics: map[string][]nvdMetric{
				"cvssMetricV31": {secondary, otherPrimary},
			},
			wantKey: "cvssMetricV31",
			wantSrc: "cna@example.com",
		},
		{
			name: "a non-CVSS system is never selected",
			metrics: map[string][]nvdMetric{
				"ssvcV203": {{Source: "cisa"}},
			},
			wantKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, key, ok := selectMetric(tt.metrics)
			if tt.wantKey == "" {
				if ok {
					t.Fatalf("selected %q, want no selection", key)
				}
				return
			}
			if !ok {
				t.Fatal("no metric selected")
			}
			if key != tt.wantKey {
				t.Errorf("key = %q, want %q", key, tt.wantKey)
			}
			if m.Source != tt.wantSrc {
				t.Errorf("source = %q, want %q", m.Source, tt.wantSrc)
			}
		})
	}
}

// TestMetricSeverityReadsPerVersionLocation guards the difference that is easiest to miss:
// CVSS v2 records baseSeverity beside cvssData, v3.x and v4.0 record it inside.
func TestMetricSeverityReadsPerVersionLocation(t *testing.T) {
	var v2 nvdMetric
	v2.BaseSeverity = "HIGH"
	if got := metricSeverity(v2); got != "HIGH" {
		t.Errorf("v2 severity = %q, want HIGH", got)
	}

	var v31 nvdMetric
	v31.CVSSData.BaseSeverity = "CRITICAL"
	if got := metricSeverity(v31); got != "CRITICAL" {
		t.Errorf("v3.1 severity = %q, want CRITICAL", got)
	}
}

func TestCountSeveritiesKeepsUnscoredSeparate(t *testing.T) {
	counts := countSeverities([]NVDVuln{
		{Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "HIGH"},
		{Severity: "MEDIUM"}, {Severity: "LOW"}, {Severity: ""},
	})
	want := NVDSeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1, Unscored: 1}
	if counts != want {
		t.Errorf("counts = %+v, want %+v", counts, want)
	}
}

// --- CPE match strings -------------------------------------------------------

func TestCPEMatchStrings(t *testing.T) {
	got := cpeMatchStrings([]string{
		"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:access_gateway:2021.03.6:*:*:*:*:*:*:*", // same product, deduped
		"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta", // too short to name a product
		"",
	})
	want := []string{
		"cpe:2.3:a:okta:access_gateway",
		"cpe:2.3:a:okta:verify",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestVendorMatchString(t *testing.T) {
	if got := vendorMatchString("cpe:2.3:a:okta:okta"); got != "cpe:2.3:a:okta" {
		t.Errorf("got %q, want cpe:2.3:a:okta", got)
	}
	if got := vendorMatchString("cpe:2.3:a"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- Fetch -------------------------------------------------------------------

func newTestNVD(t *testing.T, h http.HandlerFunc, apiKey string) *NVD {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	// Zero interval: tests must not pay NVD's six-second courtesy delay.
	return NewNVD(apiKey,
		WithNVDBaseURL(srv.URL),
		WithNVDHTTPClient(srv.Client()),
		WithNVDRateInterval(0),
	)
}

func oktaEntity(cpes ...string) ResolvedEntity {
	return ResolvedEntity{CanonicalName: "Okta, Inc.", CPEs: cpes}
}

func TestFetchNVDHappyPath(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/cves/2.0") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("virtualMatchString"); got != "cpe:2.3:a:okta:access_gateway" {
			t.Errorf("virtualMatchString = %q", got)
		}
		// cpeName rejects wildcard versions with a 404, so it must never be used.
		if r.URL.Query().Has("cpeName") {
			t.Error("cpeName must not be used; it rejects version-agnostic CPEs")
		}
		w.Write(fixture(t, "nvd_cves_okta.json"))
	}, "")

	sec, err := n.Fetch(context.Background(), Query{Company: "Okta"},
		oktaEntity("cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sec.Status != StatusOK {
		t.Fatalf("status = %s, err = %s", sec.Status, sec.Err)
	}

	res, ok := sec.Data.(NVDResult)
	if !ok {
		t.Fatalf("Data is %T, want NVDResult", sec.Data)
	}
	if res.TotalCVEs != 12 {
		t.Errorf("TotalCVEs = %d, want 12", res.TotalCVEs)
	}
	if res.Severity.High == 0 || res.Severity.Medium == 0 {
		t.Errorf("severity counts look wrong: %+v", res.Severity)
	}
	if len(res.Queries) != 1 || res.Queries[0].Verification != NVDVerifiedByResults {
		t.Errorf("queries = %+v", res.Queries)
	}
	// Sorted most severe first, so the same data always renders the same way.
	for i := 1; i < len(res.CVEs); i++ {
		if res.CVEs[i-1].BaseScore < res.CVEs[i].BaseScore {
			t.Fatalf("CVEs not sorted by score: %v", res.CVEs)
		}
	}
	if len(sec.Citations) != res.TotalCVEs {
		t.Errorf("got %d citations for %d CVEs", len(sec.Citations), res.TotalCVEs)
	}
}

func TestFetchNVDSkipsWithoutCPEs(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be made without a CPE")
	}, "")

	sec, err := n.Fetch(context.Background(), Query{Company: "Obscure Ltd"}, ResolvedEntity{})
	if err != nil {
		t.Fatalf("no CPEs must not be an error: %v", err)
	}
	if sec.Status != StatusSkipped {
		t.Fatalf("status = %s, want skipped", sec.Status)
	}
	if sec.Note == "" {
		t.Error("a skipped section must say why")
	}
}

// TestFetchNVDDistinguishesCleanFromInvented is the heart of this source: NVD answers
// 200/totalResults 0 for both, and rendering them the same way is the silently-wrong report
// spec §15 warns about.
func TestFetchNVDDistinguishesCleanFromInvented(t *testing.T) {
	tests := []struct {
		name         string
		dictionary   string
		wantStatus   Status
		wantVerified NVDVerification
	}{
		{
			name:         "vendor is genuinely clean",
			dictionary:   "nvd_cpes_okta_vendor.json", // product exists, just no CVEs
			wantStatus:   StatusOK,
			wantVerified: NVDVerifiedInDictionary,
		},
		{
			name:         "CPE does not exist",
			dictionary:   "nvd_cpes_empty.json",
			wantStatus:   StatusFailed,
			wantVerified: NVDUnverified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dictCalls int
			n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/cves/"):
					w.Write(fixture(t, "nvd_cves_empty.json"))
				case strings.HasPrefix(r.URL.Path, "/cpes/"):
					dictCalls++
					// The first dictionary call checks the product; a second, only on
					// failure, enumerates the vendor's real products.
					if dictCalls == 1 {
						w.Write(fixture(t, tt.dictionary))
						return
					}
					w.Write(fixture(t, "nvd_cpes_okta_vendor.json"))
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			}, "")

			sec, _ := n.Fetch(context.Background(), Query{Company: "Okta"},
				oktaEntity("cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*"))

			if sec.Status != tt.wantStatus {
				t.Fatalf("status = %s (err %q), want %s", sec.Status, sec.Err, tt.wantStatus)
			}

			if tt.wantStatus == StatusFailed {
				// The verdict travels on the section, not only in the prose. Without it a
				// caller cannot tell "NVD judged these fictional" from "NVD never answered",
				// and the resolution cache pins an invented CPE for 720h on the difference.
				res, ok := sec.Data.(NVDResult)
				if !ok {
					t.Fatalf("failed section carries no NVDResult (Data = %T)", sec.Data)
				}
				if res.AnyVerified() {
					t.Error("AnyVerified() on an all-invented result")
				}
				// The error must point at entity resolution and name the real products,
				// so the analyst can correct it rather than merely distrust it.
				if !strings.Contains(sec.Err, "cpe:2.3:a:okta:okta") {
					t.Errorf("error does not name the bad CPE: %s", sec.Err)
				}
				if !strings.Contains(sec.Err, "access_gateway") {
					t.Errorf("error does not name NVD's real products: %s", sec.Err)
				}
				// A failed section still carries no *answer*. The result attached above is
				// verdicts only — no CVE list and no total — so there is nothing
				// answer-shaped for a caller to mistake for a clean vendor. The renderer
				// reads Data on StatusOK alone, and only OK sections are ever cached.
				if res.TotalCVEs != 0 || len(res.CVEs) != 0 {
					t.Errorf("failed section carries an answer: TotalCVEs=%d CVEs=%d",
						res.TotalCVEs, len(res.CVEs))
				}
				return
			}

			res := sec.Data.(NVDResult)
			if res.Queries[0].Verification != tt.wantVerified {
				t.Errorf("verification = %q, want %q", res.Queries[0].Verification, tt.wantVerified)
			}
			if res.TotalCVEs != 0 {
				t.Errorf("TotalCVEs = %d, want 0", res.TotalCVEs)
			}
		})
	}
}

// TestFetchNVDPartialVerificationStillReports: one bad CPE must not discard a good one.
func TestFetchNVDPartialVerificationStillReports(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cpes/") {
			w.Write(fixture(t, "nvd_cpes_empty.json"))
			return
		}
		if r.URL.Query().Get("virtualMatchString") == "cpe:2.3:a:okta:access_gateway" {
			w.Write(fixture(t, "nvd_cves_okta.json"))
			return
		}
		w.Write(fixture(t, "nvd_cves_empty.json"))
	}, "")

	sec, err := n.Fetch(context.Background(), Query{Company: "Okta"}, oktaEntity(
		"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*",
	))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sec.Status != StatusOK {
		t.Fatalf("status = %s, want ok — real CVEs must not be discarded", sec.Status)
	}
	res := sec.Data.(NVDResult)
	if res.TotalCVEs != 12 {
		t.Errorf("TotalCVEs = %d, want 12", res.TotalCVEs)
	}
	if len(res.Queries) != 2 {
		t.Fatalf("got %d queries, want 2", len(res.Queries))
	}
	if res.Queries[1].Verification != NVDUnverified {
		t.Errorf("the invented CPE must still be flagged: %+v", res.Queries[1])
	}
}

func TestFetchNVDDedupesAcrossCPEs(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "nvd_cves_okta.json"))
	}, "")

	sec, err := n.Fetch(context.Background(), Query{Company: "Okta"}, oktaEntity(
		"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*",
	))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The same 12 CVEs come back for both CPEs; a CVE must be counted once.
	if res := sec.Data.(NVDResult); res.TotalCVEs != 12 {
		t.Errorf("TotalCVEs = %d, want 12 after dedup", res.TotalCVEs)
	}
}

func TestFetchNVDPaginates(t *testing.T) {
	var calls int
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		start := r.URL.Query().Get("startIndex")
		// Two pages of one CVE each, out of a claimed total of two.
		id := "CVE-2024-0001"
		if start != "0" {
			id = "CVE-2024-0002"
		}
		fmt.Fprintf(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":%q,"metrics":{}}}]}`, id)
	}, "")
	n.resultsPerCPE = 5

	sec, err := n.Fetch(context.Background(), Query{Company: "X"},
		oktaEntity("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d requests, want 2 pages", calls)
	}
	if res := sec.Data.(NVDResult); res.TotalCVEs != 2 {
		t.Errorf("TotalCVEs = %d, want 2", res.TotalCVEs)
	}
}

// TestFetchNVDPaginationTerminatesOnInconsistentTotal: a server claiming more results than
// it serves must not spin the loop forever.
func TestFetchNVDPaginationTerminatesOnInconsistentTotal(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"totalResults":99,"vulnerabilities":[]}`))
	}, "")

	done := make(chan struct{})
	go func() {
		defer close(done)
		n.Fetch(context.Background(), Query{Company: "X"},
			oktaEntity("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pagination did not terminate")
	}
}

func TestFetchNVDCapsCPEs(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "nvd_cves_okta.json"))
	}, "")
	n.maxCPEs = 1

	sec, err := n.Fetch(context.Background(), Query{Company: "Okta"}, oktaEntity(
		"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*",
	))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	res := sec.Data.(NVDResult)
	if len(res.Queries) != 1 {
		t.Errorf("queried %d CPEs, want 1", len(res.Queries))
	}
	// A capped CPE must be reported, never silently dropped.
	if len(res.Unqueried) != 1 || res.Unqueried[0] != "cpe:2.3:a:okta:verify" {
		t.Errorf("Unqueried = %v, want the skipped CPE named", res.Unqueried)
	}
}

func TestFetchNVDSendsAPIKeyAsHeader(t *testing.T) {
	const key = "test-nvd-key"
	var gotHeader, gotURL string
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("apiKey")
		gotURL = r.URL.String()
		w.Write(fixture(t, "nvd_cves_okta.json"))
	}, key)

	if _, err := n.Fetch(context.Background(), Query{Company: "Okta"},
		oktaEntity("cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*")); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotHeader != key {
		t.Errorf("apiKey header = %q, want %q", gotHeader, key)
	}
	// In the URL it would end up in url.Error strings, which are rendered.
	if strings.Contains(gotURL, key) {
		t.Errorf("API key leaked into the query string: %s", gotURL)
	}
}

func TestNewNVDPicksIntervalFromKey(t *testing.T) {
	if got := NewNVD("").interval; got != nvdUnkeyedInterval {
		t.Errorf("unkeyed interval = %v, want %v", got, nvdUnkeyedInterval)
	}
	if got := NewNVD("key").interval; got != nvdKeyedInterval {
		t.Errorf("keyed interval = %v, want %v", got, nvdKeyedInterval)
	}
}

func TestNVDRateLimiterSpacesRequests(t *testing.T) {
	var calls int
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write(fixture(t, "nvd_cves_okta.json"))
	}, "")
	n.interval = 40 * time.Millisecond

	start := time.Now()
	if _, err := n.Fetch(context.Background(), Query{Company: "Okta"}, oktaEntity(
		"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:mobile:*:*:*:*:*:*:*:*",
	)); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls != 3 {
		t.Fatalf("made %d requests, want 3", calls)
	}
	// Three requests means at least two gaps.
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Errorf("3 requests took %v, want the rate limiter to space them out", elapsed)
	}
}

func TestFetchNVDHTTPErrorsBecomeFailed(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{http.StatusNotFound, "404"},
		{http.StatusForbidden, EnvNVDKeyName},
		{http.StatusTooManyRequests, "rate limit"},
		{http.StatusServiceUnavailable, "503"},
		{http.StatusInternalServerError, "500"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
			}, "")

			sec, err := n.Fetch(context.Background(), Query{Company: "Okta"},
				oktaEntity("cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*"))
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

// TestFetchNVDDeadlineIsPartialNotFailure: whatever already came back is still true.
func TestFetchNVDDeadlineIsPartialNotFailure(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture(t, "nvd_cves_okta.json"))
	}, "")
	n.interval = 300 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	sec, err := n.Fetch(ctx, Query{Company: "Okta"}, oktaEntity(
		"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*",
	))
	if err != nil {
		t.Fatalf("a deadline mid-walk is a partial answer, not a failure: %v", err)
	}
	if sec.Status != StatusOK {
		t.Fatalf("status = %s, want ok", sec.Status)
	}
	res := sec.Data.(NVDResult)
	if len(res.Unqueried) == 0 {
		t.Error("the CPEs we ran out of time for must be reported")
	}
}

func TestFetchNVDNeverLeaksAPIKey(t *testing.T) {
	const canary = "canary-nvd-key-do-not-render"
	n := newTestNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		// NVD echoing the rejected credential back is exactly what must not reach a report.
		w.Write([]byte(`{"message":"invalid apiKey ` + canary + `"}`))
	}, canary)

	sec, err := n.Fetch(context.Background(), Query{Company: "Okta"},
		oktaEntity("cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*"))

	if strings.Contains(sec.Err, canary) {
		t.Errorf("API key leaked into Section.Err: %s", sec.Err)
	}
	if strings.Contains(sec.Note, canary) {
		t.Errorf("API key leaked into Section.Note: %s", sec.Note)
	}
	if err != nil && strings.Contains(err.Error(), canary) {
		t.Errorf("API key leaked into the error: %v", err)
	}
	if fmt.Sprintf("%+v", sec) != "" && strings.Contains(fmt.Sprintf("%+v", sec), canary) {
		t.Error("API key leaked into the rendered section")
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestNVDResultAnyVerified(t *testing.T) {
	cases := []struct {
		name  string
		verds []NVDVerification
		want  bool
	}{
		{"no queries at all", nil, false},
		{"every CPE invented", []NVDVerification{NVDUnverified, NVDUnverified}, false},
		{"one confirmed by CVEs", []NVDVerification{NVDVerifiedByResults}, true},
		{"one confirmed by the dictionary", []NVDVerification{NVDVerifiedInDictionary}, true},
		// A mapping can be good enough to cache while still carrying an invented entry.
		// NVD names that entry loudly on every run, which is the correction path.
		{"mixed", []NVDVerification{NVDUnverified, NVDVerifiedInDictionary}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var res NVDResult
			for _, v := range tc.verds {
				res.Queries = append(res.Queries, NVDQuery{Verification: v})
			}
			if got := res.AnyVerified(); got != tc.want {
				t.Errorf("AnyVerified() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- VendorProducts: the catalogue entity resolution picks from ---------------
//
// This is the authoritative half of CPE resolution. The model proposes a vendor; NVD says
// which products exist under it. Everything downstream is bounded by what these tests cover.

func TestVendorProductsReadsTheCatalogue(t *testing.T) {
	var queries []string
	n := newTestNVD(t, func(w http.ResponseWriter, req *http.Request) {
		queries = append(queries, req.URL.RawQuery)
		_, _ = w.Write(fixture(t, "nvd_cpes_okta_vendor.json"))
	}, "")

	cat, err := n.VendorProducts(context.Background(), "cpe:2.3:a:okta", "")
	if err != nil {
		t.Fatalf("VendorProducts: %v", err)
	}
	if !cat.Exists() {
		t.Fatal("a vendor with 287 dictionary rows does not exist")
	}
	if got := strings.Join(cat.Tokens(), ","); !strings.Contains(got, "access_gateway") {
		t.Errorf("products = %s, want the real Okta catalogue", got)
	}
	// The trap this whole path exists to close: NVD registers no product called "okta".
	if cat.Has("okta") {
		t.Error("catalogue claims an okta:okta product")
	}
	// A 9-row page of a 287-row vendor is a sample, and saying otherwise would turn "not in
	// this page" into "NVD does not register it".
	if cat.Complete {
		t.Errorf("Complete = true for a %d-row page of %d rows", len(cat.Products), cat.TotalRows)
	}
	if len(queries) != 1 {
		t.Errorf("made %d requests, want 1: no narrowing term was given", len(queries))
	}
	if strings.Contains(queries[0], "keywordSearch") {
		t.Errorf("unfiltered lookup sent a keywordSearch: %s", queries[0])
	}
}

// A page that covered every row NVD holds is exhaustive, and only then may it say so.
func TestVendorProductsCompleteWhenThePageCoversEverything(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(fixture(t, "nvd_cpes_okta_gateway.json"))
	}, "")

	cat, err := n.VendorProducts(context.Background(), "cpe:2.3:a:okta", "")
	if err != nil {
		t.Fatalf("VendorProducts: %v", err)
	}
	if !cat.Complete {
		t.Errorf("Complete = false for a %d-row page of %d rows", len(cat.Products), cat.TotalRows)
	}
}

// Microsoft holds 15,183 dictionary rows — eight pages, and at the unkeyed six-second
// interval most of an assessment's budget. The service narrows it to one page instead.
func TestVendorProductsNarrowsAnOversizedVendor(t *testing.T) {
	var queries []string
	n := newTestNVD(t, func(w http.ResponseWriter, req *http.Request) {
		queries = append(queries, req.URL.RawQuery)
		if req.URL.Query().Get("keywordSearch") != "" {
			_, _ = w.Write(fixture(t, "nvd_cpes_okta_gateway.json"))
			return
		}
		_, _ = w.Write(fixture(t, "nvd_cpes_okta_vendor.json"))
	}, "")

	cat, err := n.VendorProducts(context.Background(), "cpe:2.3:a:okta", "Access Gateway")
	if err != nil {
		t.Fatalf("VendorProducts: %v", err)
	}
	if len(queries) != 2 {
		t.Fatalf("made %d requests, want 2: unfiltered, then narrowed", len(queries))
	}
	if !strings.Contains(queries[1], "keywordSearch=Access+Gateway") {
		t.Errorf("second request did not carry the narrowing term: %s", queries[1])
	}
	if cat.Narrowed != "Access Gateway" {
		t.Errorf("Narrowed = %q, want the term recorded so the caller can qualify the answer",
			cat.Narrowed)
	}
	if !cat.Complete || len(cat.Products) != 1 {
		t.Errorf("got %d products, Complete=%v; want the narrowed page", len(cat.Products), cat.Complete)
	}
}

// A keyword matching nothing has said nothing about the vendor. Returning it would turn "too
// big to read" into "this vendor registers no products", which is the confident wrong answer.
func TestVendorProductsKeepsThePartialListWhenNarrowingFindsNothing(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("keywordSearch") != "" {
			_, _ = w.Write(fixture(t, "nvd_cpes_empty.json"))
			return
		}
		_, _ = w.Write(fixture(t, "nvd_cpes_okta_vendor.json"))
	}, "")

	cat, err := n.VendorProducts(context.Background(), "cpe:2.3:a:okta", "nothing matches this")
	if err != nil {
		t.Fatalf("VendorProducts: %v", err)
	}
	if !cat.Exists() {
		t.Fatal("a vendor NVD holds 287 rows for came back as unregistered")
	}
	if len(cat.Products) != 9 || cat.Narrowed != "" {
		t.Errorf("got %d products narrowed by %q, want the unfiltered page kept",
			len(cat.Products), cat.Narrowed)
	}
}

// A vendor NVD has never heard of. Distinct from a failure, and the caller must be able to
// tell: one means the company registers no CPEs, the other means we could not look.
func TestVendorProductsOnAnUnknownVendor(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(fixture(t, "nvd_cpes_empty.json"))
	}, "")

	cat, err := n.VendorProducts(context.Background(), "cpe:2.3:a:notavendor", "SSO")
	if err != nil {
		t.Fatalf("an unregistered vendor is an answer, not an error: %v", err)
	}
	if cat.Exists() || len(cat.Products) != 0 {
		t.Errorf("got %+v, want an empty catalogue", cat)
	}
}

func TestVendorProductsHTTPErrorIsAnError(t *testing.T) {
	n := newTestNVD(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, "")

	if _, err := n.VendorProducts(context.Background(), "cpe:2.3:a:okta", ""); err == nil {
		t.Fatal("VendorProducts swallowed HTTP 503")
	}
}
