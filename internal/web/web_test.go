package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aalcar/vrm/internal/report"
	"github.com/aalcar/vrm/internal/sources"
)

// renderReport executes the report template the way the handler does, without a database or a
// pipeline behind it. The template is what Phase 11's acceptance criterion is about — the
// pipeline it renders is already covered in internal/assess.
func renderReport(t *testing.T, r report.Report) string {
	t.Helper()
	tmpl, err := template.New("vrm").Funcs(funcs()).ParseFS(templateFS,
		"templates/*.html", "templates/*.css", "templates/partials/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "report.html", r); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return b.String()
}

func baseReport() report.Report {
	return report.Report{
		Query:            sources.Query{Company: "Okta", Service: "SSO"},
		CacheKey:         [2]string{"okta", "sso"},
		ConfigPath:       "config.yaml",
		ResolutionModel:  "claude-sonnet-5",
		ResearchModel:    "claude-sonnet-5",
		AutomatedSources: []string{"bitsight", "nvd"},
		ManualSources:    []string{"ssllabs"},
		Full:             true,
		Entity: sources.ResolvedEntity{
			CanonicalName: "Okta, Inc.",
			Domains:       []string{"okta.com"},
			CPEs:          []string{"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*"},
			Packages:      []sources.Package{{Ecosystem: "npm", Name: "@okta/okta-auth-js"}},
		},
	}
}

// TestEveryFieldIsEscaped is the Phase 11 acceptance criterion: "all external data
// HTML-escaped".
//
// Not a formality. Every string below arrives from a vendor API, a scraped page, or a language
// model — none of them are places this tool controls, and the CA AG and FedRAMP sections are
// literally parsed out of someone else's HTML. A single template.HTML anywhere in the render
// path turns a scraped page into script execution in an analyst's browser.
func TestEveryFieldIsEscaped(t *testing.T) {
	const payload = `<script>alert('xss')</script>`

	r := baseReport()
	r.Entity.CanonicalName = payload
	r.Entity.Domains = []string{payload}
	r.Resolution.CPEOrigin = payload
	r.Resolution.Dropped = []string{payload}
	r.Sections = []sources.Section{
		sources.Failed(sources.SourceBitSight, errors.New(payload)),
		sources.Skipped(sources.SourceOSV, payload),
		sources.OK(sources.SourceCAAG, sources.CAAGResult{
			Searched: []string{payload},
			Entries: []sources.CAAGEntry{{
				Organization: payload, SearchedAs: "other",
				BreachDates: []string{payload}, ReportedDate: payload,
				ReportURL: "https://oag.ca.gov/x",
			}},
		}),
		sources.OK(sources.SourceFedRAMP, sources.FedRAMPResult{
			Offerings: []sources.FedRAMPOffering{{
				Offering: payload, Status: payload, ImpactLevel: payload,
				Provider: payload, MatchedAlias: payload, URL: "https://marketplace.fedramp.gov/x",
			}},
		}),
		sources.OK("ssllabs", sources.ManualResult{
			Value: payload, RecordedAt: time.Now(), URL: "https://www.ssllabs.com/ssltest",
		}),
		sources.OK(sources.SourceResearch, sources.Research{
			SupplierDescription: sources.Finding{
				Value:     payload,
				Citations: []sources.Citation{{Title: payload, URL: "https://example.com/"}},
			},
			Dropped: []string{payload},
		}),
	}

	got := renderReport(t, r)
	if strings.Contains(got, payload) {
		t.Fatal("an unescaped <script> tag reached the page")
	}
	// And it is present, escaped — otherwise this test would also pass on a template that
	// silently dropped every field.
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("the payload is neither escaped nor present; the fields may not render at all:\n%s", got)
	}
}

// TestAJavascriptURLIsNeutralised. Citation and report URLs come from a model and from scraped
// pages, so one can perfectly well be "javascript:...". html/template filters URL contexts,
// and this pins that the links really are in one.
func TestAJavascriptURLIsNeutralised(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceBitSight, sources.BitSightRating{
			CompanyName: "Okta", PrimaryDomain: "okta.com", Rating: 780,
		}, sources.Citation{Title: "click", URL: "javascript:alert(1)"}),
	}

	got := renderReport(t, r)
	if strings.Contains(got, "javascript:alert") {
		t.Errorf("a javascript: URL survived into an href:\n%s", got)
	}
	if !strings.Contains(got, "#ZgotmplZ") {
		t.Error("html/template did not treat the href as a URL context")
	}
}

// TestTheBrowserAndTerminalAgreeOnOutcomes. Both renderers label sections from
// report.Rows/Summarize, so a skip means the same thing in both. This is the test that fails
// if the web UI ever grows its own opinion.
func TestTheBrowserAndTerminalAgreeOnOutcomes(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceCAAG, sources.CAAGResult{Searched: []string{"okta"}}),
		sources.Failed(sources.SourceBitSight, errors.New("HTTP 403")),
		sources.Skipped(sources.SourceOSV, "no packages"),
		sources.Skipped("ssllabs", "no entry recorded"),
	}

	got := renderReport(t, r)
	for _, row := range r.Rows() {
		want := string(row.Outcome)
		if !strings.Contains(got, ">"+want+"<") {
			t.Errorf("section %q is not labelled %q in the HTML", row.Section.Source, want)
		}
	}
	if !strings.Contains(got, "awaiting manual check") {
		t.Error("a manual skip lost its distinct label in the browser")
	}
	// The counts are wrapped in <b>, so compare against the summary the terminal renderer
	// would have used rather than against a hand-written string.
	sum := r.Summarize()
	for _, want := range []string{
		fmt.Sprintf("<b>%d</b> answered", len(sum.OK)),
		fmt.Sprintf("<b>%d</b> failed", len(sum.Failed)),
		fmt.Sprintf("<b>%d</b> unanswered", len(sum.Unanswered)),
		fmt.Sprintf("<b>%d</b> awaiting a manual check", len(sum.Awaiting)),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary counts do not match Summarize: missing %q", want)
		}
	}
}

// TestAnUnrenderableDataTypeIsNotSilent is the map failure, in the browser.
//
// A cached Section.Data that decoded into a map matches none of the type-assertion funcs. With
// no fallback the section would be a heading with an empty body — an "ok" badge claiming an
// answer that is not there, which is the strongest claim this tool can make and the one it can
// least support.
func TestAnUnrenderableDataTypeIsNotSilent(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceBitSight, map[string]any{"rating": 780},
			sources.Citation{Title: "BitSight", URL: "https://service.bitsighttech.com/"}),
	}

	if got := renderReport(t, r); !strings.Contains(got, "https://service.bitsighttech.com/") {
		t.Errorf("a section the template could not match rendered nothing at all:\n%s", got)
	}
}

// TestEmptyResultsKeepTheirQualifier. A FedRAMP section with no offerings and a CA AG section
// with no entries are successful answers, and both are meaningless without the qualifier that
// says what was searched — "not on the marketplace" and "we could not read the marketplace"
// look identical otherwise.
func TestEmptyResultsKeepTheirQualifier(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceFedRAMP, sources.FedRAMPResult{
			Searched: []string{"okta"}, TotalRecords: 691,
		}),
		sources.OK(sources.SourceCAAG, sources.CAAGResult{Searched: []string{"okta"}}),
	}

	got := renderReport(t, r)
	for _, want := range []string{"691", "no listing for", "no California-reported breaches"} {
		if !strings.Contains(got, want) {
			t.Errorf("an empty-but-successful section lost %q:\n%s", want, got)
		}
	}
}

// TestAnUnverifiedZeroSaysSo. NVD answers 200/totalResults 0 both for a clean vendor and for a
// CPE that does not exist, so the products it does register for that vendor have to appear
// beside the zero or it reads as a clean result.
func TestAnUnverifiedZeroSaysSo(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceNVD, sources.NVDResult{
			Queries: []sources.NVDQuery{{
				CPE: "cpe:2.3:a:okta:okta", TotalResults: 0,
				Verification:  sources.NVDUnverified,
				KnownProducts: []string{"access_gateway", "verify"},
			}},
			Unqueried: []string{"cpe:2.3:a:okta:mobile:*:*:*:*:*:*:*:*"},
		}),
	}

	got := renderReport(t, r)
	for _, want := range []string{"access_gateway", "not queried", "cpe:2.3:a:okta:mobile"} {
		if !strings.Contains(got, want) {
			t.Errorf("the NVD section lost %q:\n%s", want, got)
		}
	}
}

// TestTheCPEOriginIsSuppressedByAnOverride matches the terminal. The origin describes how the
// model arrived at its CPEs, and an override means those are not what was queried.
func TestTheCPEOriginIsSuppressedByAnOverride(t *testing.T) {
	r := baseReport()
	r.Resolution.CPEOrigin = "chosen from NVD's dictionary"

	if got := renderReport(t, r); !strings.Contains(got, "chosen from NVD") {
		t.Error("the CPE origin is missing when there is no override")
	}
	r.CPEsOverridden = true
	if got := renderReport(t, r); strings.Contains(got, "chosen from NVD") {
		t.Error("the model's CPE origin was shown under an analyst's overridden CPEs")
	}
}

// TestTheFormRenders is the smoke test for the page HTMX lives on: it must carry the script,
// the target it swaps into, and the post it swaps from.
func TestTheFormRenders(t *testing.T) {
	s, err := New(nil, "config.yaml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`hx-post="/assess"`, `hx-target="#report"`, `id="report"`,
		"htmx.org@2.0.10", "integrity=", `name="company"`, `name="service"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form is missing %q", want)
		}
	}
}

// TestABadCPEOverrideIsRefused. Silently querying fewer CPEs than asked for would look
// identical to a vendor with nothing to find.
func TestABadCPEOverrideIsRefused(t *testing.T) {
	s, err := New(nil, "config.yaml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/assess",
		strings.NewReader("company=Okta&service=SSO&cpe=not-a-cpe"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "not-a-cpe") {
		t.Errorf("the rejected override is not named in the response: %s", rec.Body.String())
	}
	// 200 so htmx swaps it in. The runner is nil here, so reaching it would panic; not
	// reaching it is the other half of the assertion.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; htmx will not swap a non-2xx, so the analyst sees a stale report", rec.Code)
	}
}

// TestAFailureIsSwappable. HTMX does not swap a non-2xx response by default, so a 500 would
// leave the previous report on screen with nothing to say the new run failed.
func TestAFailureIsSwappable(t *testing.T) {
	s, err := New(nil, "config.yaml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	s.fail(rec, errors.New(`resolution failed for <script>alert(1)</script>`))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; htmx will not swap it", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<script>alert") {
		t.Error("the error message was not escaped; it can quote form input")
	}
}

// TestCappedNeverLosesRows pins the arithmetic behind the "+N more" line. A cap that says the
// wrong number understates a vendor's CVE count, which is the one direction that matters.
func TestCappedNeverLosesRows(t *testing.T) {
	rows := make([]int, 25)
	for _, full := range []bool{false, true} {
		got := capped(rows, full)
		shown := 0
		if s, ok := got.Shown.([]int); ok {
			shown = len(s)
		}
		if shown+got.Held != len(rows) {
			t.Errorf("full=%v: %d shown + %d held != %d rows", full, shown, got.Held, len(rows))
		}
	}
	if got := capped(rows, false); got.Held != 15 {
		t.Errorf("Held = %d, want 15", got.Held)
	}
	if got := capped(rows, true); got.Held != 0 {
		t.Errorf("a full render held back %d rows", got.Held)
	}
}
