package report

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aalcar/vrm/internal/sources"
)

// -update rewrites the golden files. Run it after a deliberate rendering change and read the
// diff — the point of a golden file is that a change to the report is something a human looked
// at, not something a test quietly accepted.
var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got against testdata/<name>.golden.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")

	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if got != string(want) {
		t.Errorf("rendered report does not match %s\n--- want ---\n%s\n--- got ---\n%s",
			path, want, got)
	}
}

func render(t *testing.T, r Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

// baseReport is the surrounding scaffolding, with no sections. Tests add their own.
func baseReport() Report {
	return Report{
		Query:            sources.Query{Company: "Okta", Service: "SSO"},
		CacheKey:         [2]string{"okta", "sso"},
		ConfigPath:       "config.yaml",
		ResolutionModel:  "claude-sonnet-5",
		ResearchModel:    "claude-sonnet-5",
		AutomatedSources: []string{"bitsight", "nvd", "osv", "fedramp", "caag", "llm_research"},
		ManualSources:    []string{"cvedetails", "ssllabs", "openbugbounty"},
		NVDKeyPresent:    true,
		Entity: sources.ResolvedEntity{
			CanonicalName: "Okta, Inc.",
			Domains:       []string{"okta.com"},
			CPEs: []string{
				"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
			},
			Packages: []sources.Package{{Ecosystem: "npm", Name: "@okta/okta-auth-js"}},
			Aliases:  []string{"Auth0"},
		},
		Resolution: sources.Resolution{
			CPEOrigin: "chosen from the 9 products NVD registers under cpe:2.3:a:okta",
			Dropped:   []string{`product "okta" (not registered under cpe:2.3:a:okta)`},
		},
	}
}

// everySection is one fully-populated section per source, in the order the fan-out emits them.
// Every field is set: a golden file over zero values would pass for a renderer that dropped
// half of them.
func everySection() []sources.Section {
	return []sources.Section{
		sources.OK(sources.SourceBitSight, sources.BitSightRating{
			CompanyName:    "Okta, Inc.",
			CompanyGUID:    "0dc8b4a6-0000-0000-0000-000000000000",
			PrimaryDomain:  "okta.com",
			Industry:       "Technology",
			Rating:         780,
			RatingRange:    "Advanced",
			RatingDate:     "2026-08-01",
			IndustryMedian: "above",
			ReportURL:      "https://service.bitsighttech.com/app/company/0dc8b4a6/overview/",
			QueriedDomain:  "okta.com",
			Alternatives:   []string{"Okta Government Solutions", "Auth0"},
		}, sources.Citation{Title: "BitSight", URL: "https://service.bitsighttech.com/"}),

		sources.OK(sources.SourceNVD, sources.NVDResult{
			Queries: []sources.NVDQuery{
				{
					CPE:          "cpe:2.3:a:okta:verify",
					TotalResults: 2,
					Verification: sources.NVDVerifiedByResults,
				},
				{
					// An unverified zero, with the products NVD does register for that vendor.
					// Without those, the zero reads as a clean result.
					CPE:           "cpe:2.3:a:okta:okta",
					TotalResults:  0,
					Verification:  sources.NVDUnverified,
					KnownProducts: []string{"access_gateway", "verify"},
				},
			},
			Unqueried: []string{"cpe:2.3:a:okta:mobile:*:*:*:*:*:*:*:*"},
			TotalCVEs: 2,
			Severity:  sources.NVDSeverityCounts{Critical: 1, Unscored: 1},
			CVEs: []sources.NVDVuln{
				{
					ID:           "CVE-2024-0001",
					Published:    "2024-01-02T00:00:00.000",
					LastModified: "2024-02-03T00:00:00.000",
					Description:  "An example advisory.",
					BaseScore:    9.8,
					Severity:     "CRITICAL",
					CVSSVersion:  "3.1",
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					ScoreSource:  "Primary",
					URL:          "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
				},
				{
					// Unscored, and scored by a CNA rather than NVD itself. Both have their own
					// line so a CNA's number is never mistaken for NVD's analysis.
					ID:          "CVE-2024-0002",
					Published:   "2024-05-06T00:00:00.000",
					ScoreSource: "GitHub, Inc.",
					URL:         "https://nvd.nist.gov/vuln/detail/CVE-2024-0002",
				},
			},
		}),

		sources.OK(sources.SourceOSV, sources.OSVResult{
			Queries: []sources.OSVQuery{{
				Package:    sources.Package{Ecosystem: "npm", Name: "@okta/okta-auth-js"},
				TotalVulns: 2,
				Truncated:  true,
			}},
			TotalVulns: 2,
			Severity:   sources.OSVSeverityCounts{Moderate: 1, Unrated: 1},
			Vulns: []sources.OSVVuln{
				{
					ID:         "GHSA-xxxx-yyyy-zzzz",
					Package:    sources.Package{Ecosystem: "npm", Name: "@okta/okta-auth-js"},
					Summary:    "An example advisory.",
					Published:  "2024-01-02T00:00:00Z",
					Aliases:    []string{"CVE-2024-0003"},
					CVEs:       []string{"CVE-2024-0003"},
					Severity:   "MODERATE",
					CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
					CVSSType:   "CVSS_V3",
					URL:        "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz",
				},
				{
					// Unrated and with no CVE alias: OSV supplies a vector, not a score, and an
					// advisory with neither must still render as a line rather than vanish.
					ID:      "GHSA-aaaa-bbbb-cccc",
					Package: sources.Package{Ecosystem: "npm", Name: "@okta/okta-auth-js"},
					URL:     "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
				},
			},
		}),

		sources.Skipped("cvedetails",
			"no entry recorded — Search the vendor; record CVE counts (https://www.cvedetails.com)"),

		sources.OK(sources.SourceFedRAMP, sources.FedRAMPResult{
			Offerings: []sources.FedRAMPOffering{{
				ID:           "F1234567890",
				Provider:     "Okta, Inc.",
				Offering:     "Okta Identity Cloud",
				Status:       "FedRAMP Certified",
				Phase:        "Authorized",
				AuthType:     "Agency",
				AuthCategory: "Rev5",
				ImpactLevel:  "High",
				URL:          "https://marketplace.fedramp.gov/products/F1234567890",
				MatchedAlias: "Okta Government Solutions",
			}},
			Searched:     []string{"okta, inc.", "auth0", "okta"},
			TotalRecords: 691,
		}),

		sources.OK(sources.SourceCAAG, sources.CAAGResult{
			Entries: []sources.CAAGEntry{{
				Organization: "Okta, Inc.",
				BreachDates:  []string{"2021-08-01", "2021-08-17"},
				ReportedDate: "2021-08-23",
				ReportURL:    "https://oag.ca.gov/ecrime/databreach/reports/sb24-000000",
				SearchedAs:   "Okta",
			}},
			Searched: []string{"okta, inc.", "auth0", "okta"},
		}),

		researchSection(),

		sources.OK("ssllabs", sources.ManualResult{
			Value:       "A+\nno weak ciphers",
			RecordedAt:  time.Date(2026, 8, 12, 9, 30, 0, 0, time.UTC),
			Instruction: "Scan the service hostname; record the grade",
			URL:         "https://www.ssllabs.com/ssltest",
		}),

		sources.Skipped("openbugbounty",
			"no entry recorded — Search the vendor domain; record open/fixed counts "+
				"(https://www.openbugbounty.org)"),
	}
}

func researchSection() sources.Section {
	return sources.OK(sources.SourceResearch, sources.Research{
		SupplierDescription: sources.Finding{
			Value:     "Okta is an identity provider.",
			Citations: []sources.Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
		},
		ServiceDescription: sources.Finding{
			Value:     "Single sign-on.",
			Citations: []sources.Citation{{Title: "Okta SSO", URL: "https://www.okta.com/products/single-sign-on/"}},
		},
		ServiceImplementation: sources.Finding{
			Value:     "Cloud-hosted SaaS.",
			Citations: []sources.Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
		},
		SupplierWebsite: sources.Finding{
			Value:     "https://www.okta.com/",
			Citations: []sources.Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
		},
		ServiceWebsite: sources.Finding{
			Value:     "https://www.okta.com/products/single-sign-on/",
			Citations: []sources.Citation{{Title: "Okta SSO", URL: "https://www.okta.com/products/single-sign-on/"}},
		},
		SecurityPage: sources.Finding{
			Value:     "https://www.okta.com/security/",
			Citations: []sources.Citation{{Title: "Okta security", URL: "https://www.okta.com/security/"}},
		},
		NotificationPage: sources.Finding{
			Value:     "https://status.okta.com/",
			Citations: []sources.Citation{{Title: "Okta status", URL: "https://status.okta.com/"}},
		},
		Locations: []sources.Location{
			{
				Finding: sources.Finding{
					Value:     "San Francisco headquarters.",
					Citations: []sources.Citation{{Title: "Okta contact", URL: "https://www.okta.com/contact/"}},
				},
				Kind:    "headquarters",
				Country: "United States",
				City:    "San Francisco, California",
			},
			{
				// No city: the renderer must fall back to the country rather than print a
				// leading comma.
				Finding: sources.Finding{
					Value:     "Data residency in the EU.",
					Citations: []sources.Citation{{Title: "Okta trust", URL: "https://trust.okta.com/"}},
				},
				Kind:    "data residency",
				Country: "Ireland",
			},
		},
		CyberLawsuits: []sources.Lawsuit{{
			Finding: sources.Finding{
				Value:     "A shareholder suit following the 2022 Lapsus$ disclosure.",
				Citations: []sources.Citation{{Title: "Reuters", URL: "https://www.reuters.com/example"}},
			},
			Outcome:        "dismissed",
			ResolutionDate: "2024-03-01",
		}},
		PastBreaches: []sources.Finding{{
			Value:     "January 2022 Lapsus$ compromise of a support engineer's laptop.",
			Citations: []sources.Citation{{Title: "Okta blog", URL: "https://www.okta.com/blog/example/"}},
		}},
		UsedKaspersky:  sources.TriNoEvidence,
		MOVEitImpacted: sources.TriYes,
		MOVEitEvidence: sources.Finding{
			Value:     "Named in a MOVEit-related filing.",
			Citations: []sources.Citation{{Title: "Example", URL: "https://www.example.com/moveit"}},
		},
		Dropped:       []string{`past_breaches[1]: dropped an uncited claim`},
		SearchResults: []sources.Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
	})
}

// TestRenderFullReport is the pin. Every source, every optional line, one file a human can
// read top to bottom — which is exactly the Phase 10 acceptance criterion, and not something a
// per-field assertion would ever demonstrate.
func TestRenderFullReport(t *testing.T) {
	r := baseReport()
	r.Sections = everySection()
	golden(t, "full", render(t, r))
}

// TestRenderDegradedReport is the other half of the tool's job: what it looks like when things
// go wrong. Failures, unverified zeros, empty-but-successful sections, an unresolved entity.
// A report is most load-bearing when it has the least to say.
func TestRenderDegradedReport(t *testing.T) {
	r := Report{
		Query:            sources.Query{Company: "Some Vendor", Service: "Widget"},
		CacheKey:         [2]string{"some vendor", "widget"},
		ConfigPath:       "config.yaml",
		ResolutionModel:  "claude-sonnet-5",
		ResearchModel:    "claude-sonnet-5",
		AutomatedSources: []string{"bitsight", "nvd", "fedramp"},
		ManualSources:    []string{"ssllabs"},
		NoCache:          true,
		Entity: sources.ResolvedEntity{
			CanonicalName: "Some Vendor",
		},
		Resolution: sources.Resolution{
			CPEOrigin: "no vendor token matched NVD's dictionary, so no CPE was queried",
		},
		Sections: []sources.Section{
			sources.Failed(sources.SourceBitSight,
				errors.New("BitSight rejected the credentials (HTTP 403); check BITSIGHT_API_KEY")),
			sources.Skipped(sources.SourceNVD, "no CPEs resolved for this vendor"),
			// Successful and empty, which is the line that has to carry its own qualifier.
			sources.OK(sources.SourceFedRAMP, sources.FedRAMPResult{
				Searched:     []string{"some vendor"},
				TotalRecords: 691,
			}),
			sources.OK(sources.SourceCAAG, sources.CAAGResult{Searched: []string{"some vendor"}}),
			sources.Failed(sources.SourceResearch, errors.New(
				"the model returned no checklist fields\nrerun with --no-cache to try again")),
			sources.Skipped("ssllabs",
				"no entry recorded — Scan the service hostname; record the grade "+
					"(https://www.ssllabs.com/ssltest)"),
		},
	}
	golden(t, "degraded", render(t, r))
}

// TestTheTwoKindsOfSkipAreLabelledDifferently is the whole point of the outcome type. Both
// sections below carry StatusSkipped, and they mean unrelated things: one is a gap in the
// data, the other is a task assigned to the person reading the report. Labelling both
// "skipped" makes an analyst read every note to find the ones addressed to them.
func TestTheTwoKindsOfSkipAreLabelledDifferently(t *testing.T) {
	r := baseReport()
	r.ManualSources = []string{"ssllabs"}
	r.Sections = []sources.Section{
		sources.Skipped(sources.SourceOSV, "no open-source packages resolved for this vendor"),
		sources.Skipped("ssllabs", "no entry recorded — Scan the service hostname"),
	}

	got := render(t, r)
	if !strings.Contains(got, "osv            unanswered") {
		t.Errorf("an automated skip is not labelled unanswered:\n%s", got)
	}
	if !strings.Contains(got, "ssllabs        awaiting manual check") {
		t.Errorf("a manual skip is not labelled as awaiting a check:\n%s", got)
	}
	// And the summary separates them too, so the counts do not merge the task into the gap.
	if !strings.Contains(got, "0 failed, 1 unanswered, 1 awaiting a manual check") {
		t.Errorf("the summary merged the two kinds of skip:\n%s", got)
	}
}

// TestTheSummaryNamesEveryCategoryThatProducedNothing. A count alone would tell an analyst
// something is missing without telling them what, which is the same slow reread the summary
// exists to avoid.
func TestTheSummaryNamesEveryCategoryThatProducedNothing(t *testing.T) {
	r := baseReport()
	r.ManualSources = []string{"ssllabs"}
	r.Sections = []sources.Section{
		sources.OK(sources.SourceCAAG, sources.CAAGResult{Searched: []string{"okta"}}),
		sources.Failed(sources.SourceBitSight, errors.New("HTTP 403")),
		sources.Failed(sources.SourceNVD, errors.New("HTTP 503")),
		sources.Skipped(sources.SourceOSV, "no packages"),
		sources.Skipped("ssllabs", "no entry recorded"),
	}

	got := render(t, r)
	for _, want := range []string{
		"5 categories: 1 answered, 2 failed, 1 unanswered, 1 awaiting a manual check",
		"failed:     bitsight, nvd",
		"unanswered: osv",
		"awaiting:   ssllabs",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not contain %q:\n%s", want, got)
		}
	}
}

// TestACleanAssessmentHasANoiselessSummary. A line reading "failed: (none)" is a line an
// analyst has to read to learn nothing; an assessment with no problems should look like one.
func TestACleanAssessmentHasANoiselessSummary(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceCAAG, sources.CAAGResult{Searched: []string{"okta"}}),
	}

	got := render(t, r)
	for _, unwanted := range []string{"failed:", "unanswered:", "awaiting:"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("an empty bucket printed a %q line:\n%s", unwanted, got)
		}
	}
	if !strings.Contains(got, "1 category: 1 answered") {
		t.Errorf("the count line is missing:\n%s", got)
	}
}

// manyCVEs builds n CVEs, worst first, the way NVD's section orders them.
func manyCVEs(n int) []sources.NVDVuln {
	out := make([]sources.NVDVuln, 0, n)
	for i := range n {
		out = append(out, sources.NVDVuln{
			ID:          fmt.Sprintf("CVE-2024-%04d", i+1),
			Published:   "2024-01-02T00:00:00.000",
			BaseScore:   9.9 - float64(i)/10,
			Severity:    "HIGH",
			CVSSVersion: "3.1",
			ScoreSource: "Primary",
			URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-2024-%04d", i+1),
		})
	}
	return out
}

func cappedReport(full bool) Report {
	r := baseReport()
	r.Full = full
	r.Sections = []sources.Section{
		sources.OK(sources.SourceNVD, sources.NVDResult{
			Queries: []sources.NVDQuery{{
				CPE:          "cpe:2.3:a:okta:verify",
				TotalResults: 25,
				Verification: sources.NVDVerifiedByResults,
			}},
			TotalCVEs: 25,
			// Counted over all 25, not over the rows that get printed.
			Severity: sources.NVDSeverityCounts{High: 25},
			CVEs:     manyCVEs(25),
		}),
	}
	return r
}

// TestALongListSaysWhatItHeldBack is the rule that makes a cap acceptable at all. A list that
// simply stops reads as the complete answer, which is the same failure as an identifier
// dropped without a word — and here it would understate a vendor's CVE count to an analyst
// deciding whether to onboard them.
func TestALongListSaysWhatItHeldBack(t *testing.T) {
	got := render(t, cappedReport(false))

	if !strings.Contains(got, "… +15 more (use --full)") {
		t.Errorf("a capped list did not say how many rows it held back:\n%s", got)
	}
	if !strings.Contains(got, "CVE-2024-0010") {
		t.Error("the tenth CVE was not printed; the cap took effect too early")
	}
	if strings.Contains(got, "CVE-2024-0011") {
		t.Error("the eleventh CVE was printed; the cap did not take effect")
	}
	// The counts are over everything. Capping the listing must never quietly cap the totals —
	// the severity line is what an analyst reads before deciding whether to read further.
	if !strings.Contains(got, "severity: critical=0 high=25") {
		t.Errorf("the severity counts were computed over the printed rows, not all of them:\n%s", got)
	}
}

// TestFullPrintsEverything is the escape hatch the truncation line advertises. A flag named in
// the output that does not work is worse than no flag.
func TestFullPrintsEverything(t *testing.T) {
	got := render(t, cappedReport(true))

	if strings.Contains(got, "use --full") {
		t.Error("--full still printed a truncation line")
	}
	for _, id := range []string{"CVE-2024-0001", "CVE-2024-0011", "CVE-2024-0025"} {
		if !strings.Contains(got, id) {
			t.Errorf("--full did not print %s", id)
		}
	}
}

// TestAListAtTheCapIsNotAnnouncedAsTruncated pins the boundary. An "+0 more" line, or a cap
// that fired one row early, would both be reported by this.
func TestAListAtTheCapIsNotAnnouncedAsTruncated(t *testing.T) {
	r := baseReport()
	r.Sections = []sources.Section{
		sources.OK(sources.SourceNVD, sources.NVDResult{
			TotalCVEs: detailCap,
			Severity:  sources.NVDSeverityCounts{High: detailCap},
			CVEs:      manyCVEs(detailCap),
		}),
	}

	got := render(t, r)
	if strings.Contains(got, "more (use --full)") {
		t.Errorf("a list of exactly %d rows was announced as truncated:\n%s", detailCap, got)
	}
	if !strings.Contains(got, fmt.Sprintf("CVE-2024-%04d", detailCap)) {
		t.Errorf("the last row of an uncapped list was not printed:\n%s", got)
	}
}

// TestOverridesAndCacheMarkersAreVisible. An override changes what was queried and a cache hit
// means nothing was queried at all; both are facts about the run that an analyst reading the
// numbers has to be able to see.
func TestOverridesAndCacheMarkersAreVisible(t *testing.T) {
	r := baseReport()
	r.DomainOverridden = true
	r.CPEsOverridden = true
	r.ResolutionCached = true
	r.Sections = []sources.Section{
		func() sources.Section {
			s := sources.OK(sources.SourceBitSight, sources.BitSightRating{
				CompanyName: "Okta, Inc.", PrimaryDomain: "okta.com",
				Rating: 780, RatingRange: "Advanced", RatingDate: "2026-08-01",
			})
			s.Cached = true
			return s
		}(),
	}

	got := render(t, r)
	for _, want := range []string{
		"(cached; --no-cache re-resolves)",
		"(overridden by --domain)",
		"(overridden by --cpe)",
		"bitsight       ok (cached)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not show %q:\n%s", want, got)
		}
	}
}

// TestTheCPEOriginIsSuppressedByAnOverride. The origin describes how the model arrived at its
// CPEs, and an override means those are not what will be queried — leaving it in would explain
// the provenance of a value no longer on the line above it.
func TestTheCPEOriginIsSuppressedByAnOverride(t *testing.T) {
	r := baseReport()
	r.CPEsOverridden = true

	if got := render(t, r); strings.Contains(got, r.Resolution.CPEOrigin) {
		t.Error("the model's CPE origin was printed under an analyst's overridden CPEs")
	}
	if got := render(t, baseReport()); !strings.Contains(got, r.Resolution.CPEOrigin) {
		t.Error("the CPE origin is missing when there is no override")
	}
}

// TestAnUnrenderableDataTypeIsNotSilent is the map failure in miniature. A cached section whose
// Data came back as a map matches no case in the type switch; if the citations did not print,
// the section would be a green heading with nothing under it — the strongest claim this tool
// can make and the one it can least support.
func TestAnUnrenderableDataTypeIsNotSilent(t *testing.T) {
	r := baseReport()
	section := sources.OK(sources.SourceBitSight,
		map[string]any{"rating": 780},
		sources.Citation{URL: "https://service.bitsighttech.com/"})
	r.Sections = []sources.Section{section}

	got := render(t, r)
	if !strings.Contains(got, "https://service.bitsighttech.com/") {
		t.Errorf("a section the renderer could not type-match printed nothing at all:\n%s", got)
	}
}

// TestRenderReportsAWriteError. A report truncated by a broken pipe is a partial answer, and
// swallowing the error would let the caller exit 0 on one.
func TestRenderReportsAWriteError(t *testing.T) {
	err := Render(failingWriter{}, baseReport())
	if err == nil {
		t.Fatal("Render succeeded against a writer that always fails")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
