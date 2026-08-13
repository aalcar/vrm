package sources

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// errFedRAMPExample stands in for the parser-breakage error the fedramp source produces.
var errFedRAMPExample = errors.New(
	"parsed only 0 marketplace records (expected at least 200): the listing page layout has changed")

// populatedSections builds one fully-populated section per cacheable source.
//
// Every field is set on purpose. A round-trip test over zero values proves almost nothing —
// a codec that dropped Data entirely would pass it — so each fixture here carries a value in
// every field that has to survive, including the nested and embedded ones.
func populatedSections() map[string]Section {
	return map[string]Section{
		SourceBitSight: OK(SourceBitSight, BitSightRating{
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
		}, Citation{Title: "BitSight", URL: "https://service.bitsighttech.com/"}),

		SourceNVD: OK(SourceNVD, NVDResult{
			Queries: []NVDQuery{{
				CPE:           "cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*",
				TotalResults:  3,
				Verification:  NVDVerifiedByResults,
				KnownProducts: []string{"okta", "advanced_server_access"},
			}},
			Unqueried: []string{"cpe:2.3:a:okta:auth0:*:*:*:*:*:*:*:*"},
			TotalCVEs: 3,
			Severity:  NVDSeverityCounts{Critical: 1, High: 1, Medium: 0, Low: 0, Unscored: 1},
			CVEs: []NVDVuln{{
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
			}},
		}),

		SourceOSV: OK(SourceOSV, OSVResult{
			Queries: []OSVQuery{{
				Package:    Package{Ecosystem: "Go", Name: "github.com/hashicorp/vault"},
				TotalVulns: 2,
				Truncated:  true,
			}},
			TotalVulns: 2,
			Severity:   OSVSeverityCounts{Critical: 0, High: 1, Moderate: 0, Low: 0, Unrated: 1},
			Vulns: []OSVVuln{{
				ID:         "GHSA-xxxx-yyyy-zzzz",
				Package:    Package{Ecosystem: "Go", Name: "github.com/hashicorp/vault"},
				Summary:    "An example advisory.",
				Published:  "2024-01-02T00:00:00Z",
				Modified:   "2024-02-03T00:00:00Z",
				Aliases:    []string{"CVE-2024-0002", "GHSA-xxxx-yyyy-zzzz"},
				CVEs:       []string{"CVE-2024-0002"},
				Severity:   "MODERATE",
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				CVSSType:   "CVSS_V3",
				URL:        "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz",
			}},
		}),

		SourceFedRAMP: OK(SourceFedRAMP, FedRAMPResult{
			Offerings: []FedRAMPOffering{{
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
			Searched:     []string{"okta", "okta inc"},
			TotalRecords: 674,
		}),

		SourceCAAG: OK(SourceCAAG, CAAGResult{
			Entries: []CAAGEntry{{
				Organization: "T-Mobile US, Inc.",
				BreachDates:  []string{"2021-08-01", "2021-08-17"},
				ReportedDate: "2021-08-23",
				ReportURL:    "https://oag.ca.gov/ecrime/databreach/reports/sb24-000000",
				SearchedAs:   "T-Mobile",
			}},
			Searched: []string{"t-mobile"},
		}),

		SourceResearch: OK(SourceResearch, Research{
			SupplierDescription: Finding{
				Value:     "Okta is an identity provider.",
				Citations: []Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
			},
			ServiceDescription: Finding{
				Value:     "Single sign-on.",
				Citations: []Citation{{Title: "Okta SSO", URL: "https://www.okta.com/products/single-sign-on/"}},
			},
			ServiceImplementation: Finding{
				Value:     "Cloud-hosted SaaS.",
				Citations: []Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
			},
			CyberLawsuits: []Lawsuit{{
				Finding: Finding{
					Value:     "A shareholder suit following the 2022 Lapsus$ disclosure.",
					Citations: []Citation{{Title: "Reuters", URL: "https://www.reuters.com/example"}},
				},
				Outcome:        "dismissed",
				ResolutionDate: "2024-03-01",
			}},
			PastBreaches: []Finding{{
				Value:     "January 2022 Lapsus$ compromise of a support engineer's laptop.",
				Citations: []Citation{{Title: "Okta blog", URL: "https://www.okta.com/blog/example/"}},
			}},
			SupplierWebsite: Finding{
				Value:     "https://www.okta.com/",
				Citations: []Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
			},
			ServiceWebsite: Finding{
				Value:     "https://www.okta.com/products/single-sign-on/",
				Citations: []Citation{{Title: "Okta SSO", URL: "https://www.okta.com/products/single-sign-on/"}},
			},
			SecurityPage: Finding{
				Value:     "https://www.okta.com/security/",
				Citations: []Citation{{Title: "Okta security", URL: "https://www.okta.com/security/"}},
			},
			NotificationPage: Finding{
				Value:     "https://status.okta.com/",
				Citations: []Citation{{Title: "Okta status", URL: "https://status.okta.com/"}},
			},
			Locations: []Location{{
				Finding: Finding{
					Value:     "San Francisco headquarters.",
					Citations: []Citation{{Title: "Okta contact", URL: "https://www.okta.com/contact/"}},
				},
				Kind:    "headquarters",
				Country: "United States",
				City:    "San Francisco, California",
			}},
			UsedKaspersky:  TriNoEvidence,
			MOVEitImpacted: TriYes,
			MOVEitEvidence: Finding{
				Value:     "Named in a MOVEit-related filing.",
				Citations: []Citation{{Title: "Example", URL: "https://www.example.com/moveit"}},
			},
			Dropped:       []string{`past_breaches[1]: dropped an uncited claim`},
			SearchResults: []Citation{{Title: "Okta", URL: "https://www.okta.com/"}},
		}),
	}
}

// TestSectionRoundTripPreservesTheConcreteType is the test this codec exists for.
//
// The failure it guards against is not a decode error — it is a successful decode into
// map[string]any, which the renderer's type switch matches no case of. That renders as a
// heading with nothing under it: a source reporting ok while showing no data.
func TestSectionRoundTripPreservesTheConcreteType(t *testing.T) {
	for source, want := range populatedSections() {
		t.Run(source, func(t *testing.T) {
			raw, err := EncodeSection(want, "fingerprint")
			if err != nil {
				t.Fatalf("EncodeSection: %v", err)
			}

			got, _, err := DecodeSection(source, raw)
			if err != nil {
				t.Fatalf("DecodeSection: %v", err)
			}

			if gotType, wantType := reflect.TypeOf(got.Data), reflect.TypeOf(want.Data); gotType != wantType {
				t.Fatalf("Data came back as %s, want %s", gotType, wantType)
			}
			if _, isMap := got.Data.(map[string]any); isMap {
				t.Fatal("Data decoded into a map; the renderer selects on the concrete type " +
					"and would render this section as an empty heading")
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("round trip changed the section\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

// TestEveryAutomatedSourceIsCacheable fails when a source is added without a codec.
//
// Without it, a new source would simply never cache — no error, no failing test, just an
// assessment that stays slow for a reason nobody would look for.
func TestEveryAutomatedSourceIsCacheable(t *testing.T) {
	for _, source := range []string{
		SourceBitSight, SourceNVD, SourceOSV, SourceFedRAMP, SourceCAAG, SourceResearch,
	} {
		if !Cacheable(source) {
			t.Errorf("source %q has no registered section codec", source)
		}
	}
}

// fingerprintEntity is a resolved entity with something in every field a source reads.
func fingerprintEntity() ResolvedEntity {
	return ResolvedEntity{
		CanonicalName: "Okta, Inc.",
		Domains:       []string{"okta.com"},
		CPEs:          []string{"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*"},
		Packages:      []Package{{Ecosystem: "npm", Name: "@okta/okta-auth-js"}},
		Aliases:       []string{"Auth0"},
	}
}

// TestEverySourceFingerprintsSomething catches a source registered with a fingerprint that
// ignores the entity — a constant. That fails open: every row hits regardless of what the
// section was computed from, which is exactly the bug the fingerprint exists to prevent, and
// nothing else would notice.
func TestEverySourceFingerprintsSomething(t *testing.T) {
	q := Query{Company: "Okta", Service: "SSO"}
	for _, source := range CacheableSources() {
		t.Run(source, func(t *testing.T) {
			full := SectionInputs(source, q, fingerprintEntity())
			empty := SectionInputs(source, q, ResolvedEntity{})
			if full == "" {
				t.Fatal("a registered source fingerprinted as the empty string")
			}
			if full == empty {
				t.Error("the fingerprint is the same for a fully resolved entity and an empty " +
					"one, so it reads none of the identifiers this source consumes")
			}
		})
	}
}

// TestFingerprintsAreScopedToTheSourceThatReadsThem keeps one source's cache from being
// invalidated by a field it never looks at. A resolution that gains a package would otherwise
// throw away FedRAMP's 168h row and re-fetch 4.7 MB for nothing.
func TestFingerprintsAreScopedToTheSourceThatReadsThem(t *testing.T) {
	q := Query{Company: "Okta", Service: "SSO"}
	base := fingerprintEntity()

	changed := base
	changed.CPEs = []string{"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*"}

	if SectionInputs(SourceNVD, q, base) == SectionInputs(SourceNVD, q, changed) {
		t.Error("nvd's fingerprint did not move when the CPEs did")
	}
	for _, source := range []string{SourceBitSight, SourceOSV, SourceFedRAMP, SourceCAAG, SourceResearch} {
		if SectionInputs(source, q, base) != SectionInputs(source, q, changed) {
			t.Errorf("%s's fingerprint moved when only the CPEs changed", source)
		}
	}
}

// TestFingerprintsAreOrderSensitive. FedRAMP and CA AG cap how many names they look up, so a
// reordered alias list is a genuine change in what gets queried, not a cosmetic one.
func TestFingerprintsAreOrderSensitive(t *testing.T) {
	q := Query{Company: "Okta", Service: "SSO"}
	forward := ResolvedEntity{CPEs: []string{"cpe:a", "cpe:b"}}
	reversed := ResolvedEntity{CPEs: []string{"cpe:b", "cpe:a"}}

	if SectionInputs(SourceNVD, q, forward) == SectionInputs(SourceNVD, q, reversed) {
		t.Error("two different orderings fingerprinted the same")
	}
}

// TestFingerprintsDoNotCollideAcrossABoundary. Concatenating identifiers without a length
// would make ["ab","c"] and ["a","bc"] the same fingerprint, and a two-CPE list would silently
// hit a row computed from a different two-CPE list.
func TestFingerprintsDoNotCollideAcrossABoundary(t *testing.T) {
	q := Query{Company: "Okta", Service: "SSO"}
	left := ResolvedEntity{CPEs: []string{"ab", "c"}}
	right := ResolvedEntity{CPEs: []string{"a", "bc"}}

	if SectionInputs(SourceNVD, q, left) == SectionInputs(SourceNVD, q, right) {
		t.Error(`["ab","c"] and ["a","bc"] fingerprinted the same`)
	}
}

// TestEncodeRejectsAnUnfingerprintedSection. Absent inputs is how a row written before this
// rule is recognized, so writing one deliberately would burn a write and cache nothing.
func TestEncodeRejectsAnUnfingerprintedSection(t *testing.T) {
	_, err := EncodeSection(bitsightSection(), "")
	if err == nil {
		t.Fatal("encoded a section with no input fingerprint; the row could never be read back")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("error does not say why: %v", err)
	}
}

// TestDecodeReportsAnAbsentFingerprint pins the upgrade path. A row written before
// fingerprinting decodes fine — it is well-formed — and reports "", which matches no live
// fingerprint, so it expires on its first read instead of erroring.
func TestDecodeReportsAnAbsentFingerprint(t *testing.T) {
	raw := `{"source":"bitsight","status":"ok"}`
	section, inputs, err := DecodeSection(SourceBitSight, []byte(raw))
	if err != nil {
		t.Fatalf("a row predating the fingerprint should still decode: %v", err)
	}
	if inputs != "" {
		t.Errorf("inputs = %q, want the empty string", inputs)
	}
	if section.Status != StatusOK {
		t.Errorf("Status = %q", section.Status)
	}
}

// TestManualSourcesAreNotCacheable pins the exemption. Manual entries are analyst data: they
// are read from their own row every run and never expire (spec §7).
func TestManualSourcesAreNotCacheable(t *testing.T) {
	for _, source := range []string{"ssllabs", "openbugbounty", "cvedetails"} {
		if Cacheable(source) {
			t.Errorf("manual source %q is registered as cacheable", source)
		}
	}
}

func TestEncodeRejectsAnUnregisteredSource(t *testing.T) {
	_, err := EncodeSection(OK("ssllabs", ManualResult{Value: "A+"}), "fingerprint")
	if err == nil {
		t.Fatal("encoded a section for a source with no codec; the row would be unreadable")
	}
	if !strings.Contains(err.Error(), "no registered section codec") {
		t.Errorf("error does not say why: %v", err)
	}
}

// TestEncodeRejectsDataOfTheWrongType catches a mis-registered source at write time.
//
// Encoding it would succeed and the row would decode into a zero NVDResult — a section
// reporting ok with every count at zero, which reads exactly like a clean vendor.
func TestEncodeRejectsDataOfTheWrongType(t *testing.T) {
	_, err := EncodeSection(OK(SourceNVD, BitSightRating{Rating: 780}), "fingerprint")
	if err == nil {
		t.Fatal("encoded BitSight data under the nvd source; it would decode as a zero NVDResult")
	}
	if !strings.Contains(err.Error(), "wrong type") {
		t.Errorf("error does not say why: %v", err)
	}
}

// TestDecodeRejectsARowKeyedUnderAnotherSource guards against attributing one source's data
// to another, which is the same class of error as a wrong CPE: plausible, sourced, and wrong.
func TestDecodeRejectsARowKeyedUnderAnotherSource(t *testing.T) {
	raw, err := EncodeSection(populatedSections()[SourceCAAG], "fingerprint")
	if err != nil {
		t.Fatalf("EncodeSection: %v", err)
	}

	if _, _, err := DecodeSection(SourceFedRAMP, raw); err == nil {
		t.Fatal("decoded a caag row as a fedramp section")
	}
}

func TestDecodeRejectsMalformedPayloads(t *testing.T) {
	cases := map[string]string{
		"not json":           `{"source":`,
		"data not an object": `{"source":"caag","status":"ok","data":"a string"}`,
		"unknown source":     `{"source":"ssllabs","status":"ok"}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			source := SourceCAAG
			if name == "unknown source" {
				source = "ssllabs"
			}
			if _, _, err := DecodeSection(source, []byte(raw)); err == nil {
				t.Fatal("decoded a malformed payload without error")
			}
		})
	}
}

// TestRoundTripOfAParsedResearchReply runs the real captured reply through the codec.
//
// The constructed fixture above is a shape I chose; this one is a shape the model produced.
// Research is the most nested type in the tool — embedded Findings inside Lawsuits and
// Locations, citation slices at three levels — so it is where a codec would break first.
func TestRoundTripOfAParsedResearchReply(t *testing.T) {
	want, err := parseResearch(readFixture(t, "research_okta.json"), okiaSearchResults(t))
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}

	raw, err := EncodeSection(OK(SourceResearch, want), "fingerprint")
	if err != nil {
		t.Fatalf("EncodeSection: %v", err)
	}
	section, _, err := DecodeSection(SourceResearch, raw)
	if err != nil {
		t.Fatalf("DecodeSection: %v", err)
	}

	got, ok := section.Data.(Research)
	if !ok {
		t.Fatalf("Data is %T, want Research", section.Data)
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("round trip changed the parsed research reply")
	}
	// Spot-check the deepest nesting rather than trusting DeepEqual alone to be read
	// correctly: an embedded Finding that vanished would still compare equal to another
	// empty one if both sides were empty for an unrelated reason.
	if len(got.Locations) > 0 && len(got.Locations[0].Citations) == 0 {
		t.Error("a location survived the round trip without its citations")
	}
}

// TestNonOKSectionsSurviveTheCodec keeps the codec about shape rather than policy. Only
// StatusOK is written to the cache, but that rule belongs to the caching layer — a codec that
// silently dropped a note or an error would hide the reason a section was stored at all.
func TestNonOKSectionsSurviveTheCodec(t *testing.T) {
	for _, want := range []Section{
		Skipped(SourceOSV, "no open-source packages resolved for this vendor"),
		Failed(SourceFedRAMP, errFedRAMPExample),
	} {
		t.Run(string(want.Status), func(t *testing.T) {
			raw, err := EncodeSection(want, "fingerprint")
			if err != nil {
				t.Fatalf("EncodeSection: %v", err)
			}
			got, _, err := DecodeSection(want.Source, raw)
			if err != nil {
				t.Fatalf("DecodeSection: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("round trip changed the section\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}
