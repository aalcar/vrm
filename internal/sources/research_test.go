package sources

import (
	"encoding/json"
	"strings"
	"testing"
)

// The happy-path fixtures are a real captured reply:
//
//	testdata/research_okta.json                — the structured JSON the model returned
//	testdata/research_okta_search_results.json — the URLs the web-search tool returned
//
// captured 2026-08-04 for "Okta" / "SSO" against claude-sonnet-5 with the web-search tool.
// The adversarial cases below are constructed rather than captured, because a reply that
// fabricates a citation or reports an uncited "yes" is exactly what must not be waited for.
// They are edits of the captured shape, which the fixture pins.

func okiaSearchResults(t *testing.T) []Citation {
	t.Helper()
	var results []Citation
	if err := json.Unmarshal([]byte(readFixture(t, "research_okta_search_results.json")), &results); err != nil {
		t.Fatalf("decode search results fixture: %v", err)
	}
	return results
}

func TestParseResearchRealReply(t *testing.T) {
	research, err := parseResearch(readFixture(t, "research_okta.json"), okiaSearchResults(t))
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}

	if research.SupplierDescription.Value == "" {
		t.Error("SupplierDescription is empty")
	}
	// Every surviving finding carries at least one citation. That is the contract, and the
	// only reason a value is allowed on screen at all.
	for label, f := range map[string]Finding{
		"supplier_description":   research.SupplierDescription,
		"service_description":    research.ServiceDescription,
		"service_implementation": research.ServiceImplementation,
		"security_page":          research.SecurityPage,
	} {
		if f.Value != "" && len(f.Citations) == 0 {
			t.Errorf("%s has a value with no citation", label)
		}
	}

	// A real reply about Okta should not claim either of the two confabulation-bait events.
	if research.UsedKaspersky == TriYes {
		t.Errorf("used_kaspersky = yes for Okta; evidence: %+v", research.UsedKasperskyEvidence)
	}
	if !research.UsedKaspersky.valid() {
		t.Errorf("used_kaspersky = %q, not one of the three permitted answers", research.UsedKaspersky)
	}
	if !research.MOVEitImpacted.valid() {
		t.Errorf("moveit_impacted = %q, not one of the three permitted answers", research.MOVEitImpacted)
	}

	// Nothing was dropped from the captured reply — the model cited only URLs it had really
	// seen. If this starts failing, the strictness of the citation check is worth revisiting
	// before the check is loosened.
	if len(research.Dropped) != 0 {
		t.Errorf("dropped %d items from a real reply: %v", len(research.Dropped), research.Dropped)
	}

	for _, l := range research.Locations {
		if l.Kind != "headquarters" && l.Kind != "operational" {
			t.Errorf("location %q is labeled %q", l.Value, l.Kind)
		}
	}
	for _, l := range research.CyberLawsuits {
		if l.Outcome == "" || l.ResolutionDate == "" {
			t.Errorf("lawsuit %q survived without an outcome and resolution date", l.Value)
		}
	}
}

// reply builds a minimal well-formed research reply, then applies overrides. Every field is
// required by the schema, so they all have to be present even when a test cares about one.
func reply(overrides map[string]any) string {
	empty := map[string]any{"value": "", "citations": []string{}}
	body := map[string]any{
		"supplier_description":    empty,
		"service_description":     empty,
		"service_implementation":  empty,
		"cyber_lawsuits":          []any{},
		"past_breaches":           []any{},
		"supplier_website":        empty,
		"service_website":         empty,
		"security_page":           empty,
		"notification_page":       empty,
		"locations":               []any{},
		"used_kaspersky":          string(TriNoEvidence),
		"used_kaspersky_evidence": empty,
		"moveit_impacted":         string(TriNoEvidence),
		"moveit_evidence":         empty,
	}
	for k, v := range overrides {
		body[k] = v
	}
	out, _ := json.Marshal(body)
	return string(out)
}

var realResults = []Citation{
	{Title: "Okta Security Trust Center", URL: "https://security.okta.com/"},
	{Title: "Okta Trust", URL: "https://trust.okta.com/"},
}

func TestUncitedKasperskyYesIsDowngraded(t *testing.T) {
	// Kaspersky and MOVEit are the highest confabulation risk in the tool: both are famous
	// events a model will pattern-match a vendor toward. A "yes" that cannot point at a
	// source naming this vendor is not a weaker yes, it is no evidence (spec §8).
	raw := reply(map[string]any{
		"used_kaspersky": string(TriYes),
		"used_kaspersky_evidence": map[string]any{
			"value":     "The vendor deployed Kaspersky Endpoint Security across its fleet.",
			"citations": []string{},
		},
	})

	research, err := parseResearch(raw, realResults)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	if research.UsedKaspersky != TriNoEvidence {
		t.Errorf("used_kaspersky = %q, want %q", research.UsedKaspersky, TriNoEvidence)
	}
	if research.UsedKasperskyEvidence.Value != "" {
		t.Errorf("the uncited claim survived: %q", research.UsedKasperskyEvidence.Value)
	}
	if !containsSubstring(research.Dropped, "downgraded") {
		t.Errorf("Dropped = %v, want it to record the downgrade", research.Dropped)
	}
}

func TestMOVEitYesWithAFabricatedCitationIsDowngraded(t *testing.T) {
	// The citation here is well-formed and plausible — and was never returned by search.
	// That is precisely the failure the check exists for: a model that can write the claim
	// can write a URL to go beside it.
	raw := reply(map[string]any{
		"moveit_impacted": string(TriYes),
		"moveit_evidence": map[string]any{
			"value":     "The vendor was named in the MOVEit breach.",
			"citations": []string{"https://www.okta.com/blog/2023/06/moveit-incident-disclosure/"},
		},
	})

	research, err := parseResearch(raw, realResults)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	if research.MOVEitImpacted != TriNoEvidence {
		t.Errorf("moveit_impacted = %q, want %q", research.MOVEitImpacted, TriNoEvidence)
	}
	if !containsSubstring(research.Dropped, "not in the web search results") {
		t.Errorf("Dropped = %v, want it to name the fabricated citation", research.Dropped)
	}
}

func TestBareNoBecomesNoEvidenceFound(t *testing.T) {
	// "No" is not one of the three answers. "We found nothing" and "it did not happen" are
	// different claims and only the first is supportable, so a bare no is read as the first.
	raw := reply(map[string]any{"used_kaspersky": "no", "moveit_impacted": "No"})

	research, err := parseResearch(raw, realResults)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	if research.UsedKaspersky != TriNoEvidence || research.MOVEitImpacted != TriNoEvidence {
		t.Errorf("got kaspersky=%q moveit=%q, want both %q",
			research.UsedKaspersky, research.MOVEitImpacted, TriNoEvidence)
	}
	if len(research.Dropped) != 2 {
		t.Errorf("Dropped = %v, want both bare answers recorded", research.Dropped)
	}
}

func TestUncitedFindingIsDropped(t *testing.T) {
	raw := reply(map[string]any{
		"supplier_description": map[string]any{
			"value":     "A large identity provider serving thousands of enterprises.",
			"citations": []string{},
		},
	})

	research, err := parseResearch(raw, realResults)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	// Dropped rather than shown with a caveat: an unverifiable claim in a sourced report
	// undermines every claim beside it.
	if research.SupplierDescription.Value != "" {
		t.Errorf("uncited finding survived: %q", research.SupplierDescription.Value)
	}
	if !containsSubstring(research.Dropped, "uncited claim") {
		t.Errorf("Dropped = %v, want the drop recorded", research.Dropped)
	}
}

func TestLawsuitDoubleFilter(t *testing.T) {
	tests := []struct {
		name    string
		lawsuit map[string]any
		keep    bool
	}{
		{
			name: "concluded with outcome and date is kept",
			lawsuit: map[string]any{
				"value":           "In re Vendor Securities Litigation",
				"citations":       []string{"https://security.okta.com/"},
				"outcome":         "Settled for $60 million",
				"resolution_date": "2024-09-12",
			},
			keep: true,
		},
		{
			// The resolution date is how "concluded" is verified; without it the entry may
			// be a pending case, and a pending case is an allegation.
			name: "no resolution date is dropped",
			lawsuit: map[string]any{
				"value":           "In re Vendor Securities Litigation",
				"citations":       []string{"https://security.okta.com/"},
				"outcome":         "Settled",
				"resolution_date": "",
			},
		},
		{
			name: "no outcome is dropped",
			lawsuit: map[string]any{
				"value":           "Class action filed over a 2023 breach",
				"citations":       []string{"https://security.okta.com/"},
				"outcome":         "",
				"resolution_date": "2024-01-05",
			},
		},
		{
			name: "concluded but uncited is dropped",
			lawsuit: map[string]any{
				"value":           "In re Vendor Securities Litigation",
				"citations":       []string{},
				"outcome":         "Dismissed",
				"resolution_date": "2023-04-01",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := reply(map[string]any{"cyber_lawsuits": []any{tt.lawsuit}})
			research, err := parseResearch(raw, realResults)
			if err != nil {
				t.Fatalf("parseResearch: %v", err)
			}
			if got := len(research.CyberLawsuits); (got == 1) != tt.keep {
				t.Errorf("kept %d lawsuits, want keep=%v (dropped: %v)",
					got, tt.keep, research.Dropped)
			}
		})
	}
}

func TestUnlabeledLocationIsDropped(t *testing.T) {
	// An unlabeled location reads as a headquarters, which overstates it. "Has an office in
	// country X" and "is headquartered in country X" carry very different weight.
	raw := reply(map[string]any{"locations": []any{
		map[string]any{
			"value": "Bengaluru, India", "citations": []string{"https://trust.okta.com/"},
			"kind": "", "country": "India", "city": "Bengaluru",
		},
		map[string]any{
			"value": "San Francisco, California", "citations": []string{"https://trust.okta.com/"},
			"kind": "headquarters", "country": "United States", "city": "San Francisco, California",
		},
	}})

	research, err := parseResearch(raw, realResults)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	if len(research.Locations) != 1 {
		t.Fatalf("kept %d locations, want only the labeled one", len(research.Locations))
	}
	if research.Locations[0].Kind != "headquarters" {
		t.Errorf("kept the wrong location: %+v", research.Locations[0])
	}
	// The city field carries the state for US locations; the schema has no room for a
	// separate one.
	if !strings.Contains(research.Locations[0].City, "California") {
		t.Errorf("City = %q, want it to carry the state", research.Locations[0].City)
	}
}

func TestCitationTitlesComeFromSearchNotTheModel(t *testing.T) {
	// The title is taken from the search result, not from anything the model wrote. It is
	// the one part of a citation that can be had from ground truth for free.
	raw := reply(map[string]any{
		"security_page": map[string]any{
			"value":     "https://security.okta.com/",
			"citations": []string{"https://security.okta.com/"},
		},
	})

	research, err := parseResearch(raw, realResults)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	if len(research.SecurityPage.Citations) != 1 {
		t.Fatalf("citations = %+v, want 1", research.SecurityPage.Citations)
	}
	if got := research.SecurityPage.Citations[0].Title; got != "Okta Security Trust Center" {
		t.Errorf("Title = %q, want the title search returned", got)
	}
}

func TestCitationMatchingIgnoresMeaninglessURLDifferences(t *testing.T) {
	// Folding only the differences that carry no meaning. Anything more — ignoring the query
	// string, or matching on host alone — would accept a citation pointing somewhere the
	// search never went.
	same := [][2]string{
		{"https://security.okta.com/", "https://SECURITY.okta.com"},
		{"https://security.okta.com/", "https://security.okta.com/#overview"},
		{"https://security.okta.com/", "HTTPS://security.okta.com/"},
	}
	for _, pair := range same {
		if a, b := normalizeCitationURL(pair[0]), normalizeCitationURL(pair[1]); a != b {
			t.Errorf("normalize(%q)=%q != normalize(%q)=%q", pair[0], a, pair[1], b)
		}
	}

	different := [][2]string{
		{"https://security.okta.com/a", "https://security.okta.com/b"},
		{"https://security.okta.com/", "https://trust.okta.com/"},
		{"https://example.com/p?id=1", "https://example.com/p?id=2"},
	}
	for _, pair := range different {
		if a, b := normalizeCitationURL(pair[0]), normalizeCitationURL(pair[1]); a == b {
			t.Errorf("normalize collapsed %q and %q to %q", pair[0], pair[1], a)
		}
	}
}

func TestParseResearchRejectsMalformedJSON(t *testing.T) {
	// Half a checklist rendered as a whole one is a wrong answer, not a thin one.
	if _, err := parseResearch(`{"supplier_description": `, realResults); err == nil {
		t.Error("parseResearch accepted a truncated reply")
	}
}

func TestNoSearchResultsMeansNoFindingsSurvive(t *testing.T) {
	// If search returned nothing, no citation can be verified, so nothing may be asserted.
	// Rendering the model's unverified recollection here would be the whole failure mode.
	raw := reply(map[string]any{
		"supplier_description": map[string]any{
			"value":     "A large identity provider.",
			"citations": []string{"https://security.okta.com/"},
		},
	})

	research, err := parseResearch(raw, nil)
	if err != nil {
		t.Fatalf("parseResearch: %v", err)
	}
	if research.SupplierDescription.Value != "" {
		t.Errorf("a finding survived with no search results to verify it: %q",
			research.SupplierDescription.Value)
	}
}

func containsSubstring(values []string, want string) bool {
	for _, v := range values {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}
