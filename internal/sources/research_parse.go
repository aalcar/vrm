package sources

import (
	"fmt"
	"net/url"
	"strings"
)

// parseResearch turns a reply into a validated checklist.
//
// # Why citations are checked against search results
//
// Spec §8 requires every non-empty finding to carry a citation, and requires an uncited
// Kaspersky or MOVEit "yes" to be downgraded rather than shown. The obvious way to get
// citations is the API's own citation blocks — but they do not survive structured output.
// A response that combines the web-search tool with a JSON schema returns the JSON in a
// text block carrying zero citations, with the real sources in separate search-result
// blocks. So the citations here are fields the model wrote, and a model that can write a
// claim can write a URL to go with it.
//
// What makes them checkable is that the search-result blocks are not model-authored: they
// are what the search tool actually returned. Every claimed citation is matched against
// that set, and one that is not in it is discarded as fabricated. This is the same move
// that fixed CPEs in Phase 3 — validate the identifier against the thing that produced it,
// rather than asking the model more firmly.
//
// The check errs toward dropping. A legitimate source cited by a URL that did not appear in
// the results is discarded, which costs a finding; the alternative is displaying invented
// evidence, which costs the analyst's trust in every other finding on the page.
func parseResearch(raw string, searchResults []Citation) (Research, error) {
	reply, err := unmarshalResearch(raw)
	if err != nil {
		return Research{}, err
	}

	v := &researchValidator{allowed: newResultIndex(searchResults)}

	out := Research{
		SupplierDescription:   v.finding(reply.SupplierDescription, "supplier_description"),
		ServiceDescription:    v.finding(reply.ServiceDescription, "service_description"),
		ServiceImplementation: v.finding(reply.ServiceImplementation, "service_implementation"),
		SupplierWebsite:       v.finding(reply.SupplierWebsite, "supplier_website"),
		ServiceWebsite:        v.finding(reply.ServiceWebsite, "service_website"),
		SecurityPage:          v.finding(reply.SecurityPage, "security_page"),
		NotificationPage:      v.finding(reply.NotificationPage, "notification_page"),
		SearchResults:         searchResults,
	}

	for i, breach := range reply.PastBreaches {
		f := v.finding(breach, fmt.Sprintf("past_breaches[%d]", i))
		if f.Value == "" {
			continue
		}
		out.PastBreaches = append(out.PastBreaches, f)
	}

	out.CyberLawsuits = v.lawsuits(reply.CyberLawsuits)
	out.Locations = v.locations(reply.Locations)

	// The two highest-confabulation fields in the tool. Both name events an LLM will
	// pattern-match toward, so a "yes" survives only with a citation that came from search.
	out.UsedKaspersky, out.UsedKasperskyEvidence = v.tri(
		reply.UsedKaspersky, reply.UsedKasperskyEvidence, "used_kaspersky")
	out.MOVEitImpacted, out.MOVEitEvidence = v.tri(
		reply.MOVEitImpacted, reply.MOVEitEvidence, "moveit_impacted")

	out.Dropped = v.dropped
	return out, nil
}

// researchValidator accumulates what it discarded, so nothing disappears silently.
type researchValidator struct {
	// allowed maps a normalized URL to the search result it came from. The title travels
	// with it, so a citation's title is the one search returned rather than one the model
	// wrote next to a URL.
	allowed map[string]Citation
	dropped []string
}

func (v *researchValidator) drop(format string, args ...any) {
	v.dropped = append(v.dropped, fmt.Sprintf(format, args...))
}

// finding keeps a claim only if it carries at least one citation that came from search.
func (v *researchValidator) finding(reply findingReply, label string) Finding {
	value := strings.TrimSpace(reply.Value)
	if value == "" {
		// An empty field is a correct and expected answer, not something to report.
		return Finding{}
	}

	citations := v.citations(reply.Citations, label)
	if len(citations) == 0 {
		// A claim with no surviving citation is not a weaker finding, it is an unverifiable
		// one. It is dropped rather than shown with a caveat.
		v.drop("%s: dropped an uncited claim", label)
		return Finding{}
	}
	return Finding{Value: value, Citations: citations}
}

// citations keeps only URLs the search tool actually returned.
func (v *researchValidator) citations(urls []string, label string) []Citation {
	var kept []Citation
	seen := make(map[string]bool, len(urls))

	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		key := normalizeCitationURL(raw)

		result, found := v.allowed[key]
		if !found {
			v.drop("%s: dropped citation %s (not in the web search results)", label, raw)
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, result)
	}
	return kept
}

// tri validates a three-valued answer and its evidence.
//
// A "yes" is only as good as its evidence, so an uncited yes becomes no_evidence_found —
// the two are different claims and only the weaker one is supportable. A value outside the
// three permitted answers, including a bare "no", becomes no_evidence_found too.
func (v *researchValidator) tri(raw string, evidence findingReply, label string) (Tri, Finding) {
	answer := Tri(strings.TrimSpace(strings.ToLower(raw)))
	if !answer.valid() {
		v.drop("%s: %q is not one of yes/no_evidence_found/not_applicable", label, raw)
		return TriNoEvidence, Finding{}
	}

	if answer != TriYes {
		// Evidence only belongs with a yes; anything attached to the other two answers is
		// commentary, and commentary is the analyst's job.
		return answer, Finding{}
	}

	finding := v.finding(evidence, label+"_evidence")
	if finding.Value == "" {
		v.drop("%s: downgraded an uncited \"yes\" to no_evidence_found", label)
		return TriNoEvidence, Finding{}
	}
	return TriYes, finding
}

// lawsuits applies the double filter from spec §8.
func (v *researchValidator) lawsuits(replies []lawsuitReply) []Lawsuit {
	var kept []Lawsuit

	for i, l := range replies {
		label := fmt.Sprintf("cyber_lawsuits[%d]", i)

		outcome := strings.TrimSpace(l.Outcome)
		resolved := strings.TrimSpace(l.ResolutionDate)

		// Both fields are how "concluded" is verified. Without them the entry may be a
		// pending case, and a pending case is an allegation rather than a finding.
		if outcome == "" || resolved == "" {
			v.drop("%s: dropped, no outcome and resolution date (cannot confirm it concluded)", label)
			continue
		}

		finding := v.finding(l.findingReply, label)
		if finding.Value == "" {
			continue
		}
		kept = append(kept, Lawsuit{Finding: finding, Outcome: outcome, ResolutionDate: resolved})
	}
	return kept
}

// locations keeps labeled locations only.
func (v *researchValidator) locations(replies []locationReply) []Location {
	var kept []Location

	for i, l := range replies {
		label := fmt.Sprintf("locations[%d]", i)

		kind := strings.TrimSpace(strings.ToLower(l.Kind))
		// An unlabeled location silently reads as a headquarters, which overstates it.
		if kind != "headquarters" && kind != "operational" {
			v.drop("%s: dropped, not labeled headquarters or operational", label)
			continue
		}

		finding := v.finding(l.findingReply, label)
		if finding.Value == "" {
			continue
		}
		kept = append(kept, Location{
			Finding: finding,
			Kind:    kind,
			Country: strings.TrimSpace(l.Country),
			City:    strings.TrimSpace(l.City),
		})
	}
	return kept
}

// newResultIndex keys the search results by normalized URL.
func newResultIndex(results []Citation) map[string]Citation {
	index := make(map[string]Citation, len(results))
	for _, r := range results {
		if key := normalizeCitationURL(r.URL); key != "" {
			index[key] = r
		}
	}
	return index
}

// normalizeCitationURL canonicalizes a URL for comparison.
//
// Only the differences that carry no meaning are folded: case in the scheme and host, a
// fragment, a trailing slash, and a default port. Query strings are kept — they routinely
// select the actual document, and ignoring them would let a citation point somewhere the
// search never returned.
func normalizeCitationURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	parsed.RawFragment = ""

	if strings.HasSuffix(parsed.Host, ":80") && parsed.Scheme == "http" {
		parsed.Host = strings.TrimSuffix(parsed.Host, ":80")
	}
	if strings.HasSuffix(parsed.Host, ":443") && parsed.Scheme == "https" {
		parsed.Host = strings.TrimSuffix(parsed.Host, ":443")
	}
	// Unconditionally, including a bare "/": "https://host.example/" and
	// "https://host.example" are the same page, and treating them as different would drop a
	// legitimate citation for punctuation.
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")

	return parsed.String()
}
