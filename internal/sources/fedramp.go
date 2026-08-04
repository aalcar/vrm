package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

// SourceFedRAMP is the registered name of this source.
const SourceFedRAMP = "fedramp"

// DefaultFedRAMPURL is the marketplace product listing.
//
// # The marketplace moved, and the old API is gone
//
// Spec §6 describes marketplace.fedramp.gov. That host is now a SvelteKit shell whose
// products route only redirects here, and its former JSON API — /api/v1/providers —
// returns 404. There is no documented replacement API, so this reads the listing page,
// which is server-rendered and carries the whole catalogue.
const DefaultFedRAMPURL = "https://www.fedramp.gov/marketplace/products/"

// fedrampProductURL is the per-offering page an analyst can open to verify a result.
// Confirmed to resolve (HTTP 200) for the ids this parser extracts.
const fedrampProductURL = "https://www.fedramp.gov/marketplace/products/"

// fedrampMinRecords is the floor below which a parse is treated as broken rather than as a
// vendor that is not listed.
//
// This is the FedRAMP form of the rule NVD forced: "we found nothing" and "we could not
// look" are different claims, and only the first may render as a clean result. If the page
// is redesigned the extraction yields zero or a handful of records, which would otherwise
// report every vendor in the world as not authorized — a confident, sourced, wrong answer.
//
// The live page carried 674 records when this was written, so 200 is a wide margin for
// genuine catalogue churn while still catching a parser that has stopped matching.
const fedrampMinRecords = 200

// fedrampAssignment matches one field of one product record.
//
// # Why this shape and not the obvious one
//
// The page contains ~5,600 tidy {id:"…",csp:"…",cso:"…",status:"…",…} object literals, and
// matching those is the natural first instinct. They are the wrong data: they are
// leveraged_systems and reuses entries — the dependency lists nested inside product
// records — and their status field is not maintained. In the captured page Okta appears in
// those arrays as "Unknown" while its actual marketplace status is "FedRAMP Certified".
// A parser built on them looks like it works and quietly reports the wrong status.
//
// The authoritative records are emitted by devalue as runs of assignments against a
// per-record variable: gK.id="F1512167750";gK.csp="Okta";gK.status="FedRAMP Certified";…
// There were 674 of those, one per marketplace offering. This matches those.
var fedrampAssignment = regexp.MustCompile(
	`\b([A-Za-z_$][A-Za-z0-9_$]*)\.(id|csp|cso|status|phase|auth_type|auth_category|impact_level)="((?:[^"\\]|\\.)*)"`)

// FedRAMPOffering is one cloud service offering listed on the marketplace.
//
// Every field is recorded in FedRAMP's own vocabulary. "FedRAMP Certified" is not restated
// as "authorized", and an impact level of "LI-SaaS" is not translated into "Low" — they are
// different things in FedRAMP's scheme, and rewriting either would be laundering.
type FedRAMPOffering struct {
	ID           string
	Provider     string // csp — the cloud service provider
	Offering     string // cso — the cloud service offering
	Status       string
	Phase        string
	AuthType     string // Agency, JAB, Program
	AuthCategory string // Rev5, 20x
	ImpactLevel  string // High, Moderate, Low, LI-SaaS, 20x Low, 20x Moderate
	URL          string
	MatchedAlias string // which name matched, when it was not the canonical one
}

// FedRAMPResult is the fedramp section's data.
type FedRAMPResult struct {
	// Offerings is empty for a vendor that is genuinely not on the marketplace — which is
	// the common case and an ordinary answer, not a gap.
	Offerings []FedRAMPOffering
	// Searched records the names tried, so "no match" is legible: a vendor listed under a
	// parent company's name is a resolution problem, not a FedRAMP one.
	Searched []string
	// TotalRecords is how many marketplace records were parsed. Surfaced because a healthy
	// number is what makes an empty Offerings trustworthy.
	TotalRecords int
}

// FedRAMP reads authorization status from the FedRAMP Marketplace.
//
// It is a passive read of a public listing — no scanning or probing of vendor
// infrastructure, here or anywhere else in this tool.
type FedRAMP struct {
	baseURL string
	client  *http.Client
	// minRecords is the layout-drift floor. Unexported and settable only from within this
	// package, so it can be lowered for a trimmed fixture but not turned off in production
	// — a configurable "accept any number of records" would defeat the check entirely.
	minRecords int
}

// FedRAMPOption configures a FedRAMP source.
type FedRAMPOption func(*FedRAMP)

// WithFedRAMPURL overrides the listing URL. For tests.
func WithFedRAMPURL(url string) FedRAMPOption {
	return func(f *FedRAMP) { f.baseURL = url }
}

// WithFedRAMPClient overrides the HTTP client. For tests.
func WithFedRAMPClient(c *http.Client) FedRAMPOption {
	return func(f *FedRAMP) { f.client = c }
}

// withFedRAMPMinRecords lowers the layout-drift floor so a trimmed fixture can be parsed.
// Unexported on purpose: production must not be able to weaken this check.
func withFedRAMPMinRecords(n int) FedRAMPOption {
	return func(f *FedRAMP) { f.minRecords = n }
}

// NewFedRAMP builds the source. No credential: the marketplace listing is public.
func NewFedRAMP(opts ...FedRAMPOption) *FedRAMP {
	f := &FedRAMP{
		baseURL: DefaultFedRAMPURL,
		// The listing is several megabytes, so this allows more time than a JSON API would.
		client:     &http.Client{Timeout: 60 * time.Second},
		minRecords: fedrampMinRecords,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

func (f *FedRAMP) Name() string { return SourceFedRAMP }

// Fetch looks the vendor up in the marketplace listing.
//
// There is always something to query — the listing does not depend on a resolved
// identifier — so this never returns StatusSkipped.
func (f *FedRAMP) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	body, err := f.fetchListing(ctx)
	if err != nil {
		return Failed(SourceFedRAMP, err), err
	}

	records, err := parseFedRAMPRecords(body, f.minRecords)
	if err != nil {
		return Failed(SourceFedRAMP, err), err
	}

	names := vendorNames(q, ent)
	result := FedRAMPResult{
		Searched:     names,
		TotalRecords: len(records),
		Offerings:    matchFedRAMPOfferings(records, names),
	}

	return OK(SourceFedRAMP, result, Citation{
		Title: "FedRAMP Marketplace",
		URL:   f.baseURL,
	}), nil
}

func (f *FedRAMP) fetchListing(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.baseURL, nil)
	if err != nil {
		return "", fmt.Errorf("build fedramp request: %w", err)
	}
	req.Header.Set("Accept", "text/html")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch fedramp marketplace: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fedramp marketplace returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read fedramp marketplace response: %w", err)
	}
	return string(body), nil
}

// parseFedRAMPRecords extracts the marketplace records from the listing page.
//
// Assignments arrive grouped by record variable, so this accumulates per variable and keeps
// every group that carries the identifying fields.
func parseFedRAMPRecords(body string, minRecords int) ([]FedRAMPOffering, error) {
	byVar := make(map[string]*FedRAMPOffering)
	order := make([]string, 0, 1024)

	for _, m := range fedrampAssignment.FindAllStringSubmatch(body, -1) {
		name, field, value := m[1], m[2], m[3]

		rec, seen := byVar[name]
		if !seen {
			rec = &FedRAMPOffering{}
			byVar[name] = rec
			order = append(order, name)
		}

		switch field {
		case "id":
			rec.ID = value
		case "csp":
			rec.Provider = value
		case "cso":
			rec.Offering = value
		case "status":
			rec.Status = value
		case "phase":
			rec.Phase = value
		case "auth_type":
			rec.AuthType = value
		case "auth_category":
			rec.AuthCategory = value
		case "impact_level":
			rec.ImpactLevel = value
		}
	}

	records := make([]FedRAMPOffering, 0, len(order))
	for _, name := range order {
		rec := byVar[name]
		// A group without a provider and an offering is some other object in the payload —
		// menu items and filter definitions share the assignment form.
		if rec.Provider == "" || rec.Offering == "" {
			continue
		}
		if rec.ID != "" {
			rec.URL = fedrampProductURL + rec.ID + "/"
		}
		records = append(records, *rec)
	}

	if len(records) < minRecords {
		// Loud, per CLAUDE.md. Silence here would render as "this vendor is not authorized"
		// for every vendor, which is a sourced-looking wrong answer rather than a gap.
		return nil, fmt.Errorf(
			"parsed only %d marketplace records (expected at least %d): the listing page layout has changed",
			len(records), minRecords)
	}
	return records, nil
}

// matchFedRAMPOfferings returns every offering whose provider matches one of the names.
func matchFedRAMPOfferings(records []FedRAMPOffering, names []string) []FedRAMPOffering {
	var matched []FedRAMPOffering
	for _, rec := range records {
		provider := normalizeVendorName(rec.Provider)
		if provider == "" {
			continue
		}
		for i, name := range names {
			if normalizeVendorName(name) != provider {
				continue
			}
			// The first name is the canonical one; anything else matched via an alias, and
			// saying so lets an analyst judge whether the match is the right company.
			if i > 0 {
				rec.MatchedAlias = name
			}
			matched = append(matched, rec)
			break
		}
	}
	return matched
}

// vendorNames is the list of names to look a vendor up under: the canonical name first,
// then aliases, then the raw query as a fallback. Deduplicated, order preserved.
func vendorNames(q Query, ent ResolvedEntity) []string {
	var names []string
	seen := make(map[string]bool)

	add := func(name string) {
		key := normalizeVendorName(name)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		names = append(names, strings.TrimSpace(name))
	}

	add(ent.CanonicalName)
	for _, alias := range ent.Aliases {
		add(alias)
	}
	// Resolution can fail or return nothing; the analyst's own words are still a lookup key.
	add(q.Company)

	return names
}

// vendorSuffixes are corporate suffixes stripped before comparing names. FedRAMP writes
// "Okta" where an analyst may type "Okta, Inc." and both mean the same company.
var vendorSuffixes = []string{
	"incorporated", "inc", "llc", "l l c", "ltd", "limited", "corporation", "corp",
	"company", "co", "plc", "gmbh", "ag", "sa", "nv", "bv", "pty", "holdings", "group",
}

var vendorNoise = regexp.MustCompile(`[^a-z0-9]+`)

// normalizeVendorName canonicalizes a company name for comparison.
//
// Deliberately conservative: it folds case, punctuation and trailing corporate suffixes,
// and nothing else. Fuzzier matching would silently attach one company's authorization to
// another, which is the same class of error as a wrong CPE and just as invisible.
func normalizeVendorName(name string) string {
	s := vendorNoise.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	fields := strings.Fields(s)
	for len(fields) > 1 {
		last := fields[len(fields)-1]
		if !slices.Contains(vendorSuffixes, last) {
			break
		}
		fields = fields[:len(fields)-1]
	}
	return strings.Join(fields, " ")
}
