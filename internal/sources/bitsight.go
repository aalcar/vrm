package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// SourceBitSight is the registered name of this source.
const SourceBitSight = "bitsight"

// DefaultBitSightBaseURL is BitSight's API host. Endpoint paths below come from the
// analyst-supplied bitsight-api-info.md; none of them are guessed (spec §6).
const DefaultBitSightBaseURL = "https://api.bitsighttech.com"

// maxResponseBytes caps how much of a response we read. A source that starts streaming
// something enormous should fail, not exhaust memory during an assessment.
const maxResponseBytes = 8 << 20 // 8 MiB

// BitSight fetches a vendor's security rating, keyed on domain.
//
// Ratings are not retrievable by domain directly, so this is a two-step call: search for
// the company GUID by domain, then fetch that company's rating.
type BitSight struct {
	client  *http.Client
	baseURL string
	apiKey  string // never logged, never rendered, never placed in an error
}

// NewBitSight builds a BitSight source. A zero client falls back to http.DefaultClient;
// per-source timeouts come from the context the orchestrator supplies.
func NewBitSight(apiKey string, opts ...BitSightOption) *BitSight {
	b := &BitSight{
		client:  http.DefaultClient,
		baseURL: DefaultBitSightBaseURL,
		apiKey:  apiKey,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// BitSightOption configures a BitSight source.
type BitSightOption func(*BitSight)

// WithBitSightBaseURL overrides the API host. Tests point this at an httptest.Server.
func WithBitSightBaseURL(u string) BitSightOption {
	return func(b *BitSight) { b.baseURL = strings.TrimRight(u, "/") }
}

// WithBitSightHTTPClient overrides the HTTP client.
func WithBitSightHTTPClient(c *http.Client) BitSightOption {
	return func(b *BitSight) { b.client = c }
}

func (b *BitSight) Name() string { return SourceBitSight }

// BitSightRating is this source's contribution to the report.
//
// CompanyName, CompanyGUID and QueriedDomain are carried so an analyst can see which
// company BitSight matched. A wrong match silently reports another company's rating, and
// nothing about the number itself would look wrong (spec §15).
//
// The response's rating_details is deliberately not modelled: it is keyed by metric slug,
// so it is naturally a map, and Section.Data must be a concrete struct (CLAUDE.md).
type BitSightRating struct {
	CompanyName   string
	CompanyGUID   string
	PrimaryDomain string
	Industry      string
	Rating        int    // BitSight's numeric rating, e.g. 750
	RatingRange   string // e.g. "Intermediate"
	RatingDate    string // ISO date of the rating, as returned

	// IndustryMedian is BitSight's placement of this rating against the industry median
	// ("below", "above"). Recorded verbatim; interpreting it is the analyst's job.
	IndustryMedian string
	// ReportURL is BitSight's own company page — the one link an analyst can actually
	// click through to verify this rating.
	ReportURL string

	QueriedDomain string // the domain that produced this match
	// Alternatives names the other companies the domain search also returned. A domain
	// search returns fuzzy matches, including unrelated customer subdomains, so an
	// analyst needs to see what else was on the list to catch a wrong pick.
	Alternatives []string
}

// Fetch resolves the first usable domain to a BitSight company and returns its most recent
// rating.
func (b *BitSight) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	domain := firstNonEmpty(ent.Domains)
	if domain == "" {
		return Skipped(b.Name(),
			"no domain resolved for this vendor; BitSight is keyed on domain"), nil
	}

	companies, err := b.searchByDomain(ctx, domain)
	if err != nil {
		return Failed(b.Name(), err), err
	}
	if len(companies) == 0 {
		return Skipped(b.Name(), fmt.Sprintf(
			"no BitSight company matches domain %q; the vendor may not be rated", domain)), nil
	}

	company, alternatives := selectCompany(companies, domain)
	rating, err := b.fetchRating(ctx, company.GUID)
	if err != nil {
		return Failed(b.Name(), err), err
	}
	rating.QueriedDomain = domain
	rating.Alternatives = alternatives

	var citations []Citation
	if rating.ReportURL != "" {
		citations = append(citations, Citation{
			Title: fmt.Sprintf("BitSight company page — %s", rating.CompanyName),
			URL:   rating.ReportURL,
		})
	}
	return OK(b.Name(), rating, citations...), nil
}

// searchByDomain calls GET /ratings/v1/companies/search?domain=<domain>.
func (b *BitSight) searchByDomain(ctx context.Context, domain string) ([]bitsightCompany, error) {
	u := fmt.Sprintf("%s/ratings/v1/companies/search?domain=%s",
		b.baseURL, url.QueryEscape(domain))

	body, err := b.get(ctx, u)
	if err != nil {
		return nil, err
	}
	companies, err := parseCompanySearch(body)
	if err != nil {
		return nil, fmt.Errorf("company search for %q: %w", domain, err)
	}
	return companies, nil
}

// fetchRating calls GET /ratings/v1/companies/{guid}.
func (b *BitSight) fetchRating(ctx context.Context, guid string) (BitSightRating, error) {
	u := fmt.Sprintf("%s/ratings/v1/companies/%s", b.baseURL, url.PathEscape(guid))

	body, err := b.get(ctx, u)
	if err != nil {
		return BitSightRating{}, err
	}
	rating, err := parseRatingDetail(body)
	if err != nil {
		return BitSightRating{}, fmt.Errorf("rating for company %s: %w", guid, err)
	}
	return rating, nil
}

// get performs an authenticated GET and returns the body, mapping transport and HTTP
// status problems to errors that never contain the API key.
func (b *BitSight) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	// HTTP Basic with the API token as username and an empty password
	// (bitsight-api-info.md §4). SetBasicAuth base64-encodes it into the Authorization
	// header, which is never logged or echoed.
	req.SetBasicAuth(b.apiKey, "")
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		// url.Error includes the request URL but not the Authorization header, so no
		// credential can reach the report through here.
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("BitSight request timed out: %w", err)
		}
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("BitSight request cancelled: %w", err)
		}
		return nil, fmt.Errorf("BitSight request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read BitSight response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode)
	}
	return body, nil
}

// statusError maps a non-200 status to an analyst-readable error.
//
// The response body is deliberately not included: it is attacker- and vendor-controlled
// text that gets rendered into a report, and on an auth failure some APIs echo back the
// credential that was rejected.
func statusError(code int) error {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf(
			"BitSight rejected the credentials (HTTP %d); check %s", code, EnvBitsightKeyName)
	case http.StatusNotFound:
		return fmt.Errorf("BitSight returned HTTP 404; the company or endpoint was not found")
	case http.StatusTooManyRequests:
		return errors.New("BitSight rate limit exceeded (HTTP 429); retry later")
	default:
		return fmt.Errorf("BitSight returned HTTP %d", code)
	}
}

// EnvBitsightKeyName is named here rather than imported from config, so sources does not
// depend on config. Kept in sync with config.EnvBitsightAPIKey.
const EnvBitsightKeyName = "BITSIGHT_API_KEY"

// bitsightCompany is one entry from the domain search response.
//
// These are the only fields search returns. In particular there is no is_primary and no
// confidence score here — is_primary exists on the company *detail* response, not on
// search results — so selection cannot lean on either.
type bitsightCompany struct {
	GUID          string `json:"guid"`
	Name          string `json:"name"`
	PrimaryDomain string `json:"primary_domain"`
	Industry      string `json:"industry"`
}

type bitsightSearchResponse struct {
	Count   int               `json:"count"`
	Results []bitsightCompany `json:"results"`
}

// parseCompanySearch extracts the company list from a domain search response.
//
// All parsing for this endpoint lives here so a shape change is caught by one fixture test
// rather than by an analyst reading an empty section (CLAUDE.md).
func parseCompanySearch(body []byte) ([]bitsightCompany, error) {
	var resp bitsightSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse company search response: %w", err)
	}
	// An empty results list is a legitimate "not rated" answer, not a parse failure. The
	// caller turns it into StatusSkipped.
	for i, c := range resp.Results {
		if strings.TrimSpace(c.GUID) == "" {
			return nil, fmt.Errorf("company search result %d has no guid; response shape may have changed", i)
		}
	}
	return resp.Results, nil
}

// selectCompany picks one company from a multi-result search, deterministically, and
// returns the names of the others so a wrong pick is visible in the report.
//
// A domain search is fuzzy: searching okta.com returns "Okta, Inc.", "Okta Group", and
// "ritasfranchises.okta.com" — the last being an unrelated customer's subdomain. Taking
// the first result would sometimes rate the wrong organisation, and the number itself
// would look perfectly normal (spec §15).
//
// So: prefer a company whose primary_domain is exactly the domain searched for, which
// eliminates subdomain matches; among those keep BitSight's own ordering; fall back to the
// first result if nothing matches exactly. This must never vary between runs.
func selectCompany(companies []bitsightCompany, domain string) (bitsightCompany, []string) {
	chosen := companies[0]
	for _, c := range companies {
		if strings.EqualFold(strings.TrimSpace(c.PrimaryDomain), strings.TrimSpace(domain)) {
			chosen = c
			break
		}
	}

	alternatives := make([]string, 0, len(companies)-1)
	for _, c := range companies {
		if c.GUID != chosen.GUID {
			alternatives = append(alternatives, fmt.Sprintf("%s [%s]", c.Name, c.PrimaryDomain))
		}
	}
	return chosen, alternatives
}

type bitsightRatingEntry struct {
	RatingDate string `json:"rating_date"`
	Rating     int    `json:"rating"`
	Range      string `json:"range"`
}

type bitsightCompanyDetail struct {
	GUID          string `json:"guid"`
	Name          string `json:"name"`
	PrimaryDomain string `json:"primary_domain"`
	Industry      string `json:"industry"`
	// DisplayURL is BitSight's own company page for this vendor.
	DisplayURL string `json:"display_url"`
	// IndustryMedian is "below"/"above" relative to the vendor's industry.
	IndustryMedian string `json:"rating_industry_median"`
	// CurrentRating is the authoritative current score. Ratings is the full historical
	// series — several hundred entries — returned most-recent-first.
	CurrentRating int                   `json:"current_rating"`
	Ratings       []bitsightRatingEntry `json:"ratings"`
}

// parseRatingDetail extracts the current rating from a company detail response.
//
// A response carrying neither current_rating nor any ratings entry is a parse failure, not
// a zero rating: a 0 rendered beside genuine scores is indistinguishable to an analyst,
// and BitSight dropping those fields is exactly the shape change this must catch loudly.
func parseRatingDetail(body []byte) (BitSightRating, error) {
	var detail bitsightCompanyDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return BitSightRating{}, fmt.Errorf("parse rating response: %w", err)
	}
	if detail.CurrentRating == 0 && len(detail.Ratings) == 0 {
		return BitSightRating{}, errors.New(
			"rating response contained neither current_rating nor any ratings entry")
	}

	// The series arrives most-recent-first, but sort rather than trust the order — a
	// silently reordered response would otherwise report a years-old score as current.
	// rating_date is an ISO date, so lexical ordering is chronological.
	var latest bitsightRatingEntry
	if len(detail.Ratings) > 0 {
		entries := make([]bitsightRatingEntry, len(detail.Ratings))
		copy(entries, detail.Ratings)
		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].RatingDate > entries[j].RatingDate
		})
		latest = entries[0]
	}

	// current_rating is authoritative; the series supplies the date and band.
	rating := detail.CurrentRating
	if rating == 0 {
		rating = latest.Rating
	}

	return BitSightRating{
		CompanyName:    detail.Name,
		CompanyGUID:    detail.GUID,
		PrimaryDomain:  detail.PrimaryDomain,
		Industry:       detail.Industry,
		Rating:         rating,
		RatingRange:    latest.Range,
		RatingDate:     latest.RatingDate,
		IndustryMedian: detail.IndustryMedian,
		ReportURL:      detail.DisplayURL,
	}, nil
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}
