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
	"sync"
	"time"
)

// SourceNVD is the registered name of this source.
const SourceNVD = "nvd"

// DefaultNVDBaseURL is the NVD REST root. The two paths below — /cves/2.0 and /cpes/2.0 —
// are NVD's documented CVE API 2.0 and CPE API 2.0 endpoints, verified against the live
// service rather than assumed (CLAUDE.md: do not guess endpoint paths).
const DefaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json"

// EnvNVDKeyName is named here rather than imported from config, so sources does not depend
// on config. Kept in sync with config.EnvNVDAPIKey.
const EnvNVDKeyName = "NVD_API_KEY"

// NVD's published rate limits: 5 requests per rolling 30s window without a key, 50 with
// one. NVD asks callers to sleep ~6s between requests; the keyed interval is the same
// window divided by the higher allowance.
const (
	nvdUnkeyedInterval = 6 * time.Second
	nvdKeyedInterval   = 600 * time.Millisecond
)

// nvdMaxResultsPerPage is the API's own ceiling on resultsPerPage.
const nvdMaxResultsPerPage = 2000

// defaultNVDMaxCPEs caps how many CPEs one assessment will query, as politeness toward a
// free service. The context deadline usually bites first at the unkeyed interval; this
// stops a vendor with dozens of resolved CPEs from monopolising the rate limit when the
// deadline is generous. CPEs beyond the cap are reported, never silently dropped.
const defaultNVDMaxCPEs = 8

// NVD fetches published CVEs for a vendor's resolved CPEs.
//
// # Why virtualMatchString and not cpeName
//
// The cpeName parameter requires the part, vendor, product and version components to hold
// real values — a version-agnostic CPE returns HTTP 404. Entity resolution produces exactly
// such wildcard CPEs, so this source uses virtualMatchString, which NVD documents as
// permitting wildcards in those components.
//
// # Why zero results triggers a second call
//
// NVD answers 200 with totalResults 0 both for a vendor that genuinely has no CVEs and for
// a CPE that does not exist. Those render identically — a clean, confident, wrong report,
// which is the failure spec §15 singles out. On zero results this source asks the CPE
// dictionary whether the product exists at all, so "no known CVEs" and "this CPE was
// invented" can never be confused.
type NVD struct {
	client        *http.Client
	baseURL       string
	apiKey        string // never logged, never rendered, never placed in an error
	resultsPerCPE int
	maxCPEs       int

	// interval and last implement the rate limiter. Source implementations must be safe
	// for concurrent use, so the clock is mutex-guarded even though the orchestrator is
	// currently sequential.
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

// NewNVD builds an NVD source. An empty apiKey is valid — NVD is a free API, and the key
// only raises the rate limit — so this source is never skipped for want of a credential.
func NewNVD(apiKey string, opts ...NVDOption) *NVD {
	interval := nvdUnkeyedInterval
	if apiKey != "" {
		interval = nvdKeyedInterval
	}
	n := &NVD{
		client:        http.DefaultClient,
		baseURL:       DefaultNVDBaseURL,
		apiKey:        apiKey,
		resultsPerCPE: 20,
		maxCPEs:       defaultNVDMaxCPEs,
		interval:      interval,
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// NVDOption configures an NVD source.
type NVDOption func(*NVD)

// WithNVDBaseURL overrides the API host. Tests point this at an httptest.Server.
func WithNVDBaseURL(u string) NVDOption {
	return func(n *NVD) { n.baseURL = strings.TrimRight(u, "/") }
}

// WithNVDHTTPClient overrides the HTTP client.
func WithNVDHTTPClient(c *http.Client) NVDOption {
	return func(n *NVD) { n.client = c }
}

// WithNVDResultsPerCPE sets how many CVEs to retrieve per CPE (config nvd.results_per_cpe).
func WithNVDResultsPerCPE(count int) NVDOption {
	return func(n *NVD) {
		if count > 0 {
			n.resultsPerCPE = count
		}
	}
}

// WithNVDRateInterval overrides the minimum gap between requests. Tests set it to zero so
// they do not pay NVD's six-second courtesy delay.
func WithNVDRateInterval(d time.Duration) NVDOption {
	return func(n *NVD) { n.interval = d }
}

// WithNVDMaxCPEs overrides how many CPEs a single assessment will query.
func WithNVDMaxCPEs(count int) NVDOption {
	return func(n *NVD) {
		if count > 0 {
			n.maxCPEs = count
		}
	}
}

func (n *NVD) Name() string { return SourceNVD }

// NVDVerification records how much we know about a CPE's existence. It is carried into the
// report because it changes what a zero CVE count means.
type NVDVerification string

const (
	// NVDVerifiedByResults means the CPE returned CVEs, which proves it exists.
	NVDVerifiedByResults NVDVerification = "has CVEs"
	// NVDVerifiedInDictionary means no CVEs, but NVD does list the product — a genuine
	// clean result.
	NVDVerifiedInDictionary NVDVerification = "no CVEs on record"
	// NVDUnverified means NVD has never heard of this product. The zero is meaningless:
	// entity resolution most likely invented the CPE.
	NVDUnverified NVDVerification = "not in NVD's CPE dictionary"
)

// NVDSeverityCounts tallies CVEs by the severity NVD recorded. Counts only — assessing what
// they mean is the analyst's job (CLAUDE.md: no editorializing).
type NVDSeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	// Unscored counts CVEs carrying no CVSS metric at all. They are real vulnerabilities
	// and must not be folded into "low".
	Unscored int
}

// NVDVuln is one CVE as NVD recorded it. Every field is interpolated verbatim (spec §2.2).
type NVDVuln struct {
	ID           string
	Published    string
	LastModified string
	Description  string

	BaseScore    float64
	Severity     string // CRITICAL / HIGH / MEDIUM / LOW, exactly as returned
	CVSSVersion  string // which CVSS version produced the score above
	VectorString string
	// ScoreSource names who scored it. NVD's own analysis is Primary; a CNA's is
	// Secondary. Recorded so a third-party score is never mistaken for NVD's.
	ScoreSource string

	URL string
}

// NVDQuery is the outcome for one CPE.
type NVDQuery struct {
	CPE          string // the match string actually sent
	TotalResults int
	Verification NVDVerification
	// KnownProducts lists what NVD actually has for the vendor, populated only when the
	// CPE could not be verified. It is what turns "0 CVEs" into an actionable correction.
	KnownProducts []string
}

// NVDResult is this source's contribution to the report.
type NVDResult struct {
	Queries []NVDQuery
	// Unqueried names CPEs the rate limit or the deadline left unvisited, so a partial
	// answer is never mistaken for a complete one.
	Unqueried []string

	TotalCVEs int
	Severity  NVDSeverityCounts
	CVEs      []NVDVuln
}

// Fetch queries NVD for every resolved CPE.
func (n *NVD) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	matches := cpeMatchStrings(ent.CPEs)
	if len(matches) == 0 {
		return Skipped(n.Name(),
			"no CPEs resolved for this vendor; NVD is keyed on CPE"), nil
	}

	result := NVDResult{}
	seen := make(map[string]bool)

	for i, match := range matches {
		if i >= n.maxCPEs {
			result.Unqueried = append(result.Unqueried, matches[i:]...)
			break
		}

		query, vulns, err := n.queryCPE(ctx, match)
		if err != nil {
			// A deadline reached partway through is a partial answer, not a failure:
			// whatever already came back is still true. Record the rest as unqueried.
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				result.Unqueried = append(result.Unqueried, matches[i:]...)
				break
			}
			return Failed(n.Name(), err), err
		}

		result.Queries = append(result.Queries, query)
		for _, v := range vulns {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			result.CVEs = append(result.CVEs, v)
		}
	}

	// Every CPE we managed to query was fictional, so there is no trustworthy answer here.
	// Reporting "0 CVEs" would be the silently-wrong output spec §15 warns about.
	if len(result.Queries) > 0 && allUnverified(result.Queries) {
		// The queries travel with the failure. The renderer only reads Data on an OK section,
		// so this changes nothing an analyst sees, but it is the difference between "NVD
		// judged these CPEs fictional" and "NVD never got far enough to judge" — and the
		// resolution cache has to tell those apart before it pins the mapping for 720h.
		section := Failed(n.Name(), unverifiedError(result.Queries))
		section.Data = result
		return section, nil
	}

	sortVulns(result.CVEs)
	result.TotalCVEs = len(result.CVEs)
	result.Severity = countSeverities(result.CVEs)

	citations := make([]Citation, 0, len(result.CVEs))
	for _, v := range result.CVEs {
		citations = append(citations, Citation{Title: v.ID, URL: v.URL})
	}
	return OK(n.Name(), result, citations...), nil
}

// queryCPE fetches one CPE's CVEs and, when there are none, establishes whether that means
// "clean" or "this CPE does not exist".
func (n *NVD) queryCPE(ctx context.Context, match string) (NVDQuery, []NVDVuln, error) {
	total, vulns, err := n.fetchCVEs(ctx, match)
	if err != nil {
		return NVDQuery{}, nil, err
	}
	query := NVDQuery{CPE: match, TotalResults: total, Verification: NVDVerifiedByResults}
	if total > 0 {
		return query, vulns, nil
	}

	exists, err := n.cpeExists(ctx, match)
	if err != nil {
		return NVDQuery{}, nil, err
	}
	if exists {
		query.Verification = NVDVerifiedInDictionary
		return query, nil, nil
	}

	query.Verification = NVDUnverified
	// Only now is a third request worth spending: naming the vendor's real products is
	// what lets an analyst correct the resolution instead of just distrusting it.
	products, err := n.vendorProducts(ctx, match)
	if err != nil {
		return NVDQuery{}, nil, err
	}
	query.KnownProducts = products
	return query, nil, nil
}

// fetchCVEs pages through the CVE API until resultsPerCPE is met or the results run out.
func (n *NVD) fetchCVEs(ctx context.Context, match string) (int, []NVDVuln, error) {
	var (
		vulns []NVDVuln
		total int
		start int
	)
	for {
		perPage := n.resultsPerCPE - len(vulns)
		if perPage > nvdMaxResultsPerPage {
			perPage = nvdMaxResultsPerPage
		}
		if perPage <= 0 {
			break
		}

		u := fmt.Sprintf("%s/cves/2.0?virtualMatchString=%s&resultsPerPage=%d&startIndex=%d",
			n.baseURL, url.QueryEscape(match), perPage, start)

		body, err := n.get(ctx, u)
		if err != nil {
			return 0, nil, err
		}
		page, err := parseNVDCVEs(body)
		if err != nil {
			return 0, nil, fmt.Errorf("CVE lookup for %s: %w", match, err)
		}

		total = page.total
		vulns = append(vulns, page.vulns...)
		start += len(page.vulns)

		// A page returning nothing ends the walk regardless of what totalResults claimed,
		// so a server disagreeing with itself cannot spin this loop forever.
		if len(page.vulns) == 0 || start >= total {
			break
		}
	}
	return total, vulns, nil
}

// cpeExists asks the CPE dictionary whether a product is listed at all.
func (n *NVD) cpeExists(ctx context.Context, match string) (bool, error) {
	u := fmt.Sprintf("%s/cpes/2.0?cpeMatchString=%s&resultsPerPage=1",
		n.baseURL, url.QueryEscape(match))

	body, err := n.get(ctx, u)
	if err != nil {
		return false, err
	}
	page, err := parseNVDCPEs(body)
	if err != nil {
		return false, fmt.Errorf("CPE dictionary lookup for %s: %w", match, err)
	}
	return page.total > 0, nil
}

// vendorProducts lists the distinct product tokens NVD holds for a CPE's vendor.
func (n *NVD) vendorProducts(ctx context.Context, match string) ([]string, error) {
	vendor := vendorMatchString(match)
	if vendor == "" {
		return nil, nil
	}

	u := fmt.Sprintf("%s/cpes/2.0?cpeMatchString=%s&resultsPerPage=%d",
		n.baseURL, url.QueryEscape(vendor), nvdMaxResultsPerPage)

	body, err := n.get(ctx, u)
	if err != nil {
		return nil, err
	}
	page, err := parseNVDCPEs(body)
	if err != nil {
		return nil, fmt.Errorf("CPE dictionary lookup for %s: %w", vendor, err)
	}
	return page.products, nil
}

// get performs a rate-limited GET and returns the body, mapping transport and HTTP status
// problems to errors that never contain the API key.
func (n *NVD) get(ctx context.Context, rawURL string) ([]byte, error) {
	if err := n.wait(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	// NVD takes the key in a header, not a query parameter. That keeps it out of the URL,
	// and therefore out of url.Error strings, which are rendered into the report.
	if n.apiKey != "" {
		req.Header.Set("apiKey", n.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("NVD request timed out: %w", err)
		}
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("NVD request cancelled: %w", err)
		}
		return nil, fmt.Errorf("NVD request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read NVD response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nvdStatusError(resp.StatusCode)
	}
	return body, nil
}

// wait enforces the minimum gap between requests, giving up if the context expires first.
func (n *NVD) wait(ctx context.Context) error {
	n.mu.Lock()
	now := time.Now()
	earliest := n.last.Add(n.interval)
	if now.Before(earliest) {
		n.last = earliest
	} else {
		n.last = now
	}
	delay := n.last.Sub(now)
	n.mu.Unlock()

	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// nvdStatusError maps a non-200 status to an analyst-readable error.
//
// The response body is deliberately excluded, for the same reason as BitSight's: it is
// external text that gets rendered into a report.
func nvdStatusError(code int) error {
	switch code {
	case http.StatusNotFound:
		return errors.New(
			"NVD returned HTTP 404; the request parameters were rejected as invalid")
	case http.StatusForbidden:
		return fmt.Errorf(
			"NVD rejected the request (HTTP 403); this usually means the rate limit was "+
				"exceeded or %s is invalid", EnvNVDKeyName)
	case http.StatusTooManyRequests:
		return errors.New("NVD rate limit exceeded (HTTP 429); retry later")
	case http.StatusServiceUnavailable:
		return errors.New("NVD is unavailable (HTTP 503); retry later")
	default:
		return fmt.Errorf("NVD returned HTTP %d", code)
	}
}

// cpeMatchStrings reduces resolved CPEs to distinct cpe:2.3:<part>:<vendor>:<product>
// prefixes, which is the form virtualMatchString wants.
//
// The version and the wildcard tail are dropped on purpose: we want every CVE affecting the
// product, not just one release. Order is preserved so runs are reproducible.
func cpeMatchStrings(cpes []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, c := range cpes {
		parts := strings.Split(strings.TrimSpace(c), ":")
		if len(parts) < 5 {
			continue
		}
		match := strings.Join(parts[:5], ":")
		if strings.HasSuffix(match, ":") || seen[match] {
			continue
		}
		seen[match] = true
		out = append(out, match)
	}
	return out
}

// vendorMatchString truncates a match string to its vendor: cpe:2.3:a:okta:okta -> cpe:2.3:a:okta.
func vendorMatchString(match string) string {
	parts := strings.Split(match, ":")
	if len(parts) < 5 {
		return ""
	}
	return strings.Join(parts[:4], ":")
}

// AnyVerified reports whether NVD confirmed at least one of the CPEs it was given, either
// by returning CVEs for it or by listing it in the dictionary.
//
// This is the authoritative answer to "did resolution invent these identifiers", and it is
// a by-product of work the fan-out already did — checking it costs no extra request. What
// it does not report is whether the *unverified* CPEs were pruned: a mapping can be
// confirmed here while still carrying invented entries alongside, which NVD names loudly on
// every run.
func (r NVDResult) AnyVerified() bool {
	for _, q := range r.Queries {
		if q.Verification != NVDUnverified {
			return true
		}
	}
	return false
}

func allUnverified(queries []NVDQuery) bool {
	for _, q := range queries {
		if q.Verification != NVDUnverified {
			return false
		}
	}
	return true
}

// unverifiedError explains that resolution, not NVD, is the problem — and names the real
// products so the analyst can correct it with --domain-style precision.
func unverifiedError(queries []NVDQuery) error {
	var b strings.Builder
	b.WriteString("none of the resolved CPEs exist in NVD's CPE dictionary, so a zero CVE " +
		"count would be meaningless; entity resolution likely invented them")
	for _, q := range queries {
		fmt.Fprintf(&b, "\n  %s is unknown to NVD", q.CPE)
		if len(q.KnownProducts) > 0 {
			fmt.Fprintf(&b, "; NVD lists these products for that vendor: %s",
				strings.Join(q.KnownProducts, ", "))
		}
	}
	return errors.New(b.String())
}

func countSeverities(vulns []NVDVuln) NVDSeverityCounts {
	var counts NVDSeverityCounts
	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			counts.Critical++
		case "HIGH":
			counts.High++
		case "MEDIUM":
			counts.Medium++
		case "LOW":
			counts.Low++
		default:
			counts.Unscored++
		}
	}
	return counts
}

// sortVulns orders by score descending, then by ID, so the same data always renders the
// same way. This is ordering by a recorded value, not a judgment about which matters most.
func sortVulns(vulns []NVDVuln) {
	sort.SliceStable(vulns, func(i, j int) bool {
		if vulns[i].BaseScore != vulns[j].BaseScore {
			return vulns[i].BaseScore > vulns[j].BaseScore
		}
		return vulns[i].ID < vulns[j].ID
	})
}

// --- parsing -----------------------------------------------------------------
//
// All CVE-response parsing lives in parseNVDCVEs and all dictionary parsing in
// parseNVDCPEs, each with a recorded fixture, so a shape change is caught by a test rather
// than by an analyst reading an empty section (CLAUDE.md).

type nvdCVEResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	// Metrics is keyed by scoring system — cvssMetricV40, cvssMetricV31, cvssMetricV30,
	// cvssMetricV2, and non-CVSS systems such as ssvcV203. Modelled as a map so an
	// unrecognised system decodes harmlessly instead of breaking the parse.
	Metrics map[string][]nvdMetric `json:"metrics"`
}

type nvdMetric struct {
	Source string `json:"source"`
	Type   string `json:"type"` // Primary (NVD's own analysis) or Secondary (a CNA's)
	// BaseSeverity at this level is where CVSS v2 puts it. v3.x and v4.0 put it inside
	// cvssData instead — a difference that silently yields an empty severity if missed.
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVEPage struct {
	total int
	vulns []NVDVuln
}

func parseNVDCVEs(body []byte) (nvdCVEPage, error) {
	var resp nvdCVEResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nvdCVEPage{}, fmt.Errorf("parse CVE response: %w", err)
	}

	page := nvdCVEPage{total: resp.TotalResults}
	for i, entry := range resp.Vulnerabilities {
		c := entry.CVE
		if strings.TrimSpace(c.ID) == "" {
			return nvdCVEPage{}, fmt.Errorf(
				"CVE entry %d has no id; response shape may have changed", i)
		}

		v := NVDVuln{
			ID:           c.ID,
			Published:    c.Published,
			LastModified: c.LastModified,
			Description:  englishDescription(c),
			URL:          "https://nvd.nist.gov/vuln/detail/" + c.ID,
		}
		if m, key, ok := selectMetric(c.Metrics); ok {
			v.BaseScore = m.CVSSData.BaseScore
			v.Severity = metricSeverity(m)
			v.CVSSVersion = metricVersion(m, key)
			v.VectorString = m.CVSSData.VectorString
			v.ScoreSource = scoreSource(m)
		}
		page.vulns = append(page.vulns, v)
	}
	return page, nil
}

// nvdMetricPreference is the order in which scoring systems are consulted.
//
// Newest CVSS version first: scores from different versions are computed differently and
// comparing them is meaningless, so the whole report should speak one version wherever it
// can. Within a version, Primary (NVD's own analysis) beats Secondary (a CNA's), and the
// choice is recorded in ScoreSource either way.
var nvdMetricPreference = []string{
	"cvssMetricV40",
	"cvssMetricV31",
	"cvssMetricV30",
	"cvssMetricV2",
}

func selectMetric(metrics map[string][]nvdMetric) (nvdMetric, string, bool) {
	for _, key := range nvdMetricPreference {
		entries := metrics[key]
		if len(entries) == 0 {
			continue
		}
		// Prefer NVD's own primary analysis, then any primary, then whatever exists.
		for _, m := range entries {
			if m.Type == "Primary" && m.Source == "nvd@nist.gov" {
				return m, key, true
			}
		}
		for _, m := range entries {
			if m.Type == "Primary" {
				return m, key, true
			}
		}
		return entries[0], key, true
	}
	return nvdMetric{}, "", false
}

// metricSeverity reads the severity from whichever level this CVSS version records it at.
func metricSeverity(m nvdMetric) string {
	if m.CVSSData.BaseSeverity != "" {
		return m.CVSSData.BaseSeverity
	}
	return m.BaseSeverity
}

// metricVersion prefers the version the payload states; the map key is the fallback.
func metricVersion(m nvdMetric, key string) string {
	if m.CVSSData.Version != "" {
		return m.CVSSData.Version
	}
	return strings.TrimPrefix(key, "cvssMetric")
}

func scoreSource(m nvdMetric) string {
	kind := m.Type
	if kind == "" {
		kind = "unspecified"
	}
	if m.Source == "" {
		return kind
	}
	return fmt.Sprintf("%s (%s)", kind, m.Source)
}

func englishDescription(c nvdCVE) string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(c.Descriptions) > 0 {
		return c.Descriptions[0].Value
	}
	return ""
}

type nvdCPEResponse struct {
	TotalResults int `json:"totalResults"`
	Products     []struct {
		CPE struct {
			CPEName string `json:"cpeName"`
		} `json:"cpe"`
	} `json:"products"`
}

type nvdCPEPage struct {
	total    int
	products []string
}

// parseNVDCPEs extracts the distinct product tokens from a CPE dictionary response.
//
// The dictionary lists one entry per version, so a vendor with nine products can return
// hundreds of rows; only the distinct product names are useful here.
func parseNVDCPEs(body []byte) (nvdCPEPage, error) {
	var resp nvdCPEResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nvdCPEPage{}, fmt.Errorf("parse CPE dictionary response: %w", err)
	}

	page := nvdCPEPage{total: resp.TotalResults}
	seen := make(map[string]bool)
	for i, p := range resp.Products {
		parts := strings.Split(p.CPE.CPEName, ":")
		if len(parts) < 5 {
			return nvdCPEPage{}, fmt.Errorf(
				"CPE dictionary entry %d has a malformed cpeName %q; response shape may have changed",
				i, p.CPE.CPEName)
		}
		if name := parts[4]; !seen[name] {
			seen[name] = true
			page.products = append(page.products, name)
		}
	}
	sort.Strings(page.products)
	return page, nil
}
