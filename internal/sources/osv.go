package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// SourceOSV is the registered name of this source.
const SourceOSV = "osv"

// DefaultOSVBaseURL is OSV's API host. The /v1/query path is OSV's documented query
// endpoint, verified against the live service (spec §6).
const DefaultOSVBaseURL = "https://api.osv.dev"

// osvMaxPages bounds page-token following. A vendor with thousands of advisories should
// produce a truncated section, not an unbounded walk inside a 30s budget.
const osvMaxPages = 5

// OSV fetches known vulnerabilities for the open-source packages a vendor publishes.
//
// # Skipped is the common case
//
// OSV is keyed on packages, not companies. Most vendors publish no OSS at all, so an empty
// ResolvedEntity.Packages is the ordinary, correct outcome and yields StatusSkipped — not a
// failure, and not something to "fix" by forcing a vendor→package mapping (spec §6).
//
// # No credential
//
// OSV is free and unauthenticated, so this source is never skipped for want of a key.
type OSV struct {
	client  *http.Client
	baseURL string
}

// NewOSV builds an OSV source.
func NewOSV(opts ...OSVOption) *OSV {
	o := &OSV{client: http.DefaultClient, baseURL: DefaultOSVBaseURL}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// OSVOption configures an OSV source.
type OSVOption func(*OSV)

// WithOSVBaseURL overrides the API host. Tests point this at an httptest.Server.
func WithOSVBaseURL(u string) OSVOption {
	return func(o *OSV) { o.baseURL = strings.TrimRight(u, "/") }
}

// WithOSVHTTPClient overrides the HTTP client.
func WithOSVHTTPClient(c *http.Client) OSVOption {
	return func(o *OSV) { o.client = c }
}

func (o *OSV) Name() string { return SourceOSV }

// OSVVuln is one advisory as OSV recorded it.
//
// Note what is absent: a numeric CVSS score. OSV supplies a CVSS vector string, not a base
// score, and deriving the number would be recomputing a value rather than reporting one.
// The vector and the database's own qualitative rating are carried verbatim instead.
type OSVVuln struct {
	ID      string
	Package Package
	Summary string

	Published string
	Modified  string

	// Aliases are the other identifiers for this advisory. CVEs is the CVE-numbered
	// subset, pulled out because it is what cross-references this to the NVD section.
	Aliases []string
	CVEs    []string

	// Severity is the advisory database's own qualitative rating — GitHub's vocabulary is
	// CRITICAL/HIGH/MODERATE/LOW, which is deliberately not translated into NVD's
	// CRITICAL/HIGH/MEDIUM/LOW. Silently restating one scale in another's words would be
	// laundering a value, and MODERATE is not a synonym for MEDIUM.
	Severity string
	// CVSSVector and CVSSType record the vector verbatim and which CVSS revision produced
	// it (CVSS_V3, CVSS_V4).
	CVSSVector string
	CVSSType   string

	URL string
}

// OSVQuery is the outcome for one package.
type OSVQuery struct {
	Package    Package
	TotalVulns int
	// Truncated reports that OSV had more pages than the page cap allowed.
	Truncated bool
}

// OSVSeverityCounts tallies advisories by the database's own rating. Unrated is its own
// bucket: 55 of HashiCorp Vault's 110 advisories carry no severity at all, and folding
// those into "low" would understate them.
type OSVSeverityCounts struct {
	Critical int
	High     int
	Moderate int
	Low      int
	Unrated  int
}

// OSVResult is this source's contribution to the report.
type OSVResult struct {
	Queries    []OSVQuery
	TotalVulns int
	Severity   OSVSeverityCounts
	Vulns      []OSVVuln
}

// Fetch queries OSV for every resolved package.
func (o *OSV) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	if len(ent.Packages) == 0 {
		return Skipped(o.Name(),
			"no open-source packages resolved for this vendor; OSV is keyed on package, "+
				"and most vendors publish none"), nil
	}

	result := OSVResult{}
	seen := make(map[string]bool)

	for _, pkg := range ent.Packages {
		vulns, truncated, err := o.queryPackage(ctx, pkg)
		if err != nil {
			return Failed(o.Name(), err), err
		}

		result.Queries = append(result.Queries, OSVQuery{
			Package:    pkg,
			TotalVulns: len(vulns),
			Truncated:  truncated,
		})
		// The same advisory can affect several of a vendor's packages; count it once but
		// keep the package that first surfaced it.
		for _, v := range vulns {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			result.Vulns = append(result.Vulns, v)
		}
	}

	sortOSVVulns(result.Vulns)
	result.TotalVulns = len(result.Vulns)
	result.Severity = countOSVSeverities(result.Vulns)

	citations := make([]Citation, 0, len(result.Vulns))
	for _, v := range result.Vulns {
		citations = append(citations, Citation{Title: v.ID, URL: v.URL})
	}
	return OK(o.Name(), result, citations...), nil
}

// queryPackage POSTs one package to /v1/query, following page tokens up to the cap.
func (o *OSV) queryPackage(ctx context.Context, pkg Package) ([]OSVVuln, bool, error) {
	var (
		all   []OSVVuln
		token string
	)
	for page := 0; page < osvMaxPages; page++ {
		body, err := o.post(ctx, pkg, token)
		if err != nil {
			return nil, false, err
		}
		vulns, next, err := parseOSVQuery(body, pkg)
		if err != nil {
			return nil, false, fmt.Errorf("OSV lookup for %s: %w", pkg, err)
		}

		all = append(all, vulns...)
		if next == "" {
			return all, false, nil
		}
		token = next
	}
	return all, true, nil
}

// osvQueryRequest is the documented request body. Ecosystem is always sent: OSV answers
// HTTP 400 "invalid query" for a name without one.
type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	PageToken string `json:"page_token,omitempty"`
}

func (o *OSV) post(ctx context.Context, pkg Package, pageToken string) ([]byte, error) {
	var reqBody osvQueryRequest
	reqBody.Package.Name = pkg.Name
	reqBody.Package.Ecosystem = pkg.Ecosystem
	reqBody.PageToken = pageToken

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encode OSV query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.baseURL+"/v1/query", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("OSV request timed out: %w", err)
		}
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("OSV request cancelled: %w", err)
		}
		return nil, fmt.Errorf("OSV request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read OSV response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, osvStatusError(resp.StatusCode, pkg)
	}
	return body, nil
}

// osvStatusError maps a non-200 status to an analyst-readable error. As elsewhere, the
// response body is excluded — it is external text rendered into a report.
func osvStatusError(code int, pkg Package) error {
	switch code {
	case http.StatusBadRequest:
		// The realistic cause is an ecosystem OSV does not recognize; resolution is the
		// thing to look at, not OSV.
		return fmt.Errorf(
			"OSV rejected the query for %s as invalid (HTTP 400); the ecosystem %q may not "+
				"be one OSV recognizes", pkg, pkg.Ecosystem)
	case http.StatusTooManyRequests:
		return errors.New("OSV rate limit exceeded (HTTP 429); retry later")
	case http.StatusServiceUnavailable:
		return errors.New("OSV is unavailable (HTTP 503); retry later")
	default:
		return fmt.Errorf("OSV returned HTTP %d for %s", code, pkg)
	}
}

// --- parsing -----------------------------------------------------------------

type osvResponse struct {
	Vulns         []osvVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token"`
}

type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Aliases   []string `json:"aliases"`
	Severity  []struct {
		Type  string `json:"type"`  // CVSS_V3, CVSS_V4
		Score string `json:"score"` // a CVSS vector string, not a number
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// parseOSVQuery extracts advisories from a query response.
//
// A package with no known vulnerabilities returns a bare "{}" — no vulns key at all — which
// is a legitimate clean answer, not a parse failure or a missing field.
func parseOSVQuery(body []byte, pkg Package) ([]OSVVuln, string, error) {
	var resp osvResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", fmt.Errorf("parse OSV response: %w", err)
	}

	vulns := make([]OSVVuln, 0, len(resp.Vulns))
	for i, v := range resp.Vulns {
		if strings.TrimSpace(v.ID) == "" {
			return nil, "", fmt.Errorf(
				"OSV entry %d has no id; response shape may have changed", i)
		}

		out := OSVVuln{
			ID:        v.ID,
			Package:   pkg,
			Summary:   v.Summary,
			Published: v.Published,
			Modified:  v.Modified,
			Aliases:   v.Aliases,
			CVEs:      cveAliases(v.Aliases),
			Severity:  v.DatabaseSpecific.Severity,
			URL:       "https://osv.dev/vulnerability/" + v.ID,
		}
		// Newest CVSS revision wins, for the same reason as NVD: vectors from different
		// revisions are not comparable.
		for _, want := range []string{"CVSS_V4", "CVSS_V3"} {
			for _, s := range v.Severity {
				if s.Type == want {
					out.CVSSType = s.Type
					out.CVSSVector = s.Score
					break
				}
			}
			if out.CVSSType != "" {
				break
			}
		}
		vulns = append(vulns, out)
	}
	return vulns, resp.NextPageToken, nil
}

// cveAliases picks the CVE identifiers out of an advisory's alias list. OSV advisories also
// carry GHSA, GO and BIT identifiers, which do not cross-reference to the NVD section.
func cveAliases(aliases []string) []string {
	var out []string
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

func countOSVSeverities(vulns []OSVVuln) OSVSeverityCounts {
	var counts OSVSeverityCounts
	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			counts.Critical++
		case "HIGH":
			counts.High++
		case "MODERATE", "MEDIUM":
			counts.Moderate++
		case "LOW":
			counts.Low++
		default:
			counts.Unrated++
		}
	}
	return counts
}

// osvSeverityRank orders the database's qualitative ratings for display. Unrated sorts last
// because it says nothing, not because it is safe.
var osvSeverityRank = map[string]int{
	"CRITICAL": 0,
	"HIGH":     1,
	"MODERATE": 2,
	"MEDIUM":   2,
	"LOW":      3,
}

func sortOSVVulns(vulns []OSVVuln) {
	rank := func(v OSVVuln) int {
		if r, ok := osvSeverityRank[strings.ToUpper(v.Severity)]; ok {
			return r
		}
		return len(osvSeverityRank)
	}
	sort.SliceStable(vulns, func(i, j int) bool {
		if ri, rj := rank(vulns[i]), rank(vulns[j]); ri != rj {
			return ri < rj
		}
		return vulns[i].ID < vulns[j].ID
	})
}
