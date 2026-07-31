package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SourceCVEDetails is the registered name of this source.
const SourceCVEDetails = "cvedetails"

// EnvCVEDetailsKeyName is named here rather than imported from config, so sources does not
// depend on config. Kept in sync with config.EnvCVEDetailsAPIKey.
const EnvCVEDetailsKeyName = "CVEDETAILS_API_KEY"

// CVEDetails is optional paid enrichment on top of NVD.
//
// # Why it is skipped by default
//
// The API is behind a Business/Enterprise subscription (spec §6). NVD is the primary CVE
// source and this only adds context, so an absent key is an ordinary skip that must never
// block or degrade an assessment.
//
// # Why there is no default base URL
//
// CVE Details' API reference is not publicly reachable, and CLAUDE.md forbids guessing
// endpoint paths. A plausible-looking wrong path would either 404 — noisy but harmless — or
// silently return something the parser misreads into another vendor's data, which is the
// failure mode spec §15 is built around. So the host is required configuration: with a key
// but no endpoint this source fails loudly rather than inventing a URL.
type CVEDetails struct {
	client  *http.Client
	baseURL string
	apiKey  string // never logged, never rendered, never placed in an error
}

// NewCVEDetails builds a CVE Details source. An empty apiKey is the common case and makes
// the source skip.
func NewCVEDetails(apiKey string, opts ...CVEDetailsOption) *CVEDetails {
	c := &CVEDetails{client: http.DefaultClient, apiKey: apiKey}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CVEDetailsOption configures a CVEDetails source.
type CVEDetailsOption func(*CVEDetails)

// WithCVEDetailsBaseURL sets the API host and is required before any request is made. Tests
// point it at an httptest.Server.
func WithCVEDetailsBaseURL(u string) CVEDetailsOption {
	return func(c *CVEDetails) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithCVEDetailsHTTPClient overrides the HTTP client.
func WithCVEDetailsHTTPClient(cl *http.Client) CVEDetailsOption {
	return func(c *CVEDetails) { c.client = cl }
}

func (c *CVEDetails) Name() string { return SourceCVEDetails }

// CVEDetailsSummary is this source's contribution to the report.
type CVEDetailsSummary struct {
	Vendor    string
	TotalCVEs int
	CVEs      []CVEDetailsCVE
}

// CVEDetailsCVE is one record, carried verbatim.
type CVEDetailsCVE struct {
	ID          string
	Summary     string
	Published   string
	CVSSScore   string
	Severity    string
	ExploitOnly bool
	URL         string
}

// Fetch returns CVE Details enrichment for the resolved vendor.
func (c *CVEDetails) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	if strings.TrimSpace(c.apiKey) == "" {
		return Skipped(c.Name(), fmt.Sprintf(
			"no %s set; CVE Details is optional paid enrichment and NVD is the primary "+
				"CVE source", EnvCVEDetailsKeyName)), nil
	}

	// A key was configured, so the analyst expects enrichment. Skipping quietly here would
	// look like "nothing to add" rather than "this never ran".
	if c.baseURL == "" {
		err := fmt.Errorf(
			"%s is set but no CVE Details API endpoint is configured; the endpoint is not "+
				"guessed because a wrong path can return another vendor's records",
			EnvCVEDetailsKeyName)
		return Failed(c.Name(), err), err
	}

	vendor := strings.TrimSpace(ent.CanonicalName)
	if vendor == "" {
		vendor = strings.TrimSpace(q.Company)
	}
	if vendor == "" {
		return Skipped(c.Name(), "no vendor name resolved; CVE Details is keyed on vendor"), nil
	}

	summary, err := c.fetchVendor(ctx, vendor)
	if err != nil {
		return Failed(c.Name(), err), err
	}
	return OK(c.Name(), summary, Citation{
		Title: fmt.Sprintf("CVE Details — %s", vendor),
		URL:   c.baseURL,
	}), nil
}

// fetchVendor queries the configured endpoint for a vendor's CVEs.
//
// The path below is the one piece of this source that is not verified against vendor docs;
// see the type comment. It is reached only when an operator has explicitly configured a
// base URL, which is the point at which they can confirm the path matches their plan.
func (c *CVEDetails) fetchVendor(ctx context.Context, vendor string) (CVEDetailsSummary, error) {
	u := fmt.Sprintf("%s/api/v1/vulnerability/search?vendorName=%s",
		c.baseURL, url.QueryEscape(vendor))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return CVEDetailsSummary{}, fmt.Errorf("build request: %w", err)
	}
	// Bearer auth per spec §6. The header is never logged or echoed.
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return CVEDetailsSummary{}, fmt.Errorf("CVE Details request timed out: %w", err)
		}
		if errors.Is(err, context.Canceled) {
			return CVEDetailsSummary{}, fmt.Errorf("CVE Details request cancelled: %w", err)
		}
		return CVEDetailsSummary{}, fmt.Errorf("CVE Details request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return CVEDetailsSummary{}, fmt.Errorf("read CVE Details response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return CVEDetailsSummary{}, cveDetailsStatusError(resp.StatusCode)
	}

	summary, err := parseCVEDetails(body, vendor)
	if err != nil {
		return CVEDetailsSummary{}, fmt.Errorf("CVE Details lookup for %q: %w", vendor, err)
	}
	return summary, nil
}

func cveDetailsStatusError(code int) error {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf(
			"CVE Details rejected the credentials (HTTP %d); check %s and that the "+
				"subscription tier includes API access", code, EnvCVEDetailsKeyName)
	case http.StatusNotFound:
		return errors.New(
			"CVE Details returned HTTP 404; the configured endpoint path may not match " +
				"this subscription's API")
	case http.StatusTooManyRequests:
		return errors.New("CVE Details rate limit exceeded (HTTP 429); retry later")
	default:
		return fmt.Errorf("CVE Details returned HTTP %d", code)
	}
}

type cveDetailsResponse struct {
	Results []struct {
		CVEID         string `json:"cveId"`
		Summary       string `json:"summary"`
		PublishDate   string `json:"publishDate"`
		CVSSScore     string `json:"cvssScore"`
		Severity      string `json:"severity"`
		IsExploitOnly bool   `json:"isExploitOnly"`
	} `json:"results"`
	TotalCount int `json:"totalCount"`
}

// parseCVEDetails extracts records from a search response.
//
// Isolated here with its own fixture like every other source (CLAUDE.md), so if the real
// response shape differs from this one, a single test fails loudly instead of the section
// quietly rendering blank rows.
func parseCVEDetails(body []byte, vendor string) (CVEDetailsSummary, error) {
	var resp cveDetailsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return CVEDetailsSummary{}, fmt.Errorf("parse CVE Details response: %w", err)
	}

	summary := CVEDetailsSummary{Vendor: vendor, TotalCVEs: resp.TotalCount}
	for i, r := range resp.Results {
		if strings.TrimSpace(r.CVEID) == "" {
			return CVEDetailsSummary{}, fmt.Errorf(
				"CVE Details result %d has no cveId; response shape may have changed", i)
		}
		summary.CVEs = append(summary.CVEs, CVEDetailsCVE{
			ID:          r.CVEID,
			Summary:     r.Summary,
			Published:   r.PublishDate,
			CVSSScore:   r.CVSSScore,
			Severity:    r.Severity,
			ExploitOnly: r.IsExploitOnly,
			URL:         "https://www.cvedetails.com/cve/" + r.CVEID + "/",
		})
	}
	if summary.TotalCVEs == 0 {
		summary.TotalCVEs = len(summary.CVEs)
	}
	return summary, nil
}
