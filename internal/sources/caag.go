package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// SourceCAAG is the registered name of this source.
const SourceCAAG = "caag"

// DefaultCAAGURL is the California Attorney General's breach-notification list.
//
// California law requires organizations to report breaches affecting more than 500
// residents, which makes this list authoritative for what it covers and deterministic in a
// way LLM research is not. It is not a national list: absence here means "not reported in
// California", never "never breached".
const DefaultCAAGURL = "https://oag.ca.gov/privacy/databreach/list"

// caagNameParam is the list's organization-name filter. It is a substring match, so a short
// name matches generously — which is why every row's organization name is recorded verbatim
// rather than being assumed to be the vendor.
const caagNameParam = "field_sb24_org_name_value"

// caagMaxNames bounds how many names are searched. Each is one request against a public
// government site, and a vendor with a long alias list should not turn one assessment into
// a dozen page loads.
const caagMaxNames = 4

// Column classes on the Drupal view. Positional indexing would silently mis-read the table
// if a column were ever added, so cells are identified by class.
const (
	caagOrgClass      = "views-field-field-sb24-org-name"
	caagBreachClass   = "views-field-field-sb24-breach-date"
	caagReportedClass = "views-field-created"
)

// caagEmptyClass marks a search that ran and matched nothing. It is the only thing
// separating a clean vendor from a broken parser, because a no-match page renders no table
// at all rather than an empty one.
const caagEmptyClass = "view-empty"

// CAAGEntry is one reported breach.
//
// Organization is what the list says, not what was searched for: the filter is a substring
// match, so a search for "T-Mobile" returns rows filed under "T-Mobile USA", "T-Mobile USA,
// Inc." and "T-Mobile US". Recording the filed name lets an analyst judge whether a row
// belongs to the vendor being assessed. Deciding that automatically would either drop real
// entries or silently attach another company's breach to this one.
type CAAGEntry struct {
	Organization string
	// BreachDates are as printed. A row can carry several, and a row can carry none — the
	// list prints "n/a" — so these are kept as strings rather than parsed into times that
	// would have to invent a value for the missing case.
	BreachDates  []string
	ReportedDate string
	ReportURL    string
	SearchedAs   string // the name whose search returned this row
}

// CAAGResult is the caag section's data.
type CAAGResult struct {
	// Entries is empty for a vendor with no California-reported breaches — an ordinary
	// answer, and the common one.
	Entries []CAAGEntry
	// Searched lists the names queried, so an empty result is legible.
	Searched []string
}

// CAAG reads the California Attorney General's breach-notification list.
type CAAG struct {
	baseURL string
	client  *http.Client
}

// CAAGOption configures a CAAG source.
type CAAGOption func(*CAAG)

// WithCAAGURL overrides the list URL. For tests.
func WithCAAGURL(u string) CAAGOption { return func(c *CAAG) { c.baseURL = u } }

// WithCAAGClient overrides the HTTP client. For tests.
func WithCAAGClient(h *http.Client) CAAGOption { return func(c *CAAG) { c.client = h } }

// NewCAAG builds the source. No credential: the list is public.
func NewCAAG(opts ...CAAGOption) *CAAG {
	c := &CAAG{
		baseURL: DefaultCAAGURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *CAAG) Name() string { return SourceCAAG }

// Fetch searches the list for the vendor under each of its known names.
//
// Never StatusSkipped: a company name is always available, so there is always something to
// query.
func (c *CAAG) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	names := vendorNames(q, ent)
	if len(names) > caagMaxNames {
		names = names[:caagMaxNames]
	}

	result := CAAGResult{Searched: names}
	seen := make(map[string]bool)

	for _, name := range names {
		entries, err := c.search(ctx, name)
		if err != nil {
			// One name failing makes the whole answer untrustworthy: the entries gathered so
			// far would render as the complete picture when it is not. That is the
			// "found nothing vs could not look" rule applied within a single source.
			return Failed(SourceCAAG, err), err
		}
		for _, e := range entries {
			// The same breach surfaces under several names when aliases overlap.
			if key := e.ReportURL; key != "" && seen[key] {
				continue
			}
			seen[e.ReportURL] = true
			result.Entries = append(result.Entries, e)
		}
	}

	return OK(SourceCAAG, result, Citation{
		Title: "California Attorney General — Data Security Breach Reports",
		URL:   c.baseURL,
	}), nil
}

// search runs one name through the list's filter.
func (c *CAAG) search(ctx context.Context, name string) ([]CAAGEntry, error) {
	target, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse caag url: %w", err)
	}
	query := target.Query()
	query.Set(caagNameParam, name)
	target.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build caag request: %w", err)
	}
	req.Header.Set("Accept", "text/html")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search the CA AG breach list for %q: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CA AG breach list returned HTTP %d for %q", resp.StatusCode, name)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read CA AG response for %q: %w", name, err)
	}

	return parseCAAGList(string(body), name)
}

// parseCAAGList extracts breach rows from one search-results page.
//
// Three outcomes, and keeping them apart is the whole job:
//
//   - rows present            → those entries
//   - no rows, view-empty div → genuinely nothing reported for this name
//   - neither                 → the page layout changed; fail loudly rather than report a
//     clean result nobody verified
func parseCAAGList(body, searchedAs string) ([]CAAGEntry, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse CA AG page for %q: %w", searchedAs, err)
	}

	var entries []CAAGEntry
	var sawEmptyMarker bool

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch {
			case hasClass(n, caagEmptyClass):
				sawEmptyMarker = true
			case n.Data == "tr":
				if entry, ok := parseCAAGRow(n, searchedAs); ok {
					entries = append(entries, entry)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	if len(entries) == 0 && !sawEmptyMarker {
		return nil, fmt.Errorf(
			"CA AG breach list for %q had neither result rows nor the %q marker: "+
				"the page layout has changed, so an empty result cannot be trusted",
			searchedAs, caagEmptyClass)
	}
	return entries, nil
}

// parseCAAGRow reads one table row. The header row has no matching cells and is skipped.
func parseCAAGRow(tr *html.Node, searchedAs string) (CAAGEntry, bool) {
	entry := CAAGEntry{SearchedAs: searchedAs}

	for cell := tr.FirstChild; cell != nil; cell = cell.NextSibling {
		if cell.Type != html.ElementNode || cell.Data != "td" {
			continue
		}
		switch {
		case hasClass(cell, caagOrgClass):
			entry.Organization = textOf(cell)
			if link := findElement(cell, "a"); link != nil {
				entry.ReportURL = attr(link, "href")
			}
		case hasClass(cell, caagBreachClass):
			entry.BreachDates = breachDates(cell)
		case hasClass(cell, caagReportedClass):
			entry.ReportedDate = textOf(cell)
		}
	}

	// A row without an organization is the header or a spacer, not a breach.
	if entry.Organization == "" {
		return CAAGEntry{}, false
	}
	return entry, true
}

// breachDates pulls the individual dates out of the breach-date cell.
//
// A row may list several dates in their own spans, or the literal text "n/a". The "n/a"
// case is left as an empty slice rather than recorded as a date, because it is the list
// saying it does not know — not a date it is reporting.
func breachDates(cell *html.Node) []string {
	var dates []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "span" && hasClass(n, "date-display-single") {
			if text := textOf(n); text != "" {
				dates = append(dates, text)
			}
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(cell)

	return dates
}

func hasClass(n *html.Node, want string) bool {
	for _, class := range strings.Fields(attr(n, "class")) {
		if class == want {
			return true
		}
	}
	return false
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func findElement(n *html.Node, tag string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tag {
		return n
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if found := findElement(child, tag); found != nil {
			return found
		}
	}
	return nil
}

// textOf returns an element's visible text, whitespace-collapsed.
func textOf(n *html.Node) string {
	var b strings.Builder

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)

	return strings.Join(strings.Fields(b.String()), " ")
}
