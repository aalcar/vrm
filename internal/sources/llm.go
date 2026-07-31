package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// This file holds the LLM-backed work. There are exactly two such jobs and they are kept
// physically separate — different functions, different prompts, different output contracts
// (spec §2.4):
//
//  1. Entity resolution (this phase): company + service -> machine identifiers, strict JSON.
//  2. Checklist research (phase 7): a fixed question list with citations.
//
// Resist any refactor that merges them into one call. Deterministic values from the other
// sources never pass through either prompt (spec §2.2).

// resolutionMaxTokens bounds the resolution reply. The output is a small JSON object; this
// is headroom, not a target.
const resolutionMaxTokens = 2048

// resolutionPrompt is the entity-resolution system prompt.
//
// Never log this, and never log the rendered request — CLAUDE.md forbids logging full
// prompts alongside keys and auth headers.
const resolutionPrompt = `You map a vendor company and one of its services to the machine identifiers a security analyst needs.

Return only identifiers you are confident are correct for THIS company. This output drives
automated vulnerability lookups: a wrong identifier silently returns another company's
security data, which is worse than returning nothing. When you are not confident, return an
empty array for that field. An empty array is a correct and expected answer.

- canonical_name: the company's full legal or commonly used corporate name.
- domains: registrable domains the company owns, most authoritative first. Bare hostnames
  only — no scheme, no path, no port.
- cpes: CPE 2.3 strings for the named service, in full 13-component form starting "cpe:2.3:".
  Use the version-agnostic wildcard form unless a specific version was named.
  The vendor and product tokens must be ones NVD has actually registered. NVD registers a
  CPE per software product, not per company: the product token names a specific product,
  and is almost never the company name repeated. For Okta the registered products are
  tokens like okta:access_gateway and okta:verify — okta:okta is not a real CPE. If you do
  not know the registered product token, return []. A fabricated CPE returns either another
  vendor's CVEs or a silent zero, and neither looks wrong in the output.
- packages: open-source packages the company publishes, each as an object with "ecosystem"
  and "name". ecosystem is the registry the package is published to, spelled exactly as one
  of: npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, CRAN,
  ConanCenter, Hackage, SwiftURL, vcpkg. name is the exact identifier that registry lists,
  which is registry-specific: npm scoped packages keep the leading @ and the slash
  (@okta/okta-auth-js), Go packages are full module paths
  (github.com/hashicorp/vault), and Maven packages are groupId:artifactId
  (com.okta.sdk:okta-sdk-api). Most vendors publish none; [] is the common and correct
  answer. Do not list packages that merely mention or depend on the company.
- aliases: former names, subsidiaries, and acquiring entities under which this company's
  security data may be filed.

Do not explain, qualify, or add commentary. Return the JSON object only.`

// resolutionSchema constrains the reply to exactly the shape ResolvedEntity needs.
//
// This is the API's structured-outputs schema, not advice to the model: the response is
// guaranteed to validate against it, which is what makes the strict-JSON contract in spec
// §10 enforceable rather than merely requested.
var resolutionSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"canonical_name": map[string]any{"type": "string"},
		"domains":        stringArraySchema,
		"cpes":           stringArraySchema,
		"packages":       packageArraySchema,
		"aliases":        stringArraySchema,
	},
	"required":             []string{"canonical_name", "domains", "cpes", "packages", "aliases"},
	"additionalProperties": false,
}

var stringArraySchema = map[string]any{
	"type":  "array",
	"items": map[string]any{"type": "string"},
}

// packageArraySchema carries the ecosystem alongside the name. OSV rejects a name-only
// query, so a bare package name is unusable and the schema does not allow one.
var packageArraySchema = map[string]any{
	"type": "array",
	"items": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"ecosystem": map[string]any{"type": "string"},
			"name":      map[string]any{"type": "string"},
		},
		"required":             []string{"ecosystem", "name"},
		"additionalProperties": false,
	},
}

// Resolver turns an analyst's query into the identifiers the deterministic sources need.
//
// It is deliberately NOT a Source: resolution runs once, before the fan-out, and every
// other source depends on its output (spec §10 step 1).
type Resolver struct {
	client anthropic.Client
	model  string
}

// ResolverOption configures a Resolver.
type ResolverOption func(*[]option.RequestOption)

// WithResolverBaseURL overrides the API host. Tests point this at an httptest.Server.
func WithResolverBaseURL(u string) ResolverOption {
	return func(opts *[]option.RequestOption) {
		*opts = append(*opts, option.WithBaseURL(u))
	}
}

// WithResolverMaxRetries overrides the SDK's retry count. Tests set it to 0 so a failure
// surfaces immediately instead of being retried.
func WithResolverMaxRetries(n int) ResolverOption {
	return func(opts *[]option.RequestOption) {
		*opts = append(*opts, option.WithMaxRetries(n))
	}
}

// NewResolver builds a Resolver for the given model.
func NewResolver(apiKey, model string, opts ...ResolverOption) *Resolver {
	reqOpts := []option.RequestOption{option.WithAPIKey(apiKey)}
	for _, opt := range opts {
		opt(&reqOpts)
	}
	return &Resolver{
		client: anthropic.NewClient(reqOpts...),
		model:  model,
	}
}

// Resolution is the outcome of an entity-resolution call.
type Resolution struct {
	Entity ResolvedEntity
	// Dropped records identifiers the model returned that failed validation. Surfaced in
	// the report rather than discarded silently: a quietly dropped CPE looks identical to
	// a vendor that genuinely has none.
	Dropped []string
}

// Resolve maps a query to machine identifiers.
//
// A malformed or unusable reply is an error, never a partially populated entity — a
// half-resolved entity would send the wrong identifiers to NVD and produce a confident,
// wrong report (spec §15).
func (r *Resolver) Resolve(ctx context.Context, q Query) (Resolution, error) {
	if strings.TrimSpace(q.Company) == "" {
		return Resolution{}, errors.New("resolve: company is required")
	}

	resp, err := r.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(r.model),
		MaxTokens: resolutionMaxTokens,
		System:    []anthropic.TextBlockParam{{Text: resolutionPrompt}},
		OutputConfig: anthropic.OutputConfigParam{
			// A short extraction, not a reasoning task.
			Effort: anthropic.OutputConfigEffort("low"),
			Format: anthropic.JSONOutputFormatParam{Schema: resolutionSchema},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(resolutionQuery(q))),
		},
	})
	if err != nil {
		// The SDK's error carries status and response body, never the Authorization
		// header. sanitizeAPIError strips any echo of the key from the body.
		return Resolution{}, fmt.Errorf("resolve %q: %w", q.Company, sanitizeAPIError(err))
	}

	// Safety classifiers can decline a request; content is empty or partial when they do.
	if resp.StopReason == anthropic.StopReasonRefusal {
		return Resolution{}, fmt.Errorf("resolve %q: the model declined to answer", q.Company)
	}

	raw, err := firstTextBlock(resp)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve %q: %w", q.Company, err)
	}
	return parseResolution(raw)
}

// resolutionQuery renders the user turn. Kept separate so the prompt constant stays fixed
// and only this varies.
func resolutionQuery(q Query) string {
	if strings.TrimSpace(q.Service) == "" {
		return fmt.Sprintf("Company: %s", q.Company)
	}
	return fmt.Sprintf("Company: %s\nService: %s", q.Company, q.Service)
}

func firstTextBlock(resp *anthropic.Message) (string, error) {
	for _, block := range resp.Content {
		if text, ok := block.AsAny().(anthropic.TextBlock); ok {
			return text.Text, nil
		}
	}
	return "", errors.New("response contained no text block")
}

// resolutionReply mirrors the structured-outputs schema. Pointer-free: a missing field
// decodes to the zero value, which the validation below rejects.
type resolutionReply struct {
	CanonicalName string   `json:"canonical_name"`
	Domains       []string `json:"domains"`
	CPEs          []string `json:"cpes"`
	Packages      []struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"packages"`
	Aliases []string `json:"aliases"`
}

// parseResolution decodes and validates a resolution reply.
//
// Schema-valid is not the same as correct. Structured outputs guarantee the shape; this
// checks the contents, dropping identifiers that would send a deterministic source looking
// for the wrong thing.
func parseResolution(raw string) (Resolution, error) {
	var reply resolutionReply
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reply); err != nil {
		return Resolution{}, fmt.Errorf("parse resolution response: %w", err)
	}

	name := strings.TrimSpace(reply.CanonicalName)
	if name == "" {
		return Resolution{}, errors.New("resolution response has an empty canonical_name")
	}

	var dropped []string
	ent := ResolvedEntity{CanonicalName: name}

	for _, d := range reply.Domains {
		norm, ok := normalizeDomain(d)
		if !ok {
			dropped = append(dropped, fmt.Sprintf("domain %q (not a bare hostname)", d))
			continue
		}
		ent.Domains = append(ent.Domains, norm)
	}
	for _, c := range reply.CPEs {
		norm, ok := normalizeCPE(c)
		if !ok {
			dropped = append(dropped, fmt.Sprintf("cpe %q (not a well-formed CPE 2.3 string)", c))
			continue
		}
		ent.CPEs = append(ent.CPEs, norm)
	}
	for _, p := range reply.Packages {
		pkg, ok := normalizePackage(p.Ecosystem, p.Name)
		if !ok {
			dropped = append(dropped, fmt.Sprintf(
				"package %q in ecosystem %q (not a recognized OSV package ecosystem)",
				p.Name, p.Ecosystem))
			continue
		}
		ent.Packages = append(ent.Packages, pkg)
	}
	for _, a := range reply.Aliases {
		if t := strings.TrimSpace(a); t != "" {
			ent.Aliases = append(ent.Aliases, t)
		}
	}

	return Resolution{Entity: ent, Dropped: dropped}, nil
}

// normalizeDomain accepts a bare registrable hostname and lowercases it.
//
// A scheme, path, port, or whitespace means the model returned a URL rather than a domain;
// BitSight's search would not match it.
func normalizeDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")

	if d == "" || strings.ContainsAny(d, " \t/\\:@?#") {
		return "", false
	}
	if !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.Contains(d, "..") {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "", false
		}
	}
	return d, true
}

// cpeComponentCount is the number of colon-separated fields in a CPE 2.3 formatted string:
// the "cpe" prefix, the "2.3" version, and 11 attributes.
const cpeComponentCount = 13

// osvEcosystems maps a lowercased ecosystem name to OSV's exact capitalization.
//
// Restricted to the language package registries on purpose. OSV also defines distro
// ecosystems (Debian, Ubuntu, Alpine, Red Hat, …), but those describe distributions
// repackaging software, not packages a vendor publishes, and most require a release or CPE
// suffix we could only invent. A vendor's own OSS lives in the registries below.
//
// Common informal spellings map to the canonical name: those are deterministic renames, not
// guesses, and the model reaches for them.
var osvEcosystems = map[string]string{
	"npm":            "npm",
	"pypi":           "PyPI",
	"pip":            "PyPI",
	"python":         "PyPI",
	"go":             "Go",
	"golang":         "Go",
	"maven":          "Maven",
	"crates.io":      "crates.io",
	"crates":         "crates.io",
	"cargo":          "crates.io",
	"rust":           "crates.io",
	"rubygems":       "RubyGems",
	"gem":            "RubyGems",
	"ruby":           "RubyGems",
	"nuget":          "NuGet",
	"packagist":      "Packagist",
	"composer":       "Packagist",
	"hex":            "Hex",
	"pub":            "Pub",
	"cran":           "CRAN",
	"conancenter":    "ConanCenter",
	"conan":          "ConanCenter",
	"hackage":        "Hackage",
	"opam":           "opam",
	"swifturl":       "SwiftURL",
	"swift":          "SwiftURL",
	"vcpkg":          "vcpkg",
	"github actions": "GitHub Actions",
}

// normalizePackage validates an ecosystem/name pair against the registries OSV accepts.
//
// An unrecognized ecosystem is dropped rather than passed through: OSV answers HTTP 400 for
// one it does not know, which would fail the whole section over a single bad entry.
func normalizePackage(ecosystem, name string) (Package, bool) {
	n := strings.TrimSpace(name)
	if n == "" {
		return Package{}, false
	}
	canonical, ok := osvEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	if !ok {
		return Package{}, false
	}
	return Package{Ecosystem: canonical, Name: n}, true
}

// ParseCPEOverride accepts an analyst-supplied CPE and returns it in full 13-component
// form.
//
// It deliberately accepts the short cpe:2.3:<part>:<vendor>:<product> prefix as well as the
// full string, because that prefix is exactly what this tool prints when it reports that a
// resolved CPE was not in NVD's dictionary. Making an analyst re-type nine wildcards to act
// on our own error message would be a good way to get the correction typo'd.
func ParseCPEOverride(raw string) (string, bool) {
	c := strings.ToLower(strings.TrimSpace(raw))
	if parts := strings.Split(c, ":"); len(parts) == 5 {
		c = c + strings.Repeat(":*", cpeComponentCount-5)
	}
	return normalizeCPE(c)
}

// normalizeCPE validates a CPE 2.3 formatted string structurally.
//
// Deliberately structural only. CLAUDE.md says to ask rather than guess on CPE formats, and
// a plausible-looking CPE built from a company name is precisely the failure spec §15 warns
// about — it returns another vendor's CVEs and nothing looks wrong. Anything that is not
// clearly well-formed is dropped rather than repaired.
func normalizeCPE(raw string) (string, bool) {
	c := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(c, "cpe:2.3:") {
		return "", false
	}

	parts := strings.Split(c, ":")
	if len(parts) != cpeComponentCount {
		return "", false
	}
	// part: application, operating system, or hardware.
	switch parts[2] {
	case "a", "o", "h":
	default:
		return "", false
	}
	// vendor and product must be present; a wildcard in either matches everything, which
	// would pull in the entire NVD.
	for _, i := range []int{3, 4} {
		if parts[i] == "" || parts[i] == "*" || parts[i] == "-" {
			return "", false
		}
	}
	return c, true
}

// sanitizeAPIError removes any echo of the API key from an SDK error.
//
// The Authorization header is not included in SDK errors, but the response body is, and an
// auth failure can quote the rejected credential back. Section errors are rendered to
// analysts, so nothing credential-shaped may survive to that point.
func sanitizeAPIError(err error) error {
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		return err
	}
	return fmt.Errorf("Anthropic API returned HTTP %d", apiErr.StatusCode)
}
