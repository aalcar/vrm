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

// This is the second of the two LLM jobs, and it is kept physically separate from entity
// resolution: different function, different prompt, different output contract (spec §2.4).
// Resolution answers "what are this vendor's machine identifiers" in strict JSON with no
// tools. Research answers a fixed checklist from live sources, with citations. Do not merge
// them.
//
// Deterministic values from the other sources never pass through this prompt. The CA AG
// scrape in particular is run independently and rendered alongside these findings rather
// than fed in to be "confirmed" (spec §8) — if the model reports a breach the CA AG list
// does not carry, that difference is informative and belongs in front of the analyst.

// SourceResearch is the registered name of this source.
const SourceResearch = "llm_research"

// researchMaxTokens allows for search results plus the checklist. Larger than resolution's
// budget because the reply carries a dozen findings and their citations.
const researchMaxTokens = 16384

// researchMaxSearches bounds the server-side web searches per assessment. Each is billed,
// and the checklist is a fixed list of questions rather than an open investigation.
const researchMaxSearches = 12

// Tri is a three-valued answer.
//
// There is deliberately no "no". "We found no evidence" and "it did not happen" are
// different claims, and only the first is supportable from a web search (spec §2.5).
type Tri string

const (
	TriYes        Tri = "yes"               // requires at least one citation
	TriNoEvidence Tri = "no_evidence_found" // NOT the same as "no"
	TriNA         Tri = "not_applicable"
)

// valid reports whether t is one of the three permitted answers. Anything else — including
// a bare "no" — is treated as no evidence.
func (t Tri) valid() bool {
	return t == TriYes || t == TriNoEvidence || t == TriNA
}

// Finding is one answered checklist question.
//
// A non-empty Value requires at least one Citation. That is enforced by the parser, not by
// the prompt: an uncited claim is dropped and the field falls back to no evidence.
type Finding struct {
	Value     string
	Citations []Citation
}

// Lawsuit is one concluded, cybersecurity-related legal action.
//
// Outcome and ResolutionDate are separate fields rather than prose because they are the
// filter: spec §8 requires an entry be concluded, and the resolution date is how
// "concluded" is verified. An entry missing either is dropped.
type Lawsuit struct {
	Finding
	Outcome        string
	ResolutionDate string
}

// Location is one place the supplier operates.
//
// Kind keeps headquarters separate from operational or employee presence. Spec §8 requires
// they be labeled and not merged: "has an office in country X" and "is headquartered in
// country X" carry very different weight in a risk assessment.
type Location struct {
	Finding
	Kind    string // headquarters | operational
	Country string
	// City carries the state for US locations ("San Francisco, California").
	//
	// Spec §8 asks for city and state as separate values. They share a field because the
	// compiled structured-outputs grammar has a hard size limit and this schema sits right
	// against it: adding one more property to the location object fails the request with
	// HTTP 400. The spec's actual requirement — that the state be stated for US locations —
	// is met, and the prompt asks for it explicitly.
	City string
}

// Research is the fixed checklist (spec §8). Not open-ended: these fields and no others.
type Research struct {
	SupplierDescription   Finding
	ServiceDescription    Finding
	ServiceImplementation Finding
	CyberLawsuits         []Lawsuit
	PastBreaches          []Finding
	SupplierWebsite       Finding
	ServiceWebsite        Finding
	SecurityPage          Finding
	NotificationPage      Finding
	Locations             []Location

	UsedKaspersky         Tri
	UsedKasperskyEvidence Finding
	MOVEitImpacted        Tri
	MOVEitEvidence        Finding

	// Dropped records what the parser threw out and why. Surfaced rather than discarded:
	// a silently dropped finding is indistinguishable from a question nobody answered.
	Dropped []string
	// SearchResults is every result the web-search tool actually returned. It is the
	// ground truth citations are checked against, and the source of their titles.
	SearchResults []Citation
}

// researchPrompt is the checklist system prompt.
//
// Never log this or the rendered request (CLAUDE.md).
const researchPrompt = `You answer a fixed checklist about a vendor for a security analyst, using web search.

Answer only the fields in the schema. Do not add commentary, severity ratings, risk framing,
or narrative — the analyst writes those. Record what a source says and cite it.

CITATIONS
Every non-empty value needs at least one citation, and each citation must be a URL that
appeared in your web search results. Do not cite a URL you did not see in those results, and
do not reconstruct or guess a URL. A claim whose citation is not in the search results is
discarded, so an uncited answer is worse than no answer.

If you cannot find evidence for a field, leave its value empty. An empty field is a correct
and expected answer.

THREE-VALUED FIELDS
used_kaspersky and moveit_impacted are exactly one of:
  "yes"                - you found a source naming THIS vendor. Requires a citation.
  "no_evidence_found"  - you looked and found nothing naming this vendor.
  "not_applicable"     - the question does not apply to this vendor.
Never answer "no". "No evidence found" and "did not happen" are different claims and you can
only support the first. Both of these events are widely reported and easy to associate with
a vendor that was never involved; answer "yes" only with a source naming this specific
vendor.

LAWSUITS
Include a lawsuit only if BOTH hold:
  a) it is concluded — settled, dismissed, or decided. Not pending, not merely filed.
  b) it is directly about cybersecurity — a breach, a data protection failure, or a
     misrepresentation about security.
General commercial, employment, IP, and antitrust litigation is excluded even for a security
vendor. Each entry must state its outcome and its resolution date. Omit any entry where you
cannot supply both.

LOCATIONS
Label each location as "headquarters" or "operational". Give the country. For US locations
put the city and state together in the city field, as "San Francisco, California". List each
location as its own entry; do not merge several into one.

WEBSITES
supplier_website, service_website, security_page and notification_page are single canonical
URLs. security_page is the vendor's security or trust center page; notification_page is
where they publish breach or incident notices.`

// researchSchema constrains the reply.
//
// It uses no minLength, maxLength, minimum, maximum, or minItems above 1: the
// structured-outputs grammar does not support those constraints and a schema carrying one
// fails to compile. Field-level requirements are enforced by the parser instead.
var researchSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"supplier_description":    findingSchema,
		"service_description":     findingSchema,
		"service_implementation":  findingSchema,
		"cyber_lawsuits":          lawsuitArraySchema,
		"past_breaches":           findingArraySchema,
		"supplier_website":        findingSchema,
		"service_website":         findingSchema,
		"security_page":           findingSchema,
		"notification_page":       findingSchema,
		"locations":               locationArraySchema,
		"used_kaspersky":          triSchema,
		"used_kaspersky_evidence": findingSchema,
		"moveit_impacted":         triSchema,
		"moveit_evidence":         findingSchema,
	},
	"required": []string{
		"supplier_description", "service_description", "service_implementation",
		"cyber_lawsuits", "past_breaches", "supplier_website", "service_website",
		"security_page", "notification_page", "locations",
		"used_kaspersky", "used_kaspersky_evidence", "moveit_impacted", "moveit_evidence",
	},
	"additionalProperties": false,
}

// triSchema does not use a JSON-schema enum, and locations' kind does not either.
//
// Enums multiply the compiled grammar, which this schema has already hit the size limit of
// once (HTTP 400, "compiled grammar is too large"). They are also redundant here: the
// parser rejects any value outside the three permitted answers and downgrades it to
// no_evidence_found, so the constraint is enforced where it has to be enforced anyway. The
// prompt states the permitted values.
var triSchema = map[string]any{"type": "string"}

// citationArraySchema is a plain array of URLs, not {title, url} objects.
//
// Two reasons. The compiled structured-outputs grammar has a size limit and this schema
// repeats citations fourteen times — objects blew past it with HTTP 400 "compiled grammar
// is too large". And the title is better taken from the search results than from the model:
// those results are the ground truth the URLs are checked against anyway, so the title
// arrives already verified instead of being one more thing that could be invented.
var citationArraySchema = map[string]any{
	"type":  "array",
	"items": map[string]any{"type": "string"},
}

var findingSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"value":     map[string]any{"type": "string"},
		"citations": citationArraySchema,
	},
	"required":             []string{"value", "citations"},
	"additionalProperties": false,
}

var findingArraySchema = map[string]any{
	"type":  "array",
	"items": findingSchema,
}

var lawsuitArraySchema = map[string]any{
	"type": "array",
	"items": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"value":           map[string]any{"type": "string"},
			"citations":       citationArraySchema,
			"outcome":         map[string]any{"type": "string"},
			"resolution_date": map[string]any{"type": "string"},
		},
		"required":             []string{"value", "citations", "outcome", "resolution_date"},
		"additionalProperties": false,
	},
}

var locationArraySchema = map[string]any{
	"type": "array",
	"items": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"value":     map[string]any{"type": "string"},
			"citations": citationArraySchema,
			"kind":      map[string]any{"type": "string"},
			"country":   map[string]any{"type": "string"},
			"city":      map[string]any{"type": "string"},
		},
		"required":             []string{"value", "citations", "kind", "country", "city"},
		"additionalProperties": false,
	},
}

// Researcher answers the checklist for one vendor.
type Researcher struct {
	client anthropic.Client
	model  string
	// apiKey is retained only for redacting an error body that echoes it. See sanitizeAPIError.
	apiKey string
}

// ResearcherOption configures a Researcher.
type ResearcherOption func(*[]option.RequestOption)

// WithResearcherBaseURL overrides the API host. Tests point this at an httptest.Server.
func WithResearcherBaseURL(u string) ResearcherOption {
	return func(opts *[]option.RequestOption) {
		*opts = append(*opts, option.WithBaseURL(u))
	}
}

// WithResearcherMaxRetries overrides the SDK retry count. Tests set 0.
func WithResearcherMaxRetries(n int) ResearcherOption {
	return func(opts *[]option.RequestOption) {
		*opts = append(*opts, option.WithMaxRetries(n))
	}
}

// NewResearcher builds a Researcher for the given model.
func NewResearcher(apiKey, model string, opts ...ResearcherOption) *Researcher {
	reqOpts := []option.RequestOption{option.WithAPIKey(apiKey)}
	for _, opt := range opts {
		opt(&reqOpts)
	}
	return &Researcher{client: anthropic.NewClient(reqOpts...), model: model, apiKey: apiKey}
}

// Name identifies the source. A Researcher is a Source: unlike resolution, research does
// not feed the other sources, so it runs inside the fan-out (spec §10 step 2).
func (r *Researcher) Name() string { return SourceResearch }

// Fetch runs the checklist and wraps it in a Section.
func (r *Researcher) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	if r.apiKey == "" {
		// Same shape as any other absent credential: a skip with a reason, not a failure.
		return Skipped(SourceResearch,
			"ANTHROPIC_API_KEY is not set; checklist research needs it"), nil
	}

	research, err := r.Research(ctx, q, ent)
	if err != nil {
		return Failed(SourceResearch, err), err
	}

	// The section's citations are the findings' own; they are rendered inline with each
	// answer rather than collected into one undifferentiated list, because a citation only
	// means anything attached to the claim it supports.
	return OK(SourceResearch, research), nil
}

// Research answers the checklist for one vendor.
func (r *Researcher) Research(ctx context.Context, q Query, ent ResolvedEntity) (Research, error) {
	if strings.TrimSpace(q.Company) == "" {
		return Research{}, errors.New("research: company is required")
	}

	resp, err := r.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(r.model),
		MaxTokens: researchMaxTokens,
		System:    []anthropic.TextBlockParam{{Text: researchPrompt}},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: researchSchema},
		},
		// The server-side web search tool: the model issues the searches and the results
		// come back in the same response, so nothing here executes a tool call.
		Tools: []anthropic.ToolUnionParam{{
			OfWebSearchTool20250305: &anthropic.WebSearchTool20250305Param{
				MaxUses: anthropic.Int(researchMaxSearches),
			},
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(researchQuery(q, ent))),
		},
	})
	if err != nil {
		return Research{}, fmt.Errorf("research %q: %w", q.Company, sanitizeAPIError(err, r.apiKey))
	}

	if resp.StopReason == anthropic.StopReasonRefusal {
		return Research{}, fmt.Errorf("research %q: the model declined to answer", q.Company)
	}

	raw, err := lastTextBlock(resp)
	if err != nil {
		return Research{}, fmt.Errorf("research %q: %w", q.Company, err)
	}

	return parseResearch(raw, searchResults(resp))
}

// researchQuery renders the user turn.
func researchQuery(q Query, ent ResolvedEntity) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Company: %s\n", q.Company)
	if strings.TrimSpace(q.Service) != "" {
		fmt.Fprintf(&b, "Service: %s\n", q.Service)
	}
	// The resolved name and aliases are identifiers, not findings — they narrow the search
	// to the right company. No deterministic result from another source is included.
	if ent.CanonicalName != "" && !strings.EqualFold(ent.CanonicalName, q.Company) {
		fmt.Fprintf(&b, "Also known as: %s\n", ent.CanonicalName)
	}
	if len(ent.Aliases) > 0 {
		fmt.Fprintf(&b, "Other names: %s\n", strings.Join(ent.Aliases, ", "))
	}
	return b.String()
}

// lastTextBlock returns the final text block.
//
// Research responses interleave thinking, server tool calls, and search results before the
// answer, so the structured JSON is the last text block rather than the first — which is
// what resolution uses.
func lastTextBlock(resp *anthropic.Message) (string, error) {
	for i := len(resp.Content) - 1; i >= 0; i-- {
		if text, ok := resp.Content[i].AsAny().(anthropic.TextBlock); ok {
			return text.Text, nil
		}
	}
	return "", errors.New("response contained no text block")
}

// searchResultURLs collects every URL the web-search tool actually returned.
//
// This is the ground truth for citation checking. The API's own citation blocks do not
// survive structured output — a response combining the two comes back with the JSON in a
// text block carrying zero citations — so citations are model-authored schema fields, and
// the only defence against a fabricated URL is comparing them against what search really
// returned.
func searchResults(resp *anthropic.Message) []Citation {
	var results []Citation
	for _, block := range resp.Content {
		result, ok := block.AsAny().(anthropic.WebSearchToolResultBlock)
		if !ok {
			continue
		}
		for _, item := range result.Content.OfWebSearchResultBlockArray {
			if item.URL != "" {
				results = append(results, Citation{Title: item.Title, URL: item.URL})
			}
		}
	}
	return results
}

// researchReply mirrors the structured-outputs schema.
type researchReply struct {
	SupplierDescription   findingReply    `json:"supplier_description"`
	ServiceDescription    findingReply    `json:"service_description"`
	ServiceImplementation findingReply    `json:"service_implementation"`
	CyberLawsuits         []lawsuitReply  `json:"cyber_lawsuits"`
	PastBreaches          []findingReply  `json:"past_breaches"`
	SupplierWebsite       findingReply    `json:"supplier_website"`
	ServiceWebsite        findingReply    `json:"service_website"`
	SecurityPage          findingReply    `json:"security_page"`
	NotificationPage      findingReply    `json:"notification_page"`
	Locations             []locationReply `json:"locations"`
	UsedKaspersky         string          `json:"used_kaspersky"`
	UsedKasperskyEvidence findingReply    `json:"used_kaspersky_evidence"`
	MOVEitImpacted        string          `json:"moveit_impacted"`
	MOVEitEvidence        findingReply    `json:"moveit_evidence"`
}

type findingReply struct {
	Value     string   `json:"value"`
	Citations []string `json:"citations"`
}

type lawsuitReply struct {
	findingReply
	Outcome        string `json:"outcome"`
	ResolutionDate string `json:"resolution_date"`
}

type locationReply struct {
	findingReply
	Kind    string `json:"kind"`
	Country string `json:"country"`
	City    string `json:"city"`
	State   string `json:"state"`
}

// unmarshalResearch decodes the reply. A malformed body is an error rather than a partial
// checklist: half a checklist rendered as a full one is a wrong answer, not a thin one.
func unmarshalResearch(raw string) (researchReply, error) {
	var reply researchReply
	if err := json.Unmarshal([]byte(raw), &reply); err != nil {
		return researchReply{}, fmt.Errorf("decode research reply: %w", err)
	}
	return reply, nil
}
