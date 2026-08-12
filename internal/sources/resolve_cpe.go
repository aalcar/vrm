package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

// This file holds the second half of entity resolution: turning a company and a service into
// CPEs that NVD has actually registered.
//
// # Why the model does not write the CPE
//
// The old design asked the model for a finished CPE string and checked it afterwards. That
// inverts the reliability of the two things it has to produce. The vendor token is close to
// deterministic — it is the company name, lowercased — and one dictionary request settles it.
// The product token is a name the model has to recall from NVD's registry, and when it cannot
// it composes a plausible one instead: six consecutive runs of "Okta" + "SSO" returned no CPE
// four times and the fictional okta:single_sign-on twice.
//
// So the model is asked for the part it can get right, NVD supplies the authoritative product
// list, and the model's remaining job is to choose from that list. Choosing is verifiable in a
// way that composing is not: every returned token is checked for membership, and one that is
// not in the list is dropped as invented. The catalogue is the ceiling on what can be queried.
//
// A caller with no directory configured (NVD switched off) keeps the old behaviour — the
// model's CPEs, structurally validated and nothing more — and CPEOrigin says so.

// CPEDirectory reads a vendor's registered products out of NVD's CPE dictionary.
//
// vendor is a cpe:2.3:<part>:<vendor> prefix; narrow is a search term used only if the vendor
// is too large to read in one page. *NVD implements this.
type CPEDirectory interface {
	VendorProducts(ctx context.Context, vendor, narrow string) (CPECatalogue, error)
}

const (
	// maxVendorCandidates bounds the dictionary requests one resolution will spend. Each
	// costs six seconds at NVD's unkeyed courtesy interval, and the candidates after the
	// first are alternate spellings — worth one retry, not a search.
	maxVendorCandidates = 2
	// maxSelectedProducts is a backstop against a "select everything" answer, not the routine
	// bound on how many CPEs get queried — NVD's own maxCPEs is that, and it already reports
	// what it left unqueried. Set to the same number deliberately: a tighter cap here trims
	// real products before NVD ever sees them, which is what a first pass at 4 did to Okta on
	// three consecutive runs. Above this, the answer is the catalogue rather than a selection.
	maxSelectedProducts = defaultNVDMaxCPEs
	// productSelectionMaxTokens bounds the selection reply: a short array of tokens.
	productSelectionMaxTokens = 1024
)

// productSelectionPrompt is the system prompt for the selection call.
//
// Never log this, or the rendered request, for the same reason as resolutionPrompt.
const productSelectionPrompt = `You are given a company, one of its services, and the list of products NVD has registered under that company's CPE vendor token. Choose the products whose vulnerabilities a security analyst assessing that service would need to see.

Choose only from the list you are given. Copy the tokens exactly. Do not invent a product, do not correct a spelling, and do not adjust a token to look more like the service name — a token that is not in the list is discarded, so an adjusted one is a lost answer, not a better one.

Membership in the list is not a reason to choose something. The product must plausibly be part of the named service, or the software that implements it. Another product from the same company is another product.

An empty list is a correct and expected answer. NVD registers CPEs for software with released versions, and a cloud service frequently has none — an operator agent or a desktop client may be registered while the service itself is not. Returning nothing says "this service has no registered CPE", which is true and useful. Returning a loosely related product says "here are this service's vulnerabilities" and attributes another product's CVEs to it.

Do not explain, qualify, or add commentary. Return the JSON object only.`

var productSelectionSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"products": stringArraySchema,
	},
	"required":             []string{"products"},
	"additionalProperties": false,
}

// groundCPEs replaces the model's proposed CPEs with ones NVD's dictionary confirms.
//
// It never returns an error. A dictionary that cannot be reached degrades to the proposed
// CPEs — the assessment still runs, the CPEs are marked unverified, and the resolution cache
// declines to pin them (see Report.CPEsVerified). Losing the whole assessment because a free
// API was slow would be the worse trade.
func (r *Resolver) groundCPEs(ctx context.Context, q Query, res Resolution) Resolution {
	if r.dir == nil {
		res.CPEOrigin = "proposed by the model and not checked against NVD (nvd is disabled)"
		return res
	}

	cat, ok := r.findVendor(ctx, q, &res)
	if !ok {
		return res
	}

	// The fast path. A proposed CPE whose product is already in the catalogue needs no second
	// opinion: NVD has confirmed the exact pair, which is all the selection call could
	// establish. This is also what keeps vendors that already resolved correctly on the same
	// path they were on, one dictionary request the wiser.
	if confirmed := confirmedCPEs(res.Entity.CPEs, cat); len(confirmed) > 0 {
		res.Dropped = append(res.Dropped, unconfirmedNotes(res.Entity.CPEs, confirmed, cat)...)
		res.Entity.CPEs = confirmed
		res.CPEOrigin = fmt.Sprintf("proposed by the model, confirmed in NVD's dictionary under %s",
			cat.Vendor)
		return res
	}

	// Nothing proposed survived, so the products NVD does register become the choices.
	for _, c := range res.Entity.CPEs {
		res.Dropped = append(res.Dropped, fmt.Sprintf(
			"cpe %q (product not registered under %s)", c, cat.Vendor))
	}
	res.Entity.CPEs = nil

	selected, err := r.selectProducts(ctx, q, cat)
	if err != nil {
		res.Dropped = append(res.Dropped, fmt.Sprintf("cpe product selection failed: %v", err))
		res.CPEOrigin = fmt.Sprintf(
			"no CPE: %s is registered in NVD but choosing a product from it failed", cat.Vendor)
		return res
	}

	accepted, invented := partitionSelection(selected, cat)
	for _, p := range invented {
		// The one failure this design is built to catch, so it is named as what it is rather
		// than folded into a generic drop.
		res.Dropped = append(res.Dropped, fmt.Sprintf(
			"product %q (not among the %d products NVD returned for %s; invented)",
			p, len(cat.Products), cat.Vendor))
	}
	if len(accepted) > maxSelectedProducts {
		// Reported, not silently trimmed. A real product cut by our own cap looks exactly
		// like a product the model never chose, and the two are not the same.
		for _, p := range accepted[maxSelectedProducts:] {
			res.Dropped = append(res.Dropped, fmt.Sprintf(
				"product %q (registered under %s, but beyond the %d-CPE limit for one service)",
				p, cat.Vendor, maxSelectedProducts))
		}
		accepted = accepted[:maxSelectedProducts]
	}
	for _, p := range accepted {
		if cpe, ok := normalizeCPE(cat.Vendor + ":" + p + strings.Repeat(":*", cpeComponentCount-5)); ok {
			res.Entity.CPEs = append(res.Entity.CPEs, cpe)
		}
	}
	res.CPEOrigin = selectionOrigin(cat, len(res.Entity.CPEs))
	return res
}

// findVendor walks the candidate vendor tokens until NVD recognises one.
//
// Candidates are the model's cpe_vendors first, then any vendor implied by a proposed CPE —
// the latter carry a part component (a/o/h) the bare tokens do not, which is the only way a
// hardware or OS vendor gets looked up at all.
func (r *Resolver) findVendor(ctx context.Context, q Query, res *Resolution) (CPECatalogue, bool) {
	candidates := vendorCandidates(*res)
	if len(candidates) == 0 {
		res.Entity.CPEs = nil
		res.CPEOrigin = "no CPE: the model proposed no CPE vendor to look up"
		return CPECatalogue{}, false
	}

	var unknown []string
	for _, vendor := range candidates {
		// The service narrows the dictionary only when the vendor is too large to read in
		// one page; for everything smaller the full product list comes back untouched.
		cat, err := r.dir.VendorProducts(ctx, vendor, q.Service)
		if err != nil {
			// Degrade, do not fail: the proposed CPEs stand, unverified and labelled as such.
			res.Dropped = append(res.Dropped,
				fmt.Sprintf("NVD's CPE dictionary was unreachable: %v", err))
			res.CPEOrigin = "proposed by the model and NOT checked: NVD's dictionary was unreachable"
			return CPECatalogue{}, false
		}
		if cat.Exists() {
			return cat, true
		}
		unknown = append(unknown, vendor)
	}

	// Every candidate spelling is unknown to NVD. That is a real answer — plenty of companies
	// register no CPEs at all — and it is not the same as "we could not check", so the CPEs go
	// rather than travelling on unverified.
	for _, v := range unknown {
		res.Dropped = append(res.Dropped, fmt.Sprintf("cpe vendor %q (unknown to NVD)", v))
	}
	for _, c := range res.Entity.CPEs {
		res.Dropped = append(res.Dropped, fmt.Sprintf("cpe %q (its vendor is unknown to NVD)", c))
	}
	res.Entity.CPEs = nil
	res.CPEOrigin = fmt.Sprintf("no CPE: NVD's dictionary has no vendor named %s",
		strings.Join(unknown, " or "))
	return CPECatalogue{}, false
}

// vendorCandidates builds the cpe:2.3:<part>:<vendor> prefixes to try, in order, deduplicated
// and capped.
func vendorCandidates(res Resolution) []string {
	var out []string
	add := func(prefix string) {
		if prefix == "" || len(out) >= maxVendorCandidates {
			return
		}
		for _, existing := range out {
			if existing == prefix {
				return
			}
		}
		out = append(out, prefix)
	}

	// Bare tokens name a vendor without a part. Applications is the assumption: this tool
	// assesses software suppliers, and a vendor with hardware or an OS in NVD almost always
	// has applications too. The proposed CPEs below are what carry a non-application part.
	for _, v := range res.CPEVendors {
		add("cpe:2.3:a:" + v)
	}
	for _, c := range res.Entity.CPEs {
		add(vendorMatchString(c))
	}
	return out
}

// confirmedCPEs keeps the proposed CPEs whose vendor and product the catalogue lists.
func confirmedCPEs(proposed []string, cat CPECatalogue) []string {
	var out []string
	for _, c := range proposed {
		if vendorMatchString(c) != cat.Vendor {
			continue
		}
		parts := strings.Split(c, ":")
		if len(parts) < 5 || !cat.Has(parts[4]) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// unconfirmedNotes explains the proposed CPEs that the confirmed set left behind.
func unconfirmedNotes(proposed, confirmed []string, cat CPECatalogue) []string {
	var out []string
	for _, c := range proposed {
		if !slices.Contains(confirmed, c) {
			out = append(out, fmt.Sprintf("cpe %q (not registered under %s)", c, cat.Vendor))
		}
	}
	return out
}

// partitionSelection splits the model's choices into ones the catalogue lists and ones it
// does not, returning the catalogue's own spelling for the former.
//
// It does not apply the selection cap. Trimming here would discard a real product with
// nothing left to report it by, and a product cut by our own limit is a different fact from
// one the model never chose; the caller enforces the cap and says what it cut.
func partitionSelection(selected []string, cat CPECatalogue) (accepted, invented []string) {
	for _, s := range selected {
		token := strings.ToLower(strings.TrimSpace(s))
		if token == "" {
			continue
		}
		var match string
		for _, p := range cat.Products {
			if strings.EqualFold(p.Token, token) {
				// The catalogue's spelling, not the model's: NVD's registry is the authority
				// on how its own token is written.
				match = p.Token
				break
			}
		}
		if match == "" {
			invented = append(invented, s)
			continue
		}
		if slices.Contains(accepted, match) {
			continue
		}
		accepted = append(accepted, match)
	}
	return accepted, invented
}

// selectionOrigin describes what the selection call was shown and what it made of it.
func selectionOrigin(cat CPECatalogue, chosen int) string {
	var b strings.Builder
	if chosen == 0 {
		fmt.Fprintf(&b, "no CPE: none of the %d products NVD registers under %s match this service",
			len(cat.Products), cat.Vendor)
	} else {
		fmt.Fprintf(&b, "chosen from the %d products NVD registers under %s",
			len(cat.Products), cat.Vendor)
	}
	// Both qualifiers change what the answer means, so neither is left implicit. A narrowed
	// or truncated list is a view of the vendor, and a product missing from it may still
	// exist — which makes "none match" a weaker claim than it looks.
	if cat.Narrowed != "" {
		fmt.Fprintf(&b, " (list narrowed by %q; %d dictionary rows)", cat.Narrowed, cat.TotalRows)
	} else if !cat.Complete {
		fmt.Fprintf(&b, " (first page only, of %d dictionary rows)", cat.TotalRows)
	}
	return b.String()
}

// selectProducts asks the model to pick from the catalogue.
//
// The reply is not trusted, only constrained: structured outputs guarantee an array of
// strings, and partitionSelection guarantees every string that survives is one NVD returned.
func (r *Resolver) selectProducts(ctx context.Context, q Query, cat CPECatalogue) ([]string, error) {
	resp, err := r.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(r.model),
		MaxTokens: productSelectionMaxTokens,
		System:    []anthropic.TextBlockParam{{Text: productSelectionPrompt}},
		OutputConfig: anthropic.OutputConfigParam{
			// Explicit, like the other two calls: an API default nobody chose is not a
			// setting (CLAUDE.md). This is a short pick from a list shown in the prompt.
			Effort: anthropic.OutputConfigEffort("low"),
			Format: anthropic.JSONOutputFormatParam{Schema: productSelectionSchema},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(selectionQuery(q, cat))),
		},
	})
	if err != nil {
		return nil, sanitizeAPIError(err, r.apiKey)
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return nil, errors.New("the model declined to choose a product")
	}

	raw, err := firstTextBlock(resp)
	if err != nil {
		return nil, err
	}

	var reply struct {
		Products []string `json:"products"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reply); err != nil {
		return nil, fmt.Errorf("parse product selection response: %w", err)
	}
	return reply.Products, nil
}

// selectionQuery renders the user turn: the query, the vendor, and the catalogue.
//
// Titles are included alongside tokens because a token is a compressed name — "verify" and
// "mobile" say very little on their own, where "Okta Verify" and "Okta Mobile" say what the
// product is. They are NVD's own titles, interpolated verbatim.
func selectionQuery(q Query, cat CPECatalogue) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Company: %s\n", q.Company)
	if strings.TrimSpace(q.Service) != "" {
		fmt.Fprintf(&b, "Service: %s\n", q.Service)
	}
	fmt.Fprintf(&b, "CPE vendor: %s\n\nRegistered products:\n", cat.Vendor)
	for _, p := range cat.Products {
		if p.Title == "" {
			fmt.Fprintf(&b, "  %s\n", p.Token)
			continue
		}
		fmt.Fprintf(&b, "  %s — %s\n", p.Token, p.Title)
	}
	return b.String()
}
