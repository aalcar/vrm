package sources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubDirectory stands in for NVD's CPE dictionary. Its recorded calls matter as much as its
// answers: the point of several tests below is that a second dictionary request, or a second
// model call, did not happen.
type stubDirectory struct {
	byVendor map[string]CPECatalogue
	err      error
	calls    []string
}

func (d *stubDirectory) VendorProducts(_ context.Context, vendor, narrow string) (CPECatalogue, error) {
	d.calls = append(d.calls, vendor+"|"+narrow)
	if d.err != nil {
		return CPECatalogue{}, d.err
	}
	if cat, ok := d.byVendor[vendor]; ok {
		return cat, nil
	}
	// Unknown to NVD: a 200 with nothing in it, which is what the dictionary actually answers.
	return CPECatalogue{Vendor: vendor}, nil
}

// oktaCatalogue is the real Okta product list, as captured in nvd_cpes_okta_vendor.json.
func oktaCatalogue(t *testing.T) CPECatalogue {
	t.Helper()
	page, err := parseNVDCPEs(fixture(t, "nvd_cpes_okta_vendor.json"))
	if err != nil {
		t.Fatalf("parse okta catalogue fixture: %v", err)
	}
	return CPECatalogue{
		Vendor:    "cpe:2.3:a:okta",
		Products:  page.products,
		TotalRows: page.total,
		Complete:  page.rows >= page.total,
	}
}

// resolverWithDirectory wires a Resolver to a stub API and a stub dictionary.
//
// The handler is given the decoded request body so a test can tell resolution's call from
// the product-selection call and answer each appropriately.
func resolverWithDirectory(
	t *testing.T,
	dir CPEDirectory,
	reply func(body string) string,
) (*Resolver, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		var payload struct {
			Messages []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		var b strings.Builder
		for _, m := range payload.Messages {
			for _, c := range m.Content {
				b.WriteString(c.Text)
			}
		}
		respondWithText(w, reply(b.String()))
	}))
	t.Cleanup(srv.Close)

	opts := []ResolverOption{WithResolverBaseURL(srv.URL), WithResolverMaxRetries(0)}
	if dir != nil {
		opts = append(opts, WithCPEDirectory(dir))
	}
	return NewResolver("test-key", "claude-sonnet-5", opts...), &calls
}

// isSelectionCall reports whether a rendered user turn is the product-selection one.
func isSelectionCall(body string) bool { return strings.Contains(body, "Registered products:") }

func resolutionReplyJSON(vendors, cpes []string) string {
	b, _ := json.Marshal(map[string]any{
		"canonical_name": "Okta, Inc.",
		"domains":        []string{"okta.com"},
		"cpe_vendors":    vendors,
		"cpes":           cpes,
		"packages":       []any{},
		"aliases":        []string{},
	})
	return string(b)
}

func selectionReplyJSON(products ...string) string {
	if products == nil {
		products = []string{}
	}
	b, _ := json.Marshal(map[string]any{"products": products})
	return string(b)
}

// A proposed CPE the dictionary already lists is the answer. Nothing is gained by asking the
// model to re-choose what NVD has just confirmed, and the second call would be billed for it.
func TestGroundCPEsConfirmsAProposedCPEWithoutASecondCall(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}
	r, calls := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			t.Error("a confirmed CPE still triggered a product-selection call")
			return selectionReplyJSON()
		}
		return resolutionReplyJSON(
			[]string{"okta"}, []string{"cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*"})
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "Access Gateway"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := strings.Join(res.Entity.CPEs, ","); got != "cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*" {
		t.Errorf("CPEs = %q, want the proposed CPE kept", got)
	}
	if *calls != 1 {
		t.Errorf("made %d model calls, want 1", *calls)
	}
	if !strings.Contains(res.CPEOrigin, "confirmed") {
		t.Errorf("CPEOrigin = %q, want it to say the CPE was confirmed", res.CPEOrigin)
	}
}

// The case this whole design exists for: the model composed a product token NVD has never
// registered. It is discarded, and the choice is made from what NVD does hold.
func TestGroundCPEsReplacesAnInventedProductWithACataloguedOne(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}
	r, calls := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			return selectionReplyJSON("access_gateway")
		}
		// okta:single_sign-on is what six live runs actually produced. It does not exist.
		return resolutionReplyJSON(
			[]string{"okta"}, []string{"cpe:2.3:a:okta:single_sign-on:*:*:*:*:*:*:*:*"})
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := strings.Join(res.Entity.CPEs, ","); got != "cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*" {
		t.Errorf("CPEs = %q, want the catalogued product", got)
	}
	if *calls != 2 {
		t.Errorf("made %d model calls, want 2 (propose, then select)", *calls)
	}
	// The discarded CPE is reported. A silently replaced identifier hides the fact that the
	// model's first answer was fictional, which is the thing an analyst most wants to know.
	if !strings.Contains(strings.Join(res.Dropped, " "), "single_sign-on") {
		t.Errorf("Dropped = %v, want it to name the invented CPE", res.Dropped)
	}
}

// The selection call is constrained by membership, not by trust. A token outside the list it
// was shown is invented, and inventing is exactly what moving the job here was meant to stop.
func TestGroundCPEsRejectsASelectionOutsideTheCatalogue(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}
	r, _ := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			return selectionReplyJSON("single_sign-on", "okta_identity_cloud")
		}
		return resolutionReplyJSON([]string{"okta"}, nil)
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Entity.CPEs) != 0 {
		t.Errorf("CPEs = %v, want none: neither token is in the catalogue", res.Entity.CPEs)
	}
	joined := strings.Join(res.Dropped, " ")
	for _, want := range []string{"single_sign-on", "okta_identity_cloud", "invented"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Dropped = %v, want it to mention %q", res.Dropped, want)
		}
	}
}

// An empty selection is a true answer, not a failure: a cloud service often has no registered
// CPE at all. It must produce no CPEs and no error, and say why.
func TestGroundCPEsAcceptsAnEmptySelection(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}
	r, _ := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			return selectionReplyJSON()
		}
		return resolutionReplyJSON([]string{"okta"}, nil)
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"})
	if err != nil {
		t.Fatalf("an empty selection is a legitimate answer, not an error: %v", err)
	}
	if len(res.Entity.CPEs) != 0 {
		t.Errorf("CPEs = %v, want none", res.Entity.CPEs)
	}
	if !strings.Contains(res.CPEOrigin, "no CPE") {
		t.Errorf("CPEOrigin = %q, want it to say no CPE was found", res.CPEOrigin)
	}
	// And the caller must not pin this for 720h: nothing here distinguishes "this service has
	// no CPE" from "this run found none".
	if res.Cacheable() {
		t.Error("a resolution with no CPEs reports itself cacheable")
	}
}

// A vendor NVD has never heard of is a real answer — many companies register no CPEs — and it
// is not the same as being unable to check. The proposed CPEs go rather than travelling on.
func TestGroundCPEsClearsCPEsWhenNoCandidateVendorIsRegistered(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{}}
	r, calls := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			t.Error("selection was attempted for a vendor NVD does not list")
			return selectionReplyJSON()
		}
		// Two distinct spellings, so both candidates are genuinely tried before giving up.
		return resolutionReplyJSON(
			[]string{"notavendor"}, []string{"cpe:2.3:a:notavendor_inc:product:*:*:*:*:*:*:*:*"})
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Nope", Service: "Thing"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Entity.CPEs) != 0 {
		t.Errorf("CPEs = %v, want none", res.Entity.CPEs)
	}
	if *calls != 1 {
		t.Errorf("made %d model calls, want 1", *calls)
	}
	if !strings.Contains(res.CPEOrigin, "no vendor named") {
		t.Errorf("CPEOrigin = %q, want it to name the unregistered vendor", res.CPEOrigin)
	}
	if len(dir.calls) != 2 {
		t.Errorf("dictionary calls = %v, want both candidates tried", dir.calls)
	}
}

// A dictionary that cannot be reached is not evidence about the vendor. Resolution degrades to
// the model's proposal — the assessment still runs — but the CPEs are labelled unchecked, which
// is what stops the cache pinning them.
func TestGroundCPEsDegradesWhenTheDictionaryFails(t *testing.T) {
	dir := &stubDirectory{err: errors.New("NVD is unavailable (HTTP 503); retry later")}
	r, _ := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			t.Error("selection ran despite the dictionary being unreachable")
			return selectionReplyJSON()
		}
		return resolutionReplyJSON(
			[]string{"okta"}, []string{"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*"})
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "Verify"})
	if err != nil {
		t.Fatalf("a dictionary outage must not fail the whole resolution: %v", err)
	}
	if len(res.Entity.CPEs) != 1 {
		t.Errorf("CPEs = %v, want the proposed CPE kept", res.Entity.CPEs)
	}
	if !strings.Contains(res.CPEOrigin, "NOT checked") {
		t.Errorf("CPEOrigin = %q, want it to say the CPEs were not checked", res.CPEOrigin)
	}
	if !strings.Contains(strings.Join(res.Dropped, " "), "503") {
		t.Errorf("Dropped = %v, want it to carry the dictionary's error", res.Dropped)
	}
}

// nvd can be switched off in config. Resolution still has to produce domains and packages, so
// it falls back to structural validation alone — and says so, because an unchecked CPE and a
// confirmed one are different claims.
func TestGroundCPEsWithoutADirectoryKeepsTheOldBehaviour(t *testing.T) {
	r, calls := resolverWithDirectory(t, nil, func(body string) string {
		if isSelectionCall(body) {
			t.Error("selection ran with no dictionary to select from")
			return selectionReplyJSON()
		}
		return resolutionReplyJSON(
			[]string{"okta"}, []string{"cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*"})
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Entity.CPEs) != 1 {
		t.Errorf("CPEs = %v, want the proposed CPE untouched", res.Entity.CPEs)
	}
	if *calls != 1 {
		t.Errorf("made %d model calls, want 1", *calls)
	}
	if !strings.Contains(res.CPEOrigin, "not checked") {
		t.Errorf("CPEOrigin = %q, want it to say NVD did not check", res.CPEOrigin)
	}
}

// The service narrows an oversized vendor, so it has to reach the dictionary.
func TestGroundCPEsPassesTheServiceToTheDictionary(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}
	r, _ := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			return selectionReplyJSON()
		}
		return resolutionReplyJSON([]string{"okta"}, nil)
	})

	if _, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(dir.calls) != 1 || dir.calls[0] != "cpe:2.3:a:okta|SSO" {
		t.Errorf("dictionary calls = %v, want one carrying the service as the narrowing term",
			dir.calls)
	}
}

func TestVendorCandidates(t *testing.T) {
	tests := []struct {
		name string
		res  Resolution
		want []string
	}{
		{
			name: "vendor tokens become application prefixes",
			res:  Resolution{CPEVendors: []string{"okta", "auth0"}},
			want: []string{"cpe:2.3:a:okta", "cpe:2.3:a:auth0"},
		},
		{
			// A bare token carries no part, so an OS or hardware vendor can only be reached
			// through a proposed CPE. Dropping these would make those vendors unresolvable.
			name: "a proposed CPE contributes its part",
			res: Resolution{
				Entity: ResolvedEntity{CPEs: []string{"cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*"}},
			},
			want: []string{"cpe:2.3:o:vendor"},
		},
		{
			name: "a proposed CPE that repeats a vendor token adds nothing",
			res: Resolution{
				CPEVendors: []string{"okta"},
				Entity:     ResolvedEntity{CPEs: []string{"cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*"}},
			},
			want: []string{"cpe:2.3:a:okta"},
		},
		{
			// Each candidate costs a six-second wait at NVD's unkeyed interval, so the list
			// is a retry for an alternate spelling, not a search.
			name: "capped",
			res:  Resolution{CPEVendors: []string{"a", "b", "c", "d"}},
			want: []string{"cpe:2.3:a:a", "cpe:2.3:a:b"},
		},
		{name: "nothing to look up", res: Resolution{}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vendorCandidates(tt.res)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("vendorCandidates = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPartitionSelection(t *testing.T) {
	cat := CPECatalogue{
		Vendor: "cpe:2.3:a:okta",
		Products: []CPEProduct{
			{Token: "access_gateway"}, {Token: "verify"}, {Token: "mobile"},
			{Token: "ldap_agent"}, {Token: "oidc_middleware"},
		},
	}
	tests := []struct {
		name                       string
		selected                   []string
		wantAccepted, wantInvented string
	}{
		{"all catalogued", []string{"verify", "mobile"}, "verify,mobile", ""},
		{"none catalogued", []string{"single_sign-on"}, "", "single_sign-on"},
		{"partly catalogued", []string{"verify", "sso"}, "verify", "sso"},
		// CPE components are lowercase by convention; a differently cased answer is the same
		// product, and it comes back in the catalogue's spelling because NVD owns that.
		{"case is not a difference", []string{"Verify"}, "verify", ""},
		{"duplicates collapse", []string{"verify", "verify"}, "verify", ""},
		{"blank entries are ignored", []string{"  ", "verify"}, "verify", ""},
		{
			// The cap is the caller's, not this function's: a product trimmed here would be
			// gone with nothing left to report it by.
			name:         "the selection cap is not applied here",
			selected:     []string{"access_gateway", "verify", "mobile", "ldap_agent", "oidc_middleware"},
			wantAccepted: "access_gateway,verify,mobile,ldap_agent,oidc_middleware",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accepted, invented := partitionSelection(tt.selected, cat)
			if got := strings.Join(accepted, ","); got != tt.wantAccepted {
				t.Errorf("accepted = %q, want %q", got, tt.wantAccepted)
			}
			if got := strings.Join(invented, ","); got != tt.wantInvented {
				t.Errorf("invented = %q, want %q", got, tt.wantInvented)
			}
		})
	}
}

// The catalogue is the model's only source of tokens, so every one of them has to reach the
// prompt. A truncated list would silently rule out products NVD does register.
func TestSelectionQueryCarriesEveryProduct(t *testing.T) {
	cat := oktaCatalogue(t)
	rendered := selectionQuery(Query{Company: "Okta", Service: "SSO"}, cat)

	for _, p := range cat.Products {
		if !strings.Contains(rendered, p.Token) {
			t.Errorf("product %q is missing from the prompt", p.Token)
		}
		// The title is what makes a token like "verify" or "mobile" mean anything.
		if p.Title != "" && !strings.Contains(rendered, p.Title) {
			t.Errorf("title %q is missing from the prompt", p.Title)
		}
	}
	if !strings.Contains(rendered, "Okta") || !strings.Contains(rendered, "SSO") {
		t.Errorf("prompt does not carry the query: %s", rendered)
	}
	if !strings.Contains(rendered, cat.Vendor) {
		t.Errorf("prompt does not name the vendor: %s", rendered)
	}
}

// Both qualifiers weaken "none of these match", so neither may be left implicit.
func TestSelectionOriginQualifiesAPartialCatalogue(t *testing.T) {
	tests := []struct {
		name   string
		cat    CPECatalogue
		chosen int
		want   []string
	}{
		{
			name:   "complete catalogue, a product chosen",
			cat:    CPECatalogue{Vendor: "cpe:2.3:a:okta", Products: []CPEProduct{{Token: "verify"}}, TotalRows: 19, Complete: true},
			chosen: 1,
			want:   []string{"chosen from the 1 products", "cpe:2.3:a:okta"},
		},
		{
			name:   "complete catalogue, nothing matched",
			cat:    CPECatalogue{Vendor: "cpe:2.3:a:okta", Products: []CPEProduct{{Token: "verify"}}, TotalRows: 19, Complete: true},
			chosen: 0,
			want:   []string{"no CPE", "none of the 1 products"},
		},
		{
			name:   "narrowed",
			cat:    CPECatalogue{Vendor: "cpe:2.3:a:microsoft", Products: []CPEProduct{{Token: "azure_devops_server"}}, TotalRows: 15183, Narrowed: "Azure DevOps"},
			chosen: 1,
			want:   []string{"narrowed by \"Azure DevOps\"", "15183"},
		},
		{
			name:   "truncated",
			cat:    CPECatalogue{Vendor: "cpe:2.3:a:okta", Products: []CPEProduct{{Token: "verify"}}, TotalRows: 287},
			chosen: 1,
			want:   []string{"first page only", "287"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectionOrigin(tt.cat, tt.chosen)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("selectionOrigin = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

// Structured outputs are what keep the selection reply to an array of strings. Without the
// schema on the request the contract is a request, not a guarantee.
func TestSelectionSendsStructuredOutputSchema(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}

	var selectionBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		raw, _ := json.Marshal(body["messages"])
		if strings.Contains(string(raw), "Registered products:") {
			selectionBody = body
			respondWithText(w, selectionReplyJSON("verify"))
			return
		}
		respondWithText(w, resolutionReplyJSON([]string{"okta"}, nil))
	}))
	t.Cleanup(srv.Close)

	r := NewResolver("test-key", "claude-sonnet-5",
		WithResolverBaseURL(srv.URL), WithResolverMaxRetries(0), WithCPEDirectory(dir))
	if _, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "Verify"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selectionBody == nil {
		t.Fatal("no selection call was made")
	}

	oc, ok := selectionBody["output_config"].(map[string]any)
	if !ok {
		t.Fatalf("selection request has no output_config: %v", selectionBody)
	}
	// CLAUDE.md: effort is set explicitly on every LLM call, never left to an API default.
	if oc["effort"] != "low" {
		t.Errorf("effort = %v, want it set explicitly to low", oc["effort"])
	}
	format, ok := oc["format"].(map[string]any)
	if !ok || format["type"] != "json_schema" {
		t.Fatalf("selection request does not use structured outputs: %v", oc)
	}
	schema, _ := format["schema"].(map[string]any)
	if schema["additionalProperties"] != false {
		t.Error("selection schema allows additional properties; the contract is not closed")
	}
	if _, ok := schema["properties"].(map[string]any)["products"]; !ok {
		t.Error("selection schema does not declare products")
	}
}

// The cap keeps one service from spending the whole NVD budget, but a product it cuts is a
// real product. Reporting it is the difference between "the model did not choose this" and
// "we chose not to ask about it" — and only one of those is a fact about the vendor.
func TestGroundCPEsReportsProductsCutByTheSelectionCap(t *testing.T) {
	dir := &stubDirectory{byVendor: map[string]CPECatalogue{
		"cpe:2.3:a:okta": oktaCatalogue(t),
	}}
	// Every product in the catalogue, which is what the cap is a backstop against. Expressed
	// relative to the cap rather than by name, so raising it does not silently stop testing it.
	everything := oktaCatalogue(t).Tokens()
	if len(everything) <= maxSelectedProducts {
		t.Skipf("the okta catalogue has %d products and the cap is %d; nothing to cut",
			len(everything), maxSelectedProducts)
	}
	r, _ := resolverWithDirectory(t, dir, func(body string) string {
		if isSelectionCall(body) {
			return selectionReplyJSON(everything...)
		}
		return resolutionReplyJSON([]string{"okta"}, nil)
	})

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Entity.CPEs) != maxSelectedProducts {
		t.Errorf("CPEs = %v, want %d", res.Entity.CPEs, maxSelectedProducts)
	}
	joined := strings.Join(res.Dropped, " ")
	for _, want := range everything[maxSelectedProducts:] {
		if !strings.Contains(joined, want) {
			t.Errorf("Dropped = %v, want it to report %q as cut by the cap", res.Dropped, want)
		}
	}
	if !strings.Contains(joined, "limit") {
		t.Errorf("Dropped = %v, want it to say the cap was the reason", res.Dropped)
	}
	// Cut by our own limit, not invented: conflating the two would blame the model for a
	// budget decision this tool made.
	if strings.Contains(joined, "invented") {
		t.Errorf("Dropped = %v, calls a catalogued product invented", res.Dropped)
	}
}
