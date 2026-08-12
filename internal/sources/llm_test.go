package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The okta fixture is a captured reply with cpe_vendors added when that field entered the
// schema. Its cpes entry is the real thing the model returned: cpe:2.3:a:okta:okta, a product
// NVD has never registered. It is kept precisely because it is wrong — the dictionary lookup
// in resolve_cpe.go exists to catch exactly this, and a fixture with a valid CPE would not
// exercise it.
func TestParseResolutionFixture(t *testing.T) {
	res, err := parseResolution(string(fixture(t, "resolution_okta.json")))
	if err != nil {
		t.Fatalf("parseResolution: %v", err)
	}
	if got := strings.Join(res.CPEVendors, ","); got != "okta,auth0" {
		t.Errorf("CPEVendors = %q, want the candidate vendor tokens", got)
	}
	if res.Entity.CanonicalName != "Okta, Inc." {
		t.Errorf("CanonicalName = %q", res.Entity.CanonicalName)
	}
	if got := strings.Join(res.Entity.Domains, ","); got != "okta.com,auth0.com" {
		t.Errorf("Domains = %q", got)
	}
	if len(res.Entity.CPEs) != 1 {
		t.Errorf("CPEs = %v, want 1 entry", res.Entity.CPEs)
	}
	if len(res.Dropped) != 0 {
		t.Errorf("Dropped = %v, want nothing dropped", res.Dropped)
	}
}

// Most vendors publish no OSS packages and many have no registered CPE. An all-empty
// resolution is a correct answer, not a failure (spec §15).
func TestParseResolutionAcceptsEmptyArrays(t *testing.T) {
	res, err := parseResolution(string(fixture(t, "resolution_unknown.json")))
	if err != nil {
		t.Fatalf("parseResolution rejected an all-empty resolution: %v", err)
	}
	if res.Entity.CanonicalName == "" {
		t.Error("CanonicalName is empty")
	}
	for name, got := range map[string][]string{
		"Domains": res.Entity.Domains, "CPEs": res.Entity.CPEs,
		"Aliases": res.Entity.Aliases,
	} {
		if len(got) != 0 {
			t.Errorf("%s = %v, want empty", name, got)
		}
	}
	if len(res.Entity.Packages) != 0 {
		t.Errorf("Packages = %v, want empty", res.Entity.Packages)
	}
}

// Acceptance criterion 2: malformed output is rejected rather than propagated. A partially
// populated entity would send wrong identifiers to NVD and produce a confident, wrong report.
func TestParseResolutionRejectsMalformed(t *testing.T) {
	tests := []struct {
		name, body string
	}{
		{"not json", `not json at all`},
		{"truncated", `{"canonical_name": "Okta", "domains": [`},
		{"missing canonical_name", `{"domains":[],"cpes":[],"packages":[],"aliases":[]}`},
		{"empty canonical_name", `{"canonical_name":"  ","domains":[],"cpes":[],"packages":[],"aliases":[]}`},
		{"wrong type for domains", `{"canonical_name":"Okta","domains":"okta.com","cpes":[],"packages":[],"aliases":[]}`},
		{"wrong type for canonical_name", `{"canonical_name":42,"domains":[],"cpes":[],"packages":[],"aliases":[]}`},
		{"unexpected field", `{"canonical_name":"Okta","domains":[],"cpes":[],"packages":[],"aliases":[],"risk_score":9}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseResolution(tt.body)
			if err == nil {
				t.Fatalf("parseResolution accepted malformed output, returned %+v", res.Entity)
			}
			if res.Entity.CanonicalName != "" || len(res.Entity.Domains) != 0 {
				t.Errorf("returned a partial entity alongside the error: %+v", res.Entity)
			}
		})
	}
}

// A wrong CPE is the worst failure in the tool: it silently returns another vendor's CVEs
// and nothing looks broken (spec §15). Anything not clearly well-formed is dropped.
func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		name, in, want string
		ok             bool
	}{
		{"well-formed wildcard", "cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*", "cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*", true},
		{"well-formed versioned", "cpe:2.3:a:okta:okta:1.2.3:*:*:*:*:*:*:*", "cpe:2.3:a:okta:okta:1.2.3:*:*:*:*:*:*:*", true},
		{"operating system part", "cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*", "cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*", true},
		{"uppercase is normalized", "CPE:2.3:A:Okta:Okta:*:*:*:*:*:*:*:*", "cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*", true},
		{"cpe 2.2 syntax", "cpe:/a:okta:okta", "", false},
		{"too few components", "cpe:2.3:a:okta:okta:*", "", false},
		{"too many components", "cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*:*", "", false},
		{"invalid part", "cpe:2.3:x:okta:okta:*:*:*:*:*:*:*:*", "", false},
		{"wildcard vendor matches everything", "cpe:2.3:a:*:okta:*:*:*:*:*:*:*:*", "", false},
		{"wildcard product matches everything", "cpe:2.3:a:okta:*:*:*:*:*:*:*:*:*", "", false},
		{"bare product name", "okta", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeCPE(tt.in)
			if ok != tt.ok {
				t.Fatalf("normalizeCPE(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("normalizeCPE(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"okta.com", "okta.com", true},
		{"OKTA.COM", "okta.com", true},
		{"  okta.com  ", "okta.com", true},
		{"okta.com.", "okta.com", true},
		{"sub.okta.com", "sub.okta.com", true},
		{"https://okta.com", "", false},
		{"okta.com/login", "", false},
		{"okta.com:443", "", false},
		{"user@okta.com", "", false},
		{"okta com", "", false},
		{"localhost", "", false},
		{"okta..com", "", false},
		{".okta.com", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeDomain(tt.in)
		if ok != tt.ok {
			t.Errorf("normalizeDomain(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Dropped identifiers must be reported. A silently discarded CPE is indistinguishable from
// a vendor that genuinely has none.
func TestParseResolutionReportsDropped(t *testing.T) {
	body := `{"canonical_name":"Okta","domains":["okta.com","https://bad.example/x"],
	          "cpes":["cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*","cpe:/a:okta:okta"],
	          "packages":[],"aliases":[]}`

	res, err := parseResolution(body)
	if err != nil {
		t.Fatalf("parseResolution: %v", err)
	}
	if len(res.Entity.Domains) != 1 || res.Entity.Domains[0] != "okta.com" {
		t.Errorf("Domains = %v, want only the valid one", res.Entity.Domains)
	}
	if len(res.Entity.CPEs) != 1 {
		t.Errorf("CPEs = %v, want only the valid one", res.Entity.CPEs)
	}
	if len(res.Dropped) != 2 {
		t.Fatalf("Dropped = %v, want 2 entries", res.Dropped)
	}
	joined := strings.Join(res.Dropped, " ")
	if !strings.Contains(joined, "bad.example") || !strings.Contains(joined, "cpe:/a:okta") {
		t.Errorf("dropped entries do not name what was thrown out: %v", res.Dropped)
	}
}

// newTestResolver points a Resolver at a stub server.
func newTestResolver(t *testing.T, h http.HandlerFunc, apiKey string) *Resolver {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewResolver(apiKey, "claude-sonnet-5",
		WithResolverBaseURL(srv.URL), WithResolverMaxRetries(0))
}

// respondWithText writes a minimal Messages API reply carrying text.
func respondWithText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": "msg_test", "type": "message", "role": "assistant",
		"model": "claude-sonnet-5", "stop_reason": "end_turn",
		"content": []map[string]any{{"type": "text", "text": text}},
		"usage":   map[string]any{"input_tokens": 1, "output_tokens": 1},
	})
}

func TestResolveHappyPath(t *testing.T) {
	r := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		respondWithText(w, string(fixture(t, "resolution_okta.json")))
	}, "test-key")

	res, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Entity.CanonicalName != "Okta, Inc." {
		t.Errorf("CanonicalName = %q", res.Entity.CanonicalName)
	}
	if len(res.Entity.CPEs) != 1 {
		t.Errorf("CPEs = %v, want 1", res.Entity.CPEs)
	}
}

// Structured outputs are what make the strict-JSON contract enforceable rather than merely
// requested, so the request must actually carry the schema.
func TestResolveSendsStructuredOutputSchema(t *testing.T) {
	var body map[string]any
	r := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewDecoder(req.Body).Decode(&body)
		respondWithText(w, string(fixture(t, "resolution_unknown.json")))
	}, "test-key")

	if _, err := r.Resolve(context.Background(), Query{Company: "Okta", Service: "SSO"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	oc, ok := body["output_config"].(map[string]any)
	if !ok {
		t.Fatalf("request has no output_config: %v", body)
	}
	format, ok := oc["format"].(map[string]any)
	if !ok {
		t.Fatalf("output_config has no format: %v", oc)
	}
	if format["type"] != "json_schema" {
		t.Errorf("format type = %v, want json_schema", format["type"])
	}
	schema, ok := format["schema"].(map[string]any)
	if !ok {
		t.Fatalf("format has no schema: %v", format)
	}
	if schema["additionalProperties"] != false {
		t.Error("schema allows additional properties; the contract is not closed")
	}
	props, _ := schema["properties"].(map[string]any)
	for _, field := range []string{"cpes", "cpe_vendors"} {
		if _, ok := props[field]; !ok {
			t.Errorf("schema does not declare %s", field)
		}
	}
}

// The vendor token is the half of a CPE the model can reliably get right, and it is pasted
// straight into a dictionary match string. Anything that is not a bare token would query
// something other than what it names.
func TestNormalizeCPEVendor(t *testing.T) {
	tests := []struct {
		name, in, want string
		ok             bool
	}{
		{"bare token", "okta", "okta", true},
		{"underscores are normal", "red_hat", "red_hat", true},
		{"hyphens are normal", "d-link", "d-link", true},
		{"case is normalized", "Atlassian", "atlassian", true},
		{"whitespace is trimmed", "  okta\t", "okta", true},
		// Registered vendor tokens do contain dots. A domain-looking token is the wrong
		// answer, but the dictionary reports it as unregistered — which is louder than
		// dropping it here, where nothing would say why the lookup never happened.
		{"a dot is allowed through", "node.js", "node.js", true},
		{"a whole CPE is not a vendor token", "cpe:2.3:a:okta:okta", "", false},
		{"a company name with spaces", "Okta Inc", "", false},
		{"a URL", "https://okta.com", "", false},
		{"empty", "   ", "", false},
		{"a wildcard would match every vendor", "*", "", false},
		{"a NA marker is not a vendor", "-", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeCPEVendor(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("normalizeCPEVendor(%q) = %q, %v; want %q, %v",
					tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

// A dropped vendor token is reported, like every other discarded identifier: silently losing
// one looks exactly like a company that publishes no software.
func TestParseResolutionReportsDroppedVendorTokens(t *testing.T) {
	res, err := parseResolution(`{"canonical_name":"Okta","domains":[],
		"cpe_vendors":["okta","Okta Inc","okta"],"cpes":[],"packages":[],"aliases":[]}`)
	if err != nil {
		t.Fatalf("parseResolution: %v", err)
	}
	if got := strings.Join(res.CPEVendors, ","); got != "okta" {
		t.Errorf("CPEVendors = %q, want the duplicate collapsed and the bad one dropped", got)
	}
	if len(res.Dropped) != 1 || !strings.Contains(res.Dropped[0], "Okta Inc") {
		t.Errorf("Dropped = %v, want it to name the rejected token", res.Dropped)
	}
}

func TestResolveRejectsEmptyCompany(t *testing.T) {
	r := NewResolver("k", "claude-sonnet-5")
	if _, err := r.Resolve(context.Background(), Query{Service: "SSO"}); err == nil {
		t.Fatal("Resolve accepted an empty company")
	}
}

func TestResolveHTTPErrorIsClear(t *testing.T) {
	r := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"message":"boom"}}`))
	}, "test-key")

	res, err := r.Resolve(context.Background(), Query{Company: "Okta"})
	if err == nil {
		t.Fatal("Resolve returned no error on HTTP 500")
	}
	// Resolution failure is fatal, so it must not masquerade as a successful empty result.
	if res.Entity.CanonicalName != "" {
		t.Errorf("returned an entity alongside the error: %+v", res.Entity)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error does not mention the status: %v", err)
	}
}

// The Anthropic key is a billable credential. An auth failure must not echo it back into an
// error an analyst reads — same rule as internal/sources/bitsight.go.
func TestResolveNeverLeaksAPIKey(t *testing.T) {
	const canary = "canary-anthropic-key-do-not-render"

	r := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// Some APIs quote the rejected credential back in the body.
		_, _ = w.Write([]byte(`{"type":"error","error":{"message":"invalid key ` + canary + `"}}`))
	}, canary)

	_, err := r.Resolve(context.Background(), Query{Company: "Okta"})
	if err == nil {
		t.Fatal("Resolve returned no error on HTTP 401")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error leaked the API key: %v", err)
	}
}

// A model refusal is not a resolution. Treating it as one would produce an empty entity and
// a report where every source skipped.
func TestResolveRefusalIsAnError(t *testing.T) {
	r := newTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant",
			"model": "claude-sonnet-5", "stop_reason": "refusal",
			"content": []map[string]any{},
			"usage":   map[string]any{"input_tokens": 1, "output_tokens": 0},
		})
	}, "test-key")

	if _, err := r.Resolve(context.Background(), Query{Company: "Okta"}); err == nil {
		t.Fatal("Resolve treated a refusal as a successful resolution")
	}
}

// The prompt must not carry deterministic source data into the model (spec §2.2), and must
// tell the model to return [] rather than guess (spec §10).
func TestResolutionPromptContract(t *testing.T) {
	if !strings.Contains(resolutionPrompt, "empty array") {
		t.Error("prompt does not instruct the model to return empty arrays for unknowns")
	}
	for _, forbidden := range []string{"rating", "CVE-", "BitSight", "FedRAMP"} {
		if strings.Contains(resolutionPrompt, forbidden) {
			t.Errorf("prompt mentions %q; deterministic data must never enter a prompt", forbidden)
		}
	}
}

func TestParseCPEOverride(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{
			// The short form is what this tool itself prints when it reports an
			// unverified CPE, so it must round-trip without hand-typed wildcards.
			name: "short vendor:product form is padded",
			in:   "cpe:2.3:a:okta:access_gateway",
			want: "cpe:2.3:a:okta:access_gateway:*:*:*:*:*:*:*:*",
			ok:   true,
		},
		{
			name: "full form passes through",
			in:   "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*",
			want: "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*",
			ok:   true,
		},
		{name: "case and spacing normalized", in: "  CPE:2.3:A:Okta:Verify  ",
			want: "cpe:2.3:a:okta:verify:*:*:*:*:*:*:*:*", ok: true},
		{name: "wrong prefix rejected", in: "cpe:2.2:a:okta:verify"},
		{name: "wildcard product rejected", in: "cpe:2.3:a:okta:*"},
		{name: "bad part rejected", in: "cpe:2.3:x:okta:verify"},
		{name: "too few components rejected", in: "cpe:2.3:a:okta"},
		{name: "empty rejected", in: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseCPEOverride(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tt.ok, got)
			}
			if ok && got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseResolutionValidatesPackages: an ecosystem OSV does not recognize is dropped and
// reported, because OSV answers HTTP 400 for one it does not know — a single bad entry
// would otherwise fail the whole section.
func TestParseResolutionValidatesPackages(t *testing.T) {
	body := `{"canonical_name":"HashiCorp","domains":[],"cpes":[],"aliases":[],
	  "packages":[
	    {"ecosystem":"golang","name":"github.com/hashicorp/vault"},
	    {"ecosystem":"Debian","name":"vault"},
	    {"ecosystem":"npm","name":""}
	  ]}`

	res, err := parseResolution(body)
	if err != nil {
		t.Fatalf("parseResolution: %v", err)
	}
	if len(res.Entity.Packages) != 1 {
		t.Fatalf("Packages = %+v, want just the Go one", res.Entity.Packages)
	}
	// Informal spellings are canonicalized to OSV's exact capitalization.
	if got := res.Entity.Packages[0]; got.Ecosystem != "Go" {
		t.Errorf("ecosystem = %q, want Go", got.Ecosystem)
	}
	if len(res.Dropped) != 2 {
		t.Errorf("Dropped = %v, want both bad entries reported", res.Dropped)
	}
}

func TestResolutionCacheability(t *testing.T) {
	full := Resolution{Entity: ResolvedEntity{
		CanonicalName: "Okta, Inc.",
		Domains:       []string{"okta.com"},
		CPEs:          []string{"cpe:2.3:a:okta:okta:*:*:*:*:*:*:*:*"},
	}}

	noCPEs := full
	noCPEs.Entity.CPEs = nil

	emptyCPEs := full
	emptyCPEs.Entity.CPEs = []string{}

	noName := full
	noName.Entity.CanonicalName = ""

	cases := []struct {
		name string
		res  Resolution
		want bool
	}{
		{"a full mapping", full, true},
		{"nil CPEs", noCPEs, false},
		{"empty CPE slice", emptyCPEs, false},
		{"no canonical name", noName, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.Cacheable(); got != tc.want {
				t.Errorf("Cacheable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Domains and packages alone are not enough. They keep BitSight and OSV working, which is
// exactly why an analyst would not notice that NVD had gone quiet for the rest of the TTL.
func TestAResolutionThatOnlyFeedsTheOtherSourcesIsNotCacheable(t *testing.T) {
	res := Resolution{Entity: ResolvedEntity{
		CanonicalName: "Okta, Inc.",
		Domains:       []string{"okta.com"},
		Packages:      []Package{{Ecosystem: "npm", Name: "@okta/okta-auth-js"}},
	}}
	if res.Cacheable() {
		t.Error("cached a resolution NVD cannot use")
	}
}
