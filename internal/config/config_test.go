package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validConfig mirrors the committed config.yaml. Tests mutate a copy of it to isolate one
// failure at a time.
const validConfig = `
models:
  resolution: claude-sonnet-5
  research: claude-sonnet-5
sources:
  bitsight: true
  nvd: true
  osv: true
  fedramp: true
  caag: false
  llm_research: true
manual_sources:
  - name: cvedetails
    url: https://www.cvedetails.com
    instruction: "Search the vendor; record CVE counts"
  - name: ssllabs
    url: https://www.ssllabs.com/ssltest
    instruction: "Scan the service hostname; record the grade"
  - name: openbugbounty
    url: https://www.openbugbounty.org
    instruction: "Search the vendor domain; record open/fixed counts"
cache_ttl:
  bitsight: 24h
  fedramp: 168h
  llm_research: 168h
  resolution: 720h
timeouts:
  per_source: 30s
  total: 90s
nvd:
  results_per_cpe: 20
listen: ":8080"
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The whole point of the custom Duration type: yaml.v3 would otherwise read "24h" as
	// 24 nanoseconds and the cache would never hit.
	ttl, ok := cfg.TTL("bitsight")
	if !ok {
		t.Fatal("no TTL for bitsight")
	}
	if want := 24 * time.Hour; ttl != want {
		t.Errorf("bitsight TTL = %v, want %v", ttl, want)
	}
	if want := 720 * time.Hour; cfg.CacheTTL["resolution"].Duration() != want {
		t.Errorf("resolution TTL = %v, want %v", cfg.CacheTTL["resolution"], want)
	}
	if want := 30 * time.Second; cfg.Timeouts.PerSource.Duration() != want {
		t.Errorf("per_source = %v, want %v", cfg.Timeouts.PerSource, want)
	}

	// caag is toggled off and must not appear.
	got := strings.Join(cfg.EnabledSources(), ",")
	if want := "bitsight,nvd,osv,fedramp,llm_research"; got != want {
		t.Errorf("EnabledSources() = %q, want %q", got, want)
	}

	// cvedetails is a manual source, not an automated one, so it is never an enabled
	// source and never carries a TTL.
	if cfg.Sources["cvedetails"] {
		t.Error("cvedetails must not be an automated source")
	}
	if _, ok := cfg.TTL("cvedetails"); ok {
		t.Error("cvedetails has a TTL; manual entries never expire")
	}

	// Manual sources are TTL-exempt by design (spec §7).
	if _, ok := cfg.TTL("ssllabs"); ok {
		t.Error("manual source ssllabs has a TTL; manual entries never expire")
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "unknown automated source",
			body:    strings.Replace(validConfig, "  caag: false", "  caag: false\n  shodan: true", 1),
			wantErr: `unknown source "shodan"`,
		},
		{
			name: "manual source missing name",
			// Appends a third manual entry that has a url but no name.
			body: strings.Replace(validConfig, "cache_ttl:",
				"  - url: https://example.com\n    instruction: \"nameless\"\ncache_ttl:", 1),
			wantErr: "name is required",
		},
		{
			name:    "duplicate manual source",
			body:    strings.Replace(validConfig, "  - name: openbugbounty", "  - name: ssllabs", 1),
			wantErr: `duplicate name "ssllabs"`,
		},
		{
			name:    "TTL for a manual source",
			body:    strings.Replace(validConfig, "  bitsight: 24h", "  bitsight: 24h\n  ssllabs: 24h", 1),
			wantErr: "never expires",
		},
		{
			name:    "unknown cache_ttl key",
			body:    strings.Replace(validConfig, "  bitsight: 24h", "  bitsight: 24h\n  shodan: 24h", 1),
			wantErr: `unknown key "shodan"`,
		},
		{
			name:    "unparseable duration",
			body:    strings.Replace(validConfig, "  bitsight: 24h", "  bitsight: soon", 1),
			wantErr: `parse duration "soon"`,
		},
		{
			name:    "total timeout below per-source",
			body:    strings.Replace(validConfig, "  total: 90s", "  total: 10s", 1),
			wantErr: "must be >= timeouts.per_source",
		},
		{
			name:    "empty model",
			body:    strings.Replace(validConfig, "  resolution: claude-sonnet-5", `  resolution: ""`, 1),
			wantErr: "models.resolution must be set",
		},
		{
			name:    "typo'd top-level key",
			body:    strings.Replace(validConfig, "listen:", "listenn:", 1),
			wantErr: "listenn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.body))
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReportsAllProblemsAtOnce(t *testing.T) {
	body := strings.Replace(validConfig, "  resolution: claude-sonnet-5", `  resolution: ""`, 1)
	body = strings.Replace(body, "  caag: false", "  caag: false\n  shodan: true", 1)
	body = strings.Replace(body, "  results_per_cpe: 20", "  results_per_cpe: 0", 1)

	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	for _, want := range []string{"models.resolution must be set", `unknown source "shodan"`, "results_per_cpe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q; got:\n%s", want, err)
		}
	}
}
