package config

import (
	"strings"
	"testing"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	// Clear everything first so the developer's real environment cannot leak in and make
	// a test pass locally that would fail on a clean machine.
	for _, k := range []string{
		EnvDatabaseURL, EnvAnthropicAPIKey, EnvBitsightAPIKey,
		EnvNVDAPIKey,
	} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoadSecretsAllPresent(t *testing.T) {
	setEnv(t, map[string]string{
		EnvDatabaseURL:     "postgres://vrm:vrm@localhost:5432/vrm?sslmode=disable",
		EnvAnthropicAPIKey: "test-anthropic",
		EnvBitsightAPIKey:  "test-bitsight",
	})

	s, err := LoadSecrets()
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	if s.AnthropicAPIKey != "test-anthropic" {
		t.Errorf("AnthropicAPIKey = %q", s.AnthropicAPIKey)
	}
	// Optional credentials drive skip-vs-run decisions, not failures (spec §6).
	if s.HasNVDKey() {
		t.Error("HasNVDKey() = true with NVD_API_KEY unset")
	}
}

func TestLoadSecretsReportsEveryMissingVar(t *testing.T) {
	// A fresh clone typically has all three unset; reporting them one at a time would
	// mean three failed runs to get started.
	setEnv(t, nil)

	_, err := LoadSecrets()
	if err == nil {
		t.Fatal("LoadSecrets succeeded with no environment set")
	}
	for _, want := range []string{EnvDatabaseURL, EnvAnthropicAPIKey, EnvBitsightAPIKey} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s; got:\n%s", want, err)
		}
	}
	// Optional variables must never be reported as missing.
	if strings.Contains(err.Error(), EnvNVDAPIKey) {
		t.Errorf("optional %s reported as missing: %s", EnvNVDAPIKey, err)
	}
}

func TestLoadSecretsNeverLeaksValues(t *testing.T) {
	// The error names variables only. DATABASE_URL in particular carries a password.
	const password = "sup3rs3cr3t"
	setEnv(t, map[string]string{
		EnvDatabaseURL: "postgres://vrm:" + password + "@localhost:5432/vrm",
	})

	_, err := LoadSecrets()
	if err == nil {
		t.Fatal("LoadSecrets succeeded, want error")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("error leaked a credential value: %s", err)
	}
}

func TestSecretsHasNoStringMethod(t *testing.T) {
	// Guards the rule that a stray %v cannot render credentials. If someone adds a
	// String() or GoString() method to Secrets, this fails.
	var s any = &Secrets{DatabaseURL: "postgres://vrm:leak@localhost/vrm"}
	if _, ok := s.(interface{ String() string }); ok {
		t.Error("Secrets has a String() method; it must not be renderable by fmt")
	}
	if _, ok := s.(interface{ GoString() string }); ok {
		t.Error("Secrets has a GoString() method; it must not be renderable by fmt")
	}
}
