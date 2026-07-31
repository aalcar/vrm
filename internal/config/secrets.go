package config

import (
	"fmt"
	"os"
	"strings"
)

// Environment variable names. Secrets are environment-only and must never appear in
// config.yaml (spec §4).
const (
	EnvDatabaseURL     = "DATABASE_URL"
	EnvAnthropicAPIKey = "ANTHROPIC_API_KEY"
	EnvBitsightAPIKey  = "BITSIGHT_API_KEY"
	EnvNVDAPIKey       = "NVD_API_KEY"
)

// Secrets holds credentials read from the environment.
//
// It deliberately has no String or GoString method, so fmt cannot render its contents via
// %v or %s. Never log this struct, its fields, or any value derived from them — including
// DATABASE_URL, which carries a password.
type Secrets struct {
	// Required. Startup fails without these.
	DatabaseURL     string
	AnthropicAPIKey string
	BitsightAPIKey  string

	// Optional. When absent NVD still works, just rate-limited hard (spec §6).
	NVDAPIKey string
}

// HasNVDKey reports whether an NVD key is configured. Without one, NVD still works but is
// rate-limited hard.
func (s *Secrets) HasNVDKey() bool { return s.NVDAPIKey != "" }

// MissingEnvError reports required environment variables that were not set. It names the
// variables only — never any value.
type MissingEnvError struct {
	Vars []string
}

func (e *MissingEnvError) Error() string {
	return fmt.Sprintf(
		"missing required environment variable(s): %s\n"+
			"Copy .env.example to .env and fill them in, or export them directly.\n"+
			"Secrets are never read from config.yaml.",
		strings.Join(e.Vars, ", "))
}

// LoadSecrets reads credentials from the environment, reporting every missing required
// variable at once. Failing on the first is a poor first-run experience when several are
// unset, which is the common case on a fresh clone.
func LoadSecrets() (*Secrets, error) {
	get := func(key string) string { return strings.TrimSpace(os.Getenv(key)) }

	s := &Secrets{
		DatabaseURL:     get(EnvDatabaseURL),
		AnthropicAPIKey: get(EnvAnthropicAPIKey),
		BitsightAPIKey:  get(EnvBitsightAPIKey),
		NVDAPIKey:       get(EnvNVDAPIKey),
	}

	required := []struct {
		name  string
		value string
	}{
		{EnvDatabaseURL, s.DatabaseURL},
		{EnvAnthropicAPIKey, s.AnthropicAPIKey},
		{EnvBitsightAPIKey, s.BitsightAPIKey},
	}

	var missing []string
	for _, r := range required {
		if r.value == "" {
			missing = append(missing, r.name)
		}
	}
	if len(missing) > 0 {
		return nil, &MissingEnvError{Vars: missing}
	}
	return s, nil
}
