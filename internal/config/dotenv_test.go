package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDotEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp .env: %v", err)
	}
	return path
}

// A malformed .env must never echo its own contents. godotenv includes the unparsed
// remainder of the file in its error, so wrapping that error would print every credential
// after the offending line to stderr — where it lands in shell scrollback and CI logs
// without the analyst ever realising a secret was disclosed.
func TestLoadDotEnvMalformedFileNeverEchoesContents(t *testing.T) {
	const canary = "should-not-appear-in-any-error"

	// The typo is on the first line; the keys that follow are the ones at risk.
	path := writeDotEnv(t, "BITSIGHT_API_KEY bs-"+canary+"\nANTHROPIC_API_KEY=sk-ant-"+canary+"\n")

	err := LoadDotEnv(path)
	if err == nil {
		t.Fatal("LoadDotEnv succeeded on a malformed file, want an error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error leaked .env contents:\n%s", err)
	}
	// It still has to be actionable.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the offending file:\n%s", err)
	}
}

func TestLoadDotEnvMissingFileIsNotAnError(t *testing.T) {
	// Production has no .env and must start cleanly without one.
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Errorf("LoadDotEnv on a missing file = %v, want nil", err)
	}
}

func TestLoadDotEnvDoesNotOverrideRealEnvironment(t *testing.T) {
	// A stale local .env must never override deployed configuration. This is the
	// difference between godotenv.Load and Overload; if someone switches them, this fails.
	t.Setenv(EnvBitsightAPIKey, "from-real-environment")
	// t.Setenv first so the original value is restored on cleanup, then genuinely unset:
	// godotenv keys off presence, and a set-but-empty variable counts as present.
	t.Setenv(EnvNVDAPIKey, "")
	if err := os.Unsetenv(EnvNVDAPIKey); err != nil {
		t.Fatalf("unset %s: %v", EnvNVDAPIKey, err)
	}

	path := writeDotEnv(t, EnvBitsightAPIKey+"=from-dotenv\n"+EnvNVDAPIKey+"=from-dotenv\n")
	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}

	if got := os.Getenv(EnvBitsightAPIKey); got != "from-real-environment" {
		t.Errorf("%s = %q, want the real environment to win", EnvBitsightAPIKey, got)
	}
	// An unset variable is still filled in from the file — that is the point of .env.
	if got := os.Getenv(EnvNVDAPIKey); got != "from-dotenv" {
		t.Errorf("%s = %q, want it populated from .env", EnvNVDAPIKey, got)
	}
}
