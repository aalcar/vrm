// Package config loads vrm's non-secret configuration from config.yaml and its secrets
// from the environment.
//
// The two are deliberately separate types. Config comes from a file that is committed and
// is safe to log; Secrets comes from the environment, must never be logged, and has no
// String method so a stray %v cannot leak it (spec §4).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// knownSources are the automated sources defined in spec §6. The set is fixed: adding a
// source is a spec change, not a config change.
var knownSources = []string{"bitsight", "nvd", "osv", "cvedetails", "fedramp", "caag"}

// nonSourceTTLs are cache_ttl keys that are not automated sources. Entity resolution and
// the research call are cached too (spec §11), but they are not Source implementations.
var nonSourceTTLs = []string{"llm_research", "resolution"}

// Duration wraps time.Duration so YAML strings like "24h" parse correctly.
//
// This is not cosmetic. yaml.v3 decodes into a bare time.Duration as raw nanoseconds, so
// every TTL in spec §11 would silently become a fraction of a millisecond and the cache
// would never hit.
type Duration time.Duration

// UnmarshalYAML parses a duration string such as "24h" or "30s".
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like %q: %w", "24h", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("duration %q must be positive", s)
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// ManualSource is a checklist category an analyst fills in out of band (spec §7).
type ManualSource struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Instruction string `yaml:"instruction"`
}

// Timeouts bound a single assessment. Total is a ceiling, not a target.
type Timeouts struct {
	PerSource Duration `yaml:"per_source"`
	Total     Duration `yaml:"total"`
}

// NVD holds NVD-specific query tuning.
type NVD struct {
	ResultsPerCPE int `yaml:"results_per_cpe"`
}

// Models holds the per-job model IDs.
//
// Entity resolution and checklist research are deliberately separate jobs with separate
// prompts and output contracts (CLAUDE.md), and they differ by an order of magnitude in
// cost, so they are configured independently.
type Models struct {
	// Resolution maps a company and service to machine identifiers. Short, strict-JSON,
	// run once per assessment.
	Resolution string `yaml:"resolution"`
	// Research answers the fixed checklist with citations. The most expensive call in the
	// system (spec §11).
	Research string `yaml:"research"`
}

// Config is the non-secret configuration from config.yaml (spec §12).
type Config struct {
	Models        Models              `yaml:"models"`
	Sources       map[string]bool     `yaml:"sources"`
	ManualSources []ManualSource      `yaml:"manual_sources"`
	CacheTTL      map[string]Duration `yaml:"cache_ttl"`
	Timeouts      Timeouts            `yaml:"timeouts"`
	NVD           NVD                 `yaml:"nvd"`
	Listen        string              `yaml:"listen"`
}

// Load reads and validates config.yaml. Unknown top-level keys are rejected so a typo
// fails loudly rather than silently falling back to a zero value.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)

	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config %s is empty", path)
		}
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s:\n%w", path, err)
	}
	return &c, nil
}

// Validate reports every problem it finds at once, rather than stopping at the first.
func (c *Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Models.Resolution) == "" {
		errs = append(errs, errors.New("models.resolution must be set"))
	}
	if strings.TrimSpace(c.Models.Research) == "" {
		errs = append(errs, errors.New("models.research must be set"))
	}

	// Sorted iteration keeps the error message deterministic across runs.
	for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
		if !slices.Contains(knownSources, name) {
			errs = append(errs, fmt.Errorf("sources: unknown source %q (known: %s)",
				name, strings.Join(knownSources, ", ")))
		}
	}

	seen := make(map[string]bool, len(c.ManualSources))
	for i, m := range c.ManualSources {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			errs = append(errs, fmt.Errorf("manual_sources[%d]: name is required", i))
			continue
		}
		if seen[name] {
			errs = append(errs, fmt.Errorf("manual_sources[%d]: duplicate name %q", i, name))
		}
		seen[name] = true
		if slices.Contains(knownSources, name) {
			errs = append(errs, fmt.Errorf(
				"manual_sources[%d]: %q collides with an automated source name", i, name))
		}
	}

	validTTL := slices.Concat(knownSources, nonSourceTTLs)
	for _, name := range slices.Sorted(maps.Keys(c.CacheTTL)) {
		// Manual sources are TTL-exempt (spec §7); a TTL for one is a misunderstanding.
		if seen[name] {
			errs = append(errs, fmt.Errorf(
				"cache_ttl: %q is a manual source and never expires; remove its TTL", name))
			continue
		}
		if !slices.Contains(validTTL, name) {
			errs = append(errs, fmt.Errorf("cache_ttl: unknown key %q (known: %s)",
				name, strings.Join(validTTL, ", ")))
		}
	}

	if c.Timeouts.PerSource <= 0 {
		errs = append(errs, errors.New("timeouts.per_source must be set and positive"))
	}
	if c.Timeouts.Total <= 0 {
		errs = append(errs, errors.New("timeouts.total must be set and positive"))
	}
	if c.Timeouts.PerSource > 0 && c.Timeouts.Total > 0 && c.Timeouts.Total < c.Timeouts.PerSource {
		errs = append(errs, fmt.Errorf("timeouts.total (%s) must be >= timeouts.per_source (%s)",
			c.Timeouts.Total, c.Timeouts.PerSource))
	}
	if c.NVD.ResultsPerCPE <= 0 {
		errs = append(errs, errors.New("nvd.results_per_cpe must be positive"))
	}

	return errors.Join(errs...)
}

// EnabledSources returns the automated sources toggled on, in stable order.
func (c *Config) EnabledSources() []string {
	var out []string
	for _, name := range knownSources {
		if c.Sources[name] {
			out = append(out, name)
		}
	}
	return out
}

// TTL returns the cache lifetime for a source and whether one is configured. Manual
// sources have no TTL by design (spec §7), so ok is false for them.
func (c *Config) TTL(source string) (time.Duration, bool) {
	d, ok := c.CacheTTL[source]
	return d.Duration(), ok
}
