// Command vrm is the CLI front-end for the vendor risk assessment tool.
//
// Kept thin by design (CLAUDE.md): flags, env, wiring. No business logic.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/config"
	"github.com/aalcar/vrm/internal/sources"
	"github.com/aalcar/vrm/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vrm: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load .env if present. Absent in production by design, so a missing file is not an
	// error, and real environment variables always win over it.
	if err := config.LoadDotEnv(config.DotEnvFile); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}

	switch cmd := os.Args[1]; cmd {
	case "assess":
		return runAssess(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vrm — vendor risk assessment

Usage:
  vrm assess "<company>" --service "<service>"

Flags:
  --service string   service or product being assessed (required)
  --domain string    vendor domain, overriding entity resolution
  --cpe string       comma-separated CPEs for NVD, overriding entity resolution
  --config string    path to config file (default "config.yaml")

Secrets come from the environment; copy .env.example to .env to get started.
`)
}

func runAssess(ctx context.Context, args []string) error {
	// stdlib flag stops parsing at the first non-flag argument, so in the documented form
	// `vrm assess "Okta" --service "SSO"` the company would swallow --service entirely.
	// Pull a leading positional off first, then parse what remains.
	var company string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		company, args = args[0], args[1:]
	}

	fset := flag.NewFlagSet("assess", flag.ContinueOnError)
	service := fset.String("service", "", "service or product being assessed (required)")
	configPath := fset.String("config", "config.yaml", "path to config file")
	// Entity resolution is Phase 2, so nothing populates ResolvedEntity yet and BitSight
	// is keyed on domain. This flag bridges the gap; it stays afterwards as an override
	// for when the model resolves a domain wrongly.
	domain := fset.String("domain", "", "vendor domain, overriding entity resolution")
	cpeFlag := fset.String("cpe", "",
		"comma-separated CPEs to query NVD with, overriding entity resolution")
	if err := fset.Parse(args); err != nil {
		return err
	}
	// Also accept the company after the flags: vrm assess --service "SSO" "Okta".
	if company == "" && fset.NArg() > 0 {
		company = fset.Arg(0)
	}

	if strings.TrimSpace(company) == "" {
		return errors.New(`company name is required, e.g. vrm assess "Okta" --service "SSO"`)
	}
	if strings.TrimSpace(*service) == "" {
		return errors.New(`--service is required, e.g. vrm assess "Okta" --service "SSO"`)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	secrets, err := config.LoadSecrets()
	if err != nil {
		return err
	}

	st, err := store.New(ctx, secrets.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		return err
	}

	q := sources.Query{Company: company, Service: *service}

	resolution, err := resolve(ctx, cfg, secrets, q)
	if err != nil {
		// Fatal, unlike a source failure. Every deterministic source keys off the resolved
		// entity, so continuing would produce a report in which everything skipped — and
		// that reads as "nothing to report" rather than "resolution broke".
		return fmt.Errorf("%w\n\nPass --domain to supply the vendor domain and skip resolution", err)
	}

	ent := resolution.Entity
	overridden := strings.TrimSpace(*domain) != ""
	if overridden {
		// Analyst override, so a bad mapping can be corrected without editing code.
		ent.Domains = []string{strings.TrimSpace(*domain)}
	}

	cpesOverridden := strings.TrimSpace(*cpeFlag) != ""
	if cpesOverridden {
		cpes, bad := parseCPEOverrides(*cpeFlag)
		if len(bad) > 0 {
			// Refuse rather than quietly querying fewer CPEs than asked for: a dropped
			// override would look identical to a vendor with nothing to find.
			return fmt.Errorf("--cpe: not a well-formed CPE 2.3 string: %s",
				strings.Join(bad, ", "))
		}
		ent.CPEs = cpes
	}

	report := assess.New(registerSources(cfg, secrets), cfg.Timeouts.PerSource.Duration()).
		Run(ctx, q, ent)

	fmt.Printf("query\n")
	fmt.Printf("  company:   %s\n", q.Company)
	fmt.Printf("  service:   %s\n", q.Service)
	fmt.Printf("  cache key: %s / %s\n",
		store.NormalizeKey(q.Company), store.NormalizeKey(q.Service))

	printEntity(ent, resolution.Dropped, overridden, cpesOverridden)

	fmt.Printf("\nconfig %s\n", *configPath)
	fmt.Printf("  models:    resolution=%s research=%s\n",
		cfg.Models.Resolution, cfg.Models.Research)
	fmt.Printf("  automated: %s\n", strings.Join(cfg.EnabledSources(), ", "))
	fmt.Printf("  optional credentials: NVD=%s CVEDetails=%s\n",
		present(secrets.HasNVDKey()), present(secrets.HasCVEDetailsKey()))

	// Plain output on purpose — the real renderer is Phase 10.
	fmt.Printf("\nsections\n")
	for _, s := range report.Sections {
		printSection(s)
	}

	return nil
}

// resolve runs entity resolution under the per-source timeout.
func resolve(
	ctx context.Context,
	cfg *config.Config,
	secrets *config.Secrets,
	q sources.Query,
) (sources.Resolution, error) {
	resolver := sources.NewResolver(secrets.AnthropicAPIKey, cfg.Models.Resolution)

	resCtx, cancel := context.WithTimeout(ctx, cfg.Timeouts.PerSource.Duration())
	defer cancel()

	return resolver.Resolve(resCtx, q)
}

// printEntity surfaces the resolved entity before any results derived from it.
//
// Entity resolution is the weakest link in the system: a wrong CPE silently returns another
// vendor's CVEs and nothing fails. Showing the mapping — and anything validation threw out —
// is what lets an analyst catch that before acting on it (spec §15).
func printEntity(ent sources.ResolvedEntity, dropped []string, domainOverridden, cpesOverridden bool) {
	fmt.Printf("\nresolved entity\n")
	fmt.Printf("  canonical: %s\n", ent.CanonicalName)
	fmt.Printf("  domains:   %s", orNone(ent.Domains))
	if domainOverridden {
		fmt.Printf("   (overridden by --domain)")
	}
	fmt.Println()
	fmt.Printf("  cpes:      %s", orNone(ent.CPEs))
	if cpesOverridden {
		fmt.Printf("   (overridden by --cpe)")
	}
	fmt.Println()
	fmt.Printf("  packages:  %s\n", orNone(ent.Packages))
	fmt.Printf("  aliases:   %s\n", orNone(ent.Aliases))

	// A silently discarded identifier is indistinguishable from a vendor that genuinely
	// has none, so say what was thrown out and why.
	for _, d := range dropped {
		fmt.Printf("  dropped:   %s\n", d)
	}
}

// parseCPEOverrides splits and validates the --cpe flag, returning the accepted CPEs and
// any entries that were not well-formed.
func parseCPEOverrides(raw string) (accepted, rejected []string) {
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		if cpe, ok := sources.ParseCPEOverride(part); ok {
			accepted = append(accepted, cpe)
		} else {
			rejected = append(rejected, strings.TrimSpace(part))
		}
	}
	return accepted, rejected
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

// registerSources builds the source list from config. A source toggled off in config.yaml
// is not registered at all, so it produces no section rather than a skipped one.
func registerSources(cfg *config.Config, secrets *config.Secrets) []sources.Source {
	var srcs []sources.Source
	if cfg.Sources[sources.SourceBitSight] {
		srcs = append(srcs, sources.NewBitSight(secrets.BitsightAPIKey))
	}
	if cfg.Sources[sources.SourceNVD] {
		// The key is optional — it raises NVD's rate limit rather than granting access —
		// so NVD is registered whether or not one is present.
		srcs = append(srcs, sources.NewNVD(secrets.NVDAPIKey,
			sources.WithNVDResultsPerCPE(cfg.NVD.ResultsPerCPE)))
	}
	return srcs
}

func printSection(s sources.Section) {
	fmt.Printf("  %-14s %s\n", s.Source, s.Status)
	switch s.Status {
	case sources.StatusOK:
		if r, ok := s.Data.(sources.BitSightRating); ok {
			// Deterministic values are interpolated verbatim (spec §2.2).
			fmt.Printf("    rating:   %d (%s) as of %s\n", r.Rating, r.RatingRange, r.RatingDate)
			if r.IndustryMedian != "" {
				fmt.Printf("    vs industry median: %s\n", r.IndustryMedian)
			}
			fmt.Printf("    matched:  %s [%s]\n", r.CompanyName, r.PrimaryDomain)
			if r.Industry != "" {
				fmt.Printf("    industry: %s\n", r.Industry)
			}
			// Surfaced so a wrong match is caught before it informs a decision.
			for _, alt := range r.Alternatives {
				fmt.Printf("    also matched (not used): %s\n", alt)
			}
		}
		if r, ok := s.Data.(sources.NVDResult); ok {
			printNVD(r)
			// The per-CVE citations are one line each and would bury everything else;
			// they are on the CVE lines already.
			return
		}
		for _, c := range s.Citations {
			fmt.Printf("    source:   %s\n", c.URL)
		}
	case sources.StatusSkipped:
		fmt.Printf("    %s\n", s.Note)
	case sources.StatusFailed:
		// Source errors can run to several lines; indent the continuations so the message
		// stays inside its section rather than reading as top-level output.
		fmt.Printf("    error: %s\n", strings.ReplaceAll(s.Err, "\n", "\n    "))
	}
}

// printNVD renders the CVE section. Counts and scores are interpolated verbatim, with no
// judgment about what they mean — that is the analyst's job (spec §2.2, CLAUDE.md).
func printNVD(r sources.NVDResult) {
	for _, q := range r.Queries {
		fmt.Printf("    %s — %d CVEs (%s)\n", q.CPE, q.TotalResults, q.Verification)
		// A CPE NVD has never heard of makes its zero meaningless, so say so here rather
		// than letting it read as a clean result.
		if len(q.KnownProducts) > 0 {
			fmt.Printf("      NVD lists these products for that vendor: %s\n",
				strings.Join(q.KnownProducts, ", "))
		}
	}
	for _, u := range r.Unqueried {
		fmt.Printf("    not queried (rate limit or deadline): %s\n", u)
	}

	s := r.Severity
	fmt.Printf("    severity: critical=%d high=%d medium=%d low=%d unscored=%d\n",
		s.Critical, s.High, s.Medium, s.Low, s.Unscored)

	for _, v := range r.CVEs {
		score := "unscored"
		if v.Severity != "" {
			score = fmt.Sprintf("%.1f %s (CVSS %s)", v.BaseScore, v.Severity, v.CVSSVersion)
		}
		fmt.Printf("    %-16s %-26s %s  %s\n", v.ID, score, v.Published[:10], v.URL)
		if v.ScoreSource != "" && !strings.HasPrefix(v.ScoreSource, "Primary") {
			// A CNA's score is not NVD's own analysis; never let them look alike.
			fmt.Printf("      scored by: %s\n", v.ScoreSource)
		}
	}
}

// present reports credential availability without revealing anything about the value.
func present(ok bool) string {
	if ok {
		return "set"
	}
	return "absent (source will be skipped)"
}
