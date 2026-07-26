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
	domain := fset.String("domain", "", "vendor domain (until Phase 2 resolves it automatically)")
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
	// Phase 2 replaces this with LLM entity resolution.
	ent := sources.ResolvedEntity{CanonicalName: company}
	if d := strings.TrimSpace(*domain); d != "" {
		ent.Domains = []string{d}
	}

	report := assess.New(registerSources(cfg, secrets), cfg.Timeouts.PerSource.Duration()).
		Run(ctx, q, ent)

	fmt.Printf("query\n")
	fmt.Printf("  company:   %s\n", q.Company)
	fmt.Printf("  service:   %s\n", q.Service)
	fmt.Printf("  cache key: %s / %s\n",
		store.NormalizeKey(q.Company), store.NormalizeKey(q.Service))
	if len(ent.Domains) > 0 {
		fmt.Printf("  domains:   %s\n", strings.Join(ent.Domains, ", "))
	}
	fmt.Printf("\nconfig %s\n", *configPath)
	fmt.Printf("  model:     %s\n", cfg.Model)
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

// registerSources builds the source list from config. A source toggled off in config.yaml
// is not registered at all, so it produces no section rather than a skipped one.
func registerSources(cfg *config.Config, secrets *config.Secrets) []sources.Source {
	var srcs []sources.Source
	if cfg.Sources[sources.SourceBitSight] {
		srcs = append(srcs, sources.NewBitSight(secrets.BitsightAPIKey))
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
		for _, c := range s.Citations {
			fmt.Printf("    source:   %s\n", c.URL)
		}
	case sources.StatusSkipped:
		fmt.Printf("    %s\n", s.Note)
	case sources.StatusFailed:
		fmt.Printf("    error: %s\n", s.Err)
	}
}

// present reports credential availability without revealing anything about the value.
func present(ok bool) string {
	if ok {
		return "set"
	}
	return "absent (source will be skipped)"
}
