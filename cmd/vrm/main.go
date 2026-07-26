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

	"github.com/aalcar/vrm/internal/config"
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

	// Phase 0 stops here: print the parsed query and confirm the wiring works.
	// Entity resolution, source fan-out and rendering arrive in later phases.
	fmt.Printf("query\n")
	fmt.Printf("  company:   %s\n", company)
	fmt.Printf("  service:   %s\n", *service)
	fmt.Printf("  cache key: %s / %s\n",
		store.NormalizeKey(company), store.NormalizeKey(*service))
	fmt.Printf("\nconfig %s\n", *configPath)
	fmt.Printf("  model:     %s\n", cfg.Model)
	fmt.Printf("  automated: %s\n", strings.Join(cfg.EnabledSources(), ", "))
	fmt.Printf("  manual:    %s\n", strings.Join(manualNames(cfg), ", "))
	fmt.Printf("  optional credentials: NVD=%s CVEDetails=%s\n",
		present(secrets.HasNVDKey()), present(secrets.HasCVEDetailsKey()))
	fmt.Printf("\ndatabase\n  connected, schema up to date\n")
	fmt.Printf("\nno sources are wired up yet (phase 0 — scaffolding).\n")

	return nil
}

func manualNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.ManualSources))
	for _, m := range cfg.ManualSources {
		names = append(names, m.Name)
	}
	return names
}

// present reports credential availability without revealing anything about the value.
func present(ok bool) string {
	if ok {
		return "set"
	}
	return "absent (source will be skipped)"
}
