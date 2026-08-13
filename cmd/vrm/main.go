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
	"slices"
	"strings"
	"syscall"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/config"
	"github.com/aalcar/vrm/internal/report"
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
	case "set":
		return runSet(ctx, os.Args[2:])
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
  vrm set    "<company>" --service "<service>" --source <name> --value "<text>"

assess flags:
  --service string   service or product being assessed (required)
  --domain string    vendor domain, overriding entity resolution
  --cpe string       comma-separated CPEs for NVD, overriding entity resolution
  --no-cache         re-query automated sources; analyst entries are never cleared
  --full             print every detail row instead of capping the long lists
  --config string    path to config file (default "config.yaml")

set flags:
  --service string   service or product being assessed (required)
  --source string    manual source to record against (required)
  --value string     the recorded answer, stored verbatim (required)
  --config string    path to config file (default "config.yaml")

Secrets come from the environment; copy .env.example to .env to get started.
`)
}

// splitCompany pulls a leading positional argument off the front.
//
// stdlib flag stops parsing at the first non-flag argument, so in the documented form
// `vrm assess "Okta" --service "SSO"` the company would swallow --service entirely.
func splitCompany(args []string) (company string, rest []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func runAssess(ctx context.Context, args []string) error {
	company, args := splitCompany(args)

	fset := flag.NewFlagSet("assess", flag.ContinueOnError)
	service := fset.String("service", "", "service or product being assessed (required)")
	configPath := fset.String("config", "config.yaml", "path to config file")
	// Entity resolution is Phase 2, so nothing populates ResolvedEntity yet and BitSight
	// is keyed on domain. This flag bridges the gap; it stays afterwards as an override
	// for when the model resolves a domain wrongly.
	domain := fset.String("domain", "", "vendor domain, overriding entity resolution")
	cpeFlag := fset.String("cpe", "",
		"comma-separated CPEs to query NVD with, overriding entity resolution")
	// Skips the cache read for every automated source and for resolution, then records what
	// it fetched — forcing a fresh call is the point, leaving yesterday's row behind is not.
	// It clears nothing, so an analyst's manual entries cannot be caught up in it (spec §11).
	noCache := fset.Bool("no-cache", false,
		"re-query automated sources; recorded manual entries are never cleared")
	// Rendering only. Nothing is fetched differently — the long lists are simply printed in
	// full rather than capped, and a capped list always says how many it held back.
	full := fset.Bool("full", false, "print every detail row instead of capping the long lists")
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

	cpes, bad := parseCPEOverrides(*cpeFlag)
	if len(bad) > 0 {
		// Refuse rather than quietly querying fewer CPEs than asked for: a dropped override
		// would look identical to a vendor with nothing to find.
		return fmt.Errorf("--cpe: not a well-formed CPE 2.3 string: %s", strings.Join(bad, ", "))
	}

	runner := assess.NewRunner(cfg, secrets, st, assess.WithWarner(warnCache))
	result, err := runner.Run(ctx, assess.Request{
		Query:   sources.Query{Company: company, Service: *service},
		Domain:  *domain,
		CPEs:    cpes,
		NoCache: *noCache,
	})
	if err != nil {
		return fmt.Errorf("%w\n\nPass --domain to supply the vendor domain and skip resolution", err)
	}

	return report.Render(os.Stdout, report.FromResult(result, runner, report.Presentation{
		ConfigPath: *configPath,
		Full:       *full,
		Color:      useColor(os.Stdout),
	}))
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

// runSet records an analyst's answer for one manual source (spec §7).
func runSet(ctx context.Context, args []string) error {
	company, args := splitCompany(args)

	fset := flag.NewFlagSet("set", flag.ContinueOnError)
	service := fset.String("service", "", "service or product being assessed (required)")
	source := fset.String("source", "", "manual source to record against (required)")
	value := fset.String("value", "", "the recorded answer, stored verbatim (required)")
	configPath := fset.String("config", "config.yaml", "path to config file")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if company == "" && fset.NArg() > 0 {
		company = fset.Arg(0)
	}

	if strings.TrimSpace(company) == "" {
		return errors.New(`company name is required, e.g. vrm set "Okta" --service "SSO" --source ssllabs --value "A+"`)
	}
	if strings.TrimSpace(*service) == "" {
		return errors.New("--service is required")
	}
	if strings.TrimSpace(*source) == "" {
		return errors.New("--source is required")
	}
	// An empty value is almost certainly a shell quoting mistake, and recording one would
	// look identical to an answered check.
	if *value == "" {
		return errors.New("--value is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	// Naming a source that does not exist would write a row nothing ever reads, so it fails
	// here with the valid names rather than appearing to succeed.
	if !slices.ContainsFunc(cfg.ManualSources, func(m config.ManualSource) bool {
		return m.Name == *source
	}) {
		return fmt.Errorf("unknown manual source %q; configured manual sources are: %s",
			*source, strings.Join(cfg.ManualNames(), ", "))
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

	if err := st.SetManual(ctx, company, *service, *source, *value); err != nil {
		return err
	}

	fmt.Printf("recorded %s for %s / %s\n",
		*source, store.NormalizeKey(company), store.NormalizeKey(*service))
	fmt.Printf("  %s\n", *value)
	return nil
}

// useColor reports whether to emit ANSI escapes.
//
// Two conditions, both required. NO_COLOR is honoured on presence rather than value, per the
// convention at no-color.org — an analyst who has set it once should never have to set it
// again per tool. And the escapes are only worth emitting to a character device: a report
// redirected to a file or piped into a diff would otherwise carry sequences that show up as
// noise in exactly the place someone is trying to read a difference.
//
// Detected from the file's mode rather than through golang.org/x/term, which would be a
// dependency for one bit of information the standard library already has.
func useColor(f *os.File) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		// Unknowable, so assume not a terminal: a missing color is invisible, where an
		// unwanted escape corrupts a file.
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// warnCache reports cache trouble without failing anything.
//
// A cache that has quietly stopped working looks exactly like one that is working — the
// assessment is simply slower and nobody knows why. This goes to stderr so it stays out of
// the report while still being impossible to miss.
func warnCache(err error) {
	fmt.Fprintf(os.Stderr, "vrm: cache: %v\n", err)
}
