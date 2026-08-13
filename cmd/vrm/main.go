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
	"time"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/config"
	"github.com/aalcar/vrm/internal/report"
	"github.com/aalcar/vrm/internal/sources"
	"github.com/aalcar/vrm/internal/store"
)

// cacheWriteTimeout bounds recording the resolution. Short on purpose: the mapping is already
// in hand, and a slow database must not become a slow assessment.
const cacheWriteTimeout = 5 * time.Second

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

	// The total budget bounds the whole assessment, resolution included — it is one
	// assessment, and a run that spent its time resolving has still spent it. Every
	// per-source deadline derives from this, so they clamp to whatever remains rather than
	// each getting a fresh budget.
	ctx, cancelTotal := context.WithTimeout(ctx, cfg.Timeouts.Total.Duration())
	defer cancelTotal()

	q := sources.Query{Company: company, Service: *service}

	// One NVD, used twice: entity resolution reads its CPE dictionary, then the fan-out
	// queries it for CVEs. They must be the same instance — the rate limiter lives on it, and
	// two limiters sharing NVD's five-requests-per-thirty-seconds budget would earn a 403.
	nvd := newNVD(cfg, secrets)

	resolution, resolutionCached, err := resolve(ctx, cfg, secrets, st, q, *noCache, nvd)
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

	assessment := assess.New(registerSources(cfg, secrets, st, *noCache, nvd), cfg.Timeouts.PerSource.Duration(),
		assess.WithSourceTimeout(sources.SourceResearch, cfg.Timeouts.Research.Duration())).
		Run(ctx, q, ent)

	// After the fan-out, not before: caching the mapping is gated on what NVD made of it.
	if !resolutionCached {
		recordResolution(ctx, cfg, st, q, resolution, assessment, cpesOverridden)
	}

	return report.Render(os.Stdout, report.Report{
		Query:            q,
		Entity:           ent,
		Resolution:       resolution,
		Sections:         assessment.Sections,
		CacheKey:         [2]string{store.NormalizeKey(q.Company), store.NormalizeKey(q.Service)},
		DomainOverridden: overridden,
		CPEsOverridden:   cpesOverridden,
		ResolutionCached: resolutionCached,
		ConfigPath:       *configPath,
		ResolutionModel:  cfg.Models.Resolution,
		ResearchModel:    cfg.Models.Research,
		AutomatedSources: cfg.EnabledSources(),
		ManualSources:    manualNames(cfg),
		NVDKeyPresent:    secrets.HasNVDKey(),
		NoCache:          *noCache,
		Full:             *full,
		Color:            useColor(os.Stdout),
	})
}

// resolve returns the entity mapping, from cache when one is fresh, and reports which it was.
//
// Resolution is cached separately from the sources rather than through the same decorator: it
// is not a Source, it runs before the fan-out, and a failure here is fatal to the run where a
// source failure is not.
func resolve(
	ctx context.Context,
	cfg *config.Config,
	secrets *config.Secrets,
	st *store.Store,
	q sources.Query,
	noCache bool,
	nvd *sources.NVD,
) (sources.Resolution, bool, error) {
	ttl, cacheable := cfg.TTL(sources.ResolutionKey)

	if cacheable && !noCache {
		res, hit, err := st.CachedResolution(ctx, q.Company, q.Service, ttl)
		switch {
		case err != nil:
			// A sick cache costs a slow answer, never no answer.
			warnCache(fmt.Errorf("resolution: %w", err))
		case hit:
			return res, true, nil
		}
	}

	opts := []sources.ResolverOption{}
	if nvd != nil {
		// A typed nil would satisfy the interface and panic on first use, so the check is on
		// the concrete pointer and the option is only added when there is something behind it.
		opts = append(opts, sources.WithCPEDirectory(nvd))
	}
	resolver := sources.NewResolver(secrets.AnthropicAPIKey, cfg.Models.Resolution, opts...)

	resCtx, cancel := context.WithTimeout(ctx, cfg.Timeouts.ResolutionTimeout())
	defer cancel()

	res, err := resolver.Resolve(resCtx, q)
	if err != nil {
		return res, false, err
	}

	return res, false, nil
}

// recordResolution caches a freshly resolved entity, but only once NVD has had its say.
//
// The write waits for the fan-out because the question "are these CPEs real" is answered by
// the source that consumes them, and that answer only exists after it has run. Resolving and
// caching in one step would pin the mapping before anything had checked it — which is how a
// CPE the model invented ends up as the assessment's answer for the next 720h.
func recordResolution(
	ctx context.Context,
	cfg *config.Config,
	st *store.Store,
	q sources.Query,
	res sources.Resolution,
	report *assess.Report,
	cpesOverridden bool,
) {
	if _, cacheable := cfg.TTL(sources.ResolutionKey); !cacheable {
		return
	}
	// The verdict below belongs to the analyst's CPEs, not the model's. Letting an override
	// earn the model's mapping a place in the cache would cache a mapping nothing checked.
	if cpesOverridden || !res.Cacheable() {
		return
	}
	// A verdict of "invented" is the one answer that blocks the write. No verdict — NVD
	// disabled, or unable to answer this run — falls back to the presence rule: an
	// unvalidated CPE that turns out wrong produces a loud failed section on every later
	// run, where an absent one produced a silent skip.
	if verified, known := report.CPEsVerified(); known && !verified {
		return
	}

	// Its own context, for the same reason a source's cache write gets one: the answer is
	// already in hand and must not be lost to the clock that bounded obtaining it.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cacheWriteTimeout)
	defer cancel()

	if err := st.PutResolution(writeCtx, q.Company, q.Service, res); err != nil {
		warnCache(fmt.Errorf("resolution: %w", err))
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
			*source, strings.Join(manualNames(cfg), ", "))
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

// manualNames lists the configured manual sources in config order.
func manualNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.ManualSources))
	for _, m := range cfg.ManualSources {
		names = append(names, m.Name)
	}
	return names
}

// newNVD builds the single NVD instance for this run, or nil when the source is switched off.
//
// Nil rather than an unused instance: with nvd disabled there is nothing to query and nothing
// to check CPEs against, and resolution must be told that rather than handed a client whose
// answers would never be read.
func newNVD(cfg *config.Config, secrets *config.Secrets) *sources.NVD {
	if !cfg.Sources[sources.SourceNVD] {
		return nil
	}
	// The key is optional — it raises NVD's rate limit rather than granting access — so NVD
	// is built whether or not one is present.
	return sources.NewNVD(secrets.NVDAPIKey, sources.WithNVDResultsPerCPE(cfg.NVD.ResultsPerCPE))
}

// registerSources builds the source list from config. A source toggled off in config.yaml is
// not registered at all, so it produces no section rather than a skipped one.
func registerSources(
	cfg *config.Config,
	secrets *config.Secrets,
	st *store.Store,
	noCache bool,
	nvd *sources.NVD,
) []sources.Source {
	// cached wraps an automated source in its configured TTL. A source with no cache_ttl
	// entry comes back unwrapped, so an omitted line means "do not cache" rather than
	// something halfway.
	cached := func(src sources.Source) sources.Source {
		ttl, ok := cfg.TTL(src.Name())
		if !ok {
			return src
		}
		return sources.Caching(src, st, ttl,
			sources.WithCacheBypass(noCache),
			sources.WithCacheWarner(warnCache))
	}

	var srcs []sources.Source
	if cfg.Sources[sources.SourceBitSight] {
		srcs = append(srcs, cached(sources.NewBitSight(secrets.BitsightAPIKey)))
	}
	if nvd != nil {
		// Built by newNVD and already handed to entity resolution, so both uses share one
		// rate limiter. cfg.Sources decided whether it exists at all.
		srcs = append(srcs, cached(nvd))
	}
	if cfg.Sources[sources.SourceOSV] {
		// OSV is free and unauthenticated.
		srcs = append(srcs, cached(sources.NewOSV()))
	}
	if cfg.Sources[sources.SourceFedRAMP] {
		// A public listing, read passively. No credential.
		srcs = append(srcs, cached(sources.NewFedRAMP()))
	}
	if cfg.Sources[sources.SourceCAAG] {
		srcs = append(srcs, cached(sources.NewCAAG()))
	}
	if cfg.Sources[sources.SourceResearch] {
		// The second LLM job, and the only one that runs inside the fan-out. It skips
		// itself when the key is absent rather than failing the assessment.
		srcs = append(srcs, cached(
			sources.NewResearcher(secrets.AnthropicAPIKey, cfg.Models.Research)))
	}
	// Manual sources are never wrapped. They are analyst data read fresh from their own row
	// every run, and they never expire (spec §7).
	//
	// Manual sources are not toggled by cfg.Sources: they are checklist categories that
	// must appear in every report, answered or not, so that a category an analyst has yet
	// to check never silently drops off the assessment (spec §3, §7).
	for _, m := range cfg.ManualSources {
		srcs = append(srcs, sources.NewManual(m.Name, m.Instruction, m.URL, st))
	}
	return srcs
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
