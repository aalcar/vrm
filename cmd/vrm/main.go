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
	// Wired now, but automated-source caching is Phase 9, so today it has nothing to
	// bypass. What it must never do — clear analyst-supplied manual entries — is already
	// true and already tested, which is the point of adding the flag before the cache.
	noCache := fset.Bool("no-cache", false,
		"re-query automated sources; recorded manual entries are never cleared")
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

	report := assess.New(registerSources(cfg, secrets, st), cfg.Timeouts.PerSource.Duration(),
		assess.WithSourceTimeout(sources.SourceResearch, cfg.Timeouts.Research.Duration())).
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
	fmt.Printf("  manual:    %s\n", strings.Join(manualNames(cfg), ", "))
	fmt.Printf("  optional credentials: NVD=%s\n", present(secrets.HasNVDKey()))
	if *noCache {
		fmt.Printf("  --no-cache: automated sources re-queried; manual entries untouched\n")
	}

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
	fmt.Printf("  packages:  %s\n", orNone(packageNames(ent.Packages)))
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

// packageNames renders packages as ecosystem:name. The ecosystem is shown because the same
// name means different software in different registries.
func packageNames(pkgs []sources.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.String())
	}
	return out
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

// registerSources builds the source list from config. A source toggled off in config.yaml
// is not registered at all, so it produces no section rather than a skipped one.
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

func registerSources(cfg *config.Config, secrets *config.Secrets, st *store.Store) []sources.Source {
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
	if cfg.Sources[sources.SourceOSV] {
		// OSV is free and unauthenticated.
		srcs = append(srcs, sources.NewOSV())
	}
	if cfg.Sources[sources.SourceFedRAMP] {
		// A public listing, read passively. No credential.
		srcs = append(srcs, sources.NewFedRAMP())
	}
	if cfg.Sources[sources.SourceCAAG] {
		srcs = append(srcs, sources.NewCAAG())
	}
	if cfg.Sources[sources.SourceResearch] {
		// The second LLM job, and the only one that runs inside the fan-out. It skips
		// itself when the key is absent rather than failing the assessment.
		srcs = append(srcs, sources.NewResearcher(secrets.AnthropicAPIKey, cfg.Models.Research))
	}
	// Manual sources are not toggled by cfg.Sources: they are checklist categories that
	// must appear in every report, answered or not, so that a category an analyst has yet
	// to check never silently drops off the assessment (spec §3, §7).
	for _, m := range cfg.ManualSources {
		srcs = append(srcs, sources.NewManual(m.Name, m.Instruction, m.URL, st))
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
		if r, ok := s.Data.(sources.OSVResult); ok {
			printOSV(r)
			return
		}
		if r, ok := s.Data.(sources.NVDResult); ok {
			printNVD(r)
			// The per-CVE citations are one line each and would bury everything else;
			// they are on the CVE lines already.
			return
		}
		if r, ok := s.Data.(sources.FedRAMPResult); ok {
			printFedRAMP(r)
			return
		}
		if r, ok := s.Data.(sources.Research); ok {
			printResearch(r)
			return
		}
		if r, ok := s.Data.(sources.CAAGResult); ok {
			printCAAG(r)
			return
		}
		if r, ok := s.Data.(sources.ManualResult); ok {
			// Analyst text, rendered exactly as recorded. Multi-line values are indented so
			// continuations stay inside the section.
			fmt.Printf("    %s\n", strings.ReplaceAll(r.Value, "\n", "\n    "))
			fmt.Printf("    recorded: %s by an analyst (%s)\n",
				r.RecordedAt.Format("2006-01-02"), r.URL)
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

// printFedRAMP renders the authorization section.
//
// Statuses and impact levels keep FedRAMP's own vocabulary: "FedRAMP Certified" is not
// restated as "authorized", and LI-SaaS is not folded into Low.
func printFedRAMP(r sources.FedRAMPResult) {
	if len(r.Offerings) == 0 {
		// Saying how many records were searched is what separates "not on the marketplace"
		// from "we could not read the marketplace".
		fmt.Printf("    no listing for %s (searched %d marketplace records)\n",
			strings.Join(r.Searched, ", "), r.TotalRecords)
		return
	}

	for _, o := range r.Offerings {
		fmt.Printf("    %s — %s\n", o.Offering, o.Status)
		fmt.Printf("      impact: %s", o.ImpactLevel)
		if o.AuthType != "" {
			fmt.Printf("  authorization: %s", o.AuthType)
		}
		if o.AuthCategory != "" {
			fmt.Printf(" (%s)", o.AuthCategory)
		}
		fmt.Println()
		if o.MatchedAlias != "" {
			// Surfaced so a wrong company is caught before its authorization is credited
			// to the vendor actually being assessed.
			fmt.Printf("      matched via alias: %s (listed as %s)\n", o.MatchedAlias, o.Provider)
		}
		fmt.Printf("      %s\n", o.URL)
	}
}

// printResearch renders the checklist.
//
// Every claim is printed with the citation that supports it. Findings the parser dropped
// are printed too: a silently missing answer is indistinguishable from a question nobody
// asked, and the analyst is the one who decides whether a dropped claim is worth chasing.
func printResearch(r sources.Research) {
	fields := []struct {
		label   string
		finding sources.Finding
	}{
		{"supplier", r.SupplierDescription},
		{"service", r.ServiceDescription},
		{"deployment", r.ServiceImplementation},
		{"supplier site", r.SupplierWebsite},
		{"service site", r.ServiceWebsite},
		{"security page", r.SecurityPage},
		{"notifications", r.NotificationPage},
	}
	for _, f := range fields {
		printFinding(f.label, f.finding)
	}

	for _, l := range r.Locations {
		where := l.Country
		if l.City != "" {
			where = l.City + ", " + l.Country
		}
		printFinding(l.Kind, sources.Finding{Value: where, Citations: l.Citations})
	}

	for _, l := range r.CyberLawsuits {
		// Outcome and resolution date are printed because they are the filter: they are how
		// an analyst confirms the entry is a concluded case rather than an allegation.
		printFinding("lawsuit", sources.Finding{
			Value:     fmt.Sprintf("%s — %s (%s)", l.Value, l.Outcome, l.ResolutionDate),
			Citations: l.Citations,
		})
	}
	for _, b := range r.PastBreaches {
		printFinding("breach", b)
	}

	// Tri-state answers are printed verbatim. "no_evidence_found" is not softened to "no":
	// it is the weaker claim on purpose.
	fmt.Printf("    %-14s %s\n", "kaspersky", r.UsedKaspersky)
	printFinding("", r.UsedKasperskyEvidence)
	fmt.Printf("    %-14s %s\n", "moveit", r.MOVEitImpacted)
	printFinding("", r.MOVEitEvidence)

	for _, d := range r.Dropped {
		fmt.Printf("    dropped: %s\n", d)
	}
}

func printFinding(label string, f sources.Finding) {
	if f.Value == "" {
		return
	}
	fmt.Printf("    %-14s %s\n", label, f.Value)
	for _, c := range f.Citations {
		fmt.Printf("      %s\n", c.URL)
	}
}

// printCAAG renders the California breach-notification section.
//
// Entries are listed as filed. No severity, no framing, no narrative — the analyst reads
// the notification and decides what it means (spec §2.7).
func printCAAG(r sources.CAAGResult) {
	if len(r.Entries) == 0 {
		// The qualifier matters: this list covers California only, so an empty result is
		// "nothing reported in California", never "never breached".
		fmt.Printf("    no California-reported breaches for %s\n", strings.Join(r.Searched, ", "))
		return
	}

	for _, e := range r.Entries {
		breached := "n/a"
		if len(e.BreachDates) > 0 {
			breached = strings.Join(e.BreachDates, ", ")
		}
		fmt.Printf("    %s — breached %s, reported %s\n", e.Organization, breached, e.ReportedDate)
		// The filed name often differs from the vendor's; showing both lets an analyst
		// confirm the row belongs to the company under assessment.
		if !strings.EqualFold(e.Organization, e.SearchedAs) {
			fmt.Printf("      found by searching: %s\n", e.SearchedAs)
		}
		fmt.Printf("      %s\n", e.ReportURL)
	}
}

// printOSV renders the OSS advisory section.
//
// Severities keep OSV's own vocabulary — GitHub's MODERATE is not restated as NVD's MEDIUM —
// and no numeric score is shown, because OSV supplies a CVSS vector rather than a score and
// deriving the number would be recomputing a value instead of reporting one.
func printOSV(r sources.OSVResult) {
	for _, q := range r.Queries {
		fmt.Printf("    %s — %d advisories\n", q.Package, q.TotalVulns)
		if q.Truncated {
			fmt.Printf("      (truncated; OSV had more pages than were fetched)\n")
		}
	}

	s := r.Severity
	fmt.Printf("    severity: critical=%d high=%d moderate=%d low=%d unrated=%d\n",
		s.Critical, s.High, s.Moderate, s.Low, s.Unrated)

	for _, v := range r.Vulns {
		severity := v.Severity
		if severity == "" {
			severity = "unrated"
		}
		fmt.Printf("    %-22s %-9s %s\n", v.ID, severity, v.URL)
		// The CVE alias is how an analyst ties this back to the NVD section.
		if len(v.CVEs) > 0 {
			fmt.Printf("      also known as: %s\n", strings.Join(v.CVEs, ", "))
		}
		if v.CVSSVector != "" {
			fmt.Printf("      %s: %s\n", v.CVSSType, v.CVSSVector)
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
