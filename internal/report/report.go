// Package report renders an assessment for a human reader.
//
// # Why this is not in cmd/vrm
//
// Rendering is the last place data can be lost, and it is the only place a section that
// fetched nothing looks the same as one that fetched everything. It gets its own package so it
// can be tested against golden files rather than by reading a terminal — and so cmd/ stays
// what CLAUDE.md says it is: flags, env, wiring.
//
// # What it may and may not do
//
// It interpolates values verbatim. It does not summarize, rank, translate between one scorer's
// vocabulary and another's, or infer anything a source did not say (spec §2.2, §2.7). The one
// judgment it makes is about presentation: which of a source's own facts to show, and in what
// order. Where a value would read as a stronger claim than the source supports — an unverified
// zero, an empty California list — the qualifier is part of the line, not an optional extra.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/aalcar/vrm/internal/sources"
)

// Report is everything the renderer needs, gathered by the caller.
//
// Config is flattened into plain strings on purpose: rendering has no business reading a
// config file, and a report assembled from a database row or an HTTP form in a later phase
// must be able to fill this in without one.
type Report struct {
	Query      sources.Query
	Entity     sources.ResolvedEntity
	Resolution sources.Resolution
	Sections   []sources.Section

	// CacheKey is the normalized (company, service) the cache actually used. Shown because a
	// vendor entered two ways is one row, and an analyst who cannot see that would read a
	// cache hit as a coincidence.
	CacheKey [2]string

	DomainOverridden bool
	CPEsOverridden   bool
	ResolutionCached bool

	ConfigPath       string
	ResolutionModel  string
	ResearchModel    string
	AutomatedSources []string
	ManualSources    []string
	NVDKeyPresent    bool
	NoCache          bool

	// Full prints every detail row instead of capping the long lists. A vendor with six CPEs
	// can carry 120 CVEs, which buries the summary and the sections under it; the cap keeps
	// the report readable, and this is how an analyst gets the rest.
	Full bool

	// Color emits ANSI escapes. The caller decides — the renderer has no business knowing
	// whether its writer is a terminal, and a report piped to a file or a diff must never
	// carry escapes. Off is always a correct answer; the report is designed to be legible
	// without it, and nothing is encoded in color alone.
	Color bool
}

// # What gets color, and what deliberately does not
//
// Only the tool's own state: a source's outcome, and the (cached) marker. Never the vendor
// data. Painting a CRITICAL red would be this tool making a severity claim in its own
// vocabulary on top of the one NVD already made — the visual equivalent of restating MODERATE
// as MEDIUM, and the analyst's judgment to make rather than ours (spec §2.7).
//
// Every label is also complete text on its own. Color is emphasis on something already said,
// never the only place something is said, so a plain-text report loses nothing.
const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
)

// outcomeColor is the escape for each outcome. Absent means uncolored.
var outcomeColor = map[Outcome]string{
	OutcomeOK:         ansiGreen,
	OutcomeFailed:     ansiRed,
	OutcomeUnanswered: ansiYellow,
	OutcomeAwaiting:   ansiCyan,
}

// detailCap bounds how many rows of one list are printed.
//
// The lists it applies to are sorted worst-first by their own source, so the cap keeps the
// entries most likely to matter — but that is a property of the ordering, not a judgment made
// here. Anything held back is counted on its own line: a silently truncated list reads as a
// complete one, which is the same failure as a silently dropped identifier.
const detailCap = 10

// Render writes the whole report to w.
//
// A write error is returned rather than ignored: a report truncated by a broken pipe is a
// partial answer, and the caller decides what that is worth.
func Render(w io.Writer, r Report) error {
	p := &printer{w: w, full: r.Full, color: r.Color}

	p.printf("query\n")
	p.printf("  company:   %s\n", r.Query.Company)
	p.printf("  service:   %s\n", r.Query.Service)
	p.printf("  cache key: %s / %s\n", r.CacheKey[0], r.CacheKey[1])

	p.entity(r)
	p.config(r)
	p.summary(r.Summarize())

	p.printf("\nsections\n")
	for _, row := range r.Rows() {
		p.section(row.Section, row.Outcome)
	}

	return p.err
}

// outcome is what a section is called in the report.
//
// There are four of these and only three Statuses, because StatusSkipped means two unrelated
// things: an automated source with nothing to query, and a checklist category waiting on an
// analyst. The first is a gap in the data and the second is a task. Rendering both as
// "skipped" makes an analyst read every note to find the ones addressed to them.
//
// The distinction is drawn here rather than by adding a fourth Status. A source does not know
// whether it is manual — that is a config fact, held by the caller — and the orchestrator has
// no reason to learn it. Nothing downstream of Status changes; only the label does.
//
// Exported, along with Rows and Summarize, so the web templates label a section exactly as the
// terminal does. Two renderers that each decide what a skip means would eventually disagree,
// and an analyst comparing a browser tab against a terminal is the last person who should be
// the one to discover it.
type Outcome string

const (
	OutcomeOK Outcome = "ok"
	// OutcomeUnanswered is an automated source that produced nothing. Deliberately not
	// "not applicable" or "not queried": the skips behind it range from "this vendor
	// publishes no packages" through "the API key is absent" to "BitSight has no company at
	// that domain", and only the note can say which. The label claims no more than that the
	// category has no answer.
	OutcomeUnanswered Outcome = "unanswered"
	OutcomeAwaiting   Outcome = "awaiting manual check"
	OutcomeFailed     Outcome = "failed"
)

// Slug is a CSS- and attribute-safe form of the outcome, for a renderer that styles by class
// rather than by escape code.
func (o Outcome) Slug() string {
	if o == OutcomeAwaiting {
		return "awaiting"
	}
	return string(o)
}

// Row is one section paired with the label it renders under.
type Row struct {
	Section sources.Section
	Outcome Outcome
}

// Rows pairs every section with its outcome, in report order.
func (r Report) Rows() []Row {
	manual := make(map[string]bool, len(r.ManualSources))
	for _, m := range r.ManualSources {
		manual[m] = true
	}
	rows := make([]Row, 0, len(r.Sections))
	for _, s := range r.Sections {
		rows = append(rows, Row{Section: s, Outcome: outcomeOf(s, manual)})
	}
	return rows
}

// Summary is the at-a-glance state of an assessment: how many categories landed in each
// outcome, and which sources those were.
type Summary struct {
	Total      int
	OK         []string
	Failed     []string
	Unanswered []string
	Awaiting   []string
}

// Summarize buckets the sections by outcome.
func (r Report) Summarize() Summary {
	s := Summary{Total: len(r.Sections)}
	for _, row := range r.Rows() {
		switch row.Outcome {
		case OutcomeFailed:
			s.Failed = append(s.Failed, row.Section.Source)
		case OutcomeUnanswered:
			s.Unanswered = append(s.Unanswered, row.Section.Source)
		case OutcomeAwaiting:
			s.Awaiting = append(s.Awaiting, row.Section.Source)
		default:
			s.OK = append(s.OK, row.Section.Source)
		}
	}
	return s
}

func outcomeOf(s sources.Section, manual map[string]bool) Outcome {
	switch s.Status {
	case sources.StatusFailed:
		return OutcomeFailed
	case sources.StatusSkipped:
		if manual[s.Source] {
			return OutcomeAwaiting
		}
		return OutcomeUnanswered
	default:
		return OutcomeOK
	}
}

// summary is the at-a-glance answer to "what state is this assessment in".
//
// Spec §13 asks that a non-author analyst be able to tell which categories are answered, which
// failed, and which await a manual check without reading the whole report. Every bucket but
// "answered" is listed by name, because a category that produced nothing is the one an analyst
// is most likely to miss and the one that most changes what the report means. A bucket with
// nothing in it prints no line: an assessment with no problems should look like one.
func (p *printer) summary(s Summary) {
	p.printf("\nsummary\n")
	p.printf("  %d %s: %d answered, %d failed, %d unanswered, %d awaiting a manual check\n",
		s.Total, plural(s.Total, "category", "categories"),
		len(s.OK), len(s.Failed), len(s.Unanswered), len(s.Awaiting))

	for _, row := range []struct {
		label   string
		outcome Outcome
		names   []string
	}{
		{"failed", OutcomeFailed, s.Failed},
		{"unanswered", OutcomeUnanswered, s.Unanswered},
		{"awaiting", OutcomeAwaiting, s.Awaiting},
	} {
		if len(row.names) > 0 {
			// Padded before painting: the escape is zero-width on screen but not to %-11s.
			label := fmt.Sprintf("%-11s", row.label+":")
			p.printf("  %s %s\n", p.paint(label, outcomeColor[row.outcome]), strings.Join(row.names, ", "))
		}
	}
}

// printer accumulates the first write error instead of returning one from every call. The
// alternative is an error check after each of a hundred lines, which is where a missed one
// hides.
type printer struct {
	w     io.Writer
	full  bool
	color bool
	err   error
}

// paint wraps s in an escape, or returns it unchanged when color is off.
//
// It never pads: an escape is zero-width on screen but counts toward a %-14s width, so a
// colored string put through a padded verb comes out misaligned. Callers pad first, then paint.
func (p *printer) paint(s, code string) string {
	if !p.color || code == "" {
		return s
	}
	return code + s + ansiReset
}

func (p *printer) printf(format string, a ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, a...)
}

// capped returns the rows to print and the number held back, which the caller announces with
// held once it has finished printing them.
func capped[T any](full bool, rows []T) (shown []T, held int) {
	if full || len(rows) <= detailCap {
		return rows, 0
	}
	return rows[:detailCap], len(rows) - detailCap
}

// held announces a truncated tail, and names the flag that shows it.
//
// The tail is announced rather than dropped: a list that ends without saying it was cut reads
// as the whole answer, which is the same class of error as an identifier discarded without a
// word — indistinguishable from one that never existed.
func (p *printer) held(n int) {
	if n == 0 {
		return
	}
	p.printf("    … +%d more (use --full)\n", n)
}

// entity surfaces the resolved entity before any results derived from it.
//
// Entity resolution is the weakest link in the system: a wrong CPE silently returns another
// vendor's CVEs and nothing fails. Showing the mapping — and anything validation threw out —
// is what lets an analyst catch that before acting on it (spec §15).
func (p *printer) entity(r Report) {
	p.printf("\nresolved entity\n")
	if r.ResolutionCached {
		// Worth saying: a cached mapping was not re-derived this run, so a model that would
		// resolve this vendor differently today has not been consulted.
		p.printf("  (cached; --no-cache re-resolves)\n")
	}
	p.printf("  canonical: %s\n", r.Entity.CanonicalName)

	p.printf("  domains:   %s", orNone(r.Entity.Domains))
	if r.DomainOverridden {
		p.printf("   (overridden by --domain)")
	}
	p.printf("\n")

	p.printf("  cpes:      %s", orNone(r.Entity.CPEs))
	if r.CPEsOverridden {
		p.printf("   (overridden by --cpe)")
	}
	p.printf("\n")

	// How the CPEs were arrived at, printed under them. A CPE NVD's dictionary confirmed and
	// one nothing checked look identical on the line above, and they are not the same claim.
	// An override supersedes it: what the model proposed is no longer what will be queried.
	if r.Resolution.CPEOrigin != "" && !r.CPEsOverridden {
		p.printf("             %s\n", r.Resolution.CPEOrigin)
	}

	p.printf("  packages:  %s\n", orNone(packageNames(r.Entity.Packages)))
	p.printf("  aliases:   %s\n", orNone(r.Entity.Aliases))

	// A silently discarded identifier is indistinguishable from a vendor that genuinely has
	// none, so say what was thrown out and why.
	for _, d := range r.Resolution.Dropped {
		p.printf("  dropped:   %s\n", d)
	}
}

// config records what produced this report. An assessment read a week later is only
// interpretable if the sources that were switched off are visible.
func (p *printer) config(r Report) {
	p.printf("\nconfig %s\n", r.ConfigPath)
	p.printf("  models:    resolution=%s research=%s\n", r.ResolutionModel, r.ResearchModel)
	p.printf("  automated: %s\n", strings.Join(r.AutomatedSources, ", "))
	p.printf("  manual:    %s\n", strings.Join(r.ManualSources, ", "))
	p.printf("  optional credentials: NVD=%s\n", present(r.NVDKeyPresent))
	if r.NoCache {
		p.printf("  --no-cache: automated sources re-queried; manual entries untouched\n")
	}
}

func (p *printer) section(s sources.Section, o Outcome) {
	status := p.paint(string(o), outcomeColor[o])
	if s.Cached {
		// The marker only. Spec §11 makes fetched_at internal bookkeeping and says not to
		// surface it as report content, so the age is not shown alongside it.
		status += p.paint(" (cached)", ansiDim)
	}
	p.printf("  %-14s %s\n", s.Source, status)

	switch s.Status {
	case sources.StatusOK:
		p.data(s)
	case sources.StatusSkipped:
		p.printf("    %s\n", s.Note)
	case sources.StatusFailed:
		// Source errors can run to several lines; indent the continuations so the message
		// stays inside its section rather than reading as top-level output.
		p.printf("    error: %s\n", strings.ReplaceAll(s.Err, "\n", "\n    "))
	}
}

// data renders one successful section's payload.
//
// The type switch is why Section.Data must come back from the cache as its concrete type: a
// map matches no case here, and the section renders as a heading with nothing under it.
func (p *printer) data(s sources.Section) {
	switch r := s.Data.(type) {
	case sources.BitSightRating:
		p.bitsight(r)
	case sources.NVDResult:
		// The per-CVE citations are one line each and would bury everything else; they are on
		// the CVE lines already.
		p.nvd(r)
		return
	case sources.OSVResult:
		p.osv(r)
		return
	case sources.FedRAMPResult:
		p.fedramp(r)
		return
	case sources.CAAGResult:
		p.caag(r)
		return
	case sources.Research:
		p.research(r)
		return
	case sources.ManualResult:
		// Analyst text, rendered exactly as recorded. Multi-line values are indented so
		// continuations stay inside the section.
		p.printf("    %s\n", strings.ReplaceAll(r.Value, "\n", "\n    "))
		p.printf("    recorded: %s by an analyst (%s)\n",
			r.RecordedAt.Format("2006-01-02"), r.URL)
		return
	}

	for _, c := range s.Citations {
		p.printf("    source:   %s\n", c.URL)
	}
}

func (p *printer) bitsight(r sources.BitSightRating) {
	// Deterministic values are interpolated verbatim (spec §2.2).
	p.printf("    rating:   %d (%s) as of %s\n", r.Rating, r.RatingRange, r.RatingDate)
	if r.IndustryMedian != "" {
		p.printf("    vs industry median: %s\n", r.IndustryMedian)
	}
	p.printf("    matched:  %s [%s]\n", r.CompanyName, r.PrimaryDomain)
	if r.Industry != "" {
		p.printf("    industry: %s\n", r.Industry)
	}
	// Surfaced so a wrong match is caught before it informs a decision.
	alternatives, held := capped(p.full, r.Alternatives)
	for _, alt := range alternatives {
		p.printf("    also matched (not used): %s\n", alt)
	}
	p.held(held)
}

// nvd renders the CVE section. Counts and scores are interpolated verbatim, with no judgment
// about what they mean — that is the analyst's job (spec §2.2, CLAUDE.md).
func (p *printer) nvd(r sources.NVDResult) {
	for _, q := range r.Queries {
		p.printf("    %s — %d CVEs (%s)\n", q.CPE, q.TotalResults, q.Verification)
		// A CPE NVD has never heard of makes its zero meaningless, so say so here rather than
		// letting it read as a clean result.
		if len(q.KnownProducts) > 0 {
			p.printf("      NVD lists these products for that vendor: %s\n",
				strings.Join(q.KnownProducts, ", "))
		}
	}
	for _, u := range r.Unqueried {
		p.printf("    not queried (rate limit or deadline): %s\n", u)
	}

	s := r.Severity
	p.printf("    severity: critical=%d high=%d medium=%d low=%d unscored=%d\n",
		s.Critical, s.High, s.Medium, s.Low, s.Unscored)

	// The counts above are over every CVE; only the listing below is capped. A vendor with six
	// CPEs can carry 120 of these, and the severity line is the part an analyst reads first.
	cves, held := capped(p.full, r.CVEs)
	for _, v := range cves {
		score := "unscored"
		if v.Severity != "" {
			score = fmt.Sprintf("%.1f %s (CVSS %s)", v.BaseScore, v.Severity, v.CVSSVersion)
		}
		p.printf("    %-16s %-26s %s  %s\n", v.ID, score, v.Published[:10], v.URL)
		if v.ScoreSource != "" && !strings.HasPrefix(v.ScoreSource, "Primary") {
			// A CNA's score is not NVD's own analysis; never let them look alike.
			p.printf("      scored by: %s\n", v.ScoreSource)
		}
	}
	p.held(held)
}

// osv renders the OSS advisory section.
//
// Severities keep OSV's own vocabulary — GitHub's MODERATE is not restated as NVD's MEDIUM —
// and no numeric score is shown, because OSV supplies a CVSS vector rather than a score and
// deriving the number would be recomputing a value instead of reporting one.
func (p *printer) osv(r sources.OSVResult) {
	for _, q := range r.Queries {
		p.printf("    %s — %d advisories\n", q.Package, q.TotalVulns)
		if q.Truncated {
			p.printf("      (truncated; OSV had more pages than were fetched)\n")
		}
	}

	s := r.Severity
	p.printf("    severity: critical=%d high=%d moderate=%d low=%d unrated=%d\n",
		s.Critical, s.High, s.Moderate, s.Low, s.Unrated)

	vulns, held := capped(p.full, r.Vulns)
	for _, v := range vulns {
		severity := v.Severity
		if severity == "" {
			severity = "unrated"
		}
		p.printf("    %-22s %-9s %s\n", v.ID, severity, v.URL)
		// The CVE alias is how an analyst ties this back to the NVD section.
		if len(v.CVEs) > 0 {
			p.printf("      also known as: %s\n", strings.Join(v.CVEs, ", "))
		}
		if v.CVSSVector != "" {
			p.printf("      %s: %s\n", v.CVSSType, v.CVSSVector)
		}
	}
	p.held(held)
}

// fedramp renders the authorization section.
//
// Statuses and impact levels keep FedRAMP's own vocabulary: "FedRAMP Certified" is not
// restated as "authorized", and LI-SaaS is not folded into Low.
func (p *printer) fedramp(r sources.FedRAMPResult) {
	if len(r.Offerings) == 0 {
		// Saying how many records were searched is what separates "not on the marketplace"
		// from "we could not read the marketplace".
		p.printf("    no listing for %s (searched %d marketplace records)\n",
			strings.Join(r.Searched, ", "), r.TotalRecords)
		return
	}

	for _, o := range r.Offerings {
		p.printf("    %s — %s\n", o.Offering, o.Status)
		p.printf("      impact: %s", o.ImpactLevel)
		if o.AuthType != "" {
			p.printf("  authorization: %s", o.AuthType)
		}
		if o.AuthCategory != "" {
			p.printf(" (%s)", o.AuthCategory)
		}
		p.printf("\n")
		if o.MatchedAlias != "" {
			// Surfaced so a wrong company is caught before its authorization is credited to
			// the vendor actually being assessed.
			p.printf("      matched via alias: %s (listed as %s)\n", o.MatchedAlias, o.Provider)
		}
		p.printf("      %s\n", o.URL)
	}
}

// caag renders the California breach-notification section.
//
// Entries are listed as filed. No severity, no framing, no narrative — the analyst reads the
// notification and decides what it means (spec §2.7).
func (p *printer) caag(r sources.CAAGResult) {
	if len(r.Entries) == 0 {
		// The qualifier matters: this list covers California only, so an empty result is
		// "nothing reported in California", never "never breached".
		p.printf("    no California-reported breaches for %s\n", strings.Join(r.Searched, ", "))
		return
	}

	entries, held := capped(p.full, r.Entries)
	for _, e := range entries {
		breached := "n/a"
		if len(e.BreachDates) > 0 {
			breached = strings.Join(e.BreachDates, ", ")
		}
		p.printf("    %s — breached %s, reported %s\n", e.Organization, breached, e.ReportedDate)
		// The filed name often differs from the vendor's; showing both lets an analyst confirm
		// the row belongs to the company under assessment.
		if !strings.EqualFold(e.Organization, e.SearchedAs) {
			p.printf("      found by searching: %s\n", e.SearchedAs)
		}
		p.printf("      %s\n", e.ReportURL)
	}
	p.held(held)
}

// research renders the checklist.
//
// Every claim is printed with the citation that supports it. Findings the parser dropped are
// printed too: a silently missing answer is indistinguishable from a question nobody asked,
// and the analyst is the one who decides whether a dropped claim is worth chasing.
func (p *printer) research(r sources.Research) {
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
		p.finding(f.label, f.finding)
	}

	for _, l := range r.Locations {
		where := l.Country
		if l.City != "" {
			where = l.City + ", " + l.Country
		}
		p.finding(l.Kind, sources.Finding{Value: where, Citations: l.Citations})
	}

	for _, l := range r.CyberLawsuits {
		// Outcome and resolution date are printed because they are the filter: they are how an
		// analyst confirms the entry is a concluded case rather than an allegation.
		p.finding("lawsuit", sources.Finding{
			Value:     fmt.Sprintf("%s — %s (%s)", l.Value, l.Outcome, l.ResolutionDate),
			Citations: l.Citations,
		})
	}
	for _, b := range r.PastBreaches {
		p.finding("breach", b)
	}

	// Tri-state answers are printed verbatim. "no_evidence_found" is not softened to "no": it
	// is the weaker claim on purpose.
	p.printf("    %-14s %s\n", "kaspersky", r.UsedKaspersky)
	p.finding("", r.UsedKasperskyEvidence)
	p.printf("    %-14s %s\n", "moveit", r.MOVEitImpacted)
	p.finding("", r.MOVEitEvidence)

	for _, d := range r.Dropped {
		p.printf("    dropped: %s\n", d)
	}
}

func (p *printer) finding(label string, f sources.Finding) {
	if f.Value == "" {
		return
	}
	p.printf("    %-14s %s\n", label, f.Value)
	for _, c := range f.Citations {
		p.printf("      %s\n", c.URL)
	}
}

// PackageNames renders the entity's packages as ecosystem:name, for a renderer that cannot
// call a package-level function.
func (r Report) PackageNames() []string { return packageNames(r.Entity.Packages) }

// packageNames renders packages as ecosystem:name. The ecosystem is shown because the same
// name means different software in different registries.
func packageNames(pkgs []sources.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.String())
	}
	return out
}

// orNone keeps an empty list from rendering as a blank, which reads as a missing line rather
// than as an answer.
func orNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// present reports credential availability without revealing anything about the value.
func present(ok bool) string {
	if ok {
		return "set"
	}
	return "absent (source will be skipped)"
}
