// Package web serves the assessment as HTML: a form, and a report HTMX swaps in.
//
// # Everything here is externally sourced text
//
// Vendor APIs, two scraped pages, and a language model. So the templates are html/template and
// never text/template (spec §4), and nothing is ever wrapped in template.HTML — a value with
// newlines is handled with CSS, because the one thing that makes any of this safe to display
// is the escaping that template.HTML switches off.
//
// # It renders the same report the terminal does
//
// Outcome labels, the summary buckets, the cache markers and the detail caps all come from
// internal/report, which owns those decisions once. A second renderer that decided for itself
// what a skip meant would eventually disagree with the first, and an analyst comparing a
// browser tab against a terminal is the last person who should discover that.
package web

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/report"
	"github.com/aalcar/vrm/internal/sources"
)

//go:embed templates/*.html templates/*.css templates/partials/*.html
var templateFS embed.FS

// Server is the HTTP front-end over one assessment pipeline.
type Server struct {
	runner     *assess.Runner
	tmpl       *template.Template
	configPath string
	log        *slog.Logger
}

// Option configures a Server.
type Option func(*Server)

// WithLogger sets the logger. Requests are logged; values from the form are not, because the
// same handler that takes a company name would take anything typed into it.
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) { s.log = l }
}

// New builds the server and parses the templates.
//
// Parsing happens once, at startup, so a broken template fails the process rather than the
// first analyst to submit the form.
func New(runner *assess.Runner, configPath string, opts ...Option) (*Server, error) {
	s := &Server{runner: runner, configPath: configPath, log: slog.Default()}
	for _, opt := range opts {
		opt(s)
	}

	tmpl, err := template.New("vrm").Funcs(funcs()).ParseFS(templateFS,
		"templates/*.html", "templates/*.css", "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s.tmpl = tmpl
	return s, nil
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.form)
	mux.HandleFunc("POST /assess", s.assess)
	return mux
}

func (s *Server) form(w http.ResponseWriter, r *http.Request) {
	s.render(w, "form.html", nil)
}

// assess runs one assessment and returns the report fragment.
//
// It blocks for as long as the assessment takes — up to timeouts.total, 360s by default.
// Phase 12 streams sections as they land; until then the indicator in the form is the only
// thing telling an analyst the request is alive, and the server's WriteTimeout has to exceed
// the assessment budget or the response is cut off mid-report.
func (s *Server) assess(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, errors.New("could not read the form"))
		return
	}

	cpes, bad := parseCPEs(r.FormValue("cpe"))
	if len(bad) > 0 {
		// Refuse rather than quietly querying fewer CPEs than asked for: a dropped override
		// would look identical to a vendor with nothing to find.
		s.fail(w, fmt.Errorf("not a well-formed CPE 2.3 string: %s", strings.Join(bad, ", ")))
		return
	}

	req := assess.Request{
		Query: sources.Query{
			Company: strings.TrimSpace(r.FormValue("company")),
			Service: strings.TrimSpace(r.FormValue("service")),
		},
		Domain:  strings.TrimSpace(r.FormValue("domain")),
		CPEs:    cpes,
		NoCache: r.FormValue("no_cache") != "",
	}

	started := time.Now()
	result, err := s.runner.Run(r.Context(), req)
	if err != nil {
		// A resolution failure is fatal to the run, unlike a source failure: every
		// deterministic source keys off the resolved entity, so continuing would produce a
		// report in which everything skipped — which reads as "nothing to report" rather than
		// "resolution broke".
		s.log.Error("assessment failed", "err", err, "took", time.Since(started))
		s.fail(w, err)
		return
	}
	s.log.Info("assessed", "sections", len(result.Report.Sections), "took", time.Since(started))

	s.render(w, "report.html", report.FromResult(result, s.runner, report.Presentation{
		ConfigPath: s.configPath,
		// The browser scrolls, so nothing is capped. The caps exist to keep a terminal
		// readable, and a <details> would hide exactly the rows an analyst scrolled to find.
		Full: true,
	}))
}

// render writes one template, or reports the failure loudly.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Buffered, so a template that fails halfway does not leave a half-written page that
	// reads as a complete report with the bottom missing.
	var buf strings.Builder
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("render failed", "template", name, "err", err)
		http.Error(w, "the report could not be rendered", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, buf.String())
}

// fail returns an error the analyst can read.
//
// Always 200, which is a deliberate and slightly uncomfortable choice. HTMX does not swap a
// non-2xx response by default, so a 400 leaves the previous report sitting on screen with
// nothing whatsoever to say the new run failed — the analyst sees the button re-enable and a
// stale report, which is worse than any status code is good. There is no non-browser client
// for this endpoint to mislead; it returns an HTML fragment and nothing else consumes it.
//
// It takes no status argument on purpose. A first pass had callers pass one, and the bad-CPE
// path passed 400 while the empty-company path passed 200 — so one of the two error messages
// silently never reached the page, which is exactly the failure this function exists to
// prevent.
func (s *Server) fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Escaped like everything else: the error may quote a company name that came from the form.
	fmt.Fprintf(w, `<h2>assessment failed</h2><p class="err verbatim">%s</p>`,
		template.HTMLEscapeString(err.Error()))
}

// parseCPEs splits and validates the CPE override field, returning the accepted CPEs and any
// entries that were not well-formed.
func parseCPEs(raw string) (accepted, rejected []string) {
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
