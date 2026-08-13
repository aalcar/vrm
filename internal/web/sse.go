package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/report"
	"github.com/aalcar/vrm/internal/sources"
)

// # Why the stream is a GET, and how it is started
//
// EventSource — which htmx-ext-sse uses — can only issue a GET. So POST /assess no longer runs
// anything: it renders a shell whose sse-connect points at GET /assess/stream with the same
// parameters, and the stream does the work. The alternative was a server-side job registry
// keyed by an id the POST returns, which buys nothing here and adds a table of live
// assessments to expire, bound, and clean up after a browser that closed the tab.
//
// The parameters are a company, a service and two overrides. Nothing secret goes in the URL.

// sseRetry tells the browser how long to wait before reconnecting, in milliseconds.
//
// Deliberately long. EventSource reconnects automatically on any drop, and a reconnect here
// does not resume anything — it starts a whole new assessment, with fresh API calls against
// rate-limited sources. The stream closes itself when the report is delivered, so the only
// reconnects that happen are real failures, and those should be slow.
const sseRetry = 60000

// stream runs one assessment and writes it out as it arrives.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Without flushing, every event would sit in a buffer until the assessment finished,
		// which is precisely the behaviour this endpoint exists to avoid. Better to say so
		// than to serve a stream that silently arrives all at once at the end.
		http.Error(w, "this server cannot stream", http.StatusInternalServerError)
		return
	}

	cpes, bad := parseCPEs(r.URL.Query().Get("cpe"))
	if len(bad) > 0 {
		http.Error(w, "malformed cpe override", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	// A proxy that buffers this would defeat the whole endpoint. X-Accel-Buffering is nginx's
	// opt-out and is ignored elsewhere, so it costs nothing to send.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sse := &eventWriter{w: w, flusher: flusher}
	sse.retry(sseRetry)

	req := assess.Request{
		Query:   query(r.URL.Query()),
		Domain:  strings.TrimSpace(r.URL.Query().Get("domain")),
		CPEs:    cpes,
		NoCache: r.URL.Query().Get("no_cache") != "",

		// Both callbacks arrive on the goroutine that called Run — this one — so writing to
		// the connection from them needs no lock.
		OnResolved: func(res assess.Result) {
			sse.send("entity", s.fragment("entity.html", s.presented(res)))
		},
		OnSection: func(section sources.Section) {
			sse.send("section", s.fragment("streamed-section.html", streamedSection{
				Row:  report.Row{Section: section, Outcome: s.outcomeOf(section)},
				Full: true,
			}))
		},
	}

	result, err := s.runner.Run(r.Context(), req)
	if err != nil {
		sse.send("report", fmt.Sprintf(
			`<h2>assessment failed</h2><p class="err verbatim">%s</p>`, escape(err.Error())))
		sse.send("done", "")
		return
	}

	// The whole report last, replacing everything streamed above it. The incremental view is
	// in completion order — that is the point of it — while the report an analyst reads and
	// files is in SectionOrder, with the entity, summary and config around it. Streaming the
	// pieces must not end in a page that is missing the parts only the full render has.
	sse.send("report", s.fragment("report.html", s.presented(result)))
	sse.send("done", "")
}

// query pulls the company and service out of the URL.
func query(v url.Values) sources.Query {
	get := func(k string) string {
		if vs := v[k]; len(vs) > 0 {
			return strings.TrimSpace(vs[0])
		}
		return ""
	}
	return sources.Query{Company: get("company"), Service: get("service")}
}

// presented builds the renderable report for a Result.
func (s *Server) presented(res assess.Result) report.Report {
	return report.FromResult(res, s.runner, report.Presentation{
		ConfigPath: s.configPath,
		Full:       true,
	})
}

// outcomeOf labels a single section the way the finished report will.
//
// It goes through report.Report so a streamed section and the same section in the final render
// cannot disagree — a source that reads "unanswered" while streaming and "awaiting manual
// check" thirty seconds later would be the tool contradicting itself mid-page.
func (s *Server) outcomeOf(section sources.Section) report.Outcome {
	r := report.Report{
		ManualSources: s.runner.Config().ManualNames(),
		Sections:      []sources.Section{section},
	}
	return r.Rows()[0].Outcome
}

// streamedSection is one section on its way to the browser, before the full report exists.
type streamedSection struct {
	Row  report.Row
	Full bool
}

// fragment renders a template to a string, or an inline error.
//
// A render failure cannot be an HTTP status here: the response is already committed and
// streaming. Saying so in the stream is the only way it reaches anyone.
func (s *Server) fragment(name string, data any) string {
	var b strings.Builder
	if err := s.tmpl.ExecuteTemplate(&b, name, data); err != nil {
		s.log.Error("render failed", "template", name, "err", err)
		return `<p class="err">a section could not be rendered</p>`
	}
	return b.String()
}

// eventWriter writes the SSE wire format.
//
// Not safe for concurrent use, and does not need to be: every caller is on the one goroutine
// running the assessment.
type eventWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (e *eventWriter) retry(ms int) {
	fmt.Fprintf(e.w, "retry: %d\n\n", ms)
	e.flusher.Flush()
}

// send writes one named event, then flushes.
//
// The payload is split across data: lines because a bare newline terminates a field in the SSE
// wire format — an HTML fragment sent unsplit would be truncated at its first line break, which
// is every fragment this file produces. An empty payload still gets one data: line, so an event
// with no body is a well-formed event rather than a malformed one.
func (e *eventWriter) send(event, payload string) {
	fmt.Fprintf(e.w, "event: %s\n", event)
	for _, line := range strings.Split(payload, "\n") {
		fmt.Fprintf(e.w, "data: %s\n", strings.TrimRight(line, "\r"))
	}
	fmt.Fprint(e.w, "\n")
	e.flusher.Flush()
}
