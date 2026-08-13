package web

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aalcar/vrm/internal/report"
	"github.com/aalcar/vrm/internal/sources"
)

// TestAMultiLineFragmentSurvivesTheWire is the bug this format invites.
//
// A bare newline terminates a field in the SSE wire format, so an HTML fragment written as one
// data: line arrives truncated at its first line break — and every fragment this server sends
// is multi-line. The failure is quiet in exactly the wrong way: the connection stays open, the
// event count is right, and each section simply loses everything below its opening tag.
func TestAMultiLineFragmentSurvivesTheWire(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &eventWriter{w: rec, flusher: rec}

	payload := "<section>\n  <h3>nvd</h3>\n  <p>2 CVEs</p>\n</section>"
	e.send("section", payload)

	// Reassemble it the way a browser does: strip the "data: " prefix and rejoin with \n.
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(rec.Body.String(), "\n\n"), "\n") {
		if after, ok := strings.CutPrefix(line, "data: "); ok {
			lines = append(lines, after)
		}
	}
	if got := strings.Join(lines, "\n"); got != payload {
		t.Errorf("the fragment did not survive the wire\n got: %q\nwant: %q", got, payload)
	}
	if !strings.HasPrefix(rec.Body.String(), "event: section\n") {
		t.Error("the event is not named")
	}
	if !strings.HasSuffix(rec.Body.String(), "\n\n") {
		t.Error("the event is not terminated by a blank line; the browser will not dispatch it")
	}
}

// TestAnEmptyPayloadIsStillAWellFormedEvent. The done event carries no body, and an event with
// no data: line at all is malformed — the browser would never dispatch it, so the stream would
// never close and EventSource would eventually reconnect and re-run the whole assessment.
func TestAnEmptyPayloadIsStillAWellFormedEvent(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &eventWriter{w: rec, flusher: rec}
	e.send("done", "")

	if got := rec.Body.String(); got != "event: done\ndata: \n\n" {
		t.Errorf("done event = %q", got)
	}
}

// TestEachEventIsFlushed. Without a flush per event the whole stream lands at once when the
// handler returns, which is precisely the behaviour this endpoint exists to avoid — and it
// would still pass every other test in this file.
func TestEachEventIsFlushed(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &eventWriter{w: rec, flusher: rec}

	e.retry(1000)
	e.send("entity", "<dl></dl>")
	e.send("section", "<section></section>")

	if rec.Flushed != true {
		t.Fatal("nothing was flushed")
	}
	// httptest records only that a flush happened, so the count is checked through a counter.
	counting := &countingFlusher{ResponseRecorder: httptest.NewRecorder()}
	e2 := &eventWriter{w: counting, flusher: counting}
	e2.retry(1000)
	e2.send("a", "x")
	e2.send("b", "y")
	if counting.flushes != 3 {
		t.Errorf("flushed %d times, want 3 (retry + two events)", counting.flushes)
	}
}

type countingFlusher struct {
	*httptest.ResponseRecorder
	flushes int
}

func (c *countingFlusher) Flush() { c.flushes++; c.ResponseRecorder.Flush() }

// TestAStreamedSectionMatchesTheFinalReport is the consistency the split renderer risks.
//
// The same section is rendered twice — once as it lands, once inside the finished report — and
// a source that reads "unanswered" while streaming and "awaiting manual check" thirty seconds
// later would be the tool contradicting itself mid-page.
func TestAStreamedSectionMatchesTheFinalReport(t *testing.T) {
	tmpl, err := template.New("vrm").Funcs(funcs()).ParseFS(templateFS,
		"templates/*.html", "templates/*.css", "templates/partials/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	full := baseReport()
	full.ManualSources = []string{"ssllabs"}
	full.Sections = []sources.Section{
		sources.OK(sources.SourceCAAG, sources.CAAGResult{Searched: []string{"okta"}}),
		sources.Skipped(sources.SourceOSV, "no packages"),
		sources.Skipped("ssllabs", "no entry recorded"),
	}

	var whole strings.Builder
	if err := tmpl.ExecuteTemplate(&whole, "report.html", full); err != nil {
		t.Fatalf("render report: %v", err)
	}

	for _, row := range full.Rows() {
		var streamed strings.Builder
		err := tmpl.ExecuteTemplate(&streamed, "streamed-section.html",
			streamedSection{Row: row, Full: true})
		if err != nil {
			t.Fatalf("render streamed %s: %v", row.Section.Source, err)
		}
		// The streamed fragment must appear verbatim inside the finished report. Anything
		// less and the two renders have diverged.
		if !strings.Contains(whole.String(), strings.TrimSpace(streamed.String())) {
			t.Errorf("the streamed %s section does not match the one in the report:\n%s",
				row.Section.Source, streamed.String())
		}
	}
}

// TestAStreamedSectionIsEscaped. The stream bypasses the report template, so it needs its own
// proof: the fragments still go through html/template and a scraped value cannot execute.
func TestAStreamedSectionIsEscaped(t *testing.T) {
	tmpl, err := template.New("vrm").Funcs(funcs()).ParseFS(templateFS,
		"templates/*.html", "templates/*.css", "templates/partials/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	const payload = `<script>alert('xss')</script>`
	row := report.Row{
		Section: sources.OK(sources.SourceCAAG, sources.CAAGResult{
			Searched: []string{payload},
			Entries: []sources.CAAGEntry{{
				Organization: payload, SearchedAs: "other",
				ReportedDate: payload, ReportURL: "https://oag.ca.gov/x",
			}},
		}),
		Outcome: report.OutcomeOK,
	}

	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "streamed-section.html",
		streamedSection{Row: row, Full: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(b.String(), payload) {
		t.Fatal("an unescaped <script> tag reached the stream")
	}
	if !strings.Contains(b.String(), "&lt;script&gt;") {
		t.Error("the payload is neither escaped nor present")
	}
}

// TestTheStreamShellNamesEveryListener. The shell is inert markup, so nothing else would catch
// a renamed event: the browser would connect, receive events nobody is listening for, and show
// an empty page under a form that looked like it worked.
func TestTheStreamShellNamesEveryListener(t *testing.T) {
	s, err := New(nil, "config.yaml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	s.render(rec, "stream.html", "company=Okta&service=SSO")

	body := rec.Body.String()
	for _, want := range []string{
		`hx-ext="sse"`, `sse-connect="/assess/stream?`,
		`sse-swap="entity"`, `sse-swap="section"`, `sse-swap="report"`,
		`hx-swap="beforeend"`, `hx-swap="outerHTML"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the stream shell is missing %q", want)
		}
	}
	// The names the shell listens for must be the names the handler sends.
	for _, event := range []string{"entity", "section", "report"} {
		if !strings.Contains(body, `sse-swap="`+event+`"`) {
			t.Errorf("nothing listens for the %q event the handler sends", event)
		}
	}
}

// TestTheFormLoadsTheSSEExtension. hx-ext="sse" is inert without it: the shell would render,
// no connection would open, and the page would sit on "assessing…" forever.
func TestTheFormLoadsTheSSEExtension(t *testing.T) {
	s, err := New(nil, "config.yaml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	s.render(rec, "form.html", nil)

	body := rec.Body.String()
	if !strings.Contains(body, "htmx-ext-sse@2.2.4") {
		t.Error("the SSE extension is not loaded; hx-ext=\"sse\" would be inert")
	}
	if strings.Count(body, "integrity=") != 2 {
		t.Error("both scripts must carry a subresource-integrity hash")
	}
}
