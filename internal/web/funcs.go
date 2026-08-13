package web

import (
	"errors"
	"html/template"
	"reflect"
	"strings"

	"github.com/aalcar/vrm/internal/sources"
)

// capCount mirrors the terminal renderer's detail cap. Only used when a report asks to be
// capped; the browser scrolls, so the web handler passes Full.
const capCount = 10

// funcs are the template helpers.
//
// # Why the type assertions live here
//
// Section.Data is an `any` holding a concrete per-source struct, and a template cannot switch
// on a type. Each helper below asserts one type and returns a pointer, nil on a mismatch, so
// {{with bitsight .Data}} selects it and {{else}} falls through to the next. The alternative —
// flattening every source into a view model in Go — would be a second copy of every rendering
// decision the terminal renderer already makes, and the copy that drifts is the one somebody
// is reading.
//
// The fall-through end of that chain is load-bearing. A cached Section.Data that decoded into
// a map matches none of these, and the template's final {{else}} prints the section's
// citations rather than nothing, so the failure shows up as a thin section instead of a green
// heading with an empty body.
func funcs() template.FuncMap {
	return template.FuncMap{
		"bitsight": as[sources.BitSightRating],
		"nvd":      as[sources.NVDResult],
		"osv":      as[sources.OSVResult],
		"fedramp":  as[sources.FedRAMPResult],
		"caag":     as[sources.CAAGResult],
		"research": as[sources.Research],
		"manual":   as[sources.ManualResult],

		"dict":      dict,
		"capped":    capped,
		"finding":   finding,
		"place":     place,
		"day":       day,
		"hasPrefix": strings.HasPrefix,
		"eqFold":    strings.EqualFold,
	}
}

// as returns v as a *T, or nil when it holds something else.
func as[T any](v any) *T {
	t, ok := v.(T)
	if !ok {
		return nil
	}
	return &t
}

// dict builds a map so a template can pass more than one value to another template.
func dict(pairs ...any) (map[string]any, error) {
	if len(pairs)%2 != 0 {
		return nil, errors.New("dict needs an even number of arguments")
	}
	m := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			return nil, errors.New("dict keys must be strings")
		}
		m[key] = pairs[i+1]
	}
	return m, nil
}

// Capped is a list split into what to show and what was held back.
//
// Held is rendered rather than dropped for the same reason the terminal prints "+N more": a
// list that simply stops reads as the complete answer, and here it would understate a vendor's
// CVE count.
//
// Shown is an `any` rather than a []T because a template FuncMap cannot hold a generic
// function — it needs one concrete value per name — so the slicing goes through reflect.
// {{range}} then walks the result by reflection anyway, so nothing is lost on the way out.
type Capped struct {
	Shown any
	Held  int
}

func capped(rows any, full bool) Capped {
	v := reflect.ValueOf(rows)
	// A non-slice is passed through untouched rather than erroring: the caller asked to cap
	// something uncappable, and showing it whole beats showing nothing.
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return Capped{Shown: rows}
	}
	if full || v.Len() <= capCount {
		return Capped{Shown: rows}
	}
	return Capped{Shown: v.Slice(0, capCount).Interface(), Held: v.Len() - capCount}
}

// finding builds a Finding from a value and its citations, so the research template can render
// a location or a lawsuit through the same partial as a plain field. Every claim keeps the
// citation that supports it.
func finding(value string, citations []sources.Citation) sources.Finding {
	return sources.Finding{Value: value, Citations: citations}
}

// place joins a city and country, tolerating a missing city rather than printing a leading
// comma.
func place(city, country string) string {
	if city == "" {
		return country
	}
	return city + ", " + country
}

// day trims a timestamp to its date. NVD publishes "2024-01-02T00:00:00.000"; the time of day
// is noise in a report about which year a CVE landed.
//
// It slices rather than parsing because the value is recorded verbatim from the source and a
// parse failure would have to invent a fallback. A string too short to hold a date is returned
// untouched — showing the raw value beats showing a guess.
func day(s string) string {
	if len(s) < 10 {
		return s
	}
	return s[:10]
}
