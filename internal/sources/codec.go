package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

// # Why a Section needs a typed codec rather than encoding/json alone
//
// Section.Data is an `any` holding a concrete per-source struct. Marshalling one is easy;
// getting the same thing back is not. json.Unmarshal into an `any` produces a
// map[string]any, which violates the invariant that Data is never a map — and it violates it
// silently. The renderer selects on the concrete type, so a cached section whose Data came
// back as a map matches no case and renders as a heading with nothing underneath: a green
// `bitsight ok` with no rating. That is the worst failure this codebase has a name for, and
// caching is the first thing in it that can produce one.
//
// So decoding is table-driven. Each cacheable source registers the type its Data actually
// holds, and the row is decoded into that type or not at all.
//
// Encoding is checked against the same table, on purpose. A source whose Data type does not
// match its registration fails at write time, where a test sees it, instead of producing a
// row that decodes into a zero value a day later.

// # Why the cache key is not (company, service, source)
//
// A section is not an answer about a vendor. It is an answer about the identifiers resolution
// handed the source — the CPEs NVD was queried with, the domain BitSight was asked about — and
// those change under a key that does not. Two ways, both real:
//
//   - `--cpe` exists so an analyst can correct a bad mapping. Without this, the corrected run
//     reads yesterday's row back and shows CVEs for the CPEs the analyst was overriding. The
//     escape hatch silently does nothing, which is worse than not having one.
//   - Resolution is cached for 720h and NVD for 24h, so the mapping outlives its sections and
//     the sections normally re-derive from it. But when the mapping itself changes — its TTL
//     lapses, a prompt improves, a dictionary read that failed last time succeeds — a warm
//     section row keeps serving the old identifiers' answer until it ages out.
//
// So each source registers the entity fields it actually reads, those are fingerprinted, and a
// row whose fingerprint disagrees with this run's is a miss. The fingerprint travels inside the
// stored payload rather than in a column: it is part of what the row means, and a row written
// before this rule has none and so expires on first read — the same read-side enforcement the
// resolution cache uses.
//
// The cost is that alternating overridden and un-overridden runs never hit each other's row,
// because one key holds one section. That is the correct trade: a miss costs a fetch, and a
// hit on the wrong identifiers costs an analyst the wrong vendor's CVEs.

// sectionCodec knows the concrete type one source's Data holds, and which parts of the
// resolved entity that source's answer depends on.
type sectionCodec struct {
	typ    reflect.Type
	decode func(json.RawMessage) (any, error)
	// inputs returns the identifiers this source reads. Order is preserved rather than
	// sorted: several sources cap how many names they look up, so a reordering is a genuine
	// change in what gets queried and must not fingerprint the same.
	inputs func(Query, ResolvedEntity) []string
}

// codecFor builds the codec for a source whose Data is a T and whose answer depends on inputs.
func codecFor[T any](inputs func(Query, ResolvedEntity) []string) sectionCodec {
	var zero T
	return sectionCodec{
		typ: reflect.TypeOf(zero),
		decode: func(raw json.RawMessage) (any, error) {
			var v T
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("decode %T: %w", v, err)
			}
			return v, nil
		},
		inputs: inputs,
	}
}

func domainInputs(_ Query, ent ResolvedEntity) []string { return ent.Domains }
func cpeInputs(_ Query, ent ResolvedEntity) []string    { return ent.CPEs }

func packageInputs(_ Query, ent ResolvedEntity) []string {
	out := make([]string, 0, len(ent.Packages))
	for _, p := range ent.Packages {
		out = append(out, p.String())
	}
	return out
}

// sectionCodecs is the set of cacheable sources.
//
// Manual sources are deliberately absent. They are analyst data rather than cache (spec §7):
// they are read from their own row on every run, they never expire, and their names come
// from config rather than from code — so there is nothing here to register and nothing that
// would benefit from a TTL.
// vendorNames is the fingerprint for the three name-driven sources. FedRAMP and CA AG search
// under it directly; research puts the same canonical name and aliases in its prompt.
var sectionCodecs = map[string]sectionCodec{
	SourceBitSight: codecFor[BitSightRating](domainInputs),
	SourceNVD:      codecFor[NVDResult](cpeInputs),
	SourceOSV:      codecFor[OSVResult](packageInputs),
	SourceFedRAMP:  codecFor[FedRAMPResult](vendorNames),
	SourceCAAG:     codecFor[CAAGResult](vendorNames),
	SourceResearch: codecFor[Research](vendorNames),
}

// Cacheable reports whether a source's sections can be stored and read back.
func Cacheable(source string) bool {
	_, ok := sectionCodecs[source]
	return ok
}

// SectionInputs fingerprints the identifiers source will read off ent on this run.
//
// A hash rather than the identifiers themselves: it is compared, never read, and a vendor with
// six CPEs and a dozen aliases would otherwise carry a few hundred bytes of duplicate payload
// in every row. Entries are length-prefixed so that ["ab","c"] and ["a","bc"] cannot collide.
//
// An unregistered source fingerprints as the empty string. Nothing caches such a source —
// Caching returns it unwrapped — so this is never compared against anything.
func SectionInputs(source string, q Query, ent ResolvedEntity) string {
	codec, ok := sectionCodecs[source]
	if !ok {
		return ""
	}
	h := sha256.New()
	for _, in := range codec.inputs(q, ent) {
		fmt.Fprintf(h, "%d:%s", len(in), in)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CacheableSources lists the sources with a registered codec, sorted. For error messages.
func CacheableSources() []string {
	names := make([]string, 0, len(sectionCodecs))
	for name := range sectionCodecs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// cachedSection is the JSON shape stored in assessments_cache.section.
//
// Data stays raw here so the envelope can be read before the type is known — the source name
// selects the decoder, and the payload is decoded only once that has been found.
//
// Section.Cached is deliberately not part of this shape. It describes how the current run
// obtained the section, not anything about the vendor, and persisting it would mean a row
// written from a cache hit could never report itself as fresh again.
type cachedSection struct {
	Source string `json:"source"`
	Status Status `json:"status"`
	// Inputs is the SectionInputs fingerprint of the identifiers this section was computed
	// from. Never omitempty: a row missing the field and a row whose identifiers hashed to
	// nothing must stay distinguishable, and readers rely on absent meaning "written before
	// this rule".
	Inputs    string          `json:"inputs"`
	Data      json.RawMessage `json:"data,omitempty"`
	Citations []Citation      `json:"citations,omitempty"`
	Note      string          `json:"note,omitempty"`
	Err       string          `json:"err,omitempty"`
}

// EncodeSection serializes a Section for the cache.
//
// It refuses a source with no registered codec, and refuses Data of a type the codec does not
// decode into. Both would produce a row that no reader can turn back into a usable section,
// and a row nothing can read is worse than no row: it is written once and fails silently on
// every subsequent read.
// inputs is the SectionInputs fingerprint of the identifiers the section was computed from;
// it is stored with the row so a later run reading different identifiers sees a miss.
func EncodeSection(s Section, inputs string) ([]byte, error) {
	codec, ok := sectionCodecs[s.Source]
	if !ok {
		return nil, fmt.Errorf(
			"source %q has no registered section codec, so its sections cannot be cached "+
				"(cacheable sources: %v)", s.Source, CacheableSources())
	}
	// An unfingerprinted row can never be read back — absent inputs is how a row predating
	// the rule is recognized — so writing one would burn a write and cache nothing.
	if inputs == "" {
		return nil, fmt.Errorf(
			"refusing to cache %s with no input fingerprint: the row could never be read back",
			s.Source)
	}

	envelope := cachedSection{
		Source:    s.Source,
		Status:    s.Status,
		Inputs:    inputs,
		Citations: s.Citations,
		Note:      s.Note,
		Err:       s.Err,
	}

	if s.Data != nil {
		if got := reflect.TypeOf(s.Data); got != codec.typ {
			return nil, fmt.Errorf(
				"source %q is registered as caching %s but produced %s; "+
					"caching it would write a row that decodes into the wrong type",
				s.Source, codec.typ, got)
		}
		raw, err := json.Marshal(s.Data)
		if err != nil {
			return nil, fmt.Errorf("encode %s data: %w", s.Source, err)
		}
		envelope.Data = raw
	}

	out, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode %s section: %w", s.Source, err)
	}
	return out, nil
}

// DecodeSection reads a Section back, restoring Data to its concrete type.
//
// The source argument is the key the row was read under. It must agree with the source
// recorded inside the payload: a disagreement means the row is not what the key says it is,
// and decoding it anyway would attribute one source's data to another.
//
// The second return is the row's input fingerprint, for the caller to compare against this
// run's. It is returned rather than checked here so that an unreadable row stays a loud error
// while identifiers that have simply moved on stay a quiet miss — those are different facts. A
// row written before fingerprinting returns "", which matches no live fingerprint.
func DecodeSection(source string, raw []byte) (Section, string, error) {
	codec, ok := sectionCodecs[source]
	if !ok {
		return Section{}, "", fmt.Errorf(
			"source %q has no registered section codec (cacheable sources: %v)",
			source, CacheableSources())
	}

	var envelope cachedSection
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Section{}, "", fmt.Errorf("decode %s section: %w", source, err)
	}
	if envelope.Source != source {
		return Section{}, "", fmt.Errorf(
			"cached row for %q holds a %q section", source, envelope.Source)
	}

	section := Section{
		Source:    envelope.Source,
		Status:    envelope.Status,
		Citations: envelope.Citations,
		Note:      envelope.Note,
		Err:       envelope.Err,
	}

	if len(envelope.Data) > 0 {
		data, err := codec.decode(envelope.Data)
		if err != nil {
			return Section{}, "", err
		}
		section.Data = data
	}
	return section, envelope.Inputs, nil
}
