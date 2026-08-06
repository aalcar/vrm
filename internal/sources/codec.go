package sources

import (
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

// sectionCodec knows the concrete type one source's Data holds.
type sectionCodec struct {
	typ    reflect.Type
	decode func(json.RawMessage) (any, error)
}

// codecFor builds the codec for a source whose Data is a T.
func codecFor[T any]() sectionCodec {
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
	}
}

// sectionCodecs is the set of cacheable sources.
//
// Manual sources are deliberately absent. They are analyst data rather than cache (spec §7):
// they are read from their own row on every run, they never expire, and their names come
// from config rather than from code — so there is nothing here to register and nothing that
// would benefit from a TTL.
var sectionCodecs = map[string]sectionCodec{
	SourceBitSight: codecFor[BitSightRating](),
	SourceNVD:      codecFor[NVDResult](),
	SourceOSV:      codecFor[OSVResult](),
	SourceFedRAMP:  codecFor[FedRAMPResult](),
	SourceCAAG:     codecFor[CAAGResult](),
	SourceResearch: codecFor[Research](),
}

// Cacheable reports whether a source's sections can be stored and read back.
func Cacheable(source string) bool {
	_, ok := sectionCodecs[source]
	return ok
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
	Source    string          `json:"source"`
	Status    Status          `json:"status"`
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
func EncodeSection(s Section) ([]byte, error) {
	codec, ok := sectionCodecs[s.Source]
	if !ok {
		return nil, fmt.Errorf(
			"source %q has no registered section codec, so its sections cannot be cached "+
				"(cacheable sources: %v)", s.Source, CacheableSources())
	}

	envelope := cachedSection{
		Source:    s.Source,
		Status:    s.Status,
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
func DecodeSection(source string, raw []byte) (Section, error) {
	codec, ok := sectionCodecs[source]
	if !ok {
		return Section{}, fmt.Errorf(
			"source %q has no registered section codec (cacheable sources: %v)",
			source, CacheableSources())
	}

	var envelope cachedSection
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Section{}, fmt.Errorf("decode %s section: %w", source, err)
	}
	if envelope.Source != source {
		return Section{}, fmt.Errorf(
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
			return Section{}, err
		}
		section.Data = data
	}
	return section, nil
}
