package sources

import (
	"context"
	"fmt"
	"time"
)

// cacheWriteTimeout bounds recording a result. Short on purpose: the answer is already in
// hand, and a slow database must not become a slow assessment.
const cacheWriteTimeout = 5 * time.Second

// SectionCache is the persistence a caching source needs.
//
// An interface rather than *store.Store so this package keeps depending on nothing, and so
// the caching behaviour can be tested without Postgres. The store's real methods satisfy it.
// inputs, on both methods, is the SectionInputs fingerprint of the identifiers the section was
// computed from. It is opaque to the cache: store it, and treat a row whose stored value
// differs as a miss.
type SectionCache interface {
	CachedSection(ctx context.Context, company, service, source string, ttl time.Duration, inputs string) (Section, bool, error)
	PutSection(ctx context.Context, company, service, source string, section Section, inputs string) error
}

// cachedSource wraps a Source with a read-through, write-through cache (spec §11).
type cachedSource struct {
	inner Source
	cache SectionCache
	ttl   time.Duration
	// bypass is --no-cache: skip the read, keep the write. Forcing a fresh call is the
	// point; leaving the stale row behind afterwards is not, so the run still refreshes
	// what it fetched.
	bypass bool
	warn   func(error)
}

// CacheOption configures a caching source.
type CacheOption func(*cachedSource)

// WithCacheBypass implements --no-cache: fetch fresh, then record the result.
func WithCacheBypass(bypass bool) CacheOption {
	return func(c *cachedSource) { c.bypass = bypass }
}

// WithCacheWarner routes cache trouble somewhere visible.
//
// Cache failures never fail a section — a stale or unwritten row costs a slow run, while a
// failed section costs an answer. But they are not swallowed either: a cache that has quietly
// stopped working looks exactly like one that is working, and this is the only thing that
// tells the two apart.
func WithCacheWarner(warn func(error)) CacheOption {
	return func(c *cachedSource) { c.warn = warn }
}

// Caching wraps src so its successful sections are cached for ttl.
//
// It returns src unchanged when there is nothing to cache with or no lifetime to cache for,
// so an unconfigured source behaves exactly as it did before rather than half-caching.
func Caching(src Source, cache SectionCache, ttl time.Duration, opts ...CacheOption) Source {
	if cache == nil || ttl <= 0 || !Cacheable(src.Name()) {
		return src
	}
	c := &cachedSource{inner: src, cache: cache, ttl: ttl}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *cachedSource) Name() string { return c.inner.Name() }

// Fetch serves a fresh cached section, or fetches and records one.
//
// # Only successful sections are cached
//
// A failure is a fact about the run, not about the vendor. Caching one would pin an upstream
// blip for the source's whole TTL — 168h for FedRAMP — and there is no way for an analyst to
// tell a cached failure from a live one. A skip is worse: it is computed from the resolved
// entity, so caching it would outlive the resolution fix that was supposed to clear it.
//
// # Only sections computed from this run's identifiers are served
//
// The row is keyed on the vendor but the answer is about the identifiers resolution supplied,
// and those move — an analyst passes --cpe, or the mapping itself changes. Both sides of the
// cache carry a fingerprint of them so that a row computed from other identifiers reads as a
// miss. See the note in codec.go for why this is not a column.
func (c *cachedSource) Fetch(ctx context.Context, q Query, ent ResolvedEntity) (Section, error) {
	inputs := SectionInputs(c.Name(), q, ent)

	if !c.bypass {
		if section, ok := c.lookup(ctx, q, inputs); ok {
			section.Cached = true
			return section, nil
		}
	}

	section, err := c.inner.Fetch(ctx, q, ent)
	if section.Status == StatusOK {
		c.record(ctx, q, section, inputs)
	}
	return section, err
}

// lookup reads the cache, reporting only a usable hit.
//
// A read error is a miss with a warning, not a failure. The cache is an accelerator; refusing
// to assess a vendor because the accelerator is sick would trade a slow answer for none.
func (c *cachedSource) lookup(ctx context.Context, q Query, inputs string) (Section, bool) {
	section, hit, err := c.cache.CachedSection(ctx, q.Company, q.Service, c.Name(), c.ttl, inputs)
	if err != nil {
		c.warnf("%s: could not read the cache, fetching fresh: %w", c.Name(), err)
		return Section{}, false
	}
	if !hit {
		return Section{}, false
	}
	// Nothing writes a non-OK row, so this is unreachable through this package. It is here
	// because the row could predate that rule, and serving a stored failure as though it
	// were this run's answer is the one outcome worth spending three lines to prevent.
	if section.Status != StatusOK {
		return Section{}, false
	}
	return section, true
}

// record writes a fresh result.
//
// The write gets its own context. Fetching may have consumed the source's entire deadline,
// and a result already in hand must not be discarded because the clock that bounded obtaining
// it also bounds recording it. Cancellation is dropped and values are kept — the write is no
// longer part of the work the caller is waiting on.
func (c *cachedSource) record(ctx context.Context, q Query, section Section, inputs string) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cacheWriteTimeout)
	defer cancel()

	if err := c.cache.PutSection(writeCtx, q.Company, q.Service, c.Name(), section, inputs); err != nil {
		c.warnf("%s: fetched successfully but could not be cached: %w", c.Name(), err)
	}
}

func (c *cachedSource) warnf(format string, args ...any) {
	if c.warn == nil {
		return
	}
	c.warn(fmt.Errorf(format, args...))
}
