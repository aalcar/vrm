// Package store owns the Postgres connection and the assessments cache schema.
//
// # Two populations, one table
//
// assessments_cache holds two different JSON shapes discriminated by the manual column:
// cached Sections written by automated sources, and analyst-recorded answers. Every read
// and every write filters on that column. A manual row read as a Section would fail to
// decode, and an automated write landing on a manual row would destroy analyst data.
//
// # Manual entries are analyst data, not cache
//
// They share assessments_cache for convenience — it is already keyed on
// (company, service, source) — but they are governed by different rules (spec §7): they
// never expire, --no-cache never clears them, and nothing overwrites them automatically.
// The manual column marks them so TTL sweeps and cache invalidation can exclude them.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aalcar/vrm/internal/sources"
	"github.com/aalcar/vrm/migrations"
)

// connectTimeout bounds the initial connectivity check so a wrong DATABASE_URL fails fast
// instead of hanging on a dial.
const connectTimeout = 10 * time.Second

// Store is a Postgres-backed cache. Safe for concurrent use — pgxpool is.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a connection pool and verifies connectivity before returning.
func New(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// Deliberately not wrapped with %w: pgx embeds the connection string in this
		// error, which would print the database password. Secrets are never logged
		// (spec §4), and that outranks the wrap-with-%w convention here.
		return nil, errors.New("DATABASE_URL is not a valid Postgres connection string")
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		// pgconn reports host, port and database here, but not credentials.
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	return &Store{pool: pool}, nil
}

// Close releases the pool. Safe to call on an already-closed Store.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Pool exposes the underlying pool for later phases.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

const createSchemaMigrations = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    text        PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Migrate applies any unapplied migrations in lexical filename order. Each runs in its own
// transaction together with its schema_migrations row, so a failure leaves no partially
// applied migration behind. Applying an already-current schema is a no-op.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, createSchemaMigrations); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if len(names) == 0 {
		return errors.New("no migrations embedded")
	}
	slices.Sort(names)

	for _, name := range names {
		applied, err := s.isApplied(ctx, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if err := s.apply(ctx, name, string(body)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) isApplied(ctx context.Context, version string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
		version).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return exists, nil
}

// apply runs one migration and records it, in a single transaction.
func (s *Store) apply(ctx context.Context, version, body string) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", version, err)
	}
	defer func() {
		// Rollback is a no-op once the transaction has committed.
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) && err == nil {
			err = fmt.Errorf("rollback migration %s: %w", version, rbErr)
		}
	}()

	if _, err := tx.Exec(ctx, body); err != nil {
		return fmt.Errorf("apply migration %s: %w", version, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return fmt.Errorf("record migration %s: %w", version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", version, err)
	}
	return nil
}

// manualPayload is the jsonb shape written to the section column. The recorded time lives
// in fetched_at rather than here, so there is one authority for it.
type manualPayload struct {
	Value string `json:"value"`
}

// ManualEntry reads the analyst's recorded answer for one source. The boolean reports
// whether an entry exists; absence is an ordinary outcome, not an error — it is how a
// manual source knows to render its instruction instead of a value.
func (s *Store) ManualEntry(ctx context.Context, company, service, source string) (sources.ManualEntry, bool, error) {
	var (
		raw     []byte
		fetched time.Time
	)
	err := s.pool.QueryRow(ctx,
		`SELECT section, fetched_at FROM assessments_cache
		 WHERE company = $1 AND service = $2 AND source = $3 AND manual`,
		NormalizeKey(company), NormalizeKey(service), source,
	).Scan(&raw, &fetched)
	if errors.Is(err, pgx.ErrNoRows) {
		return sources.ManualEntry{}, false, nil
	}
	if err != nil {
		return sources.ManualEntry{}, false, fmt.Errorf("read manual entry for %s: %w", source, err)
	}

	var payload manualPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return sources.ManualEntry{}, false, fmt.Errorf("decode manual entry for %s: %w", source, err)
	}
	return sources.ManualEntry{Value: payload.Value, RecordedAt: fetched}, true, nil
}

// SetManual records an analyst's answer, replacing any previous one for the same
// (company, service, source). Re-running vrm set is how an analyst corrects an entry, so
// overwriting here is deliberate — what must never happen is an *automated* source
// overwriting one, which is why every write path other than this one excludes manual rows.
func (s *Store) SetManual(ctx context.Context, company, service, source, value string) error {
	payload, err := json.Marshal(manualPayload{Value: value})
	if err != nil {
		return fmt.Errorf("encode manual entry for %s: %w", source, err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO assessments_cache (company, service, source, section, fetched_at, manual)
		 VALUES ($1, $2, $3, $4, now(), true)
		 ON CONFLICT (company, service, source)
		 DO UPDATE SET section = EXCLUDED.section, fetched_at = now(), manual = true`,
		NormalizeKey(company), NormalizeKey(service), source, payload)
	if err != nil {
		return fmt.Errorf("record manual entry for %s: %w", source, err)
	}
	return nil
}

// CachedSection reads a section that is still inside its TTL.
//
// The boolean reports a usable hit. A row that has aged out is reported the same way as no
// row at all, because the caller does the same thing with either: fetch. Nothing is deleted
// on expiry — the fresh result overwrites it, and a row that is never re-requested costs
// nothing but a little disk.
//
// The TTL comparison happens in Postgres rather than in Go. fetched_at is written by the
// database's clock, so comparing it against the application's would make freshness depend on
// how closely two machines agree.
func (s *Store) CachedSection(
	ctx context.Context,
	company, service, source string,
	ttl time.Duration,
) (sources.Section, bool, error) {
	// A source with no configured TTL is not cached at all. Treating a non-positive TTL as
	// "always fresh" would turn a missing config line into a permanent cache.
	if ttl <= 0 {
		return sources.Section{}, false, nil
	}

	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT section FROM assessments_cache
		 WHERE company = $1 AND service = $2 AND source = $3
		   AND NOT manual
		   AND fetched_at > now() - make_interval(secs => $4)`,
		NormalizeKey(company), NormalizeKey(service), source, ttl.Seconds(),
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return sources.Section{}, false, nil
	}
	if err != nil {
		return sources.Section{}, false, fmt.Errorf("read cached section for %s: %w", source, err)
	}

	section, err := sources.DecodeSection(source, raw)
	if err != nil {
		// A row that cannot be decoded is reported rather than swallowed. Silently treating
		// it as a miss would hide a schema change behind nothing worse than a slow run, and
		// the next write overwrites it anyway.
		return sources.Section{}, false, fmt.Errorf("cached section for %s is unreadable: %w", source, err)
	}
	return section, true, nil
}

// PutSection records a section, replacing any previous one for the same key.
//
// Which sections are worth caching is not decided here — that rule lives with the caching
// source in internal/sources, next to the code that knows what a fresh result cost.
//
// The upsert refuses to touch a manual row. Configuration already keeps automated and manual
// source names apart, so this should be unreachable; it is written as a loud error rather
// than a silent no-op because the thing it protects is the one kind of data in this tool that
// cannot be re-fetched.
func (s *Store) PutSection(
	ctx context.Context,
	company, service, source string,
	section sources.Section,
) error {
	payload, err := sources.EncodeSection(section)
	if err != nil {
		return fmt.Errorf("encode section for %s: %w", source, err)
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO assessments_cache (company, service, source, section, fetched_at, manual)
		 VALUES ($1, $2, $3, $4, now(), false)
		 ON CONFLICT (company, service, source)
		 DO UPDATE SET section = EXCLUDED.section, fetched_at = now()
		 WHERE NOT assessments_cache.manual`,
		NormalizeKey(company), NormalizeKey(service), source, payload)
	if err != nil {
		return fmt.Errorf("cache section for %s: %w", source, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf(
			"refused to cache %s: an analyst's manual entry occupies that row and is never "+
				"overwritten automatically", source)
	}
	return nil
}

// CachedResolution reads an entity resolution that is still inside its TTL.
//
// # A cached mapping is a persistent one
//
// Resolution is the weakest link in the system (spec §15) and this pins its answer for as
// long as its TTL allows — 720h by default, because an entity mapping is near-static. What
// makes that acceptable is that the resolved entity is printed at the top of every report,
// so a wrong mapping is visible on every run rather than only the one that produced it, and
// --no-cache re-resolves while --domain and --cpe override the parts that matter.
func (s *Store) CachedResolution(
	ctx context.Context,
	company, service string,
	ttl time.Duration,
) (sources.Resolution, bool, error) {
	if ttl <= 0 {
		return sources.Resolution{}, false, nil
	}

	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT section FROM assessments_cache
		 WHERE company = $1 AND service = $2 AND source = $3
		   AND NOT manual
		   AND fetched_at > now() - make_interval(secs => $4)`,
		NormalizeKey(company), NormalizeKey(service), sources.ResolutionKey, ttl.Seconds(),
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return sources.Resolution{}, false, nil
	}
	if err != nil {
		return sources.Resolution{}, false, fmt.Errorf("read cached resolution: %w", err)
	}

	var res sources.Resolution
	if err := json.Unmarshal(raw, &res); err != nil {
		return sources.Resolution{}, false, fmt.Errorf("cached resolution is unreadable: %w", err)
	}
	// A resolution with no canonical name is not a mapping, and every deterministic source
	// keys off one. Serving it would produce a report in which everything skipped.
	if res.Entity.CanonicalName == "" {
		return sources.Resolution{}, false, fmt.Errorf(
			"cached resolution has no canonical name; re-resolving")
	}
	return res, true, nil
}

// PutResolution records an entity resolution.
//
// Unlike a Section this needs no codec: Resolution is a plain struct with no `any` in it, so
// encoding/json round-trips it into its own concrete type unaided.
func (s *Store) PutResolution(ctx context.Context, company, service string, res sources.Resolution) error {
	if res.Entity.CanonicalName == "" {
		return errors.New("refusing to cache a resolution with no canonical name")
	}

	payload, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("encode resolution: %w", err)
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO assessments_cache (company, service, source, section, fetched_at, manual)
		 VALUES ($1, $2, $3, $4, now(), false)
		 ON CONFLICT (company, service, source)
		 DO UPDATE SET section = EXCLUDED.section, fetched_at = now()
		 WHERE NOT assessments_cache.manual`,
		NormalizeKey(company), NormalizeKey(service), sources.ResolutionKey, payload)
	if err != nil {
		return fmt.Errorf("cache resolution: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(
			"refused to cache the resolution: an analyst's manual entry occupies that row")
	}
	return nil
}

// NormalizeKey canonicalizes a company or service name for use in the assessments_cache
// primary key, so "Okta", " okta " and "Okta  Inc" address the row an analyst expects.
//
// Every read and write must go through this, or the cache silently fragments into
// near-duplicate rows that never hit.
func NormalizeKey(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
