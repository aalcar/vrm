// Package store owns the Postgres connection and the assessments cache schema.
//
// Phase 0 establishes the connection and applies migrations. Read/write cache logic
// arrives in Phase 9; manual-entry writes in Phase 5.
package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

// NormalizeKey canonicalizes a company or service name for use in the assessments_cache
// primary key, so "Okta", " okta " and "Okta  Inc" address the row an analyst expects.
//
// Every read and write must go through this, or the cache silently fragments into
// near-duplicate rows that never hit.
func NormalizeKey(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
