// Package migrations embeds the SQL schema migrations.
//
// It exists so //go:embed can reach the repo-root migrations/ directory that the spec's
// layout (§5) calls for: embed cannot reference files outside its own package directory,
// so internal/store cannot embed them directly.
package migrations

import "embed"

// FS holds the migration files, applied in lexical filename order.
//
//go:embed *.sql
var FS embed.FS
