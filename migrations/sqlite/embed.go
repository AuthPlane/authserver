// Package sqlite embeds SQL migration files for the SQLite backend.
package sqlite

import "embed"

// Migrations contains the embedded SQL migration files.
//
//go:embed *.sql
var Migrations embed.FS
