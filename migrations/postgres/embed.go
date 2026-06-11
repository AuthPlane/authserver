// Package postgres provides embedded PostgreSQL migration files.
package postgres

import "embed"

// Migrations contains all .sql migration files for the PostgreSQL adapter.
//
//go:embed *.sql
var Migrations embed.FS
