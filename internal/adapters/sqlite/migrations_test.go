//go:build integration

package sqlite_test

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/observability"
	migrations "github.com/authplane/authserver/migrations/sqlite"
)

// TestMigrations_001Initial_UpDownUpRoundTrip closes the BRIEF §1
// pre-release exit gate: the consolidated `001_initial.up.sql` and
// `001_initial.down.sql` are exercised in CI as a fresh-install +
// drop-everything roundtrip. Previously, the up script ran on every
// integration boot but the down script was never exercised —
// adds permanent coverage.
//
// Round trip:
//
//   - Apply 001_initial.up.sql → assert every expected table exists.
//   - Apply 001_initial.down.sql → assert every expected table is
//     dropped (only sqlite_sequence and the schema_migrations row may
//     linger; the down script drops schema_migrations too).
//   - Re-apply 001_initial.up.sql → assert the schema is identical to
//     the first up (table names match exactly).
func TestMigrations_001Initial_UpDownUpRoundTrip(t *testing.T) {
	ctx := context.Background()
	obs := observability.NewNoop()

	db, err := sqlite.Open(":memory:", obs)
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Pass 1: up.
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("first up migration: %v", err)
	}
	tablesAfterFirstUp := listSQLiteTables(t, db.DB)
	if len(tablesAfterFirstUp) == 0 {
		t.Fatal("first up: no tables present — embedded migration FS empty?")
	}
	for _, expected := range expectedSQLiteTables {
		if !contains(tablesAfterFirstUp, expected) {
			t.Errorf("first up: missing expected table %q (got %v)", expected, tablesAfterFirstUp)
		}
	}

	// Pass 2: down. The 001_initial.down.sql script drops every table
	// the up script created (FK-respecting reverse order, including
	// schema_migrations).
	downSQL, err := migrations.Migrations.ReadFile("001_initial.down.sql")
	if err != nil {
		t.Fatalf("read down script: %v", err)
	}
	if _, err := db.DB.ExecContext(ctx, string(downSQL)); err != nil {
		t.Fatalf("apply down script: %v", err)
	}
	tablesAfterDown := listSQLiteTables(t, db.DB)
	for _, table := range expectedSQLiteTables {
		if contains(tablesAfterDown, table) {
			t.Errorf("after down: table %q still exists (down script didn't drop it)", table)
		}
	}

	// Pass 3: up again. Schema must match the first up byte-for-byte
	// at the table-name level. (We do not diff column definitions —
	// the embedded SQL is the source of truth for that.)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("second up migration: %v", err)
	}
	tablesAfterSecondUp := listSQLiteTables(t, db.DB)
	if !slicesEqual(tablesAfterFirstUp, tablesAfterSecondUp) {
		t.Errorf("schema changed between up→down→up:\nfirst up:  %v\nsecond up: %v",
			tablesAfterFirstUp, tablesAfterSecondUp)
	}
}

// expectedSQLiteTables enumerates the tables 001_initial.up.sql
// creates (regenerate via `grep -E "^CREATE TABLE" 001_initial.up.sql`
// when adding tables in a future migration).  added this list as
// the explicit assertion target so a regression that drops a CREATE
// TABLE shows up here, not silently downstream.
var expectedSQLiteTables = []string{
	"clients",
	"users",
	"auth_sessions",
	"token_families",
	"refresh_tokens",
	"audit_events",
	"access_token_jtis",
	"revoked_jtis",
	"machine_tokens",
	"dpop_jtis",
	"dpop_nonces",
	"runtime_settings",
	"trusted_idps",
	"assertion_jtis",
	"xaa_policies",
	"subject_mappings",
	"broker_providers",
	"resources",
	"consent_grants",
	"broker_grants",
	"issuances",
	"connect_pending_states",
}

// listSQLiteTables returns user-defined tables (excluding
// sqlite_sequence and schema_migrations control tables).
func listSQLiteTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'`)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return strings.Join(ac, ",") == strings.Join(bc, ",")
}
