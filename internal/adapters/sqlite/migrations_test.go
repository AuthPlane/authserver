//go:build integration

package sqlite_test

import (
	"context"
	"database/sql"
	"fmt"
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

// The runner applies every embedded migration that is not yet recorded,
// not just those above the highest recorded version. That is what lets a
// migration ship on a patch line after higher-numbered ones exist on the
// next minor: 013 lands on v0.2.1 while 005–012 belong to v0.3.0.
//
// Three paths have to hold, and this pins each with the real embedded
// set (versions 1–4 and 13 on this line):
//
//   - fresh install applies everything, in version order;
//   - a database that already recorded a high version (as a v0.2.1 install
//     records 13) still gets a lower, later-added version applied — this
//     is the v0.2.1 → v0.3.0 upgrade, simulated by deleting a low row;
//   - a database that recorded a version is not handed it again, even
//     when a lower one is pending — the two cases have to hold together,
//     since MAX(version) satisfies one at the cost of the other.
func TestMigrate_AppliesEveryUnrecordedVersion(t *testing.T) {
	ctx := context.Background()
	obs := observability.NewNoop()

	db, err := sqlite.Open(":memory:", obs)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("fresh migrate: %v", err)
	}
	applied := recordedVersions(t, db.DB)
	embedded := embeddedVersions(t)
	if !slicesEqualInt(applied, embedded) {
		t.Fatalf("fresh install recorded %v, embedded set is %v", applied, embedded)
	}
	if !contains(listSQLiteTables(t, db.DB), "issuances") {
		t.Fatal("issuances table missing after fresh migrate")
	}
	if !columnExists(t, db.DB, "issuances", "parent_jti") {
		t.Fatal("013 not applied on fresh install: issuances.parent_jti missing")
	}

	// Simulate "a lower version was added after a higher one was
	// recorded": forget 004 and its column, then migrate again. MAX(version)
	// would see 13 and skip it; the set-based runner must apply it.
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 4`); err != nil {
		t.Fatalf("forget 004: %v", err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE clients DROP COLUMN application_type`); err != nil {
		t.Fatalf("undo 004: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate with a lower version pending: %v", err)
	}
	if !columnExists(t, db.DB, "clients", "application_type") {
		t.Fatal("pending lower version 004 was not applied while 013 was recorded")
	}
	if !slicesEqualInt(recordedVersions(t, db.DB), embedded) {
		t.Fatalf("after re-apply recorded %v, want %v", recordedVersions(t, db.DB), embedded)
	}

	// Migrate again with nothing pending: a no-op. Re-applying 013 would
	// fail on the duplicate column, so a clean return proves nothing ran.
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("no-op migrate re-applied something: %v", err)
	}
}

func recordedVersions(t *testing.T, db *sql.DB) []int {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, v)
	}
	return out
}

func embeddedVersions(t *testing.T) []int {
	t.Helper()
	entries, err := migrations.Migrations.ReadDir(".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	var out []int
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

func slicesEqualInt(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
