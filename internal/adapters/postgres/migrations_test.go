//go:build integration_postgres

package postgres_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/internal/observability"
	migrations "github.com/authplane/authserver/migrations/postgres"
)

// TestMigrations_001Initial_UpDownUpRoundTrip mirrors the sqlite
// roundtrip test against postgres, closing the BRIEF §1 pre-release
// exit gate: the consolidated `001_initial.up.sql` and
// `001_initial.down.sql` are exercised in CI.
//
// The test uses the testcontainer DSN injected by main_test.go
// (AUTHPLANE_STORAGE_POSTGRES_DSN) and operates on the database the
// container ships. To avoid trampling parallel integration tests in
// the same database, the round-trip runs end-to-end inside a
// fresh-database scope: drop everything first, run up, run down, run
// up again. Final state is the same fully-migrated database the rest
// of the integration suite expects.
func TestMigrations_001Initial_UpDownUpRoundTrip(t *testing.T) {
	ctx := context.Background()
	obs := observability.NewNoop()

	// Pre-clean: apply the down script first so the DB starts from a
	// known empty state. (The container may already be migrated by an
	// earlier test in the suite.) We use a raw pool here so we can run
	// the down script without the migrate runner's "track applied
	// migrations" semantics getting in the way.
	rawPool, err := pgxpool.New(ctx, pgContainerDSN)
	if err != nil {
		t.Fatalf("open raw pool: %v", err)
	}
	t.Cleanup(rawPool.Close)

	downSQL, err := migrations.Migrations.ReadFile("001_initial.down.sql")
	if err != nil {
		t.Fatalf("read down script: %v", err)
	}
	upSQL, err := migrations.Migrations.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read up script: %v", err)
	}

	// Normalise: drop everything from prior tests so the round-trip
	// starts clean.
	if _, err := rawPool.Exec(ctx, string(downSQL)); err != nil {
		t.Fatalf("pre-clean down: %v", err)
	}
	rawPool.Close()

	// Pass 1: up.
	db, err := postgres.Open(ctx, pgContainerDSN, postgres.PoolConfig{MaxConns: 5}, obs)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatalf("first up migration: %v", err)
	}
	tablesAfterFirstUp := listPGTables(t, ctx, db.Pool)
	if len(tablesAfterFirstUp) == 0 {
		db.Close()
		t.Fatal("first up: no tables present")
	}
	for _, expected := range expectedPGTables {
		if !containsString(tablesAfterFirstUp, expected) {
			t.Errorf("first up: missing expected table %q (got %v)", expected, tablesAfterFirstUp)
		}
	}

	// Pass 2: down.
	if _, err := db.Pool.Exec(ctx, string(downSQL)); err != nil {
		db.Close()
		t.Fatalf("apply down script: %v", err)
	}
	tablesAfterDown := listPGTables(t, ctx, db.Pool)
	for _, table := range expectedPGTables {
		if containsString(tablesAfterDown, table) {
			t.Errorf("after down: table %q still exists", table)
		}
	}

	// Pass 3: up again — direct exec (the migrate runner won't re-run
	// because schema_migrations was dropped, but the version-tracking
	// logic only runs missing versions; recreating the table from
	// scratch would loop. Just exec the script and re-verify.)
	if _, err := db.Pool.Exec(ctx, string(upSQL)); err != nil {
		db.Close()
		t.Fatalf("second up migration: %v", err)
	}
	tablesAfterSecondUp := listPGTables(t, ctx, db.Pool)
	if !slicesEqualPG(tablesAfterFirstUp, tablesAfterSecondUp) {
		t.Errorf("schema changed between up→down→up:\nfirst up:  %v\nsecond up: %v",
			tablesAfterFirstUp, tablesAfterSecondUp)
	}

	db.Close()
}

// expectedPGTables enumerates the tables 001_initial.up.sql creates in
// the postgres backend. Slightly different from the sqlite list:
// postgres has signing_keys (NOTIFY-bearing) which the sqlite backend
// does not.
var expectedPGTables = []string{
	"clients",
	"users",
	"auth_sessions",
	"token_families",
	"refresh_tokens",
	"audit_events",
	"access_token_jtis",
	"revoked_jtis",
	"signing_keys",
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

func listPGTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename != 'schema_migrations'`)
	if err != nil {
		t.Fatalf("query pg_tables: %v", err)
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

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func slicesEqualPG(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return strings.Join(ac, ",") == strings.Join(bc, ",")
}

// Same contract as the SQLite runner test: every embedded version that is
// not recorded gets applied, including one numbered below the highest
// recorded — the v0.2.1 → v0.3.0 path, where 013 is on the row already and
// 005–012 arrive later.
func TestMigrate_AppliesEveryUnrecordedVersion(t *testing.T) {
	ctx := context.Background()
	obs := observability.NewNoop()

	// Start from an empty schema: the container is shared across tests.
	rawPool, err := pgxpool.New(ctx, pgContainerDSN)
	if err != nil {
		t.Fatalf("open raw pool: %v", err)
	}
	downSQL, err := migrations.Migrations.ReadFile("001_initial.down.sql")
	if err != nil {
		t.Fatalf("read down script: %v", err)
	}
	if _, err := rawPool.Exec(ctx, string(downSQL)); err != nil {
		t.Fatalf("pre-clean down: %v", err)
	}
	rawPool.Close()

	db, err := postgres.Open(ctx, pgContainerDSN, postgres.PoolConfig{MaxConns: 5}, obs)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("fresh migrate: %v", err)
	}
	embedded := embeddedPGVersions(t)
	if got := recordedPGVersions(t, ctx, db.Pool); !slicesEqualIntPG(got, embedded) {
		t.Fatalf("fresh install recorded %v, embedded set is %v", got, embedded)
	}
	if !pgColumnExists(t, ctx, db.Pool, "issuances", "parent_jti") {
		t.Fatal("013 not applied on fresh install: issuances.parent_jti missing")
	}

	// Forget 004 and undo it, then migrate with 013 still recorded.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 4`); err != nil {
		t.Fatalf("forget 004: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `ALTER TABLE clients DROP COLUMN application_type`); err != nil {
		t.Fatalf("undo 004: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate with a lower version pending: %v", err)
	}
	if !pgColumnExists(t, ctx, db.Pool, "clients", "application_type") {
		t.Fatal("pending lower version 004 was not applied while 013 was recorded")
	}
	if got := recordedPGVersions(t, ctx, db.Pool); !slicesEqualIntPG(got, embedded) {
		t.Fatalf("after re-apply recorded %v, want %v", got, embedded)
	}

	// Nothing pending: must not re-run 013 (the ADD COLUMN would fail).
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("no-op migrate re-applied something: %v", err)
	}
}

func recordedPGVersions(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []int {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
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

func embeddedPGVersions(t *testing.T) []int {
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

func pgColumnExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, column string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
		table, column).Scan(&n); err != nil {
		t.Fatalf("information_schema: %v", err)
	}
	return n > 0
}

func slicesEqualIntPG(a, b []int) bool {
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
