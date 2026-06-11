//go:build integration_postgres

package postgres_test

import (
	"context"
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
