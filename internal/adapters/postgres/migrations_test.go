//go:build integration_postgres

package postgres_test

import (
	"context"
	"fmt"
	"io/fs"
	"reflect"
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

// 014 makes users.email nullable. The upgrade from 013 keeps every row and
// column (a federated user's empty-string email becomes NULL), keeps child rows, and
// lets any number of users have no email while a present one stays unique.
// The down migration restores NOT NULL while at most one user has no email
// and refuses, changing nothing, when two or more do.
func TestMigration014_UpgradeAndDown(t *testing.T) {
	ctx := context.Background()
	pool := pgAt013(t)

	seedPG014Fixture(t, pool)
	before := dumpPGUsers(t, pool)
	children := countPGChildren(t, pool)

	db, err := postgres.Open(ctx, pgContainerDSN, postgres.PoolConfig{MaxConns: 5}, observability.NewNoop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate 013 → 014: %v", err)
	}

	want := map[string][]string{}
	for id, row := range before {
		want[id] = append([]string(nil), row...)
	}
	want["fed-noemail"][1] = "NULL"
	if got := dumpPGUsers(t, pool); !reflect.DeepEqual(got, want) {
		t.Errorf("users after 014:\n got %v\nwant %v", got, want)
	}
	if got := countPGChildren(t, pool); got != children {
		t.Errorf("child rows after 014: %d, want %d", got, children)
	}
	var nullable string
	if err := pool.QueryRow(ctx,
		`SELECT is_nullable FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email'`).Scan(&nullable); err != nil || nullable != "YES" {
		t.Errorf("users.email is_nullable = %q (%v), want YES", nullable, err)
	}
	for _, id := range []string{"n1", "n2"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, email, provider, provider_sub, created_at, updated_at) VALUES ($1, NULL, 'oidc', $1, NOW(), NOW())`, id); err != nil {
			t.Fatalf("insert email-less user %s: %v", id, err)
		}
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, created_at, updated_at) VALUES ('dup', 'a@corp.example', NOW(), NOW())`); err == nil {
		t.Error("duplicate present email accepted after 014")
	}

	downSQL, err := migrations.Migrations.ReadFile("014_user_email_nullable.down.sql")
	if err != nil {
		t.Fatalf("read down: %v", err)
	}
	applyDown := func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(downSQL)); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		return tx.Commit(ctx)
	}

	// Three email-less users: down cannot restore UNIQUE NOT NULL.
	withThree := dumpPGUsers(t, pool)
	if err := applyDown(); err == nil {
		t.Fatal("down succeeded with three email-less users")
	}
	if got := dumpPGUsers(t, pool); !reflect.DeepEqual(got, withThree) {
		t.Errorf("failed down changed users")
	}

	// Back to one: down restores the 013 shape and the '' email.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id IN ('n1', 'n2')`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := applyDown(); err != nil {
		t.Fatalf("down with one email-less user: %v", err)
	}
	if got := dumpPGUsers(t, pool); !reflect.DeepEqual(got, before) {
		t.Errorf("users after up+down:\n got %v\nwant %v", got, before)
	}
	if err := pool.QueryRow(ctx,
		`SELECT is_nullable FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email'`).Scan(&nullable); err != nil || nullable != "NO" {
		t.Errorf("users.email is_nullable after down = %q (%v), want NO", nullable, err)
	}

	// Leave the shared database fully migrated for the rest of the suite.
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 14`); err != nil {
		t.Fatalf("forget 014: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("re-apply 014: %v", err)
	}
}

// pgAt013 resets the shared container database and migrates it through 013
// only — the state a v0.2.1 install is in before upgrading. The final
// db.Migrate in the caller brings it back to the fully migrated schema the
// rest of the suite expects.
func pgAt013(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgContainerDSN)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	downSQL, err := migrations.Migrations.ReadFile("001_initial.down.sql")
	if err != nil {
		t.Fatalf("read 001 down: %v", err)
	}
	if _, err := pool.Exec(ctx, string(downSQL)); err != nil {
		t.Fatalf("pre-clean down: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations`); err != nil {
		t.Fatalf("clear schema_migrations: %v", err)
	}

	entries, err := fs.ReadDir(migrations.Migrations, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	type mig struct {
		v    int
		name string
	}
	var ups []mig
	for _, e := range entries {
		var v int
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err != nil || v > 13 {
			continue
		}
		ups = append(ups, mig{v, e.Name()})
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].v < ups[j].v })
	for _, m := range ups {
		data, _ := fs.ReadFile(migrations.Migrations, m.name)
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			t.Fatalf("apply %s: %v", m.name, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.v); err != nil {
			t.Fatalf("record %d: %v", m.v, err)
		}
	}
	return pool
}

func seedPG014Fixture(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO users (id, email, name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at) VALUES
			('local-a', 'a@corp.example', 'Alice', '$2a$12$hashA', 'admin', 'active', 'local', '', 3, '2026-01-01T00:00:00.123456Z', '2026-02-01T00:00:00Z'),
			('local-b', 'b@corp.example', '', '$2a$12$hashB', 'user', 'disabled', 'local', '', 1, '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z'),
			('fed-email', 'f@corp.example', 'Fed', '', 'user', 'active', 'oidc', 'okta-1', 5, '2026-01-03T00:00:00Z', '2026-03-01T00:00:00Z'),
			('fed-noemail', '', 'No Mail', '', 'user', 'active', 'oidc', 'okta-2', 2, '2026-01-04T00:00:00Z', '2026-01-05T00:00:00Z')`,
		`INSERT INTO clients (id, issued_at, updated_at) VALUES ('c1', NOW(), NOW())`,
	}
	for _, id := range []string{"local-a", "local-b", "fed-email", "fed-noemail"} {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO token_families (id, client_id, user_id, created_at) VALUES ('tf-%s', 'c1', '%s', NOW())`, id, id))
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}
}

// dumpPGUsers returns every users row keyed by id, each column rendered as
// text with NULL spelled "NULL" so it stays distinct from the empty string.
func dumpPGUsers(t *testing.T, pool *pgxpool.Pool) map[string][]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT id,
		COALESCE(quote_literal(email), 'NULL'), quote_literal(name), quote_literal(password_hash),
		role, status, provider, quote_literal(provider_sub), version::text, created_at::text, updated_at::text
		FROM users`)
	if err != nil {
		t.Fatalf("dump users: %v", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		r := make([]string, 11)
		ptrs := make([]any, 11)
		for i := range r {
			ptrs[i] = &r[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[r[0]] = r
	}
	return out
}

func countPGChildren(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM token_families`).Scan(&n); err != nil {
		t.Fatalf("count children: %v", err)
	}
	return n
}
