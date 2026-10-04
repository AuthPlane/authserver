//go:build integration

package sqlite_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"reflect"
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

// 014 rebuilds users to make email nullable. The upgrade has to keep every
// row and column, keep every child row (a DROP TABLE with foreign keys on
// would cascade-delete them), leave foreign keys enforced afterwards, and
// let any number of users have no email while a present one stays unique.
func TestMigration014_UpgradeFrom013PreservesUsersAndChildren(t *testing.T) {
	ctx := context.Background()
	db := openAt013(t)

	seed014Fixture(t, db.DB)
	before := dumpUsers(t, db.DB)
	shapeAt013 := tableInfo(t, db.DB, "users")
	children := countChildren(t, db.DB)

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate 013 → 014: %v", err)
	}

	// Every row and column survives; the only change is a federated user's
	// '' email becoming NULL.
	want := map[string][]string{}
	for id, row := range before {
		want[id] = append([]string(nil), row...)
	}
	want["fed-noemail"][1] = "NULL"
	if got := dumpUsers(t, db.DB); !reflect.DeepEqual(got, want) {
		t.Errorf("users after 014:\n got %v\nwant %v", got, want)
	}
	if got := countChildren(t, db.DB); got != children {
		t.Errorf("child rows after 014: %d, want %d (rebuild cascaded)", got, children)
	}

	var fk int
	if err := db.DB.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys after migrate = %d (%v), want 1", fk, err)
	}
	for _, idx := range []string{"idx_users_provider_sub", "idx_users_created_at"} {
		var n int
		_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n)
		if n != 1 {
			t.Errorf("index %s missing after 014", idx)
		}
	}
	// Child FKs still point at users and are enforced.
	if _, err := db.DB.ExecContext(ctx,
		`INSERT INTO token_families (id, client_id, user_id, created_at) VALUES ('tf-ghost', 'c1', 'no-such-user', '2026-01-01T00:00:00Z')`); err == nil {
		t.Error("token_families accepted a user_id with no users row: FK lost in rebuild")
	}
	// Deleting a user still cascades to its children.
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM users WHERE id = 'local-b'`); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var orphan int
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_families WHERE user_id = 'local-b'`).Scan(&orphan)
	if orphan != 0 {
		t.Error("ON DELETE CASCADE from users lost in rebuild")
	}

	// New shape: email nullable, NULLs distinct, present emails unique.
	for _, ins := range []string{
		`INSERT INTO users (id, email, provider, provider_sub, created_at, updated_at) VALUES ('n1', NULL, 'oidc', 'x1', 't', 't')`,
		`INSERT INTO users (id, email, provider, provider_sub, created_at, updated_at) VALUES ('n2', NULL, 'oidc', 'x2', 't', 't')`,
	} {
		if _, err := db.DB.ExecContext(ctx, ins); err != nil {
			t.Fatalf("insert email-less user: %v", err)
		}
	}
	if _, err := db.DB.ExecContext(ctx,
		`INSERT INTO users (id, email, created_at, updated_at) VALUES ('dup', 'a@corp.example', 't', 't')`); err == nil {
		t.Error("duplicate present email accepted after 014")
	}

	// Apart from email's NOT NULL, the column set is what 013 had.
	after := tableInfo(t, db.DB, "users")
	for i := range shapeAt013 {
		if shapeAt013[i].name == "email" {
			shapeAt013[i].notNull = 0
		}
	}
	if !reflect.DeepEqual(after, shapeAt013) {
		t.Errorf("users columns after 014:\n got %+v\nwant %+v", after, shapeAt013)
	}
}

// The down migration restores the 013 shape when at most one user has no
// email, and refuses (leaving the schema as is) when two or more do.
func TestMigration014_Down(t *testing.T) {
	ctx := context.Background()
	downSQL, err := migrations.Migrations.ReadFile("014_user_email_nullable.down.sql")
	if err != nil {
		t.Fatalf("read down: %v", err)
	}
	applyDown := func(db *sql.DB) error {
		if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return err
		}
		defer func() { _, _ = db.ExecContext(ctx, `PRAGMA foreign_keys = ON`) }()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(downSQL)); err != nil {
			_ = tx.Rollback()
			return err
		}
		return tx.Commit()
	}

	t.Run("OneEmailless_RestoresShape", func(t *testing.T) {
		db := openAt013(t)
		seed014Fixture(t, db.DB)
		shapeAt013 := tableInfo(t, db.DB, "users")
		before := dumpUsers(t, db.DB)
		children := countChildren(t, db.DB)
		if err := db.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if err := applyDown(db.DB); err != nil {
			t.Fatalf("down: %v", err)
		}
		if got := tableInfo(t, db.DB, "users"); !reflect.DeepEqual(got, shapeAt013) {
			t.Errorf("users columns after down:\n got %+v\nwant %+v", got, shapeAt013)
		}
		if got := dumpUsers(t, db.DB); !reflect.DeepEqual(got, before) {
			t.Errorf("users after up+down:\n got %v\nwant %v", got, before)
		}
		if got := countChildren(t, db.DB); got != children {
			t.Errorf("child rows after down: %d, want %d", got, children)
		}
	})

	t.Run("TwoEmailless_Refuses", func(t *testing.T) {
		db := openAt013(t)
		seed014Fixture(t, db.DB)
		if err := db.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if _, err := db.DB.ExecContext(ctx,
			`INSERT INTO users (id, email, provider, provider_sub, created_at, updated_at) VALUES ('n2', NULL, 'oidc', 'x2', 't', 't')`); err != nil {
			t.Fatalf("insert second email-less user: %v", err)
		}
		before := dumpUsers(t, db.DB)
		if err := applyDown(db.DB); err == nil {
			t.Fatal("down succeeded with two email-less users; it cannot restore UNIQUE NOT NULL")
		}
		if got := dumpUsers(t, db.DB); !reflect.DeepEqual(got, before) {
			t.Errorf("failed down changed users:\n got %v\nwant %v", got, before)
		}
	})
}

// openAt013 returns an in-memory database migrated through 013 only — the
// state a v0.2.1 install is in before upgrading.
func openAt013(t *testing.T) *sqlite.DB {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(":memory:", observability.NewNoop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.DB.ExecContext(ctx, `CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')))`); err != nil {
		t.Fatalf("schema_migrations: %v", err)
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
		if _, err := db.DB.ExecContext(ctx, string(data)); err != nil {
			t.Fatalf("apply %s: %v", m.name, err)
		}
		if _, err := db.DB.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, m.v); err != nil {
			t.Fatalf("record %d: %v", m.v, err)
		}
	}
	return db
}

// seed014Fixture writes local and federated users (one federated user with
// the empty-string email the pre-014 code stored for a missing claim) and rows in
// every table that cascades from users.
func seed014Fixture(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO users (id, email, name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at) VALUES
			('local-a', 'a@corp.example', 'Alice', '$2a$12$hashA', 'admin', 'active', 'local', '', 3, '2026-01-01T00:00:00.123456789Z', '2026-02-01T00:00:00Z'),
			('local-b', 'b@corp.example', '', '$2a$12$hashB', 'user', 'disabled', 'local', '', 1, '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z'),
			('fed-email', 'f@corp.example', 'Fed', '', 'user', 'active', 'oidc', 'okta-1', 5, '2026-01-03T00:00:00Z', '2026-03-01T00:00:00Z'),
			('fed-noemail', '', 'No Mail', '', 'user', 'active', 'oidc', 'okta-2', 2, '2026-01-04T00:00:00Z', '2026-01-05T00:00:00Z')`,
		`INSERT INTO clients (id, issued_at, updated_at) VALUES ('c1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		`INSERT INTO resources (id, slug, display_name, uri, backend_kind, created_at, updated_at) VALUES ('r1', 'r1', 'r1', 'https://r1.example/mcp', 'mint', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		`INSERT INTO broker_providers (id, slug, display_name, protocol, created_at, updated_at) VALUES ('p1', 'p1', 'p1', 'oauth', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	}
	for _, id := range []string{"local-a", "local-b", "fed-email", "fed-noemail"} {
		stmts = append(stmts,
			fmt.Sprintf(`INSERT INTO token_families (id, client_id, user_id, created_at) VALUES ('tf-%s', 'c1', '%s', '2026-01-01T00:00:00Z')`, id, id),
			fmt.Sprintf(`INSERT INTO consent_grants (id, user_id, client_id, resource_id, created_at, updated_at) VALUES ('cg-%s', '%s', 'c1', 'r1', 't', 't')`, id, id),
			fmt.Sprintf(`INSERT INTO broker_grants (id, user_id, broker_provider_id, credential_data, enc_backend, created_at, updated_at) VALUES ('bg-%s', '%s', 'p1', x'00', 'aes', 't', 't')`, id, id),
		)
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}
}

// dumpUsers returns every users row keyed by id, each column rendered with
// quote() so NULL and the empty string stay distinguishable.
func dumpUsers(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT id, quote(email), quote(name), quote(password_hash),
		quote(role), quote(status), quote(provider), quote(provider_sub), quote(version), quote(created_at), quote(updated_at)
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

func countChildren(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT
		(SELECT COUNT(*) FROM token_families) + (SELECT COUNT(*) FROM consent_grants) + (SELECT COUNT(*) FROM broker_grants)`).Scan(&n); err != nil {
		t.Fatalf("count children: %v", err)
	}
	return n
}

type colInfo struct {
	cid     int
	name    string
	typ     string
	notNull int
	dflt    sql.NullString
	pk      int
}

func tableInfo(t *testing.T, db *sql.DB, table string) []colInfo {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT cid, name, type, "notnull", dflt_value, pk FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	var out []colInfo
	for rows.Next() {
		var c colInfo
		if err := rows.Scan(&c.cid, &c.name, &c.typ, &c.notNull, &c.dflt, &c.pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, c)
	}
	return out
}

// 016 keeps refresh for clients stored before the refresh_token grant was
// enforced: an exact ["authorization_code"] gains refresh_token, every other
// list is left as stored.
func TestMigration016_BackfillsRefreshGrant(t *testing.T) {
	ctx := context.Background()
	db := openAt013(t)

	stored := map[string]string{
		"authcode-only": `["authorization_code"]`,
		"both":          `["authorization_code","refresh_token"]`,
		"machine":       `["client_credentials"]`,
		"mixed":         `["authorization_code","client_credentials"]`,
	}
	for id, gt := range stored {
		if _, err := db.DB.ExecContext(ctx, `INSERT INTO clients (id, grant_types, issued_at, updated_at)
			VALUES (?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, id, gt); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	want := map[string]string{
		"authcode-only": `["authorization_code","refresh_token"]`,
		"both":          stored["both"],
		"machine":       stored["machine"],
		"mixed":         stored["mixed"],
	}
	for id, w := range want {
		var got string
		if err := db.DB.QueryRowContext(ctx, `SELECT grant_types FROM clients WHERE id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if got != w {
			t.Errorf("%s grant_types = %s, want %s", id, got, w)
		}
	}
}
