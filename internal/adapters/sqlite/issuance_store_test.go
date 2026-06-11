//go:build integration

package sqlite_test

import (
	"context"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/testdata"
)

func TestIssuanceStore(t *testing.T) {
	testdata.RunIssuanceStoreTests(t, func(t *testing.T) testdata.IssuanceStoreSuiteDeps {
		db := testdata.SetupTestDB(t)
		stores := db.NewStores()
		return testdata.IssuanceStoreSuiteDeps{
			Issuances:        stores.Issuance,
			Resources:        stores.Resource,
			Users:            stores.User,
			ExplainQueryPlan: sqliteExplainer(db),
		}
	})
}

// sqliteExplainer returns a ExplainQueryPlan adapter that runs
// EXPLAIN QUERY PLAN against the underlying *sql.DB and joins the
// resulting "detail" column into a single string the suite greps for
// index names. Postgres-style $1/$2 placeholders are rewritten to
// SQLite-style ? on the way through so the suite's query is portable.
func sqliteExplainer(db *sqlite.DB) func(t *testing.T, query string, args ...any) string {
	return func(t *testing.T, query string, args ...any) string {
		t.Helper()
		ctx := context.Background()
		rows, err := db.DB.QueryContext(ctx, "EXPLAIN QUERY PLAN "+rewritePlaceholders(query), args...)
		if err != nil {
			t.Fatalf("explain query plan: %v", err)
		}
		defer func() { _ = rows.Close() }()
		var b strings.Builder
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				t.Fatalf("scan explain row: %v", err)
			}
			b.WriteString(detail)
			b.WriteByte('\n')
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate explain rows: %v", err)
		}
		return b.String()
	}
}

// rewritePlaceholders converts $1, $2, … sequences to ?. The numbering
// of pgx parameters is irrelevant for SQLite — it binds positionally.
func rewritePlaceholders(query string) string {
	out := query
	for n := 1; n <= 9; n++ {
		out = strings.ReplaceAll(out, fmtDollar(n), "?")
	}
	return out
}

func fmtDollar(n int) string { return "$" + string(rune('0'+n)) }
