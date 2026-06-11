//go:build integration_postgres

package postgres_test

import (
	"context"
	"strings"
	"testing"

	pgadapter "github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/testdata"
)

func TestIssuanceStore(t *testing.T) {
	testdata.RunIssuanceStoreTests(t, func(t *testing.T) testdata.IssuanceStoreSuiteDeps {
		db := testdata.SetupTestPGDB(t, pgContainerDSN)
		stores := db.NewStores()
		return testdata.IssuanceStoreSuiteDeps{
			Issuances:        stores.Issuance,
			Resources:        stores.Resource,
			Users:            stores.User,
			ExplainQueryPlan: postgresExplainer(db),
		}
	})
}

// postgresExplainer returns an ExplainQueryPlan adapter that runs
// EXPLAIN against the pgx pool and joins every plan-tree line into a
// single lower-cased string the suite greps for index names.
func postgresExplainer(db *pgadapter.DB) func(t *testing.T, query string, args ...any) string {
	return func(t *testing.T, query string, args ...any) string {
		t.Helper()
		ctx := context.Background()
		rows, err := db.Pool.Query(ctx, "EXPLAIN "+query, args...)
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		defer rows.Close()
		var b strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatalf("scan explain row: %v", err)
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate explain rows: %v", err)
		}
		return b.String()
	}
}
