//go:build integration_postgres

package testdata

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pgadapter "github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/internal/observability"
)

// nonAlphaNum matches any character that is not a-z or 0-9.
var nonAlphaNum = regexp.MustCompile(`[^a-z0-9]`)

// pgTestDBName derives a short, valid PostgreSQL identifier from a test name.
// The result is at most 63 characters (PostgreSQL identifier limit).
func pgTestDBName(testName string) string {
	// Use SHA-256 to get a deterministic, short unique name.
	h := sha256.Sum256([]byte(testName))
	return fmt.Sprintf("t%x", h[:8]) // "t" + 16 hex chars = 17 chars
}

// sanitizeLabel makes a human-readable suffix from the test name for debug clarity.
// Not used as the actual DB name (too long); kept for logging.
func sanitizeLabel(name string) string {
	s := strings.ToLower(name)
	s = nonAlphaNum.ReplaceAllString(s, "_")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// SetupTestPGDB creates a fresh PostgreSQL database in the test container,
// runs all migrations, and returns a *postgres.DB backed by that database.
// The database is dropped when the test completes (via t.Cleanup).
//
// baseDSN must point to the container's admin database (typically the one
// returned by container.ConnectionString in TestMain).
func SetupTestPGDB(t *testing.T, baseDSN string) *pgadapter.DB {
	t.Helper()
	ctx := context.Background()

	dbName := pgTestDBName(t.Name())

	// Admin pool: connected to the base (container) database.
	adminPool, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("setup pg: admin pool: %v", err)
	}

	// Drop first in case a previous run left it (e.g., test crashed).
	_, _ = adminPool.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize())

	if _, err := adminPool.Exec(ctx,
		"CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize(),
	); err != nil {
		adminPool.Close()
		t.Fatalf("setup pg: create database %q: %v", dbName, err)
	}
	adminPool.Close()

	// Build config pointing to the new database.
	cfg, err := pgxpool.ParseConfig(baseDSN)
	if err != nil {
		t.Fatalf("setup pg: parse config: %v", err)
	}
	cfg.ConnConfig.Database = dbName

	testPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("setup pg: open test pool: %v", err)
	}

	obs := observability.NewNoop()
	db := pgadapter.WrapPool(testPool, obs)

	if err := db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatalf("setup pg: migrate: %v", err)
	}

	t.Cleanup(func() {
		db.Close()

		// Drop the test database.
		dropPool, err := pgxpool.New(context.Background(), baseDSN)
		if err != nil {
			t.Logf("cleanup pg: open admin pool: %v", err)
			return
		}
		defer dropPool.Close()
		_, _ = dropPool.Exec(context.Background(),
			"DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize(),
		)
	})

	return db
}

// SetupTestPGStores creates a fresh PostgreSQL database and returns all stores.
// It is a convenience wrapper around SetupTestPGDB.
func SetupTestPGStores(t *testing.T, baseDSN string) *pgadapter.Stores {
	t.Helper()
	return SetupTestPGDB(t, baseDSN).NewStores()
}
