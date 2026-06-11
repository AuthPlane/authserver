// Package testdata provides test infrastructure for integration tests.
package testdata

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// TestHelper provides access to stores for test setup.
type TestHelper struct {
	Stores *sqlite.Stores
}

// SetupTestDB creates an in-memory SQLite database with migrations applied.
// It registers cleanup to close the DB when the test completes.
func SetupTestDB(t *testing.T) *sqlite.DB {
	t.Helper()

	obs := testProvider()
	db, err := sqlite.Open(":memory:", obs)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatalf("migrate test db: %v", err)
	}

	t.Cleanup(func() { db.Close() })
	return db
}

// SetupTestStores creates an in-memory SQLite database and returns all stores.
func SetupTestStores(t *testing.T) *sqlite.Stores {
	t.Helper()
	return SetupTestDB(t).NewStores()
}

func testProvider() *observability.Provider {
	return observability.NewNoop()
}

// SeedClientAndUser creates a minimal client and user with the given IDs.
// Required by tests that insert token_families rows directly (:
// token_families.client_id and user_id are now FK-enforced).
func SeedClientAndUser(t *testing.T, cs output.ClientStore, us output.UserStore, clientID, userID string) {
	t.Helper()
	ctx := context.Background()
	if err := cs.Create(ctx, newTestClient(clientID)); err != nil {
		t.Fatalf("seed client %q: %v", clientID, err)
	}
	if err := us.Create(ctx, newTestUser(userID, userID+"@test.com")); err != nil {
		t.Fatalf("seed user %q: %v", userID, err)
	}
}

// EnsureClient idempotently creates a client with the given ID.
// helper for tests that need a parent client for token_families/machine_tokens
// FKs but may not know whether a previous step already seeded it.
func EnsureClient(t *testing.T, cs output.ClientStore, id string) {
	t.Helper()
	ctx := context.Background()
	if got, _ := cs.GetByID(ctx, id); got != nil {
		return
	}
	if err := cs.Create(ctx, newTestClient(id)); err != nil {
		t.Fatalf("ensure client %q: %v", id, err)
	}
}

// EnsureUser idempotently creates a user with the given ID. helper.
func EnsureUser(t *testing.T, us output.UserStore, id string) {
	t.Helper()
	ctx := context.Background()
	if got, _ := us.GetByID(ctx, id); got != nil {
		return
	}
	// Email must be unique; derive it from the ID so independent EnsureUser
	// calls in the same test database do not collide.
	if err := us.Create(ctx, newTestUser(id, id+"@test.com")); err != nil {
		t.Fatalf("ensure user %q: %v", id, err)
	}
}
