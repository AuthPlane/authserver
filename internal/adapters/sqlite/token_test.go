//go:build integration

package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestTokenStore(t *testing.T) {
	testdata.RunTokenStoreTests(t, func(t *testing.T) (output.TokenStore, output.ClientStore, output.UserStore) {
		s := testdata.SetupTestStores(t)
		return s.Token, s.Client, s.User
	})
}

// TestTokenStore_CascadeDelete verifies the ON DELETE CASCADE FK constraint
// by deleting a token_family directly via raw SQL. This test requires raw
// DB access and cannot be expressed through the TokenStore interface alone.
func TestTokenStore_CascadeDelete(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	testdata.SeedClientAndUser(t, stores.Client, stores.User, "client-1", "user-1")

	f := &token.Family{
		ID:        "fam-cascade",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scope:     "tools/query",
		Resource:  "https://mcp.example.com",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := stores.Token.CreateFamily(ctx, f); err != nil {
		t.Fatalf("create family: %v", err)
	}

	rt := &token.RefreshToken{
		ID:        "rt-cascade",
		FamilyID:  "fam-cascade",
		TokenHash: "hash-cascade",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := stores.Token.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	// Delete family directly — refresh tokens should cascade.
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM token_families WHERE id = ?`, "fam-cascade"); err != nil {
		t.Fatalf("delete family: %v", err)
	}

	_, err := stores.Token.GetRefreshTokenByHash(ctx, "hash-cascade")
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant after cascade delete, got %v", err)
	}
}

// TestRevocationStore_JTICascadeDelete verifies that access_token_jtis rows
// are removed automatically when their parent token_family is deleted.
func TestRevocationStore_JTICascadeDelete(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	testdata.SeedClientAndUser(t, stores.Client, stores.User, "client-1", "user-1")

	f := &token.Family{
		ID:        "fam-jti-cascade",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scope:     "tools/query",
		Resource:  "https://mcp.example.com",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := stores.Token.CreateFamily(ctx, f); err != nil {
		t.Fatalf("create family: %v", err)
	}

	if err := stores.Revocation.TrackJTI(ctx, "jti-cascade", "fam-jti-cascade",
		time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("track jti: %v", err)
	}

	if _, err := db.DB.ExecContext(ctx, `DELETE FROM token_families WHERE id = ?`, "fam-jti-cascade"); err != nil {
		t.Fatalf("delete family: %v", err)
	}

	var count int
	if err := db.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM access_token_jtis WHERE jti = ?`, "jti-cascade").Scan(&count); err != nil {
		t.Fatalf("query jti: %v", err)
	}
	if count != 0 {
		t.Errorf("expected jti to be cascade-deleted, found %d rows", count)
	}
}

// TestTokenFamily_CascadeFromClient verifies that deleting a
// parent clients row cascades to remove its token_families and any
// downstream refresh_tokens / access_token_jtis. This is the belt-and-
// suspenders cleanup the FK provides for code paths that bypass
// AdminService.DeleteClient's explicit revoke step.
func TestTokenFamily_CascadeFromClient(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	testdata.SeedClientAndUser(t, stores.Client, stores.User, "fk-cli-client", "fk-cli-user")

	f := &token.Family{
		ID:        "fam-fk-cli",
		ClientID:  "fk-cli-client",
		UserID:    "fk-cli-user",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := stores.Token.CreateFamily(ctx, f); err != nil {
		t.Fatalf("create family: %v", err)
	}
	rt := &token.RefreshToken{
		ID: "rt-fk-cli", FamilyID: "fam-fk-cli", TokenHash: "hash-fk-cli",
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := stores.Token.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	if _, err := db.DB.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, "fk-cli-client"); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	if _, err := stores.Token.GetFamily(ctx, "fam-fk-cli"); !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("family: expected ErrInvalidGrant after cascade, got %v", err)
	}
	if _, err := stores.Token.GetRefreshTokenByHash(ctx, "hash-fk-cli"); !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("refresh token: expected ErrInvalidGrant after cascade, got %v", err)
	}
}

// TestTokenFamily_CascadeFromUser verifies the symmetric cascade
// from users → token_families.
func TestTokenFamily_CascadeFromUser(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	testdata.SeedClientAndUser(t, stores.Client, stores.User, "fk-usr-client", "fk-usr-user")

	f := &token.Family{
		ID:        "fam-fk-usr",
		ClientID:  "fk-usr-client",
		UserID:    "fk-usr-user",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := stores.Token.CreateFamily(ctx, f); err != nil {
		t.Fatalf("create family: %v", err)
	}

	if _, err := db.DB.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, "fk-usr-user"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	if _, err := stores.Token.GetFamily(ctx, "fam-fk-usr"); !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("family: expected ErrInvalidGrant after cascade, got %v", err)
	}
}

// TestTokenFamily_FKViolation verifies the DB rejects inserting
// a token_family whose client_id or user_id has no parent row.
func TestTokenFamily_FKViolation(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	// Seed only a user, leave client_id orphan.
	testdata.EnsureUser(t, stores.User, "fk-violation-user")

	err := stores.Token.CreateFamily(ctx, &token.Family{
		ID:        "fam-fk-bad-client",
		ClientID:  "no-such-client",
		UserID:    "fk-violation-user",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	})
	assertFKViolation(t, err, "missing client_id")

	// Seed only a client, leave user_id orphan.
	testdata.EnsureClient(t, stores.Client, "fk-violation-client")
	err = stores.Token.CreateFamily(ctx, &token.Family{
		ID:        "fam-fk-bad-user",
		ClientID:  "fk-violation-client",
		UserID:    "no-such-user",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	})
	assertFKViolation(t, err, "missing user_id")
}

// assertFKViolation fails the test unless err is non-nil AND its message
// indicates a FK constraint violation. SQLite (modernc.org/sqlite) reports
// "FOREIGN KEY constraint failed"; bare-`err != nil` is too loose because
// it also passes for unrelated I/O errors.
func assertFKViolation(t *testing.T, err error, scenario string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected FK violation, got nil", scenario)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Errorf("%s: expected error mentioning foreign key, got: %v", scenario, err)
	}
}

// TestRevocationStore_JTIForeignKeyViolation verifies that inserting a JTI
// referencing a non-existent family fails with a FK constraint error.
func TestRevocationStore_JTIForeignKeyViolation(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	err := stores.Revocation.TrackJTI(ctx, "jti-orphan", "fam-does-not-exist",
		time.Now().UTC().Add(time.Hour))
	if err == nil {
		t.Fatal("expected FK violation, got nil")
	}
}
