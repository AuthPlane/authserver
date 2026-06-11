package testdata

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/ports/output"
)

// newTestFamily returns a minimal valid TokenFamily for use in tests.
func newTestFamily(id string) *token.Family {
	return &token.Family{
		ID:        id,
		ClientID:  "client-1",
		UserID:    "user-1",
		Scope:     "tools/query",
		Resource:  "https://mcp.example.com",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
}

// newTestRefreshToken returns a minimal valid RefreshToken for use in tests.
func newTestRefreshToken(id, familyID, hash string) *token.RefreshToken {
	return &token.RefreshToken{
		ID:        id,
		FamilyID:  familyID,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
}

// RunTokenStoreTests runs the full TokenStore test suite (excluding CascadeDelete,
// which requires raw DB access and lives in adapter-specific test files).
// newStores is called once per subtest to provide a fresh, isolated trio.
// Client + User stores are needed to seed the parent rows that the
// token_families.client_id / user_id FKs point at.
func RunTokenStoreTests(t *testing.T, newStores func(*testing.T) (output.TokenStore, output.ClientStore, output.UserStore)) {
	t.Helper()

	// Seed the canonical client-1 / user-1 rows that newTestFamily references.
	seedFKParents := func(t *testing.T, cs output.ClientStore, us output.UserStore) {
		t.Helper()
		ctx := context.Background()
		if err := cs.Create(ctx, newTestClient("client-1")); err != nil {
			t.Fatalf("seed client-1: %v", err)
		}
		if err := us.Create(ctx, newTestUser("user-1", "user-1@test.com")); err != nil {
			t.Fatalf("seed user-1: %v", err)
		}
	}

	t.Run("CreateFamilyAndGet", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-1")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		got, err := store.GetFamily(ctx, "fam-1")
		if err != nil {
			t.Fatalf("get family: %v", err)
		}
		if got.ClientID != "client-1" {
			t.Errorf("client_id: got %q, want %q", got.ClientID, "client-1")
		}
		if got.Status != token.FamilyActive {
			t.Errorf("status: got %q, want %q", got.Status, token.FamilyActive)
		}
		if got.RevokedAt != nil {
			t.Errorf("revoked_at: expected nil, got %v", got.RevokedAt)
		}
	})

	t.Run("GetFamily_NotFound", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		_, err := store.GetFamily(ctx, "nonexistent")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("CreateRefreshTokenAndGetByHash", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-rt")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		rt := newTestRefreshToken("rt-1", "fam-rt", "hash-rt-1")
		if err := store.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}

		got, err := store.GetRefreshTokenByHash(ctx, "hash-rt-1")
		if err != nil {
			t.Fatalf("get by hash: %v", err)
		}
		if got.ID != "rt-1" {
			t.Errorf("id: got %q, want %q", got.ID, "rt-1")
		}
		if got.FamilyID != "fam-rt" {
			t.Errorf("family_id: got %q, want %q", got.FamilyID, "fam-rt")
		}
		if got.ConsumedAt != nil {
			t.Errorf("consumed_at: expected nil, got %v", got.ConsumedAt)
		}
	})

	t.Run("GetRefreshTokenByHash_NotFound", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		_, err := store.GetRefreshTokenByHash(ctx, "nonexistent")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("ConsumeRefreshToken", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-consume")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		rt := newTestRefreshToken("rt-consume", "fam-consume", "hash-consume")
		if err := store.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}

		got, err := store.ConsumeRefreshToken(ctx, "rt-consume")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if got.ConsumedAt == nil {
			t.Fatal("expected consumed_at to be set after first consume")
		}
	})

	t.Run("ConsumeRefreshToken_ReuseDetection", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-reuse")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		rt := newTestRefreshToken("rt-reuse", "fam-reuse", "hash-reuse")
		if err := store.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}

		// First consume sets consumed_at.
		first, err := store.ConsumeRefreshToken(ctx, "rt-reuse")
		if err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if first.ConsumedAt == nil {
			t.Fatal("first consume: expected consumed_at set")
		}

		// Second consume returns ErrRefreshTokenReused (atomic TOCTOU fix).
		_, err = store.ConsumeRefreshToken(ctx, "rt-reuse")
		if !errors.Is(err, domain.ErrRefreshTokenReused) {
			t.Fatalf("second consume should return ErrRefreshTokenReused, got: %v", err)
		}
	})

	t.Run("ConsumeRefreshToken_NotFound", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		_, err := store.ConsumeRefreshToken(ctx, "nonexistent")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-revoke")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		for i := 0; i < 3; i++ {
			rt := newTestRefreshToken(
				fmt.Sprintf("rt-rev-%d", i),
				"fam-revoke",
				fmt.Sprintf("hash-rev-%d", i),
			)
			if err := store.CreateRefreshToken(ctx, rt); err != nil {
				t.Fatalf("create refresh token %d: %v", i, err)
			}
		}

		// Consume one (simulating normal rotation).
		if _, err := store.ConsumeRefreshToken(ctx, "rt-rev-0"); err != nil {
			t.Fatalf("consume rt-0: %v", err)
		}

		if err := store.RevokeFamily(ctx, "fam-revoke"); err != nil {
			t.Fatalf("revoke family: %v", err)
		}

		fam, err := store.GetFamily(ctx, "fam-revoke")
		if err != nil {
			t.Fatalf("get family after revoke: %v", err)
		}
		if fam.Status != token.FamilyRevoked {
			t.Errorf("family status: got %q, want %q", fam.Status, token.FamilyRevoked)
		}
		if fam.RevokedAt == nil {
			t.Error("family revoked_at: expected non-nil")
		}

		// All unconsumed tokens should now be consumed.
		for i := 1; i < 3; i++ {
			rt, err := store.GetRefreshTokenByHash(ctx, fmt.Sprintf("hash-rev-%d", i))
			if err != nil {
				t.Fatalf("get rt-%d after revoke: %v", i, err)
			}
			if rt.ConsumedAt == nil {
				t.Errorf("rt-%d: expected consumed_at set after family revocation", i)
			}
		}
	})

	t.Run("RevokeFamily_Idempotent", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-idem")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		if err := store.RevokeFamily(ctx, "fam-idem"); err != nil {
			t.Fatalf("first revoke: %v", err)
		}
		if err := store.RevokeFamily(ctx, "fam-idem"); err != nil {
			t.Fatalf("second revoke (should be no-op): %v", err)
		}
	})

	t.Run("PurgeExpired", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		f := newTestFamily("fam-purge")
		if err := store.CreateFamily(ctx, f); err != nil {
			t.Fatalf("create family: %v", err)
		}

		now := time.Now().UTC()
		past := now.Add(-1 * time.Hour)
		future := now.Add(1 * time.Hour)
		pastConsumed := now.Add(-30 * time.Minute)
		recentConsumed := now.Add(-1 * time.Minute)

		rows := []*token.RefreshToken{
			// Expired + consumed → deleted
			{ID: "rt-exp-cons", FamilyID: "fam-purge", TokenHash: "hash-exp-cons",
				ExpiresAt: past, ConsumedAt: &pastConsumed, CreatedAt: past.Add(-time.Hour)},
			// Expired + unconsumed → deleted
			{ID: "rt-exp-unc", FamilyID: "fam-purge", TokenHash: "hash-exp-unc",
				ExpiresAt: past, CreatedAt: past.Add(-time.Hour)},
			// Active + consumed → retained
			{ID: "rt-act-cons", FamilyID: "fam-purge", TokenHash: "hash-act-cons",
				ExpiresAt: future, ConsumedAt: &recentConsumed, CreatedAt: now.Add(-10 * time.Minute)},
			// Active + unconsumed → retained
			{ID: "rt-act-unc", FamilyID: "fam-purge", TokenHash: "hash-act-unc",
				ExpiresAt: future, CreatedAt: now.Add(-10 * time.Minute)},
		}
		for _, rt := range rows {
			if err := store.CreateRefreshToken(ctx, rt); err != nil {
				t.Fatalf("create %s: %v", rt.ID, err)
			}
		}

		n, err := store.PurgeExpired(ctx)
		if err != nil {
			t.Fatalf("purge expired: %v", err)
		}
		if n != 2 {
			t.Errorf("purge count: got %d, want 2", n)
		}

		// Deleted rows
		for _, hash := range []string{"hash-exp-cons", "hash-exp-unc"} {
			if _, err := store.GetRefreshTokenByHash(ctx, hash); !errors.Is(err, domain.ErrInvalidGrant) {
				t.Errorf("%s: expected ErrInvalidGrant after purge, got %v", hash, err)
			}
		}
		// Retained rows
		for _, hash := range []string{"hash-act-cons", "hash-act-unc"} {
			if _, err := store.GetRefreshTokenByHash(ctx, hash); err != nil {
				t.Errorf("%s: expected retained, got %v", hash, err)
			}
		}
	})

	t.Run("PurgeExpired_Empty", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		n, err := store.PurgeExpired(ctx)
		if err != nil {
			t.Fatalf("purge expired: %v", err)
		}
		if n != 0 {
			t.Errorf("purge count on empty: got %d, want 0", n)
		}
	})

	t.Run("CountIssuedSince", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		base := time.Now().UTC().Add(-time.Hour)
		for i := 0; i < 3; i++ {
			f := newTestFamily(fmt.Sprintf("fam-cnt-%d", i))
			f.CreatedAt = base.Add(time.Duration(i) * 20 * time.Minute)
			if err := store.CreateFamily(ctx, f); err != nil {
				t.Fatalf("create family %d: %v", i, err)
			}
		}

		count, err := store.CountIssuedSince(ctx, base.Add(10*time.Minute).Unix())
		if err != nil {
			t.Fatalf("count issued since: %v", err)
		}
		if count != 2 {
			t.Errorf("count: got %d, want 2", count)
		}
	})

	t.Run("CountRevokedSince", func(t *testing.T) {
		store, clients, users := newStores(t)
		seedFKParents(t, clients, users)
		ctx := context.Background()

		for i := 0; i < 3; i++ {
			f := newTestFamily(fmt.Sprintf("fam-rcnt-%d", i))
			if err := store.CreateFamily(ctx, f); err != nil {
				t.Fatalf("create family %d: %v", i, err)
			}
		}

		since := time.Now().UTC().Add(-time.Minute)

		for i := 0; i < 2; i++ {
			if err := store.RevokeFamily(ctx, fmt.Sprintf("fam-rcnt-%d", i)); err != nil {
				t.Fatalf("revoke %d: %v", i, err)
			}
		}

		count, err := store.CountRevokedSince(ctx, since.Unix())
		if err != nil {
			t.Fatalf("count revoked since: %v", err)
		}
		if count != 2 {
			t.Errorf("count: got %d, want 2", count)
		}
	})
}
