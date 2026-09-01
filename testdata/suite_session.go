package testdata

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/ports/output"
)

// newTestSession returns a minimal valid AuthSession for use in tests.
func newTestSession(id, codeHash string) *session.AuthSession {
	now := time.Now().UTC()
	return &session.AuthSession{
		ID:                  id,
		ClientID:            "client-1",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "random-state",
		CodeHash:            codeHash,
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
}

// RunSessionStoreTests runs the full SessionStore test suite.
// newStore is called once per subtest to provide a fresh, isolated store.
func RunSessionStoreTests(t *testing.T, newStore func(*testing.T) output.SessionStore) {
	t.Helper()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		s := newTestSession("sess-1", "hash-1")
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByID(ctx, "sess-1")
		if err != nil {
			t.Fatalf("get by id: %v", err)
		}
		if got.ClientID != "client-1" {
			t.Errorf("client_id: got %q, want %q", got.ClientID, "client-1")
		}
		if got.CodeHash != "hash-1" {
			t.Errorf("code_hash: got %q, want %q", got.CodeHash, "hash-1")
		}
		if got.ConsumedAt != nil {
			t.Errorf("consumed_at: expected nil, got %v", got.ConsumedAt)
		}
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.GetByID(ctx, "nonexistent")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("ConsumeByCodeHash", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		s := newTestSession("sess-consume", "hash-consume")
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.ConsumeByCodeHash(ctx, "hash-consume")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if got.ConsumedAt == nil {
			t.Fatal("expected consumed_at to be set")
		}
		if got.ID != "sess-consume" {
			t.Errorf("id: got %q, want %q", got.ID, "sess-consume")
		}
	})

	t.Run("ConsumeByCodeHash_AlreadyConsumed", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		s := newTestSession("sess-double", "hash-double")
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("create: %v", err)
		}

		if _, err := store.ConsumeByCodeHash(ctx, "hash-double"); err != nil {
			t.Fatalf("first consume: %v", err)
		}

		got, err := store.ConsumeByCodeHash(ctx, "hash-double")
		if !errors.Is(err, domain.ErrCodeConsumed) {
			t.Errorf("expected ErrCodeConsumed, got %v", err)
		}
		// The session comes back alongside the error so the caller can act on
		// the replay. This is not a non-consuming read: a fresh code
		// is always burned.
		if got == nil {
			t.Fatal("expected the consumed session alongside ErrCodeConsumed, got nil")
		}
		if got.ID != "sess-double" {
			t.Errorf("id: got %q, want %q", got.ID, "sess-double")
		}
		if got.CodeChallenge != "challenge-value" {
			t.Errorf("code_challenge: got %q, want %q", got.CodeChallenge, "challenge-value")
		}
	})

	t.Run("ConsumeByCodeHash_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.ConsumeByCodeHash(ctx, "nonexistent-hash")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("ConsumeByCodeHash_Concurrent", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		s := newTestSession("sess-conc", "hash-conc")
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("create: %v", err)
		}

		const goroutines = 10
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			successes int
			consumed  int
		)

		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := store.ConsumeByCodeHash(ctx, "hash-conc")
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					successes++
				} else if errors.Is(err, domain.ErrCodeConsumed) {
					consumed++
				} else {
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		wg.Wait()

		if successes != 1 {
			t.Errorf("expected exactly 1 success, got %d", successes)
		}
		if consumed != goroutines-1 {
			t.Errorf("expected %d ErrCodeConsumed, got %d", goroutines-1, consumed)
		}
	})

	t.Run("UpdateCodeHashAndScope_RefusedOnConsumedSession", func(t *testing.T) {
		// A session whose code has already been redeemed must never accept a
		// fresh code: that code could never be legitimately redeemed, and a
		// later "replay" of it would hand ExchangeCode's reuse path the
		// session's genuine PKCE verifier — treated as a credentialed replay
		// and revoking the tokens the first redemption issued. Regression
		// coverage for the UPDATE guard: WHERE ... AND consumed_at IS NULL.
		store := newStore(t)
		ctx := context.Background()

		s := newTestSession("sess-consumed-update", "hash-consumed-update")
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := store.ConsumeByCodeHash(ctx, "hash-consumed-update"); err != nil {
			t.Fatalf("consume: %v", err)
		}

		err := store.UpdateCodeHashAndScope(ctx, "sess-consumed-update", "new-hash", "tools/query")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant minting a code onto a consumed session, got %v", err)
		}

		// The consumed session must be left untouched: no new code_hash, no
		// scope narrowing.
		got, gerr := store.GetByID(ctx, "sess-consumed-update")
		if gerr != nil {
			t.Fatalf("re-read session: %v", gerr)
		}
		if got.CodeHash != "hash-consumed-update" {
			t.Errorf("code_hash mutated on a refused update: got %q", got.CodeHash)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		expired := newTestSession("sess-exp", "hash-exp")
		expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		if err := store.Create(ctx, expired); err != nil {
			t.Fatalf("create expired: %v", err)
		}

		valid := newTestSession("sess-valid", "hash-valid")
		if err := store.Create(ctx, valid); err != nil {
			t.Fatalf("create valid: %v", err)
		}

		n, err := store.DeleteExpired(ctx)
		if err != nil {
			t.Fatalf("delete expired: %v", err)
		}
		if n != 1 {
			t.Errorf("deleted %d, want 1", n)
		}

		_, err = store.GetByID(ctx, "sess-valid")
		if err != nil {
			t.Errorf("valid session missing: %v", err)
		}

		_, err = store.GetByID(ctx, "sess-exp")
		if !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant for deleted session, got %v", err)
		}
	})

	t.Run("Delete_ByID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		s := newTestSession("sess-del", "hash-del")
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.Delete(ctx, "sess-del"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := store.GetByID(ctx, "sess-del"); !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("expected ErrInvalidGrant after delete, got %v", err)
		}
	})

	t.Run("Delete_Missing_NoError", func(t *testing.T) {
		// Idempotent: deleting a non-existent session is not an error.
		// Postcondition is "session is not present" — already satisfied.
		store := newStore(t)
		ctx := context.Background()

		if err := store.Delete(ctx, "never-existed"); err != nil {
			t.Errorf("delete missing session: %v", err)
		}
	})
}
