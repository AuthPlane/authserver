package testdata

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/ports/output"
)

// RunDPoPNonceStoreTests runs the full DPoPNonceStore contract tests.
func RunDPoPNonceStoreTests(t *testing.T, newStore func(*testing.T) output.DPoPNonceStore) {
	t.Helper()

	t.Run("ConsumeJTI_Success", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		err := store.ConsumeJTI(ctx, "jti-unique-1", time.Now().Add(5*time.Minute))
		if err != nil {
			t.Fatalf("consume jti: %v", err)
		}
	})

	t.Run("ConsumeJTI_Replay", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		jti := "jti-replay-test"
		expiry := time.Now().Add(5 * time.Minute)

		if err := store.ConsumeJTI(ctx, jti, expiry); err != nil {
			t.Fatalf("first consume: %v", err)
		}

		err := store.ConsumeJTI(ctx, jti, expiry)
		if !errors.Is(err, domain.ErrDPoPReplay) {
			t.Errorf("expected ErrDPoPReplay, got %v", err)
		}
	})

	t.Run("IssueNonce_Success", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		nonce, err := store.IssueNonce(ctx, 60*time.Second)
		if err != nil {
			t.Fatalf("issue nonce: %v", err)
		}
		if nonce == "" {
			t.Error("expected non-empty nonce")
		}
	})

	t.Run("IssueNonce_Unique", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		nonce1, err := store.IssueNonce(ctx, 60*time.Second)
		if err != nil {
			t.Fatalf("issue nonce 1: %v", err)
		}
		nonce2, err := store.IssueNonce(ctx, 60*time.Second)
		if err != nil {
			t.Fatalf("issue nonce 2: %v", err)
		}
		if nonce1 == nonce2 {
			t.Error("consecutive nonces should not be equal")
		}
	})

	t.Run("ValidateNonce_Valid", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		nonce, err := store.IssueNonce(ctx, 60*time.Second)
		if err != nil {
			t.Fatalf("issue nonce: %v", err)
		}

		if err := store.ValidateNonce(ctx, nonce); err != nil {
			t.Errorf("validate nonce: %v", err)
		}
	})

	t.Run("ValidateNonce_Unknown", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		err := store.ValidateNonce(ctx, "unknown-nonce")
		if !errors.Is(err, domain.ErrDPoPNonceMismatch) {
			t.Errorf("expected ErrDPoPNonceMismatch, got %v", err)
		}
	})

	t.Run("ValidateNonce_Expired", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		// Issue a nonce with very short TTL, then validate after expiry.
		nonce, err := store.IssueNonce(ctx, 1*time.Millisecond)
		if err != nil {
			t.Fatalf("issue nonce: %v", err)
		}

		// Wait for it to expire.
		time.Sleep(10 * time.Millisecond)

		err = store.ValidateNonce(ctx, nonce)
		if !errors.Is(err, domain.ErrDPoPNonceMismatch) {
			t.Errorf("expected ErrDPoPNonceMismatch for expired nonce, got %v", err)
		}
	})

	t.Run("PurgeExpired_RemovesExpiredJTIs", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		// Insert an expired JTI.
		if err := store.ConsumeJTI(ctx, "jti-expired", time.Now().Add(-1*time.Minute)); err != nil {
			t.Fatalf("consume expired jti: %v", err)
		}
		// Insert an active JTI.
		if err := store.ConsumeJTI(ctx, "jti-active", time.Now().Add(5*time.Minute)); err != nil {
			t.Fatalf("consume active jti: %v", err)
		}

		if err := store.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}

		// Active JTI should still be present (replay detected).
		err := store.ConsumeJTI(ctx, "jti-active", time.Now().Add(5*time.Minute))
		if !errors.Is(err, domain.ErrDPoPReplay) {
			t.Error("active jti should still be present after purge")
		}

		// Expired JTI should be gone (no replay error).
		err = store.ConsumeJTI(ctx, "jti-expired", time.Now().Add(5*time.Minute))
		if err != nil {
			t.Errorf("expired jti should be purged, got %v", err)
		}
	})

	t.Run("PurgeExpired_RemovesExpiredNonces", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		// Issue a nonce with very short TTL.
		nonce, err := store.IssueNonce(ctx, 1*time.Millisecond)
		if err != nil {
			t.Fatalf("issue nonce: %v", err)
		}
		time.Sleep(10 * time.Millisecond)

		if err := store.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}

		// Nonce should be gone.
		err = store.ValidateNonce(ctx, nonce)
		if !errors.Is(err, domain.ErrDPoPNonceMismatch) {
			t.Error("expired nonce should be purged")
		}
	})
}
