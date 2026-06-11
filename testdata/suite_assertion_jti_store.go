package testdata

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/ports/output"
)

// RunAssertionJTIStoreTests runs the shared assertion JTI store contract tests.
func RunAssertionJTIStoreTests(t *testing.T, newStore func(*testing.T) output.AssertionJTIStore) {
	t.Helper()

	t.Run("ConsumeJTI_Success", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		err := store.ConsumeJTI(ctx, "jti-1", time.Now().Add(5*time.Minute))
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
	})

	t.Run("ConsumeJTI_Replay", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		expiry := time.Now().Add(5 * time.Minute)
		if err := store.ConsumeJTI(ctx, "jti-replay", expiry); err != nil {
			t.Fatalf("first consume: %v", err)
		}

		err := store.ConsumeJTI(ctx, "jti-replay", expiry)
		if err != domain.ErrAssertionReplay {
			t.Fatalf("expected ErrAssertionReplay, got: %v", err)
		}
	})

	t.Run("PurgeExpired", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		// Insert an already-expired JTI.
		if err := store.ConsumeJTI(ctx, "jti-expired", time.Now().Add(-1*time.Minute)); err != nil {
			t.Fatalf("consume expired: %v", err)
		}

		if err := store.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}

		// The expired JTI should now be purged, so re-using it should succeed.
		if err := store.ConsumeJTI(ctx, "jti-expired", time.Now().Add(5*time.Minute)); err != nil {
			t.Fatalf("re-consume after purge: %v", err)
		}
	})

	t.Run("DifferentJTIs", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		expiry := time.Now().Add(5 * time.Minute)
		if err := store.ConsumeJTI(ctx, "jti-a", expiry); err != nil {
			t.Fatalf("consume a: %v", err)
		}
		if err := store.ConsumeJTI(ctx, "jti-b", expiry); err != nil {
			t.Fatalf("consume b: %v", err)
		}
	})
}
