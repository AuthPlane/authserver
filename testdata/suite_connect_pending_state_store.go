package testdata

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// ConnectPendingStateStoreSuiteDeps bundles the stores an 
// ConnectPendingStateStore integration suite needs. The suite seeds its
// own broker providers and broker resources so the (provider_id,
// resource_id) FK chain is satisfiable.
type ConnectPendingStateStoreSuiteDeps struct {
	States    output.ConnectPendingStateStore
	Providers output.BrokerProviderStore
	Resources output.ResourceStore
}

// RunConnectPendingStateStoreTests runs the integration test suite
// against the supplied factory.
func RunConnectPendingStateStoreTests(t *testing.T, newDeps func(*testing.T) ConnectPendingStateStoreSuiteDeps) {
	t.Helper()

	t.Run("Insert_PersistsScopes", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedBrokerProvider(t, deps.Providers, "p-cps-ins", "cps-ins")
		r := seedBrokerResourceForState(t, deps.Resources, "r-cps-ins", "cps-ins", "p-cps-ins")

		state := &resource.ConnectPendingState{
			ID:           "cps-ins",
			UserID:       "u-cps-ins",
			ProviderID:   "p-cps-ins",
			ResourceID:   r.ID,
			CodeVerifier: "verifier-bytes-base64url",
			ReturnURL:    "https://app.example/cb",
			Scopes:       []string{"calendar:read", "calendar:write"},
			ExpiresAt:    time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second),
		}
		if err := deps.States.Insert(ctx, state); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := deps.States.Consume(ctx, "cps-ins")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if !reflect.DeepEqual(got.Scopes, state.Scopes) {
			t.Errorf("scopes round-trip: got %v, want %v", got.Scopes, state.Scopes)
		}
		if got.CodeVerifier != state.CodeVerifier {
			t.Errorf("code_verifier round-trip mismatch")
		}
		if got.ReturnURL != state.ReturnURL {
			t.Errorf("return_url round-trip: got %q, want %q", got.ReturnURL, state.ReturnURL)
		}
	})

	t.Run("Consume_AtomicGetDelete", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedBrokerProvider(t, deps.Providers, "p-cps-ad", "cps-ad")
		r := seedBrokerResourceForState(t, deps.Resources, "r-cps-ad", "cps-ad", "p-cps-ad")

		state := newConnectPendingState("cps-ad", "u", "p-cps-ad", r.ID,
			time.Now().UTC().Add(10*time.Minute))
		if err := deps.States.Insert(ctx, state); err != nil {
			t.Fatalf("insert: %v", err)
		}

		// First consume succeeds.
		first, err := deps.States.Consume(ctx, "cps-ad")
		if err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if first.ID != "cps-ad" {
			t.Errorf("first consume returned wrong id %q", first.ID)
		}

		// Second consume returns the not-found sentinel; the row was
		// deleted in the same transaction as the first.
		_, err = deps.States.Consume(ctx, "cps-ad")
		if !errors.Is(err, domain.ErrPendingStateNotFound) {
			t.Fatalf("second consume err = %v, want ErrPendingStateNotFound", err)
		}
	})

	t.Run("Consume_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		_, err := deps.States.Consume(ctx, "no-such-state")
		if !errors.Is(err, domain.ErrPendingStateNotFound) {
			t.Fatalf("err = %v, want ErrPendingStateNotFound", err)
		}
	})

	t.Run("PurgeExpired", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedBrokerProvider(t, deps.Providers, "p-cps-pg", "cps-pg")
		r := seedBrokerResourceForState(t, deps.Resources, "r-cps-pg", "cps-pg", "p-cps-pg")

		now := time.Now().UTC().Truncate(time.Second)
		expired := newConnectPendingState("cps-pg-old", "u", "p-cps-pg", r.ID, now.Add(-time.Hour))
		fresh := newConnectPendingState("cps-pg-new", "u", "p-cps-pg", r.ID, now.Add(10*time.Minute))
		if err := deps.States.Insert(ctx, expired); err != nil {
			t.Fatalf("insert expired: %v", err)
		}
		if err := deps.States.Insert(ctx, fresh); err != nil {
			t.Fatalf("insert fresh: %v", err)
		}

		// Purge with a cutoff between the two — only the expired row
		// should drop. Cutoff = now means expires_at < now drops the
		// expired row but not the fresh one.
		n, err := deps.States.PurgeExpired(ctx, now)
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if n != 1 {
			t.Errorf("purged = %d, want 1", n)
		}

		// Fresh row still consumable.
		got, err := deps.States.Consume(ctx, "cps-pg-new")
		if err != nil {
			t.Fatalf("consume fresh after purge: %v", err)
		}
		if got.ID != "cps-pg-new" {
			t.Errorf("fresh row missing after purge")
		}

		// Expired row was removed by purge — consume returns the
		// sentinel.
		_, err = deps.States.Consume(ctx, "cps-pg-old")
		if !errors.Is(err, domain.ErrPendingStateNotFound) {
			t.Fatalf("consume expired after purge err = %v, want ErrPendingStateNotFound", err)
		}
	})

	t.Run("FK_ProviderMustExist", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		// Resource exists but provider does not. We pin the resource to
		// some real broker provider so the resource itself can be
		// inserted, but the pending-state row points to a different
		// (missing) provider id.
		seedBrokerProvider(t, deps.Providers, "p-fk-real", "fk-prov-real")
		r := seedBrokerResourceForState(t, deps.Resources, "r-fk-prov", "fk-prov", "p-fk-real")

		state := newConnectPendingState("cps-fk-prov", "u", "p-does-not-exist", r.ID,
			time.Now().UTC().Add(10*time.Minute))
		err := deps.States.Insert(ctx, state)
		if err == nil {
			t.Fatal("expected FK violation on missing provider_id, got nil")
		}
		if !looksLikeFKError(err) {
			t.Fatalf("expected FK error, got: %v", err)
		}
	})

	t.Run("FK_ResourceMustExist", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedBrokerProvider(t, deps.Providers, "p-fk-res", "fk-res")

		state := newConnectPendingState("cps-fk-res", "u", "p-fk-res", "r-does-not-exist",
			time.Now().UTC().Add(10*time.Minute))
		err := deps.States.Insert(ctx, state)
		if err == nil {
			t.Fatal("expected FK violation on missing resource_id, got nil")
		}
		if !looksLikeFKError(err) {
			t.Fatalf("expected FK error, got: %v", err)
		}
	})
}

// newConnectPendingState builds a minimal pending-state row for the
// suite. ExpiresAt is the only knob the tests vary; everything else is
// fixed.
func newConnectPendingState(id, userID, providerID, resourceID string, expiresAt time.Time) *resource.ConnectPendingState {
	return &resource.ConnectPendingState{
		ID:           id,
		UserID:       userID,
		ProviderID:   providerID,
		ResourceID:   resourceID,
		CodeVerifier: "verifier-" + id,
		ReturnURL:    "https://app.example/cb",
		Scopes:       []string{"calendar:read"},
		ExpiresAt:    expiresAt.Truncate(time.Second),
	}
}

// seedBrokerResourceForState creates a Broker resource referencing the
// given provider so the connect_pending_states.resource_id FK is
// satisfiable. Returns the inserted resource.
func seedBrokerResourceForState(t *testing.T, store output.ResourceStore, id, slug, providerID string) *resource.Resource {
	t.Helper()
	r := newBrokerResource(id, slug, providerID)
	if err := store.Create(context.Background(), r); err != nil {
		t.Fatalf("seed broker resource %q: %v", id, err)
	}
	return r
}
