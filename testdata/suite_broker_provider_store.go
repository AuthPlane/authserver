package testdata

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerProviderStoreSuiteDeps bundles the stores and FK-seed helpers needed
// by the BrokerProviderStore integration suite.
type BrokerProviderStoreSuiteDeps struct {
	Providers output.BrokerProviderStore
	Resources output.ResourceStore
	Users     output.UserStore

	// SeedBrokerGrant inserts a row into broker_grants for the FK-block test.
	// user/provider must already exist.
	SeedBrokerGrant func(t *testing.T, id, userID, providerID string)
}

// RunBrokerProviderStoreTests runs the full BrokerProviderStore integration
// suite.
func RunBrokerProviderStoreTests(t *testing.T, newDeps func(*testing.T) BrokerProviderStoreSuiteDeps) {
	t.Helper()

	t.Run("Create_Roundtrip", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		// Single-key adapter-shaped JSON. Compared via JSON equality so the
		// test is portable across sqlite TEXT and postgres JSONB
		// (the data model).
		cfg := []byte(`{"client_id":"abc","client_secret_env":"GOOGLE_CLIENT_SECRET","authorize_url":"https://accounts.google.com/o/oauth2/v2/auth"}`)
		now := time.Now().UTC().Truncate(time.Second)

		p := &resource.BrokerProvider{
			ID:          "p-rt",
			Slug:        "google-rt",
			DisplayName: "Google (round-trip)",
			Protocol:    resource.ProtocolOAuth,
			ConfigData:  cfg,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := deps.Providers.Create(ctx, p); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := deps.Providers.GetByID(ctx, p.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if !jsonEqual(t, got.ConfigData, cfg) {
			t.Errorf("config_data round-trip mismatch:\n got %s\nwant %s", got.ConfigData, cfg)
		}
		if got.Protocol != resource.ProtocolOAuth {
			t.Errorf("protocol = %q, want %q", got.Protocol, resource.ProtocolOAuth)
		}
		if got.Slug != "google-rt" {
			t.Errorf("slug = %q, want %q", got.Slug, "google-rt")
		}
	})

	t.Run("Create_DuplicateSlug_Conflict", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		now := time.Now().UTC().Truncate(time.Second)
		p1 := &resource.BrokerProvider{
			ID: "p-dup-1", Slug: "dup-slug", DisplayName: "First",
			Protocol: resource.ProtocolOAuth, ConfigData: []byte(`{}`),
			CreatedAt: now, UpdatedAt: now,
		}
		if err := deps.Providers.Create(ctx, p1); err != nil {
			t.Fatalf("create first: %v", err)
		}

		p2 := &resource.BrokerProvider{
			ID: "p-dup-2", Slug: "dup-slug", DisplayName: "Second",
			Protocol: resource.ProtocolAPIKey, ConfigData: []byte(`{}`),
			CreatedAt: now, UpdatedAt: now,
		}
		err := deps.Providers.Create(ctx, p2)
		if err == nil {
			t.Fatal("expected unique-slug conflict, got nil")
		}
	})

	t.Run("Delete_BlockedByResource", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		now := time.Now().UTC().Truncate(time.Second)
		p := &resource.BrokerProvider{
			ID: "p-fk-res", Slug: "fk-by-resource", DisplayName: "FK Provider",
			Protocol: resource.ProtocolOAuth, ConfigData: []byte(`{}`),
			CreatedAt: now, UpdatedAt: now,
		}
		if err := deps.Providers.Create(ctx, p); err != nil {
			t.Fatalf("create provider: %v", err)
		}

		r := newBrokerResource("r-fk-res", "fk-resource-on-provider", p.ID)
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create dependent resource: %v", err)
		}

		err := deps.Providers.Delete(ctx, p.ID)
		if !errors.Is(err, domain.ErrBrokerProviderHasReferences) {
			t.Fatalf("expected ErrBrokerProviderHasReferences, got %v", err)
		}
	})

	t.Run("Delete_BlockedByBrokerGrant", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		seedUser(t, deps.Users, "u-fk-bg")

		now := time.Now().UTC().Truncate(time.Second)
		p := &resource.BrokerProvider{
			ID: "p-fk-bg", Slug: "fk-by-grant", DisplayName: "FK BG Provider",
			Protocol: resource.ProtocolOAuth, ConfigData: []byte(`{}`),
			CreatedAt: now, UpdatedAt: now,
		}
		if err := deps.Providers.Create(ctx, p); err != nil {
			t.Fatalf("create provider: %v", err)
		}

		deps.SeedBrokerGrant(t, "bg-1", "u-fk-bg", p.ID)

		err := deps.Providers.Delete(ctx, p.ID)
		if !errors.Is(err, domain.ErrBrokerProviderHasReferences) {
			t.Fatalf("expected ErrBrokerProviderHasReferences, got %v", err)
		}
	})
}

// jsonEqual reports whether a and b represent the same JSON value, ignoring
// whitespace and key ordering. Used by Create_Roundtrip so the test is
// portable across sqlite TEXT (byte-exact) and postgres JSONB (canonicalized).
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	return reflect.DeepEqual(av, bv)
}
