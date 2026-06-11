package testdata

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/ports/output"
)

func newTestPolicy(id, idpID string) xaa.Policy {
	now := time.Now().UTC()
	return xaa.Policy{
		ID:        id,
		Name:      "Test Policy " + id,
		IDPID:     idpID,
		ClientIDs: []string{"client-1", "client-2"},
		Scopes:    []string{"read", "write"},
		Resources: nil,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// RunXAAPolicyStoreTests runs the shared XAA policy store contract tests.
func RunXAAPolicyStoreTests(t *testing.T, newStores func(*testing.T) (output.XAAPolicyStore, output.IDPStore)) {
	t.Helper()

	// Helper to seed a trusted IdP (required for FK).
	seedIdP := func(t *testing.T, idpStore output.IDPStore, id string) {
		t.Helper()
		now := time.Now().UTC()
		err := idpStore.Save(context.Background(), idp.TrustedIDP{
			ID:        id,
			Name:      "Test IdP " + id,
			Issuer:    "https://" + id + ".example.com",
			JWKSUri:   "https://" + id + ".example.com/.well-known/jwks.json",
			Audience:  "https://authplane.example.com",
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("seed idp %q: %v", id, err)
		}
	}

	t.Run("SaveAndGetByID", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-1")

		p := newTestPolicy("policy-1", "idp-1")
		if err := store.Save(ctx, p); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetByID(ctx, "policy-1")
		if err != nil {
			t.Fatalf("get by id: %v", err)
		}
		if got.Name != p.Name {
			t.Errorf("name = %q, want %q", got.Name, p.Name)
		}
		if len(got.ClientIDs) != 2 || got.ClientIDs[0] != "client-1" {
			t.Errorf("client_ids = %v, want [client-1, client-2]", got.ClientIDs)
		}
		if len(got.Scopes) != 2 {
			t.Errorf("scopes = %v, want [read, write]", got.Scopes)
		}
		if got.Resources != nil {
			t.Errorf("resources = %v, want nil", got.Resources)
		}
		if !got.Enabled {
			t.Errorf("enabled = false, want true")
		}
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		store, _ := newStores(t)
		ctx := context.Background()

		_, err := store.GetByID(ctx, "nonexistent")
		if err != domain.ErrXAAPolicyNotFound {
			t.Fatalf("expected ErrXAAPolicyNotFound, got: %v", err)
		}
	})

	t.Run("ListByIDP", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-a")
		seedIdP(t, idpStore, "idp-b")

		if err := store.Save(ctx, newTestPolicy("p1", "idp-a")); err != nil {
			t.Fatalf("save p1: %v", err)
		}
		if err := store.Save(ctx, newTestPolicy("p2", "idp-a")); err != nil {
			t.Fatalf("save p2: %v", err)
		}
		if err := store.Save(ctx, newTestPolicy("p3", "idp-b")); err != nil {
			t.Fatalf("save p3: %v", err)
		}

		list, err := store.ListByIDP(ctx, "idp-a")
		if err != nil {
			t.Fatalf("list by idp: %v", err)
		}
		if len(list) != 2 {
			t.Errorf("len = %d, want 2", len(list))
		}
	})

	t.Run("List", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-x")

		if err := store.Save(ctx, newTestPolicy("px1", "idp-x")); err != nil {
			t.Fatalf("save: %v", err)
		}
		if err := store.Save(ctx, newTestPolicy("px2", "idp-x")); err != nil {
			t.Fatalf("save: %v", err)
		}

		list, err := store.List(ctx)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 2 {
			t.Errorf("len = %d, want 2", len(list))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-del")

		if err := store.Save(ctx, newTestPolicy("p-del", "idp-del")); err != nil {
			t.Fatalf("save: %v", err)
		}

		if err := store.Delete(ctx, "p-del"); err != nil {
			t.Fatalf("delete: %v", err)
		}

		_, err := store.GetByID(ctx, "p-del")
		if err != domain.ErrXAAPolicyNotFound {
			t.Fatalf("expected ErrXAAPolicyNotFound after delete, got: %v", err)
		}
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		store, _ := newStores(t)
		ctx := context.Background()

		err := store.Delete(ctx, "nonexistent")
		if err != domain.ErrXAAPolicyNotFound {
			t.Fatalf("expected ErrXAAPolicyNotFound, got: %v", err)
		}
	})

	t.Run("SaveUpdate", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-upd")

		p := newTestPolicy("p-upd", "idp-upd")
		if err := store.Save(ctx, p); err != nil {
			t.Fatalf("save: %v", err)
		}

		p.Name = "Updated Policy"
		p.ClientIDs = []string{"client-3"}
		p.Scopes = nil
		p.Enabled = false
		p.UpdatedAt = time.Now().UTC()
		if err := store.Save(ctx, p); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := store.GetByID(ctx, "p-upd")
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Name != "Updated Policy" {
			t.Errorf("name = %q, want %q", got.Name, "Updated Policy")
		}
		if len(got.ClientIDs) != 1 || got.ClientIDs[0] != "client-3" {
			t.Errorf("client_ids = %v, want [client-3]", got.ClientIDs)
		}
		if got.Scopes != nil {
			t.Errorf("scopes = %v, want nil", got.Scopes)
		}
		if got.Enabled {
			t.Errorf("enabled = true, want false")
		}
	})

	t.Run("NilArraysHandledAsNull", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-nil")

		now := time.Now().UTC()
		p := xaa.Policy{
			ID:        "p-nil",
			Name:      "Permissive",
			IDPID:     "idp-nil",
			ClientIDs: nil, // all clients
			Scopes:    nil, // client default
			Resources: nil, // all resources
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := store.Save(ctx, p); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetByID(ctx, "p-nil")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ClientIDs != nil {
			t.Errorf("client_ids = %v, want nil", got.ClientIDs)
		}
		if got.Scopes != nil {
			t.Errorf("scopes = %v, want nil", got.Scopes)
		}
		if got.Resources != nil {
			t.Errorf("resources = %v, want nil", got.Resources)
		}
	})
}
