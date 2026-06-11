package testdata

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/ports/output"
)

func newTestIDP(id, issuer string) idp.TrustedIDP {
	now := time.Now().UTC()
	return idp.TrustedIDP{
		ID:        id,
		Name:      "Test IdP " + id,
		Issuer:    issuer,
		JWKSUri:   issuer + "/.well-known/jwks.json",
		Audience:  "https://authplane.example.com",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// RunIdPStoreTests runs the shared IdP store contract tests.
func RunIdPStoreTests(t *testing.T, newStore func(*testing.T) output.IDPStore) {
	t.Helper()

	t.Run("SaveAndGetByID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		idpEntity := newTestIDP("idp-1", "https://idp1.example.com")
		if err := store.Save(ctx, idpEntity); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetByID(ctx, "idp-1")
		if err != nil {
			t.Fatalf("get by id: %v", err)
		}
		if got.Name != idpEntity.Name {
			t.Errorf("name = %q, want %q", got.Name, idpEntity.Name)
		}
		if got.Issuer != idpEntity.Issuer {
			t.Errorf("issuer = %q, want %q", got.Issuer, idpEntity.Issuer)
		}
		if got.Enabled != true {
			t.Errorf("enabled = %v, want true", got.Enabled)
		}
	})

	t.Run("GetByIssuer", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		idpEntity := newTestIDP("idp-2", "https://idp2.example.com")
		if err := store.Save(ctx, idpEntity); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetByIssuer(ctx, "https://idp2.example.com")
		if err != nil {
			t.Fatalf("get by issuer: %v", err)
		}
		if got.ID != "idp-2" {
			t.Errorf("id = %q, want %q", got.ID, "idp-2")
		}
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.GetByID(ctx, "nonexistent")
		if err != domain.ErrIDPNotFound {
			t.Fatalf("expected ErrIDPNotFound, got: %v", err)
		}
	})

	t.Run("GetByIssuer_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.GetByIssuer(ctx, "https://nonexistent.example.com")
		if err != domain.ErrIDPNotFound {
			t.Fatalf("expected ErrIDPNotFound, got: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		if err := store.Save(ctx, newTestIDP("idp-a", "https://a.example.com")); err != nil {
			t.Fatalf("save a: %v", err)
		}
		if err := store.Save(ctx, newTestIDP("idp-b", "https://b.example.com")); err != nil {
			t.Fatalf("save b: %v", err)
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
		store := newStore(t)
		ctx := context.Background()

		if err := store.Save(ctx, newTestIDP("idp-del", "https://del.example.com")); err != nil {
			t.Fatalf("save: %v", err)
		}

		if err := store.Delete(ctx, "idp-del"); err != nil {
			t.Fatalf("delete: %v", err)
		}

		_, err := store.GetByID(ctx, "idp-del")
		if err != domain.ErrIDPNotFound {
			t.Fatalf("expected ErrIDPNotFound after delete, got: %v", err)
		}
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		err := store.Delete(ctx, "nonexistent")
		if err != domain.ErrIDPNotFound {
			t.Fatalf("expected ErrIDPNotFound, got: %v", err)
		}
	})

	t.Run("SaveUpdate", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		idpEntity := newTestIDP("idp-upd", "https://upd.example.com")
		if err := store.Save(ctx, idpEntity); err != nil {
			t.Fatalf("save: %v", err)
		}

		idpEntity.Name = "Updated Name"
		idpEntity.Enabled = false
		idpEntity.UpdatedAt = time.Now().UTC()
		if err := store.Save(ctx, idpEntity); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := store.GetByID(ctx, "idp-upd")
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Name != "Updated Name" {
			t.Errorf("name = %q, want %q", got.Name, "Updated Name")
		}
		if got.Enabled != false {
			t.Errorf("enabled = %v, want false", got.Enabled)
		}
	})
}
