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

func newTestMapping(id, idpID, subject string) xaa.SubjectMapping {
	return xaa.SubjectMapping{
		ID:          id,
		IDPID:       idpID,
		IDPSubject:  subject,
		LocalUserID: "local-user-" + id,
		CreatedAt:   time.Now().UTC(),
	}
}

// RunSubjectMappingStoreTests runs the shared subject mapping store contract tests.
func RunSubjectMappingStoreTests(t *testing.T, newStores func(*testing.T) (output.SubjectMappingStore, output.IDPStore)) {
	t.Helper()

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

	t.Run("SaveAndGetMapping", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-1")

		m := newTestMapping("m1", "idp-1", "user@acme.com")
		if err := store.Save(ctx, m); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetMapping(ctx, "idp-1", "user@acme.com")
		if err != nil {
			t.Fatalf("get mapping: %v", err)
		}
		if got.ID != "m1" {
			t.Errorf("id = %q, want %q", got.ID, "m1")
		}
		if got.LocalUserID != "local-user-m1" {
			t.Errorf("local_user_id = %q, want %q", got.LocalUserID, "local-user-m1")
		}
		if got.IDPSubject != "user@acme.com" {
			t.Errorf("idp_subject = %q, want %q", got.IDPSubject, "user@acme.com")
		}
	})

	t.Run("GetMapping_NotFound", func(t *testing.T) {
		store, _ := newStores(t)
		ctx := context.Background()

		_, err := store.GetMapping(ctx, "nonexistent", "nobody")
		if err != domain.ErrSubjectMappingNotFound {
			t.Fatalf("expected ErrSubjectMappingNotFound, got: %v", err)
		}
	})

	t.Run("ListByIDP", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-a")

		if err := store.Save(ctx, newTestMapping("ma1", "idp-a", "user1@acme.com")); err != nil {
			t.Fatalf("save 1: %v", err)
		}
		if err := store.Save(ctx, newTestMapping("ma2", "idp-a", "user2@acme.com")); err != nil {
			t.Fatalf("save 2: %v", err)
		}

		list, err := store.ListByIDP(ctx, "idp-a")
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

		if err := store.Save(ctx, newTestMapping("m-del", "idp-del", "del@acme.com")); err != nil {
			t.Fatalf("save: %v", err)
		}

		if err := store.Delete(ctx, "m-del"); err != nil {
			t.Fatalf("delete: %v", err)
		}

		_, err := store.GetMapping(ctx, "idp-del", "del@acme.com")
		if err != domain.ErrSubjectMappingNotFound {
			t.Fatalf("expected ErrSubjectMappingNotFound after delete, got: %v", err)
		}
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		store, _ := newStores(t)
		ctx := context.Background()

		err := store.Delete(ctx, "nonexistent")
		if err != domain.ErrSubjectMappingNotFound {
			t.Fatalf("expected ErrSubjectMappingNotFound, got: %v", err)
		}
	})

	t.Run("DuplicateMapping_Rejected", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-dup")

		if err := store.Save(ctx, newTestMapping("m-dup1", "idp-dup", "same@acme.com")); err != nil {
			t.Fatalf("save first: %v", err)
		}

		// Different ID but same (idp_id, idp_subject) — should fail with unique constraint.
		m2 := newTestMapping("m-dup2", "idp-dup", "same@acme.com")
		err := store.Save(ctx, m2)
		if err == nil {
			t.Fatalf("expected error for duplicate mapping, got nil")
		}
		if err != domain.ErrSubjectMappingDuplicate {
			t.Fatalf("expected ErrSubjectMappingDuplicate, got: %v", err)
		}
	})

	t.Run("EmptyLocalUserID", func(t *testing.T) {
		store, idpStore := newStores(t)
		ctx := context.Background()

		seedIdP(t, idpStore, "idp-empty")

		m := xaa.SubjectMapping{
			ID:          "m-empty",
			IDPID:       "idp-empty",
			IDPSubject:  "nolocal@acme.com",
			LocalUserID: "", // empty = auto-provision
			CreatedAt:   time.Now().UTC(),
		}
		if err := store.Save(ctx, m); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, err := store.GetMapping(ctx, "idp-empty", "nolocal@acme.com")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.LocalUserID != "" {
			t.Errorf("local_user_id = %q, want empty", got.LocalUserID)
		}
	})
}
