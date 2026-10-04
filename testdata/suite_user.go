package testdata

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

// newTestUser returns a minimal valid User for use in tests.
func newTestUser(id, email string) *user.User {
	now := time.Now().UTC()
	return &user.User{
		ID:           id,
		Email:        email,
		Name:         "Test User",
		PasswordHash: "$2a$10$fakehash",
		Role:         user.RoleUser,
		Status:       user.StatusActive,
		Provider:     user.ProviderLocal,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// RunUserStoreTests runs the full UserStore test suite.
// newStore is called once per subtest to provide a fresh, isolated store.
func RunUserStoreTests(t *testing.T, newStore func(*testing.T) output.UserStore) {
	t.Helper()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("user-1", "alice@example.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("get by id: %v", err)
		}
		if got.Email != u.Email {
			t.Errorf("email: got %q, want %q", got.Email, u.Email)
		}
		if got.Role != user.RoleUser {
			t.Errorf("role: got %q, want %q", got.Role, user.RoleUser)
		}
	})

	t.Run("GetByEmail", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("user-2", "bob@example.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByEmail(ctx, "bob@example.com")
		if err != nil {
			t.Fatalf("get by email: %v", err)
		}
		if got.ID != u.ID {
			t.Errorf("id: got %q, want %q", got.ID, u.ID)
		}
	})

	t.Run("GetByProviderSub", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("user-fed", "federated@example.com")
		u.Provider = user.ProviderOIDC
		u.ProviderSub = "google|12345"
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByProviderSub(ctx, user.ProviderOIDC, "google|12345")
		if err != nil {
			t.Fatalf("get by provider sub: %v", err)
		}
		if got.ID != u.ID {
			t.Errorf("id: got %q, want %q", got.ID, u.ID)
		}
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.GetByID(ctx, "nonexistent")
		if !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("GetByEmail_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.GetByEmail(ctx, "nobody@example.com")
		if !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("DuplicateEmail", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u1 := newTestUser("user-a", "dup@example.com")
		if err := store.Create(ctx, u1); err != nil {
			t.Fatalf("create first: %v", err)
		}

		u2 := newTestUser("user-b", "dup@example.com")
		err := store.Create(ctx, u2)
		if err == nil {
			t.Fatal("expected error on duplicate email, got nil")
		}
		// duplicate email must surface as the ErrUserAlreadyExists
		// domain sentinel so the admin handler can map it to 409 Conflict.
		if !errors.Is(err, domain.ErrUserAlreadyExists) {
			t.Errorf("expected ErrUserAlreadyExists, got %v", err)
		}
	})

	t.Run("Update", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("user-upd", "update@example.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		u.Role = user.RoleAdmin
		u.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, u); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := store.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Role != user.RoleAdmin {
			t.Errorf("role after update: got %q, want %q", got.Role, user.RoleAdmin)
		}
	})

	t.Run("ListAndCount", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		for i, email := range []string{"a@test.com", "b@test.com", "c@test.com"} {
			u := newTestUser(fmt.Sprintf("user-%d", i), email)
			if err := store.Create(ctx, u); err != nil {
				t.Fatalf("create %d: %v", i, err)
			}
		}

		users, err := store.List(ctx)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(users) != 3 {
			t.Fatalf("got %d users, want 3", len(users))
		}

		count, err := store.Count(ctx)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 3 {
			t.Errorf("count: got %d, want 3", count)
		}
	})

	// A federated IdP need not release an email. Any number of users may
	// have none (stored as NULL, read back as ""), none of them is reachable
	// by looking up the empty email, and they stay findable by
	// (provider, provider_sub).
	// One account per federated identity; local accounts (provider_sub "")
	// are not constrained by it.
	t.Run("OneAccountPerFederatedIdentity", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		first := newTestUser("fed-first", "")
		first.PasswordHash = ""
		first.Provider = user.ProviderOIDC
		first.ProviderSub = "same-idp-sub"
		if err := store.Create(ctx, first); err != nil {
			t.Fatalf("create first: %v", err)
		}
		dup := newTestUser("fed-dup", "")
		dup.PasswordHash = ""
		dup.Provider = user.ProviderOIDC
		dup.ProviderSub = "same-idp-sub"
		if err := store.Create(ctx, dup); !errors.Is(err, domain.ErrUserAlreadyExists) {
			t.Fatalf("second account for the same identity: want ErrUserAlreadyExists, got %v", err)
		}
		for _, id := range []string{"local-a", "local-b"} {
			if err := store.Create(ctx, newTestUser(id, id+"@example.com")); err != nil {
				t.Fatalf("local account %s: %v", id, err)
			}
		}
	})

	t.Run("UsersWithoutEmail", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		for _, sub := range []string{"idp-sub-1", "idp-sub-2", "idp-sub-3"} {
			u := newTestUser("user-"+sub, "")
			u.PasswordHash = ""
			u.Provider = user.ProviderOIDC
			u.ProviderSub = sub
			if err := store.Create(ctx, u); err != nil {
				t.Fatalf("create email-less user %s: %v", sub, err)
			}
		}

		got, err := store.GetByProviderSub(ctx, user.ProviderOIDC, "idp-sub-2")
		if err != nil {
			t.Fatalf("GetByProviderSub: %v", err)
		}
		if got.ID != "user-idp-sub-2" || got.Email != "" {
			t.Errorf("got id=%q email=%q, want user-idp-sub-2 with no email", got.ID, got.Email)
		}

		if _, err := store.GetByEmail(ctx, ""); !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("GetByEmail(\"\"): want ErrUserNotFound, got %v", err)
		}

		// Update keeps a missing email missing, and setting one later
		// enforces uniqueness like any other email.
		got.Name = "renamed"
		got.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, got); err != nil {
			t.Fatalf("update email-less user: %v", err)
		}
		if err := store.Create(ctx, newTestUser("local-1", "taken@example.com")); err != nil {
			t.Fatalf("create local: %v", err)
		}
		got, err = store.GetByID(ctx, "user-idp-sub-2")
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Name != "renamed" || got.Email != "" {
			t.Errorf("after update: name=%q email=%q", got.Name, got.Email)
		}
		got.Email = "taken@example.com"
		if err := store.Update(ctx, got); !errors.Is(err, domain.ErrUserAlreadyExists) {
			t.Errorf("update to a taken email: want ErrUserAlreadyExists, got %v", err)
		}

		users, err := store.List(ctx)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(users) != 4 {
			t.Errorf("list: got %d users, want 4", len(users))
		}
	})
}
