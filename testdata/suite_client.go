// Package testdata provides shared integration test infrastructure.
// Suite functions run the full store contract tests against any implementation.
package testdata

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/ports/output"
)

// newTestClient returns a minimal valid Client for use in tests.
func newTestClient(id string) *client.Client {
	now := time.Now().UTC()
	return &client.Client{
		ID:                      id,
		SecretHash:              "",
		Name:                    "Test Client " + id,
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
}

// RunClientStoreTests runs the full ClientStore test suite.
// newStore is called once per subtest to provide a fresh, isolated store.
func RunClientStoreTests(t *testing.T, newStore func(*testing.T) output.ClientStore) {
	t.Helper()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("client-1")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.GetByID(ctx, "client-1")
		if err != nil {
			t.Fatalf("get by id: %v", err)
		}
		if got.Name != c.Name {
			t.Errorf("name: got %q, want %q", got.Name, c.Name)
		}
		if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example.com/callback" {
			t.Errorf("redirect_uris: got %v", got.RedirectURIs)
		}
		if got.Status != client.StatusActive {
			t.Errorf("status: got %q, want %q", got.Status, client.StatusActive)
		}
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		_, err := store.GetByID(ctx, "nonexistent")
		if !errors.Is(err, domain.ErrInvalidClient) {
			t.Errorf("expected ErrInvalidClient, got %v", err)
		}
	})

	t.Run("GetByCIMDURL", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("cimd-client")
		c.RegistrationSource = client.SourceCIMD
		c.CIMDURL = "https://mcp.example.com/.well-known/oauth-client"
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByCIMDURL(ctx, c.CIMDURL)
		if err != nil {
			t.Fatalf("get by cimd url: %v", err)
		}
		if got == nil {
			t.Fatal("expected client, got nil")
		}
		if got.ID != "cimd-client" {
			t.Errorf("id: got %q, want %q", got.ID, "cimd-client")
		}
	})

	t.Run("GetByCIMDURL_NotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		got, err := store.GetByCIMDURL(ctx, "https://nope.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("client-upd")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		c.Name = "Updated Name"
		c.Status = client.StatusSuspended
		c.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, c); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := store.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Name != "Updated Name" {
			t.Errorf("name: got %q, want %q", got.Name, "Updated Name")
		}
		if got.Status != client.StatusSuspended {
			t.Errorf("status: got %q, want %q", got.Status, client.StatusSuspended)
		}
	})

	t.Run("ListAndCount", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		for _, id := range []string{"c-1", "c-2", "c-3"} {
			c := newTestClient(id)
			if err := store.Create(ctx, c); err != nil {
				t.Fatalf("create %s: %v", id, err)
			}
		}

		clients, err := store.List(ctx, "", "", 10, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(clients) != 3 {
			t.Fatalf("got %d clients, want 3", len(clients))
		}

		count, err := store.Count(ctx, "")
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 3 {
			t.Errorf("count: got %d, want 3", count)
		}
	})

	t.Run("ListFilterStatus", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		active := newTestClient("c-active")
		suspended := newTestClient("c-suspended")
		suspended.Status = client.StatusSuspended

		for _, c := range []*client.Client{active, suspended} {
			if err := store.Create(ctx, c); err != nil {
				t.Fatalf("create %s: %v", c.ID, err)
			}
		}

		clients, err := store.List(ctx, string(client.StatusActive), "", 10, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(clients) != 1 {
			t.Fatalf("got %d active clients, want 1", len(clients))
		}
		if clients[0].ID != "c-active" {
			t.Errorf("got ID %q, want %q", clients[0].ID, "c-active")
		}
	})

	t.Run("DuplicateID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("c-dup")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create first: %v", err)
		}
		if err := store.Create(ctx, c); err == nil {
			t.Fatal("expected error on duplicate, got nil")
		}
	})
}
