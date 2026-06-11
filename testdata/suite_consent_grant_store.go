package testdata

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// ConsentGrantStoreSuiteDeps bundles the stores an 
// ConsentGrantStore integration suite needs. The suite seeds its own
// users / clients / Mint resources via the supplied stores so the
// (user_id, client_id, resource_id) FK chain is satisfiable end-to-end.
type ConsentGrantStoreSuiteDeps struct {
	Grants    output.ConsentGrantStore
	Resources output.ResourceStore
	Users     output.UserStore
	Clients   output.ClientStore
}

// RunConsentGrantStoreTests runs the integration test suite against
// the supplied factory.
func RunConsentGrantStoreTests(t *testing.T, newDeps func(*testing.T) ConsentGrantStoreSuiteDeps) {
	t.Helper()

	t.Run("Upsert_NewGrant", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-up-new")
		seedClient(t, deps.Clients, "c-up-new")
		r := seedMintResource(t, deps.Resources, "r-up-new", "up-new")

		now := time.Now().UTC().Truncate(time.Second)
		g := &resource.ConsentGrant{
			ID:         "cg-up-new",
			UserID:     "u-up-new",
			ClientID:   "c-up-new",
			ResourceID: r.ID,
			Scopes:     []string{"calendar:read", "calendar:write"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := deps.Grants.Upsert(ctx, g); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-up-new", "c-up-new", r.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("expected grant, got nil")
		}
		if !reflect.DeepEqual(got.Scopes, g.Scopes) {
			t.Errorf("scopes round-trip: got %v, want %v", got.Scopes, g.Scopes)
		}
		if got.RevokedAt != nil {
			t.Errorf("RevokedAt = %v, want nil for new grant", got.RevokedAt)
		}
	})

	t.Run("Upsert_ScopeExpansion", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-up-exp")
		seedClient(t, deps.Clients, "c-up-exp")
		r := seedMintResource(t, deps.Resources, "r-up-exp", "up-exp")

		now := time.Now().UTC().Truncate(time.Second)
		first := &resource.ConsentGrant{
			ID:         "cg-up-exp",
			UserID:     "u-up-exp",
			ClientID:   "c-up-exp",
			ResourceID: r.ID,
			Scopes:     []string{"calendar:read"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := deps.Grants.Upsert(ctx, first); err != nil {
			t.Fatalf("first upsert: %v", err)
		}

		// Second upsert with broader scopes — same (user, client,
		// resource) tuple, different ID. ON CONFLICT must update the
		// existing row's scopes / updated_at.
		later := now.Add(time.Minute)
		second := &resource.ConsentGrant{
			ID:         "cg-up-exp-2",
			UserID:     "u-up-exp",
			ClientID:   "c-up-exp",
			ResourceID: r.ID,
			Scopes:     []string{"calendar:read", "calendar:write", "drive:read"},
			CreatedAt:  later,
			UpdatedAt:  later,
		}
		if err := deps.Grants.Upsert(ctx, second); err != nil {
			t.Fatalf("second upsert: %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-up-exp", "c-up-exp", r.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("expected grant after scope expansion, got nil")
		}
		if len(got.Scopes) != 3 {
			t.Fatalf("scopes len = %d, want 3 (after expansion)", len(got.Scopes))
		}
		// updated_at must reflect the second upsert.
		if !got.UpdatedAt.Equal(later) {
			t.Errorf("updated_at = %v, want %v", got.UpdatedAt, later)
		}

		// Single-row invariant: ListForUser sees exactly one row for
		// the (user, client, resource) tuple.
		all, err := deps.Grants.ListForUser(ctx, "u-up-exp")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(all) != 1 {
			t.Fatalf("ListForUser len = %d, want 1 (Upsert re-uses row)", len(all))
		}
	})

	t.Run("Get_FiltersRevoked", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-filt")
		seedClient(t, deps.Clients, "c-filt")
		r := seedMintResource(t, deps.Resources, "r-filt", "filt-revoked")

		now := time.Now().UTC().Truncate(time.Second)
		g := &resource.ConsentGrant{
			ID:         "cg-filt",
			UserID:     "u-filt",
			ClientID:   "c-filt",
			ResourceID: r.ID,
			Scopes:     []string{"x"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := deps.Grants.Upsert(ctx, g); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		if err := deps.Grants.Revoke(ctx, "cg-filt"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-filt", "c-filt", r.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got != nil {
			t.Fatalf("expected (nil, nil) for revoked row, got %+v", got)
		}
	})

	t.Run("FK_ResourceMustExist", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-fk-r")
		seedClient(t, deps.Clients, "c-fk-r")

		now := time.Now().UTC().Truncate(time.Second)
		g := &resource.ConsentGrant{
			ID:         "cg-fk-r",
			UserID:     "u-fk-r",
			ClientID:   "c-fk-r",
			ResourceID: "r-does-not-exist",
			Scopes:     []string{"x"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		err := deps.Grants.Upsert(ctx, g)
		if err == nil {
			t.Fatal("expected FK violation on missing resource_id, got nil")
		}
		if !looksLikeFKError(err) {
			t.Fatalf("expected FK error, got: %v", err)
		}
	})

	t.Run("FK_ClientMustExist", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-fk-c")
		r := seedMintResource(t, deps.Resources, "r-fk-c", "fk-client")

		now := time.Now().UTC().Truncate(time.Second)
		g := &resource.ConsentGrant{
			ID:         "cg-fk-c",
			UserID:     "u-fk-c",
			ClientID:   "c-does-not-exist",
			ResourceID: r.ID,
			Scopes:     []string{"x"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		err := deps.Grants.Upsert(ctx, g)
		if err == nil {
			t.Fatal("expected FK violation on missing client_id, got nil")
		}
		if !looksLikeFKError(err) {
			t.Fatalf("expected FK error, got: %v", err)
		}
	})

	t.Run("Revoke_SetsTimestamp", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-rev")
		seedClient(t, deps.Clients, "c-rev")
		r := seedMintResource(t, deps.Resources, "r-rev", "rev-ts")

		now := time.Now().UTC().Truncate(time.Second)
		g := &resource.ConsentGrant{
			ID:         "cg-rev",
			UserID:     "u-rev",
			ClientID:   "c-rev",
			ResourceID: r.ID,
			Scopes:     []string{"x"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := deps.Grants.Upsert(ctx, g); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		before := time.Now().UTC()
		if err := deps.Grants.Revoke(ctx, "cg-rev"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		after := time.Now().UTC()

		// Revoked rows are excluded from Get; pull from ListForUser
		// and check the timestamp falls within [before, after].
		all, err := deps.Grants.ListForUser(ctx, "u-rev")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(all) != 1 {
			t.Fatalf("ListForUser len = %d, want 1", len(all))
		}
		if all[0].RevokedAt == nil {
			t.Fatal("RevokedAt = nil, want a timestamp after Revoke")
		}
		// Allow 1s slack on either side for backend clock-resolution
		// (postgres NOW() vs sqlite RFC3339).
		ts := *all[0].RevokedAt
		if ts.Before(before.Add(-time.Second)) || ts.After(after.Add(time.Second)) {
			t.Errorf("RevokedAt = %v, expected within [%v, %v]", ts, before, after)
		}
	})

	t.Run("ListForUser_IncludesRevoked", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-lfu")
		seedClient(t, deps.Clients, "c-lfu-1")
		seedClient(t, deps.Clients, "c-lfu-2")
		r1 := seedMintResource(t, deps.Resources, "r-lfu-1", "lfu-one")
		r2 := seedMintResource(t, deps.Resources, "r-lfu-2", "lfu-two")

		now := time.Now().UTC().Truncate(time.Second)
		// Active grant.
		active := &resource.ConsentGrant{
			ID: "cg-lfu-active", UserID: "u-lfu", ClientID: "c-lfu-1", ResourceID: r1.ID,
			Scopes: []string{"a"}, CreatedAt: now, UpdatedAt: now,
		}
		// Grant we'll revoke.
		toRevoke := &resource.ConsentGrant{
			ID: "cg-lfu-revoked", UserID: "u-lfu", ClientID: "c-lfu-2", ResourceID: r2.ID,
			Scopes: []string{"b"}, CreatedAt: now, UpdatedAt: now,
		}
		if err := deps.Grants.Upsert(ctx, active); err != nil {
			t.Fatalf("upsert active: %v", err)
		}
		if err := deps.Grants.Upsert(ctx, toRevoke); err != nil {
			t.Fatalf("upsert toRevoke: %v", err)
		}
		if err := deps.Grants.Revoke(ctx, "cg-lfu-revoked"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		all, err := deps.Grants.ListForUser(ctx, "u-lfu")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(all) != 2 {
			t.Fatalf("ListForUser len = %d, want 2 (active + revoked)", len(all))
		}

		var sawActive, sawRevoked bool
		for _, g := range all {
			switch g.ID {
			case "cg-lfu-active":
				sawActive = true
				if g.RevokedAt != nil {
					t.Errorf("active grant has RevokedAt = %v", g.RevokedAt)
				}
			case "cg-lfu-revoked":
				sawRevoked = true
				if g.RevokedAt == nil {
					t.Errorf("revoked grant has RevokedAt = nil")
				}
			}
		}
		if !sawActive || !sawRevoked {
			t.Errorf("ListForUser missing rows: active=%v revoked=%v", sawActive, sawRevoked)
		}
	})

	// GetByID is the by-id lookup added in  for the admin
	// revocation cascade. Unlike Get (which filters revoked rows out),
	// GetByID returns the row regardless of revocation state — the
	// cascade needs the (user, client, resource) triple of an already-
	// revoked grant just as much as an active one.
	t.Run("GetByID_ActiveAndRevoked", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-gbi")
		seedClient(t, deps.Clients, "c-gbi-active")
		seedClient(t, deps.Clients, "c-gbi-revoked")
		r := seedMintResource(t, deps.Resources, "r-gbi", "gbi")

		now := time.Now().UTC().Truncate(time.Second)
		active := &resource.ConsentGrant{
			ID: "cg-gbi-active", UserID: "u-gbi", ClientID: "c-gbi-active", ResourceID: r.ID,
			Scopes: []string{"a"}, CreatedAt: now, UpdatedAt: now,
		}
		revoked := &resource.ConsentGrant{
			ID: "cg-gbi-revoked", UserID: "u-gbi", ClientID: "c-gbi-revoked", ResourceID: r.ID,
			Scopes: []string{"b"}, CreatedAt: now, UpdatedAt: now,
		}
		if err := deps.Grants.Upsert(ctx, active); err != nil {
			t.Fatalf("upsert active: %v", err)
		}
		if err := deps.Grants.Upsert(ctx, revoked); err != nil {
			t.Fatalf("upsert revoked: %v", err)
		}
		if err := deps.Grants.Revoke(ctx, "cg-gbi-revoked"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		gotActive, err := deps.Grants.GetByID(ctx, "cg-gbi-active")
		if err != nil {
			t.Fatalf("GetByID active: %v", err)
		}
		if gotActive == nil || gotActive.ID != "cg-gbi-active" {
			t.Fatalf("GetByID active: got %+v", gotActive)
		}
		if gotActive.RevokedAt != nil {
			t.Errorf("active grant: RevokedAt = %v, want nil", gotActive.RevokedAt)
		}

		gotRevoked, err := deps.Grants.GetByID(ctx, "cg-gbi-revoked")
		if err != nil {
			t.Fatalf("GetByID revoked: %v", err)
		}
		if gotRevoked == nil || gotRevoked.ID != "cg-gbi-revoked" {
			t.Fatalf("GetByID revoked: got %+v", gotRevoked)
		}
		if gotRevoked.RevokedAt == nil {
			t.Error("revoked grant: RevokedAt = nil, want timestamp (GetByID must NOT filter on revoked_at)")
		}
	})

	t.Run("GetByID_NotFound_ReturnsNilNoError", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		got, err := deps.Grants.GetByID(ctx, "no-such-id")
		if err != nil {
			t.Fatalf("GetByID miss returned error: %v (expected nil)", err)
		}
		if got != nil {
			t.Errorf("GetByID miss: got %+v, want nil", got)
		}
	})
}

// seedMintResource is a shared helper for grant suites that need a
// pre-existing Mint resource as the FK target. It returns the resource
// so the caller can use its ID.
func seedMintResource(t *testing.T, store output.ResourceStore, id, slug string) *resource.Resource {
	t.Helper()
	r := newMintResource(id, slug)
	if err := store.Create(context.Background(), r); err != nil {
		t.Fatalf("seed mint resource %q: %v", id, err)
	}
	return r
}

// looksLikeFKError reports whether err is a foreign-key violation in
// either the sqlite or postgres adapter. The two backends produce
// different error shapes — sqlite wraps the modernc driver's "FOREIGN
// KEY constraint failed" string, postgres surfaces SQLSTATE 23503 (the
// pgx error message contains "violates foreign key constraint"). The
// adapters wrap these with %w but neither converts them to a domain
// sentinel for the unified consent grant store, so the suite matches
// on the underlying message rather than on a typed sentinel.
func looksLikeFKError(err error) bool {
	if err == nil {
		return false
	}
	// Walk the error chain so callers can wrap with %w.
	for cur := err; cur != nil; cur = errors.Unwrap(cur) {
		msg := cur.Error()
		if strings.Contains(msg, "FOREIGN KEY constraint failed") ||
			strings.Contains(msg, "violates foreign key constraint") {
			return true
		}
	}
	return false
}
