package testdata

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// ResourceStoreSuiteDeps bundles the stores and FK-seed helpers a ResourceStore
// integration suite needs. ConsentGrantStore / IssuanceStore / BrokerGrantStore
// don't exist yet, so the FK-block tests use backend-specific
// raw-insert callbacks that the per-backend wrapper supplies.
type ResourceStoreSuiteDeps struct {
	Resources output.ResourceStore
	Providers output.BrokerProviderStore
	Users     output.UserStore
	Clients   output.ClientStore

	// SeedConsentGrant inserts a row into consent_grants_unified for the
	// Resource FK-block test. user/client/resource must already exist.
	SeedConsentGrant func(t *testing.T, id, userID, clientID, resourceID string)

	// SeedIssuance inserts a row into issuances for the Resource FK-block test.
	SeedIssuance func(t *testing.T, id, userID, clientID, resourceID string)

	// SeedBrokerGrant inserts a row into broker_grants for the
	// BrokerProvider FK-block test.
	SeedBrokerGrant func(t *testing.T, id, userID, providerID string)
}

// RunResourceStoreTests runs the full ResourceStore integration suite. The
// factory is called once per subtest to provide an isolated, freshly migrated
// backend.
func RunResourceStoreTests(t *testing.T, newDeps func(*testing.T) ResourceStoreSuiteDeps) {
	t.Helper()

	t.Run("Create_NormalizesSlug", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		r := newMintResource("r-norm", "GOOGLE-CAL")
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create: %v", err)
		}
		if r.Slug != "google-cal" {
			t.Errorf("slug not normalized in-place: got %q, want %q", r.Slug, "google-cal")
		}

		got, err := deps.Resources.GetBySlug(ctx, "google-cal")
		if err != nil {
			t.Fatalf("get by normalized slug: %v", err)
		}
		if got.Slug != "google-cal" {
			t.Errorf("persisted slug = %q, want %q", got.Slug, "google-cal")
		}
	})

	t.Run("Create_RejectsBadSlug", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		r := newMintResource("r-bad", "Bad Slug!")
		err := deps.Resources.Create(ctx, r)
		if !errors.Is(err, domain.ErrInvalidSlug) {
			t.Fatalf("expected ErrInvalidSlug, got %v", err)
		}
	})

	t.Run("Create_BrokerWithoutProvider_Rejected", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		r := newMintResource("r-bad-broker", "broker-no-provider")
		r.BackendKind = resource.BackendBroker
		// BrokerProviderID intentionally empty — the SQL CHECK should fire.
		if err := deps.Resources.Create(ctx, r); err == nil {
			t.Fatal("expected CHECK violation, got nil")
		}
	})

	t.Run("Create_MintWithProvider_Rejected", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		seedProvider(t, deps, "p-mint-bad", "provider-mint-bad")

		r := newMintResource("r-bad-mint", "mint-with-provider")
		r.BrokerProviderID = "p-mint-bad" // CHECK forbids
		if err := deps.Resources.Create(ctx, r); err == nil {
			t.Fatal("expected CHECK violation, got nil")
		}
	})

	t.Run("GetBySlug_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		_, err := deps.Resources.GetBySlug(ctx, "does-not-exist")
		if !errors.Is(err, domain.ErrResourceNotFound) {
			t.Fatalf("expected ErrResourceNotFound, got %v", err)
		}
	})

	t.Run("Resolve_BySlug_SingleHit", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		r := newMintResource("r-resolve-slug", "resolve-by-slug")
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := deps.Resources.Resolve(ctx, "resolve-by-slug")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(got) != 1 || got[0].ID != r.ID {
			t.Fatalf("expected 1 row %q, got %d %+v", r.ID, len(got), got)
		}
	})

	t.Run("Resolve_ByURI_SingleHit", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		r := newMintResource("r-resolve-uri", "resolve-uri")
		r.URI = "https://mcp.example.com/uri-1"
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := deps.Resources.Resolve(ctx, r.URI)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(got) != 1 || got[0].ID != r.ID {
			t.Fatalf("expected 1 row %q, got %d %+v", r.ID, len(got), got)
		}
	})

	t.Run("Resolve_ByURI_MultipleHits", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		// Two resources with distinct slugs but the same URI — admin
		// configuration mistake the resolver must surface as ambiguous.
		shared := "https://mcp.example.com/dup-uri"
		r1 := newMintResource("r-dup-1", "dup-one")
		r1.URI = shared
		r2 := newMintResource("r-dup-2", "dup-two")
		r2.URI = shared
		if err := deps.Resources.Create(ctx, r1); err != nil {
			t.Fatalf("create r1: %v", err)
		}
		if err := deps.Resources.Create(ctx, r2); err != nil {
			t.Fatalf("create r2: %v", err)
		}

		got, err := deps.Resources.Resolve(ctx, shared)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 rows for ambiguous uri, got %d: %+v", len(got), got)
		}
	})

	t.Run("Resolve_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		got, err := deps.Resources.Resolve(ctx, "no-such-thing")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty slice, got %d: %+v", len(got), got)
		}
	})

	t.Run("List_FilterByBackendKind", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		seedProvider(t, deps, "p-list", "provider-for-list")

		mint := newMintResource("r-list-mint", "list-mint")
		broker := newBrokerResource("r-list-broker", "list-broker", "p-list")
		if err := deps.Resources.Create(ctx, mint); err != nil {
			t.Fatalf("create mint: %v", err)
		}
		if err := deps.Resources.Create(ctx, broker); err != nil {
			t.Fatalf("create broker: %v", err)
		}

		got, err := deps.Resources.List(ctx, output.ResourceFilter{BackendKind: resource.BackendBroker})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].ID != broker.ID {
			t.Fatalf("expected 1 broker row, got %d %+v", len(got), got)
		}
	})

	t.Run("List_FilterByBrokerProvider", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		seedProvider(t, deps, "p-a", "provider-a")
		seedProvider(t, deps, "p-b", "provider-b")

		ra := newBrokerResource("r-fp-a", "filter-prov-a", "p-a")
		rb := newBrokerResource("r-fp-b", "filter-prov-b", "p-b")
		if err := deps.Resources.Create(ctx, ra); err != nil {
			t.Fatalf("create a: %v", err)
		}
		if err := deps.Resources.Create(ctx, rb); err != nil {
			t.Fatalf("create b: %v", err)
		}

		got, err := deps.Resources.List(ctx, output.ResourceFilter{BrokerProviderID: "p-a"})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].ID != ra.ID {
			t.Fatalf("expected 1 row backed by p-a, got %d %+v", len(got), got)
		}
	})

	t.Run("Update_RoundtripsScopesAndPolicy", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		seedProvider(t, deps, "p-rt", "provider-roundtrip")
		r := newBrokerResource("r-rt", "roundtrip", "p-rt")
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create: %v", err)
		}

		r.Scopes = []resource.Scope{
			{Name: "calendar:read", Description: "Read calendar", Upstream: "https://www.googleapis.com/auth/calendar.readonly"},
			{Name: "calendar:write", Upstream: "https://www.googleapis.com/auth/calendar"},
		}
		r.Policy = resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: []string{"mcp-actor-a", "mcp-actor-b"}},
			Runtime:  resource.RuntimePolicy{ClientIDs: []string{"runtime-cli-a", "runtime-cli-b"}},
			Connect:  resource.ConnectPolicy{AllowedReturnURLs: []string{"https://app.example.com/callback"}},
		}
		r.UpdatedAt = time.Now().UTC().Truncate(time.Second)
		if err := deps.Resources.Update(ctx, r); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := deps.Resources.GetByID(ctx, r.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Scopes) != 2 {
			t.Fatalf("scopes len = %d, want 2", len(got.Scopes))
		}
		if got.Scopes[0].Upstream != "https://www.googleapis.com/auth/calendar.readonly" {
			t.Errorf("scope[0].Upstream = %q, want canonical Google URL", got.Scopes[0].Upstream)
		}
		if got.Scopes[1].Description != "" {
			t.Errorf("scope[1].Description = %q, want empty (omitempty round-trip)", got.Scopes[1].Description)
		}
		if len(got.Policy.Exchange.AllowedClientIDs) != 2 ||
			got.Policy.Exchange.AllowedClientIDs[0] != "mcp-actor-a" ||
			got.Policy.Exchange.AllowedClientIDs[1] != "mcp-actor-b" {
			t.Errorf("policy.exchange.allowed_client_ids = %+v, want [mcp-actor-a mcp-actor-b]",
				got.Policy.Exchange.AllowedClientIDs)
		}
		if len(got.Policy.Connect.AllowedReturnURLs) != 1 ||
			got.Policy.Connect.AllowedReturnURLs[0] != "https://app.example.com/callback" {
			t.Errorf("policy.connect.allowed_return_urls = %+v", got.Policy.Connect.AllowedReturnURLs)
		}
		if len(got.Policy.Runtime.ClientIDs) != 2 ||
			got.Policy.Runtime.ClientIDs[0] != "runtime-cli-a" ||
			got.Policy.Runtime.ClientIDs[1] != "runtime-cli-b" {
			t.Errorf("policy.runtime.client_ids = %+v, want [runtime-cli-a runtime-cli-b]",
				got.Policy.Runtime.ClientIDs)
		}
	})

	t.Run("Create_RoundtripsPolicyAcrossAllReadPaths", func(t *testing.T) {
		// 's Broker branch reads Resource.Policy.Exchange.AllowedClientIDs
		// as the operator gate. If any read path
		// silently drops Policy on hydration, that gate goes always-permissive.
		// This test exercises all four read paths after Create.
		deps := newDeps(t)
		ctx := context.Background()

		seedProvider(t, deps, "p-pol", "policy-roundtrip")
		r := newBrokerResource("r-pol", "policy-roundtrip", "p-pol")
		r.URI = "https://policy.example.com"
		r.Scopes = []resource.Scope{{Name: "read", Upstream: "read"}}
		r.Policy = resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: []string{"actor-a", "actor-b", "actor-c"}},
			Connect:  resource.ConnectPolicy{AllowedReturnURLs: []string{"https://app.example.com/cb"}},
		}
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create: %v", err)
		}

		assertPolicy := func(t *testing.T, label string, got *resource.Resource) {
			t.Helper()
			if got == nil {
				t.Fatalf("%s: nil resource", label)
			}
			if len(got.Policy.Exchange.AllowedClientIDs) != 3 {
				t.Errorf("%s: AllowedClientIDs len=%d, want 3 (got %v)",
					label, len(got.Policy.Exchange.AllowedClientIDs), got.Policy.Exchange.AllowedClientIDs)
			}
			if len(got.Policy.Connect.AllowedReturnURLs) != 1 {
				t.Errorf("%s: AllowedReturnURLs len=%d, want 1", label, len(got.Policy.Connect.AllowedReturnURLs))
			}
		}

		got, err := deps.Resources.GetByID(ctx, r.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		assertPolicy(t, "GetByID", got)

		got, err = deps.Resources.GetBySlug(ctx, r.Slug)
		if err != nil {
			t.Fatalf("GetBySlug: %v", err)
		}
		assertPolicy(t, "GetBySlug", got)

		rows, err := deps.Resources.Resolve(ctx, r.Slug)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("Resolve len=%d, want 1", len(rows))
		}
		assertPolicy(t, "Resolve", rows[0])

		list, err := deps.Resources.List(ctx, output.ResourceFilter{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var listed *resource.Resource
		for _, candidate := range list {
			if candidate.ID == r.ID {
				listed = candidate
				break
			}
		}
		if listed == nil {
			t.Fatalf("List did not return %q", r.ID)
		}
		assertPolicy(t, "List", listed)
	})

	t.Run("FindByRuntimeClientID_ZeroOneAndAmbiguous", func(t *testing.T) {
		// pin the three cases the broker dispatch agent-attestation
		// gate distinguishes. Run against both adapters via the suite so the
		// jsonb @> (postgres) and json_each (sqlite) implementations stay in
		// lockstep.
		deps := newDeps(t)
		ctx := context.Background()

		soloR := newMintResource("r-rt-solo", "rt-solo")
		soloR.Policy = resource.Policy{
			Runtime: resource.RuntimePolicy{ClientIDs: []string{"cli-solo"}},
		}
		if err := deps.Resources.Create(ctx, soloR); err != nil {
			t.Fatalf("create solo: %v", err)
		}

		ambA := newMintResource("r-rt-amb-a", "rt-amb-a")
		ambA.Policy = resource.Policy{
			Runtime: resource.RuntimePolicy{ClientIDs: []string{"cli-amb"}},
		}
		ambB := newMintResource("r-rt-amb-b", "rt-amb-b")
		ambB.Policy = resource.Policy{
			Runtime: resource.RuntimePolicy{ClientIDs: []string{"cli-amb"}},
		}
		if err := deps.Resources.Create(ctx, ambA); err != nil {
			t.Fatalf("create amb-a: %v", err)
		}
		if err := deps.Resources.Create(ctx, ambB); err != nil {
			t.Fatalf("create amb-b: %v", err)
		}

		// 0 — no match.
		_, err := deps.Resources.FindByRuntimeClientID(ctx, "cli-nobody")
		if !errors.Is(err, domain.ErrResourceNotFound) {
			t.Errorf("FindByRuntimeClientID(cli-nobody): got %v, want ErrResourceNotFound", err)
		}

		// 1 — exactly one match returns the resource.
		got, err := deps.Resources.FindByRuntimeClientID(ctx, "cli-solo")
		if err != nil {
			t.Fatalf("FindByRuntimeClientID(cli-solo): %v", err)
		}
		if got == nil || got.ID != soloR.ID {
			t.Errorf("FindByRuntimeClientID(cli-solo): got %+v, want %q", got, soloR.ID)
		}

		// 2+ — operator misconfiguration, runtime treats as ambiguous and
		// fail-closes upstream. Store layer surfaces ErrAmbiguousResource.
		_, err = deps.Resources.FindByRuntimeClientID(ctx, "cli-amb")
		if !errors.Is(err, domain.ErrAmbiguousResource) {
			t.Errorf("FindByRuntimeClientID(cli-amb): got %v, want ErrAmbiguousResource", err)
		}

		// Empty client_id is a fast-path miss (no DB query needed in the
		// runtime gate; defensive at the store seam).
		_, err = deps.Resources.FindByRuntimeClientID(ctx, "")
		if !errors.Is(err, domain.ErrResourceNotFound) {
			t.Errorf("FindByRuntimeClientID(empty): got %v, want ErrResourceNotFound", err)
		}
	})

	t.Run("Delete_BlockedByConsentGrant", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		seedUser(t, deps.Users, "u-cg-block")
		seedClient(t, deps.Clients, "c-cg-block")
		r := newMintResource("r-cg-block", "cg-block")
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create resource: %v", err)
		}
		deps.SeedConsentGrant(t, "cg-1", "u-cg-block", "c-cg-block", r.ID)

		err := deps.Resources.Delete(ctx, r.ID)
		if !errors.Is(err, domain.ErrResourceHasReferences) {
			t.Fatalf("expected ErrResourceHasReferences, got %v", err)
		}
	})

	t.Run("Delete_BlockedByIssuance", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		r := newMintResource("r-iss-block", "iss-block")
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("create resource: %v", err)
		}
		// issuances.subject_user_id and client_id are bare TEXT (no FK).
		deps.SeedIssuance(t, "iss-1", "u-anon", "c-anon", r.ID)

		err := deps.Resources.Delete(ctx, r.ID)
		if !errors.Is(err, domain.ErrResourceHasReferences) {
			t.Fatalf("expected ErrResourceHasReferences, got %v", err)
		}
	})
}

// --- shared builders / seed helpers ---

func newMintResource(id, slug string) *resource.Resource {
	now := time.Now().UTC().Truncate(time.Second)
	return &resource.Resource{
		ID:          id,
		Slug:        slug,
		DisplayName: "Test " + id,
		BackendKind: resource.BackendMint,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func newBrokerResource(id, slug, providerID string) *resource.Resource {
	r := newMintResource(id, slug)
	r.BackendKind = resource.BackendBroker
	r.BrokerProviderID = providerID
	return r
}

func seedProvider(t *testing.T, deps ResourceStoreSuiteDeps, id, slug string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	p := &resource.BrokerProvider{
		ID:          id,
		Slug:        slug,
		DisplayName: "Test " + id,
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x"}`),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := deps.Providers.Create(context.Background(), p); err != nil {
		t.Fatalf("seed provider %q: %v", id, err)
	}
}

func seedUser(t *testing.T, store output.UserStore, id string) {
	t.Helper()
	u := newTestUser(id, id+"@example.com")
	if err := store.Create(context.Background(), u); err != nil {
		t.Fatalf("seed user %q: %v", id, err)
	}
}

func seedClient(t *testing.T, store output.ClientStore, id string) {
	t.Helper()
	if err := store.Create(context.Background(), newTestClient(id)); err != nil {
		t.Fatalf("seed client %q: %v", id, err)
	}
}
