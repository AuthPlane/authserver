package testdata

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// FrontingLinkStoreSuiteDeps bundles the stores a FrontingLinkStore
// integration suite needs. The Resources store is required so the suite
// can seed the FK targets fronting_links references.
type FrontingLinkStoreSuiteDeps struct {
	Links     output.FrontingLinkStore
	Resources output.ResourceStore
	Providers output.BrokerProviderStore
}

// RunFrontingLinkStoreTests runs the full FrontingLinkStore integration
// suite. Per-backend wrappers (sqlite + postgres) call this with a fresh
// migrated DB. Mirrors the structure of RunResourceStoreTests.
func RunFrontingLinkStoreTests(t *testing.T, newDeps func(*testing.T) FrontingLinkStoreSuiteDeps) {
	t.Helper()

	t.Run("Create_GetRoundTrip", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedTwoMintsForFronting(t, deps, "src-rt", "tgt-rt")

		link := &resource.FrontingLink{
			SourceSlug: "src-rt",
			TargetSlug: "tgt-rt",
			ScopeMap:   resource.ScopeMap{"a": {"AA"}, "b": {"BB", "CC"}},
			CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
			CreatedBy:  "admin",
		}
		if err := deps.Links.Create(ctx, link); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := deps.Links.Get(ctx, "src-rt", "tgt-rt")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceSlug != "src-rt" || got.TargetSlug != "tgt-rt" {
			t.Errorf("pkey mismatch: %+v", got)
		}
		if !reflect.DeepEqual(map[string][]string(got.ScopeMap), map[string][]string{"a": {"AA"}, "b": {"BB", "CC"}}) {
			t.Errorf("scope_map mismatch: %v", got.ScopeMap)
		}
		if got.CreatedBy != "admin" {
			t.Errorf("created_by mismatch: %q", got.CreatedBy)
		}
	})

	t.Run("Get_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		_, err := deps.Links.Get(ctx, "no", "thing")
		if !errors.Is(err, domain.ErrFrontingLinkNotFound) {
			t.Fatalf("expected ErrFrontingLinkNotFound, got %v", err)
		}
	})

	t.Run("Create_DuplicatePair_Conflict", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedTwoMintsForFronting(t, deps, "dup-src", "dup-tgt")

		l := &resource.FrontingLink{
			SourceSlug: "dup-src", TargetSlug: "dup-tgt",
			ScopeMap:  resource.ScopeMap{"x": {"X"}},
			CreatedAt: time.Now().UTC(), CreatedBy: "admin",
		}
		if err := deps.Links.Create(ctx, l); err != nil {
			t.Fatalf("first create: %v", err)
		}
		err := deps.Links.Create(ctx, l)
		if !errors.Is(err, domain.ErrFrontingLinkExists) {
			t.Fatalf("expected ErrFrontingLinkExists, got %v", err)
		}
	})

	t.Run("Create_FKMissingResource_InvalidRequest", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		l := &resource.FrontingLink{
			SourceSlug: "ghost-src", TargetSlug: "ghost-tgt",
			ScopeMap:  resource.ScopeMap{"x": {"X"}},
			CreatedAt: time.Now().UTC(), CreatedBy: "admin",
		}
		err := deps.Links.Create(ctx, l)
		if err == nil {
			t.Fatal("expected FK error, got nil")
		}
		// We translate FK violations to invalid_request domain errors so
		// HTTP handlers can return a clean 400 with a helpful message.
		// Check it's a domain error of the invalid_request flavor.
		if !domain.IsError(err) {
			t.Fatalf("expected domain error, got %T %v", err, err)
		}
	})

	t.Run("Update_PreservesProvenance", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedTwoMintsForFronting(t, deps, "upd-src", "upd-tgt")

		original := &resource.FrontingLink{
			SourceSlug: "upd-src", TargetSlug: "upd-tgt",
			ScopeMap:  resource.ScopeMap{"a": {"AA"}},
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond), CreatedBy: "founder",
		}
		if err := deps.Links.Create(ctx, original); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Mutate scope map only — created_by/created_at on the patched copy
		// are intentionally left at zero to verify the adapter preserves
		// provenance.
		patched := &resource.FrontingLink{
			SourceSlug: "upd-src", TargetSlug: "upd-tgt",
			ScopeMap:  resource.ScopeMap{"a": {"AA", "AB"}, "b": {"BB"}},
			CreatedAt: time.Time{}, CreatedBy: "",
		}
		if err := deps.Links.Update(ctx, patched); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := deps.Links.Get(ctx, "upd-src", "upd-tgt")
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.CreatedBy != "founder" {
			t.Errorf("created_by clobbered: got %q", got.CreatedBy)
		}
		if got.CreatedAt.IsZero() {
			t.Error("created_at clobbered to zero")
		}
		if !reflect.DeepEqual(map[string][]string(got.ScopeMap), map[string][]string{"a": {"AA", "AB"}, "b": {"BB"}}) {
			t.Errorf("scope_map not updated: %v", got.ScopeMap)
		}
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		l := &resource.FrontingLink{SourceSlug: "ghost", TargetSlug: "ghost", ScopeMap: resource.ScopeMap{"a": {"A"}}}
		err := deps.Links.Update(ctx, l)
		if !errors.Is(err, domain.ErrFrontingLinkNotFound) {
			t.Fatalf("expected ErrFrontingLinkNotFound, got %v", err)
		}
	})

	t.Run("Delete_RemovesRow", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedTwoMintsForFronting(t, deps, "del-src", "del-tgt")

		l := &resource.FrontingLink{
			SourceSlug: "del-src", TargetSlug: "del-tgt",
			ScopeMap:  resource.ScopeMap{"a": {"A"}},
			CreatedAt: time.Now().UTC(), CreatedBy: "admin",
		}
		if err := deps.Links.Create(ctx, l); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := deps.Links.Delete(ctx, "del-src", "del-tgt"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := deps.Links.Get(ctx, "del-src", "del-tgt"); !errors.Is(err, domain.ErrFrontingLinkNotFound) {
			t.Fatalf("expected ErrFrontingLinkNotFound after delete, got %v", err)
		}
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		err := deps.Links.Delete(ctx, "ghost", "ghost")
		if !errors.Is(err, domain.ErrFrontingLinkNotFound) {
			t.Fatalf("expected ErrFrontingLinkNotFound, got %v", err)
		}
	})

	t.Run("FK_BlocksResourceDelete", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedTwoMintsForFronting(t, deps, "fk-src", "fk-tgt")
		src, err := deps.Resources.GetBySlug(ctx, "fk-src")
		if err != nil {
			t.Fatalf("lookup src: %v", err)
		}

		l := &resource.FrontingLink{
			SourceSlug: "fk-src", TargetSlug: "fk-tgt",
			ScopeMap:  resource.ScopeMap{"a": {"A"}},
			CreatedAt: time.Now().UTC(), CreatedBy: "admin",
		}
		if err := deps.Links.Create(ctx, l); err != nil {
			t.Fatalf("create link: %v", err)
		}

		// The DB FK is ON DELETE RESTRICT — direct ResourceStore.Delete
		// must surface the violation as ErrResourceHasReferences.
		err = deps.Resources.Delete(ctx, src.ID)
		if !errors.Is(err, domain.ErrResourceHasReferences) {
			t.Fatalf("expected ErrResourceHasReferences, got %v", err)
		}
	})

	t.Run("List_FiltersAndOrder", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedThreeMintsForFronting(t, deps, "lf-a", "lf-b", "lf-c")

		// a→b, a→c, b→c. List filtering must split source/target cleanly.
		mustCreate := func(s, t1 string) {
			err := deps.Links.Create(ctx, &resource.FrontingLink{
				SourceSlug: s, TargetSlug: t1,
				ScopeMap:  resource.ScopeMap{"a": {"A"}},
				CreatedAt: time.Now().UTC(), CreatedBy: "admin",
			})
			if err != nil {
				t.Fatalf("seed link %s→%s: %v", s, t1, err)
			}
		}
		mustCreate("lf-a", "lf-b")
		mustCreate("lf-a", "lf-c")
		mustCreate("lf-b", "lf-c")

		bySource, err := deps.Links.List(ctx, output.FrontingLinkFilter{Source: "lf-a"})
		if err != nil {
			t.Fatalf("list by source: %v", err)
		}
		got := pairsOf(bySource)
		want := []string{"lf-a→lf-b", "lf-a→lf-c"}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("source filter: got %v, want %v", got, want)
		}

		byTarget, err := deps.Links.List(ctx, output.FrontingLinkFilter{Target: "lf-c"})
		if err != nil {
			t.Fatalf("list by target: %v", err)
		}
		got = pairsOf(byTarget)
		want = []string{"lf-a→lf-c", "lf-b→lf-c"}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("target filter: got %v, want %v", got, want)
		}

		// Both filters: at most one row, the matching pair.
		bySrcTgt, err := deps.Links.List(ctx, output.FrontingLinkFilter{Source: "lf-a", Target: "lf-c"})
		if err != nil {
			t.Fatalf("list by src+tgt: %v", err)
		}
		if len(bySrcTgt) != 1 || bySrcTgt[0].SourceSlug != "lf-a" || bySrcTgt[0].TargetSlug != "lf-c" {
			t.Errorf("source+target filter: got %v", pairsOf(bySrcTgt))
		}
	})

	t.Run("ListForResource_ReturnsBothDirections", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedThreeMintsForFronting(t, deps, "fr-a", "fr-b", "fr-c")

		mustCreate := func(s, t1 string) {
			err := deps.Links.Create(ctx, &resource.FrontingLink{
				SourceSlug: s, TargetSlug: t1,
				ScopeMap:  resource.ScopeMap{"a": {"A"}},
				CreatedAt: time.Now().UTC(), CreatedBy: "admin",
			})
			if err != nil {
				t.Fatalf("seed link: %v", err)
			}
		}
		mustCreate("fr-a", "fr-b") // outbound from b's POV is empty; inbound = a→b
		mustCreate("fr-b", "fr-c") // outbound from b = b→c

		all, err := deps.Links.ListForResource(ctx, "fr-b")
		if err != nil {
			t.Fatalf("list for resource: %v", err)
		}
		got := pairsOf(all)
		sort.Strings(got)
		want := []string{"fr-a→fr-b", "fr-b→fr-c"}
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ListForResource(b): got %v, want %v", got, want)
		}
	})

	t.Run("DeleteForResource_RemovesAll", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedThreeMintsForFronting(t, deps, "dr-a", "dr-b", "dr-c")

		mustCreate := func(s, t1 string) {
			err := deps.Links.Create(ctx, &resource.FrontingLink{
				SourceSlug: s, TargetSlug: t1,
				ScopeMap:  resource.ScopeMap{"a": {"A"}},
				CreatedAt: time.Now().UTC(), CreatedBy: "admin",
			})
			if err != nil {
				t.Fatalf("seed link: %v", err)
			}
		}
		mustCreate("dr-a", "dr-b")
		mustCreate("dr-b", "dr-c")
		mustCreate("dr-a", "dr-c") // unrelated to b — must survive

		n, err := deps.Links.DeleteForResource(ctx, "dr-b")
		if err != nil {
			t.Fatalf("delete for resource: %v", err)
		}
		if n != 2 {
			t.Errorf("expected 2 deletions (a→b, b→c), got %d", n)
		}

		surviving, err := deps.Links.List(ctx, output.FrontingLinkFilter{})
		if err != nil {
			t.Fatalf("list survivors: %v", err)
		}
		if len(surviving) != 1 || surviving[0].SourceSlug != "dr-a" || surviving[0].TargetSlug != "dr-c" {
			t.Errorf("expected only dr-a→dr-c surviving, got %v", pairsOf(surviving))
		}
	})

	t.Run("ScopeMap_1NRoundTrip", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedTwoMintsForFronting(t, deps, "rt-src", "rt-tgt")

		fanout := resource.ScopeMap{
			"single":     {"only"},
			"two":        {"first", "second"},
			"three":      {"a", "b", "c"},
			"unicode-キー": {"値1", "値2"},
		}
		if err := deps.Links.Create(ctx, &resource.FrontingLink{
			SourceSlug: "rt-src", TargetSlug: "rt-tgt",
			ScopeMap:  fanout,
			CreatedAt: time.Now().UTC(), CreatedBy: "admin",
		}); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := deps.Links.Get(ctx, "rt-src", "rt-tgt")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if !reflect.DeepEqual(map[string][]string(got.ScopeMap), map[string][]string(fanout)) {
			t.Errorf("scope_map round-trip mismatch: got %v, want %v", got.ScopeMap, fanout)
		}
	})
}

// --- helpers (unexported) ---

func seedTwoMintsForFronting(t *testing.T, deps FrontingLinkStoreSuiteDeps, srcSlug, tgtSlug string) {
	t.Helper()
	ctx := context.Background()
	for _, s := range []string{srcSlug, tgtSlug} {
		r := &resource.Resource{
			Slug:        s,
			DisplayName: s,
			BackendKind: resource.BackendMint,
			Scopes:      []resource.Scope{{Name: "a"}, {Name: "b"}, {Name: "AA"}, {Name: "BB"}, {Name: "CC"}, {Name: "AB"}, {Name: "X"}, {Name: "A"}, {Name: "x"}, {Name: "only"}, {Name: "first"}, {Name: "second"}, {Name: "c"}, {Name: "値1"}, {Name: "値2"}, {Name: "single"}, {Name: "two"}, {Name: "three"}, {Name: "unicode-キー"}},
		}
		// seedMintResource (resource_store suite helper) embeds an ID +
		// timestamps; use a direct seed inline instead so we don't have to
		// share that helper's internals across files.
		r.ID = "rid-" + s
		r.CreatedAt = time.Now().UTC()
		r.UpdatedAt = r.CreatedAt
		if err := deps.Resources.Create(ctx, r); err != nil {
			t.Fatalf("seed resource %q: %v", s, err)
		}
	}
}

func seedThreeMintsForFronting(t *testing.T, deps FrontingLinkStoreSuiteDeps, a, b, c string) {
	t.Helper()
	seedTwoMintsForFronting(t, deps, a, b)
	ctx := context.Background()
	r := &resource.Resource{
		Slug:        c,
		DisplayName: c,
		BackendKind: resource.BackendMint,
		Scopes:      []resource.Scope{{Name: "a"}, {Name: "A"}},
		ID:          "rid-" + c,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := deps.Resources.Create(ctx, r); err != nil {
		t.Fatalf("seed resource %q: %v", c, err)
	}
}

func pairsOf(links []*resource.FrontingLink) []string {
	out := make([]string, len(links))
	for i, l := range links {
		out[i] = l.SourceSlug + "→" + l.TargetSlug
	}
	return out
}
