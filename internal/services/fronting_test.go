package services

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	auditdom "github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// fakeFrontingLinkStore is a minimal in-memory output.FrontingLinkStore for
// FrontingService unit tests. Keyed on "source\x00target".
type fakeFrontingLinkStore struct {
	mu    sync.Mutex
	links map[string]*resource.FrontingLink
}

func newFakeFrontingLinkStore() *fakeFrontingLinkStore {
	return &fakeFrontingLinkStore{links: make(map[string]*resource.FrontingLink)}
}

func key(s, t string) string { return s + "\x00" + t }

func (s *fakeFrontingLinkStore) Get(_ context.Context, src, tgt string) (*resource.FrontingLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[key(src, tgt)]
	if !ok {
		return nil, domain.ErrFrontingLinkNotFound
	}
	cp := *l
	return &cp, nil
}

func (s *fakeFrontingLinkStore) List(_ context.Context, filter output.FrontingLinkFilter) ([]*resource.FrontingLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.FrontingLink
	for _, l := range s.links {
		if filter.Source != "" && l.SourceSlug != filter.Source {
			continue
		}
		if filter.Target != "" && l.TargetSlug != filter.Target {
			continue
		}
		cp := *l
		out = append(out, &cp)
	}
	// Stable order matches the SQL ORDER BY contract.
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceSlug != out[j].SourceSlug {
			return out[i].SourceSlug < out[j].SourceSlug
		}
		return out[i].TargetSlug < out[j].TargetSlug
	})
	return out, nil
}

func (s *fakeFrontingLinkStore) ListForResource(ctx context.Context, slug string) ([]*resource.FrontingLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.FrontingLink
	for _, l := range s.links {
		if l.SourceSlug == slug || l.TargetSlug == slug {
			cp := *l
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceSlug != out[j].SourceSlug {
			return out[i].SourceSlug < out[j].SourceSlug
		}
		return out[i].TargetSlug < out[j].TargetSlug
	})
	return out, nil
}

func (s *fakeFrontingLinkStore) Create(_ context.Context, l *resource.FrontingLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.links[key(l.SourceSlug, l.TargetSlug)]; exists {
		return domain.ErrFrontingLinkExists
	}
	cp := *l
	s.links[key(l.SourceSlug, l.TargetSlug)] = &cp
	return nil
}

func (s *fakeFrontingLinkStore) Update(_ context.Context, l *resource.FrontingLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.links[key(l.SourceSlug, l.TargetSlug)]
	if !ok {
		return domain.ErrFrontingLinkNotFound
	}
	existing.ScopeMap = l.ScopeMap
	return nil
}

func (s *fakeFrontingLinkStore) Delete(_ context.Context, src, tgt string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.links[key(src, tgt)]; !ok {
		return domain.ErrFrontingLinkNotFound
	}
	delete(s.links, key(src, tgt))
	return nil
}

func (s *fakeFrontingLinkStore) DeleteForResource(_ context.Context, slug string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, l := range s.links {
		if l.SourceSlug == slug || l.TargetSlug == slug {
			delete(s.links, k)
			n++
		}
	}
	return n, nil
}

// fakeAudit captures audit events for assertion.
type fakeAudit struct {
	mu     sync.Mutex
	events []auditdom.Event
}

func newFakeAudit() *fakeAudit { return &fakeAudit{} }

func (f *fakeAudit) Record(_ context.Context, e auditdom.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeAudit) actions() []auditdom.Action {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auditdom.Action, len(f.events))
	for i, e := range f.events {
		out[i] = e.Action
	}
	return out
}

// --- helpers ---

func newFrontingService(t *testing.T) (*FrontingService, *fakeResourceStore, *fakeFrontingLinkStore, *fakeAudit) {
	t.Helper()
	res := newFakeResourceStore()
	links := newFakeFrontingLinkStore()
	a := newFakeAudit()
	return NewFrontingService(links, res, nil, observability.NewNoop(), a), res, links, a
}

func seedResource(t *testing.T, res *fakeResourceStore, slug string, kind resource.BackendKind, scopeNames []string) *resource.Resource {
	t.Helper()
	r := &resource.Resource{
		ID:          "rid-" + slug,
		Slug:        slug,
		DisplayName: slug,
		BackendKind: kind,
	}
	for _, n := range scopeNames {
		r.Scopes = append(r.Scopes, resource.Scope{Name: n})
	}
	if kind == resource.BackendBroker {
		r.BrokerProviderID = "prov-" + slug
	}
	if err := res.Create(context.Background(), r); err != nil {
		t.Fatalf("seed resource %q: %v", slug, err)
	}
	return r
}

// --- tests ---

func TestFrontingService_Create_HappyPath(t *testing.T) {
	svc, res, links, a := newFrontingService(t)
	seedResource(t, res, "gw", resource.BackendMint, []string{"read", "write"})
	seedResource(t, res, "api", resource.BackendMint, []string{"R", "W"})

	link := &resource.FrontingLink{
		SourceSlug: "gw", TargetSlug: "api",
		ScopeMap: resource.ScopeMap{"read": {"R"}, "write": {"W"}},
	}
	if err := svc.Create(context.Background(), link, "alice"); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := links.Get(context.Background(), "gw", "api")
	if err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if got.CreatedBy != "alice" {
		t.Errorf("created_by: got %q, want %q", got.CreatedBy, "alice")
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at not set")
	}
	if !reflect.DeepEqual(map[string][]string(got.ScopeMap), map[string][]string{"read": {"R"}, "write": {"W"}}) {
		t.Errorf("scope_map mismatch: %v", got.ScopeMap)
	}
	if len(a.events) != 1 || a.events[0].Action != auditdom.ActionFrontingLinkCreated {
		t.Errorf("expected single ActionFrontingLinkCreated audit event, got %v", a.actions())
	}
}

func TestFrontingService_Create_RuleByRule(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, res *fakeResourceStore, links *fakeFrontingLinkStore)
		link         *resource.FrontingLink
		wantSentinel error
		wantSubstr   string
	}{
		{
			name: "MissingSource",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "tgt", resource.BackendMint, []string{"S"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "ghost", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{"a": {"S"}},
			},
			wantSubstr: "source_slug",
		},
		{
			name: "MissingTarget",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "src", resource.BackendMint, []string{"a"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "src", TargetSlug: "ghost",
				ScopeMap: resource.ScopeMap{"a": {"S"}},
			},
			wantSubstr: "target_slug",
		},
		{
			name: "SourceNotMint",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "broker-src", resource.BackendBroker, []string{"a"})
				seedResource(t, res, "tgt", resource.BackendMint, []string{"S"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "broker-src", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{"a": {"S"}},
			},
			wantSubstr: "backend_kind=mint",
		},
		{
			name: "ScopeMapKeyMissingFromSource",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "src", resource.BackendMint, []string{"x"})
				seedResource(t, res, "tgt", resource.BackendMint, []string{"S"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "src", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{"missing": {"S"}},
			},
			wantSubstr: "is not a scope on source",
		},
		{
			name: "ScopeMapValueMissingFromTarget",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "src", resource.BackendMint, []string{"a"})
				seedResource(t, res, "tgt", resource.BackendMint, []string{"S"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "src", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{"a": {"WRONG"}},
			},
			wantSubstr: "is not a scope on target",
		},
		{
			name: "DuplicatePair",
			setup: func(t *testing.T, res *fakeResourceStore, links *fakeFrontingLinkStore) {
				seedResource(t, res, "src", resource.BackendMint, []string{"a"})
				seedResource(t, res, "tgt", resource.BackendMint, []string{"S"})
				_ = links.Create(context.Background(), &resource.FrontingLink{
					SourceSlug: "src", TargetSlug: "tgt",
					ScopeMap:  resource.ScopeMap{"a": {"S"}},
					CreatedAt: time.Now().UTC(),
					CreatedBy: "admin",
				})
			},
			link: &resource.FrontingLink{
				SourceSlug: "src", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{"a": {"S"}},
			},
			wantSentinel: domain.ErrFrontingLinkExists,
		},
		{
			name: "BrokerTargetWithoutProvider",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "src", resource.BackendMint, []string{"a"})
				// Manually-craft broker target with empty provider id —
				// real storage rejects this (CHECK constraint), but the
				// service layer also defends against it.
				broken := &resource.Resource{
					ID:          "rid-tgt",
					Slug:        "tgt",
					DisplayName: "tgt",
					BackendKind: resource.BackendBroker,
					Scopes:      []resource.Scope{{Name: "S"}},
				}
				res.bySlug[broken.Slug] = broken.ID
				res.byID[broken.ID] = broken
			},
			link: &resource.FrontingLink{
				SourceSlug: "src", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{"a": {"S"}},
			},
			wantSubstr: "broker_provider_id",
		},
		{
			name: "SelfLoop",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "lonely", resource.BackendMint, []string{"a"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "lonely", TargetSlug: "lonely",
				ScopeMap: resource.ScopeMap{"a": {"a"}},
			},
			wantSubstr: "no self-loop",
		},
		{
			name: "EmptyScopeMap",
			setup: func(t *testing.T, res *fakeResourceStore, _ *fakeFrontingLinkStore) {
				seedResource(t, res, "src", resource.BackendMint, []string{"a"})
				seedResource(t, res, "tgt", resource.BackendMint, []string{"S"})
			},
			link: &resource.FrontingLink{
				SourceSlug: "src", TargetSlug: "tgt",
				ScopeMap: resource.ScopeMap{},
			},
			wantSubstr: "scope_map must contain at least one entry",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, res, links, _ := newFrontingService(t)
			tc.setup(t, res, links)
			err := svc.Create(context.Background(), tc.link, "admin")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantSentinel != nil && !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("expected sentinel %v, got %v", tc.wantSentinel, err)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantSubstr, err.Error())
			}
		})
	}
}

func TestFrontingService_CycleDetection(t *testing.T) {
	t.Run("SelfLoop", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "x", resource.BackendMint, []string{"a"})
		err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "x", TargetSlug: "x",
			ScopeMap: resource.ScopeMap{"a": {"a"}},
		}, "admin")
		// Self-loop is caught at link.Validate() — wantSubstr branch above.
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("TwoCycle", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "a", resource.BackendMint, []string{"s"})
		seedResource(t, res, "b", resource.BackendMint, []string{"s"})

		// a→b is fine.
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "a", TargetSlug: "b",
			ScopeMap: resource.ScopeMap{"s": {"s"}},
		}, "admin"); err != nil {
			t.Fatalf("a→b: %v", err)
		}

		// b→a closes the cycle.
		err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "b", TargetSlug: "a",
			ScopeMap: resource.ScopeMap{"s": {"s"}},
		}, "admin")
		if !errors.Is(err, domain.ErrFrontingLinkCycle) {
			t.Fatalf("expected ErrFrontingLinkCycle, got %v", err)
		}
	})

	t.Run("ThreeCycle", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "a", resource.BackendMint, []string{"s"})
		seedResource(t, res, "b", resource.BackendMint, []string{"s"})
		seedResource(t, res, "c", resource.BackendMint, []string{"s"})

		mustCreate := func(s, t1 string) {
			err := svc.Create(context.Background(), &resource.FrontingLink{
				SourceSlug: s, TargetSlug: t1,
				ScopeMap: resource.ScopeMap{"s": {"s"}},
			}, "admin")
			if err != nil {
				t.Fatalf("%s→%s: %v", s, t1, err)
			}
		}
		mustCreate("a", "b")
		mustCreate("b", "c")

		// c→a closes the 3-cycle.
		err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "c", TargetSlug: "a",
			ScopeMap: resource.ScopeMap{"s": {"s"}},
		}, "admin")
		if !errors.Is(err, domain.ErrFrontingLinkCycle) {
			t.Fatalf("expected ErrFrontingLinkCycle, got %v", err)
		}
	})

	t.Run("Diamond_NotACycle", func(t *testing.T) {
		// a→b, a→c, b→d, c→d — diamond (multiple paths from a to d) but
		// no cycle. All four edges must succeed.
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "a", resource.BackendMint, []string{"s"})
		seedResource(t, res, "b", resource.BackendMint, []string{"s"})
		seedResource(t, res, "c", resource.BackendMint, []string{"s"})
		seedResource(t, res, "d", resource.BackendMint, []string{"s"})

		mustCreate := func(s, t1 string) {
			err := svc.Create(context.Background(), &resource.FrontingLink{
				SourceSlug: s, TargetSlug: t1,
				ScopeMap: resource.ScopeMap{"s": {"s"}},
			}, "admin")
			if err != nil {
				t.Fatalf("%s→%s: %v", s, t1, err)
			}
		}
		mustCreate("a", "b")
		mustCreate("a", "c")
		mustCreate("b", "d")
		mustCreate("c", "d") // diamond complete; no cycle
	})
}

func TestFrontingService_Validate_DryRunDoesNotPersist(t *testing.T) {
	svc, res, links, recorder := newFrontingService(t)
	seedResource(t, res, "src", resource.BackendMint, []string{"a"})
	seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})

	link := &resource.FrontingLink{
		SourceSlug: "src", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}
	if err := svc.Validate(context.Background(), link); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Validate must not persist or audit.
	if got, _ := links.Get(context.Background(), "src", "tgt"); got != nil {
		t.Errorf("validate persisted a row")
	}
	if len(recorder.events) != 0 {
		t.Errorf("validate emitted audit events: %v", recorder.actions())
	}
}

func TestFrontingService_Patch_ScopeMap(t *testing.T) {
	svc, res, links, _ := newFrontingService(t)
	seedResource(t, res, "src", resource.BackendMint, []string{"a", "b"})
	seedResource(t, res, "tgt", resource.BackendMint, []string{"A", "B"})

	if err := svc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "src", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}, "alice"); err != nil {
		t.Fatalf("create: %v", err)
	}

	newMap := resource.ScopeMap{"a": {"A"}, "b": {"B"}}
	updated, err := svc.Patch(context.Background(), "src", "tgt", input.FrontingLinkPatch{ScopeMap: &newMap}, "bob")
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if !reflect.DeepEqual(map[string][]string(updated.ScopeMap), map[string][]string{"a": {"A"}, "b": {"B"}}) {
		t.Errorf("scope_map not updated: %v", updated.ScopeMap)
	}

	// Empty patch — ScopeMap nil — must not mutate or audit.
	preEvents := 0
	if a, ok := svc.audit.(*fakeAudit); ok {
		preEvents = len(a.events)
	}
	_, err = svc.Patch(context.Background(), "src", "tgt", input.FrontingLinkPatch{}, "carol")
	if err != nil {
		t.Fatalf("noop patch: %v", err)
	}
	if a, ok := svc.audit.(*fakeAudit); ok && len(a.events) != preEvents {
		t.Errorf("noop patch emitted %d new audit events", len(a.events)-preEvents)
	}

	// Provenance preserved across patch.
	got, _ := links.Get(context.Background(), "src", "tgt")
	if got.CreatedBy != "alice" {
		t.Errorf("created_by clobbered: %q", got.CreatedBy)
	}
}

// TestFrontingService_Patch_EmptyScopeMap_Rejects guards the wire-contract
// distinction the PATCH-dirty pattern enforces: a nil ScopeMap pointer is
// LEFT UNCHANGED (no-op), an explicit empty map is a wipe attempt and must
// reject. Without this test, a regression that treats `*patch.ScopeMap`
// as no-op when empty would silently let callers wipe the map.
func TestFrontingService_Patch_EmptyScopeMap_Rejects(t *testing.T) {
	svc, res, links, _ := newFrontingService(t)
	seedResource(t, res, "src", resource.BackendMint, []string{"a"})
	seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
	if err := svc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "src", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}, "admin"); err != nil {
		t.Fatalf("create: %v", err)
	}

	empty := resource.ScopeMap{}
	_, err := svc.Patch(context.Background(), "src", "tgt", input.FrontingLinkPatch{ScopeMap: &empty}, "admin")
	if err == nil {
		t.Fatal("expected empty-scope-map rejection, got nil")
	}
	if !strings.Contains(err.Error(), "scope_map must contain at least one entry") {
		t.Errorf("expected non-empty rule message, got %q", err.Error())
	}

	// Underlying row unchanged.
	got, _ := links.Get(context.Background(), "src", "tgt")
	if len(got.ScopeMap) != 1 {
		t.Errorf("scope_map clobbered by rejected patch: %v", got.ScopeMap)
	}
}

func TestFrontingService_Patch_RevalidatesScopeMembership(t *testing.T) {
	svc, res, _, _ := newFrontingService(t)
	seedResource(t, res, "src", resource.BackendMint, []string{"a"})
	seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
	if err := svc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "src", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}, "admin"); err != nil {
		t.Fatalf("create: %v", err)
	}

	bad := resource.ScopeMap{"a": {"NOT_ON_TARGET"}}
	_, err := svc.Patch(context.Background(), "src", "tgt", input.FrontingLinkPatch{ScopeMap: &bad}, "admin")
	if err == nil || !strings.Contains(err.Error(), "is not a scope on target") {
		t.Fatalf("expected target-scope rejection, got %v", err)
	}
}

func TestFrontingService_ValidateResourceUpdate(t *testing.T) {
	t.Run("ScopeRemoval_OnSource_Blocked", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "src", resource.BackendMint, []string{"a", "b"})
		seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "src", TargetSlug: "tgt",
			ScopeMap: resource.ScopeMap{"a": {"A"}},
		}, "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}

		prev, _ := res.GetBySlug(context.Background(), "src")
		next := *prev
		next.Scopes = []resource.Scope{{Name: "b"}} // dropped "a"
		err := svc.ValidateResourceUpdate(context.Background(), prev, &next)
		if err == nil || !strings.Contains(err.Error(), "cannot remove scope") {
			t.Fatalf("expected scope-removal block, got %v", err)
		}
	})

	t.Run("ScopeRemoval_OnTarget_Blocked", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "src", resource.BackendMint, []string{"a"})
		seedResource(t, res, "tgt", resource.BackendMint, []string{"A", "B"})
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "src", TargetSlug: "tgt",
			ScopeMap: resource.ScopeMap{"a": {"A"}},
		}, "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}

		prev, _ := res.GetBySlug(context.Background(), "tgt")
		next := *prev
		next.Scopes = []resource.Scope{{Name: "B"}} // dropped "A"
		err := svc.ValidateResourceUpdate(context.Background(), prev, &next)
		if err == nil || !strings.Contains(err.Error(), "cannot remove scope") {
			t.Fatalf("expected scope-removal block, got %v", err)
		}
	})

	t.Run("ScopeRename_OnSource_Blocked", func(t *testing.T) {
		// Spec: scope rename referenced by a link is forbidden entirely.
		// The implementation collapses rename → remove + add; this test
		// pins that semantic. Renaming source's "a" → "view" while "a"
		// is a scope_map key on a link must reject identically to a
		// plain removal.
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "src", resource.BackendMint, []string{"a"})
		seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "src", TargetSlug: "tgt",
			ScopeMap: resource.ScopeMap{"a": {"A"}},
		}, "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}

		prev, _ := res.GetBySlug(context.Background(), "src")
		next := *prev
		next.Scopes = []resource.Scope{{Name: "view"}} // renamed "a" → "view"
		err := svc.ValidateResourceUpdate(context.Background(), prev, &next)
		if err == nil || !strings.Contains(err.Error(), "cannot remove scope") {
			t.Fatalf("expected scope-rename block (via removal path), got %v", err)
		}
	})

	t.Run("ScopeRename_OnTarget_Blocked", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "src", resource.BackendMint, []string{"a"})
		seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "src", TargetSlug: "tgt",
			ScopeMap: resource.ScopeMap{"a": {"A"}},
		}, "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}

		prev, _ := res.GetBySlug(context.Background(), "tgt")
		next := *prev
		next.Scopes = []resource.Scope{{Name: "READ"}} // renamed "A" → "READ"
		err := svc.ValidateResourceUpdate(context.Background(), prev, &next)
		if err == nil || !strings.Contains(err.Error(), "cannot remove scope") {
			t.Fatalf("expected target scope-rename block, got %v", err)
		}
	})

	t.Run("ScopeRemoval_Unreferenced_Allowed", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "src", resource.BackendMint, []string{"a", "b"})
		seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "src", TargetSlug: "tgt",
			ScopeMap: resource.ScopeMap{"a": {"A"}},
		}, "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}

		prev, _ := res.GetBySlug(context.Background(), "src")
		next := *prev
		next.Scopes = []resource.Scope{{Name: "a"}} // dropped "b" (not referenced)
		if err := svc.ValidateResourceUpdate(context.Background(), prev, &next); err != nil {
			t.Errorf("unreferenced scope removal blocked: %v", err)
		}
	})

	t.Run("KindChange_Forbidden", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "src", resource.BackendMint, []string{"a"})
		seedResource(t, res, "tgt", resource.BackendMint, []string{"A"})
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: "src", TargetSlug: "tgt",
			ScopeMap: resource.ScopeMap{"a": {"A"}},
		}, "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}

		prev, _ := res.GetBySlug(context.Background(), "src")
		next := *prev
		next.BackendKind = resource.BackendBroker
		err := svc.ValidateResourceUpdate(context.Background(), prev, &next)
		if err == nil || !strings.Contains(err.Error(), "kind change") {
			t.Fatalf("expected kind-change block, got %v", err)
		}
	})

	t.Run("NoLinks_AllowsAnyChange", func(t *testing.T) {
		svc, res, _, _ := newFrontingService(t)
		seedResource(t, res, "lonely", resource.BackendMint, []string{"a", "b"})
		prev, _ := res.GetBySlug(context.Background(), "lonely")
		next := *prev
		next.Scopes = []resource.Scope{} // wipe everything
		next.BackendKind = resource.BackendBroker
		next.BrokerProviderID = "anything"
		if err := svc.ValidateResourceUpdate(context.Background(), prev, &next); err != nil {
			t.Errorf("change-with-no-links blocked: %v", err)
		}
	})
}

func TestFrontingService_CascadeDeleteForResource(t *testing.T) {
	svc, res, links, recorder := newFrontingService(t)
	seedResource(t, res, "a", resource.BackendMint, []string{"s"})
	seedResource(t, res, "b", resource.BackendMint, []string{"s"})
	seedResource(t, res, "c", resource.BackendMint, []string{"s"})

	mustCreate := func(s, t1 string) {
		if err := svc.Create(context.Background(), &resource.FrontingLink{
			SourceSlug: s, TargetSlug: t1,
			ScopeMap: resource.ScopeMap{"s": {"s"}},
		}, "admin"); err != nil {
			t.Fatalf("%s→%s: %v", s, t1, err)
		}
	}
	mustCreate("a", "b")
	mustCreate("b", "c")
	mustCreate("a", "c") // unrelated to b — must survive

	auditPre := len(recorder.events)
	dependents, err := svc.CascadeDeleteForResource(context.Background(), "b", "alice")
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if len(dependents) != 2 {
		t.Errorf("expected 2 dependents, got %d", len(dependents))
	}

	// Two deletion audit events emitted.
	deletionEvents := 0
	for _, e := range recorder.events[auditPre:] {
		if e.Action == auditdom.ActionFrontingLinkDeleted {
			deletionEvents++
		}
	}
	if deletionEvents != 2 {
		t.Errorf("expected 2 deletion audit events, got %d", deletionEvents)
	}

	survivors, _ := links.List(context.Background(), output.FrontingLinkFilter{})
	if len(survivors) != 1 {
		t.Errorf("expected 1 surviving link (a→c), got %d", len(survivors))
	}
}
