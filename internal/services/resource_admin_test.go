package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	clientdom "github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// fakeResourceStore is a minimal in-memory output.ResourceStore for unit
// tests.
type fakeResourceStore struct {
	mu       sync.Mutex
	byID     map[string]*resource.Resource
	bySlug   map[string]string
	deleteFn func(ctx context.Context, id string) error
}

func newFakeResourceStore() *fakeResourceStore {
	return &fakeResourceStore{
		byID:   make(map[string]*resource.Resource),
		bySlug: make(map[string]string),
	}
}

func (s *fakeResourceStore) GetByID(_ context.Context, id string) (*resource.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrResourceNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *fakeResourceStore) GetBySlug(_ context.Context, slug string) (*resource.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySlug[slug]
	if !ok {
		return nil, domain.ErrResourceNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *fakeResourceStore) Resolve(_ context.Context, _ string) ([]*resource.Resource, error) {
	return nil, nil
}

func (s *fakeResourceStore) List(_ context.Context, filter output.ResourceFilter) ([]*resource.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*resource.Resource, 0, len(s.byID))
	for _, r := range s.byID {
		if filter.BackendKind != "" && r.BackendKind != filter.BackendKind {
			continue
		}
		if filter.BrokerProviderID != "" && r.BrokerProviderID != filter.BrokerProviderID {
			continue
		}
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

func (s *fakeResourceStore) Create(_ context.Context, r *resource.Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bySlug[r.Slug]; exists {
		return errors.New("duplicate slug")
	}
	cp := *r
	s.byID[r.ID] = &cp
	s.bySlug[r.Slug] = r.ID
	return nil
}

func (s *fakeResourceStore) Update(_ context.Context, r *resource.Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.byID[r.ID]
	if !ok {
		return domain.ErrResourceNotFound
	}
	if existing.Slug != r.Slug {
		delete(s.bySlug, existing.Slug)
		s.bySlug[r.Slug] = r.ID
	}
	cp := *r
	s.byID[r.ID] = &cp
	return nil
}

func (s *fakeResourceStore) Delete(ctx context.Context, id string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return domain.ErrResourceNotFound
	}
	delete(s.byID, id)
	delete(s.bySlug, r.Slug)
	return nil
}

func (s *fakeResourceStore) FindByRuntimeClientID(_ context.Context, clientID string) (*resource.Resource, error) {
	if clientID == "" {
		return nil, domain.ErrResourceNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matches []*resource.Resource
	for _, r := range s.byID {
		for _, cid := range r.Policy.Runtime.ClientIDs {
			if cid == clientID {
				cp := *r
				matches = append(matches, &cp)
				break
			}
		}
	}
	switch len(matches) {
	case 0:
		return nil, domain.ErrResourceNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, domain.ErrAmbiguousResource
	}
}

// fakeBrokerProviderStore is the minimal in-memory store the admin service
// needs for cross-table validation.
type fakeBrokerProviderStore struct {
	mu       sync.Mutex
	byID     map[string]*resource.BrokerProvider
	bySlug   map[string]string
	deleteFn func(ctx context.Context, id string) error
}

func newFakeBrokerProviderStore() *fakeBrokerProviderStore {
	return &fakeBrokerProviderStore{
		byID:   make(map[string]*resource.BrokerProvider),
		bySlug: make(map[string]string),
	}
}

func (s *fakeBrokerProviderStore) GetByID(_ context.Context, id string) (*resource.BrokerProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrResourceNotFound
	}
	cp := *p
	return &cp, nil
}

func (s *fakeBrokerProviderStore) GetBySlug(_ context.Context, slug string) (*resource.BrokerProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySlug[slug]
	if !ok {
		return nil, domain.ErrResourceNotFound
	}
	cp := *s.byID[id]
	return &cp, nil
}

func (s *fakeBrokerProviderStore) List(_ context.Context) ([]*resource.BrokerProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*resource.BrokerProvider, 0, len(s.byID))
	for _, p := range s.byID {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func (s *fakeBrokerProviderStore) Create(_ context.Context, p *resource.BrokerProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bySlug[p.Slug]; exists {
		return errors.New("duplicate slug")
	}
	cp := *p
	s.byID[p.ID] = &cp
	s.bySlug[p.Slug] = p.ID
	return nil
}

func (s *fakeBrokerProviderStore) Update(_ context.Context, p *resource.BrokerProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.byID[p.ID]
	if !ok {
		return domain.ErrResourceNotFound
	}
	if existing.Slug != p.Slug {
		delete(s.bySlug, existing.Slug)
		s.bySlug[p.Slug] = p.ID
	}
	cp := *p
	s.byID[p.ID] = &cp
	return nil
}

func (s *fakeBrokerProviderStore) Delete(ctx context.Context, id string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	if !ok {
		return domain.ErrResourceNotFound
	}
	delete(s.byID, id)
	delete(s.bySlug, p.Slug)
	return nil
}

func (s *fakeBrokerProviderStore) seed(id, slug string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = &resource.BrokerProvider{
		ID:          id,
		Slug:        slug,
		DisplayName: slug,
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte("{}"),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	s.bySlug[slug] = id
}

// fakeClientStore is a minimal in-memory output.ClientStore for the policy
// validation path.
type fakeClientStore struct {
	mu   sync.Mutex
	byID map[string]*clientdom.Client
}

func newFakeClientStore() *fakeClientStore {
	return &fakeClientStore{byID: make(map[string]*clientdom.Client)}
}

func (s *fakeClientStore) Create(_ context.Context, c *clientdom.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.byID[c.ID] = &cp
	return nil
}

func (s *fakeClientStore) GetByID(_ context.Context, id string) (*clientdom.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrInvalidClient
	}
	cp := *c
	return &cp, nil
}

func (s *fakeClientStore) GetByCIMDURL(_ context.Context, _ string) (*clientdom.Client, error) {
	return nil, domain.ErrInvalidClient
}

func (s *fakeClientStore) Update(_ context.Context, c *clientdom.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.byID[c.ID] = &cp
	return nil
}

func (s *fakeClientStore) List(_ context.Context, _ string, _ string, _, _ int) ([]clientdom.Client, error) {
	return nil, nil
}

func (s *fakeClientStore) Count(_ context.Context, _ string) (int, error) { return 0, nil }

func (s *fakeClientStore) ListAgents(_ context.Context) ([]clientdom.Client, error) {
	return nil, nil
}

func (s *fakeClientStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	return nil
}

func (s *fakeClientStore) seed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = &clientdom.Client{ID: id, Status: clientdom.StatusActive}
}

// resourceAdminTestEnv bundles the wired-up service plus its dependencies for
// tests.
type resourceAdminTestEnv struct {
	svc       *ResourceAdminService
	resources *fakeResourceStore
	providers *fakeBrokerProviderStore
	clients   *fakeClientStore
	audit     *mockAuditRecorder
}

func newResourceAdminTestEnv() *resourceAdminTestEnv {
	resources := newFakeResourceStore()
	providers := newFakeBrokerProviderStore()
	clients := newFakeClientStore()
	auditMock := &mockAuditRecorder{}
	svc := NewResourceAdminService(resources, providers, clients, observability.NewNoop(), auditMock)
	return &resourceAdminTestEnv{
		svc:       svc,
		resources: resources,
		providers: providers,
		clients:   clients,
		audit:     auditMock,
	}
}

func TestResourceAdmin_Create_HappyPath(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.providers.seed("p-google", "google-workspace")
	ctx := context.Background()

	r := &resource.Resource{
		Slug:             "google-calendar",
		DisplayName:      "Google Calendar",
		URI:              "https://www.googleapis.com/calendar/v3",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "p-google",
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if r.ID == "" {
		t.Fatal("expected ID to be assigned")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}

	got, err := env.svc.GetByID(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Slug != "google-calendar" {
		t.Errorf("slug: got %q, want %q", got.Slug, "google-calendar")
	}
}

func TestResourceAdmin_Create_RejectsCallerSuppliedID(t *testing.T) {
	env := newResourceAdminTestEnv()
	r := &resource.Resource{
		ID:          "caller-supplied",
		Slug:        "x",
		BackendKind: resource.BackendMint,
	}
	err := env.svc.Create(context.Background(), r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request domain error, got %v", err)
	}
}

func TestResourceAdmin_Create_RejectsInvalidSlug(t *testing.T) {
	env := newResourceAdminTestEnv()
	r := &resource.Resource{
		Slug:        "Invalid Slug!",
		BackendKind: resource.BackendMint,
	}
	err := env.svc.Create(context.Background(), r)
	if !errors.Is(err, domain.ErrInvalidSlug) {
		t.Fatalf("expected ErrInvalidSlug, got %v", err)
	}
}

func TestResourceAdmin_Create_BrokerKindMissingProvider_Rejected(t *testing.T) {
	env := newResourceAdminTestEnv()
	r := &resource.Resource{
		Slug:        "needs-provider",
		BackendKind: resource.BackendBroker,
	}
	err := env.svc.Create(context.Background(), r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestResourceAdmin_Create_UnknownBrokerProvider_Rejected(t *testing.T) {
	env := newResourceAdminTestEnv()
	r := &resource.Resource{
		Slug:             "dangling",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "does-not-exist",
	}
	err := env.svc.Create(context.Background(), r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request, got %v", err)
	}
}

func TestResourceAdmin_Create_PolicyAllowsUnknownClient_Rejected(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.clients.seed("known-client")
	r := &resource.Resource{
		Slug:        "policy-bad",
		BackendKind: resource.BackendMint,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{
				AllowedClientIDs: []string{"known-client", "unknown-client"},
			},
		},
	}
	err := env.svc.Create(context.Background(), r)
	if err == nil {
		t.Fatal("expected error for unknown client_id, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request, got %v", err)
	}
}

// TestResourceAdmin_Patch_AppliesOnlySuppliedFields is the load-bearing
// security regression: omitting `policy` from the patch must keep the
// existing policy.exchange.allowed_client_ids intact.
func TestResourceAdmin_Patch_AppliesOnlySuppliedFields(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.clients.seed("x")
	ctx := context.Background()

	r := &resource.Resource{
		Slug:        "guarded",
		BackendKind: resource.BackendMint,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: []string{"x"}},
		},
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	newDisplay := "Guarded (renamed)"
	got, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{DisplayName: &newDisplay})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if got.DisplayName != newDisplay {
		t.Errorf("display_name: got %q, want %q", got.DisplayName, newDisplay)
	}
	if len(got.Policy.Exchange.AllowedClientIDs) != 1 || got.Policy.Exchange.AllowedClientIDs[0] != "x" {
		t.Errorf("allow-list widened or wiped: got %v, want [x]", got.Policy.Exchange.AllowedClientIDs)
	}
}

func TestResourceAdmin_Patch_ExplicitEmptyPolicy_Wipes(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.clients.seed("x")
	ctx := context.Background()

	r := &resource.Resource{
		Slug:        "wipeable",
		BackendKind: resource.BackendMint,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: []string{"x"}},
		},
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	emptyPolicy := resource.Policy{}
	got, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{Policy: &emptyPolicy})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(got.Policy.Exchange.AllowedClientIDs) != 0 {
		t.Errorf("expected wiped allowlist, got %v", got.Policy.Exchange.AllowedClientIDs)
	}
}

func TestResourceAdmin_Patch_ResultingResourceMustValidate(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.providers.seed("p-x", "px")
	ctx := context.Background()

	r := &resource.Resource{
		Slug:             "broker-r",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "p-x",
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	mint := resource.BackendMint
	_, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{BackendKind: &mint})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestResourceAdmin_Create_DuplicateSlug_Returns409(t *testing.T) {
	env := newResourceAdminTestEnv()
	ctx := context.Background()

	first := &resource.Resource{Slug: "dup", BackendKind: resource.BackendMint}
	if err := env.svc.Create(ctx, first); err != nil {
		t.Fatalf("seed: %v", err)
	}

	second := &resource.Resource{Slug: "dup", BackendKind: resource.BackendMint}
	err := env.svc.Create(ctx, second)
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != domain.CodeConflict {
		t.Errorf("expected CodeConflict domain error, got %v", err)
	}
}

func TestResourceAdmin_Patch_SlugCollision_Returns409(t *testing.T) {
	env := newResourceAdminTestEnv()
	ctx := context.Background()

	a := &resource.Resource{Slug: "alpha", BackendKind: resource.BackendMint}
	b := &resource.Resource{Slug: "bravo", BackendKind: resource.BackendMint}
	if err := env.svc.Create(ctx, a); err != nil {
		t.Fatalf("seed alpha: %v", err)
	}
	if err := env.svc.Create(ctx, b); err != nil {
		t.Fatalf("seed bravo: %v", err)
	}

	// Try to rename b → "alpha".
	clash := "alpha"
	_, err := env.svc.Patch(ctx, b.ID, input.ResourcePatch{Slug: &clash})
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != domain.CodeConflict {
		t.Errorf("expected CodeConflict, got %v", err)
	}
}

func TestResourceAdmin_Patch_SlugNoOpRewrite_Succeeds(t *testing.T) {
	env := newResourceAdminTestEnv()
	ctx := context.Background()

	r := &resource.Resource{Slug: "same", BackendKind: resource.BackendMint}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Patch slug → same value: must succeed (excludeID guard).
	same := "same"
	if _, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{Slug: &same}); err != nil {
		t.Fatalf("no-op slug rewrite failed: %v", err)
	}
}

func TestResourceAdmin_Delete_FKBlock_Returns409Code(t *testing.T) {
	env := newResourceAdminTestEnv()
	ctx := context.Background()

	r := &resource.Resource{Slug: "fk-blocked", BackendKind: resource.BackendMint}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("seed: %v", err)
	}
	env.resources.deleteFn = func(_ context.Context, _ string) error {
		return domain.ErrResourceHasReferences
	}

	err := env.svc.Delete(ctx, r.ID)
	if !errors.Is(err, domain.ErrResourceHasReferences) {
		t.Fatalf("expected ErrResourceHasReferences, got %v", err)
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != domain.CodeConflict {
		t.Errorf("expected CodeConflict, got %v", err)
	}
}

func TestResourceAdmin_Delete_NotFound(t *testing.T) {
	env := newResourceAdminTestEnv()
	err := env.svc.Delete(context.Background(), "does-not-exist")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound, got %v", err)
	}
}

func TestResourceAdmin_AuditRecordedOnEveryMutation(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.providers.seed("p-a", "audit")
	ctx := context.Background()

	r := &resource.Resource{
		Slug:             "audit-resource",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "p-a",
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}

	displayName := "Audit (renamed)"
	if _, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{DisplayName: &displayName}); err != nil {
		t.Fatalf("Patch: %v", err)
	}

	if err := env.svc.Delete(ctx, r.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	wantActions := map[audit.Action]bool{
		audit.ActionResourceCreated: false,
		audit.ActionResourcePatched: false,
		audit.ActionResourceDeleted: false,
	}
	for _, e := range env.audit.events {
		if _, ok := wantActions[e.Action]; ok {
			wantActions[e.Action] = true
		}
	}
	for action, seen := range wantActions {
		if !seen {
			t.Errorf("missing audit event for %s", action)
		}
	}
}

// TestResourceAdmin_Create_LowercasesSlug locks slug case-folding through
// the service: callers can send mixed-case input and the persisted slug is
// canonical lowercase. The slug-conflict pre-check relies on this so a
// rename to "ALPHA" correctly clashes with an existing "alpha" row.
func TestResourceAdmin_Create_LowercasesSlug(t *testing.T) {
	env := newResourceAdminTestEnv()
	r := &resource.Resource{Slug: "GOOGLE-Calendar", BackendKind: resource.BackendMint}
	if err := env.svc.Create(context.Background(), r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if r.Slug != "google-calendar" {
		t.Errorf("slug not lowercased: got %q, want %q", r.Slug, "google-calendar")
	}
}

// TestResourceAdmin_Patch_EmptyPatchIsNoOp locks the F5 fix: PATCH with no
// fields touched returns the current resource without bumping UpdatedAt or
// emitting an audit event. Write amplification + audit-log noise reduction.
func TestResourceAdmin_Patch_EmptyPatchIsNoOp(t *testing.T) {
	env := newResourceAdminTestEnv()
	ctx := context.Background()

	r := &resource.Resource{Slug: "no-op", BackendKind: resource.BackendMint}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("seed: %v", err)
	}
	updatedBefore := r.UpdatedAt
	auditBefore := len(env.audit.events)

	got, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if !got.UpdatedAt.Equal(updatedBefore) {
		t.Errorf("UpdatedAt bumped on empty patch: before=%v after=%v", updatedBefore, got.UpdatedAt)
	}
	if len(env.audit.events) != auditBefore {
		t.Errorf("audit event emitted on empty patch: before=%d after=%d", auditBefore, len(env.audit.events))
	}
}

// TestResourceAdmin_List_PassesFilterThrough is the regression for audit
// finding F9: the service must thread the input.ResourceFilter into the
// store's output.ResourceFilter without mistransforming any field.
func TestResourceAdmin_List_PassesFilterThrough(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.providers.seed("p-list", "list-broker")
	ctx := context.Background()

	// Seed two Mint and two Broker resources.
	for _, slug := range []string{"mint-a", "mint-b"} {
		r := &resource.Resource{Slug: slug, BackendKind: resource.BackendMint}
		if err := env.svc.Create(ctx, r); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}
	for _, slug := range []string{"broker-a", "broker-b"} {
		r := &resource.Resource{
			Slug: slug, BackendKind: resource.BackendBroker, BrokerProviderID: "p-list",
		}
		if err := env.svc.Create(ctx, r); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}

	t.Run("no filter returns all", func(t *testing.T) {
		got, err := env.svc.List(ctx, input.ResourceFilter{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 4 {
			t.Errorf("got %d rows, want 4", len(got))
		}
	})

	t.Run("backend_kind=mint", func(t *testing.T) {
		got, err := env.svc.List(ctx, input.ResourceFilter{BackendKind: resource.BackendMint})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("got %d mint rows, want 2", len(got))
		}
		for _, r := range got {
			if r.BackendKind != resource.BackendMint {
				t.Errorf("non-mint row in mint filter: %+v", r)
			}
		}
	})

	t.Run("backend_kind=broker", func(t *testing.T) {
		got, err := env.svc.List(ctx, input.ResourceFilter{BackendKind: resource.BackendBroker})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("got %d broker rows, want 2", len(got))
		}
	})

	t.Run("broker_provider_id filter", func(t *testing.T) {
		got, err := env.svc.List(ctx, input.ResourceFilter{BrokerProviderID: "p-list"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("got %d rows, want 2 (broker-a + broker-b)", len(got))
		}
	})

	t.Run("nonexistent broker_provider_id returns empty", func(t *testing.T) {
		got, err := env.svc.List(ctx, input.ResourceFilter{BrokerProviderID: "p-nope"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %d rows, want 0", len(got))
		}
	})
}

// TestResourceAdmin_Mint_DropsConnectPolicy is the regression for audit
// finding G7: a caller-supplied policy.connect on a Mint resource MUST
// NOT be persisted, even though the wire response correctly hides it.
// Without this guard, the orphaned data reappears on a Mint→Broker
// conversion.
func TestResourceAdmin_Mint_DropsConnectPolicy(t *testing.T) {
	env := newResourceAdminTestEnv()
	ctx := context.Background()

	// Create with a connect block on a Mint resource — should persist as empty.
	r := &resource.Resource{
		Slug:        "mint-drop-connect",
		BackendKind: resource.BackendMint,
		Policy: resource.Policy{
			Connect: resource.ConnectPolicy{
				AllowedReturnURLs: []string{"https://app/cb1", "https://app/cb2"},
			},
		},
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := env.svc.GetByID(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(got.Policy.Connect.AllowedReturnURLs) != 0 {
		t.Errorf("Mint resource persisted connect.allowed_return_urls: %v", got.Policy.Connect.AllowedReturnURLs)
	}

	// Patch attempting to add a connect block — should still drop on save.
	patched, err := env.svc.Patch(ctx, r.ID, input.ResourcePatch{
		Policy: &resource.Policy{
			Connect: resource.ConnectPolicy{
				AllowedReturnURLs: []string{"https://app/cb3"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(patched.Policy.Connect.AllowedReturnURLs) != 0 {
		t.Errorf("Mint resource patched connect leaked through: %v", patched.Policy.Connect.AllowedReturnURLs)
	}
}

// TestResourceAdmin_Broker_PreservesConnectPolicy is the inverse — Broker
// resources MUST keep the operator-supplied connect policy.
func TestResourceAdmin_Broker_PreservesConnectPolicy(t *testing.T) {
	env := newResourceAdminTestEnv()
	env.providers.seed("p-bk-connect", "bk-connect")
	ctx := context.Background()

	r := &resource.Resource{
		Slug:             "broker-keeps-connect",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "p-bk-connect",
		Policy: resource.Policy{
			Connect: resource.ConnectPolicy{
				AllowedReturnURLs: []string{"https://app/cb"},
			},
		},
	}
	if err := env.svc.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := env.svc.GetByID(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(got.Policy.Connect.AllowedReturnURLs) != 1 || got.Policy.Connect.AllowedReturnURLs[0] != "https://app/cb" {
		t.Errorf("Broker connect.allowed_return_urls lost: %v", got.Policy.Connect.AllowedReturnURLs)
	}
}
