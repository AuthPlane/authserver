package services

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
)

// fakeConsentGrantStore is a minimal in-memory output.ConsentGrantStore
// for grant-admin unit tests.
type fakeConsentGrantStore struct {
	mu   sync.Mutex
	rows map[string]*resource.ConsentGrant
}

func newFakeConsentGrantStore() *fakeConsentGrantStore {
	return &fakeConsentGrantStore{rows: make(map[string]*resource.ConsentGrant)}
}

func (s *fakeConsentGrantStore) Get(_ context.Context, userID, clientID, resourceID string) (*resource.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.rows {
		if g.UserID == userID && g.ClientID == clientID && g.ResourceID == resourceID && g.RevokedAt == nil {
			cp := *g
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *fakeConsentGrantStore) GetByID(_ context.Context, id string) (*resource.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.rows[id]
	if !ok {
		return nil, nil
	}
	cp := *g
	return &cp, nil
}

func (s *fakeConsentGrantStore) Upsert(_ context.Context, g *resource.ConsentGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.rows[g.ID] = &cp
	return nil
}

func (s *fakeConsentGrantStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.rows[id]
	if !ok {
		return nil // idempotent
	}
	now := time.Now().UTC()
	g.RevokedAt = &now
	return nil
}

func (s *fakeConsentGrantStore) ListForUser(_ context.Context, userID string) ([]*resource.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.ConsentGrant
	for _, g := range s.rows {
		if g.UserID == userID {
			cp := *g
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// fakeBrokerGrantStore is a minimal in-memory output.BrokerGrantStore.
type fakeBrokerGrantStore struct {
	mu   sync.Mutex
	rows map[string]*resource.BrokerGrant
}

func newFakeBrokerGrantStore() *fakeBrokerGrantStore {
	return &fakeBrokerGrantStore{rows: make(map[string]*resource.BrokerGrant)}
}

func (s *fakeBrokerGrantStore) Get(_ context.Context, userID, brokerProviderID string) (*resource.BrokerGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.rows {
		if g.UserID == userID && g.BrokerProviderID == brokerProviderID && g.RevokedAt == nil {
			cp := *g
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *fakeBrokerGrantStore) GetByID(_ context.Context, id string) (*resource.BrokerGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.rows[id]
	if !ok {
		return nil, nil
	}
	cp := *g
	return &cp, nil
}

func (s *fakeBrokerGrantStore) Create(_ context.Context, g *resource.BrokerGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.rows[g.ID] = &cp
	return nil
}

func (s *fakeBrokerGrantStore) Upsert(_ context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.rows {
		if existing.UserID == g.UserID && existing.BrokerProviderID == g.BrokerProviderID {
			existing.CredentialData = g.CredentialData
			existing.ScopesGranted = g.ScopesGranted
			existing.EncBackend = g.EncBackend
			existing.Version++
			existing.UpdatedAt = time.Now().UTC()
			existing.RevokedAt = nil
			cp := *existing
			cp.ID = id
			return &cp, nil
		}
	}
	cp := *g
	if cp.Version == 0 {
		cp.Version = 1
	}
	s.rows[g.ID] = &cp
	out := cp
	return &out, nil
}

func (s *fakeBrokerGrantStore) UpdateWithVersion(_ context.Context, _ *resource.BrokerGrant) error {
	return nil
}

func (s *fakeBrokerGrantStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.rows[id]
	if !ok {
		return nil // idempotent
	}
	now := time.Now().UTC()
	g.RevokedAt = &now
	return nil
}

func (s *fakeBrokerGrantStore) ListForUser(_ context.Context, userID string) ([]*resource.BrokerGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.BrokerGrant
	for _, g := range s.rows {
		if g.UserID == userID {
			cp := *g
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// fakeIssuanceStore is a minimal in-memory output.IssuanceStore.
type fakeIssuanceStore struct {
	mu   sync.Mutex
	rows map[string]*resource.Issuance

	// revokeFamilyErr lets a test inject a cascade failure to exercise
	// the partial-success path in GrantAdminService.RevokeConsent.
	revokeFamilyErr error
	revokeErr       error
	getByIDErr      error
}

func newFakeIssuanceStore() *fakeIssuanceStore {
	return &fakeIssuanceStore{rows: make(map[string]*resource.Issuance)}
}

func (s *fakeIssuanceStore) Insert(_ context.Context, i *resource.Issuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *i
	s.rows[i.ID] = &cp
	return nil
}

func (s *fakeIssuanceStore) GetByID(_ context.Context, id string) (*resource.Issuance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getByIDErr != nil {
		return nil, s.getByIDErr
	}
	i, ok := s.rows[id]
	if !ok {
		return nil, nil // caller maps to ErrIssuanceNotFound
	}
	cp := *i
	return &cp, nil
}

func (s *fakeIssuanceStore) GetByJTI(_ context.Context, jti string) (*resource.Issuance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.rows {
		if i.JTI == jti {
			cp := *i
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *fakeIssuanceStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revokeErr != nil {
		return s.revokeErr
	}
	i, ok := s.rows[id]
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	i.RevokedAt = &now
	return nil
}

func (s *fakeIssuanceStore) RevokeFamily(_ context.Context, userID, clientID, resourceID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revokeFamilyErr != nil {
		return 0, s.revokeFamilyErr
	}
	count := 0
	now := time.Now().UTC()
	for _, i := range s.rows {
		if i.SubjectUserID == userID && i.ClientID == clientID && i.ResourceID == resourceID &&
			i.BackendKind == resource.BackendMint && i.RevokedAt == nil {
			i.RevokedAt = &now
			count++
		}
	}
	return count, nil
}

func (s *fakeIssuanceStore) ListForUser(_ context.Context, userID string, since time.Time) ([]*resource.Issuance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.Issuance
	for _, i := range s.rows {
		if i.SubjectUserID == userID && !i.IssuedAt.Before(since) {
			cp := *i
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out, nil
}

func (s *fakeIssuanceStore) ListForActor(_ context.Context, clientID string, since time.Time) ([]*resource.Issuance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.Issuance
	for _, i := range s.rows {
		if i.ClientID == clientID && !i.IssuedAt.Before(since) {
			cp := *i
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out, nil
}

func (s *fakeIssuanceStore) ListForResource(_ context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*resource.Issuance
	for _, i := range s.rows {
		if i.ResourceID == resourceID && !i.IssuedAt.Before(since) {
			cp := *i
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out, nil
}

func (s *fakeIssuanceStore) PurgeExpired(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

// grantAdminTestEnv bundles the wired-up service plus its dependencies.
type grantAdminTestEnv struct {
	svc       *GrantAdminService
	consents  *fakeConsentGrantStore
	brokers   *fakeBrokerGrantStore
	issuances *fakeIssuanceStore
	audit     *mockAuditRecorder
}

func newGrantAdminTestEnv() *grantAdminTestEnv {
	consents := newFakeConsentGrantStore()
	brokers := newFakeBrokerGrantStore()
	issuances := newFakeIssuanceStore()
	auditMock := &mockAuditRecorder{}
	svc := NewGrantAdminService(consents, brokers, issuances, observability.NewNoop(), auditMock)
	return &grantAdminTestEnv{
		svc:       svc,
		consents:  consents,
		brokers:   brokers,
		issuances: issuances,
		audit:     auditMock,
	}
}

func TestGrantAdmin_ListForUser_BothShapes(t *testing.T) {
	env := newGrantAdminTestEnv()
	ctx := context.Background()

	now := time.Now().UTC()
	env.consents.rows["cg-1"] = &resource.ConsentGrant{
		ID: "cg-1", UserID: "alice", ClientID: "notes-agent",
		ResourceID: "R-test-mcp", Scopes: []string{"tasks:summarize"},
		CreatedAt: now.Add(-time.Hour),
	}
	env.brokers.rows["bg-1"] = &resource.BrokerGrant{
		ID: "bg-1", UserID: "alice", BrokerProviderID: "BP-google",
		ScopesGranted: []string{"https://www.googleapis.com/auth/calendar"},
		Version:       3, EncBackend: "aes_master",
		CreatedAt: now.Add(-2 * time.Hour),
	}

	got, err := env.svc.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(got.Consent) != 1 {
		t.Fatalf("consent: got %d rows, want 1", len(got.Consent))
	}
	if len(got.Broker) != 1 {
		t.Fatalf("broker: got %d rows, want 1", len(got.Broker))
	}
	if got.Consent[0].ID != "cg-1" || got.Broker[0].ID != "bg-1" {
		t.Errorf("ids: got consent=%q broker=%q", got.Consent[0].ID, got.Broker[0].ID)
	}
}

func TestGrantAdmin_ListForUser_RejectsEmptyUserID(t *testing.T) {
	env := newGrantAdminTestEnv()
	if _, err := env.svc.ListForUser(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty user_id")
	}
}

func TestGrantAdmin_RevokeConsent_CascadesToIssuances(t *testing.T) {
	env := newGrantAdminTestEnv()
	ctx := context.Background()

	now := time.Now().UTC()
	env.consents.rows["cg-1"] = &resource.ConsentGrant{
		ID: "cg-1", UserID: "alice", ClientID: "notes-agent",
		ResourceID: "R-test-mcp", Scopes: []string{"tasks:summarize"},
		CreatedAt: now.Add(-time.Hour),
	}
	// Two live mint issuances matching the triple, one broker (must NOT
	// be revoked), and one mint with a different triple (must NOT be
	// revoked either).
	env.issuances.rows["i-mint-1"] = &resource.Issuance{
		ID: "i-mint-1", SubjectUserID: "alice", ClientID: "notes-agent",
		ResourceID: "R-test-mcp", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-30 * time.Minute), ExpiresAt: now.Add(30 * time.Minute),
	}
	env.issuances.rows["i-mint-2"] = &resource.Issuance{
		ID: "i-mint-2", SubjectUserID: "alice", ClientID: "notes-agent",
		ResourceID: "R-test-mcp", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-15 * time.Minute), ExpiresAt: now.Add(45 * time.Minute),
	}
	env.issuances.rows["i-broker"] = &resource.Issuance{
		ID: "i-broker", SubjectUserID: "alice", ClientID: "notes-agent",
		ResourceID: "R-test-mcp", BackendKind: resource.BackendBroker,
		IssuedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(50 * time.Minute),
	}
	env.issuances.rows["i-other"] = &resource.Issuance{
		ID: "i-other", SubjectUserID: "alice", ClientID: "different-agent",
		ResourceID: "R-test-mcp", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(55 * time.Minute),
	}

	if err := env.svc.RevokeConsent(ctx, "cg-1"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}

	// Grant revoked
	if env.consents.rows["cg-1"].RevokedAt == nil {
		t.Error("consent grant not revoked")
	}
	// Mint issuances revoked
	if env.issuances.rows["i-mint-1"].RevokedAt == nil {
		t.Error("i-mint-1 not revoked")
	}
	if env.issuances.rows["i-mint-2"].RevokedAt == nil {
		t.Error("i-mint-2 not revoked")
	}
	// Broker + other-agent stay live
	if env.issuances.rows["i-broker"].RevokedAt != nil {
		t.Error("broker issuance revoked unexpectedly")
	}
	if env.issuances.rows["i-other"].RevokedAt != nil {
		t.Error("other-triple issuance revoked unexpectedly")
	}

	// Audit emitted with the cascade count
	if len(env.audit.events) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(env.audit.events))
	}
	got := env.audit.events[0]
	if got.Action != audit.ActionConsentGrantRevokedAdmin {
		t.Errorf("action: got %q", got.Action)
	}
	if !substr(got.Detail, "revoked_issuances=2") {
		t.Errorf("detail missing revoked_issuances=2: %q", got.Detail)
	}
	// Audit-followup B17: enriched detail also carries client_id +
	// resource_id so forensic queries don't need a follow-up lookup.
	for _, want := range []string{"user_id=alice", "client_id=notes-agent", "resource_id=R-test-mcp"} {
		if !substr(got.Detail, want) {
			t.Errorf("detail missing %q: full detail = %q", want, got.Detail)
		}
	}
}

func TestGrantAdmin_RevokeConsent_IssuanceCascadeFails_RevocationStillReturnsSuccess(t *testing.T) {
	env := newGrantAdminTestEnv()
	ctx := context.Background()

	env.consents.rows["cg-1"] = &resource.ConsentGrant{
		ID: "cg-1", UserID: "alice", ClientID: "notes-agent", ResourceID: "R",
	}
	env.issuances.revokeFamilyErr = errors.New("simulated cascade failure")

	if err := env.svc.RevokeConsent(ctx, "cg-1"); err != nil {
		t.Fatalf("RevokeConsent: expected nil err on cascade failure, got %v", err)
	}
	// Grant still revoked despite cascade failure
	if env.consents.rows["cg-1"].RevokedAt == nil {
		t.Error("grant must remain revoked even when cascade fails")
	}
	// Audit must reflect the failure with revoked_issuances=0
	if len(env.audit.events) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(env.audit.events))
	}
	if !substr(env.audit.events[0].Detail, "revoked_issuances=0") {
		t.Errorf("detail must report revoked_issuances=0 on cascade failure: %q", env.audit.events[0].Detail)
	}
	if !substr(env.audit.events[0].Detail, "cascade=failed") {
		t.Errorf("detail must include cascade=failed marker: %q", env.audit.events[0].Detail)
	}
}

func TestGrantAdmin_RevokeBroker_NoIssuanceCascade(t *testing.T) {
	env := newGrantAdminTestEnv()
	ctx := context.Background()

	now := time.Now().UTC()
	env.brokers.rows["bg-1"] = &resource.BrokerGrant{
		ID: "bg-1", UserID: "alice", BrokerProviderID: "BP-google",
		CreatedAt: now,
	}
	// Live broker issuance for the same user — must stay live (broker
	// tokens are not AS-revocable).
	env.issuances.rows["i-broker"] = &resource.Issuance{
		ID: "i-broker", SubjectUserID: "alice", ClientID: "notes-agent",
		ResourceID: "R-google-cal", BackendKind: resource.BackendBroker,
	}

	if err := env.svc.RevokeBroker(ctx, "bg-1"); err != nil {
		t.Fatalf("RevokeBroker: %v", err)
	}
	if env.brokers.rows["bg-1"].RevokedAt == nil {
		t.Error("broker grant not revoked")
	}
	if env.issuances.rows["i-broker"].RevokedAt != nil {
		t.Error("broker issuance revoked unexpectedly — there is no cascade")
	}
	if len(env.audit.events) != 1 || env.audit.events[0].Action != audit.ActionBrokerGrantRevokedAdmin {
		t.Errorf("audit action: got %v, want broker_grant.revoked_admin", env.audit.events)
	}
	// Audit-followup B17: detail must include user_id + broker_provider_id
	// for single-step forensics.
	got := env.audit.events[0].Detail
	if !substr(got, "user_id=alice") {
		t.Errorf("detail missing user_id=alice: %q", got)
	}
	if !substr(got, "broker_provider_id=BP-google") {
		t.Errorf("detail missing broker_provider_id=BP-google: %q", got)
	}
}

// TestGrantAdmin_RevokeBroker_UnknownID_AuditDetailEmptyPair locks the
// fallback behavior of the B17 enrichment: when GetByID returns
// (nil, nil) the detail records empty values rather than crashing or
// skipping the audit row.
func TestGrantAdmin_RevokeBroker_UnknownID_AuditDetailEmptyPair(t *testing.T) {
	env := newGrantAdminTestEnv()
	if err := env.svc.RevokeBroker(context.Background(), "bg-missing"); err != nil {
		t.Fatalf("RevokeBroker: %v", err)
	}
	if len(env.audit.events) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(env.audit.events))
	}
	got := env.audit.events[0].Detail
	if !substr(got, "id=bg-missing") {
		t.Errorf("detail missing id: %q", got)
	}
	if !substr(got, "user_id=") {
		t.Errorf("detail missing user_id key: %q", got)
	}
	if !substr(got, "broker_provider_id=") {
		t.Errorf("detail missing broker_provider_id key: %q", got)
	}
}

func TestGrantAdmin_AuditRecordedOnEveryMutation(t *testing.T) {
	env := newGrantAdminTestEnv()
	ctx := context.Background()

	env.consents.rows["cg-1"] = &resource.ConsentGrant{
		ID: "cg-1", UserID: "alice", ClientID: "agent", ResourceID: "R",
	}
	env.brokers.rows["bg-1"] = &resource.BrokerGrant{
		ID: "bg-1", UserID: "alice", BrokerProviderID: "BP",
	}

	if err := env.svc.RevokeConsent(ctx, "cg-1"); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.RevokeBroker(ctx, "bg-1"); err != nil {
		t.Fatal(err)
	}

	want := map[audit.Action]bool{
		audit.ActionConsentGrantRevokedAdmin: false,
		audit.ActionBrokerGrantRevokedAdmin:  false,
	}
	for _, e := range env.audit.events {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("missing audit event for %s", action)
		}
	}
}

func TestGrantAdmin_RevokeConsent_UnknownID_NoOp(t *testing.T) {
	env := newGrantAdminTestEnv()
	ctx := context.Background()

	// No grants seeded. Revoke against an unknown id is a no-op cascade
	// and idempotent storage Revoke.
	if err := env.svc.RevokeConsent(ctx, "cg-missing"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if len(env.audit.events) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(env.audit.events))
	}
	if !substr(env.audit.events[0].Detail, "revoked_issuances=0") {
		t.Errorf("expected revoked_issuances=0 for unknown id, got %q", env.audit.events[0].Detail)
	}
}

func TestGrantAdmin_RevokeConsent_RejectsEmptyID(t *testing.T) {
	env := newGrantAdminTestEnv()
	if err := env.svc.RevokeConsent(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestGrantAdmin_RevokeBroker_RejectsEmptyID(t *testing.T) {
	env := newGrantAdminTestEnv()
	if err := env.svc.RevokeBroker(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty id")
	}
}

// substr is a stripped-down strings.Contains avoiding a strings import
// in this test file. Local name to avoid colliding with the package's
// own `contains` helper in xaa_policy.go.
func substr(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
