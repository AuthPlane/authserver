package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
)

type issuanceAdminTestEnv struct {
	svc       *IssuanceAdminService
	issuances *fakeIssuanceStore
	audit     *mockAuditRecorder
}

func newIssuanceAdminTestEnv() *issuanceAdminTestEnv {
	issuances := newFakeIssuanceStore()
	auditMock := &mockAuditRecorder{}
	svc := NewIssuanceAdminService(issuances, observability.NewNoop(), auditMock)
	return &issuanceAdminTestEnv{
		svc:       svc,
		issuances: issuances,
		audit:     auditMock,
	}
}

func TestIssuanceAdmin_ListForUser_FiltersBySince(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	ctx := context.Background()
	now := time.Now().UTC()

	env.issuances.rows["i-old"] = &resource.Issuance{
		ID: "i-old", SubjectUserID: "alice", ClientID: "agent",
		ResourceID: "R", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-48 * time.Hour),
	}
	env.issuances.rows["i-new"] = &resource.Issuance{
		ID: "i-new", SubjectUserID: "alice", ClientID: "agent",
		ResourceID: "R", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-1 * time.Hour),
	}

	got, err := env.svc.ListForUser(ctx, "alice", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(got) != 1 || got[0].ID != "i-new" {
		t.Errorf("got %d rows; want only i-new", len(got))
	}
}

func TestIssuanceAdmin_ListForUser_RejectsEmptyUserID(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	if _, err := env.svc.ListForUser(context.Background(), "", time.Now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestIssuanceAdmin_ListForActor_FiltersBySince(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	ctx := context.Background()
	now := time.Now().UTC()

	env.issuances.rows["i-old"] = &resource.Issuance{
		ID: "i-old", SubjectUserID: "u1", ClientID: "test-mcp",
		ResourceID: "R", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-48 * time.Hour),
	}
	env.issuances.rows["i-new"] = &resource.Issuance{
		ID: "i-new", SubjectUserID: "u2", ClientID: "test-mcp",
		ResourceID: "R", BackendKind: resource.BackendMint,
		IssuedAt: now.Add(-1 * time.Hour),
	}

	got, err := env.svc.ListForActor(ctx, "test-mcp", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("ListForActor: %v", err)
	}
	if len(got) != 1 || got[0].ID != "i-new" {
		t.Errorf("got %d rows; want only i-new", len(got))
	}
}

func TestIssuanceAdmin_ListForActor_RejectsEmptyClientID(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	if _, err := env.svc.ListForActor(context.Background(), "", time.Now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestIssuanceAdmin_GetByID_NotFound_Returns404(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	// Default fake store returns (nil, nil) on miss — parallel to
	// GetByJTI's contract. The service is responsible for mapping that
	// into domain.ErrIssuanceNotFound for the admin 404 path.
	_, err := env.svc.GetByID(context.Background(), "i-missing")
	if !errors.Is(err, domain.ErrIssuanceNotFound) {
		t.Errorf("err: got %v, want ErrIssuanceNotFound", err)
	}
}

func TestIssuanceAdmin_GetByID_StoreError_PropagatesNotAsNotFound(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	env.issuances.getByIDErr = errors.New("simulated db failure")
	_, err := env.svc.GetByID(context.Background(), "i-1")
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, domain.ErrIssuanceNotFound) {
		t.Errorf("store errors must NOT be misclassified as not-found: %v", err)
	}
}

func TestIssuanceAdmin_GetByID_HappyPath(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	now := time.Now().UTC()
	env.issuances.rows["i-1"] = &resource.Issuance{
		ID: "i-1", SubjectUserID: "alice", ClientID: "agent",
		ResourceID: "R", BackendKind: resource.BackendMint,
		IssuedAt: now,
	}

	got, err := env.svc.GetByID(context.Background(), "i-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != "i-1" {
		t.Errorf("id: got %q, want i-1", got.ID)
	}
}

func TestIssuanceAdmin_GetByID_RejectsEmptyID(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	if _, err := env.svc.GetByID(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestIssuanceAdmin_GetByJTI_NotFound_ReturnsNilNoError(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	got, err := env.svc.GetByJTI(context.Background(), "no-such-jti")
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil result on miss, got %+v", got)
	}
}

func TestIssuanceAdmin_GetByJTI_HappyPath(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	env.issuances.rows["i-1"] = &resource.Issuance{
		ID: "i-1", JTI: "abc123", SubjectUserID: "alice",
		ClientID: "agent", ResourceID: "R", BackendKind: resource.BackendMint,
	}
	got, err := env.svc.GetByJTI(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}
	if got == nil || got.JTI != "abc123" {
		t.Errorf("got %+v, want issuance with jti=abc123", got)
	}
}

func TestIssuanceAdmin_GetByJTI_RejectsEmptyJTI(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	if _, err := env.svc.GetByJTI(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestIssuanceAdmin_Revoke_HappyPath(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	now := time.Now().UTC()
	env.issuances.rows["i-1"] = &resource.Issuance{
		ID: "i-1", SubjectUserID: "alice", ClientID: "agent",
		ResourceID: "R", BackendKind: resource.BackendMint,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}

	if err := env.svc.Revoke(context.Background(), "i-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if env.issuances.rows["i-1"].RevokedAt == nil {
		t.Error("expected revoked_at set on issuance row")
	}
	if len(env.audit.events) != 1 || env.audit.events[0].Action != audit.ActionIssuanceRevokedAdmin {
		t.Errorf("audit: got %+v, want one issuance.revoked_admin event", env.audit.events)
	}
	// Audit-followup B17: detail carries the (subject_user_id,
	// client_id, resource_id) triple recovered from GetByID pre-revoke.
	got := env.audit.events[0].Detail
	for _, want := range []string{"id=i-1", "subject_user_id=alice", "client_id=agent", "resource_id=R"} {
		if !substr(got, want) {
			t.Errorf("detail missing %q: full detail = %q", want, got)
		}
	}
}

// TestIssuanceAdmin_Revoke_UnknownID_AuditDetailEmptyTriple locks the
// fallback behavior of B17: when GetByID returns (nil, nil), the audit
// detail still emits the keys with empty values.
func TestIssuanceAdmin_Revoke_UnknownID_AuditDetailEmptyTriple(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	if err := env.svc.Revoke(context.Background(), "i-missing"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(env.audit.events) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(env.audit.events))
	}
	got := env.audit.events[0].Detail
	for _, want := range []string{"id=i-missing", "subject_user_id=", "client_id=", "resource_id="} {
		if !substr(got, want) {
			t.Errorf("detail missing key %q: full detail = %q", want, got)
		}
	}
}

func TestIssuanceAdmin_Revoke_RejectsEmptyID(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	if err := env.svc.Revoke(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestIssuanceAdmin_Revoke_PropagatesStoreError(t *testing.T) {
	env := newIssuanceAdminTestEnv()
	env.issuances.revokeErr = errors.New("boom")
	if err := env.svc.Revoke(context.Background(), "i-1"); err == nil {
		t.Fatal("expected error")
	}
	if len(env.audit.events) != 0 {
		t.Errorf("no audit event expected on store failure, got %d", len(env.audit.events))
	}
}
