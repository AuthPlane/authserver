package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

// The consent-revocation cascade against real stores (in-memory SQLite),
// so the recursive lineage walk, the family revocation and the JTI
// denylist are the adapters' own and not a fake's idea of them.
//
// The fixture is a delegation chain. Alice consented app A to resource R:
//
//	hop0   A's own token for R            (client A, consent A, no parent)
//	hop1   X exchanged hop0 for R          (client X, consent A, parent hop0)
//	hop2   Y exchanged hop1 for R2         (client Y, consent X, parent hop1)
//	other  Y's token for R2 from elsewhere (client Y, consent X, other parent)
//
// plus two refresh families A holds for alice: fam-R for R and fam-else
// for another resource. Revoking (alice, A, R) must reach hop0, hop1,
// hop2 and fam-R — and nothing else.
type cascadeFixture struct {
	stores  *sqlite.Stores
	svc     *GrantAdminService
	audit   *mockAuditRecorder
	grantID string
	resURI  string
}

func newCascadeFixture(t *testing.T) *cascadeFixture {
	t.Helper()
	ctx := context.Background()
	stores := testdata.SetupTestStores(t)
	now := time.Now().UTC().Truncate(time.Second)

	testdata.EnsureUser(t, stores.User, "alice")
	for _, id := range []string{"app-A", "svc-X", "svc-Y"} {
		testdata.EnsureClient(t, stores.Client, id)
	}
	testdata.CreateMintResource(t, stores, "res-R", "r", "https://r.test")
	testdata.CreateMintResource(t, stores, "res-R2", "r2", "https://r2.test")

	grant := &resource.ConsentGrant{
		ID: "cg-A-R", UserID: "alice", ClientID: "app-A", ResourceID: "res-R",
		Scopes: []string{"tools/echo"}, CreatedAt: now, UpdatedAt: now,
	}
	if err := stores.ConsentGrant.Upsert(ctx, grant); err != nil {
		t.Fatalf("upsert grant: %v", err)
	}

	mk := func(jti, clientID, resourceID, consentClientID, parent string) *resource.Issuance {
		return &resource.Issuance{
			ID: jti, JTI: jti, SubjectUserID: "alice", ClientID: clientID, ResourceID: resourceID,
			Scopes: []string{"tools/echo"}, BackendKind: resource.BackendMint, Revocable: true,
			IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			ConsentClientID: consentClientID, ParentJTI: parent,
		}
	}
	for _, iss := range []*resource.Issuance{
		mk("hop0", "app-A", "res-R", "app-A", ""),
		mk("hop1", "svc-X", "res-R", "app-A", "hop0"),
		mk("hop2", "svc-Y", "res-R2", "svc-X", "hop1"),
		mk("other", "svc-Y", "res-R2", "svc-X", "unrelated-root"),
	} {
		if err := stores.Issuance.Insert(ctx, iss); err != nil {
			t.Fatalf("insert %s: %v", iss.ID, err)
		}
	}

	for _, f := range []struct{ id, uri string }{{"fam-R", "https://r.test"}, {"fam-else", "https://else.test"}} {
		if err := stores.Token.CreateFamily(ctx, &token.Family{
			ID: f.id, ClientID: "app-A", UserID: "alice", Scope: "tools/echo",
			Resource: f.uri, Status: token.FamilyActive, CreatedAt: now,
		}); err != nil {
			t.Fatalf("create family %s: %v", f.id, err)
		}
		// Each family issued one access token whose jti it tracks.
		if err := stores.Revocation.TrackJTI(ctx, "at-"+f.id, f.id, now.Add(time.Hour)); err != nil {
			t.Fatalf("track jti for %s: %v", f.id, err)
		}
	}

	auditor := &mockAuditRecorder{}
	svc := NewGrantAdminService(stores.ConsentGrant, stores.BrokerGrant, stores.Issuance, observability.NewNoop(), auditor)
	svc.WithRefreshFamilyCascade(stores.Token, stores.Revocation, stores.Resource)
	return &cascadeFixture{stores: stores, svc: svc, audit: auditor, grantID: grant.ID, resURI: "https://r.test"}
}

func (f *cascadeFixture) issuanceRevoked(t *testing.T, jti string) bool {
	t.Helper()
	got, err := f.stores.Issuance.GetByJTI(context.Background(), jti)
	if err != nil || got == nil {
		t.Fatalf("get issuance %s: %v %v", jti, got, err)
	}
	return got.RevokedAt != nil
}

func (f *cascadeFixture) familyActive(t *testing.T, id string) bool {
	t.Helper()
	fam, err := f.stores.Token.GetFamily(context.Background(), id)
	if err != nil {
		t.Fatalf("get family %s: %v", id, err)
	}
	return fam.Status == token.FamilyActive
}

func (f *cascadeFixture) jtiDenylisted(t *testing.T, jti string) bool {
	t.Helper()
	revoked, err := f.stores.Revocation.IsRevoked(context.Background(), jti)
	if err != nil {
		t.Fatalf("is revoked %s: %v", jti, err)
	}
	return revoked
}

func TestRevokeConsent_ReachesEveryHopAndTheClientsFamily(t *testing.T) {
	f := newCascadeFixture(t)

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}

	for _, jti := range []string{"hop0", "hop1", "hop2"} {
		if !f.issuanceRevoked(t, jti) {
			t.Errorf("%s should be revoked by the cascade", jti)
		}
	}
	if f.issuanceRevoked(t, "other") {
		t.Error("a token under X's consent from an unrelated root must not be revoked")
	}

	if f.familyActive(t, "fam-R") {
		t.Error("app-A's refresh family for R should be revoked")
	}
	if !f.jtiDenylisted(t, "at-fam-R") {
		t.Error("fam-R's access-token jti should be denylisted")
	}
	if !f.familyActive(t, "fam-else") {
		t.Error("app-A's refresh family for another resource must stay active")
	}
	if f.jtiDenylisted(t, "at-fam-else") {
		t.Error("fam-else's access-token jti must not be denylisted")
	}

	if len(f.audit.events) != 1 || f.audit.events[0].Action != audit.ActionConsentGrantRevokedAdmin {
		t.Fatalf("audit: %+v", f.audit.events)
	}
	detail := f.audit.events[0].Detail
	for _, want := range []string{"revoked_issuances=3", "revoked_families=1"} {
		if !strings.Contains(detail, want) {
			t.Errorf("audit detail missing %q: %q", want, detail)
		}
	}
	if strings.Contains(detail, "failed") {
		t.Errorf("audit detail reports a failure: %q", detail)
	}
}

// Revoking twice is safe and the second pass reports zero reach.
func TestRevokeConsent_Idempotent(t *testing.T) {
	f := newCascadeFixture(t)
	ctx := context.Background()
	if err := f.svc.RevokeConsent(ctx, f.grantID); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := f.svc.RevokeConsent(ctx, f.grantID); err != nil {
		t.Fatalf("second: %v", err)
	}
	detail := f.audit.events[1].Detail
	for _, want := range []string{"revoked_issuances=0", "revoked_families=0"} {
		if !strings.Contains(detail, want) {
			t.Errorf("second audit detail missing %q: %q", want, detail)
		}
	}
}

// A token exchanged from a hop the operator already revoked one at a time
// is still reached when the consent is revoked afterwards.
func TestRevokeConsent_WalksThroughAnAlreadyRevokedHop(t *testing.T) {
	f := newCascadeFixture(t)
	ctx := context.Background()
	if err := f.stores.Issuance.Revoke(ctx, "hop1"); err != nil {
		t.Fatalf("pre-revoke hop1: %v", err)
	}
	if err := f.svc.RevokeConsent(ctx, f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !f.issuanceRevoked(t, "hop2") {
		t.Error("hop2 should be reached through the already-revoked hop1")
	}
	if !strings.Contains(f.audit.events[0].Detail, "revoked_issuances=2") {
		t.Errorf("hop1 was already revoked, want revoked_issuances=2: %q", f.audit.events[0].Detail)
	}
}

// Without the family cascade wired, RevokeConsent still revokes the grant
// and the issuances, and says in the audit row that no family was reached.
func TestRevokeConsent_FamilyCascadeUnwired_IssuancesStillRevoked(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.tokens, f.svc.revocation, f.svc.resources = nil, nil, nil

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !f.issuanceRevoked(t, "hop2") {
		t.Error("issuance cascade must not depend on the family cascade")
	}
	if !f.familyActive(t, "fam-R") {
		t.Error("unwired: family should be untouched")
	}
	if !strings.Contains(f.audit.events[0].Detail, "revoked_families=0") {
		t.Errorf("audit: %q", f.audit.events[0].Detail)
	}
}

// The family cascade pages through the client's active families; a
// matching family past the first page is still found.
func TestRevokeConsent_FamilyBeyondFirstPage(t *testing.T) {
	f := newCascadeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// 60 newer families for other resources sort ahead of fam-R
	// (created_at DESC), pushing it onto the second page of 50.
	for i := 0; i < 60; i++ {
		if err := f.stores.Token.CreateFamily(ctx, &token.Family{
			ID: "fam-noise-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), ClientID: "app-A", UserID: "alice",
			Scope: "tools/echo", Resource: "https://noise.test", Status: token.FamilyActive,
			CreatedAt: now.Add(time.Duration(i+1) * time.Minute),
		}); err != nil {
			t.Fatalf("create noise family %d: %v", i, err)
		}
	}

	if err := f.svc.RevokeConsent(ctx, f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if f.familyActive(t, "fam-R") {
		t.Error("fam-R on the second page should still be revoked")
	}
	if !strings.Contains(f.audit.events[0].Detail, "revoked_families=1") {
		t.Errorf("audit: %q", f.audit.events[0].Detail)
	}
}

// A grant whose resource row is gone has no families to match; the
// issuance cascade still runs and nothing is reported as failed. The
// store answers ErrResourceNotFound for it, which is a miss, not a fault.
func TestRevokeConsent_ResourceGone_NoFamilyMatch(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.resources = resourceByIDFunc(func(context.Context, string) (*resource.Resource, error) {
		return nil, domain.ErrResourceNotFound
	})

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !f.issuanceRevoked(t, "hop1") {
		t.Error("issuances should still be revoked")
	}
	if !f.familyActive(t, "fam-R") {
		t.Error("with no resource to match on, the family is left alone")
	}
	if strings.Contains(f.audit.events[0].Detail, "failed") {
		t.Errorf("not a failure: %q", f.audit.events[0].Detail)
	}
}

type resourceByIDFunc func(context.Context, string) (*resource.Resource, error)

func (fn resourceByIDFunc) GetByID(ctx context.Context, id string) (*resource.Resource, error) {
	return fn(ctx, id)
}

// A store fault while resolving the resource is a failed cascade, and the
// audit row says so — an operator alerting on it learns the families were
// not reached.
func TestRevokeConsent_ResourceLookupFails_ReportedInAudit(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.resources = resourceByIDFunc(func(context.Context, string) (*resource.Resource, error) {
		return nil, errors.New("store down")
	})

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !f.issuanceRevoked(t, "hop2") {
		t.Error("issuances should still be revoked")
	}
	if !strings.Contains(f.audit.events[0].Detail, "family_cascade=failed") {
		t.Errorf("audit should flag the family cascade: %q", f.audit.events[0].Detail)
	}
}

// ---- error paths in the family cascade ----

// failingTokenStore wraps the real store and fails one method.
type failingTokenStore struct {
	output.TokenStore
	failList   bool
	failRevoke bool
}

func (f *failingTokenStore) ListFamilies(ctx context.Context, filter output.FamilyFilter) ([]token.Family, int, error) {
	if f.failList {
		return nil, 0, errors.New("families unavailable")
	}
	return f.TokenStore.ListFamilies(ctx, filter)
}

func (f *failingTokenStore) RevokeFamily(ctx context.Context, id string) (bool, error) {
	if f.failRevoke {
		return false, errors.New("revoke unavailable")
	}
	return f.TokenStore.RevokeFamily(ctx, id)
}

type failingRevocationStore struct {
	output.RevocationStore
}

func (f *failingRevocationStore) RevokeByFamily(context.Context, string) error {
	return errors.New("denylist unavailable")
}

func TestRevokeConsent_FamilyListFails_FlaggedIssuancesStillRevoked(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.tokens = &failingTokenStore{TokenStore: f.stores.Token, failList: true}

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	for _, jti := range []string{"hop0", "hop1", "hop2"} {
		if !f.issuanceRevoked(t, jti) {
			t.Errorf("%s should be revoked regardless of the family cascade", jti)
		}
	}
	if !f.familyActive(t, "fam-R") {
		t.Error("with the list failing, nothing was revoked — the family should still be active")
	}
	d := f.audit.events[0].Detail
	if !strings.Contains(d, "family_cascade=failed") || !strings.Contains(d, "revoked_families=0") {
		t.Errorf("audit: %q", d)
	}
}

func TestRevokeConsent_FamilyRevokeFails_Flagged(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.tokens = &failingTokenStore{TokenStore: f.stores.Token, failRevoke: true}

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !f.familyActive(t, "fam-R") {
		t.Error("revoke failed, so the family must still be active")
	}
	if f.jtiDenylisted(t, "at-fam-R") {
		t.Error("the denylist must not run for a family whose revoke failed — order is family first")
	}
	if !strings.Contains(f.audit.events[0].Detail, "family_cascade=failed") {
		t.Errorf("audit: %q", f.audit.events[0].Detail)
	}
}

// The family half succeeded and the denylist half failed: the session is
// dead (no more refreshes) but its in-flight access tokens outlive it,
// and the audit row says so.
func TestRevokeConsent_DenylistFails_FamilyStillRevokedAndFlagged(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.revocation = &failingRevocationStore{RevocationStore: f.stores.Revocation}

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if f.familyActive(t, "fam-R") {
		t.Error("the family half ran before the denylist: fam-R should be revoked")
	}
	if f.jtiDenylisted(t, "at-fam-R") {
		t.Error("denylist failed; the jti should not be listed")
	}
	if !strings.Contains(f.audit.events[0].Detail, "family_cascade=failed") {
		t.Errorf("audit: %q", f.audit.events[0].Detail)
	}
}

// Both cascades failing: the grant is still revoked (no new mints), and
// the audit row carries both markers so an alert on either fires.
type failingIssuanceStore struct {
	output.IssuanceStore
}

func (failingIssuanceStore) RevokeFamily(context.Context, string, string, string) (int, error) {
	return 0, errors.New("issuances unavailable")
}

func TestRevokeConsent_BothCascadesFail_GrantStillRevokedBothFlagged(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.issuances = failingIssuanceStore{IssuanceStore: f.stores.Issuance}
	f.svc.tokens = &failingTokenStore{TokenStore: f.stores.Token, failList: true}

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	g, err := f.stores.ConsentGrant.GetByID(context.Background(), f.grantID)
	if err != nil || g == nil || g.RevokedAt == nil {
		t.Fatalf("the grant itself must be revoked whatever the cascades did: %+v %v", g, err)
	}
	d := f.audit.events[0].Detail
	for _, want := range []string{"cascade=failed", "family_cascade=failed", "revoked_issuances=0", "revoked_families=0"} {
		if !strings.Contains(d, want) {
			t.Errorf("audit missing %q: %q", want, d)
		}
	}
}

// The grant store cannot revoke: nothing else runs and the error is
// returned — the operator sees the failure rather than a 204.
type failingConsentStore struct {
	output.ConsentGrantStore
}

func (failingConsentStore) Revoke(context.Context, string) error {
	return errors.New("grants unavailable")
}

func TestRevokeConsent_GrantRevokeFails_ErrorAndNoCascade(t *testing.T) {
	f := newCascadeFixture(t)
	f.svc.consents = failingConsentStore{ConsentGrantStore: f.stores.ConsentGrant}

	if err := f.svc.RevokeConsent(context.Background(), f.grantID); err == nil {
		t.Fatal("expected an error when the grant cannot be revoked")
	}
	if f.issuanceRevoked(t, "hop1") {
		t.Error("no cascade may run when the grant revoke failed")
	}
	if !f.familyActive(t, "fam-R") {
		t.Error("no family cascade may run when the grant revoke failed")
	}
	if len(f.audit.events) != 0 {
		t.Errorf("no audit row on a failed revoke, got %+v", f.audit.events)
	}
}
