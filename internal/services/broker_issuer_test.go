package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// --- Mock output.BrokerGrantStore ---

type mockBrokerGrantStore struct {
	mu sync.Mutex

	getFn       func(ctx context.Context, userID, providerID string) (*resource.BrokerGrant, error)
	updateFn    func(ctx context.Context, g *resource.BrokerGrant) error
	upsertFn    func(ctx context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error)
	createSeen  *resource.BrokerGrant
	createErr   error
	updateSeen  *resource.BrokerGrant
	upsertSeen  *resource.BrokerGrant
	upsertErr   error
	revokeSeen  string
	revokeErr   error
	listForUser func(userID string) ([]*resource.BrokerGrant, error)
}

func (m *mockBrokerGrantStore) GetByID(_ context.Context, _ string) (*resource.BrokerGrant, error) {
	return nil, errMockNotConfigured
}

func (m *mockBrokerGrantStore) Get(ctx context.Context, userID, providerID string) (*resource.BrokerGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getFn == nil {
		return nil, errMockNotConfigured
	}
	return m.getFn(ctx, userID, providerID)
}

func (m *mockBrokerGrantStore) Create(_ context.Context, g *resource.BrokerGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createSeen = g
	return m.createErr
}

func (m *mockBrokerGrantStore) Upsert(ctx context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertSeen = g
	if m.upsertFn != nil {
		return m.upsertFn(ctx, g)
	}
	if m.upsertErr != nil {
		return nil, m.upsertErr
	}
	// Default: echo the supplied grant back unchanged (insert path).
	out := *g
	if out.Version == 0 {
		out.Version = 1
	}
	return &out, nil
}

func (m *mockBrokerGrantStore) UpdateWithVersion(ctx context.Context, g *resource.BrokerGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateSeen = g
	if m.updateFn == nil {
		return nil
	}
	return m.updateFn(ctx, g)
}

func (m *mockBrokerGrantStore) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeSeen = id
	return m.revokeErr
}

func (m *mockBrokerGrantStore) ListForUser(_ context.Context, userID string) ([]*resource.BrokerGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listForUser == nil {
		return nil, errMockNotConfigured
	}
	return m.listForUser(userID)
}

// --- Mock output.IssuanceStore ---

type mockIssuanceStore struct {
	insertSeen *resource.Issuance
	insertErr  error
}

func (m *mockIssuanceStore) Insert(_ context.Context, i *resource.Issuance) error {
	m.insertSeen = i
	return m.insertErr
}

func (m *mockIssuanceStore) GetByID(_ context.Context, _ string) (*resource.Issuance, error) {
	return nil, errMockNotConfigured
}

func (m *mockIssuanceStore) GetByJTI(_ context.Context, _ string) (*resource.Issuance, error) {
	return nil, errMockNotConfigured
}

func (m *mockIssuanceStore) Revoke(_ context.Context, _ string) error {
	return errMockNotConfigured
}

func (m *mockIssuanceStore) RevokeFamily(_ context.Context, _, _, _ string) (int, error) {
	return 0, errMockNotConfigured
}

func (m *mockIssuanceStore) ListForUser(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
	return nil, errMockNotConfigured
}

func (m *mockIssuanceStore) ListForActor(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
	return nil, errMockNotConfigured
}

func (m *mockIssuanceStore) ListForResource(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
	return nil, errMockNotConfigured
}

func (m *mockIssuanceStore) PurgeExpired(_ context.Context, _ time.Time) (int, error) {
	return 0, errMockNotConfigured
}

// --- Mock output.DataEncryptor ---

type mockDataEncryptor struct {
	encrypt    func(ctx context.Context, plaintext []byte, ownerContext string) ([]byte, error)
	decrypt    func(ctx context.Context, ciphertext []byte, ownerContext string) ([]byte, error)
	driverName string
}

func (m *mockDataEncryptor) Encrypt(ctx context.Context, plaintext []byte, ownerContext string) ([]byte, error) {
	if m.encrypt == nil {
		// Default: prefix the plaintext so callers can assert it ran.
		return append([]byte("enc:"+ownerContext+":"), plaintext...), nil
	}
	return m.encrypt(ctx, plaintext, ownerContext)
}

func (m *mockDataEncryptor) Decrypt(ctx context.Context, ciphertext []byte, ownerContext string) ([]byte, error) {
	if m.decrypt == nil {
		// Default: strip the matching prefix produced by Encrypt's
		// default. Tests that need a deterministic plaintext set decrypt.
		prefix := []byte("enc:" + ownerContext + ":")
		if len(ciphertext) >= len(prefix) && string(ciphertext[:len(prefix)]) == string(prefix) {
			return ciphertext[len(prefix):], nil
		}
		return ciphertext, nil
	}
	return m.decrypt(ctx, ciphertext, ownerContext)
}

func (m *mockDataEncryptor) DriverName() string {
	if m.driverName == "" {
		return "mock"
	}
	return m.driverName
}

// --- Stub BrokerProtocol adapter (registered via brokerproto.Registry) ---

type stubBrokerAdapter struct {
	name        string
	vendFn      func(ctx context.Context, p *resource.BrokerProvider, r *resource.Resource, credential []byte, scopes []string) (string, int, []byte, error)
	vendCalls   int
	lastCred    []byte
	lastScopes  []string
	lastResID   string
	lastProvID  string
	mu          sync.Mutex
	connectFail error

	// Simple override fields for tests that don't need a full vendFn.
	// When vendFn is nil and vendErr is non-nil, Vend returns vendErr.
	// When vendFn is nil and vendAccessToken is non-empty, Vend returns
	// vendAccessToken and vendExpiresIn. Otherwise the default "tok-<slug>"
	// and 3600 apply (preserving all pre-existing test behavior).
	vendErr         error
	vendAccessToken string
	vendExpiresIn   int
}

func (s *stubBrokerAdapter) Name() string { return s.name }

func (s *stubBrokerAdapter) BuildConnectURL(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	string, string, string, []string,
) (string, *resource.ConnectPendingState, error) {
	if s.connectFail != nil {
		return "", nil, s.connectFail
	}
	return "", nil, nil
}

func (s *stubBrokerAdapter) HandleCallback(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	string, string, *resource.ConnectPendingState,
) ([]byte, []string, error) {
	return nil, nil, nil
}

func (s *stubBrokerAdapter) Vend(
	ctx context.Context,
	p *resource.BrokerProvider,
	r *resource.Resource,
	credential []byte,
	scopes []string,
) (string, int, []byte, error) {
	s.mu.Lock()
	s.vendCalls++
	s.lastCred = append([]byte(nil), credential...)
	s.lastScopes = append([]string(nil), scopes...)
	s.lastResID = r.ID
	s.lastProvID = p.ID
	s.mu.Unlock()
	if s.vendFn != nil {
		return s.vendFn(ctx, p, r, credential, scopes)
	}
	if s.vendErr != nil {
		return "", 0, nil, s.vendErr
	}
	if s.vendAccessToken != "" {
		return s.vendAccessToken, s.vendExpiresIn, nil, nil
	}
	return "tok-" + r.Slug, 3600, nil, nil
}

func (s *stubBrokerAdapter) Revoke(context.Context, *resource.BrokerProvider, []byte) error {
	return nil
}

// --- Capturing audit recorder ---

type captureAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureAuditRecorder) Record(_ context.Context, e audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureAuditRecorder) take() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// --- Fixtures ---

func newGitHubBrokerResource() *resource.Resource {
	return &resource.Resource{
		ID:               "res-gh",
		Slug:             "github",
		DisplayName:      "GitHub",
		URI:              "https://api.github.com",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "bp-gh",
		Scopes: []resource.Scope{
			{Name: "repos.read", Upstream: "repo"},
			{Name: "users.read", Upstream: "read:user"},
		},
	}
}

func newGitHubBrokerProvider() *resource.BrokerProvider {
	return &resource.BrokerProvider{
		ID:          "bp-gh",
		Slug:        "github",
		DisplayName: "GitHub",
		Protocol:    resource.ProtocolOAuth,
	}
}

// activeGrant returns a grant whose CredentialData has been "encrypted"
// by the mock encryptor's default Encrypt function. The default Decrypt
// reverses this transparently so the plaintext seen by the adapter is
// "live-token".
func activeGrant(userID, providerID string, scopesGranted []string) *resource.BrokerGrant {
	owner := brokerOwnerContext(userID, providerID)
	return &resource.BrokerGrant{
		ID:               "bg-1",
		UserID:           userID,
		BrokerProviderID: providerID,
		CredentialData:   []byte("enc:" + owner + ":live-token"),
		ScopesGranted:    scopesGranted,
		EncBackend:       "mock",
		Version:          1,
	}
}

func newBrokerIssuer(t *testing.T, grants *mockBrokerGrantStore, issuances *mockIssuanceStore, enc *mockDataEncryptor, reg *brokerproto.Registry, audits AuditRecorder) *BrokerIssuer {
	t.Helper()
	return NewBrokerIssuer(grants, enc, issuances, reg, observability.NewNoop(), audits)
}

func newRegistryWith(t *testing.T, name string, vendFn func(ctx context.Context, p *resource.BrokerProvider, r *resource.Resource, credential []byte, scopes []string) (string, int, []byte, error)) (*brokerproto.Registry, *stubBrokerAdapter) {
	t.Helper()
	reg := brokerproto.NewRegistry()
	stub := &stubBrokerAdapter{name: name, vendFn: vendFn}
	if err := reg.Register(stub); err != nil {
		t.Fatalf("register stub adapter: %v", err)
	}
	return reg, stub
}

func baseRequest(provider *resource.BrokerProvider, res *resource.Resource, scopes []string, agent *AgentIdentityClaims) IssueRequest {
	return IssueRequest{
		Resource:      res,
		Provider:      provider,
		SubjectUserID: "user-42",
		ActorClientID: "mcp-client",
		Scopes:        scopes,
		AgentIdentity: agent,
	}
}

// --- Tests ---

func TestBrokerIssuer_Kind(t *testing.T) {
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, &mockBrokerGrantStore{}, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)
	if got := bi.Kind(); got != resource.BackendBroker {
		t.Errorf("Kind() = %q, want %q", got, resource.BackendBroker)
	}
}

func TestBrokerIssuer_SatisfiesIssuerInterface(t *testing.T) {
	// Compile-time substitution gate. The line below would not compile
	// if BrokerIssuer's method set drifted from the Issuer interface.
	var _ Issuer = (*BrokerIssuer)(nil)
}

func TestBrokerIssuer_Issue_HappyPath(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo", "read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, userID, providerID string) (*resource.BrokerGrant, error) {
			if userID != "user-42" || providerID != "bp-gh" {
				t.Fatalf("Get called with (%q, %q)", userID, providerID)
			}
			return grant, nil
		},
	}
	issuances := &mockIssuanceStore{}
	enc := &mockDataEncryptor{}
	reg, stub := newRegistryWith(t, "oauth", nil)
	auditor := &captureAuditRecorder{}
	bi := newBrokerIssuer(t, grants, issuances, enc, reg, auditor)

	resp, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}
	if resp.AccessToken != "tok-github" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "tok-github")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, "Bearer")
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, 3600)
	}
	if resp.IssuanceID == "" {
		t.Error("IssuanceID should be non-empty")
	}
	// Adapter received the decrypted plaintext, not the on-disk ciphertext.
	if string(stub.lastCred) != "live-token" {
		t.Errorf("adapter saw credential %q, want %q", string(stub.lastCred), "live-token")
	}
	// Issuance row carries the broker shape.
	if issuances.insertSeen == nil {
		t.Fatal("expected issuance to be inserted")
	}
	if issuances.insertSeen.BackendKind != resource.BackendBroker {
		t.Errorf("issuance.BackendKind = %q, want %q", issuances.insertSeen.BackendKind, resource.BackendBroker)
	}
	if issuances.insertSeen.Revocable {
		t.Error("broker issuance must not be marked revocable")
	}
	if issuances.insertSeen.JTI != "" {
		t.Errorf("broker issuance.JTI = %q, want empty", issuances.insertSeen.JTI)
	}
	if issuances.insertSeen.ResourceID != "res-gh" {
		t.Errorf("issuance.ResourceID = %q, want %q", issuances.insertSeen.ResourceID, "res-gh")
	}
	// No rotation → store.UpdateWithVersion must not have been called.
	if grants.updateSeen != nil {
		t.Errorf("UpdateWithVersion called unexpectedly with %+v", grants.updateSeen)
	}
}

func TestBrokerIssuer_Issue_NoBrokerGrant_ConsentRequired(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return nil, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	resp, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	if resp != nil {
		t.Errorf("expected nil response on consent_required, got %+v", resp)
	}
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("Issue error = %v, want *domain.ConsentRequiredError", err)
	}
	if cre.ProviderSlug != "github" {
		t.Errorf("ConsentRequiredError.ProviderSlug = %q, want %q", cre.ProviderSlug, "github")
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("ConsentRequiredError.Cause = %q, want %q ( bound-D)", cre.Cause, domain.CauseConsentMissing)
	}
	if domain.ErrorCode(err) != "consent_required" {
		t.Errorf("error code = %q, want %q", domain.ErrorCode(err), "consent_required")
	}
}

func TestBrokerIssuer_Issue_RevokedGrant_ConsentRequired(t *testing.T) {
	// The storage adapter's Get filters revoked_at IS NULL, so a revoked
	// grant comes back as nil — the same code path as never-connected.
	// This test pins that contract so a future relaxation of the filter
	// (e.g. returning revoked rows for admin views) doesn't accidentally
	// bypass the consent gate at vend time.
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return nil, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"users.read"}, nil))
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("Issue error = %v, want *domain.ConsentRequiredError", err)
	}
}

func TestBrokerIssuer_Issue_ScopeInsufficient_ConsentRequired(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	// Granted set is missing "repo" — the upstream-form of the requested
	// "repos.read" scope.
	grant := activeGrant("user-42", "bp-gh", []string{"read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, stub := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("Issue error = %v, want *domain.ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("ConsentRequiredError.Cause = %q, want %q ( bound-E)", cre.Cause, domain.CauseScopeInsufficient)
	}
	if len(cre.MissingScopes) == 0 {
		t.Errorf("ConsentRequiredError.MissingScopes empty, want upstream-form list ( bound-E)")
	}
	if stub.vendCalls != 0 {
		t.Errorf("adapter.Vend called %d times on insufficient scope; want 0", stub.vendCalls)
	}
}

func TestBrokerIssuer_Issue_ScopeNotInCatalog_Surfaced(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"not-in-catalog"}, nil))
	if !errors.Is(err, domain.ErrScopeNotInCatalog) {
		t.Fatalf("Issue error = %v, want errors.Is domain.ErrScopeNotInCatalog", err)
	}
}

func TestBrokerIssuer_Issue_AdapterNotRegistered(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	prov.Protocol = "xyz" // not registered
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	if !errors.Is(err, domain.ErrAdapterNotRegistered) {
		t.Fatalf("Issue error = %v, want errors.Is domain.ErrAdapterNotRegistered", err)
	}
}

func TestBrokerIssuer_Issue_DecryptionFailure_Wrapped(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	enc := &mockDataEncryptor{
		decrypt: func(_ context.Context, _ []byte, _ string) ([]byte, error) {
			return nil, domain.ErrDecryptionFailed
		},
	}
	reg, stub := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, enc, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	if !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Fatalf("Issue error = %v, want errors.Is domain.ErrDecryptionFailed", err)
	}
	if !strings.Contains(err.Error(), "decrypt broker credential") {
		t.Errorf("error message = %q, want it to mention 'decrypt broker credential'", err.Error())
	}
	if stub.vendCalls != 0 {
		t.Errorf("adapter.Vend called %d times on decrypt failure; want 0", stub.vendCalls)
	}
}

func TestBrokerIssuer_Issue_DecryptUsesBrokerOwnerContext(t *testing.T) {
	// The "broker:" prefix is a deliberate divergence from the legacy
	// "connection:" prefix variant — it ensures that data at rest in
	// broker_grants cannot be cross-decrypted with a stale or misconfigured
	// ciphertext blob.
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-77", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	var seenContext string
	enc := &mockDataEncryptor{
		decrypt: func(_ context.Context, ciphertext []byte, ownerContext string) ([]byte, error) {
			seenContext = ownerContext
			return []byte("plaintext"), nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, enc, reg, nil)

	req := baseRequest(prov, res, []string{"repos.read"}, nil)
	req.SubjectUserID = "user-77"
	if _, err := bi.Issue(context.Background(), req); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	want := "broker:user-77:bp-gh"
	if seenContext != want {
		t.Errorf("encryptor saw owner context %q, want %q", seenContext, want)
	}
	if strings.HasPrefix(seenContext, "connection:") {
		t.Errorf("owner context %q has the wrong prefix", seenContext)
	}
}

func TestBrokerIssuer_Issue_PersistsRotatedCredential(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	enc := &mockDataEncryptor{}
	reg, _ := newRegistryWith(t, "oauth", func(_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource, _ []byte, _ []string) (string, int, []byte, error) {
		return "tok-rotated", 1800, []byte("rotated-credential"), nil
	})
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, enc, reg, nil)

	if _, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if grants.updateSeen == nil {
		t.Fatal("UpdateWithVersion not called on rotation")
	}
	wantOnDisk := "enc:broker:user-42:bp-gh:rotated-credential"
	if string(grants.updateSeen.CredentialData) != wantOnDisk {
		t.Errorf("rotated CredentialData on disk = %q, want %q",
			string(grants.updateSeen.CredentialData), wantOnDisk)
	}
}

func TestBrokerIssuer_Issue_RotationLostRace_LogsAndContinues(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
		updateFn: func(_ context.Context, _ *resource.BrokerGrant) error {
			return domain.ErrBrokerGrantConflict
		},
	}
	reg, _ := newRegistryWith(t, "oauth", func(_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource, _ []byte, _ []string) (string, int, []byte, error) {
		return "tok-after-race", 1800, []byte("rotated-credential"), nil
	})
	issuances := &mockIssuanceStore{}
	bi := newBrokerIssuer(t, grants, issuances, &mockDataEncryptor{}, reg, nil)

	resp, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	if err != nil {
		t.Fatalf("Issue: unexpected error on optimistic-lock conflict: %v", err)
	}
	if resp.AccessToken != "tok-after-race" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "tok-after-race")
	}
	if issuances.insertSeen == nil {
		t.Error("issuance row should still be inserted after lost rotation race")
	}
}

func TestBrokerIssuer_Issue_PersistsAgentChain(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	issuances := &mockIssuanceStore{}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, issuances, &mockDataEncryptor{}, reg, nil)

	agent := &AgentIdentityClaims{
		AgentID:    "agent-leaf",
		AgentChain: []string{"agent-root", "agent-mid", "agent-leaf"},
	}
	if _, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, agent)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issuances.insertSeen == nil {
		t.Fatal("issuance not inserted")
	}
	if issuances.insertSeen.AgentID != "agent-leaf" {
		t.Errorf("agent_id = %q, want %q", issuances.insertSeen.AgentID, "agent-leaf")
	}
	wantChain := []string{"agent-root", "agent-mid", "agent-leaf"}
	if len(issuances.insertSeen.AgentChain) != len(wantChain) {
		t.Fatalf("agent_chain len = %d, want %d", len(issuances.insertSeen.AgentChain), len(wantChain))
	}
	for i, c := range wantChain {
		if issuances.insertSeen.AgentChain[i] != c {
			t.Errorf("agent_chain[%d] = %q, want %q", i, issuances.insertSeen.AgentChain[i], c)
		}
	}
}

func TestBrokerIssuer_Issue_NoAgentIdentity_EmptyChain(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	issuances := &mockIssuanceStore{}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, issuances, &mockDataEncryptor{}, reg, nil)

	if _, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issuances.insertSeen == nil {
		t.Fatal("issuance not inserted")
	}
	if issuances.insertSeen.AgentID != "" {
		t.Errorf("agent_id = %q, want empty", issuances.insertSeen.AgentID)
	}
	if len(issuances.insertSeen.AgentChain) != 0 {
		t.Errorf("agent_chain len = %d, want 0", len(issuances.insertSeen.AgentChain))
	}
}

func TestBrokerIssuer_Issue_AuditEvent_Recorded(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo", "read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	auditor := &captureAuditRecorder{}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, auditor)

	if _, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read", "users.read"}, nil)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	events := auditor.take()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Action != audit.ActionUpstreamTokenIssued {
		t.Errorf("audit action = %q, want %q", e.Action, audit.ActionUpstreamTokenIssued)
	}
	if e.ActorID != "user-42" {
		t.Errorf("audit actor_id = %q, want %q", e.ActorID, "user-42")
	}
	if e.ClientID != "mcp-client" {
		t.Errorf("audit client_id = %q, want %q", e.ClientID, "mcp-client")
	}
	for _, want := range []string{"provider=github", "resource=github", "scopes=repos.read users.read"} {
		if !strings.Contains(e.Detail, want) {
			t.Errorf("audit detail %q missing %q", e.Detail, want)
		}
	}
}

func TestBrokerIssuer_Issue_RejectsMintResource(t *testing.T) {
	// Defensive guard. TokenExchangeService should not dispatch a Mint
	// resource to BrokerIssuer; if it does, fail loudly rather than
	// silently producing a broker token shape.
	res := &resource.Resource{
		ID:          "res-mint",
		Slug:        "my-mcp",
		BackendKind: resource.BackendMint,
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, &mockBrokerGrantStore{}, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), IssueRequest{
		Resource:      res,
		Provider:      nil,
		SubjectUserID: "u",
	})
	if err == nil {
		t.Fatal("expected error when Issue is called with a Mint resource")
	}
}

// sentinel-translation tests ─────────────────────────────────────────

func TestBrokerIssuer_Issue_AdapterInvalidGrant_MapsToConsentMissing(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo", "read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	vendErr := fmt.Errorf("vend failed: %w", output.ErrUpstreamInvalidGrant)
	reg, _ := newRegistryWith(t, "oauth", func(_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource, _ []byte, _ []string) (string, int, []byte, error) {
		return "", 0, nil, vendErr
	})
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))

	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
	if cre.DeniedReason != "invalid_grant" {
		t.Errorf("DeniedReason = %q, want %q", cre.DeniedReason, "invalid_grant")
	}
	// ProviderSlug must be populated so the HTTP layer can build the connect URL.
	if cre.ProviderSlug == "" {
		t.Errorf("ProviderSlug must be set for consent_url construction")
	}
}

func TestBrokerIssuer_Issue_AdapterUnavailable_MapsToConsentMissing(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo", "read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	vendErr := fmt.Errorf("vend failed: %w", output.ErrUpstreamUnavailable)
	reg, _ := newRegistryWith(t, "oauth", func(_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource, _ []byte, _ []string) (string, int, []byte, error) {
		return "", 0, nil, vendErr
	})
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))

	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
	if cre.DeniedReason != "upstream_error" {
		t.Errorf("DeniedReason = %q, want %q", cre.DeniedReason, "upstream_error")
	}
	if cre.ProviderSlug == "" {
		t.Errorf("ProviderSlug must be set for consent_url construction")
	}
}

func TestBrokerIssuer_Issue_AdapterScopeDowngrade_MapsToScopeInsufficient(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo", "read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	vendErr := fmt.Errorf("vend failed: %w", output.ErrUpstreamScopeDowngrade)
	reg, _ := newRegistryWith(t, "oauth", func(_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource, _ []byte, _ []string) (string, int, []byte, error) {
		return "", 0, nil, vendErr
	})
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))

	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	if cre.DeniedReason != "scope_downgrade" {
		t.Errorf("DeniedReason = %q, want %q", cre.DeniedReason, "scope_downgrade")
	}
	if cre.ProviderSlug == "" {
		t.Errorf("ProviderSlug must be set for consent_url construction")
	}
}
