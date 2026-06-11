//go:build integration

package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const testIssuer = "http://localhost:8080"

// mockAuditRecorder captures audit events for testing.
type mockAuditRecorder struct {
	count  int
	events []audit.Event
}

func (m *mockAuditRecorder) Record(_ context.Context, e audit.Event) {
	m.count++
	m.events = append(m.events, e)
}

// introspectEnv holds the test environment for introspection tests.
type introspectEnv struct {
	svc      *services.IntrospectionService
	kp       *crypto.KeyPair
	clientID string
}

func newIntrospectEnv(t *testing.T) *introspectEnv {
	t.Helper()

	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Create a signing key pair.
	kp, err := crypto.GenerateKeyPair("ES256", "test-kid-1")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Create a test client (confidential).
	secretHash, err := crypto.HashBcrypt("test-secret")
	if err != nil {
		t.Fatalf("hash bcrypt: %v", err)
	}
	c := &client.Client{
		ID:           "introspect-client-1",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Create test user referenced in validClaims() Subject field.
	now := time.Now().UTC()
	testUser := &user.User{
		ID:        "user-1",
		Email:     "user1@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusActive,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.User.Create(context.Background(), testUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Mock JWKS provider.
	jwksMock := &mockJWKSBuild{kp: kp}

	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		testIssuer, obs, nil,
	)

	return &introspectEnv{
		svc:      svc,
		kp:       kp,
		clientID: c.ID,
	}
}

// mockJWKSBuild implements services.JWKSBuildProvider.
type mockJWKSBuild struct {
	kp *crypto.KeyPair
}

func (m *mockJWKSBuild) BuildJWKS(_ context.Context) (*jose.JSONWebKeySet, error) {
	jwks := crypto.BuildJWKS(m.kp)
	return &jwks, nil
}

func signTestToken(t *testing.T, kp *crypto.KeyPair, claims crypto.AccessTokenClaims) string {
	t.Helper()
	token, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	return token
}

func validClaims() crypto.AccessTokenClaims {
	now := time.Now().UTC()
	return crypto.AccessTokenClaims{
		Issuer:   testIssuer,
		Subject:  "user-1",
		Audience: []string{"https://resource.example.com"},
		ClientID: "introspect-client-1",
		Scope:    "tools/read tools/write",
		JTI:      crypto.GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(15 * time.Minute).Unix(),
	}
}

func TestIntrospect_ValidToken_Active(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active=true")
	}
	if resp.Sub != "user-1" {
		t.Errorf("Sub = %q, want user-1", resp.Sub)
	}
	if resp.ClientID != "introspect-client-1" {
		t.Errorf("ClientID = %q, want introspect-client-1", resp.ClientID)
	}
	if resp.Scope != "tools/read tools/write" {
		t.Errorf("Scope = %q, want 'tools/read tools/write'", resp.Scope)
	}
	if resp.Iss != testIssuer {
		t.Errorf("Iss = %q, want %q", resp.Iss, testIssuer)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	if resp.Jti != claims.JTI {
		t.Errorf("Jti = %q, want %q", resp.Jti, claims.JTI)
	}
}

func TestIntrospect_ExpiredToken_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	claims.Expiry = time.Now().Add(-1 * time.Hour).Unix()
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for expired token")
	}
}

func TestIntrospect_RevokedJTI_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()
	stores := testdata.SetupTestStores(t)

	// Create a fresh env with this store's revocation store.
	jwksMock := &mockJWKSBuild{kp: env.kp}

	// Create client in the new store.
	secretHash, _ := crypto.HashBcrypt("test-secret")
	c := &client.Client{
		ID:           "introspect-client-1",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, c)

	// token_families.user_id is FK-enforced.
	testdata.EnsureUser(t, stores.User, "user-1")

	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, nil,
		testIssuer, testObs(), nil,
	)

	// Family must exist due to FK constraint on access_token_jtis.family_id.
	if err := stores.Token.CreateFamily(ctx, &token.Family{
		ID:        "family-1",
		ClientID:  "introspect-client-1",
		UserID:    "user-1",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}

	claims := validClaims()
	signedToken := signTestToken(t, env.kp, claims)

	// Track the JTI, then revoke it.
	if err := stores.Revocation.TrackJTI(ctx, claims.JTI, "family-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("TrackJTI: %v", err)
	}
	if err := stores.Revocation.RevokeJTI(ctx, claims.JTI); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        signedToken,
		ClientID:     "introspect-client-1",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for revoked JTI")
	}
}

func TestIntrospect_InvalidSignature_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	// Sign with a different key.
	otherKP, _ := crypto.GenerateKeyPair("ES256", "other-kid")
	claims := validClaims()
	token := signTestToken(t, otherKP, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for token with unknown kid")
	}
}

func TestIntrospect_SuspendedClient_Inactive(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	kp, _ := crypto.GenerateKeyPair("ES256", "test-kid-1")
	jwksMock := &mockJWKSBuild{kp: kp}

	// Create a requesting client (active).
	secretHash, _ := crypto.HashBcrypt("test-secret")
	reqClient := &client.Client{
		ID:           "requesting-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, reqClient)

	// Create the issuing client (suspended).
	issuingClient := &client.Client{
		ID:           "issuing-client-suspended",
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusSuspended,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, issuingClient)

	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, nil,
		testIssuer, testObs(), nil,
	)

	claims := validClaims()
	claims.ClientID = "issuing-client-suspended"
	token := signTestToken(t, kp, claims)

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "requesting-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for suspended issuing client")
	}
}

func TestIntrospect_InvalidClientAuth_Error(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	token := signTestToken(t, env.kp, claims)

	_, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "wrong-secret",
	})
	if err == nil {
		t.Fatal("expected error for invalid client auth")
	}
}

func TestIntrospect_NonJWT_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        "this-is-not-a-jwt",
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for non-JWT token")
	}
}

func TestIntrospect_DisabledUser_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	token := signTestToken(t, env.kp, claims)

	// Disable the user (created as active in newIntrospectEnv).
	stores := testdata.SetupTestStores(t)
	// We need a fresh env with a user store that has the disabled user.
	kp := env.kp
	jwksMock := &mockJWKSBuild{kp: kp}

	secretHash, _ := crypto.HashBcrypt("test-secret")
	c := &client.Client{
		ID:           "introspect-client-1",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, c)

	// Create user as disabled.
	now := time.Now().UTC()
	disabledUser := &user.User{
		ID:        "user-1",
		Email:     "user1@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusDisabled,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = stores.User.Create(ctx, disabledUser)

	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		testIssuer, testObs(), nil,
	)

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "introspect-client-1",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for disabled user")
	}
}

func TestIntrospect_FutureNBF_Inactive(t *testing.T) {
	env := newIntrospectEnv(t)
	ctx := context.Background()

	claims := validClaims()
	claims.NotBefore = time.Now().Add(1 * time.Hour).Unix() // not yet valid
	token := signTestToken(t, env.kp, claims)

	resp, err := env.svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     env.clientID,
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if resp.Active {
		t.Fatal("expected active=false for token with future nbf")
	}
}

func TestIntrospect_AuditRecorded(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	kp, _ := crypto.GenerateKeyPair("ES256", "test-kid-1")
	jwksMock := &mockJWKSBuild{kp: kp}

	secretHash, _ := crypto.HashBcrypt("test-secret")
	c := &client.Client{
		ID:           "audit-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	_ = stores.Client.Create(ctx, c)

	auditMock := &mockAuditRecorder{}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, nil,
		testIssuer, testObs(), auditMock,
	)

	claims := validClaims()
	claims.ClientID = "audit-client"
	token := signTestToken(t, kp, claims)

	resp, err := svc.IntrospectToken(ctx, input.IntrospectRequest{
		Token:        token,
		ClientID:     "audit-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active=true")
	}
	if auditMock.count == 0 {
		t.Error("expected audit event to be recorded")
	}
}
