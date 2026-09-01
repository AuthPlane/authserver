//go:build integration

package services_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// dpopTokenTestSetup extends tokenTestSetup with DPoP-enabled token service.
type dpopTokenTestSetup struct {
	tokenSvc *services.TokenService
	jwksSvc  *services.JWKSService
	h        *testdata.TestHelper
	dpopKey  *ecdsa.PrivateKey // client's DPoP key pair
}

func newDPoPTokenTestSetup(t *testing.T) *dpopTokenTestSetup {
	return newDPoPTokenTestSetupWithEnabled(t, true)
}

func newDPoPTokenTestSetupWithEnabled(t *testing.T, dpopEnabled bool) *dpopTokenTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Create test user.
	now := time.Now().UTC()
	testUser := &user.User{
		ID:        "user-42",
		Email:     "user42@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusActive,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.User.Create(context.Background(), testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}

	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	cfg := static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	})

	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, staticIssuerForTest("https://auth.example.com"), obs)

	tokenSvc := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, stores.User,
		jwksSvc, mintIssuer, cfg, obs, auditSvc,
		stores.Revocation, nil,
	)

	// Wire DPoP on the token service. dpopEnabled mirrors a substitute provider
	// toggling DPoP per request; the OSS default always resolves Enabled=true.
	tokenSvc.WithDPoP(stores.DPoPNonce, static.NewDPoPConfigProvider(output.DPoPConfig{
		Enabled:       dpopEnabled,
		ProofLifetime: 60 * time.Second,
		RequireNonce:  false,
		NonceTTL:      60 * time.Second,
	}))

	// Generate a client DPoP key pair (ES256).
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	return &dpopTokenTestSetup{
		tokenSvc: tokenSvc,
		jwksSvc:  jwksSvc,
		h:        &testdata.TestHelper{Stores: stores},
		dpopKey:  dpopKey,
	}
}

// createSessionWithCode creates a client and auth session for DPoP testing.
func (s *dpopTokenTestSetup) createSessionWithCode(t *testing.T) (*client.Client, string, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "DPoP Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	code := crypto.GenerateAuthCode()
	codeHash := crypto.HashSHA256(code)

	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "user-42",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "state-123",
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}

	if err := s.h.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	return c, code, verifier
}

// createDPoPProof generates a valid DPoP proof JWT signed by the test key.
func (s *dpopTokenTestSetup) createDPoPProof(t *testing.T, method, uri string) string {
	t.Helper()
	signer, err := crypto.NewDPoPSigner(s.dpopKey, jose.ES256)
	if err != nil {
		t.Fatalf("create dpop signer: %v", err)
	}

	proof, err := crypto.CreateDPoPProof(signer, crypto.GenerateRandomString(16), method, uri, time.Now(), "", "")
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}
	return proof
}

// TestToken_ExchangeCode_WithDPoP_BindsJKT verifies that when a valid DPoP proof
// is presented during code exchange, the resulting access token is DPoP-bound
// with the correct cnf.jkt claim.
func TestToken_ExchangeCode_WithDPoP_BindsJKT(t *testing.T) {
	setup := newDPoPTokenTestSetup(t)
	c, code, verifier := setup.createSessionWithCode(t)

	proof := setup.createDPoPProof(t, "POST", "https://auth.example.com/oauth/token")

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
		DPoPProof:    proof,
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Token type must be DPoP.
	if resp.TokenType != "DPoP" {
		t.Errorf("token_type: got %q, want DPoP", resp.TokenType)
	}

	// Verify JWT has cnf.jkt claim.
	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	claims, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	if claims.Cnf == nil {
		t.Fatal("cnf claim missing from DPoP-bound token")
	}
	jkt, ok := claims.Cnf["jkt"].(string)
	if !ok || jkt == "" {
		t.Fatal("cnf.jkt is missing or empty")
	}

	// Verify JKT matches the client's DPoP key.
	expectedJKT, err := crypto.ComputeJKT(jose.JSONWebKey{Key: &setup.dpopKey.PublicKey})
	if err != nil {
		t.Fatalf("compute expected jkt: %v", err)
	}
	if jkt != expectedJKT {
		t.Errorf("jkt mismatch: got %q, want %q", jkt, expectedJKT)
	}
}

// TestToken_ExchangeCode_DPoPDisabled_IgnoresProof_StandardBearer verifies that
// when the resolved DPoP config reports Enabled=false, a presented DPoP proof is
// ignored and a standard Bearer token is issued (no cnf binding). The OSS default
// always resolves Enabled=true, so this exercises the substitute-provider path
// where DPoP is toggled off per request.
func TestToken_ExchangeCode_DPoPDisabled_IgnoresProof_StandardBearer(t *testing.T) {
	setup := newDPoPTokenTestSetupWithEnabled(t, false)
	c, code, verifier := setup.createSessionWithCode(t)

	proof := setup.createDPoPProof(t, "POST", "https://auth.example.com/oauth/token")

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
		DPoPProof:    proof,
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// DPoP disabled for this request → proof ignored → standard Bearer.
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer (DPoP disabled)", resp.TokenType)
	}

	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claims, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}
	if claims.Cnf != nil {
		t.Error("cnf claim must be absent when DPoP is disabled for the request")
	}
}

// TestToken_ExchangeCode_InvalidDPoPProof_Returns400 verifies that an invalid
// DPoP proof causes the exchange to fail.
func TestToken_ExchangeCode_InvalidDPoPProof_Returns400(t *testing.T) {
	setup := newDPoPTokenTestSetup(t)
	c, code, verifier := setup.createSessionWithCode(t)

	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
		DPoPProof:    "not-a-valid-jwt",
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if err == nil {
		t.Fatal("expected error for invalid DPoP proof")
	}
	if !isDPoPError(err) {
		t.Errorf("expected DPoP error, got: %v", err)
	}
}

// A rejected DPoP proof spends the authorization code, so the retry RFC 9449 §8
// mandates for use_dpop_nonce finds the code already gone. Pinned deliberately:
// hoisting the validation above the consume was tried and reverted, because it
// put the proof verification behind no caller check at all.
func TestToken_ExchangeCode_RejectedDPoPProof_SpendsTheCode(t *testing.T) {
	setup := newDPoPTokenTestSetup(t)
	c, code, verifier := setup.createSessionWithCode(t)

	if _, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
		DPoPProof:    "not-a-valid-jwt",
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	}); !isDPoPError(err) {
		t.Fatalf("err = %v, want a DPoP error", err)
	}

	// The retry the protocol expects — with a proof the server accepts — finds
	// the code already spent.
	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
		DPoPProof:    setup.createDPoPProof(t, "POST", "https://auth.example.com/oauth/token"),
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("err = %v, want ErrCodeConsumed — if the retry now succeeds the validation "+
			"moved above the consume, which is only safe if it stays behind caller proof", err)
	}
}

// TestToken_ExchangeCode_NoDPoP_StandardBearer_NoChange verifies that the
// absence of a DPoP proof results in a standard Bearer token without cnf.
func TestToken_ExchangeCode_NoDPoP_StandardBearer_NoChange(t *testing.T) {
	setup := newDPoPTokenTestSetup(t)
	c, code, verifier := setup.createSessionWithCode(t)

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
		// No DPoP fields — standard flow.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", resp.TokenType)
	}

	// Verify JWT does NOT have cnf claim.
	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	claims, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	if claims.Cnf != nil {
		t.Error("cnf claim should be absent for standard Bearer token")
	}
}

// TestToken_Refresh_DPoPProofRequired verifies that a DPoP proof can be
// provided during refresh to bind the new access token.
func TestToken_Refresh_DPoPProofRequired(t *testing.T) {
	setup := newDPoPTokenTestSetup(t)
	c, code, verifier := setup.createSessionWithCode(t)

	// First exchange — no DPoP (standard bearer).
	resp1, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Refresh with DPoP proof — new token should be DPoP-bound.
	proof := setup.createDPoPProof(t, "POST", "https://auth.example.com/oauth/token")

	resp2, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: resp1.RefreshToken,
		ClientID:     c.ID,
		DPoPProof:    proof,
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if resp2.TokenType != "DPoP" {
		t.Errorf("token_type after refresh: got %q, want DPoP", resp2.TokenType)
	}

	// Verify JWT has cnf.jkt.
	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	claims, err := crypto.VerifyAccessToken(resp2.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	if claims.Cnf == nil {
		t.Fatal("cnf claim missing from DPoP-bound refreshed token")
	}
	jkt, ok := claims.Cnf["jkt"].(string)
	if !ok || jkt == "" {
		t.Fatal("cnf.jkt is missing or empty in refreshed token")
	}
}

// TestIntrospect_DPoPBoundToken_ReturnsCNFJKT verifies that introspection
// of a DPoP-bound token returns the cnf.jkt claim and token_type=DPoP.
func TestIntrospect_DPoPBoundToken_ReturnsCNFJKT(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Create signing key pair.
	kp, err := crypto.GenerateKeyPair("ES256", "test-kid-1")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Create test client.
	secretHash, err := crypto.HashBcrypt("test-secret")
	if err != nil {
		t.Fatalf("hash bcrypt: %v", err)
	}
	c := &client.Client{
		ID:           "introspect-dpop-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Create test user.
	now := time.Now().UTC()
	testUser := &user.User{
		ID:        "user-dpop-1",
		Email:     "userdpop@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusActive,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.User.Create(context.Background(), testUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Sign a DPoP-bound token (with cnf.jkt).
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}
	expectedJKT, err := crypto.ComputeJKT(jose.JSONWebKey{Key: &dpopKey.PublicKey})
	if err != nil {
		t.Fatalf("compute jkt: %v", err)
	}

	claims := crypto.AccessTokenClaims{
		Issuer:    "https://auth.example.com",
		Subject:   "user-dpop-1",
		Audience:  []string{"https://auth.example.com"},
		ClientID:  "introspect-dpop-client",
		Scope:     "tools/query",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  now.Unix(),
		Expiry:    now.Add(15 * time.Minute).Unix(),
		NotBefore: now.Unix(),
		Cnf:       map[string]interface{}{"jkt": expectedJKT},
	}

	accessToken, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	// Create introspection service with mock JWKS.
	jwksMock := &mockJWKSBuild{kp: kp}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		staticIssuerForTest("https://auth.example.com"), obs, nil,
	)

	resp, err := svc.IntrospectToken(context.Background(), input.IntrospectRequest{
		Token:        accessToken,
		ClientID:     "introspect-dpop-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}

	if !resp.Active {
		t.Fatal("expected token to be active")
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("token_type: got %q, want DPoP", resp.TokenType)
	}
	if resp.Cnf == nil {
		t.Fatal("cnf missing from introspection response")
	}
	gotJKT, ok := resp.Cnf["jkt"].(string)
	if !ok || gotJKT == "" {
		t.Fatal("cnf.jkt missing or empty")
	}
	if gotJKT != expectedJKT {
		t.Errorf("cnf.jkt: got %q, want %q", gotJKT, expectedJKT)
	}
}

// TestIntrospect_StandardBearerToken_NoCnf verifies that introspection of a
// standard Bearer token returns token_type=Bearer and no cnf claim.
func TestIntrospect_StandardBearerToken_NoCnf(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	kp, err := crypto.GenerateKeyPair("ES256", "test-kid-2")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	secretHash, err := crypto.HashBcrypt("test-secret")
	if err != nil {
		t.Fatalf("hash bcrypt: %v", err)
	}
	c := &client.Client{
		ID:           "introspect-bearer-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	now := time.Now().UTC()
	testUser := &user.User{
		ID:        "user-bearer-1",
		Email:     "userbearer@example.com",
		Role:      user.RoleUser,
		Status:    user.StatusActive,
		Provider:  user.ProviderLocal,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.User.Create(context.Background(), testUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Sign a standard Bearer token (no cnf).
	claims := crypto.AccessTokenClaims{
		Issuer:    "https://auth.example.com",
		Subject:   "user-bearer-1",
		Audience:  []string{"https://auth.example.com"},
		ClientID:  "introspect-bearer-client",
		Scope:     "tools/query",
		JTI:       crypto.GenerateRandomString(16),
		IssuedAt:  now.Unix(),
		Expiry:    now.Add(15 * time.Minute).Unix(),
		NotBefore: now.Unix(),
		// No Cnf — standard Bearer.
	}

	accessToken, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	jwksMock := &mockJWKSBuild{kp: kp}
	svc := services.NewIntrospectionService(
		jwksMock, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		staticIssuerForTest("https://auth.example.com"), obs, nil,
	)

	resp, err := svc.IntrospectToken(context.Background(), input.IntrospectRequest{
		Token:        accessToken,
		ClientID:     "introspect-bearer-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}

	if !resp.Active {
		t.Fatal("expected token to be active")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", resp.TokenType)
	}
	if resp.Cnf != nil {
		t.Error("cnf should be nil for standard Bearer token")
	}
}

// TestToken_ExchangeCode_DPoPReplay_Rejected verifies that replaying the same
// DPoP proof JTI is rejected.
func TestToken_ExchangeCode_DPoPReplay_Rejected(t *testing.T) {
	setup := newDPoPTokenTestSetup(t)

	// Create a DPoP proof.
	signer, err := crypto.NewDPoPSigner(setup.dpopKey, jose.ES256)
	if err != nil {
		t.Fatalf("create dpop signer: %v", err)
	}

	fixedJTI := "fixed-jti-for-replay-test"
	proof, err := crypto.CreateDPoPProof(signer, fixedJTI, "POST", "https://auth.example.com/oauth/token", time.Now(), "", "")
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}

	// First exchange with this proof — should succeed.
	c1, code1, verifier1 := setup.createSessionWithCode(t)
	_, err = setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code1,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c1.ID,
		CodeVerifier: verifier1,
		DPoPProof:    proof,
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if err != nil {
		t.Fatalf("first exchange should succeed: %v", err)
	}

	// Second exchange with the same proof JTI — should fail with replay error.
	// Need a new session since auth codes are single-use.
	c2, code2, verifier2 := setup.createSessionWithCode(t)

	// Create a new proof with the same JTI.
	proof2, err := crypto.CreateDPoPProof(signer, fixedJTI, "POST", "https://auth.example.com/oauth/token", time.Now(), "", "")
	if err != nil {
		t.Fatalf("create dpop proof 2: %v", err)
	}

	_, err = setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code2,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c2.ID,
		CodeVerifier: verifier2,
		DPoPProof:    proof2,
		HTTPMethod:   "POST",
		HTTPURL:      "https://auth.example.com/oauth/token",
	})
	if err == nil {
		t.Fatal("expected error for replayed DPoP JTI")
	}
	if !isDPoPReplayError(err) {
		t.Errorf("expected DPoP replay error, got: %v", err)
	}
}

// isDPoPError checks if the error is a DPoP-related domain error.
func isDPoPError(err error) bool {
	var de domain.Error
	if !errors.As(err, &de) {
		return false
	}
	code := de.Code()
	return code == "invalid_dpop_proof" || code == "use_dpop_nonce"
}

// isDPoPReplayError checks if the error is specifically a DPoP replay error.
func isDPoPReplayError(err error) bool {
	return errors.Is(err, domain.ErrDPoPReplay)
}
