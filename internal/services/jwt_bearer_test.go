//go:build integration

package services_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const jwtBearerIssuer = "https://auth.example.com"
const idpIssuer = "https://acme.okta.com"

type jwtBearerTestSetup struct {
	svc     *services.JWTBearerService
	h       *testdata.TestHelper
	obs     *observability.Provider
	idpKey  *ecdsa.PrivateKey
	idpJWKS *jose.JSONWebKeySet
}

func newJWTBearerTestSetup(t *testing.T) *jwtBearerTestSetup {
	return newJWTBearerTestSetupWithMode(t, "")
}

func newJWTBearerTestSetupWithMode(t *testing.T, subjectMode string) *jwtBearerTestSetup {
	return newJWTBearerTestSetupWithXAA(t, static.NewXAAConfigProvider(output.XAAConfig{
		TokenExpiry:     15 * time.Minute,
		MaxAssertionAge: 5 * time.Minute,
		SubjectMode:     subjectMode,
	}))
}

func newJWTBearerTestSetupWithXAA(t *testing.T, xaaConfig output.XAAConfigProvider) *jwtBearerTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Generate IdP signing key.
	idpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	idpJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &idpKey.PublicKey,
				KeyID:     "idp-kid-1",
				Algorithm: "ES256",
				Use:       "sig",
			},
		},
	}

	// Register trusted IdP.
	trustedIdP := idp.TrustedIDP{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Acme Corp",
		Issuer:    idpIssuer,
		JWKSUri:   idpIssuer + "/.well-known/jwks.json",
		Audience:  jwtBearerIssuer,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := stores.IDP.Save(context.Background(), trustedIdP); err != nil {
		t.Fatalf("save IdP: %v", err)
	}

	// Setup signing key for the AS.
	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	resources := []services.ResourceInfo{
		{URI: "https://api.example.com", Scopes: []string{"read", "write"}},
		{URI: "https://api.other.example", Scopes: []string{"read", "write"}},
	}

	// Create a mock JWKS cache that returns our test IdP's JWKS.
	mockCache := &mockIDPJWKSCache{keys: idpJWKS}

	svc := services.NewJWTBearerService(
		stores.IDP, mockCache, stores.AssertionJTI,
		stores.Client, stores.MachineToken, jwksSvc,
		staticIssuerForTest(jwtBearerIssuer),
		xaaConfig,
		obs, auditSvc,
		services.NewStaticResourceLister(resources),
	)

	return &jwtBearerTestSetup{
		svc:     svc,
		h:       &testdata.TestHelper{Stores: stores},
		obs:     obs,
		idpKey:  idpKey,
		idpJWKS: idpJWKS,
	}
}

// mockIDPJWKSCache is a mock cache that returns pre-configured JWKS.
type mockIDPJWKSCache struct {
	keys *jose.JSONWebKeySet
}

func (m *mockIDPJWKSCache) GetKeys(_ context.Context, _ string) (*jose.JSONWebKeySet, error) {
	return m.keys, nil
}

func (m *mockIDPJWKSCache) InvalidateCache(_ context.Context, _ string) error {
	return nil
}

// createJWTBearerClient creates a confidential client with jwt-bearer grant type.
func (s *jwtBearerTestSetup) createJWTBearerClient(t *testing.T, scope string) (*client.Client, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	secret := crypto.GenerateClientSecret()
	hash, err := crypto.HashBcrypt(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		SecretHash:              hash,
		Name:                    "JWT Bearer Test Client",
		RedirectURIs:            []string{},
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		ResponseTypes:           []string{},
		TokenEndpointAuthMethod: "client_secret_basic",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceAdmin,
		Scope:                   scope,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c, secret
}

// signTestIDJAG creates a signed ID-JAG JWT.
func (s *jwtBearerTestSetup) signTestIDJAG(t *testing.T, claims token.IdentityAssertion) string {
	t.Helper()
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       s.idpKey,
	}
	opts := &jose.SignerOptions{}
	opts.WithType("oauth-id-jag+jwt")
	opts.WithHeader(jose.HeaderKey("kid"), "idp-kid-1")

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return raw
}

func (s *jwtBearerTestSetup) validAssertion(clientID string) token.IdentityAssertion {
	now := time.Now().Unix()
	return token.IdentityAssertion{
		Issuer:   idpIssuer,
		Subject:  "user@acme.com",
		Audience: jwtBearerIssuer,
		ClientID: clientID,
		JTI:      crypto.GenerateRandomString(16),
		Expiry:   now + 300,
		IssuedAt: now,
		Scope:    "read write",
	}
}

// failingXAAConfigProvider always errors, to assert jwt-bearer (XAA) issuance
// fails closed on a config-resolution error rather than proceeding.
type failingXAAConfigProvider struct{ err error }

func (p failingXAAConfigProvider) Config(context.Context) (output.XAAConfig, error) {
	return output.XAAConfig{}, p.err
}

func TestJWTBearerGrant_ConfigError_FailsClosed(t *testing.T) {
	wantErr := errors.New("xaa config unavailable")
	setup := newJWTBearerTestSetupWithXAA(t, failingXAAConfigProvider{err: wantErr})

	// XAA config resolves at the top of GrantJWTBearer, before any assertion
	// validation, so an empty request still reaches the fail-closed path.
	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v on config failure, got %v", wantErr, err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on config failure, got %+v", resp)
	}
}

func TestJWTBearerGrant_HappyPath(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("expires_in = %d, want 900", resp.ExpiresIn)
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read")
	}

	// Verify JWT claims.
	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}

	// Subject should be iss:sub format.
	expectedSub := idpIssuer + ":user@acme.com"
	if claims["sub"] != expectedSub {
		t.Errorf("sub = %v, want %q", claims["sub"], expectedSub)
	}
	if claims["client_id"] != c.ID {
		t.Errorf("client_id = %v, want %q", claims["client_id"], c.ID)
	}
	if claims["iss"] != jwtBearerIssuer {
		t.Errorf("iss = %v, want %q", claims["iss"], jwtBearerIssuer)
	}

	// act.sub should be the IdP issuer.
	act, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatal("act claim missing or wrong type")
	}
	if act["sub"] != idpIssuer {
		t.Errorf("act.sub = %v, want %q", act["sub"], idpIssuer)
	}
}

func TestJWTBearerGrant_NoRefreshToken(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// JWTBearerResponse has no RefreshToken field by design.
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

func TestJWTBearerGrant_UntrustedIssuer(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Issuer = "https://untrusted.example.com"
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrAssertionIssuerUntrusted) {
		t.Errorf("err = %v, want ErrAssertionIssuerUntrusted", err)
	}
}

func TestJWTBearerGrant_ClientMismatch(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion("different-client-id") // wrong client_id
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrAssertionClientMismatch) {
		t.Errorf("err = %v, want ErrAssertionClientMismatch", err)
	}
}

func TestJWTBearerGrant_ReplayPrevention(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	// First use should succeed.
	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("first grant: %v", err)
	}

	// Second use with same JTI should fail with replay.
	_, err = setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrAssertionReplay) {
		t.Errorf("err = %v, want ErrAssertionReplay", err)
	}
}

func TestJWTBearerGrant_ScopeValidation(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read")

	assertion := setup.validAssertion(c.ID)
	assertion.Scope = "admin" // not in client's registered scopes

	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "admin",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope", err)
	}
}

func TestJWTBearerGrant_MissingAssertion(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    "",
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrAssertionInvalid) {
		t.Errorf("err = %v, want ErrAssertionInvalid", err)
	}
}

func TestJWTBearerGrant_WrongGrantType(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create client WITHOUT jwt-bearer grant type.
	secret := crypto.GenerateClientSecret()
	hash, _ := crypto.HashBcrypt(secret)

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		SecretHash:              hash,
		Name:                    "Auth Code Only Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceAdmin,
		Scope:                   "read write",
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrUnauthorizedClient) {
		t.Errorf("err = %v, want ErrUnauthorizedClient", err)
	}
}

func TestJWTBearerGrant_MachineTokenStored(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Extract JTI from JWT.
	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}
	jti := claims["jti"].(string)

	// Verify machine token was stored.
	mt, err := setup.h.Stores.MachineToken.GetByJTI(context.Background(), jti)
	if err != nil {
		t.Fatalf("get machine token: %v", err)
	}
	if mt.ClientID != c.ID {
		t.Errorf("machine token client_id = %q, want %q", mt.ClientID, c.ID)
	}
	if mt.Revoked {
		t.Error("machine token should not be revoked")
	}
}

func TestJWTBearerGrant_InvalidClient(t *testing.T) {
	setup := newJWTBearerTestSetup(t)

	assertion := setup.validAssertion("nonexistent-client")
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     "nonexistent-client",
		ClientSecret: "some-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestJWTBearerGrant_WithResource(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = "https://api.example.com"
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Verify aud is set to the resource.
	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var rawClaims map[string]json.RawMessage
	if err := tok.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}
	var aud []string
	if err := json.Unmarshal(rawClaims["aud"], &aud); err != nil {
		t.Fatalf("parse aud: %v", err)
	}
	if len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [https://api.example.com]", aud)
	}
}

// --- : Policy Engine + Subject Mapping Tests ---

// newJWTBearerWithPolicySetup creates a test setup with policy + subject mapping enabled.
func newJWTBearerWithPolicySetup(t *testing.T, subjectMode string) *jwtBearerTestSetup {
	t.Helper()
	setup := newJWTBearerTestSetupWithMode(t, subjectMode)
	obs := testObs()

	policySvc := services.NewXAAPolicyService(
		setup.h.Stores.XAAPolicy, setup.h.Stores.IDP,
		obs, services.NewAuditService(setup.h.Stores.Audit, obs),
	)
	mappingSvc := services.NewSubjectMappingService(
		setup.h.Stores.SubjectMapping, setup.h.Stores.IDP, obs,
	)
	setup.svc.WithPolicy(policySvc, mappingSvc)
	return setup
}

func TestJWTBearerGrant_PolicyDenied_NoPolicy(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	// No policy exists → should be denied.
	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrAssertionPolicyDenied) {
		t.Errorf("err = %v, want ErrAssertionPolicyDenied", err)
	}
}

func TestJWTBearerGrant_PolicyAllows(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	// Get the IdP ID from the store.
	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create a permissive policy for this IdP.
	now := time.Now().UTC()
	policy := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Allow All",
		IDPID:     idpEntity.ID,
		ClientIDs: nil, // all clients
		Scopes:    nil, // client default
		Resources: nil, // all resources
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := setup.h.Stores.XAAPolicy.Save(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read")
	}
}

func TestJWTBearerGrant_PolicyScopeRestriction_ExceedingRequest_Denied(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write delete")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create a policy that only allows "read" scope.
	now := time.Now().UTC()
	policy := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Read Only",
		IDPID:     idpEntity.ID,
		Scopes:    []string{"read"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := setup.h.Stores.XAAPolicy.Save(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	// Request "read write" but policy max is "read". Fail-closed: a policy
	// that cannot satisfy the full request does not match — and with no
	// other matching policy, the assertion is denied. Pre-fix the policy
	// silently narrowed to "read"; that hid operator misconfiguration and
	// inverted the expectation that operator-defined scope caps surface as
	// explicit denials rather than silent reductions.
	_, err = setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read write",
	})
	if !errors.Is(err, domain.ErrAssertionPolicyDenied) {
		t.Fatalf("err = %v, want ErrAssertionPolicyDenied (policy max < request)", err)
	}
}

func TestJWTBearerGrant_PolicyScopeRestriction_CoveringRequest_Allowed(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write delete")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	now := time.Now().UTC()
	policy := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Read+Write",
		IDPID:     idpEntity.ID,
		Scopes:    []string{"read", "write"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := setup.h.Stores.XAAPolicy.Save(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	// Policy max [read, write] strictly covers request [read]. Allowed.
	resp, err := setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want read", resp.Scope)
	}
}

func TestJWTBearerGrant_PolicyClientRestriction(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create a policy that only allows a different client.
	now := time.Now().UTC()
	policy := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Other Client Only",
		IDPID:     idpEntity.ID,
		ClientIDs: []string{"other-client-id"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := setup.h.Stores.XAAPolicy.Save(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	_, err = setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrAssertionPolicyDenied) {
		t.Errorf("err = %v, want ErrAssertionPolicyDenied (client not in policy)", err)
	}
}

func TestJWTBearerGrant_SubjectMapping_AutoMap(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create permissive policy.
	now := time.Now().UTC()
	if err := setup.h.Stores.XAAPolicy.Save(ctx, xaa.Policy{
		ID: crypto.GenerateRandomString(16), Name: "Allow All", IDPID: idpEntity.ID,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	// No subject mapping → auto_map should use iss:sub.
	resp, err := setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	tok, _ := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	var claims map[string]any
	_ = tok.UnsafeClaimsWithoutVerification(&claims)

	expectedSub := idpIssuer + ":user@acme.com"
	if claims["sub"] != expectedSub {
		t.Errorf("sub = %v, want %q (auto_map)", claims["sub"], expectedSub)
	}
}

func TestJWTBearerGrant_SubjectMapping_Strict_Denied(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "strict")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create permissive policy.
	now := time.Now().UTC()
	if err := setup.h.Stores.XAAPolicy.Save(ctx, xaa.Policy{
		ID: crypto.GenerateRandomString(16), Name: "Allow All", IDPID: idpEntity.ID,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	// No subject mapping → strict mode should deny.
	_, err = setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrSubjectMappingNotFound) {
		t.Errorf("err = %v, want ErrSubjectMappingNotFound", err)
	}
}

func TestJWTBearerGrant_SubjectMapping_ExplicitMapping(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "strict")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create permissive policy.
	now := time.Now().UTC()
	if err := setup.h.Stores.XAAPolicy.Save(ctx, xaa.Policy{
		ID: crypto.GenerateRandomString(16), Name: "Allow All", IDPID: idpEntity.ID,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	// Create a subject mapping for user@acme.com → local-user-123.
	if err := setup.h.Stores.SubjectMapping.Save(ctx, xaa.SubjectMapping{
		ID:          crypto.GenerateRandomString(16),
		IDPID:       idpEntity.ID,
		IDPSubject:  "user@acme.com",
		LocalUserID: "local-user-123",
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("save mapping: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Verify subject is the mapped local user ID.
	tok, _ := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	var claims map[string]any
	_ = tok.UnsafeClaimsWithoutVerification(&claims)

	if claims["sub"] != "local-user-123" {
		t.Errorf("sub = %v, want %q (mapped)", claims["sub"], "local-user-123")
	}
}

func TestJWTBearerGrant_DisabledPolicyIgnored(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Create a disabled policy — should not match.
	now := time.Now().UTC()
	if err := setup.h.Stores.XAAPolicy.Save(ctx, xaa.Policy{
		ID: crypto.GenerateRandomString(16), Name: "Disabled", IDPID: idpEntity.ID,
		Enabled: false, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	_, err = setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrAssertionPolicyDenied) {
		t.Errorf("err = %v, want ErrAssertionPolicyDenied (disabled policy)", err)
	}
}

func TestJWTBearerGrant_ScopeFromAssertion(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write delete")

	assertion := setup.validAssertion(c.ID)
	assertion.Scope = "read write"
	raw := setup.signTestIDJAG(t, assertion)

	// No scope in request — should use scope from assertion.
	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if resp.Scope != "read write" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read write")
	}
}

// --- Adversarial tests: assertion vs request conflict scenarios ---

func TestJWTBearerGrant_RequestScopeExceedingAssertionScope_Rejected(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write delete")

	assertion := setup.validAssertion(c.ID)
	assertion.Scope = "read" // IdP limits to read only
	raw := setup.signTestIDJAG(t, assertion)

	// Request broader scopes than assertion permits — fail-closed: the
	// assertion is an upper bound and a request that exceeds it is
	// invalid_scope, not silently narrowed. Mirrors the client_credentials
	// fix. Pre-fix this returned a "read" token silently.
	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read write delete",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope (request exceeds assertion ceiling)", err)
	}
}

func TestJWTBearerGrant_RequestScopeSubsetOfAssertion(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write delete")

	assertion := setup.validAssertion(c.ID)
	assertion.Scope = "read write" // IdP allows read + write
	raw := setup.signTestIDJAG(t, assertion)

	// Request only "read" — narrower than assertion, should work.
	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read")
	}
}

func TestJWTBearerGrant_AssertionScopeOutsideClientRegistration(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read") // client only has "read"

	assertion := setup.validAssertion(c.ID)
	assertion.Scope = "admin" // IdP asserts scope not in client registration
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope (assertion scope outside client registration)", err)
	}
}

func TestJWTBearerGrant_ResourceMismatchRejected(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = "https://api.example.com"
	raw := setup.signTestIDJAG(t, assertion)

	// Request a different resource than what the assertion specifies.
	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.other.example",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope (resource mismatch)", err)
	}
}

func TestJWTBearerGrant_RequestResourceWithEmptyAssertionResource(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = "" // assertion omits resource
	raw := setup.signTestIDJAG(t, assertion)

	// Request a known resource — should be allowed (legitimate use case).
	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("grant: %v (should allow request resource when assertion omits it)", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

func TestJWTBearerGrant_PolicyResourceRestriction_UsesEffectiveResource(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Policy restricts to https://api.example.com only.
	now := time.Now().UTC()
	policy := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Allowed Resource Only",
		IDPID:     idpEntity.ID,
		Resources: []string{"https://api.example.com"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := setup.h.Stores.XAAPolicy.Save(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = "" // Omit resource from assertion
	raw := setup.signTestIDJAG(t, assertion)

	// Request a different resource — policy must deny based on effective resource.
	_, err = setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.other.example",
	})
	if !errors.Is(err, domain.ErrAssertionPolicyDenied) {
		t.Errorf("err = %v, want ErrAssertionPolicyDenied (resource not in policy)", err)
	}
}

func TestJWTBearerGrant_PolicyResourceRestriction_RequestMatchesPolicy(t *testing.T) {
	setup := newJWTBearerWithPolicySetup(t, "auto_map")
	c, secret := setup.createJWTBearerClient(t, "read write")
	ctx := context.Background()

	idpEntity, err := setup.h.Stores.IDP.GetByIssuer(ctx, idpIssuer)
	if err != nil {
		t.Fatalf("get idp: %v", err)
	}

	// Policy restricts to https://api.example.com only.
	now := time.Now().UTC()
	policy := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      "Allowed Resource Only",
		IDPID:     idpEntity.ID,
		Resources: []string{"https://api.example.com"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := setup.h.Stores.XAAPolicy.Save(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = "" // Omit resource from assertion
	raw := setup.signTestIDJAG(t, assertion)

	// Request the allowed resource — policy must permit.
	resp, err := setup.svc.GrantJWTBearer(ctx, input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

// --- xaa.require_resource ---

// newJWTBearerRequireResourceSetup mirrors the default setup with
// require_resource turned on, so the flag is the only variable under test.
func newJWTBearerRequireResourceSetup(t *testing.T) *jwtBearerTestSetup {
	t.Helper()
	return newJWTBearerTestSetupWithXAA(t, static.NewXAAConfigProvider(output.XAAConfig{
		TokenExpiry:     15 * time.Minute,
		MaxAssertionAge: 5 * time.Minute,
		RequireResource: true,
	}))
}

// audienceOf reads the aud claim off an issued access token.
func audienceOf(t *testing.T, accessToken string) []string {
	t.Helper()
	tok, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var rawClaims map[string]json.RawMessage
	if err := tok.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}
	var aud []string
	if err := json.Unmarshal(rawClaims["aud"], &aud); err != nil {
		t.Fatalf("parse aud: %v", err)
	}
	return aud
}

// TestJWTBearerGrant_NoResource_DefaultMintsIssuerAudience pins the default
// (require_resource=false): an exchange that names no resource on either the
// assertion or the request still succeeds, and the token falls back to the
// issuer as its audience. Turning the flag on must leave this untouched.
func TestJWTBearerGrant_NoResource_DefaultMintsIssuerAudience(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = ""
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v (default must stay permissive)", err)
	}
	if aud := audienceOf(t, resp.AccessToken); len(aud) != 1 || aud[0] != jwtBearerIssuer {
		t.Errorf("aud = %v, want [%s]", aud, jwtBearerIssuer)
	}
}

// TestJWTBearerGrant_RequireResource_NoResourceRejected is the point of the
// flag: with it on, the issuer-audience fallback is unreachable because the
// exchange is refused before a token is minted.
func TestJWTBearerGrant_RequireResource_NoResourceRejected(t *testing.T) {
	setup := newJWTBearerRequireResourceSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = ""
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err == nil || !errors.Is(err, domain.ErrInvalidTarget) {
		t.Fatalf("grant err = %v, want ErrInvalidTarget", err)
	}
	if resp != nil {
		t.Errorf("expected nil response, got %+v", resp)
	}
}

// TestJWTBearerGrant_RequireResource_RefusalLeavesAssertionUsable — the
// refusal runs before the jti is consumed, so the correction the error asks
// for actually works: the client resends the same assertion with a resource
// and gets a token. Without this ordering the retry returns ErrAssertionReplay
// and every attempt costs a fresh IdP round-trip.
func TestJWTBearerGrant_RequireResource_RefusalLeavesAssertionUsable(t *testing.T) {
	setup := newJWTBearerRequireResourceSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = ""
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err == nil || !errors.Is(err, domain.ErrInvalidTarget) {
		t.Fatalf("first grant err = %v, want ErrInvalidTarget", err)
	}

	// Same assertion, corrected request.
	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("corrective retry: %v (the refusal must not spend the assertion)", err)
	}
	if aud := audienceOf(t, resp.AccessToken); len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [https://api.example.com]", aud)
	}
}

// TestJWTBearerGrant_UnknownResourceSpendsAssertion pins the other side of
// the jti boundary. Refusals that read server state — here the resource
// catalog — run after the assertion is spent, on purpose: leaving it usable
// would let a captured assertion be resent with one candidate URI after
// another until the catalog is enumerated. Losing the retry is the price of
// closing that oracle, so this asymmetry is deliberate, not an oversight.
func TestJWTBearerGrant_UnknownResourceSpendsAssertion(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://not-registered.example",
	})
	if err == nil || !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("grant err = %v, want ErrInvalidScope for an unknown resource", err)
	}

	// Same assertion, this time naming a registered resource: the catalog
	// probe already spent it.
	_, err = setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if !errors.Is(err, domain.ErrAssertionReplay) {
		t.Fatalf("retry err = %v, want ErrAssertionReplay — a catalog probe must not be repeatable", err)
	}
}

// TestJWTBearerGrant_ScopeCeilingSpendsAssertion — same boundary for the
// scope ceiling, which reads the client's registered scope.
func TestJWTBearerGrant_ScopeCeilingSpendsAssertion(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read")

	assertion := setup.validAssertion(c.ID)
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "write",
	})
	if err == nil || !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("grant err = %v, want ErrInvalidScope", err)
	}

	_, err = setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrAssertionReplay) {
		t.Fatalf("retry err = %v, want ErrAssertionReplay — a scope probe must not be repeatable", err)
	}
}

// TestJWTBearerGrant_ClientMismatchLeavesAssertionUsable — an assertion
// presented against the wrong client is refused before the jti is consumed,
// so it cannot be used to burn the legitimate client's assertion.
func TestJWTBearerGrant_ClientMismatchLeavesAssertionUsable(t *testing.T) {
	setup := newJWTBearerTestSetup(t)
	victim, victimSecret := setup.createJWTBearerClient(t, "read write")
	attacker, attackerSecret := setup.createJWTBearerClient(t, "read write")

	// Assertion minted for the victim client.
	assertion := setup.validAssertion(victim.ID)
	raw := setup.signTestIDJAG(t, assertion)

	_, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     attacker.ID,
		ClientSecret: attackerSecret,
		Scope:        "read",
	})
	if err == nil || !errors.Is(err, domain.ErrAssertionClientMismatch) {
		t.Fatalf("mismatched grant err = %v, want ErrAssertionClientMismatch", err)
	}

	// The rightful client can still use it.
	if _, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     victim.ID,
		ClientSecret: victimSecret,
		Scope:        "read",
	}); err != nil {
		t.Fatalf("victim grant: %v (a mismatched presentation must not spend the assertion)", err)
	}
}

// TestJWTBearerGrant_RequireResource_AssertionResourceAccepted — the resource
// claim on the assertion satisfies the requirement.
func TestJWTBearerGrant_RequireResource_AssertionResourceAccepted(t *testing.T) {
	setup := newJWTBearerRequireResourceSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = "https://api.example.com"
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if aud := audienceOf(t, resp.AccessToken); len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [https://api.example.com]", aud)
	}
}

// TestJWTBearerGrant_RequireResource_RequestResourceAccepted — the resource
// parameter on the token request (RFC 8707) satisfies the requirement just as
// the assertion claim does. What the flag forbids is a token with no resource
// at all, not a particular way of naming one.
func TestJWTBearerGrant_RequireResource_RequestResourceAccepted(t *testing.T) {
	setup := newJWTBearerRequireResourceSetup(t)
	c, secret := setup.createJWTBearerClient(t, "read write")

	assertion := setup.validAssertion(c.ID)
	assertion.Resource = ""
	raw := setup.signTestIDJAG(t, assertion)

	resp, err := setup.svc.GrantJWTBearer(context.Background(), input.JWTBearerRequest{
		Assertion:    raw,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if aud := audienceOf(t, resp.AccessToken); len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [https://api.example.com]", aud)
	}
}
