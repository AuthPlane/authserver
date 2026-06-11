//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

type tokenTestSetup struct {
	tokenSvc *services.TokenService
	jwksSvc  *services.JWKSService
	auditSvc *services.AuditService
	h        *testdata.TestHelper
}

func newTokenTestSetup(t *testing.T) *tokenTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Create the test user referenced by createSessionWithCode (UserID: "user-42").
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

	jwksSvc := services.NewJWKSService(ks, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	cfg := services.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}

	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, "https://auth.example.com", obs)

	tokenSvc := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, stores.User,
		jwksSvc, mintIssuer, "https://auth.example.com", cfg, obs, auditSvc,
		stores.Revocation, services.NewStaticResourceLister(nil),
	)

	return &tokenTestSetup{
		tokenSvc: tokenSvc,
		jwksSvc:  jwksSvc,
		auditSvc: auditSvc,
		h:        &testdata.TestHelper{Stores: stores},
	}
}

// createSessionWithCode creates a client and auth session with a code hash for testing token exchange.
func (s *tokenTestSetup) createSessionWithCode(t *testing.T, isPublic bool) (*client.Client, *session.AuthSession, string, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	// Create client.
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Token Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	var clientSecret string
	if !isPublic {
		clientSecret = crypto.GenerateClientSecret()
		hash, _ := crypto.HashBcrypt(clientSecret)
		c.SecretHash = hash
		c.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Generate PKCE verifier + challenge.
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// Generate auth code + hash.
	code := crypto.GenerateAuthCode()
	codeHash := crypto.HashSHA256(code)

	// Create session with code hash.
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

	return c, sess, code, verifier
}

func TestToken_ExchangeCode_FullFlow(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q", resp.TokenType)
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("expires_in: got %d, want 900", resp.ExpiresIn)
	}
	if resp.RefreshToken == "" {
		t.Error("refresh_token is empty")
	}
	if resp.Scope != "tools/query" {
		t.Errorf("scope: got %q", resp.Scope)
	}

	// Verify JWT claims.
	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	claims, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	if claims.Issuer != "https://auth.example.com" {
		t.Errorf("iss: got %q", claims.Issuer)
	}
	if claims.Subject != "user-42" {
		t.Errorf("sub: got %q", claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://mcp.example.com" {
		t.Errorf("aud: got %v", claims.Audience)
	}
	if claims.ClientID != c.ID {
		t.Errorf("client_id: got %q", claims.ClientID)
	}
	if claims.Scope != "tools/query" {
		t.Errorf("scope: got %q", claims.Scope)
	}
	if claims.JTI == "" {
		t.Error("jti is empty")
	}

	// Matrix: 1.4.8 — upgraded from ⚠️: expires_in must be a positive number
	if resp.ExpiresIn <= 0 {
		t.Errorf("expires_in: got %d, want positive number", resp.ExpiresIn)
	}

	// Matrix: 15.1 — upgraded from ⚠️: token.issued audit event recorded
	events, err := setup.auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(audit.ActionTokenIssued),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 token.issued audit event, got %d", len(events))
	}
	// Matrix: 15.9 — upgraded from ⚠️: audit record includes client_id
	if events[0].ClientID != c.ID {
		t.Errorf("audit client_id: got %q, want %q", events[0].ClientID, c.ID)
	}
	// Matrix: 15.10 — upgraded from ⚠️: audit record includes user_id
	if events[0].ActorID != "user-42" {
		t.Errorf("audit actor_id: got %q, want %q", events[0].ActorID, "user-42")
	}
}

func TestToken_ExchangeCode_JWTTypHeader(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Parse the raw JWT to check typ header.
	parsed, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if typ != "at+jwt" {
		t.Errorf("typ header: got %q, want %q", typ, "at+jwt")
	}
}

func TestToken_ExchangeCode_PKCEMismatch(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, _ := setup.createSessionWithCode(t, true)

	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: crypto.GenerateVerifier(), // wrong verifier
	})
	if !errors.Is(err, domain.ErrInvalidPKCE) {
		t.Errorf("expected ErrInvalidPKCE, got: %v", err)
	}
}

func TestToken_ExchangeCode_CodeReplay(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	// First exchange — should succeed.
	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// Second exchange — code replay.
	_, err = setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if !errors.Is(err, domain.ErrCodeConsumed) {
		t.Errorf("expected ErrCodeConsumed, got: %v", err)
	}
}

func TestToken_ExchangeCode_WrongClientID(t *testing.T) {
	setup := newTokenTestSetup(t)
	_, _, code, verifier := setup.createSessionWithCode(t, true)

	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     "wrong-client",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

func TestToken_ExchangeCode_WrongRedirectURI(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://evil.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

func TestToken_ExchangeCode_ExpiredSession(t *testing.T) {
	setup := newTokenTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Expired Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, c); err != nil {
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
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(-1 * time.Hour), // already expired
		CreatedAt:           now.Add(-2 * time.Hour),
	}
	if err := setup.h.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, err := setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant for expired session, got: %v", err)
	}
}

func TestToken_ExchangeCode_ConfidentialClient_ValidSecret(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, false)

	// Get the plaintext secret from the client we created.
	// createSessionWithCode returns the client with SecretHash set.
	// We need to create with a known secret.
	ctx := context.Background()
	now := time.Now().UTC()

	// Create confidential client with known secret.
	secret := "test-secret-value"
	hash, _ := crypto.HashBcrypt(secret)
	confClient := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Confidential",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, confClient); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Create session for this client.
	newVerifier := crypto.GenerateVerifier()
	newChallenge := crypto.ComputeS256Challenge(newVerifier)
	newCode := crypto.GenerateAuthCode()
	newCodeHash := crypto.HashSHA256(newCode)
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            confClient.ID,
		UserID:              "user-42",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		CodeHash:            newCodeHash,
		CodeChallenge:       newChallenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := setup.h.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, err := setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         newCode,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     confClient.ID,
		ClientSecret: secret,
		CodeVerifier: newVerifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}

	// Clean up the unused session from createSessionWithCode.
	_ = c
	_ = code
	_ = verifier
}

func TestToken_ExchangeCode_ConfidentialClient_MissingSecret(t *testing.T) {
	setup := newTokenTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	secret := "test-secret"
	hash, _ := crypto.HashBcrypt(secret)
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Missing Secret",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
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
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := setup.h.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, err := setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		ClientSecret: "", // missing
		CodeVerifier: verifier,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

func TestToken_ExchangeCode_ConfidentialClient_WrongSecret(t *testing.T) {
	setup := newTokenTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	secret := "correct-secret"
	hash, _ := crypto.HashBcrypt(secret)
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Wrong Secret",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
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
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := setup.h.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, err := setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		ClientSecret: "wrong-secret",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

func TestToken_ExchangeCode_RefreshTokenCreated(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Verify refresh token can be looked up by hash.
	rtHash := crypto.HashSHA256(resp.RefreshToken)
	rt, err := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if rt.FamilyID == "" {
		t.Error("family_id is empty")
	}

	// Verify family exists.
	family, err := setup.h.Stores.Token.GetFamily(context.Background(), rt.FamilyID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if family.ClientID != c.ID {
		t.Errorf("family client_id: got %q, want %q", family.ClientID, c.ID)
	}
	if family.UserID != "user-42" {
		t.Errorf("family user_id: got %q", family.UserID)
	}
	if family.Status != "active" {
		t.Errorf("family status: got %q", family.Status)
	}
}

// --- Refresh Token Tests ---

// exchangeForTokens is a helper that does a full code exchange and returns the token response.
func (s *tokenTestSetup) exchangeForTokens(t *testing.T, isPublic bool) (*input.TokenResponse, *client.Client, string) {
	t.Helper()
	c, _, code, verifier := s.createSessionWithCode(t, isPublic)

	var clientSecret string
	if !isPublic {
		// For confidential clients, we need to retrieve the secret.
		// createSessionWithCode creates with random secret - we need a known one.
		// This helper only supports public clients for simplicity.
		t.Fatal("exchangeForTokens only supports public clients; use exchangeForTokensConfidential for confidential")
	}

	resp, err := s.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		ClientSecret: clientSecret,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp, c, ""
}

// exchangeForTokensConfidential creates a confidential client, session, and exchanges for tokens.
func (s *tokenTestSetup) exchangeForTokensConfidential(t *testing.T) (*input.TokenResponse, *client.Client, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	secret := "test-refresh-secret"
	hash, _ := crypto.HashBcrypt(secret)
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Refresh Conf Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
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
		Scope:               "tools/query tools/create",
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

	resp, err := s.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		ClientSecret: secret,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp, c, secret
}

func TestRefresh_RotateSuccess(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	resp, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("new access_token is empty")
	}
	if resp.RefreshToken == "" {
		t.Error("new refresh_token is empty")
	}
	if resp.RefreshToken == initial.RefreshToken {
		t.Error("refresh_token was not rotated")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q", resp.TokenType)
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("expires_in: got %d, want 900", resp.ExpiresIn)
	}
	if resp.Scope != "tools/query" {
		t.Errorf("scope: got %q", resp.Scope)
	}

	// Matrix: 15.2 — upgraded from ⚠️: token.refreshed audit event recorded
	events, err := setup.auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(audit.ActionTokenRefreshed),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Error("expected at least 1 token.refreshed audit event")
	}

	// Matrix: 1.5.10 — upgraded from ⚠️: jti must be unique across tokens
	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claimsA, err := crypto.VerifyAccessToken(initial.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify initial: %v", err)
	}
	claimsB, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify refreshed: %v", err)
	}
	if claimsA.JTI == claimsB.JTI {
		t.Error("jti must differ between tokens (uniqueness requirement)")
	}
}

func TestRefresh_OldTokenRejectedAfterRotation(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// First refresh succeeds.
	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// Reuse of old token → family revoked.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Errorf("expected ErrFamilyRevoked, got: %v", err)
	}
}

func TestRefresh_ReuseDetection_FamilyKilled(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Rotate once.
	rotated, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// Reuse old token → family revoked.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked on reuse, got: %v", err)
	}

	// Now even the new rotated token should fail because family is revoked.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: rotated.RefreshToken,
		ClientID:     c.ID,
	})
	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Errorf("expected ErrFamilyRevoked for new token after family kill, got: %v", err)
	}
}

func TestRefresh_ScopeNarrowingAccepted(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, secret := setup.exchangeForTokensConfidential(t)

	resp, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "tools/query", // narrower than "tools/query tools/create"
	})
	if err != nil {
		t.Fatalf("refresh with narrowed scope: %v", err)
	}
	if resp.Scope != "tools/query" {
		t.Errorf("scope: got %q, want %q", resp.Scope, "tools/query")
	}
}

func TestRefresh_ScopeWideningRejected(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		Scope:        "tools/query tools/admin", // "tools/admin" not in original scope
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("expected ErrInvalidScope, got: %v", err)
	}
}

func TestRefresh_ExpiredToken(t *testing.T) {
	setup := newTokenTestSetup(t)
	ctx := context.Background()

	// Exchange for tokens first.
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Directly expire the refresh token in the store.
	rtHash := crypto.HashSHA256(initial.RefreshToken)
	rt, err := setup.h.Stores.Token.GetRefreshTokenByHash(ctx, rtHash)
	if err != nil {
		t.Fatalf("get rt: %v", err)
	}

	// Create a new refresh token with expired time in the same family.
	expiredRT := &token.RefreshToken{
		ID:        crypto.GenerateRandomString(16),
		FamilyID:  rt.FamilyID,
		TokenHash: crypto.HashSHA256("expired-token-plain"),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour), // already expired
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := setup.h.Stores.Token.CreateRefreshToken(ctx, expiredRT); err != nil {
		t.Fatalf("create expired rt: %v", err)
	}

	_, err = setup.tokenSvc.RefreshToken(ctx, input.RefreshTokenRequest{
		RefreshToken: "expired-token-plain",
		ClientID:     c.ID,
	})
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant for expired token, got: %v", err)
	}
}

func TestRefresh_ConfidentialClientSecretRequired(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokensConfidential(t)

	// Try to refresh without providing the secret.
	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: "", // missing
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

func TestRefresh_WrongClientID(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, _, _ := setup.exchangeForTokens(t, true)

	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     "wrong-client-id",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

// Matrix: 1.3.8 — resource binding: token aud must match authorize-time resource
func TestToken_ExchangeCode_ResourceBinding(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	// The session was created with Resource: "https://mcp.example.com".
	// Exchange the code and verify the token aud is bound to that resource.
	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claims, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// aud MUST be the resource from the authorization request.
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://mcp.example.com" {
		t.Errorf("aud: got %v, want [https://mcp.example.com]", claims.Audience)
	}

	// Note: ExchangeCodeRequest does not accept a resource parameter.
	// The server always binds the token to the session resource, preventing
	// an attacker from changing the audience at exchange time.
}

// Matrix: 5.7 — refresh must preserve resource binding
func TestRefresh_PreservesResourceBinding(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Verify original token aud.
	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	origClaims, err := crypto.VerifyAccessToken(initial.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify original: %v", err)
	}
	if len(origClaims.Audience) != 1 || origClaims.Audience[0] != "https://mcp.example.com" {
		t.Fatalf("original aud: got %v", origClaims.Audience)
	}

	// Refresh.
	refreshed, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Verify refreshed token has the same aud.
	refreshClaims, err := crypto.VerifyAccessToken(refreshed.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify refreshed: %v", err)
	}
	if len(refreshClaims.Audience) != 1 || refreshClaims.Audience[0] != origClaims.Audience[0] {
		t.Errorf("refreshed aud: got %v, want %v", refreshClaims.Audience, origClaims.Audience)
	}
}

// Matrix: 1.2.5 — missing code_verifier at exchange must be rejected
func TestToken_ExchangeCode_MissingVerifier(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, _ := setup.createSessionWithCode(t, true)

	// Exchange with empty code_verifier (not wrong — completely missing).
	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: "", // intentionally empty
	})
	if !errors.Is(err, domain.ErrInvalidPKCE) {
		t.Errorf("expected ErrInvalidPKCE, got: %v", err)
	}
}

// Matrix: 15.8 — refresh token reuse must be logged in audit
func TestRefresh_ReuseDetection_AuditEvent(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Rotate once — consume the original token.
	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// Reuse the old token → triggers reuse detection and family revocation.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Fatalf("expected ErrFamilyRevoked, got: %v", err)
	}

	// Verify audit event for family revocation with reuse_detection detail.
	events, err := setup.auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(audit.ActionFamilyRevoked),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Fatal("expected at least 1 family.revoked audit event after reuse detection")
	}

	found := false
	for _, e := range events {
		if strings.Contains(e.Detail, "reuse_detection") {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit event should contain 'reuse_detection' in detail")
	}
}

// Matrix: 15.11 — audit records must include trace_id when tracing is active
func TestAudit_TraceIDInRecords(t *testing.T) {
	stores := testdata.SetupTestStores(t)

	// Use a real SDK TracerProvider to generate actual trace IDs.
	tp := sdktrace.NewTracerProvider()
	defer tp.Shutdown(context.Background())
	realTracer := tp.Tracer("test")

	// Start from a noop Provider and swap in the real tracer.
	obs := observability.NewNoop()
	obs.Tracer = realTracer

	auditSvc := services.NewAuditService(stores.Audit, obs)

	// Start a real span so the context carries a valid trace ID.
	ctx, span := realTracer.Start(context.Background(), "test-operation")
	expectedTraceID := span.SpanContext().TraceID().String()
	defer span.End()

	if expectedTraceID == "" || expectedTraceID == "00000000000000000000000000000000" {
		t.Fatal("SDK tracer should generate a non-zero trace ID")
	}

	// Record an audit event through the service — it should extract trace_id from ctx.
	auditSvc.Record(ctx, audit.NewEvent(audit.ActionTokenIssued, "user-trace", "client-trace", "", "trace test"))

	// Query the event back.
	events, err := auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(audit.ActionTokenIssued),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) < 1 {
		t.Fatal("expected at least 1 audit event")
	}

	if events[0].TraceID == "" {
		t.Error("trace_id should be present in audit record when tracing is active")
	}
	if events[0].TraceID != expectedTraceID {
		t.Errorf("trace_id: got %q, want %q", events[0].TraceID, expectedTraceID)
	}
}

// Matrix: 5.5 — new refresh token gets fresh expiry (not the original's expiry)
func TestRefresh_NewTokenHasFreshExpiry(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Look up the original refresh token in the store to get its ExpiresAt.
	originalHash := crypto.HashSHA256(initial.RefreshToken)
	originalRT, err := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), originalHash)
	if err != nil {
		t.Fatalf("get original refresh token: %v", err)
	}
	originalExpiry := originalRT.ExpiresAt

	// Wait briefly so the new token's CreatedAt/ExpiresAt differ from the original.
	time.Sleep(50 * time.Millisecond)

	// Refresh the token.
	resp, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Look up the new refresh token to check its expiry.
	newHash := crypto.HashSHA256(resp.RefreshToken)
	newRT, err := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), newHash)
	if err != nil {
		t.Fatalf("get new refresh token: %v", err)
	}

	// The new token's ExpiresAt must be strictly after the original's.
	// This proves the server sets a fresh expiry from now, not from the original.
	if !newRT.ExpiresAt.After(originalExpiry) {
		t.Errorf("new refresh token expiry (%v) should be after original (%v)",
			newRT.ExpiresAt, originalExpiry)
	}
}

// Matrix: 5.9 — refresh token generation tracking
// The system uses family-based reuse detection: any reuse of a consumed token
// kills the entire family. There is no per-token generation counter.
// This test documents the behavior by doing sequential refreshes and verifying
// that each produces a distinct new token (monotonic chain), and that reuse of
// any prior token revokes the family.
func TestRefresh_FamilyBasedReuseDetection_ChainedRefreshes(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Chain 3 sequential refreshes.
	tokens := []string{initial.RefreshToken}
	current := initial.RefreshToken
	for i := 0; i < 3; i++ {
		resp, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
			RefreshToken: current,
			ClientID:     c.ID,
		})
		if err != nil {
			t.Fatalf("refresh %d: %v", i+1, err)
		}
		if resp.RefreshToken == current {
			t.Errorf("refresh %d: token was not rotated", i+1)
		}
		tokens = append(tokens, resp.RefreshToken)
		current = resp.RefreshToken
	}

	// All 4 tokens (initial + 3 refreshes) must be distinct.
	seen := make(map[string]bool)
	for _, tok := range tokens {
		if seen[tok] {
			t.Error("duplicate refresh token in chain")
		}
		seen[tok] = true
	}

	// Reuse of any consumed token (e.g., the initial) must fail (family revoked).
	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err == nil {
		t.Error("reusing initial token after chain should fail (family revocation)")
	}
	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Errorf("expected ErrFamilyRevoked, got: %v", err)
	}
}

// Matrix: 18.11 — Suspended client rejected at token exchange
func TestToken_ExchangeCode_SuspendedClient_Rejected(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	// Suspend the client after creating the session.
	c.Suspend()
	if err := setup.h.Stores.Client.Update(context.Background(), c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	_, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err == nil {
		t.Fatal("exchange with suspended client should fail")
	}
	if !errors.Is(err, domain.ErrClientSuspended) {
		t.Errorf("expected ErrClientSuspended, got: %v", err)
	}
}

// Matrix: 18.12 — Suspended client rejected at refresh
func TestRefresh_SuspendedClient_Rejected(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Suspend the client after obtaining tokens.
	c.Suspend()
	if err := setup.h.Stores.Client.Update(context.Background(), c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err == nil {
		t.Fatal("refresh with suspended client should fail")
	}
	if !errors.Is(err, domain.ErrClientSuspended) {
		t.Errorf("expected ErrClientSuspended, got: %v", err)
	}
}

func TestRefresh_DisabledUser_Rejected(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	// Disable user-42 after obtaining tokens.
	u, err := setup.h.Stores.User.GetByID(context.Background(), "user-42")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if err := u.Disable(); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if err := setup.h.Stores.User.Update(context.Background(), u); err != nil {
		t.Fatalf("update user: %v", err)
	}

	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	if err == nil {
		t.Fatal("refresh with disabled user should fail")
	}
	if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

// Matrix: 18.13 — JWT access token includes nbf claim
func TestToken_ExchangeCode_JWTHasNbfClaim(t *testing.T) {
	setup := newTokenTestSetup(t)
	c, _, code, verifier := setup.createSessionWithCode(t, true)

	resp, err := setup.tokenSvc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	jwks, err := setup.jwksSvc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	claims, err := crypto.VerifyAccessToken(resp.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.NotBefore == 0 {
		t.Error("nbf claim should be present and non-zero")
	}
	if claims.NotBefore > claims.IssuedAt {
		t.Errorf("nbf (%d) should be <= iat (%d)", claims.NotBefore, claims.IssuedAt)
	}
}

// newTokenTestSetupWithResources creates a token test setup with resource configuration.
// Used for testing may_act claim population (RFC 8693 §5).
func newTokenTestSetupWithResources(t *testing.T, resources []services.ResourceInfo) *tokenTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Create the test user referenced by createSessionWithCode (UserID: "user-42").
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

	jwksSvc := services.NewJWKSService(ks, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	cfg := services.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}

	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, "https://auth.example.com", obs)

	tokenSvc := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, stores.User,
		jwksSvc, mintIssuer, "https://auth.example.com", cfg, obs, auditSvc,
		stores.Revocation, services.NewStaticResourceLister(resources),
	)

	return &tokenTestSetup{
		tokenSvc: tokenSvc,
		jwksSvc:  jwksSvc,
		auditSvc: auditSvc,
		h:        &testdata.TestHelper{Stores: stores},
	}
}

// ( retired may_act emission; Resource.Policy.Exchange.AllowedClientIDs
// replaces the single-actor mode. TestExchangeCode_*MayAct* tests were deleted
// in the review-pass refinements.)

// ============================================================================
// Refresh-token ordering adversarial tests (ADV6) — 2026-05-18 audit MEDIUM.
//
// Pre-fix order in RefreshToken:
//   1. Lookup
//   2. Check expiry
//   3. CONSUME (atomic; revokes the family on reuse)
//   4. Get family
//   5. Check client_id == family.ClientID
//   6. Authenticate client (secret)
//
// Problems:
//   (a) For a confidential client, anyone holding the refresh token without
//       the client secret can burn it — DoS the legitimate next refresh.
//   (b) Reuse detection runs before authentication: an attacker holding any
//       captured rotated-out token can revoke the entire family without ever
//       proving they are the client.
//
// These tests assert the post-condition: after a failed auth attempt, the
// refresh token must still be consumable by the legitimate caller, AND the
// family must remain Active.
// ============================================================================

// wrongClientSecret_RefreshSurvives is the headline ADV6 assertion: a failed
// authentication must NOT mutate refresh state. Previously the call returned
// ErrInvalidClient only AFTER the refresh row had been marked consumed.
func TestRefresh_WrongClientSecret_RefreshTokenSurvives(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, secret := setup.exchangeForTokensConfidential(t)

	// Snapshot family for later compare.
	rtHash := crypto.HashSHA256(initial.RefreshToken)
	rt0, err := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)
	if err != nil {
		t.Fatalf("pre lookup: %v", err)
	}
	family0, err := setup.h.Stores.Token.GetFamily(context.Background(), rt0.FamilyID)
	if err != nil {
		t.Fatalf("pre family: %v", err)
	}
	if !family0.IsActive() {
		t.Fatalf("precondition: family must be active, got %q", family0.Status)
	}

	// Attacker presents a wrong secret with the right client and refresh.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: "totally-wrong-" + secret,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("expected ErrInvalidClient, got: %v", err)
	}

	// Side-effect 1: family is still active.
	family1, err := setup.h.Stores.Token.GetFamily(context.Background(), rt0.FamilyID)
	if err != nil {
		t.Fatalf("post family: %v", err)
	}
	if !family1.IsActive() {
		t.Errorf("family revoked by failed-auth attempt: status=%q", family1.Status)
	}

	// Side-effect 2: the refresh token is still usable by the legitimate
	// client. This is the load-bearing assertion — pre-fix this fails because
	// the token was already consumed.
	resp, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("legitimate refresh after failed auth: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Error("legitimate refresh returned no new refresh_token")
	}
}

// Wrong client_id on a public client: an unauthenticated caller knowing the
// refresh token must not be able to burn it by pointing at a different client.
func TestRefresh_WrongClientID_RefreshTokenSurvives(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	rtHash := crypto.HashSHA256(initial.RefreshToken)
	rt0, err := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)
	if err != nil {
		t.Fatalf("pre lookup: %v", err)
	}

	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     "definitely-not-" + c.ID,
	})
	if err == nil {
		t.Fatal("wrong client_id must be rejected")
	}

	// Family active.
	family1, err := setup.h.Stores.Token.GetFamily(context.Background(), rt0.FamilyID)
	if err != nil {
		t.Fatalf("post family: %v", err)
	}
	if !family1.IsActive() {
		t.Errorf("family revoked by wrong-client_id attempt: status=%q", family1.Status)
	}

	// Refresh token still consumable by legitimate client.
	if _, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	}); err != nil {
		t.Fatalf("legitimate refresh after wrong-client_id attempt: %v", err)
	}
}

// Empty client_id: same threat — should be rejected without burning anything.
func TestRefresh_EmptyClientID_RefreshTokenSurvives(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, _ := setup.exchangeForTokens(t, true)

	rtHash := crypto.HashSHA256(initial.RefreshToken)
	rt0, _ := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)

	_, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     "",
	})
	if err == nil {
		t.Fatal("empty client_id must be rejected")
	}

	family, _ := setup.h.Stores.Token.GetFamily(context.Background(), rt0.FamilyID)
	if !family.IsActive() {
		t.Errorf("family revoked by empty-client_id attempt: status=%q", family.Status)
	}
	if _, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	}); err != nil {
		t.Fatalf("legitimate refresh after empty-client_id attempt: %v", err)
	}
}

// Reuse detection must STILL fire when the legitimate client presents a
// rotated-out refresh token. This is the regression guard so the fix does not
// over-correct and turn reuse detection into a no-op.
func TestRefresh_AuthenticatedReuse_RevokesFamily(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, secret := setup.exchangeForTokensConfidential(t)

	// First legitimate refresh — rotates the token.
	resp1, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// Replay the (now rotated-out) original token with VALID credentials.
	// Pre-fix and post-fix both treat this as reuse → revoke family.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err == nil {
		t.Fatal("reuse of authenticated rotated-out refresh must error")
	}

	// Family is revoked.
	rtHash := crypto.HashSHA256(resp1.RefreshToken)
	rt1, _ := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)
	if rt1 == nil {
		t.Fatal("rotated refresh missing after reuse")
	}
	family, _ := setup.h.Stores.Token.GetFamily(context.Background(), rt1.FamilyID)
	if family.IsActive() {
		t.Errorf("family must be revoked after authenticated reuse, got status=%q", family.Status)
	}
}

// Unauthenticated replay of a rotated-out token (the worst pre-fix case):
// holding any stale refresh token + the right client_id should NOT be enough
// to nuke the family. The legitimate refresh chain must remain usable.
//
// Note: this is the most aggressive interpretation of the fix. If we adopt
// a weaker reorder (auth-before-consume but reuse-detection still pre-auth),
// this test will require the legitimate chain to absorb a revocation —
// adjust then. Currently the audit's spec is "fetch family, authenticate
// client, THEN consume", which makes this test pass.
func TestRefresh_UnauthenticatedReuse_DoesNotRevokeFamily(t *testing.T) {
	setup := newTokenTestSetup(t)
	initial, c, secret := setup.exchangeForTokensConfidential(t)

	// Rotate once with valid creds so `initial` becomes a rotated-out token.
	rotated, err := setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Snapshot family pre-attack.
	rtHash := crypto.HashSHA256(rotated.RefreshToken)
	rt1, _ := setup.h.Stores.Token.GetRefreshTokenByHash(context.Background(), rtHash)

	// Attacker replays the rotated-out token with WRONG secret.
	_, err = setup.tokenSvc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
		ClientSecret: "wrong-" + secret,
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("expected ErrInvalidClient, got: %v", err)
	}

	// Family must still be active — unauthenticated callers cannot revoke.
	family, _ := setup.h.Stores.Token.GetFamily(context.Background(), rt1.FamilyID)
	if !family.IsActive() {
		t.Errorf("family revoked by unauthenticated reuse attempt: status=%q", family.Status)
	}
}

