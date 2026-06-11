//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

type ccTestSetup struct {
	svc      *services.ClientCredentialsService
	jwksSvc  *services.JWKSService
	auditSvc *services.AuditService
	h        *testdata.TestHelper
	obs      *observability.Provider
}

func newCCTestSetup(t *testing.T) *ccTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}

	jwksSvc := services.NewJWKSService(ks, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	// Static resources for resource validation.
	resources := []services.ResourceInfo{
		{URI: "https://api.example.com", Scopes: []string{"read", "write"}},
	}

	svc := services.NewClientCredentialsService(
		stores.Client,
		stores.MachineToken,
		jwksSvc,
		"https://auth.example.com",
		15*time.Minute,
		obs,
		auditSvc,
		services.NewStaticResourceLister(resources),
	)

	return &ccTestSetup{
		svc:      svc,
		jwksSvc:  jwksSvc,
		auditSvc: auditSvc,
		h:        &testdata.TestHelper{Stores: stores},
		obs:      obs,
	}
}

// createConfidentialClient creates a confidential client with client_credentials grant type.
func (s *ccTestSetup) createConfidentialClient(t *testing.T, scope string) (*client.Client, string) {
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
		Name:                    "CC Test Client",
		RedirectURIs:            []string{},
		GrantTypes:              []string{"client_credentials"},
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

func TestClientCredentials_ValidExchange(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if resp.ExpiresIn != 900 { // 15 minutes
		t.Errorf("expires_in = %d, want 900", resp.ExpiresIn)
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read")
	}
}

func TestClientCredentials_WrongSecret_Returns401(t *testing.T) {
	setup := newCCTestSetup(t)
	c, _ := setup.createConfidentialClient(t, "read write")

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: "wrong-secret",
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestClientCredentials_GrantTypeNotAllowed_ReturnsUnauthorizedClient(t *testing.T) {
	setup := newCCTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	secret := crypto.GenerateClientSecret()
	hash, _ := crypto.HashBcrypt(secret)

	// Create a client WITHOUT client_credentials grant type.
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

	_, err := setup.svc.Exchange(ctx, input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if !errors.Is(err, domain.ErrUnauthorizedClient) {
		t.Errorf("err = %v, want ErrUnauthorizedClient", err)
	}
}

func TestClientCredentials_ScopeExceedsRegistered_ReturnsInvalidScope(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read")

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "admin", // Not in registered scopes.
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope", err)
	}
}

func TestClientCredentials_MissingScope_UsesAllClientScopes(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write delete")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		// No scope requested — should use all registered scopes.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Scope != "delete read write" { // ScopeSet.String() is sorted
		t.Errorf("scope = %q, want %q", resp.Scope, "delete read write")
	}
}

func TestClientCredentials_ResourceBinding_SetsAud(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Parse the JWT to verify aud.
	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var raw map[string]json.RawMessage
	// Use UnsafeClaimsWithoutVerification since we're just checking structure.
	if err := tok.UnsafeClaimsWithoutVerification(&raw); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}

	var aud []string
	if err := json.Unmarshal(raw["aud"], &aud); err != nil {
		// Try single string
		var singleAud string
		if err2 := json.Unmarshal(raw["aud"], &singleAud); err2 != nil {
			t.Fatalf("parse aud: %v / %v", err, err2)
		}
		aud = []string{singleAud}
	}
	if len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [https://api.example.com]", aud)
	}
}

func TestClientCredentials_JWT_RequiredClaims(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}

	// RFC 9068 §2.2: sub = client_id for machine tokens.
	if claims["sub"] != c.ID {
		t.Errorf("sub = %v, want %q", claims["sub"], c.ID)
	}
	if claims["client_id"] != c.ID {
		t.Errorf("client_id = %v, want %q", claims["client_id"], c.ID)
	}
	if claims["iss"] != "https://auth.example.com" {
		t.Errorf("iss = %v, want %q", claims["iss"], "https://auth.example.com")
	}
	if claims["scope"] != "read" {
		t.Errorf("scope = %v, want %q", claims["scope"], "read")
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("jti is missing or empty")
	}
	if claims["iat"] == nil {
		t.Error("iat is missing")
	}
	if claims["exp"] == nil {
		t.Error("exp is missing")
	}
	if claims["nbf"] == nil {
		t.Error("nbf is missing")
	}
}

func TestClientCredentials_NoRefreshToken(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// ClientCredentialsResponse does not have a RefreshToken field,
	// so we verify at the type level that it's not present.
	// Additionally verify the response is well-formed.
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

func TestClientCredentials_MissingClientID_ReturnsInvalidClient(t *testing.T) {
	setup := newCCTestSetup(t)

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     "",
		ClientSecret: "some-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestClientCredentials_MissingSecret_ReturnsInvalidClient(t *testing.T) {
	setup := newCCTestSetup(t)
	c, _ := setup.createConfidentialClient(t, "read")

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: "",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestClientCredentials_PublicClient_ReturnsInvalidClient(t *testing.T) {
	setup := newCCTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create a public client with client_credentials grant.
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Public Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"client_credentials"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceAdmin,
		Scope:                   "read",
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := setup.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err := setup.svc.Exchange(ctx, input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: "some-secret",
	})
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient", err)
	}
}

func TestClientCredentials_SuspendedClient_ReturnsClientSuspended(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read")

	// Suspend the client.
	c.Status = client.StatusSuspended
	c.UpdatedAt = time.Now().UTC()
	if err := setup.h.Stores.Client.Update(context.Background(), c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
	})
	if !errors.Is(err, domain.ErrClientSuspended) {
		t.Errorf("err = %v, want ErrClientSuspended", err)
	}
}

func TestClientCredentials_MachineTokenStored(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Extract JTI from JWT to verify machine token was stored.
	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}
	jti := claims["jti"].(string)

	// Look up in machine token store.
	mt, err := setup.h.Stores.MachineToken.GetByJTI(context.Background(), jti)
	if err != nil {
		t.Fatalf("get machine token: %v", err)
	}
	if mt == nil {
		t.Fatal("machine token not found in store")
	}
	if mt.ClientID != c.ID {
		t.Errorf("machine token client_id = %q, want %q", mt.ClientID, c.ID)
	}
	if mt.Revoked {
		t.Error("machine token should not be revoked")
	}
	if mt.Scopes.String() != "read" {
		t.Errorf("machine token scopes = %q, want %q", mt.Scopes.String(), "read")
	}
}

func TestClientCredentials_NoAudWithoutResource(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		// No resource — aud defaults to issuer.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}

	// aud should default to issuer when no resource.
	aud := claims["aud"]
	switch v := aud.(type) {
	case []any:
		if len(v) != 1 || v[0] != "https://auth.example.com" {
			t.Errorf("aud = %v, want [https://auth.example.com]", v)
		}
	case string:
		if v != "https://auth.example.com" {
			t.Errorf("aud = %v, want https://auth.example.com", v)
		}
	default:
		t.Errorf("unexpected aud type: %T", aud)
	}
}

func TestClientCredentials_OverbroadScope_Rejected(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write delete")

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read admin", // admin not in registered scopes
	})
	// Fail-closed: any requested scope outside the client's registered set
	// is invalid_scope, even when other requested scopes would have
	// intersected. Silent narrowing hid client misconfiguration.
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope", err)
	}
}

func TestClientCredentials_ExactSubset_Allowed(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write delete")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read write", // strict subset of registered scopes
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Scope != "read write" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read write")
	}
}

func TestClientCredentials_EmptyClientScope_AllScopesAllowed(t *testing.T) {
	setup := newCCTestSetup(t)
	// Empty scope = no per-client restriction.
	c, secret := setup.createConfidentialClient(t, "")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		// No scope requested and client has no scope — should succeed with empty scope.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Scope != "" {
		t.Errorf("scope = %q, want empty", resp.Scope)
	}
}

func TestClientCredentials_UnknownResource_ReturnsInvalidScope(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write")

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://evil.example.com", // Not in static config or scope store.
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope", err)
	}
}

func TestClientCredentials_KnownResource_Succeeds(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read write")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
		Resource:     "https://api.example.com", // In static config.
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Verify aud is set to the known resource.
	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := tok.UnsafeClaimsWithoutVerification(&raw); err != nil {
		t.Fatalf("unsafe claims: %v", err)
	}
	var aud []string
	if err := json.Unmarshal(raw["aud"], &aud); err != nil {
		var singleAud string
		if err2 := json.Unmarshal(raw["aud"], &singleAud); err2 != nil {
			t.Fatalf("parse aud: %v / %v", err, err2)
		}
		aud = []string{singleAud}
	}
	if len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [https://api.example.com]", aud)
	}
}
