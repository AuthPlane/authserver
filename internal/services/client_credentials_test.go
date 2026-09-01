//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
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
	return newCCTestSetupWithConfig(t, static.NewClientCredentialsConfigProvider(output.ClientCredentialsConfig{TokenExpiry: 15 * time.Minute}))
}

func newCCTestSetupWithConfig(t *testing.T, ccConfig output.ClientCredentialsConfigProvider) *ccTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}

	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)
	auditSvc := services.NewAuditService(stores.Audit, obs)

	// Static resources for resource validation.
	resources := []services.ResourceInfo{
		{URI: "https://api.example.com", Scopes: []string{"read", "write"}},
	}

	svc := services.NewClientCredentialsService(
		stores.Client,
		stores.MachineToken,
		jwksSvc,
		staticIssuerForTest("https://auth.example.com"),
		ccConfig,
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

// createConfidentialClient creates an admin-provisioned confidential client
// with client_credentials grant type.
func (s *ccTestSetup) createConfidentialClient(t *testing.T, scope string) (*client.Client, string) {
	t.Helper()
	return s.createConfidentialClientWithSource(t, scope, client.SourceAdmin)
}

// createConfidentialClientWithSource is createConfidentialClient with the
// registration door made explicit. The scope-denial message branches on it, so
// a test that cares which door the client came through has to say so.
func (s *ccTestSetup) createConfidentialClientWithSource(
	t *testing.T, scope string, source client.RegistrationSource,
) (*client.Client, string) {
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
		RegistrationSource:      source,
		Scope:                   scope,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	if err := s.h.Stores.Client.Create(ctx, c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c, secret
}

// failingCCConfigProvider always errors, to assert client-credentials issuance
// fails closed on a config-resolution error rather than minting a token.
type failingCCConfigProvider struct{ err error }

func (p failingCCConfigProvider) Config(context.Context) (output.ClientCredentialsConfig, error) {
	return output.ClientCredentialsConfig{}, p.err
}

func TestClientCredentials_ConfigError_FailsClosed(t *testing.T) {
	wantErr := errors.New("cc config unavailable")
	setup := newCCTestSetupWithConfig(t, failingCCConfigProvider{err: wantErr})
	c, secret := setup.createConfidentialClient(t, "read write")

	resp, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read",
	})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v on config failure, got %v", wantErr, err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on config failure, got %+v", resp)
	}
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

// An empty client Scope is NOT "no restriction" for this grant — it is an empty
// ceiling. Requesting anything against it fails (see the two tests below); the
// only thing that succeeds is requesting nothing, which yields an empty scope.
func TestClientCredentials_EmptyClientScope_NoScopeRequested_IssuesEmptyScope(t *testing.T) {
	setup := newCCTestSetup(t)
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

// TestClientCredentials_AdminClientNoScopes_ErrorPointsAtTheGrant covers the
// operator who provisioned a machine client through the admin surface and left
// its scope empty. The generic invalid_scope text points at the token request
// while the cause is the registration two steps earlier — and for this client
// the remedy really is PATCH: it is an M2M client merely missing its grant.
func TestClientCredentials_AdminClientNoScopes_ErrorPointsAtTheGrant(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClientWithSource(t, "", client.SourceAdmin)

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "profile",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope", err)
	}
	// err.Error() IS the wire error_description (api/public/oauth/handlers.go:399).
	if !strings.Contains(err.Error(), "no registered scopes") {
		t.Errorf("error_description = %q, want it to state the client has no registered scopes", err.Error())
	}
	if !strings.Contains(err.Error(), "PATCH /admin/clients/{client_id}") {
		t.Errorf("error_description = %q, want the PATCH remedy for an admin-provisioned client", err.Error())
	}
}

// TestClientCredentials_DynamicallyRegisteredClient_ErrorRedirectsToTheAdminAPI
// covers the other empty-ceiling client: one that came through a registration
// door that only issues user-delegated clients. Telling this developer to PATCH
// is wrong advice — it repairs a client that should not have been created for
// this grant. The message names the door, not the field.
func TestClientCredentials_DynamicallyRegisteredClient_ErrorRedirectsToTheAdminAPI(t *testing.T) {
	for _, source := range []client.RegistrationSource{client.SourceDCR, client.SourceCIMD} {
		t.Run(string(source), func(t *testing.T) {
			setup := newCCTestSetup(t)
			c, secret := setup.createConfidentialClientWithSource(t, "", source)

			_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
				ClientID:     c.ID,
				ClientSecret: secret,
				Scope:        "profile",
			})
			if !errors.Is(err, domain.ErrInvalidScope) {
				t.Fatalf("err = %v, want ErrInvalidScope", err)
			}
			if !strings.Contains(err.Error(), "created through dynamic registration") {
				t.Errorf("error_description = %q, want it to name the registration door", err.Error())
			}
			if !strings.Contains(err.Error(), "pre-registered through the admin API") {
				t.Errorf("error_description = %q, want it to redirect to the admin API", err.Error())
			}
			// The repair advice must not reach this client: patching it around
			// the rule is the pattern the message exists to stop.
			if strings.Contains(err.Error(), "PATCH") {
				t.Errorf("error_description = %q, must not offer PATCH to a dynamically registered client", err.Error())
			}
		})
	}
}

// TestClientCredentials_ScopeExceedsRegistered_ErrorNamesTheOverreach is the
// third branch: a client that DOES have registered scopes but asked for more
// must not be told it has none — that would send the operator to the admin API
// for a client already configured there.
func TestClientCredentials_ScopeExceedsRegistered_ErrorNamesTheOverreach(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClient(t, "read")

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read admin",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope", err)
	}
	if !strings.Contains(err.Error(), "exceeds the client's registered scopes") {
		t.Errorf("error_description = %q, want it to state the request exceeded the registered set", err.Error())
	}
	if strings.Contains(err.Error(), "no registered scopes") {
		t.Errorf("error_description = %q, must not claim the client has no scopes", err.Error())
	}
}

// TestClientCredentials_DCRClientWithGrantedScopes_ErrorNamesTheOverreach pins
// the branch order. A dynamically registered client whose scopes were later
// granted by an operator is, at that point, a configured client overreaching —
// the registration door stops being the story, so the overreach message wins.
// Checking the source first would misdiagnose every such request.
func TestClientCredentials_DCRClientWithGrantedScopes_ErrorNamesTheOverreach(t *testing.T) {
	setup := newCCTestSetup(t)
	c, secret := setup.createConfidentialClientWithSource(t, "read", client.SourceDCR)

	_, err := setup.svc.Exchange(context.Background(), input.ClientCredentialsRequest{
		ClientID:     c.ID,
		ClientSecret: secret,
		Scope:        "read admin",
	})
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("err = %v, want ErrInvalidScope", err)
	}
	if !strings.Contains(err.Error(), "exceeds the client's registered scopes") {
		t.Errorf("error_description = %q, want the overreach message", err.Error())
	}
	if strings.Contains(err.Error(), "dynamic registration") {
		t.Errorf("error_description = %q, must not blame the registration door for an overreach", err.Error())
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
