//go:build integration

package public_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// oauthTestEnv holds the full wired test environment for OAuth endpoint tests.
type oauthTestEnv struct {
	ts         *httptest.Server
	stores     *testdata.TestHelper
	authSvc    *services.UserAuthService
	authzSvc   *services.AuthorizeService
	resourceID string // ID of the seeded Mint resource (for consent_grants.resource_id seeding)
}

func newOAuthTestServer(t *testing.T) *oauthTestEnv {
	t.Helper()

	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Key store + JWKS service.
	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)

	// Auth service.
	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	// Seed Mint resource for the registry-backed authorize/consent paths.
	now := time.Now().UTC()
	mintRes := &resource.Resource{
		ID:          crypto.GenerateRandomString(16),
		Slug:        "mcp-oauth-test",
		DisplayName: "OAuth Test MCP",
		URI:         "https://mcp.example.com",
		BackendKind: resource.BackendMint,
		Scopes: []resource.Scope{
			{Name: "tools/query", Description: "Query"},
			{Name: "tools/create", Description: "Create"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.Resource.Create(context.Background(), mintRes); err != nil {
		t.Fatalf("seed mint resource: %v", err)
	}

	// token_families.user_id is FK-enforced. Several tests build
	// AuthSession rows referencing these IDs and then exchange them for
	// tokens; seed the parent users up front so the token endpoint can
	// persist a family for them.
	testdata.EnsureUser(t, stores.User, "user-42")
	testdata.EnsureUser(t, stores.User, "user-check-url")

	registry := services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs)

	authzSvc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		nil, registry,
		static.NewOAuthConfigProvider(output.OAuthConfig{RequireScope: false}),
		obs,
	)

	// Consent service.
	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)

	// Token service.
	tokenCfg := static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	})
	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, staticIssuerForTest("https://auth.example.com"), obs)
	tokenSvc := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, stores.User,
		jwksSvc, mintIssuer, tokenCfg, obs, nil,
		stores.Revocation, nil,
	)

	// Revocation service.
	revokeSvc := services.NewRevocationService(stores.Token, stores.Client, stores.MachineToken, nil, staticIssuerForTest(""), obs, nil, stores.Revocation)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  authSvc,
		LoginDisplay:          static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		Authorize:             authzSvc,
		Consent:               consentSvc,
		Token:                 tokenSvc,
		Revoke:                revokeSvc,
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &oauthTestEnv{
		ts:         ts,
		stores:     &testdata.TestHelper{Stores: stores},
		authSvc:    authSvc,
		authzSvc:   authzSvc,
		resourceID: mintRes.ID,
	}
}

// createOAuthClient creates an active public client in the store.
func (e *oauthTestEnv) createClient(t *testing.T, isPublic bool) (*client.Client, string) {
	t.Helper()
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "OAuth Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	var secret string
	if !isPublic {
		secret = crypto.GenerateClientSecret()
		hash, _ := crypto.HashBcrypt(secret)
		c.SecretHash = hash
		c.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if err := e.stores.Stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c, secret
}

// loginAndGetCookie creates a user, logs in, and returns the session cookie.
func (e *oauthTestEnv) loginAndGetCookie(t *testing.T) []*http.Cookie {
	t.Helper()
	ctx := t.Context()

	_, err := e.authSvc.CreateUser(ctx, "oauth-test@example.com", "", "pass123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	jar := &testCookieJar{}
	hc := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := postLogin(t, hc, e.ts.URL, "oauth-test@example.com", "pass123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	u, _ := url.Parse(e.ts.URL)
	return jar.Cookies(u)
}

// --- GET /oauth/authorize ---

func TestAuthorizeEndpoint_InvalidClient_ShowsErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {"unknown-client"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Invalid client → error page, NOT redirect.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

func TestAuthorizeEndpoint_InvalidRedirectURI_ShowsErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Invalid redirect → error page, NOT redirect.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

func TestAuthorizeEndpoint_NoUser_RedirectsToLogin(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// No user → redirect to /login.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?redirect=") {
		t.Errorf("location: got %q, want /login?redirect=...", loc)
	}
}

func TestAuthorizeEndpoint_MissingPKCE_RedirectsWithError(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	q := url.Values{
		"client_id":     {c.ID},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"tools/query"},
		"state":         {"s1"},
		"resource":      {"https://mcp.example.com"},
		// code_challenge intentionally omitted
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// PKCE error → redirect with error param (redirect_uri is valid).
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if parsed.Query().Get("error") == "" {
		t.Error("redirect should contain error param")
	}
	if parsed.Query().Get("state") != "s1" {
		t.Errorf("state: got %q", parsed.Query().Get("state"))
	}
}

func TestAuthorizeEndpoint_WithUser_WithConsent_RedirectsWithCode(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	// Create user and log in.
	cookies := env.loginAndGetCookie(t)

	// Get user ID from the auth service.
	u, err := env.authSvc.Authenticate(t.Context(), "oauth-test@example.com", "pass123")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// Create prior consent grant on the unified store.
	now := time.Now().UTC()
	grant := &resource.ConsentGrant{
		ID:         crypto.GenerateRandomString(16),
		UserID:     u.ID,
		ClientID:   c.ID,
		ResourceID: env.resourceID,
		Scopes:     []string{"tools/query"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := env.stores.Stores.ConsentGrant.Upsert(context.Background(), grant); err != nil {
		t.Fatalf("upsert consent: %v", err)
	}

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{
		Jar: &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// User logged in + consent exists → redirect with code.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if !strings.HasPrefix(loc, "https://app.example.com/callback") {
		t.Errorf("location: got %q, want redirect to callback", loc)
	}
	if parsed.Query().Get("code") == "" {
		t.Error("redirect should contain code param")
	}
	if parsed.Query().Get("state") != "s1" {
		t.Errorf("state: got %q", parsed.Query().Get("state"))
	}
}

// --- POST /oauth/token ---

func TestTokenEndpoint_ValidExchange(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create session with code.
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
		State:               "s1",
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {c.ID},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	// Verify response headers.
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control: got %q, want no-store", cc)
	}
	if pragma := resp.Header.Get("Pragma"); pragma != "no-cache" {
		t.Errorf("pragma: got %q, want no-cache", pragma)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tokenResp["access_token"] == nil || tokenResp["access_token"] == "" {
		t.Error("access_token is empty")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token_type: got %v", tokenResp["token_type"])
	}
	if tokenResp["refresh_token"] == nil || tokenResp["refresh_token"] == "" {
		t.Error("refresh_token is empty")
	}
	if tokenResp["scope"] != "tools/query" {
		t.Errorf("scope: got %v", tokenResp["scope"])
	}

	// Matrix: 1.4.8 — upgraded from ⚠️: expires_in present and positive
	if ei, ok := tokenResp["expires_in"].(float64); !ok || ei <= 0 {
		t.Errorf("expires_in: got %v, want positive number", tokenResp["expires_in"])
	}
}

func TestTokenEndpoint_InvalidCode_Returns400(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {c.ID},
		"code_verifier": {"bad-verifier"},
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}

	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error: got %v", errResp["error"])
	}

	// Matrix: 1.4.12 — upgraded from ⚠️: no access_token in error response
	if errResp["access_token"] != nil {
		t.Error("error response must not contain access_token")
	}

	// Matrix: 10.2 — upgraded from ⚠️: error_description present
	if errResp["error_description"] == nil || errResp["error_description"] == "" {
		t.Error("error response should include error_description")
	}
}

func TestTokenEndpoint_UnsupportedGrantType_Returns400(t *testing.T) {
	env := newOAuthTestServer(t)

	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}

	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "unsupported_grant_type" {
		t.Errorf("error: got %v", errResp["error"])
	}
}

// Matrix: 1.4.1 — missing grant_type must return unsupported_grant_type
func TestTokenEndpoint_MissingGrantType_Returns400(t *testing.T) {
	env := newOAuthTestServer(t)

	form := url.Values{
		"code":          {"some-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"some-client"},
		"code_verifier": {"some-verifier"},
		// grant_type intentionally omitted
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}

	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "unsupported_grant_type" {
		t.Errorf("error: got %v, want unsupported_grant_type", errResp["error"])
	}
}

// Matrix: 10.3 — error responses must use Content-Type: application/problem+json (RFC 9457)
func TestTokenEndpoint_ErrorContentType_RFC9457(t *testing.T) {
	env := newOAuthTestServer(t)

	// Send invalid request to trigger an error response.
	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("error Content-Type: got %q, want application/problem+json", ct)
	}

	// Also verify RFC 9457 fields are present.
	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["type"] == nil || errResp["type"] == "" {
		t.Error("RFC 9457: 'type' field missing")
	}
	if errResp["title"] == nil || errResp["title"] == "" {
		t.Error("RFC 9457: 'title' field missing")
	}
	if errResp["status"] == nil {
		t.Error("RFC 9457: 'status' field missing")
	}
}

func TestTokenEndpoint_BasicAuth_ConfidentialClient(t *testing.T) {
	env := newOAuthTestServer(t)
	c, secret := env.createClient(t, false)
	ctx := context.Background()
	now := time.Now().UTC()

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
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {verifier},
	}

	req, _ := http.NewRequest("POST", env.ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set Basic auth header.
	creds := url.QueryEscape(c.ID) + ":" + url.QueryEscape(secret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("status: got %d, want 200; error: %v", resp.StatusCode, errResp)
	}

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	if tokenResp["access_token"] == nil || tokenResp["access_token"] == "" {
		t.Error("access_token is empty")
	}
}

// --- POST /oauth/token grant_type=refresh_token ---

// exchangeCodeForTokens is a test helper that creates a session, exchanges the code, and returns the token response.
func (e *oauthTestEnv) exchangeCodeForTokens(t *testing.T, c *client.Client, secret string) map[string]any {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	// Ensure user exists (required by refresh token user-status check).
	// Ignore error in case user already created by a previous call.
	_, _ = e.authSvc.CreateUser(ctx, "user42@example.com", "", "pass123", user.RoleUser)
	u42, err := e.stores.Stores.User.GetByEmail(ctx, "user42@example.com")
	if err != nil {
		t.Fatalf("get test user: %v", err)
	}

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	code := crypto.GenerateAuthCode()
	codeHash := crypto.HashSHA256(code)

	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              u42.ID,
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "s1",
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := e.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {c.ID},
		"code_verifier": {verifier},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}

	resp, err := http.PostForm(e.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status: got %d, want 200", resp.StatusCode)
	}

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	return tokenResp
}

func TestTokenEndpoint_RefreshToken_Success(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	// Exchange code for tokens.
	initial := env.exchangeCodeForTokens(t, c, "")

	refreshToken, _ := initial["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("no refresh_token in initial exchange")
	}

	// Refresh.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ID},
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("status: got %d, want 200; error: %v", resp.StatusCode, errResp)
	}

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)

	if tokenResp["access_token"] == nil || tokenResp["access_token"] == "" {
		t.Error("access_token is empty")
	}
	if tokenResp["refresh_token"] == nil || tokenResp["refresh_token"] == "" {
		t.Error("refresh_token is empty")
	}
	if tokenResp["refresh_token"] == refreshToken {
		t.Error("refresh_token was not rotated")
	}
}

func TestTokenEndpoint_RefreshToken_InvalidToken_Returns400(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"bogus-token"},
		"client_id":     {c.ID},
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}

	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error: got %v, want invalid_grant", errResp["error"])
	}
}

// --- POST /oauth/revoke ---

func TestRevokeEndpoint_ValidRefreshToken_Returns200(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	// Exchange code for tokens.
	initial := env.exchangeCodeForTokens(t, c, "")
	refreshToken, _ := initial["refresh_token"].(string)

	// Revoke the refresh token.
	form := url.Values{
		"token":     {refreshToken},
		"client_id": {c.ID},
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/revoke", form)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	// Verify: trying to use the revoked refresh token should fail.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ID},
	}
	refreshResp, err := http.PostForm(env.ts.URL+"/oauth/token", refreshForm)
	if err != nil {
		t.Fatalf("refresh after revoke: %v", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusBadRequest {
		t.Errorf("refresh after revoke status: got %d, want 400", refreshResp.StatusCode)
	}
}

func TestRevokeEndpoint_UnknownToken_Returns200(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	form := url.Values{
		"token":     {"unknown-token-value"},
		"client_id": {c.ID},
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/revoke", form)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestRevokeEndpoint_MissingToken_Returns400(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	form := url.Values{
		"client_id": {c.ID},
		// token intentionally missing
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/revoke", form)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestRevokeEndpoint_BasicAuth_ConfidentialClient(t *testing.T) {
	env := newOAuthTestServer(t)
	c, secret := env.createClient(t, false) // confidential client

	// Exchange code for tokens using the confidential client.
	initial := env.exchangeCodeForTokens(t, c, secret)
	refreshToken, _ := initial["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("no refresh_token in initial exchange")
	}

	// Revoke using HTTP Basic auth (not form body).
	form := url.Values{
		"token": {refreshToken},
	}
	req, err := http.NewRequest("POST", env.ts.URL+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.ID+":"+secret)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	// Verify: trying to use the revoked refresh token should fail.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ID},
		"client_secret": {secret},
	}
	refreshResp, err := http.PostForm(env.ts.URL+"/oauth/token", refreshForm)
	if err != nil {
		t.Fatalf("refresh after revoke: %v", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusBadRequest {
		t.Errorf("refresh after revoke status: got %d, want 400", refreshResp.StatusCode)
	}
}

func TestRevokeEndpoint_BasicAuth_WrongSecret_Returns401(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, false) // confidential client

	form := url.Values{
		"token": {"some-token"},
	}
	req, err := http.NewRequest("POST", env.ts.URL+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.ID+":wrong-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wwwAuth, "Basic") {
		t.Errorf("expected WWW-Authenticate: Basic, got %q", wwwAuth)
	}
}

// --- Batch 1: Authorization request validation ---

// Matrix: 1.1.1 — response_type required
func TestAuthorizeEndpoint_MissingResponseType_ShowsErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":    {c.ID},
		"redirect_uri": {"https://app.example.com/callback"},
		// response_type intentionally omitted
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Missing response_type → error page (not redirect to unvalidated URI).
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

// Matrix: 1.1.2 — implicit flow (response_type=token) must be rejected
func TestAuthorizeEndpoint_ImplicitFlowRejected(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"token"}, // OAuth 2.1 bans implicit flow
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// response_type=token → error page.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

// Matrix: 1.1.3 — missing client_id must show error page
func TestAuthorizeEndpoint_MissingClientID_ShowsErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		// client_id intentionally omitted
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Missing client_id → error page, NOT redirect.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

// Matrix: 1.1.5 — missing redirect_uri must show error page (NOT redirect)
func TestAuthorizeEndpoint_MissingRedirectURI_ShowsErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id": {c.ID},
		// redirect_uri intentionally omitted
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Missing redirect_uri → error page, NOT redirect to unknown URI.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

// --- Batch 7: Error status codes ---

// Matrix: 10.7 — invalid_client on token endpoint must return 401
func TestTokenEndpoint_InvalidClient_Returns401(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create a valid session so the code exchange proceeds past code lookup.
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
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Exchange with wrong client_id → ErrInvalidClient → 401.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"wrong-client-id"},
		"code_verifier": {verifier},
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}

	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "invalid_client" {
		t.Errorf("error: got %v, want invalid_client", errResp["error"])
	}

	// Matrix: 10.6 — upgraded from ⚠️: error response must not leak internal details
	errBody, _ := json.Marshal(errResp)
	bodyStr := string(errBody)
	for _, leak := range []string{".go:", "runtime.", "goroutine", "SELECT ", "INSERT ", "panic"} {
		if strings.Contains(bodyStr, leak) {
			t.Errorf("error response contains internal detail: %q", leak)
		}
	}
}

// Matrix: 1.1.11 — upgraded from ⚠️: unknown scope with valid resource must return invalid_scope
func TestAuthorizeEndpoint_UnknownScope_ValidResource(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/nonexistent_tool"}, // unknown scope for the resource
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if errCode := parsed.Query().Get("error"); errCode != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope", errCode)
	}
	if parsed.Query().Get("state") != "s1" {
		t.Errorf("state: got %q", parsed.Query().Get("state"))
	}
}

// Matrix: 14.2 — upgraded from ⚠️: missing code_verifier entirely at token exchange must fail
func TestTokenEndpoint_MissingCodeVerifier_Returns400(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	ctx := context.Background()
	now := time.Now().UTC()

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
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Exchange without code_verifier entirely (PKCE downgrade attempt).
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://app.example.com/callback"},
		"client_id":    {c.ID},
		// code_verifier intentionally omitted
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}

	var errResp map[string]any
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error: got %v, want invalid_grant (PKCE verification failed)", errResp["error"])
	}
}

// Matrix: 13.7 — upgraded from ⚠️: active session skips login (redirects to consent, not login)
func TestAuthorizeEndpoint_WithSession_SkipsLogin(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	// Create user and log in to get session cookies.
	cookies := env.loginAndGetCookie(t)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{
		Jar: &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// With active session and no prior consent → redirect to /consent, NOT /login.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if strings.HasPrefix(loc, "/login") {
		t.Errorf("should redirect to /consent, not /login; got %q", loc)
	}
	if !strings.HasPrefix(loc, "/consent") {
		t.Errorf("expected redirect to /consent, got %q", loc)
	}
}

// Matrix: 14.17 — error responses must not leak internal implementation details
func TestTokenEndpoint_ErrorInfoLeakage(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	leakPatterns := []string{".go:", "runtime.", "goroutine", "SELECT ", "INSERT ", "panic", "sql:", "sqlite", "file:", "/internal/"}

	cases := []struct {
		name string
		form url.Values
	}{
		{
			name: "unsupported_grant_type",
			form: url.Values{"grant_type": {"client_credentials"}},
		},
		{
			name: "missing_grant_type",
			form: url.Values{"code": {"x"}, "client_id": {c.ID}},
		},
		{
			name: "invalid_code",
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"bogus-code"},
				"redirect_uri":  {"https://app.example.com/callback"},
				"client_id":     {c.ID},
				"code_verifier": {strings.Repeat("x", 43)},
			},
		},
		{
			name: "invalid_refresh",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"bogus-token"},
				"client_id":     {c.ID},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.PostForm(env.ts.URL+"/oauth/token", tc.form)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()

			var errResp map[string]any
			json.NewDecoder(resp.Body).Decode(&errResp)
			bodyBytes, _ := json.Marshal(errResp)
			bodyStr := string(bodyBytes)

			for _, pattern := range leakPatterns {
				if strings.Contains(bodyStr, pattern) {
					t.Errorf("error response contains internal detail %q: %s", pattern, bodyStr)
				}
			}
		})
	}
}

// Matrix: 10.5 — error responses include X-Request-ID for trace correlation
func TestTokenEndpoint_ErrorResponse_HasRequestID(t *testing.T) {
	env := newOAuthTestServer(t)

	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	reqID := resp.Header.Get("X-Request-ID")
	if reqID == "" {
		t.Error("error response should include X-Request-ID header for trace correlation")
	}
}

// Matrix: 14.18 — state parameter with newlines must not cause header injection
func TestAuthorizeEndpoint_StateHeaderInjection(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// Craft a state with CRLF injection attempt.
	maliciousState := "legit\r\nX-Injected: evil"

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"nonexistent_scope"}, // will trigger error redirect
		"state":                 {maliciousState},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// The injected header must not appear in response headers.
	if resp.Header.Get("X-Injected") != "" {
		t.Error("header injection via state parameter: X-Injected header found in response")
	}

	// If we got a redirect, verify the state is URL-encoded in the Location.
	if loc := resp.Header.Get("Location"); loc != "" {
		if strings.Contains(loc, "\r\n") || strings.Contains(loc, "\n") {
			t.Error("Location header contains raw newlines — potential header injection")
		}
	}
}

// Matrix: 10.9 — invalid scope on authorize must return error type invalid_scope
func TestAuthorizeEndpoint_InvalidScope_ReturnsInvalidScope(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"nonexistent_scope"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Invalid scope with valid redirect_uri → redirect with error=invalid_scope.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if errCode := parsed.Query().Get("error"); errCode != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope", errCode)
	}
	if parsed.Query().Get("state") != "s1" {
		t.Errorf("state: got %q", parsed.Query().Get("state"))
	}
}

// Matrix: 14.19 — access token must not appear in URL query parameters
func TestTokenEndpoint_NoTokenInURL(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	// Exchange code for tokens via the existing helper.
	tokenResp := env.exchangeCodeForTokens(t, c, "")
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("no access_token in response body")
	}

	// Token endpoint response is a JSON body — verify no Location header leaks the token.
	// (exchangeCodeForTokens already asserts 200, so we re-do a raw POST to check headers.)
	ctx := context.Background()
	now := time.Now().UTC()
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	code := crypto.GenerateAuthCode()
	codeHash := crypto.HashSHA256(code)

	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              "user-check-url",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "tools/query",
		Resource:            "https://mcp.example.com",
		State:               "s1",
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := env.stores.Stores.Session.Create(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {c.ID},
		"code_verifier": {verifier},
	}
	resp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// Token endpoint must NOT include a Location header (tokens only in body).
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("token endpoint must not return Location header, got %q", loc)
		if strings.Contains(loc, "access_token") {
			t.Error("Location header contains access_token — OAuth 2.1 violation")
		}
	}

	// Verify the authorize endpoint redirect uses ?code=, not ?access_token=.
	// The implicit flow (response_type=token) is already rejected by TestAuthorizeEndpoint_ImplicitFlowRejected.
	// Here we verify the code flow redirect contains only code, not token.
	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authResp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authResp.Body.Close()

	// Regardless of the redirect destination, access_token must never appear in URL.
	if authResp.StatusCode == http.StatusSeeOther {
		authLoc := authResp.Header.Get("Location")
		if strings.Contains(authLoc, "access_token=") {
			t.Error("authorize redirect must not contain access_token in URL")
		}
	}
}

// Matrix: 1.1.14 — missing resource parameter behavior documented
func TestAuthorizeEndpoint_MissingResource_Succeeds(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// Send authorize request WITHOUT a resource parameter.
	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		// No "resource" parameter.
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Server allows missing resource — redirects to login (no user in session).
	// A 400 error page would mean resource is required; a redirect means it's optional.
	if resp.StatusCode == http.StatusBadRequest {
		t.Fatal("server requires resource parameter (unexpected); update matrix to document requirement")
	}
	// Should redirect to login or consent — not an error.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303 (redirect to login)", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?redirect=") {
		t.Errorf("location: got %q, want /login?redirect=...", loc)
	}
}

// Matrix: 1.1.15 — extra unknown parameters ignored
func TestAuthorizeEndpoint_ExtraParamsIgnored(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// Valid authorize request with extra unknown parameters appended.
	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"foo":                   {"bar"},
		"baz":                   {"qux"},
		"unknown_param":         {"value"},
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Extra params should be ignored — request should proceed normally (redirect to login).
	if resp.StatusCode == http.StatusBadRequest {
		t.Fatal("extra unknown parameters should be ignored, not cause an error")
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303 (redirect to login)", resp.StatusCode)
	}
}

// Matrix: 1.1.7 — redirect_uri with extra query params must be rejected (exact match)
func TestAuthorizeEndpoint_RedirectURIExtraParams_ShowsErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// The registered redirect_uri is "https://app.example.com/callback".
	// Adding query params makes it a different string → must fail exact match.
	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback?extra=param"},
		"response_type":         {"code"},
		"scope":                 {"tools/query"},
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := http.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Mismatched redirect_uri → error page (NOT redirect to the unregistered URI).
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
}

// --- oauth.require_scope config ---

// TestAuthorize_RequireScope_RejectsEmptyScope verifies that require_scope=true
// rejects authorize requests missing the scope parameter with invalid_scope.
func TestAuthorize_RequireScope_RejectsEmptyScope(t *testing.T) {
	// Create a server with requireScope=true.
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	now := time.Now().UTC()
	mintRes := &resource.Resource{
		ID:          crypto.GenerateRandomString(16),
		Slug:        "mcp-rs-true",
		DisplayName: "RS True MCP",
		URI:         "https://mcp.example.com",
		BackendKind: resource.BackendMint,
		Scopes: []resource.Scope{
			{Name: "tools/query", Description: "Query"},
			{Name: "tools/create", Description: "Create"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := stores.Resource.Create(context.Background(), mintRes); err != nil {
		t.Fatalf("seed mint resource: %v", err)
	}
	registry := services.NewResourceRegistry(stores.Resource, stores.BrokerProvider, obs)

	authzSvc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		nil, registry,
		static.NewOAuthConfigProvider(output.OAuthConfig{RequireScope: true}),
		obs, // requireScope=true
	)

	consentSvc := services.NewConsentService(
		stores.ConsentGrant, stores.Session, stores.Client, registry, obs, nil,
	)
	tokenCfg := static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	})
	mintIssuer := services.NewMintIssuer(jwksSvc, stores.Issuance, staticIssuerForTest("https://auth.example.com"), obs)
	tokenSvc := services.NewTokenService(
		stores.Session, stores.Token, stores.Client, stores.User,
		jwksSvc, mintIssuer, tokenCfg, obs, nil,
		stores.Revocation, nil,
	)
	revokeSvc := services.NewRevocationService(stores.Token, stores.Client, stores.MachineToken, nil, staticIssuerForTest(""), obs, nil, stores.Revocation)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  authSvc,
		LoginDisplay:          static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		Authorize:             authzSvc,
		Consent:               consentSvc,
		Token:                 tokenSvc,
		Revoke:                revokeSvc,
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Create a client.
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "RequireScope Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// Authorize request WITHOUT scope.
	q := url.Values{
		"client_id":     {c.ID},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		// scope intentionally omitted
		"state":                 {"s1"},
		"resource":              {"https://mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	hc := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := hc.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// require_scope=true → redirect with error=invalid_scope.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if errCode := parsed.Query().Get("error"); errCode != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope", errCode)
	}
}

// --- ADR-012: Default scope when scope parameter is absent (require_scope=false) ---

// Matrix: 22.7 — missing scope defaults to registered scopes for the resource.
func TestAuthorize_MissingScope_DefaultScopes(t *testing.T) {
	t.Run("with_resource", func(t *testing.T) {
		env := newOAuthTestServer(t)
		c, _ := env.createClient(t, true)

		// Create user and log in.
		cookies := env.loginAndGetCookie(t)

		// Get user ID.
		u, err := env.authSvc.Authenticate(t.Context(), "oauth-test@example.com", "pass123")
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}

		// Create consent grant covering all registered scopes for the resource.
		// ADR-012 defaults scope to "tools/query tools/create" for https://mcp.example.com.
		now := time.Now().UTC()
		grant := &resource.ConsentGrant{
			ID:         crypto.GenerateRandomString(16),
			UserID:     u.ID,
			ClientID:   c.ID,
			ResourceID: env.resourceID,
			Scopes:     []string{"tools/query", "tools/create"},
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := env.stores.Stores.ConsentGrant.Upsert(context.Background(), grant); err != nil {
			t.Fatalf("upsert consent: %v", err)
		}

		verifier := crypto.GenerateVerifier()
		challenge := crypto.ComputeS256Challenge(verifier)

		// Authorize request WITHOUT scope but WITH resource.
		q := url.Values{
			"client_id":     {c.ID},
			"redirect_uri":  {"https://app.example.com/callback"},
			"response_type": {"code"},
			// scope intentionally omitted — ADR-012.
			"state":                 {"s1"},
			"resource":              {"https://mcp.example.com"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}

		hc := &http.Client{
			Jar: &testCookieJar{cookies: cookies},
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()

		// User logged in + consent covers defaulted scopes → redirect with code.
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status: got %d, want 303", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		parsed, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("parse location: %v", err)
		}
		if !strings.HasPrefix(loc, "https://app.example.com/callback") {
			t.Fatalf("location: got %q, want redirect to callback", loc)
		}
		code := parsed.Query().Get("code")
		if code == "" {
			t.Fatal("redirect should contain code param")
		}
		if parsed.Query().Get("state") != "s1" {
			t.Errorf("state: got %q", parsed.Query().Get("state"))
		}

		// Exchange code for tokens.
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://app.example.com/callback"},
			"client_id":     {c.ID},
			"code_verifier": {verifier},
		}

		tokenResp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
		if err != nil {
			t.Fatalf("token exchange: %v", err)
		}
		defer tokenResp.Body.Close()

		if tokenResp.StatusCode != http.StatusOK {
			var errBody map[string]any
			json.NewDecoder(tokenResp.Body).Decode(&errBody)
			t.Fatalf("token status: got %d, want 200; error: %v", tokenResp.StatusCode, errBody)
		}

		var tokenBody map[string]any
		json.NewDecoder(tokenResp.Body).Decode(&tokenBody)

		// Verify defaulted scope appears in token response.
		scope, _ := tokenBody["scope"].(string)
		if scope == "" {
			t.Fatal("token response scope is empty — default scope substitution failed")
		}
		scopeSet := make(map[string]bool)
		for _, s := range strings.Fields(scope) {
			scopeSet[s] = true
		}
		if !scopeSet["tools/query"] {
			t.Errorf("scope missing tools/query: got %q", scope)
		}
		if !scopeSet["tools/create"] {
			t.Errorf("scope missing tools/create: got %q", scope)
		}
	})

	t.Run("no_scope_no_resource", func(t *testing.T) {
		env := newOAuthTestServer(t)
		c, _ := env.createClient(t, true)

		// Create user and log in.
		cookies := env.loginAndGetCookie(t)

		if _, err := env.authSvc.Authenticate(t.Context(), "oauth-test@example.com", "pass123"); err != nil {
			t.Fatalf("authenticate: %v", err)
		}

		// : the unified consent_grants requires resource_id (FK).
		// Empty-resource flows route through the consent screen on every
		// /authorize call; no pre-seed is possible. The test accepts a
		// redirect to /consent OR a redirect to the callback below.

		verifier := crypto.GenerateVerifier()
		challenge := crypto.ComputeS256Challenge(verifier)

		// Authorize request WITHOUT scope AND WITHOUT resource.
		q := url.Values{
			"client_id":             {c.ID},
			"redirect_uri":          {"https://app.example.com/callback"},
			"response_type":         {"code"},
			"state":                 {"s2"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}

		hc := &http.Client{
			Jar: &testCookieJar{cookies: cookies},
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()

		// Should proceed (redirect with code or to consent) — NOT fail.
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status: got %d, want 303", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		parsed, _ := url.Parse(loc)

		// The authorize request must NOT return an error.
		if errCode := parsed.Query().Get("error"); errCode != "" {
			t.Errorf("authorize should not return error when scope is defaulted; got error=%q", errCode)
		}

		// If redirected to callback (consent satisfied), verify code + exchange tokens.
		if strings.HasPrefix(loc, "https://app.example.com/callback") {
			code := parsed.Query().Get("code")
			if code == "" {
				t.Fatal("redirect to callback should contain code param")
			}

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {"https://app.example.com/callback"},
				"client_id":     {c.ID},
				"code_verifier": {verifier},
			}
			tokenResp, err := http.PostForm(env.ts.URL+"/oauth/token", form)
			if err != nil {
				t.Fatalf("token exchange: %v", err)
			}
			defer tokenResp.Body.Close()

			if tokenResp.StatusCode != http.StatusOK {
				var errBody map[string]any
				json.NewDecoder(tokenResp.Body).Decode(&errBody)
				t.Fatalf("token status: got %d; error: %v", tokenResp.StatusCode, errBody)
			}

			var tokenBody map[string]any
			json.NewDecoder(tokenResp.Body).Decode(&tokenBody)

			scope, _ := tokenBody["scope"].(string)
			if scope == "" {
				t.Fatal("token scope is empty — default scope substitution failed (no resource)")
			}
			scopeSet := make(map[string]bool)
			for _, s := range strings.Fields(scope) {
				scopeSet[s] = true
			}
			if !scopeSet["tools/query"] {
				t.Errorf("scope missing tools/query: got %q", scope)
			}
			if !scopeSet["tools/create"] {
				t.Errorf("scope missing tools/create: got %q", scope)
			}
		}
	})
}

// --- Token Exchange: consent_required ---

// stubTokenExchangeProvider is a minimal mock for TokenExchangeProvider.
type stubTokenExchangeProvider struct {
	exchangeFn func(ctx context.Context, req input.TokenExchangeRequest) (*input.TokenExchangeResponse, error)
}

func (s *stubTokenExchangeProvider) Exchange(ctx context.Context, req input.TokenExchangeRequest) (*input.TokenExchangeResponse, error) {
	return s.exchangeFn(ctx, req)
}

// TestTokenExchange_ConsentRequired_ReturnsConsentURL asserts that the
// token endpoint maps a domain.ConsentRequiredError to an
// application/problem+json response with error code consent_required and
// an absolute consent_url built from the issuer (IssuerProvider). The URL
// shape itself is pinned by api/public/connection/consent_url_test.go.
func TestTokenExchange_ConsentRequired_ReturnsConsentURL(t *testing.T) {
	mock := &stubTokenExchangeProvider{
		exchangeFn: func(_ context.Context, _ input.TokenExchangeRequest) (*input.TokenExchangeResponse, error) {
			return nil, &domain.ConsentRequiredError{ProviderSlug: "google-calendar", ResourceSlug: "google-calendar"}
		},
	}

	obs := testObs()
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		TokenExchange:         mock,
		IssuerProvider:        staticIssuerForTest("https://as.test"),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"dummy"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"google-calendar"},
		"client_id":          {"test-client"},
		"client_secret":      {"test-secret"},
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want %q", ct, "application/problem+json")
	}

	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ConsentURL       string `json:"consent_url"`
		Cause            string `json:"cause"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if body.Error != "consent_required" {
		t.Errorf("error: got %q, want %q", body.Error, "consent_required")
	}
	if body.ErrorDescription != "Authorize access to google-calendar" {
		t.Errorf("error_description: got %q, want %q", body.ErrorDescription, "Authorize access to google-calendar")
	}
	wantURL := "https://as.test/connect/google-calendar?resource=google-calendar&return_url=" + url.QueryEscape("https://as.test/connections")
	if body.ConsentURL != wantURL {
		t.Errorf("consent_url: got %q, want %q", body.ConsentURL, wantURL)
	}
	// : legacy ConsentRequiredError with empty Cause maps to
	// "consent_missing" on the wire.
	if body.Cause != domain.CauseConsentMissing {
		t.Errorf("cause: got %q, want %q", body.Cause, domain.CauseConsentMissing)
	}
}

// TestTokenExchange_ConsentRequired_EmptyBase_OmitsConsentURL asserts that
// when the issuer resolves empty the handler still emits the
// consent_required error code, but the consent_url field is omitted from
// the JSON response (per api/shared.WriteOAuthErrorWithConsent + omitempty).
// The per-request warn log is not asserted here — it is a side effect, not
// a wire-contract obligation.
func TestTokenExchange_ConsentRequired_EmptyBase_OmitsConsentURL(t *testing.T) {
	mock := &stubTokenExchangeProvider{
		exchangeFn: func(_ context.Context, _ input.TokenExchangeRequest) (*input.TokenExchangeResponse, error) {
			return nil, &domain.ConsentRequiredError{ProviderSlug: "google-calendar", ResourceSlug: "google-calendar"}
		},
	}

	obs := testObs()
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		TokenExchange:         mock,
		// IssuerProvider intentionally resolves empty → consent_url omitted.
		IssuerProvider: staticIssuerForTest(""),
		SessionCookie:  apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"dummy"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"google-calendar"},
		"client_id":          {"test-client"},
		"client_secret":      {"test-secret"},
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// Decode into a map so we can distinguish "missing" from "present and empty".
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if body["error"] != "consent_required" {
		t.Errorf("error: got %v, want consent_required", body["error"])
	}
	if _, ok := body["consent_url"]; ok {
		t.Errorf("consent_url should be omitted when base is empty, got %v", body["consent_url"])
	}
}

// TestTokenExchange_ConsentRequired_EmptyProviderSlug_EmitsAuthorizeURL asserts
// the  wire shape: when the service-layer ConsentRequiredError has only
// ResourceSlug populated (Mint dispatch user-consent path, or Broker bound-B
// agent-attestation path), the handler synthesizes an AS-side re-consent URL
// pointing at `/authorize?resource=<slug>`, NOT a `/connect/<provider>` URL.
// The remediation for those cases is the user re-running /authorize, not an
// upstream-OAuth reconnect dance.
func TestTokenExchange_ConsentRequired_EmptyProviderSlug_EmitsAuthorizeURL(t *testing.T) {
	mock := &stubTokenExchangeProvider{
		exchangeFn: func(_ context.Context, _ input.TokenExchangeRequest) (*input.TokenExchangeResponse, error) {
			return nil, &domain.ConsentRequiredError{
				ResourceSlug: "internal-mcp",
				Cause:        domain.CauseConsentMissing,
			}
		},
	}

	obs := testObs()
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		TokenExchange:         mock,
		IssuerProvider:        staticIssuerForTest("https://as.test"),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"dummy"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"internal-mcp"},
		"client_id":          {"test-client"},
		"client_secret":      {"test-secret"},
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "consent_required" {
		t.Errorf("error: got %v, want consent_required", body["error"])
	}
	wantURL := "https://as.test/authorize?resource=internal-mcp"
	if got, _ := body["consent_url"].(string); got != wantURL {
		t.Errorf("consent_url: got %v, want %q", body["consent_url"], wantURL)
	}
	if got, _ := body["cause"].(string); got != domain.CauseConsentMissing {
		t.Errorf("cause: got %v, want %q", body["cause"], domain.CauseConsentMissing)
	}
}

// TestTokenExchange_ConsentRequired_BoundC_EmitsAuthorizeURLWithScope asserts
// the  bound-C wire shape: when the service-layer ConsentRequiredError
// carries Cause=CauseScopeInsufficient + MissingScopes, the handler emits a
// /authorize URL with `scope=<missing>` so the consent UI can prompt for the
// expanded scope set.
func TestTokenExchange_ConsentRequired_BoundC_EmitsAuthorizeURLWithScope(t *testing.T) {
	mock := &stubTokenExchangeProvider{
		exchangeFn: func(_ context.Context, _ input.TokenExchangeRequest) (*input.TokenExchangeResponse, error) {
			return nil, &domain.ConsentRequiredError{
				ResourceSlug:  "test-mcp",
				Cause:         domain.CauseScopeInsufficient,
				MissingScopes: []string{"admin:org"},
			}
		},
	}

	obs := testObs()
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		TokenExchange:         mock,
		IssuerProvider:        staticIssuerForTest("https://as.test"),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"dummy"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"github-repo"},
		"scope":              {"admin:org"},
		"client_id":          {"test-mcp"},
		"client_secret":      {"test-secret"},
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	wantURL := "https://as.test/authorize?resource=test-mcp&scope=admin%3Aorg"
	if got, _ := body["consent_url"].(string); got != wantURL {
		t.Errorf("consent_url: got %v, want %q", body["consent_url"], wantURL)
	}
	if got, _ := body["cause"].(string); got != domain.CauseScopeInsufficient {
		t.Errorf("cause: got %v, want %q", body["cause"], domain.CauseScopeInsufficient)
	}
	// MissingScopes must NOT be on the wire (probe-oracle reduction).
	if _, ok := body["missing_scopes"]; ok {
		t.Errorf("missing_scopes should NOT be serialized; body[missing_scopes]=%v", body["missing_scopes"])
	}
}

// --- : per-MCP consent screen integration tests ---

// startAuthorizeAndExtractSessionID kicks off /authorize, follows the redirect
// to /consent, and returns (cookies, sessionID). Used by the per-MCP consent
// integration tests.
func startAuthorizeAndExtractSessionID(t *testing.T, env *oauthTestEnv, c *client.Client, scope, resourceParam string) ([]*http.Cookie, string) {
	t.Helper()
	cookies := env.loginAndGetCookie(t)
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {"per-mcp-state"},
		"resource":              {resourceParam},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	hc := &http.Client{
		Jar:           &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 to /consent, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/consent" {
		t.Fatalf("Location path: got %q, want /consent", loc.Path)
	}
	sid := loc.Query().Get("session_id")
	if sid == "" {
		t.Fatal("session_id missing from /consent redirect")
	}
	return cookies, sid
}

// TestConsent_GET_RendersPerMCPTemplate verifies GET /consent renders the
// rewritten per-MCP shape: the header reads "<ClientName> wants permission to
// access <ResourceDisplayName>" and at least one scope description appears as
// the primary label.
func TestConsent_GET_RendersPerMCPTemplate(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	cookies, sid := startAuthorizeAndExtractSessionID(t, env, c, "tools/query", "https://mcp.example.com")

	hc := &http.Client{
		Jar:           &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Get(env.ts.URL + "/consent?session_id=" + url.QueryEscape(sid))
	if err != nil {
		t.Fatalf("GET /consent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var body strings.Builder
	io.Copy(&body, resp.Body)
	bs := body.String()
	if !strings.Contains(bs, "wants permission to access") {
		t.Error("body missing per-MCP header phrase")
	}
	if !strings.Contains(bs, "OAuth Test MCP") {
		t.Error("body missing ResourceDisplayName")
	}
	if !strings.Contains(bs, "Query") {
		t.Error("body missing scope description rendered as primary label")
	}
}

// TestConsent_POST_Allow_PersistsToUnifiedStore verifies POST /consent with
// action=allow writes to the renamed consent_grants table and redirects with
// a code. This is the load-bearing assertion for : the write side now
// lands in the same table dispatchMint reads.
func TestConsent_POST_Allow_PersistsToUnifiedStore(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	cookies, sid := startAuthorizeAndExtractSessionID(t, env, c, "tools/query", "https://mcp.example.com")

	// First do a GET to obtain the CSRF token.
	hc := &http.Client{
		Jar:           &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	getResp, err := hc.Get(env.ts.URL + "/consent?session_id=" + url.QueryEscape(sid))
	if err != nil {
		t.Fatalf("GET /consent: %v", err)
	}
	var bodyBuf strings.Builder
	io.Copy(&bodyBuf, getResp.Body)
	getResp.Body.Close()
	csrfToken := extractCSRFToken(bodyBuf.String())
	if csrfToken == "" {
		t.Fatal("could not extract CSRF token from /consent body")
	}

	form := url.Values{
		"session_id": {sid},
		"csrf_token": {csrfToken},
		"action":     {"allow"},
		"scopes":     {"tools/query"},
	}
	postReq, _ := http.NewRequest("POST", env.ts.URL+"/consent", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp, err := hc.Do(postReq)
	if err != nil {
		t.Fatalf("POST /consent: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", postResp.StatusCode)
	}
	loc := postResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/callback") {
		t.Errorf("expected redirect to callback, got %q", loc)
	}
	parsed, _ := url.Parse(loc)
	if parsed.Query().Get("code") == "" {
		t.Error("redirect missing auth code")
	}

	// Verify the row was persisted to the renamed unified table.
	got, err := env.stores.Stores.ConsentGrant.Get(context.Background(), "", c.ID, env.resourceID)
	if err != nil {
		t.Fatalf("query unified consent grant: %v", err)
	}
	if got != nil {
		// The user_id is whatever the session cookie maps to; the important
		// invariant is that resource_id matches the seeded resource UUID.
		if got.ResourceID != env.resourceID {
			t.Errorf("ResourceID: got %q, want %q (resource UUID, NOT URI)", got.ResourceID, env.resourceID)
		}
	} else {
		// Try listing for the user behind the session cookie. The test
		// env's authSvc.Authenticate gives us the user.
		u, authErr := env.authSvc.Authenticate(context.Background(), "oauth-test@example.com", "pass123")
		if authErr != nil {
			t.Fatalf("authenticate: %v", authErr)
		}
		got, err = env.stores.Stores.ConsentGrant.Get(context.Background(), u.ID, c.ID, env.resourceID)
		if err != nil {
			t.Fatalf("query unified consent grant by user: %v", err)
		}
		if got == nil {
			t.Fatal("expected unified consent grant row, got nil — write side did not land in renamed table")
		}
	}
}

// TestConsent_GET_BrokerResource_RendersErrorPage verifies that when /authorize
// resolves to a Broker resource, the consent flow surfaces the Mint-only
// invariant via the AS-side error page (NOT a redirect).
func TestConsent_GET_BrokerResource_RendersErrorPage(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)

	// Seed a Broker resource directly into the registry-backed store.
	now := time.Now().UTC()
	bp := &resource.BrokerProvider{
		ID:          crypto.GenerateRandomString(16),
		Slug:        "broker-test-provider",
		DisplayName: "Broker Provider",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"stub","client_secret_ref":"STUB"}`),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := env.stores.Stores.BrokerProvider.Create(context.Background(), bp); err != nil {
		t.Fatalf("seed broker provider: %v", err)
	}
	brokerRes := &resource.Resource{
		ID:               crypto.GenerateRandomString(16),
		Slug:             "broker-mcp",
		DisplayName:      "Broker MCP",
		URI:              "https://broker-mcp.example.com",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: bp.ID,
		Scopes:           []resource.Scope{{Name: "read", Description: "Read"}},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := env.stores.Stores.Resource.Create(context.Background(), brokerRes); err != nil {
		t.Fatalf("seed broker resource: %v", err)
	}

	cookies := env.loginAndGetCookie(t)
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)
	q := url.Values{
		"client_id":             {c.ID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"read"},
		"state":                 {"broker-state"},
		"resource":              {"https://broker-mcp.example.com"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	hc := &http.Client{
		Jar:           &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Get(env.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	var body strings.Builder
	io.Copy(&body, resp.Body)
	if !strings.Contains(body.String(), "Invalid Resource") {
		t.Error("body missing 'Invalid Resource' title")
	}
	if !strings.Contains(body.String(), "broker resources") {
		t.Error("body missing broker-resource explanation")
	}
}

// TestConsent_POST_CSRFRequired verifies POST /consent rejects requests
// without a valid csrf_token. Regression: the per-MCP rewrite must preserve
// CSRF gating.
func TestConsent_POST_CSRFRequired(t *testing.T) {
	env := newOAuthTestServer(t)
	c, _ := env.createClient(t, true)
	cookies, sid := startAuthorizeAndExtractSessionID(t, env, c, "tools/query", "https://mcp.example.com")

	form := url.Values{
		"session_id": {sid},
		"csrf_token": {"bogus"},
		"action":     {"allow"},
		"scopes":     {"tools/query"},
	}
	hc := &http.Client{
		Jar:           &testCookieJar{cookies: cookies},
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	postReq, _ := http.NewRequest("POST", env.ts.URL+"/consent", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(postReq)
	if err != nil {
		t.Fatalf("POST /consent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", resp.StatusCode)
	}
}

// extractCSRFToken pulls the csrf_token hidden input value out of the consent
// page body. Cheap regex; the page is small.
func extractCSRFToken(body string) string {
	const marker = `name="csrf_token" value="`
	idx := strings.Index(body, marker)
	if idx == -1 {
		return ""
	}
	rest := body[idx+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	return rest[:end]
}
