package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// stubSecretResolver returns a fixed plaintext secret for any reference. The
// adapter treats the reference as opaque and no longer validates its shape,
// so tests may use any string; allowlist enforcement now lives in the env
// resolver (see cmd/authserver).
type stubSecretResolver struct {
	secret string
	err    error
}

func (s *stubSecretResolver) Resolve(_ context.Context, _ output.SecretSource) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.secret, nil
}

func newAdapter(t *testing.T, ts *httptest.Server) *Adapter {
	t.Helper()
	return New(
		ts.Client(),
		&stubSecretResolver{secret: "test-secret"},
		WithCallbackURL("http://127.0.0.1:9000/broker/callback/google"),
		WithAllowLoopback(true),
	)
}

// fakeUpstream wires a single httptest.Server that implements both /token
// and /revoke. Tests pass a tokenHandler to control the token-endpoint
// response per scenario.
type fakeUpstream struct {
	server          *httptest.Server
	tokenRequests   []url.Values
	revokeRequests  []url.Values
	revokeStatus    int
	tokenHandler    http.HandlerFunc
	tokenURL        string
	revokeURL       string
	authorizeURLRaw string
}

func newFakeUpstream(t *testing.T, tokenHandler http.HandlerFunc) *fakeUpstream {
	t.Helper()
	fu := &fakeUpstream{tokenHandler: tokenHandler, revokeStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fu.tokenRequests = append(fu.tokenRequests, r.PostForm)
		fu.tokenHandler(w, r)
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fu.revokeRequests = append(fu.revokeRequests, r.PostForm)
		w.WriteHeader(fu.revokeStatus)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	fu.server = httptest.NewServer(mux)
	t.Cleanup(fu.server.Close)
	fu.tokenURL = fu.server.URL + "/token"
	fu.revokeURL = fu.server.URL + "/revoke"
	fu.authorizeURLRaw = fu.server.URL + "/authorize"
	return fu
}

func (fu *fakeUpstream) configBytes(t *testing.T, extra map[string]string, responseFormat string) []byte {
	t.Helper()
	cfg := configData{
		ClientID:        "test-client-id",
		ClientSecretRef: "CONNECTOR_TEST_SECRET",
		AuthorizeURL:    fu.authorizeURLRaw,
		TokenURL:        fu.tokenURL,
		RevokeURL:       fu.revokeURL,
		ResponseFormat:  responseFormat,
		ExtraAuthParams: extra,
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal configData: %v", err)
	}
	return b
}

func mustResource(scopes ...resource.Scope) *resource.Resource {
	return &resource.Resource{
		ID:               "R-test",
		Slug:             "test",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "P-test",
		Scopes:           scopes,
	}
}

func mustProvider(t *testing.T, configBytes []byte) *resource.BrokerProvider {
	t.Helper()
	return &resource.BrokerProvider{
		ID:         "P-test",
		Slug:       "google-workspace",
		Protocol:   resource.ProtocolOAuth,
		ConfigData: configBytes,
	}
}

// --- Name() -----------------------------------------------------------------

func TestOAuthAdapter_Name_ReturnsOauth(t *testing.T) {
	a := New(nil, nil)
	if got := a.Name(); got != "oauth" {
		t.Fatalf("Name() = %q, want oauth", got)
	}
}

// --- BuildConnectURL --------------------------------------------------------

func TestOAuthAdapter_BuildConnectURL_IncludesPKCEChallenge(t *testing.T) {
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.read"})

	authURL, pending, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/post-connect", "", []string{"calendar:read"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	if pending == nil || pending.CodeVerifier == "" {
		t.Fatalf("expected non-empty pending state with code_verifier, got %+v", pending)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("code_challenge") == "" {
		t.Errorf("authorize URL missing code_challenge: %s", authURL)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("state") != pending.ID {
		t.Errorf("state = %q, want pending.ID = %q", q.Get("state"), pending.ID)
	}
	if q.Get("client_id") != "test-client-id" {
		t.Errorf("client_id = %q, want test-client-id", q.Get("client_id"))
	}
}

func TestOAuthAdapter_BuildConnectURL_AppendsExtraAuthParams(t *testing.T) {
	// (Q4.4): provider-configured extras like Google's
	// access_type=offline must round-trip into the authorize URL.
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, map[string]string{
		"access_type": "offline",
		"prompt":      "consent",
	}, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.read"})

	authURL, _, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/post-connect", "", []string{"calendar:read"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	q := parsedQuery(t, authURL)
	if q.Get("access_type") != "offline" {
		t.Errorf("access_type = %q, want offline", q.Get("access_type"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("prompt = %q, want consent", q.Get("prompt"))
	}
}

func TestOAuthAdapter_BuildConnectURL_FiltersReservedParams(t *testing.T) {
	// Defense-in-depth: even if a reserved key reached the DB by hand-edit,
	// the adapter silently drops it from extra_auth_params so a hostile
	// configurator cannot override standard OAuth params.
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, map[string]string{
		"client_id":    "attacker-client",
		"redirect_uri": "https://evil.example.com/cb",
		"state":        "attacker-state",
	}, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.read"})

	authURL, pending, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/post-connect", "", []string{"calendar:read"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	q := parsedQuery(t, authURL)
	if q.Get("client_id") != "test-client-id" {
		t.Errorf("client_id overridden by extra_auth_params: got %q", q.Get("client_id"))
	}
	if q.Get("state") != pending.ID {
		t.Errorf("state overridden by extra_auth_params: got %q", q.Get("state"))
	}
	if q.Get("redirect_uri") != "http://127.0.0.1:9000/broker/callback/google" {
		t.Errorf("redirect_uri overridden by extra_auth_params: got %q", q.Get("redirect_uri"))
	}
}

func TestOAuthAdapter_BuildConnectURL_MapsFineToUpstreamScopes(t *testing.T) {
	// narrowing: the URL emits the upstream wire scope, not the fine
	// scope. A separate Resource ("R-google-calendar-read") sees a different
	// upstream subset than another ("R-google-calendar-write").
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{
		Name:     "calendar:read",
		Upstream: "https://www.googleapis.com/auth/calendar.readonly",
	})

	authURL, _, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/post-connect", "", []string{"calendar:read"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	q := parsedQuery(t, authURL)
	if got := q.Get("scope"); got != "https://www.googleapis.com/auth/calendar.readonly" {
		t.Errorf("scope = %q, want https://www.googleapis.com/auth/calendar.readonly", got)
	}
	if strings.Contains(q.Get("scope"), "calendar:read") {
		t.Errorf("scope leaked fine scope: %q", q.Get("scope"))
	}
}

func TestOAuthAdapter_BuildConnectURL_PassthroughScopeWithoutMapping(t *testing.T) {
	// Defensive: a Broker scope with empty Upstream passes through to the
	// upstream verbatim. (BrokerIssuer guards Mint resources from reaching
	// this adapter; this test covers the misconfigured-Broker path.)
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "openid", Upstream: ""})

	authURL, _, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/post-connect", "", []string{"openid"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	q := parsedQuery(t, authURL)
	if q.Get("scope") != "openid" {
		t.Errorf("scope = %q, want openid (passthrough)", q.Get("scope"))
	}
}

func TestOAuthAdapter_BuildConnectURL_PerCallCallbackOverridesInstanceDefault(t *testing.T) {
	// RFC 6749 §4.1.3 +  contract: ConnectService is the single source
	// of truth for redirect_uri because the path is per-provider
	// (/connect/{provider}/callback). The per-call callbackURL must take
	// precedence over the instance-level WithCallbackURL default.
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server) // instance default is /broker/callback/google
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.read"})

	want := "https://as.example.com/connect/google-workspace/callback"
	authURL, _, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/done", want, []string{"calendar:read"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	q := parsedQuery(t, authURL)
	if got := q.Get("redirect_uri"); got != want {
		t.Errorf("redirect_uri = %q, want %q (per-call must override instance default)", got, want)
	}
}

func TestOAuthAdapter_BuildConnectURL_PerCallCallbackEmpty_FallsBackToInstance(t *testing.T) {
	// Empty per-call callbackURL keeps the WithCallbackURL fallback intact —
	// useful for older callers (BrokerIssuer.Vend) that don't construct the
	// URL themselves.
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.read"})

	authURL, _, err := a.BuildConnectURL(context.Background(), prov, r,
		"user-1", "https://app.example.com/done", "", []string{"calendar:read"})
	if err != nil {
		t.Fatalf("BuildConnectURL: %v", err)
	}
	q := parsedQuery(t, authURL)
	if got := q.Get("redirect_uri"); got != "http://127.0.0.1:9000/broker/callback/google" {
		t.Errorf("redirect_uri = %q, want instance default", got)
	}
}

// --- HandleCallback ---------------------------------------------------------

func TestOAuthAdapter_HandleCallback_PersistsRefreshToken(t *testing.T) {
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token":  "atk-from-callback",
		"refresh_token": "rtk-from-callback",
		"expires_in":    3600,
		"scope":         "https://www.googleapis.com/auth/calendar.readonly",
	}))
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"})
	pending := &resource.ConnectPendingState{
		ID:           "state-abc",
		UserID:       "user-1",
		ProviderID:   prov.ID,
		ResourceID:   r.ID,
		CodeVerifier: "verifier-xyz",
	}

	credBytes, granted, err := a.HandleCallback(context.Background(), prov, r, "auth-code-123", "", pending)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	cred, err := parseCredential(credBytes)
	if err != nil {
		t.Fatalf("parseCredential: %v", err)
	}
	if cred.RefreshToken != "rtk-from-callback" {
		t.Errorf("RefreshToken = %q, want rtk-from-callback", cred.RefreshToken)
	}
	if len(granted) != 1 || granted[0] != "https://www.googleapis.com/auth/calendar.readonly" {
		t.Errorf("scopesGranted = %v, want [https://www.googleapis.com/auth/calendar.readonly]", granted)
	}

	if len(fu.tokenRequests) != 1 {
		t.Fatalf("expected 1 token request, got %d", len(fu.tokenRequests))
	}
	tr := fu.tokenRequests[0]
	if tr.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", tr.Get("grant_type"))
	}
	if tr.Get("code") != "auth-code-123" {
		t.Errorf("code = %q, want auth-code-123", tr.Get("code"))
	}
	if tr.Get("code_verifier") != "verifier-xyz" {
		t.Errorf("code_verifier = %q, want verifier-xyz", tr.Get("code_verifier"))
	}
	if tr.Get("client_id") != "test-client-id" {
		t.Errorf("client_id = %q, want test-client-id", tr.Get("client_id"))
	}
	if tr.Get("client_secret") != "test-secret" {
		t.Errorf("client_secret missing — secret resolver did not run")
	}
}

func TestOAuthAdapter_HandleCallback_PerCallCallbackSentInTokenRequest(t *testing.T) {
	// RFC 6749 §4.1.3: redirect_uri at the token endpoint MUST equal the one
	// at the authorize endpoint. ConnectService passes the same value to
	// both BuildConnectURL and HandleCallback; the adapter must forward it.
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token":  "atk",
		"refresh_token": "rtk",
		"expires_in":    3600,
		"scope":         "calendar.read",
	}))
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.read"})
	pending := &resource.ConnectPendingState{
		ID:           "state-abc",
		ProviderID:   prov.ID,
		ResourceID:   r.ID,
		CodeVerifier: "verifier-xyz",
	}
	want := "https://as.example.com/connect/google-workspace/callback"

	if _, _, err := a.HandleCallback(context.Background(), prov, r, "code", want, pending); err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if len(fu.tokenRequests) != 1 {
		t.Fatalf("expected 1 token request, got %d", len(fu.tokenRequests))
	}
	if got := fu.tokenRequests[0].Get("redirect_uri"); got != want {
		t.Errorf("token-endpoint redirect_uri = %q, want %q", got, want)
	}
}

func TestOAuthAdapter_HandleCallback_ParsesFormResponseFormat(t *testing.T) {
	// Some upstreams (e.g. GitHub's legacy /login/oauth/access_token) return
	// application/x-www-form-urlencoded instead of JSON. Adapter must parse
	// that shape when configData.ResponseFormat == "form".
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = io.WriteString(w, "access_token=gho_access&refresh_token=ghr_refresh&expires_in=7200&scope=repo+read%3Auser")
	})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "form"))
	r := mustResource(resource.Scope{Name: "repo", Upstream: "repo"})
	pending := &resource.ConnectPendingState{ID: "state-1", CodeVerifier: "verifier-1"}

	credBytes, granted, err := a.HandleCallback(context.Background(), prov, r, "code", "", pending)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	cred, _ := parseCredential(credBytes)
	if cred.RefreshToken != "ghr_refresh" {
		t.Errorf("refresh_token = %q, want ghr_refresh", cred.RefreshToken)
	}
	if len(granted) != 2 || granted[0] != "repo" || granted[1] != "read:user" {
		t.Errorf("scopesGranted = %v, want [repo read:user]", granted)
	}
}

func TestOAuthAdapter_HandleCallback_RejectsUpstreamError(t *testing.T) {
	// a 400 response with invalid_grant body is now classified as
	// ErrUpstreamInvalidGrant rather than the generic errUpstreamHTTP.
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"bad code"}`)
	})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "x"})
	pending := &resource.ConnectPendingState{ID: "state-1", CodeVerifier: "verifier-1"}

	_, _, err := a.HandleCallback(context.Background(), prov, r, "bad-code", "", pending)
	if err == nil {
		t.Fatal("expected error from 400 response, got nil")
	}
	if !errors.Is(err, output.ErrUpstreamInvalidGrant) {
		t.Errorf("error = %v, want wraps output.ErrUpstreamInvalidGrant", err)
	}
}

// --- Vend -------------------------------------------------------------------

func TestOAuthAdapter_Vend_ReturnsFreshAccessToken(t *testing.T) {
	// Refresh-token grant, no rotation. updatedCredential must be nil so
	// BrokerIssuer skips the optimistic-lock UPDATE.
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "atk-fresh",
		"expires_in":   1800,
		"scope":        "https://www.googleapis.com/auth/calendar.readonly",
	}))
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"})
	cred, _ := marshalCredential("rtk-current")

	access, expiresIn, updated, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if access != "atk-fresh" {
		t.Errorf("access token = %q, want atk-fresh", access)
	}
	if expiresIn != 1800 {
		t.Errorf("expiresIn = %d, want 1800", expiresIn)
	}
	if updated != nil {
		t.Errorf("updatedCredential = %v, want nil (no rotation)", updated)
	}

	if len(fu.tokenRequests) != 1 {
		t.Fatalf("expected 1 token request, got %d", len(fu.tokenRequests))
	}
	if got := fu.tokenRequests[0].Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", got)
	}
	if got := fu.tokenRequests[0].Get("refresh_token"); got != "rtk-current" {
		t.Errorf("refresh_token = %q, want rtk-current", got)
	}
}

func TestOAuthAdapter_Vend_PersistsRotatedRefresh(t *testing.T) {
	// Upstream rotated the refresh token. Adapter returns updatedCredential
	// non-nil with the new refresh — BrokerIssuer encrypts and persists.
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token":  "atk-fresh",
		"refresh_token": "rtk-rotated",
		"expires_in":    1800,
		"scope":         "https://www.googleapis.com/auth/calendar.readonly",
	}))
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"})
	cred, _ := marshalCredential("rtk-old")

	_, _, updated, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if updated == nil {
		t.Fatal("expected updatedCredential non-nil after rotation, got nil")
	}
	rotated, err := parseCredential(updated)
	if err != nil {
		t.Fatalf("parseCredential(updated): %v", err)
	}
	if rotated.RefreshToken != "rtk-rotated" {
		t.Errorf("rotated.RefreshToken = %q, want rtk-rotated", rotated.RefreshToken)
	}
}

func TestOAuthAdapter_Vend_NarrowsScopesPerResource(t *testing.T) {
	// an MCP that owns R-google-calendar-read sees ONLY
	// calendar.readonly upstream — never calendar.events — even if the
	// underlying broker_grant covers both.
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "atk-narrow",
		"expires_in":   1800,
		"scope":        "https://www.googleapis.com/auth/calendar.readonly",
	}))
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	rRead := mustResource(resource.Scope{
		Name:     "calendar:read",
		Upstream: "https://www.googleapis.com/auth/calendar.readonly",
	})
	cred, _ := marshalCredential("rtk-shared")

	_, _, _, err := a.Vend(context.Background(), prov, rRead, cred, []string{"calendar:read"})
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if len(fu.tokenRequests) != 1 {
		t.Fatalf("expected 1 token request, got %d", len(fu.tokenRequests))
	}
	scope := fu.tokenRequests[0].Get("scope")
	if scope != "https://www.googleapis.com/auth/calendar.readonly" {
		t.Errorf("scope = %q, want only calendar.readonly", scope)
	}
	if strings.Contains(scope, "calendar.events") {
		t.Errorf("scope leaked write access: %q", scope)
	}
}

// --- Revoke -----------------------------------------------------------------

func TestOAuthAdapter_Revoke_NoRevokeURL_ReturnsNil(t *testing.T) {
	// Upstream that doesn't support RFC 7009 (revoke_url empty) → no-op,
	// nil error. Local revocation remains authoritative.
	cfg := configData{
		ClientID:        "test-client-id",
		ClientSecretRef: "CONNECTOR_TEST_SECRET",
		AuthorizeURL:    "https://example.com/auth",
		TokenURL:        "https://example.com/token",
		RevokeURL:       "", // intentionally empty
	}
	cfgBytes, _ := json.Marshal(cfg)
	prov := &resource.BrokerProvider{ID: "P", Protocol: resource.ProtocolOAuth, ConfigData: cfgBytes}
	cred, _ := marshalCredential("rtk")

	a := New(http.DefaultClient, &stubSecretResolver{secret: "test-secret"})
	if err := a.Revoke(context.Background(), prov, cred); err != nil {
		t.Errorf("Revoke with no revoke_url: %v, want nil", err)
	}
}

func TestOAuthAdapter_Revoke_BestEffort_LogsAndContinues(t *testing.T) {
	// Upstream returns 500 → adapter swallows the error and returns nil, per
	// design doc §4.4 "Best-effort; failure does not block the local
	// revocation."
	fu := newFakeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	fu.revokeStatus = http.StatusInternalServerError
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	cred, _ := marshalCredential("rtk")

	if err := a.Revoke(context.Background(), prov, cred); err != nil {
		t.Errorf("Revoke with 500 upstream: %v, want nil (best-effort)", err)
	}
	if len(fu.revokeRequests) != 1 {
		t.Fatalf("expected revoke called once, got %d times", len(fu.revokeRequests))
	}
	if got := fu.revokeRequests[0].Get("token"); got != "rtk" {
		t.Errorf("revoke token = %q, want rtk", got)
	}
}

// --- Vend upstream error classification ----------------------------

func TestVend_UpstreamInvalidGrant(t *testing.T) {
	// Server returns 400 with RFC 6749 §5.2 invalid_grant body.
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"refresh token revoked"}`)
	})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "readonly", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("rt-x")

	_, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"readonly"})
	if !errors.Is(err, output.ErrUpstreamInvalidGrant) {
		t.Errorf("err = %v, want errors.Is(..., ErrUpstreamInvalidGrant) = true", err)
	}
}

func TestVend_UpstreamUnavailable_5xx(t *testing.T) {
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "readonly", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("rt-x")

	_, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"readonly"})
	if !errors.Is(err, output.ErrUpstreamUnavailable) {
		t.Errorf("err = %v, want errors.Is(..., ErrUpstreamUnavailable) = true", err)
	}
}

func TestVend_UpstreamScopeDowngrade(t *testing.T) {
	// Upstream returns 200 with a NON-EMPTY scope that is a strict subset of
	// what we requested — the explicitly narrower list must trigger downgrade.
	// Request was for [readonly] (→ upstream "calendar.readonly"); upstream
	// came back with "only.something.else", which does not cover it.
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"access_token":"at-x","token_type":"Bearer","expires_in":3600,"scope":"only.something.else"}`)
	})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "readonly", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("rt-x")

	_, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"readonly"})
	if !errors.Is(err, output.ErrUpstreamScopeDowngrade) {
		t.Errorf("err = %v, want errors.Is(..., ErrUpstreamScopeDowngrade) = true", err)
	}
}

func TestVend_UpstreamOmitsScope_NotDowngrade(t *testing.T) {
	// RFC 6749 §5.1: an absent (or empty) scope field means "unchanged from
	// what was requested" — the adapter must NOT classify this as downgrade.
	// Regression guard: Google and other IdPs routinely omit scope on refresh.
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"access_token":"at-x","token_type":"Bearer","expires_in":3600}`)
	})
	a := newAdapter(t, fu.server)
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "readonly", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("rt-x")

	accessToken, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"readonly"})
	if err != nil {
		t.Fatalf("Vend with omitted scope must succeed (RFC 6749 §5.1): %v", err)
	}
	if accessToken != "at-x" {
		t.Errorf("access_token = %q, want %q", accessToken, "at-x")
	}
}

// --- helpers ----------------------------------------------------------------

func parsedQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return u.Query()
}

func jsonTokenResponder(payload map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}
}
