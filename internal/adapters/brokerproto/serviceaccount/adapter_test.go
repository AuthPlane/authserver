package serviceaccount

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// stubSecretResolver returns a fixed PEM string for any reference. The
// adapter treats the reference as opaque and no longer validates its shape,
// so tests may use any string; allowlist enforcement now lives in the env
// resolver (see cmd/authserver).
type stubSecretResolver struct {
	pem string
	err error
}

func (s *stubSecretResolver) Resolve(_ context.Context, _ output.SecretSource) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.pem, nil
}

// rsaKeyPair returns an RSA-2048 private key paired with its PKCS#8 PEM
// encoding. PKCS#8 is the format Google Workspace SA keys ship in.
func rsaKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return priv, string(pemBytes)
}

// ecKeyPair returns a P-256 ECDSA private key paired with its PKCS#8 PEM
// encoding. P-256 is what ES256 expects.
func ecKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return priv, string(pemBytes)
}

// fakeUpstream wires an httptest.Server that implements /token. Tests pass
// a tokenHandler to control the response per scenario; the rig captures
// every form submission so assertions about grant_type and assertion
// claims can run after the call.
type fakeUpstream struct {
	server         *httptest.Server
	tokenRequests  []url.Values
	tokenHandler   http.HandlerFunc
	lastAssertion  string
	tokenURL       string
	capturedHeader http.Header
}

func newFakeUpstream(t *testing.T, tokenHandler http.HandlerFunc) *fakeUpstream {
	t.Helper()
	fu := &fakeUpstream{tokenHandler: tokenHandler}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fu.tokenRequests = append(fu.tokenRequests, r.PostForm)
		fu.lastAssertion = r.PostForm.Get("assertion")
		fu.capturedHeader = r.Header.Clone()
		fu.tokenHandler(w, r)
	})
	fu.server = httptest.NewServer(mux)
	t.Cleanup(fu.server.Close)
	fu.tokenURL = fu.server.URL + "/token"
	return fu
}

func (fu *fakeUpstream) configBytes(t *testing.T, alg string, ttlSeconds int) []byte {
	t.Helper()
	cfg := configData{
		TokenURL:        fu.tokenURL,
		SAEmail:         "sa@svc.example.iam",
		SAKeyRef:        "CONNECTOR_TEST_SA_KEY",
		Algorithm:       alg,
		TokenTTLSeconds: ttlSeconds,
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal configData: %v", err)
	}
	return b
}

func newAdapter(t *testing.T, ts *httptest.Server, keyPEM string) *Adapter {
	t.Helper()
	return New(
		ts.Client(),
		&stubSecretResolver{pem: keyPEM},
		WithAllowLoopback(true),
	)
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
		Slug:       "google-workspace-sa",
		Protocol:   resource.ProtocolServiceAccount,
		ConfigData: configBytes,
	}
}

func jsonTokenResponder(payload map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}
}

// --- Name() -----------------------------------------------------------------

func TestServiceAccountAdapter_Name_ReturnsServiceAccount(t *testing.T) {
	a := New(nil, nil)
	if got := a.Name(); got != "service_account" {
		t.Fatalf("Name() = %q, want service_account", got)
	}
}

// --- BuildConnectURL / HandleCallback ---------------------------------------

func TestServiceAccountAdapter_BuildConnectURL_ReturnsErrNoConnectStep(t *testing.T) {
	// service_account has no per-user upstream consent flow. The
	// orchestration layer compares with errors.Is and skips the
	// OAuth redirect dance.
	a := New(nil, nil)
	authURL, pending, err := a.BuildConnectURL(context.Background(),
		&resource.BrokerProvider{}, &resource.Resource{},
		"user-1", "https://app.example.com/post-connect", "https://as.example.com/connect/sa/callback", []string{"any"})
	if !errors.Is(err, output.ErrNoConnectStep) {
		t.Fatalf("err = %v, want output.ErrNoConnectStep", err)
	}
	if authURL != "" {
		t.Errorf("authURL = %q, want empty when no connect step", authURL)
	}
	if pending != nil {
		t.Errorf("pending = %+v, want nil when no connect step", pending)
	}
}

func TestServiceAccountAdapter_HandleCallback_ReturnsErrNoConnectStep(t *testing.T) {
	a := New(nil, nil)
	credBytes, granted, err := a.HandleCallback(context.Background(),
		&resource.BrokerProvider{}, &resource.Resource{},
		"unused-code", "https://as.example.com/connect/sa/callback", &resource.ConnectPendingState{ID: "unused"})
	if !errors.Is(err, output.ErrNoConnectStep) {
		t.Fatalf("err = %v, want output.ErrNoConnectStep", err)
	}
	if credBytes != nil {
		t.Errorf("credBytes = %v, want nil when no connect step", credBytes)
	}
	if granted != nil {
		t.Errorf("scopesGranted = %v, want nil when no connect step", granted)
	}
}

// --- Vend -------------------------------------------------------------------

func TestServiceAccountAdapter_Vend_SignsAssertionWithRS256(t *testing.T) {
	priv, keyPEM := rsaKeyPair(t)
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "atk-rs256",
		"expires_in":   1800,
	}))
	a := newAdapter(t, fu.server, keyPEM)
	prov := mustProvider(t, fu.configBytes(t, "RS256", 0))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"})
	cred, _ := marshalCredential("alice@example.com")

	access, expiresIn, updated, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if access != "atk-rs256" {
		t.Errorf("access token = %q, want atk-rs256", access)
	}
	if expiresIn != 1800 {
		t.Errorf("expiresIn = %d, want 1800", expiresIn)
	}
	if updated != nil {
		t.Errorf("updatedCredential = %v, want nil (SA never rotates)", updated)
	}
	if fu.lastAssertion == "" {
		t.Fatal("upstream never received an assertion")
	}

	// Verify the assertion against the SA public key.
	parsed, err := jwt.ParseSigned(fu.lastAssertion, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims assertionClaims
	if err := parsed.Claims(&priv.PublicKey, &claims); err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
}

func TestServiceAccountAdapter_Vend_SignsAssertionWithES256(t *testing.T) {
	priv, keyPEM := ecKeyPair(t)
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "atk-es256",
		"expires_in":   900,
	}))
	a := newAdapter(t, fu.server, keyPEM)
	prov := mustProvider(t, fu.configBytes(t, "ES256", 0))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("bob@example.com")

	access, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if access != "atk-es256" {
		t.Errorf("access token = %q, want atk-es256", access)
	}
	if fu.lastAssertion == "" {
		t.Fatal("upstream never received an assertion")
	}

	parsed, err := jwt.ParseSigned(fu.lastAssertion, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse ES256 assertion: %v", err)
	}
	var claims assertionClaims
	if err := parsed.Claims(&priv.PublicKey, &claims); err != nil {
		t.Fatalf("verify ES256 assertion: %v", err)
	}
}

func TestServiceAccountAdapter_Vend_AssertionClaims_IssSubAud(t *testing.T) {
	priv, keyPEM := rsaKeyPair(t)
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{"access_token": "atk", "expires_in": 60}))
	a := newAdapter(t, fu.server, keyPEM)
	prov := mustProvider(t, fu.configBytes(t, "RS256", 600))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("alice@example.com")

	if _, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"}); err != nil {
		t.Fatalf("Vend: %v", err)
	}

	claims := decodeAssertionClaims(t, fu.lastAssertion, &priv.PublicKey, jose.RS256)
	if claims.Issuer != "sa@svc.example.iam" {
		t.Errorf("iss = %q, want sa@svc.example.iam (cfg.SAEmail)", claims.Issuer)
	}
	if claims.Subject != "alice@example.com" {
		t.Errorf("sub = %q, want alice@example.com (cred.ImpersonateSub)", claims.Subject)
	}
	if claims.Audience != fu.tokenURL {
		t.Errorf("aud = %q, want %q (cfg.TokenURL)", claims.Audience, fu.tokenURL)
	}
	if claims.JTI == "" {
		t.Error("jti is empty — RFC 7519 §4.1.7 replay defense requires non-empty jti")
	}

	if got := fu.tokenRequests[0].Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q, want urn:ietf:params:oauth:grant-type:jwt-bearer", got)
	}
	if got := fu.capturedHeader.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
	}
}

func TestServiceAccountAdapter_Vend_AssertionJTI_UniquePerVend(t *testing.T) {
	// Per RFC 7519 §4.1.7, the same jti MUST NOT be assigned to two different
	// JWTs. An assertion without jti — or with a constant jti — is replayable
	// against the upstream token endpoint for the entire iat→exp window.
	priv, keyPEM := rsaKeyPair(t)
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{"access_token": "atk", "expires_in": 60}))
	a := newAdapter(t, fu.server, keyPEM)
	prov := mustProvider(t, fu.configBytes(t, "RS256", 600))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("alice@example.com")

	if _, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"}); err != nil {
		t.Fatalf("first Vend: %v", err)
	}
	first := decodeAssertionClaims(t, fu.lastAssertion, &priv.PublicKey, jose.RS256)

	if _, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"}); err != nil {
		t.Fatalf("second Vend: %v", err)
	}
	second := decodeAssertionClaims(t, fu.lastAssertion, &priv.PublicKey, jose.RS256)

	if first.JTI == "" || second.JTI == "" {
		t.Fatalf("jti must be non-empty: first=%q second=%q", first.JTI, second.JTI)
	}
	if first.JTI == second.JTI {
		t.Errorf("jti collided across two consecutive Vends: %q (replay defense broken)", first.JTI)
	}
	// Sanity: 32-byte URL-safe base64 = 43 chars without padding.
	if len(first.JTI) < 22 {
		t.Errorf("jti length %d looks low-entropy (want >= 22 chars URL-safe base64)", len(first.JTI))
	}
}

func TestServiceAccountAdapter_Vend_AssertionExpiry_RespectsTTL(t *testing.T) {
	priv, keyPEM := rsaKeyPair(t)
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{"access_token": "atk", "expires_in": 60}))
	a := newAdapter(t, fu.server, keyPEM)
	const ttl = 600
	prov := mustProvider(t, fu.configBytes(t, "RS256", ttl))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("alice@example.com")

	if _, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"}); err != nil {
		t.Fatalf("Vend: %v", err)
	}

	claims := decodeAssertionClaims(t, fu.lastAssertion, &priv.PublicKey, jose.RS256)
	if got := claims.Expiry - claims.IssuedAt; got != int64(ttl) {
		t.Errorf("exp - iat = %d, want %d (cfg.TokenTTLSeconds)", got, ttl)
	}
}

func TestServiceAccountAdapter_Vend_NarrowsScopesPerResource(t *testing.T) {
	// the scope claim in the assertion is the upstream-format
	// narrowed list. A Resource scoped to calendar.readonly never produces
	// an assertion with calendar.events.
	priv, keyPEM := rsaKeyPair(t)
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{"access_token": "atk", "expires_in": 60}))
	a := newAdapter(t, fu.server, keyPEM)
	prov := mustProvider(t, fu.configBytes(t, "RS256", 0))
	rRead := mustResource(resource.Scope{
		Name:     "calendar:read",
		Upstream: "https://www.googleapis.com/auth/calendar.readonly",
	})
	cred, _ := marshalCredential("carol@example.com")

	if _, _, _, err := a.Vend(context.Background(), prov, rRead, cred, []string{"calendar:read"}); err != nil {
		t.Fatalf("Vend: %v", err)
	}

	claims := decodeAssertionClaims(t, fu.lastAssertion, &priv.PublicKey, jose.RS256)
	if claims.Scope != "https://www.googleapis.com/auth/calendar.readonly" {
		t.Errorf("scope = %q, want only calendar.readonly", claims.Scope)
	}
	if strings.Contains(claims.Scope, "calendar.events") {
		t.Errorf("scope leaked write access: %q", claims.Scope)
	}
	if strings.Contains(claims.Scope, "calendar:read") {
		t.Errorf("scope leaked fine scope: %q", claims.Scope)
	}
}

func TestServiceAccountAdapter_Vend_UpstreamReturns400_WrappedError(t *testing.T) {
	_, keyPEM := rsaKeyPair(t)
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"bad assertion"}`)
	})
	a := newAdapter(t, fu.server, keyPEM)
	prov := mustProvider(t, fu.configBytes(t, "RS256", 0))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "calendar.readonly"})
	cred, _ := marshalCredential("dave@example.com")

	_, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err == nil {
		t.Fatal("expected error from 400 response, got nil")
	}
	if !errors.Is(err, errUpstreamHTTP) {
		t.Errorf("error = %v, want wraps errUpstreamHTTP", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %v, want to contain status code", err)
	}
}

// --- Revoke -----------------------------------------------------------------

func TestServiceAccountAdapter_Revoke_NoOpReturnsNil(t *testing.T) {
	// Service-account upstreams hand out short-lived tokens that expire
	// naturally; the AS holds no per-user credential to revoke. Revoke
	// must return nil so BrokerIssuer treats the local revocation
	// (broker_grants.revoked_at) as authoritative.
	a := New(nil, nil)
	prov := &resource.BrokerProvider{ID: "P", Protocol: resource.ProtocolServiceAccount}
	cred, _ := marshalCredential("eve@example.com")

	if err := a.Revoke(context.Background(), prov, cred); err != nil {
		t.Errorf("Revoke = %v, want nil (no-op)", err)
	}
}

// --- helpers ----------------------------------------------------------------

// decodeAssertionClaims parses and verifies the given JWT assertion against
// the public key, returning the typed claims for assertion-shape tests.
func decodeAssertionClaims(t *testing.T, assertion string, pub interface{}, alg jose.SignatureAlgorithm) assertionClaims {
	t.Helper()
	parsed, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims assertionClaims
	if err := parsed.Claims(pub, &claims); err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	return claims
}
