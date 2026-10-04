//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// MockOIDCProvider is an in-process upstream OpenID Provider for the
// oidc-federated-login topology. It serves discovery, JWKS, an authorize
// endpoint that immediately redirects back with a code, and a token endpoint
// that returns a signed ID token. The AS talks to it through the production
// OIDC adapter (internal/adapters/oidc), so ID-token verification is the
// real code path, not a stub.
//
// A test sets the identity the next login asserts with SetNextIdentity and,
// to probe the verifier, bends the next ID token with SetNextTamper.
type MockOIDCProvider struct {
	Server       *httptest.Server
	Issuer       string
	ClientID     string
	ClientSecret string

	key      *ecdsa.PrivateKey
	kid      string
	rogueKey *ecdsa.PrivateKey

	mu       sync.Mutex
	next     OIDCIdentity
	tamper   OIDCTamper
	codes    map[string]oidcPendingCode
	tokenHit int
}

// OIDCIdentity is the set of claims the next ID token asserts.
type OIDCIdentity struct {
	Subject string
	Email   string // empty omits the claim
	Name    string
}

// OIDCTamper bends one aspect of the next ID token. The zero value issues a
// well-formed token.
type OIDCTamper struct {
	Issuer      string // override iss
	Audience    string // override aud
	Nonce       string // override nonce (the one bound at authorize is used otherwise)
	Expired     bool   // exp in the past
	RogueKey    bool   // sign with a key the JWKS does not publish, same kid
	OmitSubject bool
}

type oidcPendingCode struct {
	nonce    string
	identity OIDCIdentity
	tamper   OIDCTamper
}

// NewMockOIDCProvider starts the provider. clientID/clientSecret are the
// credentials the AS is configured with; the token endpoint enforces them.
func NewMockOIDCProvider(t *testing.T, clientID, clientSecret string) *MockOIDCProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("mock oidc: generate key: %v", err)
	}
	rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("mock oidc: generate rogue key: %v", err)
	}
	m := &MockOIDCProvider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		key:          key,
		rogueKey:     rogue,
		kid:          "mock-oidc-kid",
		codes:        map[string]oidcPendingCode{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.Issuer,
			"authorization_endpoint":                m.Issuer + "/authorize",
			"token_endpoint":                        m.Issuer + "/token",
			"jwks_uri":                              m.Issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"scopes_supported":                      []string{"openid", "email", "profile"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: m.kid, Algorithm: string(jose.ES256), Use: "sig",
		}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		buf := make([]byte, 12)
		_, _ = rand.Read(buf)
		code := hex.EncodeToString(buf)
		m.mu.Lock()
		m.codes[code] = oidcPendingCode{nonce: q.Get("nonce"), identity: m.next, tamper: m.tamper}
		m.tamper = OIDCTamper{}
		m.mu.Unlock()
		target, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || q.Get("redirect_uri") == "" {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		v := target.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		target.RawQuery = v.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok || id != m.ClientID || secret != m.ClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		m.mu.Lock()
		m.tokenHit++
		pending, found := m.codes[r.PostForm.Get("code")]
		delete(m.codes, r.PostForm.Get("code"))
		m.mu.Unlock()
		if !found {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		idToken, err := m.sign(pending)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-at-" + pending.identity.Subject,
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     idToken,
		})
	})

	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Server.Close)
	m.Issuer = m.Server.URL
	return m
}

// SetNextIdentity sets the identity the next /authorize round asserts.
func (m *MockOIDCProvider) SetNextIdentity(id OIDCIdentity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next = id
}

// SetNextTamper bends the ID token minted for the next /authorize round only.
func (m *MockOIDCProvider) SetNextTamper(tp OIDCTamper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tamper = tp
}

// TokenRequests counts the token-endpoint calls the AS made.
func (m *MockOIDCProvider) TokenRequests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokenHit
}

func (m *MockOIDCProvider) sign(p oidcPendingCode) (string, error) {
	signKey := m.key
	if p.tamper.RogueKey {
		signKey = m.rogueKey
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: signKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), m.kid),
	)
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{
		"iss":   m.Issuer,
		"sub":   p.identity.Subject,
		"aud":   m.ClientID,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": p.nonce,
	}
	if p.identity.Email != "" {
		claims["email"] = p.identity.Email
	}
	if p.identity.Name != "" {
		claims["name"] = p.identity.Name
	}
	if p.tamper.Issuer != "" {
		claims["iss"] = p.tamper.Issuer
	}
	if p.tamper.Audience != "" {
		claims["aud"] = p.tamper.Audience
	}
	if p.tamper.Nonce != "" {
		claims["nonce"] = p.tamper.Nonce
	}
	if p.tamper.Expired {
		claims["iat"] = now.Add(-time.Hour).Unix()
		claims["exp"] = now.Add(-30 * time.Minute).Unix()
	}
	if p.tamper.OmitSubject {
		delete(claims, "sub")
	}
	return josejwt.Signed(signer).Claims(claims).Serialize()
}
