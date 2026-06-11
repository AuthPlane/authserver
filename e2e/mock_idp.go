//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
)

// MockIdP is a mock Identity Provider for E2E tests.
// It serves OIDC discovery metadata and JWKS, and can sign ID-JAG assertions.
type MockIdP struct {
	Server *httptest.Server
	Issuer string // Server URL

	privKey *ecdsa.PrivateKey
	signer  jose.Signer
	kid     string
}

// NewMockIdP creates a mock IdP HTTP server that serves OIDC discovery and JWKS.
func NewMockIdP(t *testing.T) *MockIdP {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate mock IdP key: %v", err)
	}

	kid := crypto.GenerateRandomString(8)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privKey},
		(&jose.SignerOptions{}).WithType("oauth-id-jag+jwt").WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		t.Fatalf("create mock IdP signer: %v", err)
	}

	m := &MockIdP{
		privKey: privKey,
		signer:  signer,
		kid:     kid,
	}

	mux := http.NewServeMux()

	// OIDC Discovery endpoint.
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   m.Issuer,
			"jwks_uri": m.Issuer + "/.well-known/jwks.json",
		})
	})

	// JWKS endpoint.
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pubKey := jose.JSONWebKey{
			Key:       &privKey.PublicKey,
			KeyID:     kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubKey}})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m.Server = srv
	m.Issuer = srv.URL

	return m
}

// IDJAGClaims holds the claims for an ID-JAG assertion.
type IDJAGClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	ClientID string `json:"client_id"`
	JTI      string `json:"jti"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Scope    string `json:"scope,omitempty"`
	Resource string `json:"resource,omitempty"`
}

// SignIDJAG creates a signed ID-JAG assertion JWT.
func (m *MockIdP) SignIDJAG(t *testing.T, audience, clientID, subject, scope string) string {
	t.Helper()

	now := time.Now().UTC()
	claims := IDJAGClaims{
		Issuer:   m.Issuer,
		Subject:  subject,
		Audience: audience,
		ClientID: clientID,
		JTI:      crypto.GenerateRandomString(16),
		Expiry:   now.Add(5 * time.Minute).Unix(),
		IssuedAt: now.Unix(),
		Scope:    scope,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal ID-JAG claims: %v", err)
	}

	signed, err := m.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign ID-JAG: %v", err)
	}

	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize ID-JAG: %v", err)
	}

	return compact
}

// SignIDJAGWithResource creates a signed ID-JAG with a resource claim.
func (m *MockIdP) SignIDJAGWithResource(t *testing.T, audience, clientID, subject, scope, resource string) string {
	t.Helper()

	now := time.Now().UTC()
	claims := IDJAGClaims{
		Issuer:   m.Issuer,
		Subject:  subject,
		Audience: audience,
		ClientID: clientID,
		JTI:      crypto.GenerateRandomString(16),
		Expiry:   now.Add(5 * time.Minute).Unix(),
		IssuedAt: now.Unix(),
		Scope:    scope,
		Resource: resource,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal ID-JAG claims: %v", err)
	}

	signed, err := m.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign ID-JAG: %v", err)
	}

	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize ID-JAG: %v", err)
	}

	return compact
}
