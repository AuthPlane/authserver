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

// IDJAGOptions varies every part of an ID-JAG assertion that a conformance
// probe needs to bend: the header type, each claim, the signing key id, and
// which claims are present at all.
//
// SignIDJAG and SignIDJAGWithResource cover the well-formed cases and build
// their assertions with the IdP's fixed signer. This builds a signer per call,
// which is what lets Typ vary — the header type is baked into a go-jose signer
// at construction, so a wrong-typ assertion cannot be produced any other way.
type IDJAGOptions struct {
	// Typ is the JWT header type. Empty means oauth-id-jag+jwt, the value the
	// Enterprise-Managed Authorization extension shows in its worked example.
	Typ string
	// Issuer defaults to the mock IdP's own issuer. Set it to something else to
	// present an assertion from an IdP the authorization server does not trust.
	Issuer   string
	Subject  string
	Audience string
	ClientID string
	Scope    string
	Resource string
	// JTI defaults to a fresh random value. Set it to replay one.
	JTI string
	// IssuedAt and Expiry default to now and now+5m.
	IssuedAt time.Time
	Expiry   time.Time
	// OmitClaims removes claims by JSON name after marshalling, so a probe can
	// present an assertion missing exactly one required claim.
	OmitClaims []string
	// KeyID defaults to the IdP's own kid. Set it to an unknown value to make
	// key resolution fail at the authorization server.
	KeyID string
}

// SignIDJAGCustom signs an ID-JAG assertion built from opts.
func (m *MockIdP) SignIDJAGCustom(t *testing.T, opts IDJAGOptions) string {
	t.Helper()

	typ := opts.Typ
	if typ == "" {
		typ = "oauth-id-jag+jwt"
	}
	kid := opts.KeyID
	if kid == "" {
		kid = m.kid
	}
	issuer := opts.Issuer
	if issuer == "" {
		issuer = m.Issuer
	}
	jti := opts.JTI
	if jti == "" {
		jti = crypto.GenerateRandomString(16)
	}
	now := time.Now().UTC()
	issuedAt := opts.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = now
	}
	expiry := opts.Expiry
	if expiry.IsZero() {
		expiry = now.Add(5 * time.Minute)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: m.privKey},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		t.Fatalf("create ID-JAG signer (typ=%q): %v", typ, err)
	}

	payload, err := json.Marshal(IDJAGClaims{
		Issuer:   issuer,
		Subject:  opts.Subject,
		Audience: opts.Audience,
		ClientID: opts.ClientID,
		JTI:      jti,
		Expiry:   expiry.Unix(),
		IssuedAt: issuedAt.Unix(),
		Scope:    opts.Scope,
		Resource: opts.Resource,
	})
	if err != nil {
		t.Fatalf("marshal ID-JAG claims: %v", err)
	}

	if len(opts.OmitClaims) > 0 {
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("unmarshal ID-JAG claims for omission: %v", err)
		}
		for _, name := range opts.OmitClaims {
			delete(claims, name)
		}
		if payload, err = json.Marshal(claims); err != nil {
			t.Fatalf("re-marshal ID-JAG claims: %v", err)
		}
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign ID-JAG: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize ID-JAG: %v", err)
	}
	return compact
}
