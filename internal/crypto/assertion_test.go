package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/token"
)

const testAudience = "https://authplane.example.com"

func testKeyAndJWKS(t *testing.T) (*ecdsa.PrivateKey, *jose.JSONWebKeySet) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &key.PublicKey,
				KeyID:     "test-kid",
				Algorithm: "ES256",
				Use:       "sig",
			},
		},
	}
	return key, jwks
}

func signIDJAG(t *testing.T, key *ecdsa.PrivateKey, claims token.IdentityAssertion, typ string) string {
	t.Helper()
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}
	opts := &jose.SignerOptions{}
	opts.WithType(jose.ContentType(typ))
	opts.WithHeader(jose.HeaderKey("kid"), "test-kid")

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

func validClaims() token.IdentityAssertion {
	now := time.Now().Unix()
	return token.IdentityAssertion{
		Issuer:   "https://acme.okta.com",
		Subject:  "user@acme.com",
		Audience: testAudience,
		ClientID: "mcp-client-1",
		JTI:      "unique-jti-123",
		Expiry:   now + 300,
		IssuedAt: now,
		Scope:    "read write",
	}
}

func TestValidateIDJAG_Valid(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")

	result, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Issuer != claims.Issuer {
		t.Errorf("issuer = %q, want %q", result.Issuer, claims.Issuer)
	}
	if result.Subject != claims.Subject {
		t.Errorf("subject = %q, want %q", result.Subject, claims.Subject)
	}
	if result.ClientID != claims.ClientID {
		t.Errorf("client_id = %q, want %q", result.ClientID, claims.ClientID)
	}
	if result.JTI != claims.JTI {
		t.Errorf("jti = %q, want %q", result.JTI, claims.JTI)
	}
	if result.Scope != claims.Scope {
		t.Errorf("scope = %q, want %q", result.Scope, claims.Scope)
	}
}

func TestValidateIDJAG_ValidWithResource(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	claims.Resource = "https://mcp-server.example.com"
	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")

	result, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Resource != "https://mcp-server.example.com" {
		t.Errorf("resource = %q", result.Resource)
	}
}

func TestValidateIDJAG_EmptyAssertion(t *testing.T) {
	_, jwks := testKeyAndJWKS(t)
	_, err := ValidateIDJAG("", jwks, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for empty assertion")
	}
	assertDomainError(t, err, domain.ErrAssertionInvalid)
}

func TestValidateIDJAG_WrongTyp_Rejected(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	raw := signIDJAG(t, key, claims, "at+jwt") // wrong type

	_, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
	assertDomainError(t, err, domain.ErrAssertionTypeMismatch)
}

func TestValidateIDJAG_Expired_Rejected(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	claims.Expiry = time.Now().Unix() - 120 // expired 2 minutes ago

	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")
	_, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for expired assertion")
	}
	assertDomainError(t, err, domain.ErrAssertionExpired)
}

func TestValidateIDJAG_WrongAudience_Rejected(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	claims.Audience = "https://wrong-audience.example.com"

	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")
	_, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	assertDomainError(t, err, domain.ErrAssertionAudienceMismatch)
}

func TestValidateIDJAG_MissingClaims_Rejected(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)

	tests := []struct {
		name   string
		mutate func(*token.IdentityAssertion)
	}{
		{"missing_iss", func(c *token.IdentityAssertion) { c.Issuer = "" }},
		{"missing_sub", func(c *token.IdentityAssertion) { c.Subject = "" }},
		{"missing_client_id", func(c *token.IdentityAssertion) { c.ClientID = "" }},
		{"missing_jti", func(c *token.IdentityAssertion) { c.JTI = "" }},
		{"missing_aud", func(c *token.IdentityAssertion) { c.Audience = "" }},
		{"missing_exp", func(c *token.IdentityAssertion) { c.Expiry = 0 }},
		{"missing_iat", func(c *token.IdentityAssertion) { c.IssuedAt = 0 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			tc.mutate(&claims)
			raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")
			_, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestValidateIDJAG_IatTooOld_Rejected(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	claims.IssuedAt = time.Now().Unix() - 600 // 10 minutes ago
	claims.Expiry = time.Now().Unix() + 300   // still valid expiry

	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")
	_, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute) // max age 5 min
	if err == nil {
		t.Fatal("expected error for too-old iat")
	}
	assertDomainError(t, err, domain.ErrAssertionExpired)
}

func TestValidateIDJAG_IatInFuture_Rejected(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	claims.IssuedAt = time.Now().Unix() + 120 // 2 minutes in the future
	claims.Expiry = time.Now().Unix() + 600

	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")
	_, err := ValidateIDJAG(raw, jwks, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for future iat")
	}
	assertDomainError(t, err, domain.ErrAssertionInvalid)
}

func TestValidateIDJAG_WrongKey_Rejected(t *testing.T) {
	key, _ := testKeyAndJWKS(t)
	_, differentJWKS := testKeyAndJWKS(t) // different key

	claims := validClaims()
	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")

	_, err := ValidateIDJAG(raw, differentJWKS, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for wrong signing key")
	}
	assertDomainError(t, err, domain.ErrAssertionInvalid)
}

func TestValidateIDJAG_GarbageJWT_Rejected(t *testing.T) {
	_, jwks := testKeyAndJWKS(t)
	_, err := ValidateIDJAG("not.a.jwt", jwks, testAudience, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for garbage JWT")
	}
	assertDomainError(t, err, domain.ErrAssertionInvalid)
}

func TestValidateIDJAG_NoMaxAge(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	claims := validClaims()
	claims.IssuedAt = time.Now().Unix() - 600 // 10 minutes ago but still valid expiry
	claims.Expiry = time.Now().Unix() + 300

	raw := signIDJAG(t, key, claims, "oauth-id-jag+jwt")
	_, err := ValidateIDJAG(raw, jwks, testAudience, 0) // no max age
	if err != nil {
		t.Fatalf("expected no error with maxAge=0, got: %v", err)
	}
}

func assertDomainError(t *testing.T, got error, want error) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected error wrapping %v, got nil", want)
	}
	// Use errors.Is for the chain check.
	if !isDomainErr(got, want) {
		t.Errorf("error = %v, want to wrap %v", got, want)
	}
}

func isDomainErr(got, want error) bool {
	for got != nil {
		if got == want {
			return true
		}
		type wrapper interface {
			Unwrap() error
		}
		w, ok := got.(wrapper)
		if !ok {
			return false
		}
		got = w.Unwrap()
	}
	return false
}
