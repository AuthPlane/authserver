package serviceaccount

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TestJWT_SignAndVerifyRoundtrip confirms the package's signing helper
// produces an assertion that round-trips through jose verification on both
// supported algorithms. Acts as a self-test on the jose configuration —
// any drift in algorithm/key wiring fails here before any adapter test
// runs against an httptest fake.
func TestJWT_SignAndVerifyRoundtrip(t *testing.T) {
	t.Run("RS256_PKCS8", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa: %v", err)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

		parsed, err := parsePrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("parse PKCS#8 RSA: %v", err)
		}
		if _, ok := parsed.(*rsa.PrivateKey); !ok {
			t.Fatalf("parsed key type = %T, want *rsa.PrivateKey", parsed)
		}
		assertRoundtrip(t, algorithmRS256, parsed, &priv.PublicKey, jose.RS256)
	})

	t.Run("RS256_PKCS1", func(t *testing.T) {
		// openssl genrsa style — `-----BEGIN RSA PRIVATE KEY-----`
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa: %v", err)
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

		parsed, err := parsePrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("parse PKCS#1 RSA: %v", err)
		}
		if _, ok := parsed.(*rsa.PrivateKey); !ok {
			t.Fatalf("parsed key type = %T, want *rsa.PrivateKey", parsed)
		}
		assertRoundtrip(t, algorithmRS256, parsed, &priv.PublicKey, jose.RS256)
	})

	t.Run("ES256_PKCS8", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

		parsed, err := parsePrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("parse PKCS#8 EC: %v", err)
		}
		if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("parsed key type = %T, want *ecdsa.PrivateKey", parsed)
		}
		assertRoundtrip(t, algorithmES256, parsed, &priv.PublicKey, jose.ES256)
	})

	t.Run("ES256_SEC1", func(t *testing.T) {
		// openssl ecparam style — `-----BEGIN EC PRIVATE KEY-----`
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal SEC1: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

		parsed, err := parsePrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("parse SEC1 EC: %v", err)
		}
		if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("parsed key type = %T, want *ecdsa.PrivateKey", parsed)
		}
		assertRoundtrip(t, algorithmES256, parsed, &priv.PublicKey, jose.ES256)
	})

	t.Run("rejects_invalid_PEM", func(t *testing.T) {
		_, err := parsePrivateKey([]byte("not a pem block"))
		if !errors.Is(err, errInvalidPEM) {
			t.Errorf("err = %v, want wraps errInvalidPEM", err)
		}
	})

	t.Run("algorithm_key_mismatch", func(t *testing.T) {
		// RS256 configured but EC key supplied → readable error.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		_, err = signAssertion(algorithmRS256, priv, assertionClaims{Issuer: "x"})
		if !errors.Is(err, errAlgorithmKeyMismatch) {
			t.Errorf("err = %v, want wraps errAlgorithmKeyMismatch", err)
		}
	})
}

func assertRoundtrip(t *testing.T, alg string, key interface{}, pub interface{}, sigAlg jose.SignatureAlgorithm) {
	t.Helper()
	claims := assertionClaims{
		Issuer:   "sa@svc.example.iam",
		Subject:  "alice@example.com",
		Audience: "https://oauth2.example.com/token",
		IssuedAt: 1000,
		Expiry:   1000 + 3600,
		Scope:    "https://www.googleapis.com/auth/calendar.readonly",
	}
	raw, err := signAssertion(alg, key, claims)
	if err != nil {
		t.Fatalf("signAssertion: %v", err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{sigAlg})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	var got assertionClaims
	if err := parsed.Claims(pub, &got); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != claims {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", got, claims)
	}
}
