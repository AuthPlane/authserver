package serviceaccount

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// errInvalidPEM is returned when the SA private key bytes resolved from the
// configured env var cannot be decoded as PEM. Surfaced as a sentinel so
// wiring code can distinguish missing-key-config from upstream failures.
var errInvalidPEM = errors.New("service_account private key: PEM decode failed")

// errAlgorithmKeyMismatch is returned when the configured Algorithm does not
// match the parsed private key type (e.g. cfg.Algorithm == "ES256" but the
// PEM holds an RSA key). Surfaced explicitly so misconfiguration produces a
// readable error rather than a downstream jose verification failure.
var errAlgorithmKeyMismatch = errors.New("service_account: configured algorithm does not match private key type")

// assertionClaims is the body of the outbound RFC 7521 §4.2 / RFC 7523 §2.1
// JWT bearer assertion. The wire-format scope claim is space-separated per
// RFC 6749 §3.3. JTI carries a per-Vend unique identifier so upstreams that
// implement RFC 7519 §4.1.7 replay defense (or similar) can dedupe — without
// jti an intercepted assertion is replayable for the entire iat→exp window.
type assertionClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	JTI      string `json:"jti"`
	Scope    string `json:"scope,omitempty"`
}

// parsePrivateKey decodes PEM bytes into an RSA or ECDSA private key,
// trying each x509 parser in turn. The order is PKCS#8 → PKCS#1 (RSA)
// → SEC1 (EC) so that:
//
//   - Google Workspace SA keys (PKCS#8 RSA) parse on the first attempt
//   - openssl-generated RSA keys with `-----BEGIN RSA PRIVATE KEY-----`
//     fall through to PKCS#1
//   - openssl-generated EC keys with `-----BEGIN EC PRIVATE KEY-----`
//     fall through to SEC1
//
// Returns either a *rsa.PrivateKey or *ecdsa.PrivateKey. Any other key
// material (Ed25519, DSA) is rejected — the configured algorithm
// (RS256 or ES256) cannot consume it.
func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errInvalidPEM
	}
	der := block.Bytes

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch typed := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return typed, nil
		default:
			return nil, fmt.Errorf("service_account private key: unsupported PKCS#8 type %T", key)
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("service_account private key: not PKCS#8, PKCS#1, or SEC1")
}

// signAssertion signs the given claims with the configured algorithm using
// jose v4. The "kid" header is intentionally omitted: upstream token
// endpoints (Google, Atlassian) identify the SA by the iss claim plus the
// public key registered alongside the SA, not by a JWS kid lookup.
func signAssertion(alg string, key crypto.PrivateKey, claims assertionClaims) (string, error) {
	var sigAlg jose.SignatureAlgorithm
	switch alg {
	case algorithmRS256:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return "", fmt.Errorf("%w: RS256 requires *rsa.PrivateKey, got %T", errAlgorithmKeyMismatch, key)
		}
		sigAlg = jose.RS256
	case algorithmES256:
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return "", fmt.Errorf("%w: ES256 requires *ecdsa.PrivateKey, got %T", errAlgorithmKeyMismatch, key)
		}
		sigAlg = jose.ES256
	default:
		return "", fmt.Errorf("service_account: unsupported algorithm %q", alg)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: sigAlg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("service_account: build signer: %w", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("service_account: sign assertion: %w", err)
	}
	return raw, nil
}
