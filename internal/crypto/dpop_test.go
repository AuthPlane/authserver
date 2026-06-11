package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/domain"
)

const (
	testHTM = "POST"
	testHTU = "https://auth.example.com/oauth/token"
)

// testProofLifetime is the default proof lifetime for tests.
var testProofLifetime = 60 * time.Second

// mustGenerateES256Key generates an ES256 key pair for testing.
func mustGenerateES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ES256 key: %v", err)
	}
	return key
}

// mustGenerateRS256Key generates an RS256 key pair for testing.
func mustGenerateRS256Key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RS256 key: %v", err)
	}
	return key
}

// mustCreateProof creates a DPoP proof with sensible defaults.
func mustCreateProof(t *testing.T, signer jose.Signer, jti, htm, htu string, iat time.Time, nonce, ath string) string {
	t.Helper()
	proof, err := CreateDPoPProof(signer, jti, htm, htu, iat, nonce, ath)
	if err != nil {
		t.Fatalf("create DPoP proof: %v", err)
	}
	return proof
}

// mustNewSigner creates a DPoP signer for the given key and algorithm.
func mustNewSigner(t *testing.T, privateKey interface{}, alg jose.SignatureAlgorithm) jose.Signer {
	t.Helper()
	signer, err := NewDPoPSigner(privateKey, alg)
	if err != nil {
		t.Fatalf("create DPoP signer: %v", err)
	}
	return signer
}

func TestValidateProof_ValidES256(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	proof := mustCreateProof(t, signer, "unique-jti-1", testHTM, testHTU, time.Now(), "", "")

	result, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JKT == "" {
		t.Error("expected non-empty JKT")
	}
	if result.JTI != "unique-jti-1" {
		t.Errorf("expected JTI unique-jti-1, got %s", result.JTI)
	}
}

func TestValidateProof_ValidRS256(t *testing.T) {
	key := mustGenerateRS256Key(t)
	signer := mustNewSigner(t, key, jose.RS256)
	proof := mustCreateProof(t, signer, "unique-jti-rs", testHTM, testHTU, time.Now(), "", "")

	result, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JKT == "" {
		t.Error("expected non-empty JKT")
	}
}

func TestValidateProof_WrongHTM(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	proof := mustCreateProof(t, signer, "jti-htm", "GET", testHTU, time.Now(), "", "")

	_, err := ValidateProof(proof, "POST", testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof, got %v", err)
	}
}

func TestValidateProof_WrongHTU(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	proof := mustCreateProof(t, signer, "jti-htu", testHTM, "https://other.example.com/oauth/token", time.Now(), "", "")

	_, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof, got %v", err)
	}
}

func TestValidateProof_HTUQueryStringStripped(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// Proof htu has no query string, request URL has one — should still pass.
	proof := mustCreateProof(t, signer, "jti-htu-qs", testHTM, testHTU, time.Now(), "", "")

	result, err := ValidateProof(proof, testHTM, testHTU+"?foo=bar", "", "", testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JKT == "" {
		t.Error("expected non-empty JKT")
	}
}

func TestValidateProof_StaleIAT(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// iat is 120 seconds ago — beyond the 60s proof lifetime.
	proof := mustCreateProof(t, signer, "jti-stale", testHTM, testHTU, time.Now().Add(-120*time.Second), "", "")

	_, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for stale iat, got %v", err)
	}
}

func TestValidateProof_FutureIATWithinTolerance(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// iat is 30 seconds in the future — within the 60s tolerance.
	proof := mustCreateProof(t, signer, "jti-future-ok", testHTM, testHTU, time.Now().Add(30*time.Second), "", "")

	result, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JKT == "" {
		t.Error("expected non-empty JKT")
	}
}

func TestValidateProof_FutureIATBeyondTolerance(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// iat is 120 seconds in the future — beyond the 60s tolerance.
	proof := mustCreateProof(t, signer, "jti-future-bad", testHTM, testHTU, time.Now().Add(120*time.Second), "", "")

	_, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for future iat, got %v", err)
	}
}

func TestValidateProof_MissingJTI(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// Empty jti.
	proof := mustCreateProof(t, signer, "", testHTM, testHTU, time.Now(), "", "")

	_, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for missing jti, got %v", err)
	}
}

func TestValidateProof_AlgNone(t *testing.T) {
	// Build a proof manually with alg:none — this should be rejected at parse time.
	// go-jose doesn't support alg:none, so we simulate with a garbage JWT.
	_, err := ValidateProof("eyJhbGciOiJub25lIiwidHlwIjoiZHBvcCtqd3QifQ.eyJqdGkiOiJ0ZXN0In0.", testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for alg:none, got %v", err)
	}
}

func TestValidateProof_AlgHS256(t *testing.T) {
	// Build an HS256-signed proof — symmetric alg should be rejected.
	// Create an HMAC signer with a symmetric key.
	signingKey := jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte("super-secret-key-for-testing-32b!"),
	}
	opts := &jose.SignerOptions{}
	opts.WithType("dpop+jwt")

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		t.Fatalf("create HS256 signer: %v", err)
	}

	proof, err := CreateDPoPProof(signer, "jti-hs256", testHTM, testHTU, time.Now(), "", "")
	if err != nil {
		t.Fatalf("create proof: %v", err)
	}

	_, err = ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for HS256, got %v", err)
	}
}

func TestValidateProof_PrivateKeyInJWK(t *testing.T) {
	key := mustGenerateES256Key(t)

	// Create a signer that embeds the PRIVATE key (not just public).
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}
	opts := &jose.SignerOptions{}
	opts.WithType("dpop+jwt")
	// Embed private key instead of public key.
	opts.WithHeader("jwk", jose.JSONWebKey{Key: key}) // private key, not &key.PublicKey

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	proof := mustCreateProof(t, signer, "jti-privkey", testHTM, testHTU, time.Now(), "", "")

	_, err = ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for private key in jwk, got %v", err)
	}
}

func TestValidateProof_InvalidATH(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)

	// Proof has wrong ath value.
	proof := mustCreateProof(t, signer, "jti-bad-ath", testHTM, testHTU, time.Now(), "", "wrong-ath-value")

	expectedATH := ComputeATH("real-access-token")
	_, err := ValidateProof(proof, testHTM, testHTU, "", expectedATH, testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for invalid ath, got %v", err)
	}
}

func TestValidateProof_ValidATH(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)

	accessToken := "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.test-payload.sig"
	expectedATH := ComputeATH(accessToken)
	proof := mustCreateProof(t, signer, "jti-good-ath", testHTM, testHTU, time.Now(), "", expectedATH)

	result, err := ValidateProof(proof, testHTM, testHTU, "", expectedATH, testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JKT == "" {
		t.Error("expected non-empty JKT")
	}
}

func TestValidateProof_MissingNonceWhenRequired(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// No nonce in proof, but server requires one.
	proof := mustCreateProof(t, signer, "jti-no-nonce", testHTM, testHTU, time.Now(), "", "")

	_, err := ValidateProof(proof, testHTM, testHTU, "server-nonce-123", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPNonceRequired) {
		t.Errorf("expected ErrDPoPNonceRequired, got %v", err)
	}
}

func TestValidateProof_WrongNonce(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	// Proof has a nonce, but it doesn't match the server's.
	proof := mustCreateProof(t, signer, "jti-wrong-nonce", testHTM, testHTU, time.Now(), "client-nonce-old", "")

	_, err := ValidateProof(proof, testHTM, testHTU, "server-nonce-new", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPNonceMismatch) {
		t.Errorf("expected ErrDPoPNonceMismatch, got %v", err)
	}
}

func TestValidateProof_ValidNonce(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer := mustNewSigner(t, key, jose.ES256)
	nonce := "server-nonce-abc"
	proof := mustCreateProof(t, signer, "jti-valid-nonce", testHTM, testHTU, time.Now(), nonce, "")

	result, err := ValidateProof(proof, testHTM, testHTU, nonce, "", testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Nonce != nonce {
		t.Errorf("expected nonce %q, got %q", nonce, result.Nonce)
	}
}

func TestComputeJKT_EC(t *testing.T) {
	key := mustGenerateES256Key(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey}

	jkt, err := ComputeJKT(jwk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jkt == "" {
		t.Error("expected non-empty JKT")
	}
	// JKT should be base64url-encoded SHA-256 (43 chars for 32 bytes).
	raw, err := base64.RawURLEncoding.DecodeString(jkt)
	if err != nil {
		t.Fatalf("JKT is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("expected 32-byte SHA-256 hash, got %d bytes", len(raw))
	}
}

func TestComputeJKT_RSA(t *testing.T) {
	key := mustGenerateRS256Key(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey}

	jkt, err := ComputeJKT(jwk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jkt == "" {
		t.Error("expected non-empty JKT")
	}
}

func TestComputeJKT_Deterministic(t *testing.T) {
	key := mustGenerateES256Key(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey}

	jkt1, _ := ComputeJKT(jwk)
	jkt2, _ := ComputeJKT(jwk)
	if jkt1 != jkt2 {
		t.Errorf("JKT should be deterministic: %s != %s", jkt1, jkt2)
	}
}

func TestComputeATH(t *testing.T) {
	token := "test-access-token"
	ath := ComputeATH(token)
	if ath == "" {
		t.Error("expected non-empty ATH")
	}
	// Should be base64url-encoded SHA-256.
	raw, err := base64.RawURLEncoding.DecodeString(ath)
	if err != nil {
		t.Fatalf("ATH is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("expected 32-byte SHA-256 hash, got %d bytes", len(raw))
	}

	// Same token should produce same ATH.
	ath2 := ComputeATH(token)
	if ath != ath2 {
		t.Error("ATH should be deterministic")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1 := GenerateNonce()
	nonce2 := GenerateNonce()
	if nonce1 == "" {
		t.Error("expected non-empty nonce")
	}
	if nonce1 == nonce2 {
		t.Error("consecutive nonces should not be equal")
	}
	// 32 bytes base64url = 43 chars.
	if len(nonce1) != 43 {
		t.Errorf("expected 43-char nonce, got %d", len(nonce1))
	}
}

func TestIsDPoPBound(t *testing.T) {
	tests := []struct {
		name   string
		claims *AccessTokenClaims
		want   bool
	}{
		{"nil claims", nil, false},
		{"no cnf", &AccessTokenClaims{}, false},
		{"cnf without jkt", &AccessTokenClaims{Cnf: map[string]interface{}{"other": "val"}}, false},
		{"cnf with jkt", &AccessTokenClaims{Cnf: map[string]interface{}{"jkt": "abc123"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDPoPBound(tt.claims)
			if got != tt.want {
				t.Errorf("IsDPoPBound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateProof_MalformedJWT(t *testing.T) {
	_, err := ValidateProof("not-a-jwt", testHTM, testHTU, "", "", testProofLifetime)
	if !errors.Is(err, domain.ErrDPoPInvalidProof) {
		t.Errorf("expected ErrDPoPInvalidProof for malformed JWT, got %v", err)
	}
}

func TestNewDPoPSigner_ES256(t *testing.T) {
	key := mustGenerateES256Key(t)
	signer, err := NewDPoPSigner(key, jose.ES256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestNewDPoPSigner_RS256(t *testing.T) {
	key := mustGenerateRS256Key(t)
	signer, err := NewDPoPSigner(key, jose.RS256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestValidateProof_PS256(t *testing.T) {
	key := mustGenerateRS256Key(t) // Same RSA key, different signing algorithm.
	signer := mustNewSigner(t, key, jose.PS256)
	proof := mustCreateProof(t, signer, "jti-ps256", testHTM, testHTU, time.Now(), "", "")

	result, err := ValidateProof(proof, testHTM, testHTU, "", "", testProofLifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JKT == "" {
		t.Error("expected non-empty JKT")
	}
}
