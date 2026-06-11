package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestGenerateKeyPairES256(t *testing.T) {
	kp, err := GenerateKeyPair("ES256", "test-es256")
	if err != nil {
		t.Fatalf("GenerateKeyPair(ES256): %v", err)
	}
	if kp.KeyID != "test-es256" {
		t.Errorf("KeyID = %q, want test-es256", kp.KeyID)
	}
	if kp.Algorithm != "ES256" {
		t.Errorf("Algorithm = %q, want ES256", kp.Algorithm)
	}
	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Error("keys should not be nil")
	}
}

func TestGenerateKeyPairRS256(t *testing.T) {
	kp, err := GenerateKeyPair("RS256", "test-rs256")
	if err != nil {
		t.Fatalf("GenerateKeyPair(RS256): %v", err)
	}
	if kp.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want RS256", kp.Algorithm)
	}
}

func TestGenerateKeyPairUnsupported(t *testing.T) {
	_, err := GenerateKeyPair("HS256", "kid")
	if err == nil {
		t.Error("unsupported algorithm should fail")
	}
}

func TestSignAndVerifyES256(t *testing.T) {
	kp, err := GenerateKeyPair("ES256", "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	testSignAndVerify(t, kp)
}

func TestSignAndVerifyRS256(t *testing.T) {
	kp, err := GenerateKeyPair("RS256", "kid-2")
	if err != nil {
		t.Fatal(err)
	}
	testSignAndVerify(t, kp)
}

func testSignAndVerify(t *testing.T, kp *KeyPair) {
	t.Helper()

	now := time.Now()
	claims := AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		Scope:    "tools/read tools/write",
		JTI:      GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(15 * time.Minute).Unix(),
	}

	token, err := SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	// Build JWKS and verify
	jwks := BuildJWKS(kp)
	got, err := VerifyAccessToken(token, &jwks)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if got.Issuer != claims.Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, claims.Issuer)
	}
	if got.Subject != claims.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, claims.Subject)
	}
	if got.ClientID != claims.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, claims.ClientID)
	}
	if got.Scope != claims.Scope {
		t.Errorf("Scope = %q, want %q", got.Scope, claims.Scope)
	}
	if got.JTI != claims.JTI {
		t.Errorf("JTI = %q, want %q", got.JTI, claims.JTI)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-exp")

	claims := AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: time.Now().Add(-30 * time.Minute).Unix(),
		Expiry:   time.Now().Add(-15 * time.Minute).Unix(), // expired 15 min ago
	}

	token, _ := SignAccessToken(kp, claims)
	jwks := BuildJWKS(kp)

	_, err := VerifyAccessToken(token, &jwks)
	if err == nil {
		t.Error("expired token should fail verification")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair("ES256", "kid-1")
	kp2, _ := GenerateKeyPair("ES256", "kid-2")

	claims := AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(15 * time.Minute).Unix(),
	}

	token, _ := SignAccessToken(kp1, claims)

	// Verify with wrong key (kp2's JWKS doesn't have kid-1)
	jwks := BuildJWKS(kp2)
	_, err := VerifyAccessToken(token, &jwks)
	if err == nil {
		t.Error("verification with wrong key should fail")
	}
}

func TestBuildJWKSMultipleKeys(t *testing.T) {
	kp1, _ := GenerateKeyPair("ES256", "kid-a")
	kp2, _ := GenerateKeyPair("RS256", "kid-b")

	jwks := BuildJWKS(kp1, kp2)
	if len(jwks.Keys) != 2 {
		t.Errorf("JWKS should have 2 keys, got %d", len(jwks.Keys))
	}

	for _, key := range jwks.Keys {
		if key.Use != "sig" {
			t.Errorf("key use = %q, want sig", key.Use)
		}
		if key.KeyID == "" {
			t.Error("key should have kid")
		}
	}
}

func TestTypHeaderIsAtJWT(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-typ")

	claims := AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(15 * time.Minute).Unix(),
	}

	token, _ := SignAccessToken(kp, claims)

	// Verify the token and confirm it parses — the VerifyAccessToken
	// function explicitly checks for typ: at+jwt and would fail otherwise.
	jwks := BuildJWKS(kp)
	_, err := VerifyAccessToken(token, &jwks)
	if err != nil {
		t.Fatalf("token with at+jwt typ should verify: %v", err)
	}
}

func TestVerifyAudience(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-aud")

	claims := AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com", "https://other.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(15 * time.Minute).Unix(),
	}

	token, _ := SignAccessToken(kp, claims)
	jwks := BuildJWKS(kp)

	got, err := VerifyAccessToken(token, &jwks)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if len(got.Audience) != 2 {
		t.Errorf("Audience length = %d, want 2", len(got.Audience))
	}
}

// Matrix: 14.8 — alg:none must be rejected (all case variations)
func TestVerify_AlgNone_Rejected(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-none")
	jwks := BuildJWKS(kp)

	now := time.Now()
	payload := fmt.Sprintf(
		`{"iss":"http://localhost:9000","sub":"user-123","aud":["https://mcp.example.com"],"client_id":"client-abc","jti":"test-jti","iat":%d,"exp":%d}`,
		now.Unix(), now.Add(15*time.Minute).Unix(),
	)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	// Test all case variations of "none" algorithm.
	algVariations := []string{"none", "None", "NONE", "nOnE"}
	for _, alg := range algVariations {
		t.Run("alg_"+alg+"_empty_sig", func(t *testing.T) {
			header := fmt.Sprintf(`{"alg":"%s","typ":"at+jwt"}`, alg)
			headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
			token := headerB64 + "." + payloadB64 + "."
			_, err := VerifyAccessToken(token, &jwks)
			if err == nil {
				t.Errorf("alg:%s with empty signature must be rejected", alg)
			}
		})

		t.Run("alg_"+alg+"_no_sig_section", func(t *testing.T) {
			header := fmt.Sprintf(`{"alg":"%s","typ":"at+jwt"}`, alg)
			headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
			token := headerB64 + "." + payloadB64
			_, err := VerifyAccessToken(token, &jwks)
			if err == nil {
				t.Errorf("alg:%s without signature section must be rejected", alg)
			}
		})
	}
}

// Matrix: 14.9 — HS256 with public key as HMAC secret must be rejected
func TestVerify_HS256WithPublicKey_Rejected(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-hs256")
	jwks := BuildJWKS(kp)

	// Marshal the public key to DER bytes — the attacker uses these as HMAC secret.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	now := time.Now()
	header := fmt.Sprintf(`{"alg":"HS256","typ":"at+jwt","kid":"%s"}`, kp.KeyID)
	payload := fmt.Sprintf(
		`{"iss":"http://localhost:9000","sub":"user-123","aud":["https://mcp.example.com"],"client_id":"client-abc","jti":"test-jti","iat":%d,"exp":%d}`,
		now.Unix(), now.Add(15*time.Minute).Unix(),
	)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	signingInput := headerB64 + "." + payloadB64

	// Sign with HMAC-SHA256 using the public key bytes as the secret.
	mac := hmac.New(sha256.New, pubKeyBytes)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	token := signingInput + "." + sigB64

	_, err = VerifyAccessToken(token, &jwks)
	if err == nil {
		t.Error("HS256 signed with public key bytes must be rejected")
	}
}

// Matrix: 1.5.16 — wrong issuer must be rejected
func TestVerify_WrongIssuer_Rejected(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-iss")
	jwks := BuildJWKS(kp)

	now := time.Now()
	claims := AccessTokenClaims{
		Issuer:   "https://evil.example.com",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(15 * time.Minute).Unix(),
	}

	token, err := SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// VerifyAccessToken alone does NOT check issuer — it succeeds.
	got, err := VerifyAccessToken(token, &jwks)
	if err != nil {
		t.Fatalf("verify should succeed without issuer check: %v", err)
	}
	if got.Issuer != "https://evil.example.com" {
		t.Errorf("issuer: got %q", got.Issuer)
	}

	// VerifyAccessTokenWithIssuer rejects mismatched issuer.
	_, err = VerifyAccessTokenWithIssuer(token, &jwks, "https://auth.authplane.ai")
	if err == nil {
		t.Error("wrong issuer must be rejected by VerifyAccessTokenWithIssuer")
	}

	// Correct issuer succeeds.
	_, err = VerifyAccessTokenWithIssuer(token, &jwks, "https://evil.example.com")
	if err != nil {
		t.Errorf("matching issuer should succeed: %v", err)
	}
}

// Matrix: 1.5.9 — iat claim must be present and recent
func TestJWT_IatClaimPresent(t *testing.T) {
	kp, _ := GenerateKeyPair("ES256", "kid-iat")
	jwks := BuildJWKS(kp)

	now := time.Now()
	claims := AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(15 * time.Minute).Unix(),
	}

	token, err := SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := VerifyAccessToken(token, &jwks)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if got.IssuedAt == 0 {
		t.Fatal("iat claim is missing (zero)")
	}

	diff := time.Since(time.Unix(got.IssuedAt, 0))
	if diff < 0 || diff > 5*time.Second {
		t.Errorf("iat claim is not within 5 seconds of now: diff=%v", diff)
	}
}
