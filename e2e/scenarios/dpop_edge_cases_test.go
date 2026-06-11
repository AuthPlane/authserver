//go:build e2e

package scenarios

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
)

// TestDPoP_AlgNone_Rejected verifies that DPoP proofs using alg:none are rejected.
// Per RFC 9449 §4.3, only asymmetric algorithms (ES256, RS256, PS256) are accepted.
func TestDPoP_AlgNone_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// Construct a DPoP proof with alg:none by hand.
	// Header: {"alg":"none","typ":"dpop+jwt","jwk":{...}}
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubJWK := jose.JSONWebKey{Key: &privKey.PublicKey}
	pubJWKBytes, _ := pubJWK.MarshalJSON()

	header := map[string]any{
		"alg": "none",
		"typ": "dpop+jwt",
		"jwk": json.RawMessage(pubJWKBytes),
	}
	claims := map[string]any{
		"jti": crypto.GenerateRandomString(16),
		"htm": "POST",
		"htu": h.Issuer + "/oauth/token",
		"iat": time.Now().Unix(),
	}

	hdrJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	fakeProof := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "."

	status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", fakeProof)
	if status == 200 {
		t.Fatal("alg:none DPoP proof should have been rejected")
	}

	var oe e2e.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if oe.Error != "invalid_dpop_proof" {
		t.Errorf("error: got %q, want invalid_dpop_proof", oe.Error)
	}
}

// TestDPoP_SymmetricAlg_Rejected verifies that DPoP proofs using HMAC (HS256)
// are rejected. Per RFC 9449 §4.3, only asymmetric algorithms are permitted.
func TestDPoP_SymmetricAlg_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// Construct a DPoP proof with HS256 by hand.
	// This simulates an attacker using a symmetric key.
	secret := []byte("attacker-shared-secret-for-hmac-256")
	header := map[string]any{
		"alg": "HS256",
		"typ": "dpop+jwt",
	}
	claims := map[string]any{
		"jti": crypto.GenerateRandomString(16),
		"htm": "POST",
		"htu": h.Issuer + "/oauth/token",
		"iat": time.Now().Unix(),
	}

	hdrJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	sigInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	fakeProof := sigInput + "." + sig

	status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", fakeProof)
	if status == 200 {
		t.Fatal("HS256 DPoP proof should have been rejected")
	}

	var oe e2e.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if oe.Error != "invalid_dpop_proof" {
		t.Errorf("error: got %q, want invalid_dpop_proof", oe.Error)
	}
}

// TestDPoP_WrongHTU_Rejected verifies that a DPoP proof with mismatched
// htu (HTTP URL) is rejected.
func TestDPoP_WrongHTU_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := crypto.NewDPoPSigner(privKey, jose.ES256)

	// Proof targets wrong URL.
	jti := crypto.GenerateRandomString(16)
	proof, _ := crypto.CreateDPoPProof(signer, jti, "POST", "https://evil.com/oauth/token", time.Now(), "", "")

	status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", proof)
	if status == 200 {
		t.Fatal("wrong HTU should have been rejected")
	}

	var oe e2e.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if oe.Error != "invalid_dpop_proof" {
		t.Errorf("error: got %q, want invalid_dpop_proof", oe.Error)
	}
}

// TestDPoP_StaleIAT_Rejected verifies that a DPoP proof with iat too far
// in the past is rejected (proof freshness check).
func TestDPoP_StaleIAT_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := crypto.NewDPoPSigner(privKey, jose.ES256)

	// Proof issued 10 minutes ago (well beyond the usual 60-second lifetime).
	jti := crypto.GenerateRandomString(16)
	staleIAT := time.Now().Add(-10 * time.Minute)
	proof, _ := crypto.CreateDPoPProof(signer, jti, "POST", h.Issuer+"/oauth/token", staleIAT, "", "")

	status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", proof)
	if status == 200 {
		t.Fatal("stale iat should have been rejected")
	}

	var oe e2e.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if oe.Error != "invalid_dpop_proof" {
		t.Errorf("error: got %q, want invalid_dpop_proof", oe.Error)
	}
}

// TestDPoP_MalformedJWT_Rejected verifies that a completely invalid DPoP
// proof string is rejected.
func TestDPoP_MalformedJWT_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	malformedProofs := []string{
		"not-a-jwt",
		"a.b",
		"a.b.c.d",
		"",
		strings.Repeat("x", 10000),
	}

	for _, proof := range malformedProofs {
		if proof == "" {
			// Empty string means no DPoP header → should succeed as Bearer.
			continue
		}
		status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", proof)
		if status == 200 {
			t.Fatalf("malformed proof %q should have been rejected", proof[:min(len(proof), 30)])
		}

		var oe e2e.OAuthError
		if err := json.Unmarshal(body, &oe); err != nil {
			t.Fatalf("decode error for proof %q: %v", proof[:min(len(proof), 30)], err)
		}
		if oe.Error != "invalid_dpop_proof" {
			t.Errorf("malformed proof error: got %q, want invalid_dpop_proof", oe.Error)
		}
	}
}
