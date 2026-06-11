//go:build integration

package services_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
)

func testObs() *observability.Provider {
	return observability.NewNoop()
}

func newJWKSService(t *testing.T, alg string) *services.JWKSService {
	t.Helper()
	dir := t.TempDir()
	obs := testObs()
	store, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("create keyfile store: %v", err)
	}
	return services.NewJWKSService(store, alg, obs)
}

func TestJWKSService_GetSigningKey_AutoGenerate(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	key, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
	if key.Algorithm != "ES256" {
		t.Errorf("alg: got %q, want %q", key.Algorithm, "ES256")
	}
	if key.KeyID == "" {
		t.Error("expected non-empty kid")
	}

	// Second call returns same key (no regeneration).
	key2, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("get signing key again: %v", err)
	}
	if key2.KeyID != key.KeyID {
		t.Errorf("kid changed: %q → %q", key.KeyID, key2.KeyID)
	}
}

func TestJWKSService_BuildJWKS(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Use != "sig" {
		t.Errorf("use: got %q, want %q", jwks.Keys[0].Use, "sig")
	}
	if jwks.Keys[0].Algorithm != "ES256" {
		t.Errorf("alg: got %q, want %q", jwks.Keys[0].Algorithm, "ES256")
	}
}

func TestJWKSService_BuildJWKS_WithPrevious(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// Generate first key.
	key1, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("first key: %v", err)
	}

	// Rotate.
	key2, err := svc.RotateKey(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if key2.KeyID == key1.KeyID {
		t.Error("rotation should create a new kid")
	}

	// JWKS should have both keys.
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(jwks.Keys))
	}

	// Verify both kids are present.
	kids := make(map[string]bool)
	for _, k := range jwks.Keys {
		kids[k.KeyID] = true
	}
	if !kids[key1.KeyID] {
		t.Errorf("previous key %q missing from JWKS", key1.KeyID)
	}
	if !kids[key2.KeyID] {
		t.Errorf("current key %q missing from JWKS", key2.KeyID)
	}
}

func TestJWKSService_SignAndVerifyViaJWKS(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// Get signing key.
	sk, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}

	// Build a crypto.KeyPair for signing.
	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  "ES256",
		KeyID:      sk.KeyID,
	}

	// Sign a JWT.
	claims := crypto.AccessTokenClaims{
		Issuer:   "https://auth.example.com",
		Subject:  "user-1",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-1",
		Scope:    "tools/query",
		JTI:      "jti-1",
		IssuedAt: 1700000000,
		Expiry:   4700000000, // far future
	}
	token, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Build JWKS.
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	// Verify via JWKS.
	verified, err := crypto.VerifyAccessToken(token, jwks)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Subject != "user-1" {
		t.Errorf("sub: got %q, want %q", verified.Subject, "user-1")
	}
	if verified.Scope != "tools/query" {
		t.Errorf("scope: got %q, want %q", verified.Scope, "tools/query")
	}
}

// Matrix: 9.8 — rotated key removed after second rotation (grace = 1 previous key)
func TestJWKSService_OldKeyRemovedAfterSecondRotation(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// Generate key A.
	keyA, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("key A: %v", err)
	}

	// Rotate to key B. JWKS should have A + B.
	keyB, err := svc.RotateKey(ctx)
	if err != nil {
		t.Fatalf("rotate to B: %v", err)
	}
	jwks, _ := svc.BuildJWKS(ctx)
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys after first rotation, got %d", len(jwks.Keys))
	}

	// Rotate to key C. JWKS should have B + C (A is gone — grace period = 1 previous key).
	keyC, err := svc.RotateKey(ctx)
	if err != nil {
		t.Fatalf("rotate to C: %v", err)
	}

	jwks, _ = svc.BuildJWKS(ctx)
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys after second rotation, got %d", len(jwks.Keys))
	}

	kids := make(map[string]bool)
	for _, k := range jwks.Keys {
		kids[k.KeyID] = true
	}

	// Key A should be gone.
	if kids[keyA.KeyID] {
		t.Error("key A should be removed after second rotation (grace = 1 previous)")
	}
	// Keys B and C should be present.
	if !kids[keyB.KeyID] {
		t.Errorf("key B (previous) should still be in JWKS")
	}
	if !kids[keyC.KeyID] {
		t.Errorf("key C (current) should be in JWKS")
	}
}

// Matrix: 9.9 — token signed with removed key fails verification
func TestJWKSService_RotatedOutKey_FailsVerification(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// Sign a token with key A.
	keyA, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("key A: %v", err)
	}

	kpA := &crypto.KeyPair{
		PrivateKey: keyA.PrivateKey,
		PublicKey:  keyA.PublicKey,
		Algorithm:  "ES256",
		KeyID:      keyA.KeyID,
	}
	claims := crypto.AccessTokenClaims{
		Issuer:   "https://auth.example.com",
		Subject:  "user-1",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-1",
		Scope:    "tools/query",
		JTI:      "jti-rotated",
		IssuedAt: 1700000000,
		Expiry:   4700000000,
	}
	tokenA, err := crypto.SignAccessToken(kpA, claims)
	if err != nil {
		t.Fatalf("sign with A: %v", err)
	}

	// Rotate to B, then to C. Key A is now gone from JWKS.
	svc.RotateKey(ctx)
	svc.RotateKey(ctx)

	// Build JWKS (only has B + C, not A).
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	// Verify token signed with A against B+C JWKS → should fail.
	_, err = crypto.VerifyAccessToken(tokenA, jwks)
	if err == nil {
		t.Error("token signed with removed key A should fail verification against B+C JWKS")
	}
}

func TestJWKSService_RS256(t *testing.T) {
	svc := newJWKSService(t, "RS256")
	ctx := context.Background()

	key, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	if key.Algorithm != "RS256" {
		t.Errorf("alg: got %q, want %q", key.Algorithm, "RS256")
	}

	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	if jwks.Keys[0].Algorithm != "RS256" {
		t.Errorf("jwks alg: got %q, want %q", jwks.Keys[0].Algorithm, "RS256")
	}
}

// TestJWKSService_Reload_AtomicSwap verifies that Reload populates the JWKS cache
// and that BuildJWKS returns the cached value.
func TestJWKSService_Reload_AtomicSwap(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// Generate a key first (so the store has something).
	key, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}

	// Call Reload explicitly — should populate cache.
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// BuildJWKS should return from cache now (which we verify by
	// checking it returns the expected keys).
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks after reload: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in cache, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != key.KeyID {
		t.Errorf("cached kid: got %q, want %q", jwks.Keys[0].KeyID, key.KeyID)
	}

	// Rotate and reload — cache should have 2 keys.
	_, err = svc.RotateKey(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// RotateKey calls Reload internally, so cache should be updated.
	jwks, err = svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks after rotation: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(jwks.Keys))
	}
}

// TestJWKSService_BuildJWKS_FallsBackWithoutCache verifies that when no cache
// is populated (no Reload called), BuildJWKS falls back to direct store reads.
// This is the backward-compatible path for keyfile/vault_transit backends.
func TestJWKSService_BuildJWKS_FallsBackWithoutCache(t *testing.T) {
	// Create a fresh service — cache is nil by default.
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// BuildJWKS without any Reload — should work via direct reads.
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks without cache: %v", err)
	}

	// It should have auto-generated a key.
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key (auto-generated), got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Use != "sig" {
		t.Errorf("use: got %q, want %q", jwks.Keys[0].Use, "sig")
	}
}
