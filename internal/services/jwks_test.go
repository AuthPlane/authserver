//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
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
	return services.NewJWKSService(store, nil, alg, obs)
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
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("create the first key: %v", err)
	}

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

// erroringAgentsConfig is an AgentsConfigProvider that always fails to resolve,
// standing in for a substitute provider hitting a transient backend error.
type erroringAgentsConfig struct{}

func (erroringAgentsConfig) Config(context.Context) (output.AgentsConfig, error) {
	return output.AgentsConfig{}, errors.New("agents config backend unavailable")
}

// stubAgentClientStore returns a single agent from ListAgents; the other methods
// are unused by the JWKS path. If degradation did NOT happen, this agent would
// surface in the document — so its absence proves the agents array was omitted.
type stubAgentClientStore struct{}

func (stubAgentClientStore) ListAgents(context.Context) ([]client.Client, error) {
	return []client.Client{{ID: "agent-1", AgentDescription: "test agent", IsAgent: true}}, nil
}
func (stubAgentClientStore) Create(context.Context, *client.Client) error { return nil }
func (stubAgentClientStore) GetByID(context.Context, string) (*client.Client, error) {
	return nil, nil
}
func (stubAgentClientStore) GetByCIMDURL(context.Context, string) (*client.Client, error) {
	return nil, nil
}
func (stubAgentClientStore) Update(context.Context, *client.Client) error { return nil }
func (stubAgentClientStore) List(context.Context, string, string, int, int) ([]client.Client, error) {
	return nil, nil
}
func (stubAgentClientStore) Count(context.Context, string) (int, error) { return 0, nil }
func (stubAgentClientStore) Delete(context.Context, string) error       { return nil }

// TestJWKSService_BuildJWKSDocument_DegradesOnAgentsConfigError verifies that a
// failure to resolve the (optional, off-by-default) agent-listing config does
// NOT take down /jwks.json: the core signing-key set is still served, only the
// agents array is omitted. Agent listing is a non-critical discovery add-on;
// coupling key distribution to its config resolution would black-hole all token
// validation for a substitute provider that errors.
func TestJWKSService_BuildJWKSDocument_DegradesOnAgentsConfigError(t *testing.T) {
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()

	// Wire a client store that WOULD list an agent, plus a config provider that
	// always errors. If the endpoint failed closed, BuildJWKSDocument would
	// return an error; if it didn't degrade, the agent would appear.
	svc.WithAgentListing(stubAgentClientStore{})
	svc.WithAgentsConfig(erroringAgentsConfig{})
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("create the first key: %v", err)
	}

	data, err := svc.BuildJWKSDocument(ctx)
	if err != nil {
		t.Fatalf("BuildJWKSDocument must degrade, not fail, on agents-config error: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal jwks document: %v", err)
	}

	// Core key set must be present and non-empty.
	keysRaw, ok := doc["keys"]
	if !ok {
		t.Fatal("jwks document missing core \"keys\" array")
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(keysRaw, &keys); err != nil {
		t.Fatalf("unmarshal keys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected at least one signing key in degraded document")
	}

	// Agents array must be omitted (degraded), not present.
	if _, present := doc["agents"]; present {
		t.Error("agents array must be omitted when agents-config resolution fails")
	}
}

// TestJWKSService_BuildJWKS_FallsBackWithoutCache verifies that when no cache
// is populated (no Reload called), BuildJWKS falls back to direct store reads.
// This is the backward-compatible path for keyfile/vault_transit backends.
func TestJWKSService_BuildJWKS_FallsBackWithoutCache(t *testing.T) {
	// Create a fresh service — cache is nil by default.
	svc := newJWKSService(t, "ES256")
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("create the first key: %v", err)
	}

	// BuildJWKS without any Reload — should work via direct reads.
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks without cache: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Use != "sig" {
		t.Errorf("use: got %q, want %q", jwks.Keys[0].Use, "sig")
	}
}

// transitLikeStore keeps its own key material, as Vault Transit does: Save
// and CreateIfAbsent ignore the key they are handed and create the next
// version themselves, named transit-v<n>. Save on an empty store creates the
// first version; on a non-empty one it rotates.
type transitLikeStore struct {
	mu       sync.Mutex
	alg      string
	versions []*output.SigningKey
}

func (s *transitLikeStore) addVersion() error {
	kp, err := crypto.GenerateKeyPair(s.alg, fmt.Sprintf("transit-v%d", len(s.versions)+1))
	if err != nil {
		return err
	}
	s.versions = append(s.versions, &output.SigningKey{
		PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, Algorithm: s.alg, KeyID: kp.KeyID,
	})
	return nil
}

func (s *transitLikeStore) LoadCurrent(context.Context) (*output.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.versions) == 0 {
		return nil, nil
	}
	return s.versions[len(s.versions)-1], nil
}

func (s *transitLikeStore) LoadPrevious(context.Context) (*output.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.versions) < 2 {
		return nil, nil
	}
	return s.versions[len(s.versions)-2], nil
}

func (s *transitLikeStore) ListActive(context.Context) ([]*output.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*output.SigningKey{}
	for i := len(s.versions) - 1; i >= 0 && len(out) < 2; i-- {
		out = append(out, s.versions[i])
	}
	return out, nil
}

func (s *transitLikeStore) Save(context.Context, *output.SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addVersion()
}

func (s *transitLikeStore) CreateIfAbsent(context.Context, *output.SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.versions) > 0 {
		return nil
	}
	return s.addVersion()
}

func (s *transitLikeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.versions)
}

// The key the service hands out and publishes is the one the store holds,
// not the one it generated locally: a store that keeps its own key material
// would otherwise sign with a key the JWKS does not carry.
func TestJWKSService_FirstUse_ReturnsAndPublishesTheStoredKey(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := services.NewJWKSService(store, nil, "ES256", testObs())
	ctx := context.Background()

	key, err := svc.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if key.KeyID != "transit-v1" {
		t.Errorf("GetSigningKey kid = %q, want the stored key transit-v1", key.KeyID)
	}
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "transit-v1" {
		t.Errorf("JWKS kids = %v, want [transit-v1]", jwksKids(jwks.Keys))
	}
}

func TestJWKSService_RotateKey_ReturnsTheStoredKey(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := services.NewJWKSService(store, nil, "ES256", testObs())
	ctx := context.Background()

	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	rotated, err := svc.RotateKey(ctx)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if rotated.KeyID != "transit-v2" {
		t.Errorf("RotateKey kid = %q, want the stored key transit-v2", rotated.KeyID)
	}
}

// First use never rotates: callers that all saw an empty store end up on
// the one key the store created.
func TestJWKSService_ConcurrentFirstUse_CreatesOneKey(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := services.NewJWKSService(store, nil, "ES256", testObs())

	const callers = 64
	kids := make([]string, callers)
	errs := make([]error, callers)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < callers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			key, err := svc.GetSigningKey(context.Background())
			if err != nil {
				errs[i] = err
				return
			}
			kids[i] = key.KeyID
		}(i)
	}
	start.Done()
	done.Wait()

	for i := range kids {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if kids[i] != "transit-v1" {
			t.Errorf("caller %d got kid %q, want transit-v1", i, kids[i])
		}
	}
	if n := store.count(); n != 1 {
		t.Errorf("store holds %d key versions after concurrent first use, want 1", n)
	}
}

func jwksKids(keys []jose.JSONWebKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.KeyID)
	}
	return out
}

// The JWKS endpoint is unauthenticated, so reading it never creates a key:
// before the first key exists it serves an empty set and writes nothing.
func TestJWKSService_BuildJWKS_EmptyStoreCreatesNothing(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := services.NewJWKSService(store, nil, "ES256", testObs())

	jwks, err := svc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Keys) != 0 {
		t.Errorf("JWKS kids = %v, want none before the first key exists", jwksKids(jwks.Keys))
	}
	if n := store.count(); n != 0 {
		t.Errorf("store holds %d keys after a JWKS read, want 0", n)
	}
}

// A store interrupted mid-rotation can hold one key as both current and
// previous; the JWKS lists it once.
func TestJWKSService_BuildJWKS_DropsADuplicateKid(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	if err := store.Save(context.Background(), nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store.versions = append(store.versions, store.versions[0])
	svc := services.NewJWKSService(store, nil, "ES256", testObs())

	jwks, err := svc.BuildJWKS(context.Background())
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if kids := jwksKids(jwks.Keys); len(kids) != 1 || kids[0] != "transit-v1" {
		t.Errorf("JWKS kids = %v, want [transit-v1] once", kids)
	}
}

// listFailingStore makes ListActive fail while failList is set.
type listFailingStore struct {
	*transitLikeStore
	failList bool
}

func (s *listFailingStore) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	if s.failList {
		return nil, errors.New("key store unavailable")
	}
	return s.transitLikeStore.ListActive(ctx)
}

// mapCache is a minimal output.Cache for the JWKS document.
type mapCache struct {
	mu sync.Mutex
	m  map[string]*jose.JSONWebKeySet
}

func (c *mapCache) Load(_ context.Context, key string) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[key], nil
}

func (c *mapCache) Store(_ context.Context, key string, v *jose.JSONWebKeySet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*jose.JSONWebKeySet{}
	}
	c.m[key] = v
	return nil
}

func (c *mapCache) Invalidate(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}

func newCachedJWKSService(store output.KeyStore) *services.JWKSService {
	return services.NewJWKSService(store, &mapCache{}, "ES256", testObs())
}

// A key rotated outside this process (the CLI, a Vault rotation, a missed
// notification) is published before the first token signed with it: the
// signing path reloads the cached JWKS when its key is not in it.
func TestJWKSService_OutOfBandRotation_PublishedAtNextSignature(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if err := store.Save(ctx, nil); err != nil { // rotation the service does not see
		t.Fatalf("out-of-band rotate: %v", err)
	}

	key, err := svc.GetSigningKey(ctx)
	if err != nil || key.KeyID != "transit-v2" {
		t.Fatalf("GetSigningKey = %v, %v; want transit-v2", key, err)
	}
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Key("transit-v2")) == 0 {
		t.Errorf("JWKS kids = %v, want transit-v2 published before it signs", jwksKids(jwks.Keys))
	}
}

// An empty set is never cached: a JWKS read before the first key exists
// must not hide that key once another process creates it.
func TestJWKSService_EmptySetNotCached(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := svc.BuildJWKS(ctx); err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if err := store.CreateIfAbsent(ctx, nil); err != nil { // another process creates the key
		t.Fatalf("create: %v", err)
	}
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Key("transit-v1")) == 0 {
		t.Errorf("JWKS kids = %v, want transit-v1: an empty set was cached", jwksKids(jwks.Keys))
	}
}

// When the reload after a rotation fails, the cached JWKS without the new
// key is dropped, so the next read goes to the store.
func TestJWKSService_FailedReloadAfterRotation_DropsCachedJWKS(t *testing.T) {
	store := &listFailingStore{transitLikeStore: &transitLikeStore{alg: "ES256"}}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if _, err := svc.BuildJWKS(ctx); err != nil { // caches [v1]
		t.Fatalf("BuildJWKS: %v", err)
	}

	store.failList = true
	if _, err := svc.RotateKey(ctx); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	store.failList = false

	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Key("transit-v2")) == 0 {
		t.Errorf("JWKS kids = %v, want transit-v2: the stale cached set was kept", jwksKids(jwks.Keys))
	}
}

// countingStore counts ListActive calls and can hold them, to test how the
// service reloads.
type countingStore struct {
	*transitLikeStore
	mu    sync.Mutex
	lists int
	delay time.Duration
	hold  chan struct{} // when set, the next ListActive waits for it to close
}

func (s *countingStore) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	keys, err := s.transitLikeStore.ListActive(ctx)
	s.mu.Lock()
	s.lists++
	hold := s.hold
	s.hold = nil
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	time.Sleep(s.delay)
	return keys, err
}

func (s *countingStore) listCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lists
}

// Many signers finding the new kid missing at once share one reload.
func TestJWKSService_UnknownKid_OneReloadForConcurrentSigners(t *testing.T) {
	store := &countingStore{transitLikeStore: &transitLikeStore{alg: "ES256"}, delay: 20 * time.Millisecond}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if err := store.Save(ctx, nil); err != nil { // out-of-band rotation
		t.Fatalf("rotate: %v", err)
	}
	before := store.listCount()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.GetSigningKey(ctx); err != nil {
				t.Errorf("GetSigningKey: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := store.listCount() - before; n > 2 {
		t.Errorf("%d reloads for 100 concurrent signers, want 1 (at most 2)", n)
	}
}

// When the reload for an unknown kid fails, the stale cached set is dropped
// so the next JWKS read goes to the store.
func TestJWKSService_UnknownKid_FailedReloadDropsCachedJWKS(t *testing.T) {
	store := &listFailingStore{transitLikeStore: &transitLikeStore{alg: "ES256"}}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if err := store.Save(ctx, nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	store.failList = true
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	store.failList = false
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Key("transit-v2")) == 0 {
		t.Errorf("JWKS kids = %v, want transit-v2: the stale set was kept", jwksKids(jwks.Keys))
	}
}

// A reload that finds no keys drops the cached set instead of keeping keys
// the store no longer has.
func TestJWKSService_ReloadOfEmptyStore_DropsCachedJWKS(t *testing.T) {
	store := &transitLikeStore{alg: "ES256"}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	store.mu.Lock()
	store.versions = nil
	store.mu.Unlock()
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Keys) != 0 {
		t.Errorf("JWKS kids = %v, want none: the store has no keys", jwksKids(jwks.Keys))
	}
}

// The JWKS read path caches what it reads, so repeated fetches do not hit
// the store.
func TestJWKSService_BuildJWKS_CachesTheSlowPath(t *testing.T) {
	store := &countingStore{transitLikeStore: &transitLikeStore{alg: "ES256"}}
	if err := store.CreateIfAbsent(context.Background(), nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := newCachedJWKSService(store)
	for i := 0; i < 3; i++ {
		if _, err := svc.BuildJWKS(context.Background()); err != nil {
			t.Fatalf("BuildJWKS: %v", err)
		}
	}
	if n := store.listCount(); n != 1 {
		t.Errorf("store read %d times for 3 JWKS fetches, want 1", n)
	}
}

// A JWKS read that began before a rotation must not replace, when it
// finishes, the newer set a reload stored meanwhile.
func TestJWKSService_SlowReadDoesNotOverwriteANewerReload(t *testing.T) {
	store := &countingStore{transitLikeStore: &transitLikeStore{alg: "ES256"}}
	ctx := context.Background()
	if err := store.CreateIfAbsent(ctx, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := newCachedJWKSService(store)

	hold := make(chan struct{})
	store.mu.Lock()
	store.hold = hold
	store.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = svc.BuildJWKS(ctx) // reads [v1], then waits
	}()
	for store.listCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := store.Save(ctx, nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := svc.Reload(ctx); err != nil { // stores [v2, v1]
		t.Fatalf("Reload: %v", err)
	}
	close(hold)
	<-done

	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Key("transit-v2")) == 0 {
		t.Errorf("JWKS kids = %v, want transit-v2: the slow read overwrote the newer set", jwksKids(jwks.Keys))
	}
}

// A reload that began reading the store before the new key existed, and
// finished after a signer saw the key, does not stand in for the signer's
// own reload: the signer still publishes its key before signing.
func TestJWKSService_UnknownKid_StaleInFlightReloadDoesNotCount(t *testing.T) {
	store := &countingStore{transitLikeStore: &transitLikeStore{alg: "ES256"}}
	svc := newCachedJWKSService(store)
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}

	hold := make(chan struct{})
	store.mu.Lock()
	store.hold = hold
	store.mu.Unlock()
	inFlight := make(chan struct{})
	go func() {
		defer close(inFlight)
		_ = svc.Reload(ctx) // reads [v1], then waits
	}()
	for store.listCount() < 2 {
		time.Sleep(time.Millisecond)
	}
	if err := store.Save(ctx, nil); err != nil { // the rotation lands
		t.Fatalf("rotate: %v", err)
	}
	signed := make(chan string)
	go func() {
		key, err := svc.GetSigningKey(ctx) // sees v2, waits for the stale reload
		if err != nil {
			t.Errorf("GetSigningKey: %v", err)
		}
		signed <- key.KeyID
	}()
	time.Sleep(20 * time.Millisecond)
	close(hold)
	<-inFlight
	if kid := <-signed; kid != "transit-v2" {
		t.Fatalf("signed with %s, want transit-v2", kid)
	}
	cached, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(cached.Key("transit-v2")) == 0 {
		t.Errorf("JWKS kids = %v after signing with transit-v2, want it published", jwksKids(cached.Keys))
	}
}

// syncFailStore makes ListActive fail while fail is set; safe across
// goroutines.
type syncFailStore struct {
	*transitLikeStore
	failMu sync.Mutex
	fail   bool
}

func (s *syncFailStore) setFail(v bool) {
	s.failMu.Lock()
	s.fail = v
	s.failMu.Unlock()
}

func (s *syncFailStore) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	s.failMu.Lock()
	f := s.fail
	s.failMu.Unlock()
	if f {
		return nil, errors.New("key store unavailable")
	}
	return s.transitLikeStore.ListActive(ctx)
}

// gatedCache holds the next Load until gate is closed, after signalling
// entered, so a test can run something between a signer's snapshot and its
// lock.
type gatedCache struct {
	mapCache
	gateMu  sync.Mutex
	gate    chan struct{}
	entered chan struct{}
}

func (c *gatedCache) Load(ctx context.Context, k string) (*jose.JSONWebKeySet, error) {
	c.gateMu.Lock()
	g := c.gate
	c.gate = nil
	c.gateMu.Unlock()
	if g != nil {
		close(c.entered)
		<-g
	}
	return c.mapCache.Load(ctx, k)
}

// A reload from elsewhere (the listener, SIGHUP) that starts after a signer
// saw its key and fails must not let the signer skip its own: the failed
// reload drops the stale set, so the key is published when it signs.
func TestJWKSService_UnknownKid_FailedReloadElsewhereDoesNotCount(t *testing.T) {
	store := &syncFailStore{transitLikeStore: &transitLikeStore{alg: "ES256"}}
	c := &gatedCache{}
	svc := services.NewJWKSService(store, c, "ES256", testObs())
	ctx := context.Background()
	if _, err := svc.GetSigningKey(ctx); err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if err := store.Save(ctx, nil); err != nil { // out-of-band rotation
		t.Fatalf("rotate: %v", err)
	}
	release := make(chan struct{})
	c.gateMu.Lock()
	c.gate, c.entered = release, make(chan struct{})
	c.gateMu.Unlock()

	signed := make(chan string)
	go func() {
		key, err := svc.GetSigningKey(ctx)
		if err != nil {
			t.Errorf("GetSigningKey: %v", err)
			signed <- ""
			return
		}
		signed <- key.KeyID
	}()
	<-c.entered // the signer has taken its snapshot and is reading the cache
	store.setFail(true)
	if err := svc.Reload(ctx); err == nil {
		t.Fatal("Reload succeeded; want the store error")
	}
	store.setFail(false)
	close(release)

	kid := <-signed
	jwks, err := svc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if kid == "" || len(jwks.Key(kid)) == 0 {
		t.Errorf("signed with %q while the JWKS holds %v", kid, jwksKids(jwks.Keys))
	}
}
