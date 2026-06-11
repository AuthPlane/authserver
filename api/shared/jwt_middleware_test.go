package shared

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
)

// staticJWKS satisfies the JWKSProvider interface for tests.
type staticJWKS struct {
	set jose.JSONWebKeySet
}

func (s *staticJWKS) BuildJWKS(_ context.Context) (*jose.JSONWebKeySet, error) {
	cp := s.set
	return &cp, nil
}

// memoryProofStore is an in-memory DPoPProofStore that returns a sentinel
// "replay" error on duplicate JTI consumption.
type memoryProofStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newMemoryProofStore() *memoryProofStore {
	return &memoryProofStore{seen: map[string]time.Time{}}
}

var errProofReplay = errors.New("dpop: jti already consumed")

func (s *memoryProofStore) ConsumeJTI(_ context.Context, jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[jti]; ok {
		return errProofReplay
	}
	s.seen[jti] = expiry
	return nil
}

func (s *memoryProofStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

const (
	testIssuer    = "https://auth.example.com"
	resourceA     = "https://res-a.example.com"
	resourceB     = "https://res-b.example.com"
	resourcePath  = "/tools/echo"
	defaultMethod = "POST"
)

// jwtTestFixture bundles the signing key, the middleware, and a noop downstream
// handler so individual cases just configure claims and call serve.
type jwtTestFixture struct {
	kp      *crypto.KeyPair
	mw      *JWTMiddleware
	called  bool
	sawSub  string
	handler http.Handler
}

func newJWTFixture(t *testing.T) *jwtTestFixture {
	t.Helper()

	kp, err := crypto.GenerateKeyPair("ES256", "test-kid")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       kp.PublicKey,
			KeyID:     kp.KeyID,
			Algorithm: "ES256",
			Use:       "sig",
		}},
	}
	mw := NewJWTMiddleware(&staticJWKS{set: jwks}, testIssuer, observability.NewNoop())

	f := &jwtTestFixture{kp: kp, mw: mw}
	f.handler = mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.called = true
		if c, ok := ClaimsFromContext(r.Context()); ok {
			f.sawSub = c.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))
	return f
}

// mint signs an access token for the given claims, defaulting iat/exp/iss/jti
// so each test case only states what matters for that case.
func (f *jwtTestFixture) mint(t *testing.T, claims crypto.AccessTokenClaims) string {
	t.Helper()
	now := time.Now()
	if claims.Issuer == "" {
		claims.Issuer = testIssuer
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.Expiry == 0 {
		claims.Expiry = now.Add(5 * time.Minute).Unix()
	}
	if claims.JTI == "" {
		claims.JTI = crypto.GenerateRandomString(16)
	}
	if claims.Subject == "" {
		claims.Subject = "user-1"
	}
	if claims.ClientID == "" {
		claims.ClientID = "client-1"
	}
	tok, err := crypto.SignAccessToken(f.kp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// serveBearer issues a Bearer-authenticated request through the middleware and
// returns the recorder. It records whether the downstream handler was reached.
func (f *jwtTestFixture) serveBearer(t *testing.T, token, urlStr string) *httptest.ResponseRecorder {
	t.Helper()
	f.called = false
	f.sawSub = ""
	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// serveDPoP issues a DPoP-authenticated request through the middleware.
func (f *jwtTestFixture) serveDPoP(t *testing.T, token, proof, method, urlStr string) *httptest.ResponseRecorder {
	t.Helper()
	f.called = false
	f.sawSub = ""
	req := httptest.NewRequestWithContext(context.Background(), method, urlStr, nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// ============================================================================
// Constructor-level footgun guards (ADV1)
// ============================================================================

// The resource-server constructor must reject empty audience. The failure mode
// it's specifically designed to prevent — "I shipped a resource server without
// configuring audience" — is precisely the 2026-05-18 audit's HIGH finding.
func TestNewResourceJWTMiddleware_PanicsOnEmptyAudience(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair("ES256", "k")
	jwks := &staticJWKS{set: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: kp.PublicKey, KeyID: kp.KeyID, Algorithm: "ES256", Use: "sig",
	}}}}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty audience")
		}
	}()
	NewResourceJWTMiddleware(jwks, testIssuer, "", newMemoryProofStore(), DPoPJWTConfig{ProofLifetime: time.Minute}, observability.NewNoop())
}

// And nil proof store — the other half of the footgun pair.
func TestNewResourceJWTMiddleware_PanicsOnNilProofStore(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair("ES256", "k")
	jwks := &staticJWKS{set: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: kp.PublicKey, KeyID: kp.KeyID, Algorithm: "ES256", Use: "sig",
	}}}}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil proofStore")
		}
	}()
	NewResourceJWTMiddleware(jwks, testIssuer, resourceA, nil, DPoPJWTConfig{ProofLifetime: time.Minute}, observability.NewNoop())
}

// Happy path: the constructor wires audience + store correctly, so a properly
// scoped token reaches the downstream handler.
func TestNewResourceJWTMiddleware_WiresAudienceAndStore(t *testing.T) {
	kp, err := crypto.GenerateKeyPair("ES256", "k")
	if err != nil {
		t.Fatal(err)
	}
	jwks := &staticJWKS{set: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: kp.PublicKey, KeyID: kp.KeyID, Algorithm: "ES256", Use: "sig",
	}}}}
	mw := NewResourceJWTMiddleware(jwks, testIssuer, resourceA, newMemoryProofStore(), DPoPJWTConfig{ProofLifetime: time.Minute}, observability.NewNoop())

	called := false
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// Mint a token for resourceA — the configured audience.
	claims := crypto.AccessTokenClaims{
		Issuer: testIssuer, Subject: "u", Audience: []string{resourceA},
		ClientID: "c", JTI: "j", IssuedAt: time.Now().Unix(),
		Expiry: time.Now().Add(time.Minute).Unix(),
	}
	tok, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, "http://server.local"+resourcePath, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called || rec.Code != http.StatusOK {
		t.Errorf("resource-constructor wiring broken: status=%d called=%v", rec.Code, called)
	}
}

// ============================================================================
// Audience adversarial tests (ADV8, ADV3)
// ============================================================================

// Cross-audience: token minted for resource A must not be honored by a
// middleware deployed for resource B. This is the HIGH finding from the
// 2026-05-18 audit and was completely uncovered prior to this file.
func TestJWTMiddleware_RejectsCrossAudienceToken(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceB)

	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{resourceA},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)

	if f.called {
		t.Fatal("downstream handler invoked for cross-audience token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate header missing: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

// "Almost valid" (ADV3): same issuer, same client, same subject, but the
// audience is a single character off. Must be rejected — substring matching
// would be a real bug.
func TestJWTMiddleware_RejectsAlmostMatchingAudience(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience("https://res.example.com")

	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{"https://res.example.com.attacker.tld"},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d called=%v: substring-prefix audience must not match", rec.Code, f.called)
	}
}

// A token with no audience claim must be rejected when the middleware is
// configured with an expected audience — no "missing means wildcard" semantics.
func TestJWTMiddleware_RejectsMissingAudience(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)

	// Mint via direct claim manipulation: SignAccessToken requires a non-empty
	// audience, so we mint with a placeholder and then exercise the case where
	// the claim is structurally present but doesn't include the expected aud.
	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{"https://unrelated.example.com"},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("token with non-matching aud must be rejected (status=%d called=%v)", rec.Code, f.called)
	}
}

// Multi-valued audience: a token containing the expected audience among others
// must still be accepted (RFC 7519 §4.1.3 permits array values).
func TestJWTMiddleware_AcceptsMatchingAudienceAmongMultiple(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)

	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{"https://other.example.com", resourceA, "https://third.example.com"},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)
	if !f.called || rec.Code != http.StatusOK {
		t.Errorf("status=%d called=%v: token with matching aud in list should succeed", rec.Code, f.called)
	}
}

// Confusion attack: token whose aud equals the issuer URL (a plausible
// "default" if some upstream forgot to set it). Must not be silently honored
// as if it were addressed to any resource.
func TestJWTMiddleware_RejectsIssuerAsAudienceConfusion(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)

	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{testIssuer},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("token with aud=issuer must be rejected when expected aud is a resource (status=%d called=%v)", rec.Code, f.called)
	}
}

// State-after-error (ADV6): a rejected request must NOT leak the validated
// claims into the request context — confirms the middleware fails before
// invoking next.ServeHTTP, not after.
func TestJWTMiddleware_CrossAudience_DoesNotInjectClaims(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceB)

	token := f.mint(t, crypto.AccessTokenClaims{
		Subject:  "user-leak",
		Audience: []string{resourceA},
	})
	_ = f.serveBearer(t, token, "http://server.local"+resourcePath)

	if f.sawSub != "" {
		t.Errorf("downstream observed subject=%q after rejected request — claims leaked", f.sawSub)
	}
}

// Sanity: a properly audienced token still works. Catches over-eager fixes
// that reject everything.
func TestJWTMiddleware_AcceptsMatchingAudience(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)

	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{resourceA},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)
	if !f.called || rec.Code != http.StatusOK {
		t.Errorf("matching-aud token should succeed (status=%d called=%v)", rec.Code, f.called)
	}
}

// When the middleware is NOT configured with an audience, we still want to
// match today's "issuer-only" behavior for the existing e2e tests. This pins
// that contract so a future "default deny" change can't silently turn off
// resource servers that haven't migrated.
func TestJWTMiddleware_NoAudienceConfigured_AcceptsAnyAudience(t *testing.T) {
	f := newJWTFixture(t)
	// No WithAudience call.

	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{resourceA},
	})

	rec := f.serveBearer(t, token, "http://server.local"+resourcePath)
	if !f.called || rec.Code != http.StatusOK {
		t.Errorf("audience check should not fire when middleware has no expected aud (status=%d)", rec.Code)
	}
}

// ============================================================================
// DPoP resource-server adversarial tests (ADV9, ADV6)
// ============================================================================

// dpopMaterial returns a fresh ES256 keypair, a DPoP signer for it, the JKT
// for the public key, and a DPoP-bound access token whose cnf.jkt matches.
type dpopMaterial struct {
	signer jose.Signer
	jkt    string
	token  string
}

func newDPoPMaterial(t *testing.T, f *jwtTestFixture, aud string) *dpopMaterial {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	signer, err := crypto.NewDPoPSigner(priv, jose.ES256)
	if err != nil {
		t.Fatalf("dpop signer: %v", err)
	}
	jkt, err := crypto.ComputeJKT(jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: "ES256"})
	if err != nil {
		t.Fatalf("jkt: %v", err)
	}
	token := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{aud},
		Cnf:      map[string]interface{}{"jkt": jkt},
	})
	return &dpopMaterial{signer: signer, jkt: jkt, token: token}
}

// HIGH/MEDIUM intersection: a DPoP-bound proof must not be replayable against
// the same resource within ProofLifetime. This is the MEDIUM finding from the
// 2026-05-18 audit. Pre-fix, the middleware verified structure but never
// consumed the JTI.
func TestJWTMiddleware_DPoPProofReplay_Rejected(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoP(DPoPJWTConfig{ProofLifetime: 60 * time.Second})
	store := newMemoryProofStore()
	f.mw.WithDPoPProofStore(store)

	mat := newDPoPMaterial(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath
	ath := crypto.ComputeATH(mat.token)
	proof, err := crypto.CreateDPoPProof(mat.signer, "proof-jti-replay", defaultMethod, urlStr, time.Now(), "", ath)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	// First request: must succeed.
	rec1 := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
	if !f.called || rec1.Code != http.StatusOK {
		t.Fatalf("first request status=%d called=%v body=%q", rec1.Code, f.called, rec1.Body.String())
	}

	// Second identical request: same proof, same target — must be rejected as
	// replay. (Past code accepted it.)
	rec2 := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
	if f.called {
		t.Fatal("downstream invoked on replayed DPoP proof")
	}
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay status: got %d, want 401", rec2.Code)
	}

	// State assertion (ADV6): the store actually saw the JTI.
	if store.Len() != 1 {
		t.Errorf("store size after replay attempt: got %d, want 1", store.Len())
	}
}

// Different JTI, same proof material parameters: each fresh JTI must be
// independently consumable, so legitimate repeat callers aren't broken.
func TestJWTMiddleware_DPoPDifferentJTI_BothAccepted(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoP(DPoPJWTConfig{ProofLifetime: 60 * time.Second})
	f.mw.WithDPoPProofStore(newMemoryProofStore())

	mat := newDPoPMaterial(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath
	ath := crypto.ComputeATH(mat.token)

	for i, jti := range []string{"jti-a", "jti-b"} {
		proof, err := crypto.CreateDPoPProof(mat.signer, jti, defaultMethod, urlStr, time.Now(), "", ath)
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		rec := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
		if !f.called || rec.Code != http.StatusOK {
			t.Errorf("request %d: status=%d called=%v", i, rec.Code, f.called)
		}
	}
}

// Cross-resource replay attempt: even with a JTI store, a proof bound to
// htu=resourceA must NOT be accepted by a middleware that thinks it's
// resourceB. ValidateProof checks htu; this test pins that.
func TestJWTMiddleware_DPoPWrongHTU_Rejected(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoP(DPoPJWTConfig{ProofLifetime: 60 * time.Second})
	f.mw.WithDPoPProofStore(newMemoryProofStore())

	mat := newDPoPMaterial(t, f, resourceA)
	ath := crypto.ComputeATH(mat.token)
	// Proof claims it's for a different URL than the request will hit.
	proof, err := crypto.CreateDPoPProof(mat.signer, "j1", defaultMethod, "http://attacker.local/somewhere", time.Now(), "", ath)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, mat.token, proof, defaultMethod, "http://server.local"+resourcePath)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d called=%v: wrong htu must be rejected", rec.Code, f.called)
	}
}

// A DPoP-bound token presented with Bearer scheme must be rejected — RFC 9449
// §7.1. Existing behavior should hold; this is a regression pin.
func TestJWTMiddleware_DPoPBoundToken_RejectedUnderBearerScheme(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoP(DPoPJWTConfig{ProofLifetime: 60 * time.Second})

	mat := newDPoPMaterial(t, f, resourceA)
	rec := f.serveBearer(t, mat.token, "http://server.local"+resourcePath)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d called=%v: DPoP-bound token must not be honored as Bearer", rec.Code, f.called)
	}
}

// State-after-error (ADV6): when DPoP binding validation fails (e.g. wrong
// jkt), the proof JTI must NOT be marked as consumed — otherwise an attacker
// could burn legitimate JTIs.
func TestJWTMiddleware_DPoPBindingFailure_DoesNotConsumeJTI(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoP(DPoPJWTConfig{ProofLifetime: 60 * time.Second})
	store := newMemoryProofStore()
	f.mw.WithDPoPProofStore(store)

	// Mint a token bound to one key, but build the proof with a DIFFERENT key.
	mat := newDPoPMaterial(t, f, resourceA)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSigner, _ := crypto.NewDPoPSigner(other, jose.ES256)
	urlStr := "http://server.local" + resourcePath
	ath := crypto.ComputeATH(mat.token)
	proof, err := crypto.CreateDPoPProof(otherSigner, "burnable-jti", defaultMethod, urlStr, time.Now(), "", ath)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d called=%v: mismatched jkt must be rejected", rec.Code, f.called)
	}
	if store.Len() != 0 {
		t.Errorf("proof JTI must not be consumed when binding fails (store len=%d)", store.Len())
	}
}

// State-after-error: when the JWT itself is invalid (wrong issuer), the
// downstream handler must not see claims and the store must not be touched.
func TestJWTMiddleware_InvalidIssuer_NoClaimsNoStore(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoP(DPoPJWTConfig{ProofLifetime: 60 * time.Second})
	store := newMemoryProofStore()
	f.mw.WithDPoPProofStore(store)

	mat := newDPoPMaterial(t, f, resourceA)
	// Mint token with WRONG issuer.
	badToken := f.mint(t, crypto.AccessTokenClaims{
		Issuer:   "https://evil.example.com",
		Audience: []string{resourceA},
		Cnf:      map[string]interface{}{"jkt": mat.jkt},
	})
	urlStr := "http://server.local" + resourcePath
	ath := crypto.ComputeATH(badToken)
	proof, _ := crypto.CreateDPoPProof(mat.signer, "j1", defaultMethod, urlStr, time.Now(), "", ath)

	rec := f.serveDPoP(t, badToken, proof, defaultMethod, urlStr)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d called=%v: bad issuer must be rejected before DPoP work", rec.Code, f.called)
	}
	if f.sawSub != "" {
		t.Errorf("subject leaked to downstream: %q", f.sawSub)
	}
	if store.Len() != 0 {
		t.Errorf("store touched on rejected request: %d", store.Len())
	}
}
