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

// staticIssuerForTest satisfies output.IssuerProvider for unit tests without
// importing internal/adapters/static (preserves consistency with integration
// test conventions).
type staticIssuerForTest string

func (s staticIssuerForTest) Issuer(_ context.Context) (string, error) { return string(s), nil }

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

// newTestKeyAndJWKS returns a fresh ES256 signing key and the single-key JWKS
// that verifies tokens minted with it.
func newTestKeyAndJWKS(t *testing.T) (*crypto.KeyPair, jose.JSONWebKeySet) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair("ES256", "test-kid")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return kp, jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       kp.PublicKey,
			KeyID:     kp.KeyID,
			Algorithm: "ES256",
			Use:       "sig",
		}},
	}
}

func newJWTFixture(t *testing.T) *jwtTestFixture {
	t.Helper()

	kp, jwks := newTestKeyAndJWKS(t)
	mw := NewJWTMiddleware(&staticJWKS{set: jwks}, staticIssuerForTest(testIssuer), observability.NewNoop())

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
	NewResourceJWTMiddleware(jwks, staticIssuerForTest(testIssuer), "", newMemoryProofStore(), DPoPJWTConfig{ProofLifetime: time.Minute}, observability.NewNoop())
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
	NewResourceJWTMiddleware(jwks, staticIssuerForTest(testIssuer), resourceA, nil, DPoPJWTConfig{ProofLifetime: time.Minute}, observability.NewNoop())
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
	mw := NewResourceJWTMiddleware(jwks, staticIssuerForTest(testIssuer), resourceA, newMemoryProofStore(), DPoPJWTConfig{ProofLifetime: time.Minute}, observability.NewNoop())

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

// ============================================================================
// Zero DPoPJWTConfig — enforcement is token-intrinsic (AUD-12)
// ============================================================================
//
// The audit's finding was a godoc that claimed a zero dpopCfg yields a
// "Bearer-only resource" with DPoP enforcement disabled. It never did: the
// proof is required because the token carries cnf.jkt, not because dpopCfg
// says so. These tests exist so that a future attempt to make the code match
// that retracted comment fails CI instead of shipping a real bypass.

// newZeroDPoPFixture builds the middleware through NewResourceJWTMiddleware
// with a zero DPoPJWTConfig — precisely the configuration an operator would
// reach for believing it turns DPoP off.
func newZeroDPoPFixture(t *testing.T) (*jwtTestFixture, *memoryProofStore) {
	t.Helper()

	kp, jwks := newTestKeyAndJWKS(t)
	store := newMemoryProofStore()
	mw := NewResourceJWTMiddleware(
		&staticJWKS{set: jwks},
		staticIssuerForTest(testIssuer),
		resourceA,
		store,
		DPoPJWTConfig{}, // the zero value under test
		observability.NewNoop(),
	)

	f := &jwtTestFixture{kp: kp, mw: mw}
	f.handler = mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.called = true
		if c, ok := ClaimsFromContext(r.Context()); ok {
			f.sawSub = c.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))
	return f, store
}

// The load-bearing assertion: a bound token with no proof at all is rejected
// even though dpopCfg is the zero value. If someone gates the
// crypto.IsDPoPBound branch on m.dpop, this request starts returning 200 and
// the bypass is live.
func TestJWTMiddleware_ZeroDPoPConfig_BoundTokenStillRequiresProof(t *testing.T) {
	f, store := newZeroDPoPFixture(t)
	mat := newDPoPMaterial(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath

	// DPoP scheme, but no DPoP proof header.
	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
	req.Header.Set("Authorization", "DPoP "+mat.token)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if f.called {
		t.Fatal("downstream invoked for a DPoP-bound token with no proof — DPoP enforcement is not token-intrinsic anymore")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if store.Len() != 0 {
		t.Errorf("store touched on rejected request: %d", store.Len())
	}
}

// The availability surprise the audit called out, pinned as intended
// behavior: presenting a bound token under Bearer is rejected, not honored.
func TestJWTMiddleware_ZeroDPoPConfig_BoundTokenRejectedUnderBearer(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	mat := newDPoPMaterial(t, f, resourceA)

	rec := f.serveBearer(t, mat.token, "http://server.local"+resourcePath)

	if f.called {
		t.Fatal("downstream invoked for a DPoP-bound token presented as Bearer")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}

// A zero dpopCfg means "60s default lifetime", not "no freshness check": a
// valid proof is accepted, and its JTI is consumed, so replay protection is on
// without the operator configuring anything.
func TestJWTMiddleware_ZeroDPoPConfig_ValidProofAcceptedAndJTIConsumed(t *testing.T) {
	f, store := newZeroDPoPFixture(t)
	mat := newDPoPMaterial(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath
	ath := crypto.ComputeATH(mat.token)

	proof, err := crypto.CreateDPoPProof(mat.signer, "zero-cfg-jti", defaultMethod, urlStr, time.Now(), "", ath)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
	if !f.called || rec.Code != http.StatusOK {
		t.Fatalf("valid proof rejected under zero dpopCfg: status=%d called=%v body=%q", rec.Code, f.called, rec.Body.String())
	}
	if store.Len() != 1 {
		t.Errorf("JTI not consumed under zero dpopCfg: store size %d, want 1", store.Len())
	}

	// Same proof again — replay must still be caught.
	rec2 := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
	if f.called || rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay accepted under zero dpopCfg: status=%d called=%v", rec2.Code, f.called)
	}
}

// The 60-second default is a real window, not an absent check: a proof issued
// well outside it is rejected.
func TestJWTMiddleware_ZeroDPoPConfig_StaleProofRejected(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	mat := newDPoPMaterial(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath
	ath := crypto.ComputeATH(mat.token)

	stale, err := crypto.CreateDPoPProof(mat.signer, "stale-jti", defaultMethod, urlStr, time.Now().Add(-90*time.Second), "", ath)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, mat.token, stale, defaultMethod, urlStr)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("stale proof accepted under the 60s default: status=%d called=%v", rec.Code, f.called)
	}
}

// AUD-12 acceptance criterion 4: the tokenless 401 advertises DPoP even with a
// zero dpopCfg. Answering "Bearer" alone would send a DPoP-bound client down a
// path this resource then rejects.
func TestJWTMiddleware_ZeroDPoPConfig_TokenlessChallengeAdvertisesDPoP(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)

	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, "http://server.local"+resourcePath, nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	// One field line carrying both challenges, not two. A client reading this
	// with a first-value-wins accessor must still see DPoP — splitting them
	// across lines would hide it from exactly the parsers this change targets,
	// so assert the single-line encoding rather than merely the presence.
	challenges := rec.Header().Values("WWW-Authenticate")
	if len(challenges) != 1 {
		t.Fatalf("tokenless challenge spread over %d field lines (%q); want 1 so first-value-wins parsers see both", len(challenges), challenges)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer, DPoP" {
		t.Errorf("tokenless challenge: got %q, want %q", got, "Bearer, DPoP")
	}
}

// ============================================================================
// The DPoP scheme itself demands a proof
// ============================================================================
//
// Advertising DPoP in the challenge to every client makes this reachable in
// normal operation: a client that follows the challenge and holds a token the
// AS chose not to bind will present Authorization: DPoP. Accepting that with
// no proof would have the resource ignore, in silence, the very scheme it
// advertises as proof-carrying.

// newUnboundDPoPCaller returns a DPoP signer and an access token WITHOUT
// cnf.jkt — the combination the review found slipping through.
func newUnboundDPoPCaller(t *testing.T, f *jwtTestFixture, aud string) (jose.Signer, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	signer, err := crypto.NewDPoPSigner(priv, jose.ES256)
	if err != nil {
		t.Fatalf("dpop signer: %v", err)
	}
	return signer, f.mint(t, crypto.AccessTokenClaims{Audience: []string{aud}})
}

func TestJWTMiddleware_DPoPScheme_UnboundTokenRequiresProof(t *testing.T) {
	f, store := newZeroDPoPFixture(t)
	_, tok := newUnboundDPoPCaller(t, f, resourceA)

	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, "http://server.local"+resourcePath, nil)
	req.Header.Set("Authorization", "DPoP "+tok) // DPoP scheme, no DPoP proof header
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if f.called {
		t.Fatal("downstream invoked for a DPoP-scheme request with no proof")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if store.Len() != 0 {
		t.Errorf("store touched on rejected request: %d", store.Len())
	}
}

// A valid proof is honored even with nothing to bind it to, so a client that
// follows the challenge is not locked out.
func TestJWTMiddleware_DPoPScheme_UnboundTokenWithValidProofAccepted(t *testing.T) {
	f, store := newZeroDPoPFixture(t)
	signer, tok := newUnboundDPoPCaller(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath

	proof, err := crypto.CreateDPoPProof(signer, "unbound-jti", defaultMethod, urlStr, time.Now(), "", crypto.ComputeATH(tok))
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, tok, proof, defaultMethod, urlStr)
	if !f.called || rec.Code != http.StatusOK {
		t.Fatalf("valid proof rejected for an unbound token: status=%d called=%v body=%q", rec.Code, f.called, rec.Body.String())
	}
	if store.Len() != 1 {
		t.Errorf("JTI not consumed: store size %d, want 1", store.Len())
	}
}

// The proof is validated, not merely required: a stale one is refused.
func TestJWTMiddleware_DPoPScheme_UnboundTokenStaleProofRejected(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	signer, tok := newUnboundDPoPCaller(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath

	stale, err := crypto.CreateDPoPProof(signer, "unbound-stale", defaultMethod, urlStr, time.Now().Add(-90*time.Second), "", crypto.ComputeATH(tok))
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, tok, stale, defaultMethod, urlStr)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("stale proof accepted for an unbound token: status=%d called=%v", rec.Code, f.called)
	}
}

// Regression guard on the blast radius: the Bearer path for an unbound token
// is untouched — no proof is demanded of a caller that never claimed to have
// one.
func TestJWTMiddleware_BearerScheme_UnboundTokenUnaffected(t *testing.T) {
	f, store := newZeroDPoPFixture(t)
	_, tok := newUnboundDPoPCaller(t, f, resourceA)

	rec := f.serveBearer(t, tok, "http://server.local"+resourcePath)
	if !f.called || rec.Code != http.StatusOK {
		t.Fatalf("plain Bearer request broken: status=%d called=%v body=%q", rec.Code, f.called, rec.Body.String())
	}
	if store.Len() != 0 {
		t.Errorf("Bearer request touched the DPoP store: %d", store.Len())
	}
}

// ============================================================================
// The DPoP-failure challenge names what actually works
// ============================================================================

// An unbound token that fails the DPoP path can still get in under Bearer, and
// the challenge has to say so. Naming DPoP alone sends the caller back to the
// scheme that just failed — the same advertisement-vs-behavior dead end the
// tokenless challenge exists to close.
func TestJWTMiddleware_DPoPFailure_UnboundTokenIsOfferedBearer(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	_, tok := newUnboundDPoPCaller(t, f, resourceA)

	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, "http://server.local"+resourcePath, nil)
	req.Header.Set("Authorization", "DPoP "+tok) // DPoP scheme, no proof
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	challenges := rec.Header().Values("WWW-Authenticate")
	if len(challenges) != 1 {
		t.Fatalf("challenge spread over %d field lines (%q); want 1", len(challenges), challenges)
	}
	got := challenges[0]
	if !strings.Contains(got, "Bearer ") {
		t.Errorf("challenge %q: want Bearer offered, since this token works under it", got)
	}
	if !strings.Contains(got, "DPoP ") {
		t.Errorf("challenge %q: want DPoP named too", got)
	}
}

// RFC 6750 §3: a request that presented a token and failed SHOULD carry the
// error attribute. Naming Bearer without one tells a client library nothing,
// and it is the attribute they read to choose between refreshing the token and
// starting authorization over.
func TestJWTMiddleware_TwoSchemeChallenge_BothCarryTheirErrorCode(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	urlStr := "http://server.local" + resourcePath
	_, unbound := newUnboundDPoPCaller(t, f, resourceA)

	dpopNoProof := func(tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		return rec
	}

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"invalid token":    f.serveBearer(t, "not-a-jwt", urlStr),
		"unbound no proof": dpopNoProof(unbound),
	} {
		got := challengeOf(t, rec)
		for _, part := range strings.Split(got, ",") {
			part = strings.TrimSpace(part)
			scheme, params, _ := strings.Cut(part, " ")
			if scheme != "Bearer" && scheme != "DPoP" {
				t.Fatalf("%s: unexpected part %q in %q", name, part, got)
			}
			if !strings.Contains(params, "error=") {
				t.Errorf("%s: %q challenge carries no error attribute in %q", name, scheme, got)
			}
		}
	}
}

// A DPoP-specific code must not appear on a Bearer challenge, whose parameter
// vocabulary RFC 6750 defines, and a proof fault must not be reported as a
// token fault — the client would fetch a new token instead of re-signing.
func TestJWTMiddleware_ErrorCodeMatchesTheScheme(t *testing.T) {
	urlStr := "http://server.local" + resourcePath

	t.Run("invalid proof is invalid_dpop_proof on DPoP, invalid_token on Bearer", func(t *testing.T) {
		f, _ := newZeroDPoPFixture(t)
		_, tok := newUnboundDPoPCaller(t, f, resourceA)
		req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)

		got := challengeOf(t, rec)
		if !strings.Contains(got, `Bearer error="invalid_token"`) {
			t.Errorf("challenge %q: Bearer must carry an RFC 6750 code", got)
		}
		if !strings.Contains(got, `DPoP error="invalid_dpop_proof"`) {
			t.Errorf("challenge %q: a proof fault is invalid_dpop_proof (RFC 9449 §7.1)", got)
		}
	})

	// RFC 9449 §7.2: a bound token presented as a bearer token is rejected per
	// RFC 6750, so the code is invalid_token — nothing is wrong with the proof.
	t.Run("wrong scheme is invalid_token, not a proof fault", func(t *testing.T) {
		f, _ := newZeroDPoPFixture(t)
		mat := newDPoPMaterial(t, f, resourceA)
		rec := f.serveBearer(t, mat.token, urlStr)

		got := challengeOf(t, rec)
		if !strings.Contains(got, `error="invalid_token"`) {
			t.Errorf("challenge %q: want invalid_token for a scheme mismatch", got)
		}
		if strings.Contains(got, "invalid_dpop_proof") {
			t.Errorf("challenge %q blames the proof for a scheme mismatch", got)
		}
	})

	t.Run("the body carries the same code as the challenge", func(t *testing.T) {
		f, _ := newZeroDPoPFixture(t)
		_, tok := newUnboundDPoPCaller(t, f, resourceA)
		req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)

		if !strings.Contains(rec.Body.String(), `"error":"invalid_dpop_proof"`) {
			t.Errorf("body %q disagrees with the DPoP challenge code", rec.Body.String())
		}
	})
}

// The mirror case, and the one that keeps the fix honest: a bound token has no
// Bearer option, so offering it would be a new lie in the other direction.
func TestJWTMiddleware_DPoPFailure_BoundTokenIsNotOfferedBearer(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	mat := newDPoPMaterial(t, f, resourceA)

	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, "http://server.local"+resourcePath, nil)
	req.Header.Set("Authorization", "DPoP "+mat.token) // bound, no proof
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); strings.Contains(got, "Bearer") {
		t.Errorf("challenge %q offers Bearer for a DPoP-bound token, which the middleware rejects", got)
	}
}

// The 401 body reaches the client verbatim, and this branch now serves unbound
// tokens too — so it must not tell an operator their token carries cnf.jkt.
func TestJWTMiddleware_DPoPFailure_UnboundTokenErrorDoesNotClaimBinding(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	_, tok := newUnboundDPoPCaller(t, f, resourceA)

	req := httptest.NewRequestWithContext(context.Background(), defaultMethod, "http://server.local"+resourcePath, nil)
	req.Header.Set("Authorization", "DPoP "+tok)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if body := rec.Body.String(); strings.Contains(body, "DPoP-bound") {
		t.Errorf("401 body %q asserts the token is DPoP-bound; it is not", body)
	}
}

// The two public entry points must give the same zero value the same meaning.
// WithDPoP once stored it verbatim, pinning the window to zero and rejecting
// every proof while the challenge still advertised DPoP — a compliant client
// sending a perfectly fresh proof could never get in.
func TestJWTMiddleware_WithDPoPZeroValue_FallsBackToDefault(t *testing.T) {
	f := newJWTFixture(t)
	f.mw.WithAudience(resourceA)
	f.mw.WithDPoPProofStore(newMemoryProofStore())
	f.mw.WithDPoP(DPoPJWTConfig{}) // stored verbatim: ProofLifetime == 0

	mat := newDPoPMaterial(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath
	proof, err := crypto.CreateDPoPProof(mat.signer, "withdpop-zero", defaultMethod, urlStr, time.Now(), "", crypto.ComputeATH(mat.token))
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, mat.token, proof, defaultMethod, urlStr)
	if !f.called || rec.Code != http.StatusOK {
		t.Errorf("WithDPoP(DPoPJWTConfig{}) rejected a fresh proof: status=%d called=%v body=%q — it must normalise to the 60s default like NewResourceJWTMiddleware", rec.Code, f.called, rec.Body.String())
	}
}

// ============================================================================
// Every 401 names the schemes that would work, not just the tokenless one
// ============================================================================

// challengeOf returns the single WWW-Authenticate field line, failing the test
// if the response carries none or splits them across lines.
func challengeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	v := rec.Header().Values("WWW-Authenticate")
	if len(v) != 1 {
		t.Fatalf("challenge spread over %d field lines (%q); want exactly 1", len(v), v)
	}
	return v[0]
}

// The branch a DPoP client hits most: its bound token merely expired. Telling
// it "Bearer" sends it to refresh, retry under Bearer, and be rejected for
// using Bearer — the dead end this middleware exists to close, on the most
// traveled of the four 401 paths.
func TestJWTMiddleware_ExpiredToken_ChallengeStillNamesDPoP(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	expired := f.mint(t, crypto.AccessTokenClaims{
		Audience: []string{resourceA},
		IssuedAt: time.Now().Add(-2 * time.Hour).Unix(),
		Expiry:   time.Now().Add(-time.Hour).Unix(),
	})

	rec := f.serveBearer(t, expired, "http://server.local"+resourcePath)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token: status=%d called=%v", rec.Code, f.called)
	}
	if got := challengeOf(t, rec); !strings.Contains(got, "DPoP") {
		t.Errorf("challenge %q omits DPoP; a DPoP client cannot tell which scheme to retry with", got)
	}
}

// Audience mismatch is the one branch where the token verified, so boundness
// is known and the challenge can be exact.
func TestJWTMiddleware_AudienceMismatch_ChallengeMatchesBoundness(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bound      bool
		wantBearer bool
	}{
		{"unbound token keeps its Bearer option", false, true},
		{"bound token is never offered Bearer", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newZeroDPoPFixture(t) // configured for resourceA
			claims := crypto.AccessTokenClaims{Audience: []string{resourceB}}
			if tc.bound {
				claims.Cnf = map[string]interface{}{"jkt": "some-thumbprint"}
			}
			tok := f.mint(t, claims)

			rec := f.serveBearer(t, tok, "http://server.local"+resourcePath)
			if f.called || rec.Code != http.StatusUnauthorized {
				t.Fatalf("cross-audience token: status=%d called=%v", rec.Code, f.called)
			}
			got := challengeOf(t, rec)
			if !strings.Contains(got, "DPoP") {
				t.Errorf("challenge %q omits DPoP", got)
			}
			if hasBearer := strings.Contains(got, "Bearer"); hasBearer != tc.wantBearer {
				t.Errorf("challenge %q: Bearer present=%v, want %v", got, hasBearer, tc.wantBearer)
			}
		})
	}
}

// A client that simply splits WWW-Authenticate on "," must still recover the
// correct set of schemes. A trailing auth-param fragment it does not recognize
// is tolerable; a missing or unknown scheme is not. This is the invariant that
// lets a single-scheme line carry error_description while a two-scheme line
// may not.
func TestJWTMiddleware_Challenges_SurviveNaiveCommaSplit(t *testing.T) {
	f, _ := newZeroDPoPFixture(t)
	_, unboundTok := newUnboundDPoPCaller(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath

	dpopNoProof := func(tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		return rec
	}

	cases := []struct {
		name string
		rec  *httptest.ResponseRecorder
		want []string
	}{
		{"tokenless", dpopNoProof(""), []string{"Bearer", "DPoP"}},
		{"invalid token", f.serveBearer(t, "not-a-jwt", urlStr), []string{"Bearer", "DPoP"}},
		{"unbound, no proof", dpopNoProof(unboundTok), []string{"Bearer", "DPoP"}},
		{"bound under Bearer", f.serveBearer(t, newDPoPMaterial(t, f, resourceA).token, urlStr), []string{"DPoP"}},
	}

	for _, tc := range cases {
		got := challengeOf(t, tc.rec)
		var schemes []string
		for _, part := range strings.Split(got, ",") {
			head, _, _ := strings.Cut(strings.TrimSpace(part), " ")
			if strings.Contains(head, "=") {
				continue // an auth-param fragment, not a scheme
			}
			schemes = append(schemes, head)
		}
		if strings.Join(schemes, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: challenge %q splits to schemes %v, want %v", tc.name, got, schemes, tc.want)
		}
	}
}

// A single-scheme challenge carries the actual reason, not a fixed string: this
// branch is reachable through several causes, and naming the wrong one sends
// the caller to the wrong fix. A two-scheme challenge carries none, so the
// naive-split invariant above holds.
func TestJWTMiddleware_Challenge_DescriptionIsCauseSpecific(t *testing.T) {
	urlStr := "http://server.local" + resourcePath

	t.Run("bound token under Bearer names the scheme problem", func(t *testing.T) {
		f, _ := newZeroDPoPFixture(t)
		mat := newDPoPMaterial(t, f, resourceA)
		rec := f.serveBearer(t, mat.token, urlStr)
		if got := challengeOf(t, rec); !strings.Contains(got, `error_description="DPoP-bound token must use DPoP authorization scheme"`) {
			t.Errorf("challenge %q does not name the scheme mismatch", got)
		}
	})

	t.Run("bound token without a proof names the missing header", func(t *testing.T) {
		f, _ := newZeroDPoPFixture(t)
		mat := newDPoPMaterial(t, f, resourceA)
		req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
		req.Header.Set("Authorization", "DPoP "+mat.token)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if got := challengeOf(t, rec); !strings.Contains(got, "proof header required") {
			t.Errorf("challenge %q does not name the missing proof header", got)
		}
	})

	t.Run("two-scheme challenge carries no description", func(t *testing.T) {
		f, _ := newZeroDPoPFixture(t)
		_, tok := newUnboundDPoPCaller(t, f, resourceA)
		req := httptest.NewRequestWithContext(context.Background(), defaultMethod, urlStr, nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if got := challengeOf(t, rec); strings.Contains(got, "error_description") {
			t.Errorf("challenge %q carries a description on a two-scheme line", got)
		}
	})
}

// Error text reaches the header, so it must not be able to break out of the
// quoted-string or pad the response.
func TestSanitizeChallengeText(t *testing.T) {
	if got := sanitizeChallengeText(`he said "hi"` + "\r\nX-Evil: 1"); strings.ContainsAny(got, "\"\r\n") {
		t.Errorf("sanitize left a quote or control character: %q", got)
	}
	if got := sanitizeChallengeText(strings.Repeat("a", 500)); len(got) > 160 {
		t.Errorf("sanitize returned %d bytes; want it bounded", len(got))
	}
}

// A caller-chosen JTI must not become an unbounded key in a store shared with
// the token endpoint.
func TestJWTMiddleware_OversizedProofJTI_Rejected(t *testing.T) {
	f, store := newZeroDPoPFixture(t)
	signer, tok := newUnboundDPoPCaller(t, f, resourceA)
	urlStr := "http://server.local" + resourcePath

	huge := strings.Repeat("A", maxDPoPProofJTILen+1)
	proof, err := crypto.CreateDPoPProof(signer, huge, defaultMethod, urlStr, time.Now(), "", crypto.ComputeATH(tok))
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	rec := f.serveDPoP(t, tok, proof, defaultMethod, urlStr)
	if f.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("oversized jti accepted: status=%d called=%v", rec.Code, f.called)
	}
	if store.Len() != 0 {
		t.Errorf("oversized jti reached the store: %d entries", store.Len())
	}
}
