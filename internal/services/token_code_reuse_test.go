//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"

	"go.opentelemetry.io/otel/attribute"
)

const mCodeReuse = "authserver_auth_code_reuse_total"

// codeReuseFixture is a token service wired like production, with the
// code-reuse counters readable and the audit sink captured.
type codeReuseFixture struct {
	setup   *tokenTestSetup
	metrics *reuseMetrics
}

func newCodeReuseFixture(t *testing.T) *codeReuseFixture {
	t.Helper()
	obs := observability.NewNoop()
	m := newReuseMetrics(t, obs)
	setup := newTokenTestSetupWithOverrides(t, static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}), tokenTestOverrides{obs: obs})
	setup.tokenSvc.WithTokenTransactions(setup.h.Stores.TransactionMgr)
	return &codeReuseFixture{setup: setup, metrics: m}
}

// newCodeReuseFixtureWithFailures builds the fixture over the same sqlite
// stores the failing wrappers were built from, so wrapper and service share
// one database.
func newCodeReuseFixtureWithFailures(t *testing.T, wrapTokens, wrapRevocation bool) *codeReuseFixture {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := observability.NewNoop()
	m := newReuseMetrics(t, obs)

	ov := tokenTestOverrides{stores: stores, obs: obs}
	if wrapTokens {
		ov.tokens = &failingRevokeFamilyStore{stores.Token}
	}
	if wrapRevocation {
		ov.revocation = &failingRevokeByFamilyStore{stores.Revocation}
	}
	setup := newTokenTestSetupWithOverrides(t, static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}), ov)
	setup.tokenSvc.WithTokenTransactions(stores.TransactionMgr)
	return &codeReuseFixture{setup: setup, metrics: m}
}

// replay redeems a fresh code once, then replays it with the given verifier.
// Returns the replay error.
func (f *codeReuseFixture) replay(t *testing.T, replayVerifier func(correct string) string) error {
	t.Helper()
	ctx := context.Background()
	c, _, code, verifier := f.setup.createSessionWithCode(t, true)

	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: verifier,
	}); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	_, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     c.ID,
		CodeVerifier: replayVerifier(verifier),
	})
	return err
}

func TestCodeReuse_CountsAndAuditsEveryReplay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verifier func(correct string) string
		want     string
	}{
		{"valid verifier", func(correct string) string { return correct }, "valid"},
		{"invalid verifier", func(string) string { return crypto.GenerateVerifier() }, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeReuseFixture(t)

			err := f.replay(t, tc.verifier)
			if !errors.Is(err, domain.ErrCodeConsumed) {
				t.Fatalf("replay: got %v, want ErrCodeConsumed", err)
			}

			got := f.metrics.valueWith(t, mCodeReuse, []attribute.KeyValue{
				attribute.String("verifier", tc.want),
			})
			if got != 1 {
				t.Errorf("%s{verifier=%q}: got %d, want 1", mCodeReuse, tc.want, got)
			}

			if !hasAuditDetail(t, f.setup, "auth_code.reused", "verifier="+tc.want) {
				t.Errorf("no auth_code.reused audit row with verifier=%s", tc.want)
			}
		})
	}
}

// hasAuditDetail reports whether an audit row with the given action exists
// whose detail contains want. AuditService.Record is synchronous, so there is
// nothing to flush.
func hasAuditDetail(t *testing.T, setup *tokenTestSetup, action, want string) bool {
	t.Helper()
	events, err := setup.h.Stores.Audit.Query(context.Background(), output.AuditFilter{
		Action: action,
		Limit:  100,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	for _, e := range events {
		if strings.Contains(e.Detail, want) {
			return true
		}
	}
	return false
}

func TestCodeReuse_ValidVerifierRevokesTheFamily(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()
	c, sess, code, verifier := f.setup.createSessionWithCode(t, true)

	resp, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	if _, err = f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("replay: got %v, want ErrCodeConsumed", err)
	}

	fam, err := f.setup.h.Stores.Token.GetFamilyByAuthSessionID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if fam.IsActive() {
		t.Error("family is still active after a credentialed replay")
	}

	// The refresh token issued at the first redemption must no longer rotate.
	if _, err := f.setup.tokenSvc.RefreshToken(ctx, input.RefreshTokenRequest{
		RefreshToken: resp.RefreshToken, ClientID: c.ID,
	}); err == nil {
		t.Error("the revoked family's refresh token still rotates")
	}
}

func TestCodeReuse_InvalidVerifierRevokesNothing(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()
	c, sess, code, verifier := f.setup.createSessionWithCode(t, true)

	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: crypto.GenerateVerifier(),
	}); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatal("replay did not answer ErrCodeConsumed")
	}

	fam, err := f.setup.h.Stores.Token.GetFamilyByAuthSessionID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if !fam.IsActive() {
		t.Error("an uncredentialed replay revoked the family — that is the DoS " +
			"the verifier gate exists to prevent (token-design-internals.md " +
			"§ authorization-code reuse detection)")
	}
}

// TestCodeReuse_ClientIDMismatchRevokesNothing covers the second half of the
// revocation gate. This replayer holds the session's genuine verifier but
// presents a different client_id, so it could never have redeemed this code
// either, and revoking on its say-so would be the same credential-free logout
// button the verifier half exists to deny.
//
// Every other test in this file replays as the session's own client, so
// dropping the clientID == sess.ClientID conjunct passes all of them.
func TestCodeReuse_ClientIDMismatchRevokesNothing(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()
	c, sess, code, verifier := f.setup.createSessionWithCode(t, true)

	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// Correct verifier, wrong client. handleCodeReuse runs off the consume at
	// step 1, ahead of the client_id check at step 3, so the replay reaches
	// the gate rather than being turned away as invalid_client.
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID + "-impostor", CodeVerifier: verifier,
	}); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatal("replay did not answer ErrCodeConsumed")
	}

	fam, err := f.setup.h.Stores.Token.GetFamilyByAuthSessionID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if !fam.IsActive() {
		t.Error("a replay presenting a different client_id revoked the family")
	}

	// The mismatch folds into verifier="invalid" instead of earning a third
	// label value, so dashboards built on valid|invalid keep their meaning.
	if got := f.metrics.valueWith(t, mCodeReuse, []attribute.KeyValue{
		attribute.String("verifier", "invalid"),
	}); got != 1 {
		t.Errorf("%s{verifier=%q}: got %d, want 1", mCodeReuse, "invalid", got)
	}
}

// TestCodeReuse_RevokesOnlyTheReplayedFamily is AC1: two live families for the
// same (client, user, scope, resource). Replaying one code must not touch the
// other — the proof that the link is a real code→family reference and not a
// heuristic join on the shared attributes.
func TestCodeReuse_RevokesOnlyTheReplayedFamily(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()

	cA, sessA, codeA, verA := f.setup.createSessionWithCode(t, true)
	sessB, codeB, verB := f.secondSessionForClient(t, sessA)

	for _, x := range []struct{ code, verifier string }{
		{codeA, verA},
		{codeB, verB},
	} {
		if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
			Code: x.code, RedirectURI: "https://app.example.com/callback",
			ClientID: cA.ID, CodeVerifier: x.verifier,
		}); err != nil {
			t.Fatalf("exchange: %v", err)
		}
	}

	famA, err := f.setup.h.Stores.Token.GetFamilyByAuthSessionID(ctx, sessA.ID)
	if err != nil {
		t.Fatalf("get family A: %v", err)
	}
	famB, err := f.setup.h.Stores.Token.GetFamilyByAuthSessionID(ctx, sessB.ID)
	if err != nil {
		t.Fatalf("get family B: %v", err)
	}
	if famA.ID == famB.ID {
		t.Fatalf("the two redemptions shared a family (%s) — the test proves nothing", famA.ID)
	}

	// Replay only A.
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: codeA, RedirectURI: "https://app.example.com/callback",
		ClientID: cA.ID, CodeVerifier: verA,
	}); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatal("replay did not answer ErrCodeConsumed")
	}

	gotA, err := f.setup.h.Stores.Token.GetFamily(ctx, famA.ID)
	if err != nil {
		t.Fatalf("get family A after replay: %v", err)
	}
	gotB, err := f.setup.h.Stores.Token.GetFamily(ctx, famB.ID)
	if err != nil {
		t.Fatalf("get family B after replay: %v", err)
	}
	if gotA.IsActive() {
		t.Error("family A survived its own code's replay")
	}
	if !gotB.IsActive() {
		t.Error("family B was revoked by a replay of a different code — over-revocation")
	}
}

func TestCodeReuse_HalfFailuresReportThemselves(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wrapTokens bool
		wrapRevoke bool
		wantHalf   string
		wantAction string
	}{
		{"family half down", true, false, "family", "family.revocation_failed"},
		{"denylist half down", false, true, "jti", "family.denylist_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeReuseFixtureWithFailures(t, tc.wrapTokens, tc.wrapRevoke)

			err := f.replay(t, func(correct string) string { return correct })
			if !errors.Is(err, domain.ErrCodeConsumed) {
				t.Fatalf("replay: got %v, want ErrCodeConsumed — a broken store must "+
					"not change what the client sees", err)
			}

			got := f.metrics.valueWith(t, mFailures, []attribute.KeyValue{
				attribute.String("path", "code_reuse"),
				attribute.String("half", tc.wantHalf),
			})
			if got != 1 {
				t.Errorf("%s{path=code_reuse,half=%s}: got %d, want 1", mFailures, tc.wantHalf, got)
			}
			if !hasAuditDetail(t, f.setup, tc.wantAction, "code_reuse family=") {
				t.Errorf("no %s audit row with a code_reuse detail", tc.wantAction)
			}
		})
	}
}

// TestCodeReuse_ValidVerifierDenylistsTheJTIs closes the other half of AC1: the
// tokens the replayed code issued must stop passing introspection, not merely
// stop rotating. TestCodeReuse_ValidVerifierRevokesTheFamily covers the family
// half; this is the denylist half.
func TestCodeReuse_ValidVerifierDenylistsTheJTIs(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()
	c, _, code, verifier := f.setup.createSessionWithCode(t, true)

	initial, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	jwks, err := f.setup.jwksSvc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claims, err := crypto.VerifyAccessToken(initial.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify initial access token: %v", err)
	}

	// Without this the test could pass against a denylist that revokes
	// everything, or nothing, indistinguishably.
	if revoked, rErr := f.setup.h.Stores.Revocation.IsRevoked(ctx, claims.JTI); rErr != nil || revoked {
		t.Fatalf("jti already denylisted before the replay (revoked=%v, err=%v)", revoked, rErr)
	}

	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("replay: got %v, want ErrCodeConsumed", err)
	}

	revoked, err := f.setup.h.Stores.Revocation.IsRevoked(ctx, claims.JTI)
	if err != nil {
		t.Fatalf("IsRevoked(%s): %v", claims.JTI, err)
	}
	if !revoked {
		t.Error("the access token issued by the replayed code is still not denylisted")
	}

	if got := f.metrics.valueWith(t, mRevoked, []attribute.KeyValue{
		attribute.String("reason", "code_reuse"),
	}); got != 1 {
		t.Errorf("%s{reason=code_reuse}: got %d, want 1", mRevoked, got)
	}
}

// secondSessionForClient creates another authorization session sharing every
// attribute of an existing one — client, user, scope, resource. Two families
// born from these are exactly what a heuristic join on those four columns
// would confuse, which is what AC1 asks us to prove we do not do.
func (f *codeReuseFixture) secondSessionForClient(t *testing.T, first *session.AuthSession) (*session.AuthSession, string, string) {
	t.Helper()
	now := time.Now().UTC()
	verifier := crypto.GenerateVerifier()
	code := crypto.GenerateAuthCode()

	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            first.ClientID,
		UserID:              first.UserID,
		RedirectURI:         first.RedirectURI,
		Scope:               first.Scope,
		Resource:            first.Resource,
		State:               "state-456",
		CodeHash:            crypto.HashSHA256(code),
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := f.setup.h.Stores.Session.Create(context.Background(), sess); err != nil {
		t.Fatalf("create second session: %v", err)
	}
	return sess, code, verifier
}

// TestCodeReuse_RepeatedReplayRevokesOnce: RevokeFamily is a documented no-op
// on an already-revoked family, so without a guard every further credentialed
// replay reports a revocation that did not happen. Detection is still recorded
// per replay — each one is an event — but the family is revoked once.
func TestCodeReuse_RepeatedReplayRevokesOnce(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()
	c, _, code, verifier := f.setup.createSessionWithCode(t, true)

	req := input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); !errors.Is(err, domain.ErrCodeConsumed) {
			t.Fatalf("replay %d: got %v, want ErrCodeConsumed", i, err)
		}
	}

	if got := f.metrics.valueWith(t, mCodeReuse, []attribute.KeyValue{
		attribute.String("verifier", "valid"),
	}); got != 2 {
		t.Errorf("%s{verifier=valid}: got %d, want 2 (one per replay)", mCodeReuse, got)
	}
	if got := countAuditDetail(t, f.setup, "auth_code.reused", "verifier=valid"); got != 2 {
		t.Errorf("auth_code.reused rows: got %d, want 2 (one per replay)", got)
	}

	if got := f.metrics.valueWith(t, mRevoked, []attribute.KeyValue{
		attribute.String("reason", "code_reuse"),
	}); got != 1 {
		t.Errorf("%s{reason=code_reuse}: got %d, want 1 (the family is revoked once)", mRevoked, got)
	}
	if got := countAuditDetail(t, f.setup, "family.revoked", "code_reuse family="); got != 1 {
		t.Errorf("family.revoked rows: got %d, want 1 (the family is revoked once)", got)
	}
}

// countAuditDetail counts audit rows with the given action whose detail
// contains want.
func countAuditDetail(t *testing.T, setup *tokenTestSetup, action, want string) int {
	t.Helper()
	events, err := setup.h.Stores.Audit.Query(context.Background(), output.AuditFilter{
		Action: action,
		Limit:  100,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	n := 0
	for _, e := range events {
		if strings.Contains(e.Detail, want) {
			n++
		}
	}
	return n
}

// TestCodeReuse_AuditRowNamesTheSessionOwner: the auth_code.reused row carries
// the user and client the replayed code was issued to, the way token.issued
// does, so it surfaces in the actor- and client-filtered audit views.
func TestCodeReuse_AuditRowNamesTheSessionOwner(t *testing.T) {
	f := newCodeReuseFixture(t)
	ctx := context.Background()
	c, sess, code, verifier := f.setup.createSessionWithCode(t, true)
	if sess.UserID == "" {
		t.Fatal("fixture session has no user; the test cannot tell an attributed row from an empty one")
	}

	req := input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("replay: got %v, want ErrCodeConsumed", err)
	}

	events, err := f.setup.h.Stores.Audit.Query(ctx, output.AuditFilter{Action: "auth_code.reused", Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("auth_code.reused rows: got %d, want 1", len(events))
	}
	if events[0].ActorID != sess.UserID {
		t.Errorf("actor_id: got %q, want the session's user %q", events[0].ActorID, sess.UserID)
	}
	if events[0].ClientID != sess.ClientID {
		t.Errorf("client_id: got %q, want the session's client %q", events[0].ClientID, sess.ClientID)
	}
}

// flakyRevokeByFamilyStore is the real RevocationStore whose RevokeByFamily
// fails while fail is true — a transient revocation-store outage.
type flakyRevokeByFamilyStore struct {
	output.RevocationStore
	fail bool
}

func (f *flakyRevokeByFamilyStore) RevokeByFamily(ctx context.Context, familyID string) error {
	if f.fail {
		return errInjected
	}
	return f.RevocationStore.RevokeByFamily(ctx, familyID)
}

// TestCodeReuse_RevokedFamilyStillRetriesTheDenylist: the denylist half runs
// on every credentialed replay, even once the family is already revoked. A
// denylist that failed on the first replay is retried by the next one; the
// family half is not re-run, so the family is still revoked (and counted)
// once.
func TestCodeReuse_RevokedFamilyStillRetriesTheDenylist(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	flaky := &flakyRevokeByFamilyStore{RevocationStore: stores.Revocation, fail: true}
	obs := observability.NewNoop()
	m := newReuseMetrics(t, obs)
	setup := newTokenTestSetupWithOverrides(t, static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}), tokenTestOverrides{stores: stores, obs: obs, revocation: flaky})
	setup.tokenSvc.WithTokenTransactions(stores.TransactionMgr)
	f := &codeReuseFixture{setup: setup, metrics: m}

	ctx := context.Background()
	c, sess, code, verifier := f.setup.createSessionWithCode(t, true)
	req := input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}
	initial, err := f.setup.tokenSvc.ExchangeCode(ctx, req)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	jwks, err := f.setup.jwksSvc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claims, err := crypto.VerifyAccessToken(initial.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify initial access token: %v", err)
	}

	// Replay #1: family revoked, denylist fails.
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("replay 1: got %v, want ErrCodeConsumed", err)
	}
	fam, err := stores.Token.GetFamilyByAuthSessionID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if fam.IsActive() {
		t.Fatal("family still active after replay 1")
	}
	if revoked, _ := stores.Revocation.IsRevoked(ctx, claims.JTI); revoked {
		t.Fatal("jti denylisted although RevokeByFamily was failing")
	}

	// Replay #2: the store is back; the denylist half must run again.
	flaky.fail = false
	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("replay 2: got %v, want ErrCodeConsumed", err)
	}
	if revoked, rErr := stores.Revocation.IsRevoked(ctx, claims.JTI); rErr != nil || !revoked {
		t.Errorf("jti not denylisted after replay 2 (revoked=%v, err=%v): the denylist half was not retried", revoked, rErr)
	}
	if got := countAuditDetail(t, f.setup, "family.revoked", "code_reuse family="); got != 1 {
		t.Errorf("family.revoked rows: got %d, want 1", got)
	}
	if got := f.metrics.valueWith(t, mRevoked, []attribute.KeyValue{
		attribute.String("reason", "code_reuse"),
	}); got != 1 {
		t.Errorf("%s{reason=code_reuse}: got %d, want 1", mRevoked, got)
	}
}

// lostRaceRevokeFamilyStore is the real TokenStore whose RevokeFamily reports
// that it revoked nothing — the row was already revoked when its UPDATE ran,
// which is what the loser of two concurrent detections sees. The family is
// revoked for real first so the state matches that story.
type lostRaceRevokeFamilyStore struct{ output.TokenStore }

func (l *lostRaceRevokeFamilyStore) RevokeFamily(ctx context.Context, familyID string) (bool, error) {
	if _, err := l.TokenStore.RevokeFamily(ctx, familyID); err != nil {
		return false, err
	}
	return false, nil
}

// TestCodeReuse_LostRaceReportsNoRevocation: when the store says the family was
// already revoked when this detection's UPDATE ran, the family half emits no
// log line, counter or audit row — the detection that won did — and the
// denylist half still runs.
func TestCodeReuse_LostRaceReportsNoRevocation(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := observability.NewNoop()
	m := newReuseMetrics(t, obs)
	setup := newTokenTestSetupWithOverrides(t, static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}), tokenTestOverrides{stores: stores, obs: obs, tokens: &lostRaceRevokeFamilyStore{stores.Token}})
	setup.tokenSvc.WithTokenTransactions(stores.TransactionMgr)
	f := &codeReuseFixture{setup: setup, metrics: m}

	ctx := context.Background()
	c, sess, code, verifier := f.setup.createSessionWithCode(t, true)
	req := input.ExchangeCodeRequest{
		Code: code, RedirectURI: "https://app.example.com/callback",
		ClientID: c.ID, CodeVerifier: verifier,
	}
	initial, err := f.setup.tokenSvc.ExchangeCode(ctx, req)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	jwks, err := f.setup.jwksSvc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claims, err := crypto.VerifyAccessToken(initial.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify initial access token: %v", err)
	}

	if _, err := f.setup.tokenSvc.ExchangeCode(ctx, req); !errors.Is(err, domain.ErrCodeConsumed) {
		t.Fatalf("replay: got %v, want ErrCodeConsumed", err)
	}

	fam, err := stores.Token.GetFamilyByAuthSessionID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get family: %v", err)
	}
	if fam.IsActive() {
		t.Fatal("family still active")
	}
	if got := countAuditDetail(t, f.setup, "family.revoked", "code_reuse family="); got != 0 {
		t.Errorf("family.revoked rows: got %d, want 0 (the winning detection reports it, not this one)", got)
	}
	if got := f.metrics.valueWith(t, mRevoked, []attribute.KeyValue{
		attribute.String("reason", "code_reuse"),
	}); got != 0 {
		t.Errorf("%s{reason=code_reuse}: got %d, want 0", mRevoked, got)
	}
	if got := f.metrics.valueWith(t, mFailures, []attribute.KeyValue{
		attribute.String("path", "code_reuse"),
	}); got != 0 {
		t.Errorf("%s{path=code_reuse}: got %d, want 0 — losing the race is not a failure", mFailures, got)
	}
	if revoked, rErr := stores.Revocation.IsRevoked(ctx, claims.JTI); rErr != nil || !revoked {
		t.Errorf("jti not denylisted (revoked=%v, err=%v): the denylist half must run regardless", revoked, rErr)
	}
}
