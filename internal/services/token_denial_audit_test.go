package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// denyingSessionStore refuses every code, standing in for a replayed
// authorization code. It returns the session alongside the sentinel, as the
// real stores do.
type denyingSessionStore struct{ output.SessionStore }

func (denyingSessionStore) ConsumeByCodeHash(context.Context, string) (*session.AuthSession, error) {
	return &session.AuthSession{
		ID:            "sess-denied",
		ClientID:      "client-denied",
		CodeChallenge: "challenge-that-no-verifier-matches",
	}, domain.ErrCodeConsumed
}

// denyingTokenStore refuses every refresh token.
type denyingTokenStore struct{ output.TokenStore }

func (denyingTokenStore) GetRefreshTokenByHash(context.Context, string) (*token.RefreshToken, error) {
	return nil, domain.ErrInvalidGrant
}

// GetFamilyByAuthSessionID is what the real store returns when no family
// exists for the session, so this fake doesn't lie.
func (denyingTokenStore) GetFamilyByAuthSessionID(context.Context, string) (*token.Family, error) {
	return nil, domain.ErrInvalidGrant
}

type staticTokenConfig struct{}

func (staticTokenConfig) Config(context.Context) (output.TokenConfig, error) {
	return output.TokenConfig{AccessTokenExpiry: time.Hour, RefreshTokenExpiry: time.Hour}, nil
}

func newDenialTokenService(rec AuditRecorder) *TokenService {
	obs := observability.NewNoop()
	return &TokenService{
		sessions:    denyingSessionStore{},
		tokens:      denyingTokenStore{},
		tokenConfig: staticTokenConfig{},
		audit:       rec,
		logger:      obs.Logger,
		tracer:      obs.Tracer,
		metrics:     obs.Metrics,
	}
}

func findAction(events []audit.Event, want audit.Action) (audit.Event, bool) {
	for _, e := range events {
		if e.Action == want {
			return e, true
		}
	}
	return audit.Event{}, false
}

// authorization_code and refresh_token were the only two grants that recorded
// nothing durable on failure — the two highest-volume user-delegation grants had
// no denial trail at all.
func TestExchangeCode_DenialIsRecorded(t *testing.T) {
	rec := &captureAuditRecorder{}
	svc := newDenialTokenService(rec)

	if _, err := svc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{
		ClientID: "client-1", Code: "replayed",
	}); err == nil {
		t.Fatal("expected the exchange to be denied")
	}

	ev, ok := findAction(rec.take(), audit.ActionTokenIssueDenied)
	if !ok {
		t.Fatal("a denied authorization-code exchange recorded no audit event")
	}
	if ev.ClientID != "client-1" {
		t.Errorf("denial client_id = %q, want client-1", ev.ClientID)
	}
	// The reason is the OAuth code the client sees, so the trail and the wire agree.
	if !strings.Contains(ev.Detail, "reason=invalid_grant") {
		t.Errorf("denial detail = %q, want reason=invalid_grant", ev.Detail)
	}
}

func TestRefreshToken_DenialIsRecorded(t *testing.T) {
	rec := &captureAuditRecorder{}
	svc := newDenialTokenService(rec)

	if _, err := svc.RefreshToken(context.Background(), input.RefreshTokenRequest{
		ClientID: "client-2", RefreshToken: "unknown",
	}); err == nil {
		t.Fatal("expected the refresh to be denied")
	}

	ev, ok := findAction(rec.take(), audit.ActionTokenRefreshDenied)
	if !ok {
		t.Fatal("a denied refresh rotation recorded no audit event")
	}
	if ev.ClientID != "client-2" {
		t.Errorf("denial client_id = %q, want client-2", ev.ClientID)
	}
	if !strings.Contains(ev.Detail, "reason=invalid_grant") {
		t.Errorf("denial detail = %q, want reason=invalid_grant", ev.Detail)
	}
}

// The denial action must be distinct from the success action, or a consumer
// counting issuances counts failures too — the bug this change fixes in
// token_exchange.
func TestDenialActionsAreDistinctFromSuccess(t *testing.T) {
	rec := &captureAuditRecorder{}
	svc := newDenialTokenService(rec)

	_, _ = svc.ExchangeCode(context.Background(), input.ExchangeCodeRequest{ClientID: "c", Code: "x"})
	_, _ = svc.RefreshToken(context.Background(), input.RefreshTokenRequest{ClientID: "c", RefreshToken: "x"})

	for _, e := range rec.take() {
		if e.Action == audit.ActionTokenIssued || e.Action == audit.ActionTokenRefreshed {
			t.Errorf("denial emitted the success action %q", e.Action)
		}
	}
}
