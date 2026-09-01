//go:build integration

package services_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// errInjected is what the failing wrappers return.
var errInjected = errors.New("injected: storage down")

// failingRevokeFamilyStore is the real TokenStore with RevokeFamily broken:
// the UPDATE never runs, as if the store were down.
type failingRevokeFamilyStore struct{ output.TokenStore }

func (f *failingRevokeFamilyStore) RevokeFamily(context.Context, string) (bool, error) {
	return false, errInjected
}

// failingRevokeByFamilyStore is the real RevocationStore with RevokeByFamily broken.
type failingRevokeByFamilyStore struct{ output.RevocationStore }

func (f *failingRevokeByFamilyStore) RevokeByFamily(context.Context, string) error {
	return errInjected
}

const (
	mReuse    = "authserver_refresh_token_reuse_total"
	mRevoked  = "authserver_tokens_revoked_total"
	mFailures = "authserver_revocation_failures_total"

	logFamilyFailed  = "failed to revoke family during reuse detection"
	logJTIFailed     = "JTI denylist failed during reuse detection"
	logFamilyRevoked = "refresh token reuse detected — family revoked"
)

// reuseMetrics swaps the three counters reuse detection touches onto a
// manual reader so their values can be asserted. Must run before the
// service is built only for tidiness — the service holds the *Metrics
// pointer, so swapping fields afterwards would work too.
type reuseMetrics struct {
	reader *sdkmetric.ManualReader
}

func newReuseMetrics(t *testing.T, obs *observability.Provider) *reuseMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	meter := provider.Meter("reuse-revocation-test")
	counter := func(name string) metric.Int64Counter {
		c, err := meter.Int64Counter(name)
		if err != nil {
			t.Fatalf("counter %q: %v", name, err)
		}
		return c
	}
	obs.Metrics.RefreshTokenReuse = counter(mReuse)
	obs.Metrics.AuthCodeReuse = counter(mCodeReuse)
	obs.Metrics.TokensRevoked = counter(mRevoked)
	obs.Metrics.RevocationFailures = counter(mFailures)
	return &reuseMetrics{reader: reader}
}

// value sums every data point of the named counter; 0 when never touched.
func (m *reuseMetrics) value(t *testing.T, name string) int64 {
	t.Helper()
	return m.valueWith(t, name, nil)
}

// valueWith sums the data points of the named counter whose attribute set
// contains every key/value in want; nil matches every data point.
func (m *reuseMetrics) valueWith(t *testing.T, name string, want []attribute.KeyValue) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := m.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, inst := range sm.Metrics {
			if inst.Name != name {
				continue
			}
			sum, ok := inst.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: data shape %T, want Sum[int64]", name, inst.Data)
			}
		points:
			for _, dp := range sum.DataPoints {
				for _, kv := range want {
					if got, ok := dp.Attributes.Value(kv.Key); !ok || got != kv.Value {
						continue points
					}
				}
				total += dp.Value
			}
		}
	}
	return total
}

// reuseFixture is a token service wired like production (transaction
// manager set), with captured logs and readable counters. tokens /
// revocation may be failing wrappers built around the same stores passed
// here; nil keeps the real store.
type reuseFixture struct {
	setup   *tokenTestSetup
	metrics *reuseMetrics
	logs    *bytes.Buffer
}

func newReuseFixture(t *testing.T, stores *sqlite.Stores, tokens output.TokenStore, revocation output.RevocationStore) *reuseFixture {
	t.Helper()
	var logs bytes.Buffer
	obs := observability.NewNoop()
	// The service copies obs.Logger at construction, so the capture handler
	// has to be in place before newTokenTestSetupWithOverrides runs.
	obs.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := newReuseMetrics(t, obs)

	setup := newTokenTestSetupWithOverrides(t, static.NewTokenConfigProvider(output.TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
	}), tokenTestOverrides{stores: stores, tokens: tokens, revocation: revocation, obs: obs})
	setup.tokenSvc.WithTokenTransactions(stores.TransactionMgr)
	return &reuseFixture{setup: setup, metrics: m, logs: &logs}
}

// triggerReuse logs in, rotates once, then replays the consumed token.
// Returns the client id, the jti of the access token issued at login (a
// tracked JTI of the family, so the denylist half reaches it) and the
// replay error.
func (f *reuseFixture) triggerReuse(t *testing.T) (clientID, initialJTI string, err error) {
	t.Helper()
	ctx := context.Background()
	initial, c, _ := f.setup.exchangeForTokens(t, true)

	jwks, err := f.setup.jwksSvc.BuildJWKS(ctx)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	claims, err := crypto.VerifyAccessToken(initial.AccessToken, jwks)
	if err != nil {
		t.Fatalf("verify initial access token: %v", err)
	}

	if _, err := f.setup.tokenSvc.RefreshToken(ctx, input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	}); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	_, err = f.setup.tokenSvc.RefreshToken(ctx, input.RefreshTokenRequest{
		RefreshToken: initial.RefreshToken,
		ClientID:     c.ID,
	})
	return c.ID, claims.JTI, err
}

// assertJTIRevoked checks the denylist for jti against the real store —
// the denylist half's only observable effect.
func (f *reuseFixture) assertJTIRevoked(t *testing.T, jti string, want bool) {
	t.Helper()
	got, err := f.setup.h.Stores.Revocation.IsRevoked(context.Background(), jti)
	if err != nil {
		t.Fatalf("IsRevoked(%s): %v", jti, err)
	}
	if got != want {
		t.Errorf("IsRevoked(%s) = %v, want %v", jti, got, want)
	}
}

func (f *reuseFixture) auditEvents(t *testing.T, action audit.Action) []audit.Event {
	t.Helper()
	events, err := f.setup.auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(action),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return events
}

func (f *reuseFixture) familyRevokedEvents(t *testing.T) []audit.Event {
	t.Helper()
	return f.auditEvents(t, audit.ActionFamilyRevoked)
}

// assertDenylistFailedRows checks how many family.denylist_failed rows the
// detection left (0 or 1) and, when one, that it names the family and half.
func (f *reuseFixture) assertDenylistFailedRows(t *testing.T, familyID string, want int) {
	t.Helper()
	rows := f.auditEvents(t, audit.ActionFamilyDenylistFailed)
	if len(rows) != want {
		t.Fatalf("family.denylist_failed audit rows = %d, want %d", len(rows), want)
	}
	if want == 1 {
		if d := rows[0].Detail; !strings.Contains(d, "family="+familyID) || !strings.Contains(d, "half=jti") {
			t.Errorf("family.denylist_failed detail = %q, want family=%s and half=jti", d, familyID)
		}
	}
}

func (f *reuseFixture) onlyFamily(t *testing.T, clientID string) token.Family {
	t.Helper()
	fams, _, err := f.setup.h.Stores.Token.ListFamilies(context.Background(), output.FamilyFilter{ClientID: clientID, Limit: 10})
	if err != nil {
		t.Fatalf("list families: %v", err)
	}
	if len(fams) != 1 {
		t.Fatalf("families for client = %d, want 1", len(fams))
	}
	return fams[0]
}

// assertRefreshDeniedAudited: the wire code is invalid_grant for every
// outcome, so the denial audit's reason is identical across them — that
// parity is deliberate, not a gap.
func assertRefreshDeniedAudited(t *testing.T, f *reuseFixture) {
	t.Helper()
	denied, err := f.setup.auditSvc.Query(context.Background(), output.AuditFilter{
		Action: string(audit.ActionTokenRefreshDenied),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	for _, e := range denied {
		if e.Detail == "reason=invalid_grant" {
			return
		}
	}
	t.Errorf("expected a token.refresh_denied event with Detail = %q, got %+v", "reason=invalid_grant", denied)
}

func halfAttr(half string) []attribute.KeyValue {
	return []attribute.KeyValue{attribute.String("path", "reuse"), attribute.String("half", half)}
}

// TestRefresh_ReuseDetection_RevokeFamilyFails_JTIsStillDenylisted — the
// family half fails. The family stays live and nothing may claim otherwise
// (the caller learns revocation failed, no family.revoked row, the failure
// is counted half=family and logged at ERROR), but the denylist half still
// runs: it reads access_token_jtis, not token_families, so the family's
// already-issued access tokens stop passing introspection and exchange.
func TestRefresh_ReuseDetection_RevokeFamilyFails_JTIsStillDenylisted(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	f := newReuseFixture(t, stores, &failingRevokeFamilyStore{TokenStore: stores.Token}, nil)
	clientID, jti, err := f.triggerReuse(t)

	if !errors.Is(err, domain.ErrReuseRevocationFailed) {
		t.Fatalf("error = %v, want ErrReuseRevocationFailed", err)
	}
	// Not redundant with the check above: it catches a chain that wraps both
	// sentinels (fmt.Errorf("%w: %w", ...)), which this branch once did.
	if errors.Is(err, domain.ErrFamilyRevoked) {
		t.Errorf("error must not also satisfy ErrFamilyRevoked: %v", err)
	}
	if n := len(f.familyRevokedEvents(t)); n != 0 {
		t.Errorf("family.revoked audit rows = %d, want 0 — revocation did not happen", n)
	}
	fam := f.onlyFamily(t, clientID)
	if fam.Status != token.FamilyActive {
		t.Errorf("family status = %q, want active", fam.Status)
	}
	failed := f.auditEvents(t, audit.ActionFamilyRevocationFailed)
	if len(failed) != 1 {
		t.Fatalf("family.revocation_failed audit rows = %d, want 1", len(failed))
	}
	if d := failed[0].Detail; !strings.Contains(d, "family="+fam.ID) || !strings.Contains(d, "half=family") {
		t.Errorf("family.revocation_failed detail = %q, want family=%s and half=family", d, fam.ID)
	}
	f.assertDenylistFailedRows(t, fam.ID, 0)
	f.assertJTIRevoked(t, jti, true)
	if v := f.metrics.value(t, mReuse); v != 1 {
		t.Errorf("%s = %d, want 1 (detection still counts)", mReuse, v)
	}
	if v := f.metrics.value(t, mRevoked); v != 0 {
		t.Errorf("%s = %d, want 0", mRevoked, v)
	}
	if v := f.metrics.valueWith(t, mFailures, halfAttr("family")); v != 1 {
		t.Errorf("%s{half=family} = %d, want 1", mFailures, v)
	}
	if v := f.metrics.value(t, mFailures); v != 1 {
		t.Errorf("%s (all halves) = %d, want 1", mFailures, v)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `"level":"ERROR"`) || !strings.Contains(logs, logFamilyFailed) {
		t.Errorf("expected ERROR log %q, got:\n%s", logFamilyFailed, logs)
	}
	if strings.Contains(logs, "family revoked") {
		t.Errorf("log must not claim the family was revoked:\n%s", logs)
	}
	if strings.Contains(logs, logJTIFailed) {
		t.Errorf("log must not claim the denylist failed:\n%s", logs)
	}
	assertRefreshDeniedAudited(t, f)
}

// TestRefresh_ReuseDetection_BothHalvesFail — both statements fail. Nothing
// is revoked, the family stays live, and each half reports its own failure:
// family.revocation_failed and family.denylist_failed are both written, both halves are
// counted, both ERROR lines are emitted (the critical and the warning alert
// fire together; the runbook's admin revoke repairs both).
func TestRefresh_ReuseDetection_BothHalvesFail(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	f := newReuseFixture(t, stores,
		&failingRevokeFamilyStore{TokenStore: stores.Token},
		&failingRevokeByFamilyStore{RevocationStore: stores.Revocation})
	clientID, jti, err := f.triggerReuse(t)

	if !errors.Is(err, domain.ErrReuseRevocationFailed) {
		t.Fatalf("error = %v, want ErrReuseRevocationFailed", err)
	}
	if errors.Is(err, domain.ErrFamilyRevoked) {
		t.Errorf("error must not also satisfy ErrFamilyRevoked: %v", err)
	}
	if n := len(f.familyRevokedEvents(t)); n != 0 {
		t.Errorf("family.revoked audit rows = %d, want 0", n)
	}
	fam := f.onlyFamily(t, clientID)
	if fam.Status != token.FamilyActive {
		t.Errorf("family status = %q, want active", fam.Status)
	}
	f.assertJTIRevoked(t, jti, false)
	failed := f.auditEvents(t, audit.ActionFamilyRevocationFailed)
	if len(failed) != 1 {
		t.Fatalf("family.revocation_failed audit rows = %d, want 1", len(failed))
	}
	if d := failed[0].Detail; !strings.Contains(d, "half=family") {
		t.Errorf("family.revocation_failed detail = %q, want half=family", d)
	}
	f.assertDenylistFailedRows(t, fam.ID, 1)
	if v := f.metrics.value(t, mReuse); v != 1 {
		t.Errorf("%s = %d, want 1", mReuse, v)
	}
	if v := f.metrics.value(t, mRevoked); v != 0 {
		t.Errorf("%s = %d, want 0", mRevoked, v)
	}
	if v := f.metrics.valueWith(t, mFailures, halfAttr("family")); v != 1 {
		t.Errorf("%s{half=family} = %d, want 1", mFailures, v)
	}
	if v := f.metrics.valueWith(t, mFailures, halfAttr("jti")); v != 1 {
		t.Errorf("%s{half=jti} = %d, want 1", mFailures, v)
	}
	if v := f.metrics.value(t, mFailures); v != 2 {
		t.Errorf("%s (all halves) = %d, want 2", mFailures, v)
	}
	logs := f.logs.String()
	for _, want := range []string{logFamilyFailed, logJTIFailed} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected ERROR log %q, got:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, logFamilyRevoked) {
		t.Errorf("log must not claim the family was revoked:\n%s", logs)
	}
	assertRefreshDeniedAudited(t, f)
}

// TestRefresh_ReuseDetection_RevokeByFamilyFails_FamilyStillRevoked — the
// JTI half fails after the family was revoked. Pins the decision that the
// family half is never held hostage by the denylist half: the family stays
// revoked (the caller sees ErrFamilyRevoked, the client must re-login), the
// audit row says the denylist is missing, and the failure is counted
// (half=jti) and logged at ERROR. Identical on SQLite and Postgres because
// the two halves no longer share a transaction.
func TestRefresh_ReuseDetection_RevokeByFamilyFails_FamilyStillRevoked(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	f := newReuseFixture(t, stores, nil, &failingRevokeByFamilyStore{RevocationStore: stores.Revocation})
	clientID, jti, err := f.triggerReuse(t)

	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Fatalf("error = %v, want ErrFamilyRevoked (the family IS revoked)", err)
	}
	f.assertJTIRevoked(t, jti, false)
	// Same guard as in JTIsStillDenylisted: a double-wrapped chain would pass the
	// positive check above and only fail here.
	if errors.Is(err, domain.ErrReuseRevocationFailed) {
		t.Errorf("error must not satisfy ErrReuseRevocationFailed: %v", err)
	}
	if fam := f.onlyFamily(t, clientID); fam.Status != token.FamilyRevoked {
		t.Errorf("family status = %q, want revoked (family half must commit on its own)", fam.Status)
	}
	events := f.familyRevokedEvents(t)
	if len(events) != 1 {
		t.Fatalf("family.revoked audit rows = %d, want 1", len(events))
	}
	if n := len(f.auditEvents(t, audit.ActionFamilyRevocationFailed)); n != 0 {
		t.Errorf("family.revocation_failed audit rows = %d, want 0 — the family was revoked", n)
	}
	if d := events[0].Detail; strings.Contains(d, "jti_denylist") {
		t.Errorf("family.revoked detail = %q, must not carry a marker — the denylist failure has its own row", d)
	}
	f.assertDenylistFailedRows(t, f.onlyFamily(t, clientID).ID, 1)
	if v := f.metrics.value(t, mReuse); v != 1 {
		t.Errorf("%s = %d, want 1", mReuse, v)
	}
	if v := f.metrics.value(t, mRevoked); v != 1 {
		t.Errorf("%s = %d, want 1 (the family was revoked)", mRevoked, v)
	}
	if v := f.metrics.valueWith(t, mFailures, halfAttr("jti")); v != 1 {
		t.Errorf("%s{half=jti} = %d, want 1", mFailures, v)
	}
	if v := f.metrics.value(t, mFailures); v != 1 {
		t.Errorf("%s (all halves) = %d, want 1", mFailures, v)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `"level":"ERROR"`) || !strings.Contains(logs, logJTIFailed) {
		t.Errorf("expected ERROR log %q, got:\n%s", logJTIFailed, logs)
	}
	if strings.Contains(logs, logFamilyFailed) {
		t.Errorf("log must not claim the family revocation failed:\n%s", logs)
	}
	if !strings.Contains(logs, logFamilyRevoked) {
		t.Errorf("expected WARN %q, got:\n%s", logFamilyRevoked, logs)
	}
	assertRefreshDeniedAudited(t, f)
}

// TestRefresh_ReuseDetection_Success_CountsRevocation is the happy path on
// the same fixture: revoked family, one audit row without a failure marker,
// counters as documented, no failure counted.
func TestRefresh_ReuseDetection_Success_CountsRevocation(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	f := newReuseFixture(t, stores, nil, nil)
	clientID, jti, err := f.triggerReuse(t)

	if !errors.Is(err, domain.ErrFamilyRevoked) {
		t.Fatalf("error = %v, want ErrFamilyRevoked", err)
	}
	f.assertJTIRevoked(t, jti, true)
	events := f.familyRevokedEvents(t)
	if len(events) != 1 {
		t.Fatalf("family.revoked audit rows = %d, want 1", len(events))
	}
	f.assertDenylistFailedRows(t, f.onlyFamily(t, clientID).ID, 0)
	if n := len(f.auditEvents(t, audit.ActionFamilyRevocationFailed)); n != 0 {
		t.Errorf("family.revocation_failed audit rows = %d, want 0", n)
	}
	if fam := f.onlyFamily(t, clientID); fam.Status != token.FamilyRevoked {
		t.Errorf("family status = %q, want revoked", fam.Status)
	}
	if v := f.metrics.value(t, mReuse); v != 1 {
		t.Errorf("%s = %d, want 1", mReuse, v)
	}
	if v := f.metrics.value(t, mRevoked); v != 1 {
		t.Errorf("%s = %d, want 1", mRevoked, v)
	}
	if v := f.metrics.value(t, mFailures); v != 0 {
		t.Errorf("%s = %d, want 0", mFailures, v)
	}
	assertRefreshDeniedAudited(t, f)
}
