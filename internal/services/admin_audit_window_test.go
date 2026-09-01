package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// captureAuditStore records the filter QueryAudit hands the store, which is the
// only place the lookback bound can be observed from the outside.
type captureAuditStore struct {
	got output.AuditFilter
}

func (c *captureAuditStore) Record(context.Context, *audit.Event) error { return nil }

func (c *captureAuditStore) Query(_ context.Context, f output.AuditFilter) ([]audit.Event, error) {
	c.got = f
	return nil, nil
}

type stubAuditQueryConfig struct {
	cfg output.AuditQueryConfig
	err error
}

func (s stubAuditQueryConfig) Config(context.Context) (output.AuditQueryConfig, error) {
	return s.cfg, s.err
}

func newAuditWindowService(store output.AuditStore, opts ...AdminServiceOpt) *AdminService {
	return NewAdminService(nil, nil, nil, store, observability.NewNoop(), nil, opts...)
}

// The bound must hold with no provider wired. An unbounded scan over
// audit_events is a defect regardless of who configured the deployment.
func TestQueryAudit_UnconfiguredStillBounded(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store)

	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{}); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}

	if store.got.SinceUnix == 0 {
		t.Fatal("since was left unbounded; offset paging would walk the whole table")
	}
	want := time.Now().UTC().Add(-defaultAuditSinceWindow)
	if delta := time.Unix(store.got.SinceUnix, 0).Sub(want); delta < -time.Minute || delta > time.Minute {
		t.Errorf("default lookback = %v off expected 24h window", delta)
	}
}

func TestQueryAudit_SinceBeyondMaxIsRejected(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store)

	since := time.Now().UTC().Add(-maxAuditSinceWindow - time.Hour)
	_, err := svc.QueryAudit(context.Background(), input.AuditFilter{Since: &since})
	if err == nil {
		t.Fatal("a since beyond the max lookback must be rejected, not silently narrowed")
	}
	// Must map to 400, not 500: the caller asked for something it may not have.
	if !domain.IsError(err) || domain.ErrorCode(err) != "invalid_request" {
		t.Errorf("error = %v (code %q), want an invalid_request domain error", err, domain.ErrorCode(err))
	}
}

func TestQueryAudit_SinceWithinMaxIsHonored(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store)

	since := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{Since: &since}); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if store.got.SinceUnix != since.Unix() {
		t.Errorf("since = %d, want %d (caller's value passed through)", store.got.SinceUnix, since.Unix())
	}
}

// A deployment that resolves the bound per request (per operator setting, per
// caller) supplies its own provider. The service applies the number and does not
// ask where it came from.
func TestQueryAudit_ProviderNarrowsTheBound(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store, WithAuditQueryConfig(stubAuditQueryConfig{
		cfg: output.AuditQueryConfig{DefaultLookback: time.Hour, MaxLookback: 7 * 24 * time.Hour},
	}))

	// Beyond the provider's 7-day max, but well inside the built-in 30-day one.
	since := time.Now().UTC().Add(-10 * 24 * time.Hour)
	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{Since: &since}); err == nil {
		t.Fatal("provider max must override the built-in default")
	}
}

func TestQueryAudit_ProviderDefaultApplied(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store, WithAuditQueryConfig(stubAuditQueryConfig{
		cfg: output.AuditQueryConfig{DefaultLookback: time.Hour, MaxLookback: 7 * 24 * time.Hour},
	}))

	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{}); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	want := time.Now().UTC().Add(-time.Hour)
	if delta := time.Unix(store.got.SinceUnix, 0).Sub(want); delta < -time.Minute || delta > time.Minute {
		t.Errorf("provider default lookback not applied (off by %v)", delta)
	}
}

// A default wider than the max would hand the caller rows past its own ceiling.
func TestQueryAudit_DefaultNeverExceedsMax(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store, WithAuditQueryConfig(stubAuditQueryConfig{
		cfg: output.AuditQueryConfig{DefaultLookback: 30 * 24 * time.Hour, MaxLookback: time.Hour},
	}))

	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{}); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	oldest := time.Now().UTC().Add(-time.Hour - time.Minute)
	if time.Unix(store.got.SinceUnix, 0).Before(oldest) {
		t.Errorf("default lookback %v escaped the max lookback", time.Unix(store.got.SinceUnix, 0))
	}
}

// MaxLookback == 0 is a default-constructed config — a deployment whose
// visibility setting was never populated — and must inherit the built-in cap,
// not remove it. Widening the window takes an explicit value.
func TestQueryAudit_ProviderZeroMaxKeepsBuiltinCap(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store, WithAuditQueryConfig(stubAuditQueryConfig{
		cfg: output.AuditQueryConfig{DefaultLookback: time.Hour},
	}))

	since := time.Now().UTC().Add(-365 * 24 * time.Hour)
	_, err := svc.QueryAudit(context.Background(), input.AuditFilter{Since: &since})
	if err == nil {
		t.Fatal("a zero provider max must keep the built-in cap, not unbound the scan")
	}
	if !domain.IsError(err) || domain.ErrorCode(err) != "invalid_request" {
		t.Errorf("error = %v (code %q), want an invalid_request domain error", err, domain.ErrorCode(err))
	}
}

// A provider may widen the window past the built-in cap — it just has to say so.
func TestQueryAudit_ProviderMayRaiseTheCapExplicitly(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store, WithAuditQueryConfig(stubAuditQueryConfig{
		cfg: output.AuditQueryConfig{DefaultLookback: time.Hour, MaxLookback: 90 * 24 * time.Hour},
	}))

	since := time.Now().UTC().Add(-60 * 24 * time.Hour)
	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{Since: &since}); err != nil {
		t.Fatalf("QueryAudit within an explicitly raised cap: %v", err)
	}
}

// The page bounds live beside the lookback bound, in the service, so no query
// parameter can route around them.
func TestQueryAudit_PageBounds(t *testing.T) {
	tests := []struct {
		name          string
		limit, offset int
		wantErr       bool
		wantLimit     int
		wantOffset    int
	}{
		{name: "omitted limit gets the default", wantLimit: defaultAuditQueryLimit},
		{name: "negative offset is clamped", offset: -3, wantLimit: defaultAuditQueryLimit},
		{name: "limit at the cap is honored", limit: maxAuditQueryLimit, wantLimit: maxAuditQueryLimit},
		{name: "limit beyond the cap is rejected", limit: maxAuditQueryLimit + 1, wantErr: true},
		{name: "offset at the cap is honored", offset: maxAuditQueryOffset, wantLimit: defaultAuditQueryLimit, wantOffset: maxAuditQueryOffset},
		{name: "offset beyond the cap is rejected", offset: maxAuditQueryOffset + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &captureAuditStore{}
			svc := newAuditWindowService(store)

			_, err := svc.QueryAudit(context.Background(), input.AuditFilter{Limit: tt.limit, Offset: tt.offset})
			if tt.wantErr {
				if err == nil {
					t.Fatal("an out-of-bounds page must be rejected, not passed to the store")
				}
				if !domain.IsError(err) || domain.ErrorCode(err) != "invalid_request" {
					t.Errorf("error = %v (code %q), want an invalid_request domain error", err, domain.ErrorCode(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("QueryAudit: %v", err)
			}
			if store.got.Limit != tt.wantLimit || store.got.Offset != tt.wantOffset {
				t.Errorf("store saw limit=%d offset=%d, want limit=%d offset=%d",
					store.got.Limit, store.got.Offset, tt.wantLimit, tt.wantOffset)
			}
		})
	}
}

// until only narrows the window, but an until at or before the effective since
// is an empty interval. It must be rejected rather than served as a silently
// empty page a caller would misread as "no events".
func TestQueryAudit_UntilNotAfterSinceIsRejected(t *testing.T) {
	since := time.Now().UTC().Add(-time.Hour)
	tests := []struct {
		name    string
		until   time.Time
		wantErr bool
	}{
		{name: "until before since", until: since.Add(-time.Minute), wantErr: true},
		{name: "until equal to since", until: since, wantErr: true},
		{name: "until after since", until: since.Add(time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &captureAuditStore{}
			svc := newAuditWindowService(store)

			sinceCopy, untilCopy := since, tt.until
			_, err := svc.QueryAudit(context.Background(), input.AuditFilter{Since: &sinceCopy, Until: &untilCopy})
			if tt.wantErr {
				if err == nil {
					t.Fatal("an empty until/since interval must be rejected, not passed to the store")
				}
				if !domain.IsError(err) || domain.ErrorCode(err) != "invalid_request" {
					t.Errorf("error = %v (code %q), want an invalid_request domain error", err, domain.ErrorCode(err))
				}
				if store.got.UntilUnix != 0 {
					t.Error("store was queried despite a rejected range")
				}
				return
			}
			if err != nil {
				t.Fatalf("QueryAudit: %v", err)
			}
			if store.got.UntilUnix != tt.until.Unix() {
				t.Errorf("store saw until=%d, want %d", store.got.UntilUnix, tt.until.Unix())
			}
		})
	}
}

func TestQueryAudit_ProviderErrorFailsClosed(t *testing.T) {
	store := &captureAuditStore{}
	svc := newAuditWindowService(store, WithAuditQueryConfig(stubAuditQueryConfig{
		err: errors.New("limits unavailable"),
	}))

	if _, err := svc.QueryAudit(context.Background(), input.AuditFilter{}); err == nil {
		t.Fatal("an unresolvable bound must fail the query, not serve it unbounded")
	}
	if store.got.SinceUnix != 0 {
		t.Error("store was queried despite an unresolved bound")
	}
}
