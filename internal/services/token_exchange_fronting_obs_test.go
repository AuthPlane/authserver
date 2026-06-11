package services

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// -----------------------------------------------------------------------------
// follow-up coverage. Pins three branches the merge PR exercised
// end-to-end but left without an in-package assertion:
//
//   - TokenExchangeTotal label shape on fronted vs direct success
//   - resolveSourceForFronting as a unit (covers nil-fronting, aud=issuer,
//     non-Mint resources, multi-aud first-wins, unresolvable fall-through)
//   - the dispatchMint warn-and-ignore branch when a fronting link names a
// non-Mint target (the seam will rewrite, so the warn shape is
//     load-bearing for that future change)
//
// These tests stay narrow on purpose — none of them re-prove what the merge
// gate (gateway_fanout_mint_to_mint_test.go) and the fronted-shape unit
// suite already cover; they only add the missing rivet at each spot.
// -----------------------------------------------------------------------------

// -- Metric label shape -------------------------------------------------------

// metricCollector wires a manual SDK reader to a real meter so individual
// TokenExchangeTotal data points become inspectable. Tests swap the single
// counter they care about onto the fixture's *observability.Metrics — the
// rest of the struct stays bound to the noop fixture so dispatchMint's
// other instrument touches (durations, denial counters) keep working.
type metricCollector struct {
	reader *sdkmetric.ManualReader
	meter  metric.Meter
}

func newMetricCollector(t *testing.T) *metricCollector {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return &metricCollector{reader: reader, meter: provider.Meter("token-exchange-fronting-test")}
}

// int64Counter builds a counter on the collector's meter. Wraps the
// instrument-creation error so call sites stay one-liners.
func (c *metricCollector) int64Counter(t *testing.T, name string) metric.Int64Counter {
	t.Helper()
	ctr, err := c.meter.Int64Counter(name)
	if err != nil {
		t.Fatalf("build counter %q: %v", name, err)
	}
	return ctr
}

// dataPoints walks the latest collected metric set for the named instrument
// and returns its int64 sum data points (one per attribute combination).
// Empty slice on miss so callers get a useful error path without nil-checks.
func (c *metricCollector) dataPoints(t *testing.T, instrumentName string) []metricdata.DataPoint[int64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := c.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("metric collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != instrumentName {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("instrument %q: data shape %T, want metricdata.Sum[int64]", instrumentName, m.Data)
			}
			return sum.DataPoints
		}
	}
	return nil
}

// TestDispatchMint_Metric_LabelsOnSuccess pins that TokenExchangeTotal
// emits one data point per success with the {kind, source, target} attribute
// shape specifies. Two dispatches drive both branches (fronted +
// direct) so the assertion catches a refactor that drops either kind label
// or transposes source/target on the direct path.
func TestDispatchMint_Metric_LabelsOnSuccess(t *testing.T) {
	mc := newMetricCollector(t)

	f := stdFixture(t)
	// Hot-swap the single counter we care about; everything else (durations,
	// denials) stays on the noop meter the fixture built. The struct field
	// is exported and Int64Counter is an interface, so this is in-contract.
	f.svc.metrics.TokenExchangeTotal = mc.int64Counter(t, "authplane_token_exchange_total")
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{"A": {"AA"}})
	// Seed a second user/agent so the direct path's consent grant doesn't
	// collide with what the fronted path ignores.
	f.seedConsentGrant(frUserID, frAgentID, f.target.ID, []string{"AA"})

	// 1. Fronted dispatch.
	subj := subjectClaimsForFronting("A", frAgentID, []string{frSourceURI})
	if _, _, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA",
	}, subj, f.target); err != nil {
		t.Fatalf("fronted dispatch: %v", err)
	}

	// 2. Direct dispatch — same shape, but no link applies (AA covers via
	// consent_grants). Drop just the seeded link; the metric state from
	// the first dispatch stays preserved on the same reader. Clear the
	// subject scope claim so the request models the identity-only token
	// flow — the source-side scope "A" is in the fronted name space and
	// doesn't cover the target scope "AA" under the hybrid ceiling
	// (ADR-002); the consent_grants row remains the operative authority.
	if err := f.frontingLinks.Delete(context.Background(), frSourceSlug, frTargetSlug); err != nil {
		t.Fatalf("delete fronting link: %v", err)
	}
	directSubj := *subj
	directSubj.Scope = ""
	if _, _, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA",
	}, &directSubj, f.target); err != nil {
		t.Fatalf("direct dispatch: %v", err)
	}

	points := mc.dataPoints(t, "authplane_token_exchange_total")
	if len(points) < 2 {
		t.Fatalf("got %d data points, want >=2 (fronted + direct)", len(points))
	}

	// Fronted point: kind=fronted, source=mcp-gw, target=rest-api, value 1.
	if !pointHasAttrs(t, points, map[string]string{
		"kind": "fronted", "source": frSourceSlug, "target": frTargetSlug,
	}, 1) {
		t.Errorf("missing fronted data point with expected attrs and value=1 (got %s)", debugPoints(points))
	}
	// Direct point: kind=direct, empty source label, target=rest-api, value 1.
	// Empty-string source on direct is intentional per dispatchMint:1071-1077.
	if !pointHasAttrs(t, points, map[string]string{
		"kind": "direct", "source": "", "target": frTargetSlug,
	}, 1) {
		t.Errorf("missing direct data point with expected attrs and value=1 (got %s)", debugPoints(points))
	}
}

// pointHasAttrs walks dataPoints looking for one whose attribute set matches
// every (k, v) pair in want and whose Value equals wantVal. Returns true on
// hit. Used in place of findPoint above to keep the attribute-key plumbing
// in one place.
func pointHasAttrs(t *testing.T, points []metricdata.DataPoint[int64], want map[string]string, wantVal int64) bool {
	t.Helper()
	for _, p := range points {
		hits := 0
		for k, v := range want {
			for _, kv := range p.Attributes.ToSlice() {
				if string(kv.Key) == k && kv.Value.AsString() == v {
					hits++
					break
				}
			}
		}
		if hits == len(want) && p.Value == wantVal {
			return true
		}
	}
	return false
}

// debugPoints renders point attrs+values as a string for failure messages.
func debugPoints(points []metricdata.DataPoint[int64]) string {
	var b strings.Builder
	for i, p := range points {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString("{")
		for j, kv := range p.Attributes.ToSlice() {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString(string(kv.Key))
			b.WriteString("=")
			b.WriteString(kv.Value.AsString())
		}
		b.WriteString("} v=")
		b.WriteString(itoaInt64(p.Value))
	}
	return b.String()
}

func itoaInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// -- resolveSourceForFronting as a unit ---------------------------------------

func TestResolveSourceForFronting(t *testing.T) {
	const (
		brokerSlug = "broker-rs"
		brokerURI  = "https://broker-rs.example.com"
	)

	f := stdFixture(t)
	// Seed a broker-backed resource so the "non-Mint skip" case has a real
	// row to walk past, not just a nil from the registry.
	br := &resource.Resource{
		ID:          "rid-" + brokerSlug,
		Slug:        brokerSlug,
		DisplayName: brokerSlug,
		URI:         brokerURI,
		BackendKind: resource.BackendBroker,
	}
	if err := f.resources.Create(context.Background(), br); err != nil {
		t.Fatalf("seed broker resource: %v", err)
	}

	tests := []struct {
		name     string
		audience []string
		wantSlug string // empty string means nil
	}{
		{"empty audience", nil, ""},
		{"only blanks", []string{"", ""}, ""},
		{"issuer skipped", []string{teFrontingIssuer}, ""},
		{"unresolvable URI", []string{"https://nope.example"}, ""},
		{"single Mint resolves", []string{frSourceURI}, frSourceSlug},
		{"first Mint wins (both Mint)", []string{frSourceURI, frTargetURI}, frSourceSlug},
		{"non-Mint skipped, next Mint wins", []string{brokerURI, frSourceURI}, frSourceSlug},
		{"only non-Mint returns nil", []string{brokerURI}, ""},
		{"issuer + Mint: walks past issuer", []string{teFrontingIssuer, frSourceURI}, frSourceSlug},
		{"unresolvable + Mint: walks past miss", []string{"https://nope.example", frSourceURI}, frSourceSlug},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.svc.resolveSourceForFronting(context.Background(), tt.audience)
			if tt.wantSlug == "" {
				if got != nil {
					t.Errorf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil, want resource with slug=%q", tt.wantSlug)
			}
			if got.Slug != tt.wantSlug {
				t.Errorf("got slug=%q, want %q", got.Slug, tt.wantSlug)
			}
		})
	}
}

// TestResolveSourceForFronting_NilDeps pins the nil-tolerance contract — the
// helper short-circuits when either dependency is unwired so direct-path
// callers (no fronting service injected) keep working byte-identically.
func TestResolveSourceForFronting_NilDeps(t *testing.T) {
	f := stdFixture(t)

	t.Run("fronting unwired", func(t *testing.T) {
		saved := f.svc.fronting
		f.svc.fronting = nil
		defer func() { f.svc.fronting = saved }()
		if got := f.svc.resolveSourceForFronting(context.Background(), []string{frSourceURI}); got != nil {
			t.Errorf("fronting=nil: got %+v, want nil", got)
		}
	})
	t.Run("registry unwired", func(t *testing.T) {
		saved := f.svc.registry
		f.svc.registry = nil
		defer func() { f.svc.registry = saved }()
		if got := f.svc.resolveSourceForFronting(context.Background(), []string{frSourceURI}); got != nil {
			t.Errorf("registry=nil: got %+v, want nil", got)
		}
	})
}

// -- Fronted-broker live observability ---

// captureLogHandler records every slog record so tests can assert log shape
// (message + attrs) without coupling to formatter output. Concurrency-safe
// because dispatch may emit from multiple spans during a single call.
type captureLogHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	Level   slog.Level
	Message string
	Attrs   map[string]any
}

func (h *captureLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureLogHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{Level: r.Level, Message: r.Message, Attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.Attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}
func (h *captureLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureLogHandler) WithGroup(_ string) slog.Handler      { return h }

// TestFrontedBroker_LiveObservability_NoWarn inverts the warn-shape
// test that previously asserted a defensive "link exists but target is not
// Mint — ignored" log for fronted-broker exchanges. After (T8 + T9)
// lights up the fronted-broker path through dispatchBroker, the warn is
// unreachable dead code — broker targets route to dispatchBroker →
// dispatchFrontedBroker, which emits audit + metric with broker labels.
//
// This test confirms three things:
//  1. The dead-code warn does NOT fire on the now-live fronted-broker path.
//  2. The dispatch-site audit event carries the fronted-broker label set
//     (chain_kind=fronted, target_kind=broker, via_link=source->target).
//  3. No defensive metric is asserted here — T9's
//     TestDispatchFrontedBroker_Audit_Success already pins that shape; this
//     test does not duplicate it.
func TestFrontedBroker_LiveObservability_NoWarn(t *testing.T) {
	f := stdBrokerFixture(t)
	// Replace the fixture logger with a capturing one so we can assert that
	// the dead-code warn branch does not fire.
	logs := &captureLogHandler{}
	f.svc.logger = slog.New(logs)

	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})
	f.adapter.vendAccessToken = "ut-1"

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	if _, err := f.dispatchBrokerFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frBrokerTargetSlug,
		Scope:    "readonly",
	}, subj); err != nil {
		t.Fatalf("dispatchBroker: %v", err)
	}

	// Assertion 1: the dead-code warn must NOT fire.
	// The message text is the string operators would grep for. If
	// something changed and the warn re-appears, the test catches it.
	const deadCodeWarn = "fronting link exists but target is not Mint — ignored"
	for _, rec := range logs.records {
		if rec.Level == slog.LevelWarn && rec.Message == deadCodeWarn {
			t.Errorf("dead-code warn fired on live fronted-broker path: %+v", rec)
		}
	}

	// Assertion 2: the dispatch-site audit event carries the fronted-broker
	// label set. BrokerIssuer.Issue also emits its own audit row; we
	// identify the dispatch-site emission by the type=broker_dispatch tag.
	events := f.auditRec.take()
	found := false
	for _, ev := range events {
		if ev.Action != audit.ActionTokenExchanged {
			continue
		}
		if !strings.Contains(ev.Detail, "type=broker_dispatch") {
			continue
		}
		for _, want := range []string{
			"chain_kind=fronted",
			"target_kind=broker",
			"via_link=" + frSourceSlug + "->" + frBrokerTargetSlug,
		} {
			if !strings.Contains(ev.Detail, want) {
				t.Errorf("audit detail %q missing fragment %q", ev.Detail, want)
			}
		}
		found = true
	}
	if !found {
		t.Fatalf("no ActionTokenExchanged audit event with type=broker_dispatch found; got %d events", len(events))
	}
}
