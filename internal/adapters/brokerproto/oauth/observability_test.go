package oauth

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
)

// newTracedObs returns a Provider whose tracer exports synchronously into an
// in-memory exporter and whose logger captures WARN and above into a buffer.
func newTracedObs(t *testing.T) (*observability.Provider, *tracetest.InMemoryExporter, *bytes.Buffer) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	var logs bytes.Buffer
	obs := observability.NewNoop()
	obs.Tracer = tp.Tracer("test")
	obs.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return obs, exporter, &logs
}

func findSpan(t *testing.T, exporter *tracetest.InMemoryExporter, name string) tracetest.SpanStub {
	t.Helper()
	for _, s := range exporter.GetSpans() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no span named %q; got %v", name, spanNames(exporter))
	return tracetest.SpanStub{}
}

func spanNames(exporter *tracetest.InMemoryExporter) []string {
	var names []string
	for _, s := range exporter.GetSpans() {
		names = append(names, s.Name)
	}
	return names
}

func attrValue(span tracetest.SpanStub, key string) (attribute.Value, bool) {
	for _, kv := range span.Attributes {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func wantStringAttr(t *testing.T, span tracetest.SpanStub, key, want string) {
	t.Helper()
	v, ok := attrValue(span, key)
	if !ok {
		t.Fatalf("span %q missing attribute %q", span.Name, key)
	}
	if v.AsString() != want {
		t.Errorf("span %q attribute %q = %q, want %q", span.Name, key, v.AsString(), want)
	}
}

func wantIntAttr(t *testing.T, span tracetest.SpanStub, key string, want int64) {
	t.Helper()
	v, ok := attrValue(span, key)
	if !ok {
		t.Fatalf("span %q missing attribute %q", span.Name, key)
	}
	if v.AsInt64() != want {
		t.Errorf("span %q attribute %q = %d, want %d", span.Name, key, v.AsInt64(), want)
	}
}

const secretBodyMarker = "SECRET-UPSTREAM-BODY-MARKER"

func TestOAuthAdapter_Exchange_SpanAndWarnOnUpstream500(t *testing.T) {
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"server_error","detail":"`+secretBodyMarker+`"}`)
	})
	obs, exporter, logs := newTracedObs(t)
	a := New(fu.server.Client(), &stubSecretResolver{secret: "test-secret"},
		WithAllowLoopback(true), WithObservability(obs))
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "x"})
	pending := &resource.ConnectPendingState{ID: "state-1", CodeVerifier: "verifier-1"}

	_, _, err := a.HandleCallback(context.Background(), prov, r, "code", "", pending)
	if err == nil {
		t.Fatal("expected error from 500 response, got nil")
	}

	span := findSpan(t, exporter, "OAuthUpstream.Exchange")
	wantStringAttr(t, span, "provider_slug", "google-workspace")
	wantStringAttr(t, span, "outcome", "error")
	wantIntAttr(t, span, "http.status_code", http.StatusInternalServerError)
	if span.Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", span.Status.Code)
	}
	if strings.Contains(span.Status.Description, secretBodyMarker) {
		t.Errorf("span status description leaks the response body: %q", span.Status.Description)
	}
	for _, ev := range span.Events {
		for _, kv := range ev.Attributes {
			if strings.Contains(kv.Value.AsString(), secretBodyMarker) {
				t.Errorf("span event %q leaks the response body: %q", ev.Name, kv.Value.AsString())
			}
		}
	}

	line := logs.String()
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "upstream token exchange failed") {
		t.Fatalf("expected a WARN 'upstream token exchange failed' line, got: %q", line)
	}
	if !strings.Contains(line, "provider_slug=google-workspace") {
		t.Errorf("log line missing provider_slug: %q", line)
	}
	if !strings.Contains(line, "status=500") {
		t.Errorf("log line missing status=500: %q", line)
	}
	if strings.Contains(line, secretBodyMarker) {
		t.Errorf("log line leaks the response body: %q", line)
	}
	if strings.Count(line, "\n") != 1 {
		t.Errorf("expected exactly one log line, got: %q", line)
	}
}

func TestOAuthAdapter_Exchange_NoWarnAndSuccessSpanOn200(t *testing.T) {
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "scope": "x",
	}))
	obs, exporter, logs := newTracedObs(t)
	a := New(fu.server.Client(), &stubSecretResolver{secret: "test-secret"},
		WithAllowLoopback(true), WithObservability(obs))
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "x"})
	pending := &resource.ConnectPendingState{ID: "state-1", CodeVerifier: "verifier-1"}

	if _, _, err := a.HandleCallback(context.Background(), prov, r, "code", "", pending); err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}

	span := findSpan(t, exporter, "OAuthUpstream.Exchange")
	wantStringAttr(t, span, "provider_slug", "google-workspace")
	wantStringAttr(t, span, "outcome", "success")
	wantIntAttr(t, span, "http.status_code", http.StatusOK)
	if span.Status.Code == codes.Error {
		t.Errorf("span status = Error on a successful exchange")
	}
	if logs.Len() != 0 {
		t.Errorf("expected no WARN log on success, got: %q", logs.String())
	}
}

func TestOAuthAdapter_Refresh_SpanAndWarnOnInvalidGrant(t *testing.T) {
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"`+secretBodyMarker+`"}`)
	})
	obs, exporter, logs := newTracedObs(t)
	a := New(fu.server.Client(), &stubSecretResolver{secret: "test-secret"},
		WithAllowLoopback(true), WithObservability(obs))
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "x"})
	cred, _ := marshalCredential("old-refresh-token")

	_, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err == nil {
		t.Fatal("expected error from 400 response, got nil")
	}
	// The caller-facing error keeps the truncated body for diagnostics.
	if !strings.Contains(err.Error(), secretBodyMarker) {
		t.Errorf("returned error should carry the truncated body, got: %v", err)
	}

	span := findSpan(t, exporter, "OAuthUpstream.Refresh")
	wantStringAttr(t, span, "provider_slug", "google-workspace")
	wantStringAttr(t, span, "outcome", "error")
	wantIntAttr(t, span, "http.status_code", http.StatusBadRequest)
	if span.Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", span.Status.Code)
	}
	if strings.Contains(span.Status.Description, secretBodyMarker) {
		t.Errorf("span status description leaks the response body: %q", span.Status.Description)
	}

	line := logs.String()
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "upstream token refresh failed") {
		t.Fatalf("expected a WARN 'upstream token refresh failed' line, got: %q", line)
	}
	if !strings.Contains(line, "provider_slug=google-workspace") || !strings.Contains(line, "status=400") {
		t.Errorf("log line missing provider_slug/status: %q", line)
	}
	if strings.Contains(line, secretBodyMarker) || strings.Contains(line, "old-refresh-token") {
		t.Errorf("log line leaks the response body or credential: %q", line)
	}
}

func TestOAuthAdapter_DefaultsToleratesNilObservability(t *testing.T) {
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "at", "expires_in": 60,
	}))
	a := New(fu.server.Client(), &stubSecretResolver{secret: "s"},
		WithAllowLoopback(true), WithObservability(nil))
	if a.logger == nil || a.tracer == nil {
		t.Fatal("nil observability provider must leave the defaults in place")
	}
	prov := mustProvider(t, fu.configBytes(t, nil, "standard"))
	cred, _ := marshalCredential("rt")
	if _, _, _, err := a.Vend(context.Background(), prov, mustResource(), cred, nil); err != nil {
		t.Fatalf("Vend with default observability: %v", err)
	}
}
