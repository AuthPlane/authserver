package serviceaccount

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
	var names []string
	for _, s := range exporter.GetSpans() {
		if s.Name == name {
			return s
		}
		names = append(names, s.Name)
	}
	t.Fatalf("no span named %q; got %v", name, names)
	return tracetest.SpanStub{}
}

func attrValue(span tracetest.SpanStub, key string) (attribute.Value, bool) {
	for _, kv := range span.Attributes {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

const secretBodyMarker = "SECRET-UPSTREAM-BODY-MARKER"

func TestServiceAccountAdapter_Issue_SpanAndWarnOnUpstream500(t *testing.T) {
	fu := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"server_error","detail":"`+secretBodyMarker+`"}`)
	})
	_, keyPEM := rsaKeyPair(t)
	obs, exporter, logs := newTracedObs(t)
	a := New(fu.server.Client(), &stubSecretResolver{pem: keyPEM},
		WithAllowLoopback(true), WithObservability(obs))
	prov := mustProvider(t, fu.configBytes(t, "RS256", 3600))
	r := mustResource(resource.Scope{Name: "calendar:read", Upstream: "x"})
	cred, _ := marshalCredential("alice@example.com")

	_, _, _, err := a.Vend(context.Background(), prov, r, cred, []string{"calendar:read"})
	if err == nil {
		t.Fatal("expected error from 500 response, got nil")
	}

	span := findSpan(t, exporter, "ServiceAccount.Issue")
	if v, ok := attrValue(span, "provider_slug"); !ok || v.AsString() != "google-workspace-sa" {
		t.Errorf("provider_slug attribute = %v (present=%v), want google-workspace-sa", v.AsString(), ok)
	}
	if v, ok := attrValue(span, "outcome"); !ok || v.AsString() != "error" {
		t.Errorf("outcome attribute = %v (present=%v), want error", v.AsString(), ok)
	}
	if v, ok := attrValue(span, "http.status_code"); !ok || v.AsInt64() != http.StatusInternalServerError {
		t.Errorf("http.status_code attribute = %v (present=%v), want 500", v.AsInt64(), ok)
	}
	if span.Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", span.Status.Code)
	}
	if strings.Contains(span.Status.Description, secretBodyMarker) {
		t.Errorf("span status description leaks the response body: %q", span.Status.Description)
	}

	line := logs.String()
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "upstream token exchange failed") {
		t.Fatalf("expected a WARN 'upstream token exchange failed' line, got: %q", line)
	}
	if !strings.Contains(line, "provider_slug=google-workspace-sa") || !strings.Contains(line, "status=500") {
		t.Errorf("log line missing provider_slug/status: %q", line)
	}
	if strings.Contains(line, secretBodyMarker) || strings.Contains(line, fu.lastAssertion) {
		t.Errorf("log line leaks the response body or the assertion: %q", line)
	}
}

func TestServiceAccountAdapter_Issue_SuccessSpanNoWarn(t *testing.T) {
	fu := newFakeUpstream(t, jsonTokenResponder(map[string]any{
		"access_token": "at", "expires_in": 3600,
	}))
	_, keyPEM := rsaKeyPair(t)
	obs, exporter, logs := newTracedObs(t)
	a := New(fu.server.Client(), &stubSecretResolver{pem: keyPEM},
		WithAllowLoopback(true), WithObservability(obs))
	prov := mustProvider(t, fu.configBytes(t, "RS256", 3600))
	cred, _ := marshalCredential("alice@example.com")

	if _, _, _, err := a.Vend(context.Background(), prov, mustResource(), cred, nil); err != nil {
		t.Fatalf("Vend: %v", err)
	}
	span := findSpan(t, exporter, "ServiceAccount.Issue")
	if v, ok := attrValue(span, "outcome"); !ok || v.AsString() != "success" {
		t.Errorf("outcome attribute = %v (present=%v), want success", v.AsString(), ok)
	}
	if span.Status.Code == codes.Error {
		t.Errorf("span status = Error on a successful exchange")
	}
	if logs.Len() != 0 {
		t.Errorf("expected no WARN log on success, got: %q", logs.String())
	}
}
