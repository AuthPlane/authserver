package hcvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/authplane/authserver/internal/observability"
)

// newTracedVaultSigner returns a VaultSigner backed by a fake Transit sign
// endpoint and a tracer that records into the returned exporter.
func newTracedVaultSigner(t *testing.T) (*VaultSigner, *tracetest.InMemoryExporter) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/sign/mykey" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		sig := base64.StdEncoding.EncodeToString([]byte("signature"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"signature": "vault:v1:" + sig, "key_version": 1},
		})
	}))
	t.Cleanup(srv.Close)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	obs := observability.NewNoop()
	obs.Tracer = tp.Tracer("test")

	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
		Timeout: 5 * time.Second,
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(c.Close)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewVaultSigner(c, "mykey", 1, &priv.PublicKey, "ES256"), exp
}

func TestVaultSigner_SignContext_JoinsCallerTrace(t *testing.T) {
	signer, exp := newTracedVaultSigner(t)

	ctx, parent := signer.client.tracer.Start(context.Background(), "caller")
	digest := make([]byte, 32)
	if _, err := signer.SignContext(ctx, digest, crypto.SHA256); err != nil {
		t.Fatalf("SignContext: %v", err)
	}
	parent.End()

	spans := exp.GetSpans()
	var signSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "VaultClient.Sign" {
			signSpan = &spans[i]
		}
	}
	if signSpan == nil {
		t.Fatalf("no VaultClient.Sign span recorded; got %d spans", len(spans))
	}
	if got, want := signSpan.Parent.SpanID(), parent.SpanContext().SpanID(); got != want {
		t.Fatalf("VaultClient.Sign parent span = %s, want caller %s", got, want)
	}
	if got, want := signSpan.SpanContext.TraceID(), parent.SpanContext().TraceID(); got != want {
		t.Fatalf("VaultClient.Sign trace = %s, want caller trace %s", got, want)
	}
}

func TestVaultSigner_Sign_WithoutContextIsRoot(t *testing.T) {
	signer, exp := newTracedVaultSigner(t)

	digest := make([]byte, 32)
	if _, err := signer.Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "VaultClient.Sign" {
		t.Fatalf("expected one VaultClient.Sign span, got %d", len(spans))
	}
	if spans[0].Parent.IsValid() {
		t.Fatalf("plain Sign should produce a root span, parent = %s", spans[0].Parent.SpanID())
	}
}
