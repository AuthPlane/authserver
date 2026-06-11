package observability

import (
	"context"
	"log/slog"
	"testing"
)

func TestRequestIDRoundTrip(t *testing.T) {
	ctx := context.Background()

	// No request ID in empty context
	_, ok := RequestIDFromContext(ctx)
	if ok {
		t.Fatal("expected no request_id in empty context")
	}

	// Set and retrieve
	ctx = WithRequestID(ctx, "req-123")
	id, ok := RequestIDFromContext(ctx)
	if !ok {
		t.Fatal("expected request_id in context")
	}
	if id != "req-123" {
		t.Fatalf("expected req-123, got %s", id)
	}
}

func TestLoggerRoundTrip(t *testing.T) {
	ctx := context.Background()
	fallback := slog.Default()

	// Fallback when not set
	got := LoggerFromContext(ctx, fallback)
	if got != fallback {
		t.Fatal("expected fallback logger")
	}

	// Set and retrieve
	custom := slog.Default().With("test", true)
	ctx = WithLogger(ctx, custom)
	got = LoggerFromContext(ctx, fallback)
	if got != custom {
		t.Fatal("expected custom logger from context")
	}
}
