package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestTraceContextHandler_InjectsTraceID(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	handler := NewTraceContextHandler(inner)
	logger := slog.New(handler)

	// Create a context with a valid span context
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "test message", "key", "value")

	var record map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("failed to parse JSON log: %v", err)
	}

	if record["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected trace_id 4bf92f3577b34da6a3ce929d0e0e4736, got %v", record["trace_id"])
	}
	if record["span_id"] != "00f067aa0ba902b7" {
		t.Errorf("expected span_id 00f067aa0ba902b7, got %v", record["span_id"])
	}
	if record["key"] != "value" {
		t.Errorf("expected key=value, got %v", record["key"])
	}
}

func TestTraceContextHandler_InjectsRequestID(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	handler := NewTraceContextHandler(inner)
	logger := slog.New(handler)

	ctx := WithRequestID(context.Background(), "req-abc-123")
	logger.InfoContext(ctx, "test message")

	var record map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("failed to parse JSON log: %v", err)
	}

	if record["request_id"] != "req-abc-123" {
		t.Errorf("expected request_id req-abc-123, got %v", record["request_id"])
	}
}

func TestTraceContextHandler_NoContextNoInjection(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	handler := NewTraceContextHandler(inner)
	logger := slog.New(handler)

	logger.InfoContext(context.Background(), "test message")

	var record map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("failed to parse JSON log: %v", err)
	}

	if _, ok := record["trace_id"]; ok {
		t.Error("expected no trace_id without active span")
	}
	if _, ok := record["request_id"]; ok {
		t.Error("expected no request_id without one in context")
	}
}

func TestMultiHandler_FansOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := slog.NewJSONHandler(&buf1, &slog.HandlerOptions{Level: slog.LevelInfo})
	h2 := slog.NewJSONHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelInfo})
	multi := NewMultiHandler(h1, h2)
	logger := slog.New(multi)

	logger.InfoContext(context.Background(), "fan out test")

	if buf1.Len() == 0 {
		t.Error("expected output in first handler")
	}
	if buf2.Len() == 0 {
		t.Error("expected output in second handler")
	}
}

func TestMultiHandler_EnabledAny(t *testing.T) {
	// One handler at Info, one at Error. Multi should be enabled at Info.
	h1 := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})
	h2 := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})
	multi := NewMultiHandler(h1, h2)

	if !multi.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("MultiHandler should be enabled at Info when at least one handler accepts it")
	}
}
