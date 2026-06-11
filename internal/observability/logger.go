package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/authplane/authserver/internal/config"
)

// TraceContextHandler injects trace_id, span_id, and request_id into every log record.
type TraceContextHandler struct {
	inner slog.Handler
}

// NewTraceContextHandler wraps a handler to inject trace context attributes.
func NewTraceContextHandler(inner slog.Handler) *TraceContextHandler {
	return &TraceContextHandler{inner: inner}
}

// Enabled implements slog.Handler.
func (h *TraceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *TraceContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		spanCtx := trace.SpanContextFromContext(ctx)
		if spanCtx.IsValid() {
			r.AddAttrs(
				slog.String("trace_id", spanCtx.TraceID().String()),
				slog.String("span_id", spanCtx.SpanID().String()),
			)
		}
		if reqID, ok := RequestIDFromContext(ctx); ok {
			r.AddAttrs(slog.String("request_id", reqID))
		}
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h *TraceContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TraceContextHandler{inner: h.inner.WithAttrs(attrs)}
}

// WithGroup implements slog.Handler.
func (h *TraceContextHandler) WithGroup(name string) slog.Handler {
	return &TraceContextHandler{inner: h.inner.WithGroup(name)}
}

// MultiHandler fans out log records to multiple handlers.
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler creates a handler that writes to all provided handlers.
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Enabled implements slog.Handler.
func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle implements slog.Handler.
func (h *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		_ = handler.Handle(ctx, r) // Don't fail request if one output is down
	}
	return nil
}

// WithAttrs implements slog.Handler.
func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: handlers}
}

// WithGroup implements slog.Handler.
func (h *MultiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &MultiHandler{handlers: handlers}
}

// buildLogger assembles the logger handler chain from config.
// Returns the logger and a shutdown function for the OTel log provider (if configured).
func buildLogger(ctx context.Context, cfg config.ObservabilityConfig) (logger *slog.Logger, shutdown func(context.Context) error) {
	level := parseLogLevel(cfg.Logging.Level)
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.Logging.AddSource,
	}

	var handlers []slog.Handler
	logShutdown := func(context.Context) error { return nil }

	// stdout handler (default if no outputs configured)
	if cfg.Logging.Outputs.Stdout || !cfg.Logging.Outputs.OTel {
		var h slog.Handler
		if cfg.Logging.Format == "json" {
			h = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			h = slog.NewTextHandler(os.Stdout, opts)
		}
		handlers = append(handlers, h)
	}

	// OTel slog bridge — exports logs via OTLP gRPC
	if cfg.Logging.Outputs.OTel && cfg.Logging.Outputs.OTelEndpoint != "" {
		lp, shutdown, err := setupLogProvider(ctx, cfg.Logging.Outputs)
		if err == nil {
			otelHandler := otelslog.NewHandler(serviceName, otelslog.WithLoggerProvider(lp))
			handlers = append(handlers, otelHandler)
			logShutdown = shutdown
		}
		// On error, silently skip OTel logs — stdout remains available
	}

	// If no handlers at all, fall back to stdout
	if len(handlers) == 0 {
		handlers = append(handlers, slog.NewJSONHandler(os.Stdout, opts))
	}

	var inner slog.Handler
	if len(handlers) == 1 {
		inner = handlers[0]
	} else {
		inner = NewMultiHandler(handlers...)
	}

	// Wrap with TraceContextHandler for automatic trace_id/span_id/request_id injection
	wrapped := NewTraceContextHandler(inner)

	return slog.New(wrapped).With("service", serviceName), logShutdown
}

// setupLogProvider creates an OTel LoggerProvider with OTLP gRPC exporter.
func setupLogProvider(ctx context.Context, outputs config.LogOutputs) (*sdklog.LoggerProvider, func(context.Context) error, error) {
	grpcOpts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(outputs.OTelEndpoint),
	}
	if outputs.Insecure {
		grpcOpts = append(grpcOpts, otlploggrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), otlploggrpc.WithInsecure())
	}

	exporter, err := otlploggrpc.New(ctx, grpcOpts...)
	if err != nil {
		return nil, nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, nil, err
	}

	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return lp.Shutdown(ctx)
	}

	return lp, shutdown, nil
}

// buildDiscardLogger creates a logger that discards all output (for tests).
func buildDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
