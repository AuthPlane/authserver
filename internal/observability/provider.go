// Package observability provides unified logging, tracing, and metrics.
package observability

import (
	"context"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/authplane/authserver/internal/config"
)

// Provider holds all observability components.
type Provider struct {
	Logger      *slog.Logger
	Tracer      trace.Tracer
	Meter       metric.Meter
	Metrics     *Metrics
	promHandler http.Handler
	shutdown    func(context.Context) error
}

const serviceName = "authserver"

// New creates a fully-wired observability provider from configuration.
// Returns the provider, a shutdown function, and any error.
func New(ctx context.Context, cfg config.ObservabilityConfig) (*Provider, func(context.Context) error, error) {
	p := &Provider{}

	// Build logger with TraceContextHandler + optional OTel bridge
	var logShutdown func(context.Context) error
	p.Logger, logShutdown = buildLogger(ctx, cfg)

	// Setup tracing
	tracer, tracerShutdown, err := setupTracing(ctx, cfg.Tracing)
	if err != nil {
		p.Logger.Error("failed to setup tracing, using noop", "error", err)
		p.Tracer = tracenoop.NewTracerProvider().Tracer(serviceName)
		tracerShutdown = func(context.Context) error { return nil }
	} else {
		p.Tracer = tracer
	}

	// Setup metrics
	metricsResult, err := setupMetricsProvider(ctx, cfg.Metrics)
	if err != nil {
		p.Logger.Error("failed to setup metrics, using noop", "error", err)
		p.Meter = metricnoop.NewMeterProvider().Meter(serviceName)
	} else {
		p.Meter = metricsResult.meter
		p.promHandler = metricsResult.promHandler
	}

	// Pre-register all metric instruments
	p.Metrics = mustNewMetrics(p.Meter)

	// Combined shutdown
	meterShutdown := func(context.Context) error { return nil }
	if metricsResult != nil {
		meterShutdown = metricsResult.shutdown
	}
	p.shutdown = func(ctx context.Context) error {
		var lastErr error
		if err := tracerShutdown(ctx); err != nil {
			lastErr = err
		}
		if err := meterShutdown(ctx); err != nil {
			lastErr = err
		}
		if err := logShutdown(ctx); err != nil {
			lastErr = err
		}
		return lastErr
	}

	return p, p.shutdown, nil
}

// Setup creates a provider (backward-compatible wrapper around New).
func Setup(cfg config.ObservabilityConfig) *Provider {
	p, _, err := New(context.Background(), cfg)
	if err != nil {
		// Fallback to noop on error
		return NewNoop()
	}
	return p
}

// Shutdown gracefully shuts down tracing/metrics exporters.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.shutdown != nil {
		return p.shutdown(ctx)
	}
	return nil
}

// WithComponent returns a derivative Provider scoped to a component name.
func (p *Provider) WithComponent(component string) *Provider {
	return &Provider{
		Logger:      p.Logger.With("component", component),
		Tracer:      p.Tracer,
		Meter:       p.Meter,
		Metrics:     p.Metrics,
		promHandler: p.promHandler,
		shutdown:    p.shutdown,
	}
}

// PrometheusHandler returns the Prometheus metrics HTTP handler, or nil if not using Prometheus.
func (p *Provider) PrometheusHandler() http.Handler {
	return p.promHandler
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
