package observability

import (
	"context"

	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// NewNoop creates a no-op Provider suitable for testing.
func NewNoop() *Provider {
	meter := metricnoop.NewMeterProvider().Meter("noop")
	return &Provider{
		Logger:   buildDiscardLogger(),
		Tracer:   tracenoop.NewTracerProvider().Tracer("noop"),
		Meter:    meter,
		Metrics:  mustNewMetrics(meter),
		shutdown: func(context.Context) error { return nil },
	}
}

// NewNoopTracer returns a no-op tracer for testing.
func NewNoopTracer() trace.Tracer {
	return tracenoop.NewTracerProvider().Tracer("noop")
}

// NewNoopMeter returns a no-op meter for testing.
func NewNoopMeter() metric.Meter {
	return metricnoop.NewMeterProvider().Meter("noop")
}
