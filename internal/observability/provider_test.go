package observability

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/config"
)

func TestNewNoop(t *testing.T) {
	p := NewNoop()
	if p.Logger == nil {
		t.Fatal("NewNoop logger should not be nil")
	}
	if p.Tracer == nil {
		t.Fatal("NewNoop tracer should not be nil")
	}
	if p.Meter == nil {
		t.Fatal("NewNoop meter should not be nil")
	}
	if p.Metrics == nil {
		t.Fatal("NewNoop metrics should not be nil")
	}
}

func TestNew_DefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	// Disable prometheus for test (requires no real exporter)
	cfg.Metrics.Provider = "none"

	p, shutdown, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	if p.Logger == nil {
		t.Fatal("logger should not be nil")
	}
	if p.Tracer == nil {
		t.Fatal("tracer should not be nil")
	}
	if p.Meter == nil {
		t.Fatal("meter should not be nil")
	}
	if p.Metrics == nil {
		t.Fatal("metrics should not be nil")
	}
	if p.Metrics.TokensIssued == nil {
		t.Fatal("metrics.TokensIssued should not be nil")
	}
}

func TestNew_PrometheusConfig(t *testing.T) {
	cfg := config.ObservabilityConfig{
		Logging: config.LoggingConfig{
			Level:   "info",
			Format:  "json",
			Outputs: config.LogOutputs{Stdout: true},
		},
		Metrics: config.MetricsConfig{
			Provider: "prometheus",
			Path:     "/metrics",
		},
		Tracing: config.TracingConfig{
			Enabled: false,
		},
	}

	p, shutdown, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	if p.PrometheusHandler() == nil {
		t.Fatal("PrometheusHandler should not be nil with prometheus provider")
	}
}

func TestNew_NoneMetrics(t *testing.T) {
	cfg := config.ObservabilityConfig{
		Logging: config.LoggingConfig{
			Level:   "info",
			Format:  "text",
			Outputs: config.LogOutputs{Stdout: true},
		},
		Metrics: config.MetricsConfig{
			Provider: "none",
		},
		Tracing: config.TracingConfig{
			Enabled: false,
		},
	}

	p, shutdown, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	if p.PrometheusHandler() != nil {
		t.Fatal("PrometheusHandler should be nil with none provider")
	}
}

func TestWithComponent(t *testing.T) {
	p := NewNoop()
	child := p.WithComponent("test-component")

	if child.Tracer != p.Tracer {
		t.Fatal("child tracer should be same as parent")
	}
	if child.Meter != p.Meter {
		t.Fatal("child meter should be same as parent")
	}
	if child.Metrics != p.Metrics {
		t.Fatal("child metrics should be same as parent")
	}
}

func TestSetup_BackwardCompat(t *testing.T) {
	cfg := config.ObservabilityConfig{
		Logging: config.LoggingConfig{
			Level:   "info",
			Format:  "json",
			Outputs: config.LogOutputs{Stdout: true},
		},
		Metrics: config.MetricsConfig{
			Provider: "none",
		},
		Tracing: config.TracingConfig{
			Enabled: false,
		},
	}

	p := Setup(cfg)
	if p == nil {
		t.Fatal("Setup should return non-nil provider")
	}
	if p.Metrics == nil {
		t.Fatal("Setup should populate Metrics")
	}
}
