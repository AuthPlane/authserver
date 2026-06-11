package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/authplane/authserver/internal/config"
)

// Metrics holds all pre-registered application metric instruments.
type Metrics struct {
	// Counters
	TokensIssued      metric.Int64Counter
	TokensRefreshed   metric.Int64Counter
	TokensRevoked     metric.Int64Counter
	AuthDenied        metric.Int64Counter
	ClientsRegistered metric.Int64Counter
	ConsentDecisions  metric.Int64Counter
	LoginAttempts     metric.Int64Counter
	RefreshTokenReuse metric.Int64Counter

	// Histograms
	TokenIssuanceDuration metric.Float64Histogram
	AuthFlowDuration      metric.Float64Histogram
	CIMDFetchDuration     metric.Float64Histogram
	DBOperationDuration   metric.Float64Histogram

	// OIDC
	OIDCExchangeDuration metric.Float64Histogram
	OIDCJWKSCacheHits    metric.Int64Counter
	OIDCJWKSCacheMisses  metric.Int64Counter

	// Introspection
	IntrospectionDuration metric.Float64Histogram
	IntrospectionTotal    metric.Int64Counter

	// Signing key management
	KeyRotationTotal  metric.Int64Counter
	KeyReloadDuration metric.Float64Histogram

	// Upstream broker connections (the AS-side of vending upstream-format
	// access tokens to MCP clients via stored per-user credentials).
	UpstreamTokenIssuedTotal      metric.Int64Counter
	UpstreamTokenIssuanceDuration metric.Float64Histogram
	UpstreamTokenRefreshTotal     metric.Int64Counter
	ConnectionConnectTotal        metric.Int64Counter
	ConnectionDisconnectTotal     metric.Int64Counter

	// Client Credentials (Phase 3)
	ClientCredentialsIssued metric.Int64Counter
	ClientCredentialsDenied metric.Int64Counter

	// DPoP (Phase 3 — RFC 9449)
	DPoPProofsValidated metric.Int64Counter
	DPoPProofsRejected  metric.Int64Counter

	// Token Exchange (Phase 3 — RFC 8693)
	TokenExchangeTotal  metric.Int64Counter
	TokenExchangeDenied metric.Int64Counter

	// Agent Identity (Phase 3 — Authplane extension)
	AgentTokensIssued metric.Int64Counter

	// XAA — Enterprise-Managed Authorization
	XAAPolicyEvaluationTotal metric.Int64Counter
	XAAIDPOperationsTotal    metric.Int64Counter
	XAASubjectResolutions    metric.Int64Counter

	// Resource Server + Cross-Client Allowlist admin operations
	ResourceServerOps metric.Int64Counter
	AllowlistOps      metric.Int64Counter

	// Gauges
	ActiveClients       metric.Int64UpDownCounter
	ActiveTokenFamilies metric.Int64UpDownCounter

	// HTTP (registered here, used in middleware)
	HTTPRequestDuration metric.Float64Histogram
	HTTPRequestsTotal   metric.Int64Counter
}

// Bucket boundaries for sub-second latency histograms (unit: seconds).
// Default OTel buckets (0, 5, 10, 25, ...) assume milliseconds, but we record seconds.
var latencyBuckets = metric.WithExplicitBucketBoundaries(
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
)

func newMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error

	// Counters
	if m.TokensIssued, err = meter.Int64Counter("authserver_tokens_issued_total",
		metric.WithDescription("Total tokens issued"),
	); err != nil {
		return nil, err
	}
	if m.TokensRefreshed, err = meter.Int64Counter("authserver_tokens_refreshed_total",
		metric.WithDescription("Total tokens refreshed"),
	); err != nil {
		return nil, err
	}
	if m.TokensRevoked, err = meter.Int64Counter("authserver_tokens_revoked_total",
		metric.WithDescription("Total tokens revoked"),
	); err != nil {
		return nil, err
	}
	if m.AuthDenied, err = meter.Int64Counter("authserver_auth_denied_total",
		metric.WithDescription("Total auth requests denied"),
	); err != nil {
		return nil, err
	}
	if m.ClientsRegistered, err = meter.Int64Counter("authserver_clients_registered_total",
		metric.WithDescription("Total clients registered"),
	); err != nil {
		return nil, err
	}
	if m.ConsentDecisions, err = meter.Int64Counter("authserver_consent_decisions_total",
		metric.WithDescription("Total consent decisions"),
	); err != nil {
		return nil, err
	}
	if m.LoginAttempts, err = meter.Int64Counter("authserver_login_attempts_total",
		metric.WithDescription("Total login attempts"),
	); err != nil {
		return nil, err
	}
	if m.RefreshTokenReuse, err = meter.Int64Counter("authserver_refresh_token_reuse_total",
		metric.WithDescription("Total refresh token reuse detections"),
	); err != nil {
		return nil, err
	}

	// Histograms
	if m.TokenIssuanceDuration, err = meter.Float64Histogram("authserver_token_issuance_duration_seconds",
		metric.WithDescription("Token issuance duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.AuthFlowDuration, err = meter.Float64Histogram("authserver_auth_flow_duration_seconds",
		metric.WithDescription("Authorization flow duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.CIMDFetchDuration, err = meter.Float64Histogram("authserver_cimd_fetch_duration_seconds",
		metric.WithDescription("CIMD document fetch duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.DBOperationDuration, err = meter.Float64Histogram("authserver_db_operation_duration_seconds",
		metric.WithDescription("Database operation duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}

	// OIDC
	if m.OIDCExchangeDuration, err = meter.Float64Histogram("authserver_oidc_exchange_duration_seconds",
		metric.WithDescription("OIDC code exchange and ID token verification duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.OIDCJWKSCacheHits, err = meter.Int64Counter("authserver_oidc_jwks_cache_hits_total",
		metric.WithDescription("Total OIDC JWKS cache hits"),
	); err != nil {
		return nil, err
	}
	if m.OIDCJWKSCacheMisses, err = meter.Int64Counter("authserver_oidc_jwks_cache_misses_total",
		metric.WithDescription("Total OIDC JWKS cache misses"),
	); err != nil {
		return nil, err
	}

	// Introspection
	if m.IntrospectionDuration, err = meter.Float64Histogram("authserver_introspection_duration_seconds",
		metric.WithDescription("Token introspection duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.IntrospectionTotal, err = meter.Int64Counter("authserver_introspection_total",
		metric.WithDescription("Total token introspections"),
	); err != nil {
		return nil, err
	}

	// Signing key management
	if m.KeyRotationTotal, err = meter.Int64Counter("authserver_key_rotation_total",
		metric.WithDescription("Total signing key rotations"),
	); err != nil {
		return nil, err
	}
	if m.KeyReloadDuration, err = meter.Float64Histogram("authserver_key_reload_duration_seconds",
		metric.WithDescription("JWKS cache reload duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}

	// Upstream broker connections
	if m.UpstreamTokenIssuedTotal, err = meter.Int64Counter("authserver_upstream_token_issued_total",
		metric.WithDescription("Total upstream-format access tokens vended to MCP clients"),
	); err != nil {
		return nil, err
	}
	if m.UpstreamTokenIssuanceDuration, err = meter.Float64Histogram("authserver_upstream_token_issuance_duration_seconds",
		metric.WithDescription("Upstream-format token issuance duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.UpstreamTokenRefreshTotal, err = meter.Int64Counter("authserver_upstream_token_refresh_total",
		metric.WithDescription("Total upstream auto-refresh operations against persisted credentials"),
	); err != nil {
		return nil, err
	}
	if m.ConnectionConnectTotal, err = meter.Int64Counter("authserver_connection_connect_total",
		metric.WithDescription("Total upstream-connection connect operations"),
	); err != nil {
		return nil, err
	}
	if m.ConnectionDisconnectTotal, err = meter.Int64Counter("authserver_connection_disconnect_total",
		metric.WithDescription("Total upstream-connection disconnect operations"),
	); err != nil {
		return nil, err
	}

	// Client Credentials (Phase 3)
	if m.ClientCredentialsIssued, err = meter.Int64Counter("authplane_client_credentials_issued_total",
		metric.WithDescription("Total client credentials tokens issued"),
	); err != nil {
		return nil, err
	}
	if m.ClientCredentialsDenied, err = meter.Int64Counter("authplane_client_credentials_denied_total",
		metric.WithDescription("Total client credentials requests denied"),
	); err != nil {
		return nil, err
	}

	// DPoP (Phase 3 — RFC 9449)
	if m.DPoPProofsValidated, err = meter.Int64Counter("authplane_dpop_proofs_validated_total",
		metric.WithDescription("Total DPoP proofs validated"),
	); err != nil {
		return nil, err
	}
	if m.DPoPProofsRejected, err = meter.Int64Counter("authplane_dpop_proofs_rejected_total",
		metric.WithDescription("Total DPoP proofs rejected"),
	); err != nil {
		return nil, err
	}

	// Token Exchange (Phase 3 — RFC 8693)
	if m.TokenExchangeTotal, err = meter.Int64Counter("authplane_token_exchange_total",
		metric.WithDescription("Total token exchange operations"),
	); err != nil {
		return nil, err
	}
	if m.TokenExchangeDenied, err = meter.Int64Counter("authplane_token_exchange_denied_total",
		metric.WithDescription("Total token exchange operations denied"),
	); err != nil {
		return nil, err
	}

	// Agent Identity (Phase 3 — Authplane extension)
	if m.AgentTokensIssued, err = meter.Int64Counter("authplane_agent_tokens_issued_total",
		metric.WithDescription("Total tokens issued with agent identity claims"),
	); err != nil {
		return nil, err
	}

	// XAA — Enterprise-Managed Authorization
	if m.XAAPolicyEvaluationTotal, err = meter.Int64Counter("authplane_xaa_policy_evaluation_total",
		metric.WithDescription("Total XAA policy evaluations"),
	); err != nil {
		return nil, err
	}
	if m.XAAIDPOperationsTotal, err = meter.Int64Counter("authplane_xaa_idp_operations_total",
		metric.WithDescription("Total XAA IdP management operations"),
	); err != nil {
		return nil, err
	}
	if m.XAASubjectResolutions, err = meter.Int64Counter("authplane_xaa_subject_resolutions_total",
		metric.WithDescription("Total XAA subject mapping resolutions"),
	); err != nil {
		return nil, err
	}

	// Resource Server + Cross-Client Allowlist admin operations
	if m.ResourceServerOps, err = meter.Int64Counter("authplane_resource_server_ops_total",
		metric.WithDescription("Total resource server admin operations"),
	); err != nil {
		return nil, err
	}
	if m.AllowlistOps, err = meter.Int64Counter("authplane_allowlist_ops_total",
		metric.WithDescription("Total cross-client allowlist admin operations"),
	); err != nil {
		return nil, err
	}

	// Gauges
	if m.ActiveClients, err = meter.Int64UpDownCounter("authserver_active_clients",
		metric.WithDescription("Current active client count"),
	); err != nil {
		return nil, err
	}
	if m.ActiveTokenFamilies, err = meter.Int64UpDownCounter("authserver_active_token_families",
		metric.WithDescription("Current active token family count"),
	); err != nil {
		return nil, err
	}

	// HTTP
	if m.HTTPRequestDuration, err = meter.Float64Histogram("authserver_http_request_duration_seconds",
		metric.WithDescription("HTTP request duration"),
		metric.WithUnit("s"),
		latencyBuckets,
	); err != nil {
		return nil, err
	}
	if m.HTTPRequestsTotal, err = meter.Int64Counter("authserver_http_requests_total",
		metric.WithDescription("Total HTTP requests"),
	); err != nil {
		return nil, err
	}

	return m, nil
}

// mustNewMetrics creates Metrics, falling back to noop meter on error.
func mustNewMetrics(meter metric.Meter) *Metrics {
	m, err := newMetrics(meter)
	if err != nil {
		noopMeter := metricnoop.NewMeterProvider().Meter("fallback")
		m, _ = newMetrics(noopMeter)
	}
	return m
}

// metricsSetupResult holds the results of metrics setup.
type metricsSetupResult struct {
	meter       metric.Meter
	shutdown    func(context.Context) error
	promHandler http.Handler
}

// setupMetrics configures the meter provider based on config.
func setupMetricsProvider(ctx context.Context, cfg config.MetricsConfig) (*metricsSetupResult, error) {
	result := &metricsSetupResult{
		shutdown: func(context.Context) error { return nil },
	}

	// Build OTel resource with service.name so all metric series carry the
	// correct job label (matching tracing and logging pipelines).
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	switch cfg.Provider {
	case "prometheus":
		exporter, err := promexporter.New()
		if err != nil {
			return nil, err
		}
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(exporter),
			sdkmetric.WithResource(res),
		)
		result.meter = mp.Meter(serviceName)
		result.shutdown = func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return mp.Shutdown(ctx)
		}
		result.promHandler = promhttp.Handler()

	case "otel":
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(cfg.OTelEndpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), otlpmetricgrpc.WithInsecure())
		}
		exporter, err := otlpmetricgrpc.New(ctx, opts...)
		if err != nil {
			return nil, err
		}
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(10*time.Second))),
			sdkmetric.WithResource(res),
		)
		result.meter = mp.Meter(serviceName)
		result.shutdown = func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return mp.Shutdown(ctx)
		}

	case "both":
		// Prometheus pull reader
		promExp, err := promexporter.New()
		if err != nil {
			return nil, err
		}
		// OTLP push reader
		otlpOpts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(cfg.OTelEndpoint),
		}
		if cfg.Insecure {
			otlpOpts = append(otlpOpts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), otlpmetricgrpc.WithInsecure())
		}
		otlpExp, err := otlpmetricgrpc.New(ctx, otlpOpts...)
		if err != nil {
			return nil, err
		}
		// MeterProvider with both readers
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(promExp),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(otlpExp, sdkmetric.WithInterval(10*time.Second))),
			sdkmetric.WithResource(res),
		)
		result.meter = mp.Meter(serviceName)
		result.promHandler = promhttp.Handler()
		result.shutdown = func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return mp.Shutdown(ctx)
		}

	default: // "none"
		result.meter = metricnoop.NewMeterProvider().Meter(serviceName)
	}

	return result, nil
}
