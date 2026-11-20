package services

import (
	"go.opentelemetry.io/otel/metric"

	"github.com/authplane/authserver/internal/observability"
)

// SetDPoPMetricsForTest points a grant service's DPoP proof counters at
// validated and rejected, so the external DPoP grant scenarios can assert
// them per grant without importing the observability package.
func SetDPoPMetricsForTest(svc any, validated, rejected metric.Int64Counter) {
	m := &observability.Metrics{DPoPProofsValidated: validated, DPoPProofsRejected: rejected}
	switch s := svc.(type) {
	case *ClientCredentialsService:
		s.metrics = m
	case *JWTBearerService:
		s.metrics = m
	case *TokenExchangeService:
		s.metrics = m
	default:
		panic("SetDPoPMetricsForTest: unsupported service type")
	}
}
