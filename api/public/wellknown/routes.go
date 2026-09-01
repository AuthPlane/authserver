package wellknown

import (
	"context"
	"net/http"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// JWKSProvider builds JWKS documents for the discovery endpoint.
type JWKSProvider interface {
	BuildJWKSDocument(ctx context.Context) ([]byte, error)
}

// HealthChecker verifies backend connectivity.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// Deps holds the dependencies for wellknown handlers.
type Deps struct {
	JWKS JWKSProvider
	// ASMetadata assembles the AS discovery document (RFC 8414). When non-nil,
	// the oauth-authorization-server / openid-configuration routes are
	// registered; the capability resolution lives entirely behind this port.
	ASMetadata input.ASMetadataPort
	Health     HealthChecker
}

// RegisterRoutes registers discovery and infrastructure routes on the mux.
func RegisterRoutes(mux *http.ServeMux, deps Deps, obs *observability.Provider) {
	wk := &handler{
		jwks:       deps.JWKS,
		asMetadata: deps.ASMetadata,
		obs:        obs,
	}
	if deps.JWKS != nil {
		mux.HandleFunc("GET /.well-known/jwks.json", wk.handleJWKS)
	}
	if deps.ASMetadata != nil {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", wk.handleASMetadata)
		mux.HandleFunc("GET /.well-known/openid-configuration", wk.handleASMetadata)
	}

	hc := &healthHandler{health: deps.Health}
	mux.HandleFunc("GET /livez", hc.handleLive)
	mux.HandleFunc("GET /health", hc.handleHealth)
	mux.HandleFunc("GET /ready", hc.handleReady)
}
