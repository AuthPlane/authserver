package wellknown

import (
	"context"
	"net/http"

	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
)

// JWKSProvider builds JWKS documents for the discovery endpoint.
type JWKSProvider interface {
	BuildJWKSDocument(ctx context.Context) ([]byte, error)
}

// ResourceEntry describes a resource server with its scopes.
type ResourceEntry struct {
	URI    string
	Scopes []string
}

// ResourceListerFunc is a function that returns registered resource servers.
// This avoids a direct dependency on the services layer.
type ResourceListerFunc func() []ResourceEntry

// HealthChecker verifies backend connectivity.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// Deps holds the dependencies for wellknown handlers.
type Deps struct {
	JWKS                 JWKSProvider
	ServerCfg            config.ServerConfig
	ResourceServers      ResourceListerFunc
	Health               HealthChecker
	HasIntrospection     bool
	HasClientCredentials bool
	HasTokenExchange     bool
	HasDPoP              bool
	HasAgentIdentity     bool
	HasCIMD              bool
	HasJWTBearer         bool
}

// RegisterRoutes registers discovery and infrastructure routes on the mux.
func RegisterRoutes(mux *http.ServeMux, deps Deps, obs *observability.Provider) {
	if deps.JWKS != nil {
		wk := &handler{
			jwks:                 deps.JWKS,
			serverCfg:            deps.ServerCfg,
			resourceServers:      deps.ResourceServers,
			hasIntrospection:     deps.HasIntrospection,
			hasClientCredentials: deps.HasClientCredentials,
			hasTokenExchange:     deps.HasTokenExchange,
			hasDPoP:              deps.HasDPoP,
			hasAgentIdentity:     deps.HasAgentIdentity,
			hasCIMD:              deps.HasCIMD,
			hasJWTBearer:         deps.HasJWTBearer,
		}
		mux.HandleFunc("GET /.well-known/jwks.json", wk.handleJWKS)
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", wk.handleASMetadata)
		mux.HandleFunc("GET /.well-known/openid-configuration", wk.handleASMetadata)
	}

	hc := &healthHandler{health: deps.Health}
	mux.HandleFunc("GET /health", hc.handleHealth)
	mux.HandleFunc("GET /ready", hc.handleReady)
}
