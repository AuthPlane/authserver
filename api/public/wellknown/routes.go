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
	// PRMetadata assembles Protected Resource Metadata (RFC 9728) for the
	// Resources registered with this AS. When non-nil, both the bare and the
	// path-suffixed oauth-protected-resource routes are registered.
	PRMetadata input.PRMetadataPort
	Health     HealthChecker
}

// RegisterRoutes registers discovery and infrastructure routes on the mux.
func RegisterRoutes(mux *http.ServeMux, deps Deps, obs *observability.Provider) {
	wk := &handler{
		jwks:       deps.JWKS,
		asMetadata: deps.ASMetadata,
		prMetadata: deps.PRMetadata,
		obs:        obs,
	}
	if deps.JWKS != nil {
		mux.HandleFunc("GET /.well-known/jwks.json", wk.handleJWKS)
	}
	if deps.ASMetadata != nil {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", wk.handleASMetadata)
		mux.HandleFunc("GET /.well-known/openid-configuration", wk.handleASMetadata)
	}
	if deps.PRMetadata != nil {
		// Two shapes, both required.
		//
		// The bare path answers for a Resource whose identifier is this origin.
		// The wildcard serves RFC 9728 §3.1's path-insertion form — a client
		// holding https://host/mcp constructs
		// https://host/.well-known/oauth-protected-resource/mcp — and doubles as
		// the AS-hosted form addressed by slug, which is the only form reachable
		// for a Resource living on a different host.
		//
		// {ref...} rather than {ref}: resource identifiers carry multi-segment
		// paths (https://host/server/mcp), and a single-segment pattern would
		// 404 exactly the deployments the RFC calls out.
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", wk.handlePRMetadata)
		mux.HandleFunc("GET /.well-known/oauth-protected-resource/{ref...}", wk.handlePRMetadata)
	}

	hc := &healthHandler{health: deps.Health}
	mux.HandleFunc("GET /livez", hc.handleLive)
	mux.HandleFunc("GET /health", hc.handleHealth)
	mux.HandleFunc("GET /ready", hc.handleReady)
}
