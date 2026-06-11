// Package wellknown provides discovery and infrastructure endpoints:
// JWKS, AS metadata, Protected Resource Metadata, health, and metrics.
package wellknown

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/authplane/authserver/internal/config"
)

// handler holds dependencies for discovery endpoints.
type handler struct {
	jwks                 JWKSProvider
	serverCfg            config.ServerConfig
	resourceServers      ResourceListerFunc
	hasIntrospection     bool
	hasClientCredentials bool
	hasTokenExchange     bool
	hasDPoP              bool
	hasAgentIdentity     bool
	hasCIMD              bool
	hasJWTBearer         bool
}

// handleJWKS serves GET /.well-known/jwks.json (RFC 7517).
func (h *handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := h.jwks.BuildJWKSDocument(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}

// handleASMetadata serves GET /.well-known/oauth-authorization-server (RFC 8414).
func (h *handler) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := h.serverCfg.Issuer

	grantTypes := []string{"authorization_code", "refresh_token"}
	if h.hasClientCredentials {
		grantTypes = append(grantTypes, "client_credentials")
	}
	if h.hasTokenExchange {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	if h.hasJWTBearer {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	}

	metadata := asMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth/authorize",
		TokenEndpoint:                     issuer + "/oauth/token",
		RegistrationEndpoint:              issuer + "/oauth/register",
		RevocationEndpoint:                issuer + "/oauth/revoke",
		JWKSURI:                           issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               grantTypes,
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
		RevocationEndpointAuthMethods:     []string{"none", "client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   h.collectScopes(),
		ResourceIndicatorsSupported:       true,
		ClientIDMetadataDocumentSupported: h.hasCIMD,
	}

	if h.hasIntrospection {
		metadata.IntrospectionEndpoint = issuer + "/oauth/introspect"
		metadata.IntrospectionEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post"}
	}

	if h.hasDPoP {
		metadata.DPoPSigningAlgValuesSupported = []string{"ES256", "RS256", "PS256"}
	}

	if h.hasAgentIdentity {
		metadata.AgentIdentitySupported = true
	}

	if h.hasJWTBearer {
		metadata.IdentityAssertionSupported = true
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(metadata)
}

func (h *handler) collectScopes() []string {
	if h.resourceServers == nil {
		return nil
	}
	seen := make(map[string]bool)
	var scopes []string
	for _, rs := range h.resourceServers() {
		for _, s := range rs.Scopes {
			if !seen[s] {
				seen[s] = true
				scopes = append(scopes, s)
			}
		}
	}
	return scopes
}

// --- Health handler ---

type healthHandler struct {
	health HealthChecker
}

func (h *healthHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}
	status := http.StatusOK

	if h.health != nil {
		pingCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := h.health.Ping(pingCtx); err != nil {
			resp.Status = "degraded"
			resp.DB = "error"
			status = http.StatusServiceUnavailable
		} else {
			resp.DB = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *healthHandler) handleReady(w http.ResponseWriter, r *http.Request) {
	if h.health != nil {
		pingCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := h.health.Ping(pingCtx); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(healthResponse{
				Status: "not_ready",
				Time:   time.Now().UTC().Format(time.RFC3339),
				DB:     "error",
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(healthResponse{
		Status: "ready",
		Time:   time.Now().UTC().Format(time.RFC3339),
		DB:     "ok",
	})
}
