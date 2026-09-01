// Package wellknown provides discovery and infrastructure endpoints:
// JWKS, AS metadata, Protected Resource Metadata, health, and metrics.
package wellknown

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// handler holds dependencies for discovery endpoints.
type handler struct {
	jwks       JWKSProvider
	asMetadata input.ASMetadataPort
	obs        *observability.Provider
}

// handleJWKS serves GET /.well-known/jwks.json (RFC 7517).
func (h *handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := h.jwks.BuildJWKSDocument(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(),
			"build JWKS document failed",
			"error", err,
		)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}

// handleASMetadata serves GET /.well-known/oauth-authorization-server (RFC 8414)
// and its alias GET /.well-known/openid-configuration. It is a thin transport
// adapter: the ASMetadataPort resolves and assembles every capability per
// request; this handler only maps the application struct onto the RFC 8414 wire
// DTO and encodes it.
func (h *handler) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	md, err := h.asMetadata.Metadata(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(),
			"build AS metadata document failed",
			"error", err,
		)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	doc := asMetadata{
		Issuer:                            md.Issuer,
		AuthorizationEndpoint:             md.AuthorizationEndpoint,
		TokenEndpoint:                     md.TokenEndpoint,
		RegistrationEndpoint:              md.RegistrationEndpoint,
		RevocationEndpoint:                md.RevocationEndpoint,
		IntrospectionEndpoint:             md.IntrospectionEndpoint,
		JWKSURI:                           md.JWKSURI,
		ResponseTypesSupported:            md.ResponseTypesSupported,
		GrantTypesSupported:               md.GrantTypesSupported,
		TokenEndpointAuthMethodsSupported: md.TokenEndpointAuthMethodsSupported,
		IntrospectionEndpointAuthMethods:  md.IntrospectionEndpointAuthMethods,
		RevocationEndpointAuthMethods:     md.RevocationEndpointAuthMethods,
		CodeChallengeMethodsSupported:     md.CodeChallengeMethodsSupported,
		ScopesSupported:                   md.ScopesSupported,
		ResourceIndicatorsSupported:       md.ResourceIndicatorsSupported,
		ClientIDMetadataDocumentSupported: md.ClientIDMetadataDocumentSupported,
		DPoPSigningAlgValuesSupported:     md.DPoPSigningAlgValuesSupported,
		AgentIdentitySupported:            md.AgentIdentitySupported,
		IdentityAssertionSupported:        md.IdentityAssertionSupported,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(doc)
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

// handleLive answers one question: is this process serving HTTP?
//
// It checks nothing else, and that is the point. A liveness probe decides
// whether to KILL the process, so making it depend on an external service turns
// that service's outage into a restart — which cannot fix the dependency, and
// here cannot even succeed: serve.go runs database migrations at startup, so a
// container restarted while the database is down exits again and degrades into
// CrashLoopBackOff, whose exponential backoff outlives the outage that caused
// it. Readiness has already removed the pod from the Service by then, so the
// restart buys no recovery at all.
//
// /health and /ready both ping the database on purpose — they answer different
// questions, for operators and for the Service router respectively. This one is
// for the kubelet's restart decision and must stay dependency-free. Adding a
// check here would reintroduce the failure mode it exists to prevent.
func (h *healthHandler) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(healthResponse{
		Status: "alive",
		Time:   time.Now().UTC().Format(time.RFC3339),
	})
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
