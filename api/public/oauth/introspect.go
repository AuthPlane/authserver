package oauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// introspectHandler handles POST /oauth/introspect.
type introspectHandler struct {
	introspect IntrospectionProvider
	// oauthConfig gates the endpoint per request from the same source that
	// drives the discovery document's introspection_endpoint. When it resolves
	// IntrospectionEnabled=false (or errors), an introspection request responds
	// 404, as if the endpoint were absent. (The route stays registered as
	// POST-only, so a non-POST probe still gets 405 rather than 404 — the gate
	// covers the POST path that real introspection uses.) When nil, the endpoint
	// is always served (the pre-seam behavior).
	oauthConfig output.OAuthConfigProvider
	obs         *observability.Provider
}

func (h *introspectHandler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	// Runtime gate: introspection-disabled returns 404 for the request, as if the
	// endpoint were absent.
	if h.oauthConfig != nil {
		cfg, err := h.oauthConfig.Config(r.Context())
		if err != nil {
			h.obs.Logger.WarnContext(r.Context(),
				"resolve OAuth config failed; treating introspection as disabled",
				"error", err,
			)
			http.NotFound(w, r)
			return
		}
		if !cfg.IntrospectionEnabled {
			http.NotFound(w, r)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	if err := r.ParseForm(); err != nil {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "token parameter is required")
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)

	req := input.IntrospectRequest{
		Token:         token,
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}

	resp, err := h.introspect.IntrospectToken(r.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="authserver"`)
			shared.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
		h.obs.Logger.ErrorContext(r.Context(), "introspection error", "error", err)
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
