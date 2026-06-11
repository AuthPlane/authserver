package oauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// introspectHandler handles POST /oauth/introspect.
type introspectHandler struct {
	introspect IntrospectionProvider
	obs        *observability.Provider
}

func (h *introspectHandler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
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
