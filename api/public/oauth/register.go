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

// registerHandler handles POST /oauth/register (RFC 7591).
type registerHandler struct {
	dcr DCRProvider
	obs *observability.Provider
}

// maxJSONBody is the maximum request body size for JSON endpoints (1 MB).
const maxJSONBody = 1 << 20

func (h *registerHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	var req input.RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	resp, err := h.dcr.RegisterClient(r.Context(), req)
	if err != nil {
		h.writeRegisterError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *registerHandler) writeRegisterError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrRegistrationDisabled):
		shared.WriteOAuthError(w, http.StatusForbidden, "access_denied", "registration is disabled")
	case errors.Is(err, domain.ErrClientSuspended):
		shared.WriteOAuthError(w, http.StatusForbidden, "access_denied", "client is suspended")
	case errors.Is(err, domain.ErrInvalidRedirectURI):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri not allowed")
	case errors.Is(err, domain.ErrInvalidClient):
		// forward the underlying validator message so operators
		// see *which* grant was rejected and *which* env var enables it.
		// The wrapped error from DCRService.RegisterClient is shaped as
		// "invalid_client: client validation failed: ..." — surface it.
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
	case domain.IsError(err):
		shared.WriteOAuthError(w, http.StatusBadRequest, domain.ErrorCode(err), "request validation failed")
	default:
		h.obs.Logger.ErrorContext(r.Context(), "dcr internal error", "error", err)
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}
