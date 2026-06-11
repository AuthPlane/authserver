// Package connectionapi serves the user-facing /connect/{provider} and
// /connections routes that orchestrate the upstream-Broker connect dance.
package connectionapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
)

// handler serves the public connection endpoints.
type handler struct {
	connect ConnectProvider
	session *shared.SessionMiddleware
	obs     *observability.Provider
}

// --- Connect / Callback ---

func (h *handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "provider path parameter required")
		return
	}

	userID, ok := shared.UserIDFromContext(r.Context())
	if !ok || userID == "" {
		http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	q := r.URL.Query()
	returnURL := q.Get("return_url")
	if returnURL == "" {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "return_url query parameter required")
		return
	}
	resourceSlug := q.Get("resource")

	redirectURL, err := h.connect.StartConnect(r.Context(), userID, provider, resourceSlug, returnURL)
	if err != nil {
		h.handleConnectError(w, r, err)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "provider path parameter required")
		return
	}

	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")

	if code == "" || state == "" {
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Bad Request", "Missing code or state parameter.")
		return
	}

	userID, ok := shared.UserIDFromContext(r.Context())
	if !ok || userID == "" {
		shared.WriteErrorPage(w, r, http.StatusForbidden, "Forbidden", "No active session. Please log in and try again.")
		return
	}

	result, err := h.connect.CompleteConnect(r.Context(), userID, state, code)
	if err != nil {
		h.handleCallbackError(w, r, err)
		return
	}

	http.Redirect(w, r, result.ReturnURL, http.StatusFound)
}

// --- List / Delete connections ---

func (h *handler) handleListConnections(w http.ResponseWriter, r *http.Request) {
	userID, ok := shared.UserIDFromContext(r.Context())
	if !ok || userID == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		shared.WriteOAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	metas, err := h.connect.ListConnections(r.Context(), userID)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "list connections failed", "error", err)
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to list connections")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metas)
}

func (h *handler) handleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "provider path parameter required")
		return
	}

	userID, ok := shared.UserIDFromContext(r.Context())
	if !ok || userID == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		shared.WriteOAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	err := h.connect.Disconnect(r.Context(), userID, provider)
	if err != nil {
		if errors.Is(err, domain.ErrConnectionNotFound) {
			shared.WriteOAuthError(w, http.StatusNotFound, "not_found", "connection not found")
			return
		}
		h.obs.Logger.ErrorContext(r.Context(), "disconnect failed", "error", err)
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to disconnect")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Error helpers ---

func (h *handler) handleConnectError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrServiceNotFound), errors.Is(err, domain.ErrResourceNotFound):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown provider or resource")
	case errors.Is(err, domain.ErrInvalidReturnURL):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "return URL not in allowed list")
	case errors.Is(err, domain.ErrAmbiguousBrokerResource):
		// the provider has multiple Broker-backed resources and
		// the caller didn't pin one. Fail-loud so the policy choice
		// (return-URL allowlist + scope catalog) is never silently
		// guessed.
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, domain.ErrInvalidTarget):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
	default:
		h.obs.Logger.ErrorContext(r.Context(), "start connect failed", "error", err)
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to start connect flow")
	}
}

func (h *handler) handleCallbackError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrStateNotFound), errors.Is(err, domain.ErrPendingStateNotFound):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid State", "The connect request has expired or was already used. Please try again.")
	case errors.Is(err, domain.ErrInvalidState):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid State", "The state parameter is invalid or tampered with.")
	case errors.Is(err, domain.ErrStateForeignUser):
		shared.WriteErrorPage(w, r, http.StatusForbidden, "Forbidden", "This connect request belongs to a different user.")
	default:
		h.obs.Logger.ErrorContext(r.Context(), "complete connect failed", "error", err)
		shared.WriteErrorPage(w, r, http.StatusInternalServerError, "Error", "Failed to complete the connection. Please try again.")
	}
}
