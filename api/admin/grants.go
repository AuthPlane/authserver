package admin

import (
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// grantAdminHandler serves the /admin/users/{id}/grants list and the
// /admin/grants/{consent|broker}/{id} revoke paths.
//
// Wire shape: ListForUser returns a single envelope with both consent
// and broker shapes so a single round trip serves the operator UX
// "what has user X authorized". Revocation is split into two paths
// because the cascade semantics differ; see the input.GrantAdminPort
// interface for the details.
type grantAdminHandler struct {
	svc input.GrantAdminPort
	obs *observability.Provider
}

// handleListUserGrants serves GET /admin/users/{id}/grants.
func (h *grantAdminHandler) handleListUserGrants(w http.ResponseWriter, r *http.Request) {
	userID, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	got, err := h.svc.ListForUser(r.Context(), userID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list user grants failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, userGrantsToView(got))
}

// handleRevokeConsentGrant serves DELETE /admin/grants/consent/{id}.
//
// The 204 response intentionally carries no body — soft-delete is the
// load-bearing semantic and the cascade outcome is in the audit trail.
// If the operator wants to verify the cascade ran, they re-query
// /admin/users/{id}/grants and /admin/issuances?user=… for the
// post-revocation state.
func (h *grantAdminHandler) handleRevokeConsentGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.svc.RevokeConsent(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "revoke consent grant failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeBrokerGrant serves DELETE /admin/grants/broker/{id}.
//
// No issuance cascade — already-vended upstream tokens are not
// AS-revocable. Audit captures the revocation; introspection is N/A
// because Broker tokens are opaque to the AS.
func (h *grantAdminHandler) handleRevokeBrokerGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.svc.RevokeBroker(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "revoke broker grant failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
