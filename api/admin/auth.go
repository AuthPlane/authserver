package admin

import (
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
)

// authHandler handles authentication verification for the admin UI.
type authHandler struct {
	version string
	audit   AuditRecorder
	obs     *observability.Provider
}

// handleAuthVerify confirms that the API key is valid.
// If the request reaches this handler, the auth middleware has already
// validated the key — we just confirm and return version info.
func (h *authHandler) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if h.audit != nil {
		h.audit.Record(r.Context(), audit.NewEvent(
			"admin.ui.login",
			"admin", "", "",
			"api_key_verified",
		))
	}

	h.obs.Logger.InfoContext(r.Context(), "admin UI login verified")

	shared.WriteJSON(w, http.StatusOK, authVerifyResponse{
		Valid:   true,
		Version: h.version,
	})
}
