package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
)

// DCRAdmin is the local interface for reading/setting DCR mode at runtime.
type DCRAdmin interface {
	GetMode() string
	SetMode(mode string)
}

// SettingsStore is the local interface for persisting runtime settings.
type SettingsStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// DCRDeps holds DCR settings management dependencies for the admin server.
type DCRDeps struct {
	DCR      DCRAdmin
	Settings SettingsStore
	Audit    AuditRecorder
}

// dcrSettingsHandler serves admin DCR settings endpoints.
type dcrSettingsHandler struct {
	dcr      DCRAdmin
	settings SettingsStore
	audit    AuditRecorder
	obs      *observability.Provider
}

// settingsKey is the runtime_settings key used to persist DCR mode.
const dcrModeSettingsKey = "dcr_mode"

// validDCRModes lists accepted DCR mode values.
var validDCRModes = map[string]bool{
	"open":               true,
	"admin_only":         true,
	"approved_redirects": true,
}

func (h *dcrSettingsHandler) handleGetDCRSettings(w http.ResponseWriter, r *http.Request) {
	_, span := h.obs.Tracer.Start(r.Context(), "dcrSettingsHandler.handleGetDCRSettings")
	defer span.End()

	mode := h.dcr.GetMode()
	shared.WriteJSON(w, http.StatusOK, dcrSettingsView{Mode: mode})
}

func (h *dcrSettingsHandler) handleUpdateDCRSettings(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.obs.Tracer.Start(r.Context(), "dcrSettingsHandler.handleUpdateDCRSettings")
	defer span.End()

	var req updateDCRSettingsRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Mode == "" {
		writeAdminError(w, http.StatusBadRequest, "mode is required")
		return
	}

	if !validDCRModes[req.Mode] {
		writeAdminError(w, http.StatusBadRequest, "invalid mode: must be open, admin_only, or approved_redirects")
		return
	}

	previousMode := h.dcr.GetMode()

	// Persist to database.
	if err := h.settings.Set(ctx, dcrModeSettingsKey, req.Mode); err != nil {
		h.obs.Logger.ErrorContext(ctx, "failed to persist DCR mode", "error", err)
		writeAdminError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Apply at runtime.
	h.dcr.SetMode(req.Mode)

	h.obs.Logger.InfoContext(ctx, "admin updated DCR mode",
		"previous_mode", previousMode,
		"new_mode", req.Mode,
	)

	if h.audit != nil {
		h.audit.Record(ctx, audit.Event{
			Action:    audit.ActionDCRModeUpdated,
			ActorID:   "admin",
			Detail:    "dcr mode changed from " + previousMode + " to " + req.Mode,
			CreatedAt: time.Now().UTC(),
		})
	}

	shared.WriteJSON(w, http.StatusOK, dcrSettingsView(req))
}
