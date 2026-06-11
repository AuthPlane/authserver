package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// XAADeps holds optional XAA dependencies for the admin server.
type XAADeps struct {
	IDP            input.XAAIDPPort
	Policy         input.XAAPolicyPort
	SubjectMapping input.SubjectMappingPort
}

// xaaIDPHandler handles admin API requests for trusted IdP management.
type xaaIDPHandler struct {
	idp input.XAAIDPPort
	obs *observability.Provider
}

type registerIDPRequest struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	JWKSUri  string `json:"jwks_uri,omitempty"`
	Audience string `json:"audience,omitempty"`
}

type idpResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Issuer    string `json:"issuer"`
	JWKSUri   string `json:"jwks_uri"`
	Audience  string `json:"audience"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type updateIDPRequestBody struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

func (h *xaaIDPHandler) handleRegisterIDP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req registerIDPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Name == "" || req.Issuer == "" {
		writeAdminError(w, http.StatusBadRequest, "name and issuer are required")
		return
	}

	entity, err := h.idp.RegisterIDP(r.Context(), input.RegisterIDPRequest{
		Name:     req.Name,
		Issuer:   req.Issuer,
		JWKSUri:  req.JWKSUri,
		Audience: req.Audience,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "register idp failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusCreated, idpResponse{
		ID:        entity.ID,
		Name:      entity.Name,
		Issuer:    entity.Issuer,
		JWKSUri:   entity.JWKSUri,
		Audience:  entity.Audience,
		Enabled:   entity.Enabled,
		CreatedAt: entity.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entity.UpdatedAt.Format(time.RFC3339),
	})
}

func (h *xaaIDPHandler) handleListIDPs(w http.ResponseWriter, r *http.Request) {
	idps, err := h.idp.ListIDPs(r.Context())
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list idps failed", err)
		return
	}

	views := make([]idpResponse, len(idps))
	for i := range idps {
		views[i] = idpResponse{
			ID:        idps[i].ID,
			Name:      idps[i].Name,
			Issuer:    idps[i].Issuer,
			JWKSUri:   idps[i].JWKSUri,
			Audience:  idps[i].Audience,
			Enabled:   idps[i].Enabled,
			CreatedAt: idps[i].CreatedAt.Format(time.RFC3339),
			UpdatedAt: idps[i].UpdatedAt.Format(time.RFC3339),
		}
	}

	shared.WriteJSON(w, http.StatusOK, views)
}

func (h *xaaIDPHandler) handleGetIDP(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	entity, err := h.idp.GetIDP(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get idp failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, idpResponse{
		ID:        entity.ID,
		Name:      entity.Name,
		Issuer:    entity.Issuer,
		JWKSUri:   entity.JWKSUri,
		Audience:  entity.Audience,
		Enabled:   entity.Enabled,
		CreatedAt: entity.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entity.UpdatedAt.Format(time.RFC3339),
	})
}

func (h *xaaIDPHandler) handleUpdateIDP(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req updateIDPRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	entity, err := h.idp.UpdateIDP(r.Context(), id, input.UpdateIDPRequest{
		Name:    req.Name,
		Enabled: req.Enabled,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "update idp failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, idpResponse{
		ID:        entity.ID,
		Name:      entity.Name,
		Issuer:    entity.Issuer,
		JWKSUri:   entity.JWKSUri,
		Audience:  entity.Audience,
		Enabled:   entity.Enabled,
		CreatedAt: entity.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entity.UpdatedAt.Format(time.RFC3339),
	})
}

func (h *xaaIDPHandler) handleDeleteIDP(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.idp.DeleteIDP(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "delete idp failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *xaaIDPHandler) handleRefreshKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.idp.RefreshKeys(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "refresh idp keys failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, map[string]string{"status": "refreshed"})
}
