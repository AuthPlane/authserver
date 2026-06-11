package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// subjectMappingHandler handles admin API requests for XAA subject mapping management.
type subjectMappingHandler struct {
	mapping input.SubjectMappingPort
	obs     *observability.Provider
}

type createMappingRequest struct {
	IDPID       string `json:"idp_id"`
	IDPSubject  string `json:"idp_subject"`
	LocalUserID string `json:"local_user_id,omitempty"`
}

type mappingResponse struct {
	ID          string `json:"id"`
	IDPID       string `json:"idp_id"`
	IDPSubject  string `json:"idp_subject"`
	LocalUserID string `json:"local_user_id,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func (h *subjectMappingHandler) handleCreateMapping(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req createMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.IDPID == "" || req.IDPSubject == "" {
		writeAdminError(w, http.StatusBadRequest, "idp_id and idp_subject are required")
		return
	}

	entity, err := h.mapping.CreateMapping(r.Context(), input.CreateMappingRequest{
		IDPID:       req.IDPID,
		IDPSubject:  req.IDPSubject,
		LocalUserID: req.LocalUserID,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create mapping failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusCreated, mappingResponse{
		ID:          entity.ID,
		IDPID:       entity.IDPID,
		IDPSubject:  entity.IDPSubject,
		LocalUserID: entity.LocalUserID,
		CreatedAt:   entity.CreatedAt.Format(time.RFC3339),
	})
}

func (h *subjectMappingHandler) handleListMappings(w http.ResponseWriter, r *http.Request) {
	idpID := r.URL.Query().Get("idp_id")

	mappings, err := h.mapping.ListMappings(r.Context(), idpID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list mappings failed", err)
		return
	}

	views := make([]mappingResponse, len(mappings))
	for i, m := range mappings {
		views[i] = mappingResponse{
			ID:          m.ID,
			IDPID:       m.IDPID,
			IDPSubject:  m.IDPSubject,
			LocalUserID: m.LocalUserID,
			CreatedAt:   m.CreatedAt.Format(time.RFC3339),
		}
	}

	shared.WriteJSON(w, http.StatusOK, views)
}

func (h *subjectMappingHandler) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.mapping.DeleteMapping(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "delete mapping failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
