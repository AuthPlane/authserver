package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// xaaPolicyHandler handles admin API requests for XAA policy management.
type xaaPolicyHandler struct {
	policy input.XAAPolicyPort
	obs    *observability.Provider
}

type createPolicyRequest struct {
	Name      string   `json:"name"`
	IDPID     string   `json:"idp_id"`
	ClientIDs []string `json:"client_ids,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Resources []string `json:"resources,omitempty"`
}

type updatePolicyRequest struct {
	Name      *string  `json:"name,omitempty"`
	ClientIDs []string `json:"client_ids,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"`
}

type policyResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	IDPID     string   `json:"idp_id"`
	ClientIDs []string `json:"client_ids"`
	Scopes    []string `json:"scopes"`
	Resources []string `json:"resources"`
	Enabled   bool     `json:"enabled"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

func (h *xaaPolicyHandler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Name == "" || req.IDPID == "" {
		writeAdminError(w, http.StatusBadRequest, "name and idp_id are required")
		return
	}

	entity, err := h.policy.CreatePolicy(r.Context(), input.CreatePolicyRequest{
		Name:      req.Name,
		IDPID:     req.IDPID,
		ClientIDs: req.ClientIDs,
		Scopes:    req.Scopes,
		Resources: req.Resources,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create policy failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusCreated, toPolicyResponse(entity))
}

func (h *xaaPolicyHandler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	idpID := r.URL.Query().Get("idp_id")

	policies, err := h.policy.ListPolicies(r.Context(), idpID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list policies failed", err)
		return
	}

	views := make([]policyResponse, len(policies))
	for i := range policies {
		views[i] = toPolicyResponseVal(&policies[i])
	}

	shared.WriteJSON(w, http.StatusOK, views)
}

func (h *xaaPolicyHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	entity, err := h.policy.GetPolicy(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get policy failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, toPolicyResponse(entity))
}

func (h *xaaPolicyHandler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req updatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	entity, err := h.policy.UpdatePolicy(r.Context(), id, input.UpdatePolicyRequest{
		Name:      req.Name,
		ClientIDs: req.ClientIDs,
		Scopes:    req.Scopes,
		Resources: req.Resources,
		Enabled:   req.Enabled,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "update policy failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, toPolicyResponse(entity))
}

func (h *xaaPolicyHandler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.policy.DeletePolicy(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "delete policy failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func toPolicyResponse(p *xaa.Policy) policyResponse {
	return policyResponse{
		ID:        p.ID,
		Name:      p.Name,
		IDPID:     p.IDPID,
		ClientIDs: emptyIfNil(p.ClientIDs),
		Scopes:    emptyIfNil(p.Scopes),
		Resources: emptyIfNil(p.Resources),
		Enabled:   p.Enabled,
		CreatedAt: p.CreatedAt.Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.Format(time.RFC3339),
	}
}

func toPolicyResponseVal(p *xaa.Policy) policyResponse {
	return toPolicyResponse(p)
}

// emptyIfNil returns an empty slice instead of nil for JSON serialization.
func emptyIfNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
