package admin

import (
	"encoding/json"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

const maxBrokerProviderBody = 1 << 20 // 1 MB

// brokerProviderAdminHandler serves /admin/broker-providers.
// Pattern mirrors resourceAdminHandler.
type brokerProviderAdminHandler struct {
	svc input.BrokerProviderAdminPort
	obs *observability.Provider
}

// handleList serves both the full list (no `slug` query param) and the
// slug-lookup short-circuit (with `slug=...`). The short-circuit returns
// a single BrokerProviderView (or 404), matching the shape of
// GET /admin/broker-providers/{id}.
func (h *brokerProviderAdminHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if slug := r.URL.Query().Get("slug"); slug != "" {
		row, err := h.svc.GetBySlug(r.Context(), slug)
		if err != nil {
			writeDomainOrInternalError(w, r, h.obs, "lookup broker provider by slug failed", err)
			return
		}
		shared.WriteJSON(w, http.StatusOK, brokerProviderToView(row))
		return
	}

	rows, err := h.svc.List(r.Context())
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list broker providers failed", err)
		return
	}
	views := make([]brokerProviderView, len(rows))
	for i, row := range rows {
		views[i] = brokerProviderToView(row)
	}
	shared.WriteJSON(w, http.StatusOK, views)
}

func (h *brokerProviderAdminHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}
	row, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get broker provider failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, brokerProviderToView(row))
}

func (h *brokerProviderAdminHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBrokerProviderBody)
	var req createBrokerProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	p := &resource.BrokerProvider{
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		Protocol:    resource.Protocol(req.Protocol),
		ConfigData:  []byte(req.ConfigData),
	}
	if err := h.svc.Create(r.Context(), p); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create broker provider failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusCreated, brokerProviderToView(p))
}

func (h *brokerProviderAdminHandler) handlePatch(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBrokerProviderBody)
	var req patchBrokerProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	patch := input.BrokerProviderPatch{
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		ConfigData:  req.ConfigData,
	}
	if req.Protocol != nil {
		proto := resource.Protocol(*req.Protocol)
		patch.Protocol = &proto
	}

	updated, err := h.svc.Patch(r.Context(), id, patch)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "patch broker provider failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, brokerProviderToView(updated))
}

func (h *brokerProviderAdminHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "delete broker provider failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
