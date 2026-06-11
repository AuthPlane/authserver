package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

const (
	maxFrontingBody       = 1 << 20 // 1 MB
	defaultFrontingLimit  = 100
	maxFrontingLimit      = 500
	frontingListMaxOffset = 1 << 30
)

// frontingAdminHandler serves /admin/fronting. Mirrors
// resourceAdminHandler in shape: the API layer never imports
// internal/services and validates only what the input port can't already
// (request shape + pagination bounds). Domain validation lives in
// FrontingService.
type frontingAdminHandler struct {
	svc input.FrontingAdminPort
	obs *observability.Provider
}

// handleList serves GET /admin/fronting and the source/target query
// short-circuits. Both `source` and `target` may be present; when both are
// supplied the result is at most one row (effectively a Get).
func (h *frontingAdminHandler) handleList(w http.ResponseWriter, r *http.Request) {
	filter, ok := h.parseListFilter(w, r)
	if !ok {
		return
	}

	rows, err := h.svc.List(r.Context(), filter)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list fronting links failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, frontingLinksToViews(rows))
}

// handleGet serves GET /admin/fronting/{source}/{target} — single-row
// lookup keyed on the composite primary key.
func (h *frontingAdminHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	source, ok := validPathParam(w, "source", r.PathValue("source"))
	if !ok {
		return
	}
	target, ok := validPathParam(w, "target", r.PathValue("target"))
	if !ok {
		return
	}

	link, err := h.svc.Get(r.Context(), source, target)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get fronting link failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, frontingLinkToView(link))
}

// handleCreate serves POST /admin/fronting. With `?dry_run=true` it
// validates without persisting and returns the would-be 201 body shape on
// success — Admin UI uses this to surface validation errors before commit.
func (h *frontingAdminHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFrontingBody)
	var req createFrontingLinkRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	link := &resource.FrontingLink{
		SourceSlug: req.Source,
		TargetSlug: req.Target,
		ScopeMap:   resource.ScopeMap(req.ScopeMap),
	}

	dryRun := r.URL.Query().Get("dry_run") == "true"
	if dryRun {
		if err := h.svc.Validate(r.Context(), link); err != nil {
			writeDomainOrInternalError(w, r, h.obs, "validate fronting link failed", err)
			return
		}
		// Validate-only path returns 200 with the would-be view shape so
		// callers can confirm wire-shape compatibility without parsing
		// status codes.
		shared.WriteJSON(w, http.StatusOK, frontingLinkToView(link))
		return
	}

	actorID := actorIDFromRequest(r)
	if err := h.svc.Create(r.Context(), link, actorID); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create fronting link failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusCreated, frontingLinkToView(link))
}

// handlePatch serves PATCH /admin/fronting/{source}/{target}. Only
// scope_map is patchable; nil = unchanged.
func (h *frontingAdminHandler) handlePatch(w http.ResponseWriter, r *http.Request) {
	source, ok := validPathParam(w, "source", r.PathValue("source"))
	if !ok {
		return
	}
	target, ok := validPathParam(w, "target", r.PathValue("target"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFrontingBody)
	var req patchFrontingLinkRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	patch := input.FrontingLinkPatch{}
	if req.ScopeMap != nil {
		sm := resource.ScopeMap(*req.ScopeMap)
		patch.ScopeMap = &sm
	}

	actorID := actorIDFromRequest(r)
	updated, err := h.svc.Patch(r.Context(), source, target, patch, actorID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "patch fronting link failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, frontingLinkToView(updated))
}

// handleDelete serves DELETE /admin/fronting/{source}/{target}.
func (h *frontingAdminHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	source, ok := validPathParam(w, "source", r.PathValue("source"))
	if !ok {
		return
	}
	target, ok := validPathParam(w, "target", r.PathValue("target"))
	if !ok {
		return
	}

	actorID := actorIDFromRequest(r)
	if err := h.svc.Delete(r.Context(), source, target, actorID); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "delete fronting link failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListForResource serves GET /admin/resources/{slug}/fronting — the
// per-Resource convenience that returns both directions in one shot.
func (h *frontingAdminHandler) handleListForResource(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}
	rows, err := h.svc.ListForResource(r.Context(), slug)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list fronting links for resource failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, resourceFrontingFromLinks(slug, rows))
}

func (h *frontingAdminHandler) parseListFilter(w http.ResponseWriter, r *http.Request) (input.FrontingLinkFilter, bool) {
	filter := input.FrontingLinkFilter{Limit: defaultFrontingLimit}
	q := r.URL.Query()
	filter.Source = q.Get("source")
	filter.Target = q.Get("target")
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxFrontingLimit {
			writeAdminError(w, http.StatusBadRequest, "limit must be 1..500")
			return filter, false
		}
		filter.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > frontingListMaxOffset {
			writeAdminError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return filter, false
		}
		filter.Offset = n
	}
	return filter, true
}

// actorIDFromRequest extracts the admin actor's identifier for audit
// recording. The current admin auth middleware authenticates by API key
// without binding to a user identity, so we record "admin" as the actor
// — same convention ResourceAdminService uses. When admin auth grows a
// per-actor identity (likely a follow-up to docs catch-up), this
// helper becomes the single seam to update.
func actorIDFromRequest(_ *http.Request) string {
	return "admin"
}
