package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

const (
	maxResourceBody       = 1 << 20 // 1 MB
	defaultResourceLimit  = 100
	maxResourceLimit      = 500
	resourceListMaxOffset = 1 << 30
)

// resourceAdminHandler serves /admin/resources. The API layer
// never imports internal/services and validates only what the input port
// can't already (request shape + pagination bounds). Domain validation lives
// in the service.
//
// providers is optional. When wired (production + the unified-resources
// test env both wire it), POST /admin/resources accepts
// `broker_provider_slug` and the handler resolves it to a UUID before
// calling svc.Create. When nil, the slug-only path returns a clean
// 400 explaining the dependency.
type resourceAdminHandler struct {
	svc       input.ResourceAdminPort
	providers input.BrokerProviderAdminPort
	obs       *observability.Provider
}

// handleList serves both the paginated list (no `slug` query param) and the
// slug-lookup short-circuit (with `slug=...`). The short-circuit returns a
// single ResourceView (or 404), matching the shape of GET /admin/resources/{id}
// — operators using the lookup almost always want one row, not a slice they
// have to unwrap.
func (h *resourceAdminHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if slug := r.URL.Query().Get("slug"); slug != "" {
		h.handleLookupBySlug(w, r, slug)
		return
	}

	filter, ok := h.parseListFilter(w, r)
	if !ok {
		return
	}

	rows, err := h.svc.List(r.Context(), filter)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list resources failed", err)
		return
	}

	views := make([]resourceView, len(rows))
	for i, row := range rows {
		views[i] = resourceToView(row)
	}
	shared.WriteJSON(w, http.StatusOK, views)
}

// handleLookupBySlug serves GET /admin/resources?slug=... — single-row
// lookup. Mutually exclusive with the list filters (`backend_kind`,
// `broker_provider_id`, `limit`, `offset`); their presence triggers a 400
// so operators don't think they're filtering when they're really hitting
// the lookup path.
func (h *resourceAdminHandler) handleLookupBySlug(w http.ResponseWriter, r *http.Request, slug string) {
	for _, conflicting := range []string{"backend_kind", "broker_provider_id", "limit", "offset"} {
		if r.URL.Query().Get(conflicting) != "" {
			writeAdminError(w, http.StatusBadRequest, "slug lookup is mutually exclusive with "+conflicting)
			return
		}
	}

	row, err := h.svc.GetBySlug(r.Context(), slug)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "lookup resource by slug failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, resourceToView(row))
}

func (h *resourceAdminHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	row, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get resource failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, resourceToView(row))
}

func (h *resourceAdminHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxResourceBody)
	var req createResourceRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	providerID, ok := h.resolveBrokerProviderID(w, r, req.BrokerProviderID, req.BrokerProviderSlug)
	if !ok {
		return
	}

	domainResource := &resource.Resource{
		Slug:             req.Slug,
		URI:              req.URI,
		BackendKind:      resource.BackendKind(req.BackendKind),
		BrokerProviderID: providerID,
		DisplayName:      req.DisplayName,
		Scopes:           scopesUpstreamFromViews(req.Scopes),
	}
	if req.Policy != nil {
		domainResource.Policy = policyFromView(*req.Policy)
	}

	if err := h.svc.Create(r.Context(), domainResource); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create resource failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusCreated, resourceToView(domainResource))
}

// resolveBrokerProviderID returns the canonical broker provider UUID for
// the create request. Operators may supply `broker_provider_id` (UUID,
// existing path) OR `broker_provider_slug` (operator-friendly, ) but
// not both with conflicting values. Either-empty returns "" without
// touching the broker provider service — Mint resources don't need a
// provider, and the service's existing validateBrokerProviderRef catches
// the empty-on-broker case downstream with a clean 400.
func (h *resourceAdminHandler) resolveBrokerProviderID(w http.ResponseWriter, r *http.Request, providerID, providerSlug string) (string, bool) {
	if providerSlug == "" {
		return providerID, true
	}
	if h.providers == nil {
		// Defensive — production wires both deps together. Surface a
		// clean 400 rather than a nil-pointer crash if a deployment
		// somehow wires only one.
		writeAdminError(w, http.StatusBadRequest, "broker_provider_slug not supported in this deployment (broker provider service not configured)")
		return "", false
	}
	row, err := h.providers.GetBySlug(r.Context(), providerSlug)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "resolve broker_provider_slug failed", err)
		return "", false
	}
	if providerID != "" && providerID != row.ID {
		writeAdminError(w, http.StatusBadRequest, "broker_provider_id and broker_provider_slug refer to different providers")
		return "", false
	}
	return row.ID, true
}

func (h *resourceAdminHandler) handlePatch(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxResourceBody)
	var req patchResourceRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	patch := input.ResourcePatch{
		Slug:             req.Slug,
		URI:              req.URI,
		BrokerProviderID: req.BrokerProviderID,
		DisplayName:      req.DisplayName,
	}
	if req.BackendKind != nil {
		bk := resource.BackendKind(*req.BackendKind)
		patch.BackendKind = &bk
	}
	if req.Scopes != nil {
		scopes := scopesUpstreamFromViews(*req.Scopes)
		patch.Scopes = &scopes
	}
	if req.Policy != nil {
		policy := policyFromView(*req.Policy)
		patch.Policy = &policy
	}

	updated, err := h.svc.Patch(r.Context(), id, patch)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "patch resource failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, resourceToView(updated))
}

func (h *resourceAdminHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	cascade := r.URL.Query().Get("cascade") == "true"

	dependents, err := h.svc.DeleteWithCascade(r.Context(), id, cascade)
	if err != nil {
		// Surface the dependent-link list with the 409 so the UI can render
		// a cascade-confirmation modal without a second round-trip.
		// Domain ErrResourceHasFrontingLinks is the only error class we
		// special-case here; other domain errors map via the generic helper.
		if errors.Is(err, domain.ErrResourceHasFrontingLinks) {
			body := frontingLinkConflictResponse{
				Detail:     "resource has fronting links — pass ?cascade=true to remove them",
				Dependents: frontingLinksToViews(dependents),
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":       "about:blank",
				"title":      http.StatusText(http.StatusConflict),
				"status":     http.StatusConflict,
				"detail":     body.Detail,
				"dependents": body.Dependents,
			})
			return
		}
		writeDomainOrInternalError(w, r, h.obs, "delete resource failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *resourceAdminHandler) parseListFilter(w http.ResponseWriter, r *http.Request) (input.ResourceFilter, bool) {
	filter := input.ResourceFilter{Limit: defaultResourceLimit}
	q := r.URL.Query()

	if v := q.Get("backend_kind"); v != "" {
		switch resource.BackendKind(v) {
		case resource.BackendMint, resource.BackendBroker:
			filter.BackendKind = resource.BackendKind(v)
		default:
			writeAdminError(w, http.StatusBadRequest, "backend_kind must be mint or broker")
			return filter, false
		}
	}
	if v := q.Get("broker_provider_id"); v != "" {
		filter.BrokerProviderID = v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxResourceLimit {
			writeAdminError(w, http.StatusBadRequest, "limit must be 1..500")
			return filter, false
		}
		filter.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > resourceListMaxOffset {
			writeAdminError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return filter, false
		}
		filter.Offset = n
	}
	return filter, true
}
