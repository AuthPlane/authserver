package admin

import (
	"encoding/json"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// resourcePolicyAdminHandler serves the per-policy-field admin endpoints
// under /admin/resources/{slug}/policy/.... The endpoints
// give operators an atomic add/remove/list surface for
// `policy.exchange.allowed_client_ids` and `policy.connect.allowed_return_urls`
// so onboarding scripts no longer need a fetch-mutate-PATCH dance.
type resourcePolicyAdminHandler struct {
	svc input.ResourceAdminPort
	obs *observability.Provider
}

// allowedClientRequest is the JSON body for
// POST /admin/resources/{slug}/policy/exchange/allowed-clients.
type allowedClientRequest struct {
	ClientID string `json:"client_id"`
}

// allowedClientsResponse is the JSON body for the GET / POST / DELETE
// allowed-clients endpoints. Same shape across all three so callers can
// react on a single field.
type allowedClientsResponse struct {
	AllowedClientIDs []string `json:"allowed_client_ids"`
}

// allowedReturnURLRequest is the JSON body for
// POST /admin/resources/{slug}/policy/connect/allowed-return-urls.
type allowedReturnURLRequest struct {
	URL string `json:"url"`
}

// allowedReturnURLsResponse is the JSON body for the GET / POST / DELETE
// allowed-return-urls endpoints.
type allowedReturnURLsResponse struct {
	AllowedReturnURLs []string `json:"allowed_return_urls"`
}

// runtimeClientRequest is the JSON body for
// POST /admin/resources/{slug}/policy/runtime/client-ids.
type runtimeClientRequest struct {
	ClientID string `json:"client_id"`
}

// runtimeClientIDsResponse is the JSON body for the GET / POST / DELETE
// runtime/client-ids endpoints. Carries the post-mutation list so callers
// can react on a single field, mirroring allowedClientsResponse.
type runtimeClientIDsResponse struct {
	ClientIDs []string `json:"client_ids"`
}

// --- exchange.allowed_client_ids ---

func (h *resourcePolicyAdminHandler) handleListAllowedClients(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}

	out, err := h.svc.ListAllowedClients(r.Context(), slug)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list allowed clients failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, allowedClientsResponse{AllowedClientIDs: orEmpty(out)})
}

func (h *resourcePolicyAdminHandler) handleAddAllowedClient(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var req allowedClientRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	out, err := h.svc.AddAllowedClient(r.Context(), slug, req.ClientID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "add allowed client failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, allowedClientsResponse{AllowedClientIDs: orEmpty(out)})
}

func (h *resourcePolicyAdminHandler) handleRemoveAllowedClient(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}
	clientID, ok := validPathParam(w, "client_id", r.PathValue("client_id"))
	if !ok {
		return
	}

	out, err := h.svc.RemoveAllowedClient(r.Context(), slug, clientID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "remove allowed client failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, allowedClientsResponse{AllowedClientIDs: orEmpty(out)})
}

// --- connect.allowed_return_urls ---

func (h *resourcePolicyAdminHandler) handleListAllowedReturnURLs(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}

	out, err := h.svc.ListAllowedReturnURLs(r.Context(), slug)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list allowed return urls failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, allowedReturnURLsResponse{AllowedReturnURLs: orEmpty(out)})
}

func (h *resourcePolicyAdminHandler) handleAddAllowedReturnURL(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var req allowedReturnURLRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	out, err := h.svc.AddAllowedReturnURL(r.Context(), slug, req.URL)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "add allowed return url failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, allowedReturnURLsResponse{AllowedReturnURLs: orEmpty(out)})
}

// handleRemoveAllowedReturnURL accepts the URL via the `url` query parameter,
// not a path segment. URLs contain `:`, `/`, `?` and `#` which collide with
// path delimiters; query-string encoding is the portable form (see PR 1
// design discussion in the thread).
func (h *resourcePolicyAdminHandler) handleRemoveAllowedReturnURL(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}
	returnURL := r.URL.Query().Get("url")
	if returnURL == "" {
		writeAdminError(w, http.StatusBadRequest, "url query parameter is required")
		return
	}

	out, err := h.svc.RemoveAllowedReturnURL(r.Context(), slug, returnURL)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "remove allowed return url failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, allowedReturnURLsResponse{AllowedReturnURLs: orEmpty(out)})
}

// --- runtime.client_ids ---

func (h *resourcePolicyAdminHandler) handleListRuntimeClientIDs(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}

	out, err := h.svc.ListRuntimeClientIDs(r.Context(), slug)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list runtime client_ids failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, runtimeClientIDsResponse{ClientIDs: orEmpty(out)})
}

func (h *resourcePolicyAdminHandler) handleAddRuntimeClientID(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var req runtimeClientRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	out, err := h.svc.AddRuntimeClientID(r.Context(), slug, req.ClientID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "add runtime client_id failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, runtimeClientIDsResponse{ClientIDs: orEmpty(out)})
}

func (h *resourcePolicyAdminHandler) handleRemoveRuntimeClientID(w http.ResponseWriter, r *http.Request) {
	slug, ok := validPathParam(w, "slug", r.PathValue("slug"))
	if !ok {
		return
	}
	clientID, ok := validPathParam(w, "client_id", r.PathValue("client_id"))
	if !ok {
		return
	}

	out, err := h.svc.RemoveRuntimeClientID(r.Context(), slug, clientID)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "remove runtime client_id failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, runtimeClientIDsResponse{ClientIDs: orEmpty(out)})
}

// orEmpty replaces a nil slice with an empty slice so JSON marshaling emits
// `[]` rather than `null`. Operators consuming the response field expect a
// stable array shape regardless of policy state.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
