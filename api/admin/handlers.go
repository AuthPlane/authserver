package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

type handlers struct {
	admin Provider
	obs   *observability.Provider
}

// --- Clients ---

func (h *handlers) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	resp, err := h.admin.CreateClient(r.Context(), input.CreateClientRequest{
		Name:                    req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		IsAgent:                 req.Agent,
		AgentDescription:        req.AgentDescription,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create client failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusCreated, createClientResponse{
		ClientID:                resp.Client.ID,
		ClientSecret:            resp.ClientSecret,
		ClientName:              resp.Client.Name,
		RedirectURIs:            resp.Client.RedirectURIs,
		GrantTypes:              resp.Client.GrantTypes,
		ResponseTypes:           resp.Client.ResponseTypes,
		TokenEndpointAuthMethod: resp.Client.TokenEndpointAuthMethod,
		Scope:                   resp.Client.Scope,
		Status:                  string(resp.Client.Status),
		RegistrationSource:      string(resp.Client.RegistrationSource),
		IsAgent:                 resp.Client.IsAgent,
		AgentDescription:        resp.Client.AgentDescription,
		IssuedAt:                resp.Client.IssuedAt.Format(time.RFC3339),
	})
}

func (h *handlers) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req updateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	updated, err := h.admin.UpdateClient(r.Context(), id, input.UpdateClientRequest{
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scope:        req.Scope,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "update client failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, newClientView(updated))
}

func (h *handlers) handleRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	resp, err := h.admin.RotateClientSecret(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "rotate client secret failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, rotateSecretResponse{
		ClientID:     resp.ClientID,
		ClientSecret: resp.ClientSecret,
	})
}

func (h *handlers) handleListClients(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	}

	filter := input.ClientFilter{
		Status: q.Get("status"),
		Source: q.Get("source"),
		Limit:  limit,
		Offset: offset,
	}

	clients, err := h.admin.ListClients(r.Context(), filter)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "list clients failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	shared.WriteJSON(w, http.StatusOK, newClientViews(clients))
}

func (h *handlers) handleGetClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.admin.GetClient(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get client failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, newClientView(c))
}

func (h *handlers) handleSuspendClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.admin.SuspendClient(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "suspend client failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, statusResponse{Status: "suspended"})
}

func (h *handlers) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.admin.RevokeClient(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "revoke client failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, statusResponse{Status: "revoked"})
}

func (h *handlers) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	force := r.URL.Query().Get("force") == "true"

	if err := h.admin.DeleteClient(r.Context(), id, force); err != nil {
		if errors.Is(err, domain.ErrClientHasActiveTokens) {
			h.writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeDomainOrInternalError(w, r, h.obs, "delete client failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) handleReactivateClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.admin.ReactivateClient(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "reactivate client failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, statusResponse{Status: "active"})
}

// --- Tokens ---

func (h *handlers) handleListTokens(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	}

	filter := input.TokenFilter{
		ClientID: q.Get("client_id"),
		UserID:   q.Get("user_id"),
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := h.admin.ListTokens(r.Context(), filter)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "list tokens failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	shared.WriteJSON(w, http.StatusOK, resp)
}

func (h *handlers) handleListUserTokens(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	}

	resp, err := h.admin.ListUserTokens(r.Context(), id, limit, offset)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "list user tokens failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, resp)
}

func (h *handlers) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	jti, ok := validPathParam(w, "jti", r.PathValue("jti"))
	if !ok {
		return
	}

	if err := h.admin.RevokeToken(r.Context(), jti); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "revoke token failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// maxAdminBody is the maximum request body size for admin JSON endpoints (1 MB).
const maxAdminBody = 1 << 20

// maxPathParamLen is the maximum length for path parameters (L3 defense-in-depth).
const maxPathParamLen = 256

// validPathParam checks that a path parameter is non-empty and within max length.
// Returns the value and true if valid, or writes a 400 error and returns false.
func validPathParam(w http.ResponseWriter, paramName, value string) (string, bool) {
	if value == "" {
		writeAdminError(w, http.StatusBadRequest, paramName+" is required")
		return "", false
	}
	if len(value) > maxPathParamLen {
		writeAdminError(w, http.StatusBadRequest, paramName+" too long")
		return "", false
	}
	return value, true
}

// --- Users ---

func (h *handlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.admin.ListUsers(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "list users failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	shared.WriteJSON(w, http.StatusOK, newUserViews(users))
}

func (h *handlers) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Email == "" || req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	role := user.RoleUser
	if req.Role == "admin" {
		role = user.RoleAdmin
	}

	u, err := h.admin.CreateUser(r.Context(), input.CreateUserRequest{
		Email:    req.Email,
		Name:     req.Name,
		Password: req.Password,
		Role:     role,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "create user failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusCreated, newUserView(u))
}

func (h *handlers) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := h.admin.GetUser(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "get user failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, newUserView(u))
}

func (h *handlers) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.admin.DisableUser(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "disable user failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, statusResponse{Status: "disabled"})
}

func (h *handlers) handleForceLogoutUser(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	count, err := h.admin.ForceLogoutUser(r.Context(), id)
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "force logout failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":        id,
		"tokens_revoked": count,
	})
}

func (h *handlers) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.admin.EnableUser(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "enable user failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, statusResponse{Status: "active"})
}

func (h *handlers) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	updated, err := h.admin.UpdateUser(r.Context(), id, input.UpdateUserRequest{
		Email: req.Email,
		Name:  req.Name,
	})
	if err != nil {
		writeDomainOrInternalError(w, r, h.obs, "update user failed", err)
		return
	}

	shared.WriteJSON(w, http.StatusOK, newUserView(updated))
}

func (h *handlers) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	force := r.URL.Query().Get("force") == "true"

	if err := h.admin.DeleteUser(r.Context(), id, force); err != nil {
		if errors.Is(err, domain.ErrUserHasActiveTokens) {
			h.writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeDomainOrInternalError(w, r, h.obs, "delete user failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Audit ---

func (h *handlers) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	}

	filter := input.AuditFilter{
		Action:   q.Get("action"),
		ActorID:  q.Get("actor_id"),
		ClientID: q.Get("client_id"),
		Limit:    limit,
		Offset:   offset,
	}

	if sinceStr := q.Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			filter.Since = &t
		}
	}
	if untilStr := q.Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			filter.Until = &t
		}
	}

	events, err := h.admin.QueryAudit(r.Context(), filter)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "query audit failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	shared.WriteJSON(w, http.StatusOK, newAuditEventViews(events))
}

// --- Stats ---

func (h *handlers) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.admin.GetStats(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "get stats failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	shared.WriteJSON(w, http.StatusOK, newStatsView(*stats))
}

// --- Helpers ---

// writeError is a thin wrapper retained for handlers.go call sites that don't
// need the domain-error switch. It writes an RFC 9457 Problem Details body.
func (h *handlers) writeError(w http.ResponseWriter, status int, msg string) {
	writeAdminError(w, status, msg)
}

// writeAdminError writes an RFC 9457 Problem Details JSON error response.
// This is the package-level function used by all admin handler structs.
func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"detail": msg,
	})
}

// writeDomainOrInternalError dispatches a domain error to its canonical HTTP
// status (404 / 409 / 403 / 400) and a non-domain error to 500 with a generic
// detail (the underlying error is logged, never leaked on the wire). This is
// the single canonical helper for admin error envelopes; and
// consolidated the previous instance/package-level pair.
func writeDomainOrInternalError(w http.ResponseWriter, r *http.Request, obs *observability.Provider, logMsg string, err error) {
	if domain.IsError(err) {
		code := domain.ErrorCode(err)
		switch code {
		case domain.CodeNotFound:
			writeAdminError(w, http.StatusNotFound, err.Error())
		case domain.CodeConflict:
			writeAdminError(w, http.StatusConflict, err.Error())
		case domain.CodeAccessDenied:
			writeAdminError(w, http.StatusForbidden, err.Error())
		default:
			writeAdminError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	obs.Logger.ErrorContext(r.Context(), logMsg, "error", err)
	writeAdminError(w, http.StatusInternalServerError, "internal error")
}
