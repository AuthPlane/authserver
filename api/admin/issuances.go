package admin

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

const (
	// defaultIssuancesSinceWindow is the default lookback applied when
	// the caller omits ?since=. Default: 24h.
	defaultIssuancesSinceWindow = 24 * time.Hour

	// maxIssuancesSinceWindow caps the windowed list query. Bigger
	// windows pull a lot of rows and shouldn't be served from the admin
	// API. Cap: 30 days.
	maxIssuancesSinceWindow = 30 * 24 * time.Hour

	// defaultIssuancesLimit / maxIssuancesLimit bound the ?limit= query
	// param. We do NOT enforce a hard truncation — the underlying store
	// query has no LIMIT clause; the cap here is the validation bound
	// on the ?limit= query param so absurd values are rejected at the
	// boundary. The 5K case is covered end-to-end by the test suite.
	defaultIssuancesLimit = 500
	maxIssuancesLimit     = 5000
)

// issuanceAdminHandler serves /admin/issuances forensic + revoke paths
// (the design, filter relaxation).
//
// Filter validation: at least one of ?user=, ?client=, ?jti=, ?resource=
// is required. ?jti= remains a point-query (other params ignored on hit).
// Otherwise the indexed dimension drives the DB query (preference order:
// user, client, resource) and any remaining filters are applied as an
// in-memory predicate before the limit truncation. This shape supports
// the Grants → Issuances cross-link from which pivots on a
// (user, client, resource) tuple without forcing a denormalized
// composite index.
type issuanceAdminHandler struct {
	svc input.IssuanceAdminPort
	obs *observability.Provider
}

// handleList serves GET /admin/issuances?...
func (h *issuanceAdminHandler) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	user := q.Get("user")
	clientID := q.Get("client")
	jti := q.Get("jti")
	resourceID := q.Get("resource")

	if countNonEmpty(user, clientID, jti, resourceID) == 0 {
		writeAdminError(w, http.StatusBadRequest, "requires at least one of: user, client, jti, resource")
		return
	}

	// JTI is a point-query: ?since= is ignored, the result is a
	// single-element array on hit and an empty array on miss (NOT 404 —
	// list semantics). When other filter params are supplied alongside
	// ?jti=, the hit must still match them — otherwise admins could
	// follow a stale grant link to a token that no longer belongs to the
	// (user, client, resource) tuple they were inspecting.
	if jti != "" {
		i, err := h.svc.GetByJTI(r.Context(), jti)
		if err != nil {
			writeDomainOrInternalError(w, r, h.obs, "get issuance by jti failed", err)
			return
		}
		var rows []issuanceView
		if i != nil && issuanceMatches(i, user, clientID, resourceID) {
			rows = []issuanceView{issuanceToView(i)}
		} else {
			rows = []issuanceView{}
		}
		shared.WriteJSON(w, http.StatusOK, issuanceListResponse{
			Issuances: rows,
			Since:     time.Time{}.UTC().Format(time.RFC3339),
			Count:     len(rows),
		})
		return
	}

	since, ok := parseSinceWindow(w, q.Get("since"))
	if !ok {
		return
	}

	limit, ok := parseLimit(w, q.Get("limit"))
	if !ok {
		return
	}

	// Pick the indexed dimension that drives the DB query. The
	// (subject_user_id, issued_at DESC), (client_id, issued_at DESC) and
	// (resource_id, issued_at DESC) indexes are all present; preference
	// order is informed by cardinality (user > client > resource in a
	// healthy fleet). The driving dimension is zeroed in the residual
	// filter tuple — rows already match it via the indexed lookup.
	var got []*resource.Issuance
	var err error
	residualUser, residualClient, residualResource := user, clientID, resourceID
	switch {
	case user != "":
		got, err = h.svc.ListForUser(r.Context(), user, since)
		if err != nil {
			writeDomainOrInternalError(w, r, h.obs, "list issuances for user failed", err)
			return
		}
		residualUser = ""
	case clientID != "":
		got, err = h.svc.ListForActor(r.Context(), clientID, since)
		if err != nil {
			writeDomainOrInternalError(w, r, h.obs, "list issuances for actor failed", err)
			return
		}
		residualClient = ""
	case resourceID != "":
		got, err = h.svc.ListForResource(r.Context(), resourceID, since)
		if err != nil {
			writeDomainOrInternalError(w, r, h.obs, "list issuances for resource failed", err)
			return
		}
		residualResource = ""
	}

	// In-memory post-filter for any remaining dimensions. The 30-day
	// since window already bounds the working set; explicitly
	// trades a composite index for the predicate-after-fetch shape
	// because the Grants → Issuances pivot is operator-driven and the
	// driving filter (user/client) keeps the working set small.
	filtered := got[:0]
	for _, i := range got {
		if issuanceMatches(i, residualUser, residualClient, residualResource) {
			filtered = append(filtered, i)
		}
	}

	rows := issuancesToViews(filtered)

	// Wire-level truncation: ?limit=N defaults to 500 and caps at 5000.
	// The IssuanceStore port does not accept a limit; truncation runs
	// here so we honor operator intent without extending the storage
	// signature. The 30-day since window already bounds DB cost; for
	// very active fleets operators should query the DB / OTel exports
	// directly.
	if len(rows) > limit {
		rows = rows[:limit]
	}

	shared.WriteJSON(w, http.StatusOK, issuanceListResponse{
		Issuances: rows,
		Since:     since.UTC().Format(time.RFC3339),
		Count:     len(rows),
	})
}

// issuanceMatches reports whether i satisfies every non-empty filter.
// Empty filters are wildcards. Used by handleList for combined
// (user, client, resource) cross-link queries and by the ?jti= path so
// a stale jti from a different tuple does not leak through.
func issuanceMatches(i *resource.Issuance, user, clientID, resourceID string) bool {
	if user != "" && i.SubjectUserID != user {
		return false
	}
	if clientID != "" && i.ClientID != clientID {
		return false
	}
	if resourceID != "" && i.ResourceID != resourceID {
		return false
	}
	return true
}

// handleGet serves GET /admin/issuances/{id} (issuance UUID).
//
// ?jti= lookups go through handleList — the path-keyed GET is UUID-only
// so Broker issuances (whose jti is empty per ) stay addressable.
func (h *issuanceAdminHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	i, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrIssuanceNotFound) {
			writeAdminError(w, http.StatusNotFound, "issuance not found")
			return
		}
		writeDomainOrInternalError(w, r, h.obs, "get issuance failed", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, issuanceToView(i))
}

// handleRevoke serves DELETE /admin/issuances/{id}.
//
// Soft-delete: revoked_at is set, the row is preserved for forensics.
// Idempotent (repeated calls are no-ops at the storage tier).
func (h *issuanceAdminHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := validPathParam(w, "id", r.PathValue("id"))
	if !ok {
		return
	}

	if err := h.svc.Revoke(r.Context(), id); err != nil {
		writeDomainOrInternalError(w, r, h.obs, "revoke issuance failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// countNonEmpty returns the number of non-empty strings in vals. Used
// for the mutual-exclusion check on the issuance filter.
func countNonEmpty(vals ...string) int {
	n := 0
	for _, v := range vals {
		if v != "" {
			n++
		}
	}
	return n
}

// parseSinceWindow honors RFC3339 ?since= with the 24h default and
// 30-day cap. Returns the effective since + ok=true on success;
// ok=false means a 400 has already been written.
func parseSinceWindow(w http.ResponseWriter, raw string) (time.Time, bool) {
	now := time.Now().UTC()
	if raw == "" {
		return now.Add(-defaultIssuancesSinceWindow), true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "since must be RFC3339")
		return time.Time{}, false
	}
	if now.Sub(t) > maxIssuancesSinceWindow {
		writeAdminError(w, http.StatusBadRequest, "since window exceeds 30 days; narrow the query or use direct DB access")
		return time.Time{}, false
	}
	return t.UTC(), true
}

// parseLimit returns the effective row cap for the response — the
// caller's ?limit= if present, otherwise the default of 500. Returns
// ok=false after writing a 400 when the param is malformed or outside
// [1, maxIssuancesLimit].
func parseLimit(w http.ResponseWriter, raw string) (int, bool) {
	if raw == "" {
		return defaultIssuancesLimit, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > maxIssuancesLimit {
		writeAdminError(w, http.StatusBadRequest, "limit must be 1..5000")
		return 0, false
	}
	return n, true
}
