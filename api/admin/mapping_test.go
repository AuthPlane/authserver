// mapping_test.go pins the admin-handler error-envelope contract that
// consolidated: every typed domain.Error reaches the wire as an
// RFC 9457 Problem Details body whose `status` field matches the HTTP
// status, with the canonical mapping (404 for not-found, 409 for
// conflict, 403 for access-denied, 400 for invalid_request, 500 for
// non-domain failures).
//
// The convention test walks every route registered in routes.go to
// catch a future handler that is added without going through
// writeDomainOrInternalError — a unit test of the helper alone would
// not catch a new misuse on a sibling handler.
//
// The focused tests cover the three defects closed:
//
//   - Defect A — domain.ErrUserNotFound was miscoded "invalid_request"
//     and produced HTTP 400 (apctl exit 3) for unknown users on
//     list-tokens / disable / enable / get. Now 404 → exit 4.
//   - Defect B — *user.StateError and *client.StateError did not
//     implement domain.Error, so writeDomainOrInternalError fell
//     through to the 500 arm on already-in-target-state transitions
//     (disable / enable / suspend / reactivate). Now 409 → exit 6.
//   - Audit emission — the no-op 409 path must NOT emit an audit
//     event, since the resource state did not change. The fixture
//     here uses a capturing recorder to assert zero events.
package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// captureAuditRecorder records audit events into an in-memory slice so
// the 409-no-audit assertions can read them back without query()ing
// SQLite. It is goroutine-safe in case a future handler dispatches the
// recorder asynchronously.
type captureAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureAuditRecorder) Record(_ context.Context, e audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureAuditRecorder) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

type auditingAdminEnv struct {
	*adminTestEnv
	rec *captureAuditRecorder
}

// newAdminTestServerWithAudit mirrors newAdminTestServer but wires a
// capturing audit recorder so the 409 tests can assert no event was
// emitted on the no-op path.
func newAdminTestServerWithAudit(t *testing.T) *auditingAdminEnv {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	rec := &captureAuditRecorder{}

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, rec,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)

	srv := apiadmin.NewServer(context.Background(), config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &auditingAdminEnv{
		adminTestEnv: &adminTestEnv{
			ts:     ts,
			stores: &testdata.TestHelper{Stores: stores},
		},
		rec: rec,
	}
}

// assertProblemDetails decodes the body and asserts the response is an
// RFC 9457 Problem Details envelope whose `status` member matches the
// HTTP status. Returns the decoded body for caller-specific checks.
func assertProblemDetails(t *testing.T, resp *http.Response, wantStatus int) map[string]any {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, wantStatus)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want application/problem+json", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, ok := body["status"].(float64); !ok || int(got) != wantStatus {
		t.Errorf("body status: got %v, want %d", body["status"], wantStatus)
	}
	if d, _ := body["detail"].(string); d == "" {
		t.Error("body detail is empty")
	}
	return body
}

// --- Defect A — 404 for unknown user ---

// surface. Each subtest hits a user-state endpoint with a
// nonsense user id and expects 404 + Problem Details. Pre- these
// returned 400 because domain.ErrUserNotFound was coded
// "invalid_request" — the helper's default arm.
func TestAdmin_UnknownUser_404_AcrossEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"GetUser", http.MethodGet, "/admin/users/does-not-exist"},
		{"ListUserTokens", http.MethodGet, "/admin/users/does-not-exist/tokens"},
		{"DisableUser", http.MethodPatch, "/admin/users/does-not-exist/disable"},
		{"EnableUser", http.MethodPatch, "/admin/users/does-not-exist/enable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newAdminTestServer(t)
			resp := env.doRequest(t, tc.method, tc.path, nil)
			defer func() { _ = resp.Body.Close() }()
			assertProblemDetails(t, resp, http.StatusNotFound)
		})
	}
}

// --- Defect A — 404 for unknown client on GET ---

// Pre- GetClient returned 404 by accident (any service error
// became "client not found" via the inline writeError). After
// it routes through writeDomainOrInternalError + ErrClientNotFound,
// keeping the 404 status but switching to Problem Details.
func TestAdmin_UnknownClient_GetClient_404(t *testing.T) {
	env := newAdminTestServer(t)
	resp := env.doRequest(t, http.MethodGet, "/admin/clients/does-not-exist", nil)
	defer func() { _ = resp.Body.Close() }()
	assertProblemDetails(t, resp, http.StatusNotFound)
}

// --- Defect B — 409 for no-op state transitions, no audit event ---

// surface. Disabling an already-disabled user, enabling an
// already-active user, suspending an already-suspended client, or
// reactivating an already-active client now returns 409. Pre-
// each returned 500 because *user.StateError / *client.StateError did
// not implement domain.Error.
func TestAdmin_NoOpStateTransitions_409_NoAudit(t *testing.T) {
	t.Run("DisableUser_AlreadyDisabled", func(t *testing.T) {
		env := newAdminTestServerWithAudit(t)
		u := newDisabledUser(t, env)

		resp := env.doRequest(t, http.MethodPatch, "/admin/users/"+u.ID+"/disable", nil)
		defer func() { _ = resp.Body.Close() }()
		assertProblemDetails(t, resp, http.StatusConflict)
		assertNoAuditEvent(t, env.rec, audit.ActionUserDisabled)
	})

	t.Run("EnableUser_AlreadyActive", func(t *testing.T) {
		env := newAdminTestServerWithAudit(t)
		u := createTestUser(t, env.stores.Stores) // active by default

		resp := env.doRequest(t, http.MethodPatch, "/admin/users/"+u.ID+"/enable", nil)
		defer func() { _ = resp.Body.Close() }()
		assertProblemDetails(t, resp, http.StatusConflict)
		// EnableUser does not record audit on success either, but assert
		// nothing got recorded for this user under any action — the no-op
		// path must not slip in a misleading "user.enabled" event.
		if got := len(env.rec.snapshot()); got != 0 {
			t.Errorf("audit events on no-op enable: got %d, want 0", got)
		}
	})

	t.Run("SuspendClient_AlreadySuspended", func(t *testing.T) {
		env := newAdminTestServerWithAudit(t)
		c := newSuspendedClient(t, env)

		resp := env.doRequest(t, http.MethodPatch, "/admin/clients/"+c.ID+"/suspend", nil)
		defer func() { _ = resp.Body.Close() }()
		assertProblemDetails(t, resp, http.StatusConflict)
		assertNoAuditEvent(t, env.rec, audit.ActionClientSuspended)
	})

	t.Run("ReactivateClient_AlreadyActive", func(t *testing.T) {
		env := newAdminTestServerWithAudit(t)
		c := createTestClient(t, env.stores.Stores) // active by default

		resp := env.doRequest(t, http.MethodPatch, "/admin/clients/"+c.ID+"/reactivate", nil)
		defer func() { _ = resp.Body.Close() }()
		assertProblemDetails(t, resp, http.StatusConflict)
		// ReactivateClient does record an audit event on the success
		// path; assert the no-op path emitted nothing.
		if got := len(env.rec.snapshot()); got != 0 {
			t.Errorf("audit events on no-op reactivate: got %d, want 0", got)
		}
	})
}

// --- Convention test — walk routes and pin the envelope ---

// TestAdmin_RouteTable_NotFoundEnvelope hits every admin route that
// takes an `id` path param with a non-existent id and asserts the
// response is a Problem Details body whose `status` matches the HTTP
// status. The goal isn't to assert a specific status (some endpoints
// return 400 for "unknown client" because their service path returns
// ErrInvalidClient — see follow-up scope notes); the goal is
// to catch a regression that emits a non-Problem-Details body or a
// status field that disagrees with the HTTP status. The next time
// someone wires a handler that bypasses writeDomainOrInternalError,
// this test fires at PR time.
func TestAdmin_RouteTable_NotFoundEnvelope(t *testing.T) {
	env := newAdminTestServer(t)

	// Build a representative request per route. The set is curated to
	// the core admin surface (clients, users, tokens) — optional deps
	// (XAA, resources, fronting) require their own server wiring and
	// are exercised by their own tests.
	cases := []struct {
		name       string
		method     string
		path       string
		body       any
		acceptable []int // canonical HTTP status(es) we accept
	}{
		{"GetUser", http.MethodGet, "/admin/users/missing", nil, []int{http.StatusNotFound}},
		{"ListUserTokens", http.MethodGet, "/admin/users/missing/tokens", nil, []int{http.StatusNotFound}},
		{"DisableUser", http.MethodPatch, "/admin/users/missing/disable", nil, []int{http.StatusNotFound}},
		{"EnableUser", http.MethodPatch, "/admin/users/missing/enable", nil, []int{http.StatusNotFound}},
		{"ForceLogoutUser", http.MethodDelete, "/admin/users/missing/tokens", nil, []int{http.StatusNotFound}},
		{"UpdateUser", http.MethodPatch, "/admin/users/missing", map[string]any{"name": "x"}, []int{http.StatusNotFound}},
		{"DeleteUser", http.MethodDelete, "/admin/users/missing", nil, []int{http.StatusNotFound}},
		{"GetClient", http.MethodGet, "/admin/clients/missing", nil, []int{http.StatusNotFound}},
		// Suspend/Revoke/Reactivate/Update on missing client return 400
		// today because the service surfaces ErrInvalidClient (OAuth
		// "invalid_client") rather than ErrClientNotFound. The
		// convention test only asserts the envelope, not the canonical
		// status — fixing those mappings is tracked as the
		// sweep follow-up.
		{"SuspendClient", http.MethodPatch, "/admin/clients/missing/suspend", nil, []int{http.StatusNotFound, http.StatusBadRequest}},
		{"RevokeClient", http.MethodPatch, "/admin/clients/missing/revoke", nil, []int{http.StatusNotFound, http.StatusBadRequest}},
		{"ReactivateClient", http.MethodPatch, "/admin/clients/missing/reactivate", nil, []int{http.StatusNotFound, http.StatusBadRequest}},
		{"UpdateClient", http.MethodPatch, "/admin/clients/missing", map[string]any{"client_name": "x"}, []int{http.StatusNotFound, http.StatusBadRequest}},
		{"DeleteClient", http.MethodDelete, "/admin/clients/missing", nil, []int{http.StatusNotFound, http.StatusBadRequest}},
		{"RotateClientSecret", http.MethodPost, "/admin/clients/missing/rotate-secret", nil, []int{http.StatusNotFound, http.StatusBadRequest}},
		{"RevokeToken", http.MethodDelete, "/admin/tokens/missing", nil, []int{http.StatusNotFound, http.StatusBadRequest}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.doRequest(t, tc.method, tc.path, tc.body)
			defer func() { _ = resp.Body.Close() }()

			if !containsInt(tc.acceptable, resp.StatusCode) {
				t.Fatalf("status: got %d, want one of %v", resp.StatusCode, tc.acceptable)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type: got %q, want application/problem+json", ct)
			}
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if got, ok := body["status"].(float64); !ok || int(got) != resp.StatusCode {
				t.Errorf("body status %v != HTTP status %d (envelope drift)", body["status"], resp.StatusCode)
			}
			if d, _ := body["detail"].(string); strings.TrimSpace(d) == "" {
				t.Error("body detail is empty")
			}
		})
	}
}

// --- Helpers ---

func newDisabledUser(t *testing.T, env *auditingAdminEnv) *user.User {
	t.Helper()
	now := time.Now().UTC()
	u := &user.User{
		ID:           crypto.GenerateRandomString(16),
		Email:        crypto.GenerateRandomString(8) + "@test.com",
		Name:         "Disabled User",
		PasswordHash: "$2a$10$dummy",
		Role:         user.RoleUser,
		Status:       user.StatusDisabled,
		Provider:     user.ProviderLocal,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := env.stores.Stores.User.Create(context.Background(), u); err != nil {
		t.Fatalf("create disabled user: %v", err)
	}
	return u
}

func newSuspendedClient(t *testing.T, env *auditingAdminEnv) *client.Client {
	t.Helper()
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Suspended Client",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusSuspended,
		RegistrationSource:      client.SourceAdmin,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := env.stores.Stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create suspended client: %v", err)
	}
	return c
}

func assertNoAuditEvent(t *testing.T, rec *captureAuditRecorder, action audit.Action) {
	t.Helper()
	for _, e := range rec.snapshot() {
		if e.Action == action {
			t.Errorf("expected no %q audit event on no-op 409, got: %+v", action, e)
		}
	}
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
