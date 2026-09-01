package wellknown

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// failingASMetadata is a test double whose port always returns an error,
// exercising the handler's critical-failure (500) path.
type failingASMetadata struct{}

var errBuildMetadata = errors.New("simulated metadata build failure")

func (failingASMetadata) Metadata(_ context.Context) (*input.ASMetadata, error) {
	return nil, errBuildMetadata
}

func TestHandleASMetadata_BuildError_Returns500(t *testing.T) {
	t.Parallel()

	h := &handler{asMetadata: failingASMetadata{}, obs: observability.NewNoop()}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	h.handleASMetadata(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// deadDB is a HealthChecker whose backend is unreachable — the condition under
// which /health and /ready must answer 503 and /livez must not.
type deadDB struct{}

var errDBDown = errors.New("simulated database outage")

func (deadDB) Ping(_ context.Context) error { return errDBDown }

// The whole reason /livez exists: a liveness probe decides whether to kill the
// process, so a database outage must not make it fail. If this test ever needs
// changing to accommodate a new check inside handleLive, the check is the bug.
func TestHandleLive_StaysOKWhileTheDatabaseIsDown(t *testing.T) {
	h := &healthHandler{health: deadDB{}}

	rr := httptest.NewRecorder()
	h.handleLive(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — liveness must not depend on the database", rr.Code)
	}
}

// Its siblings answer the opposite way on the same condition. Asserted here so
// the three endpoints' contract is visible in one place: a future edit that
// makes /livez DB-aware, or /ready DB-blind, breaks this.
func TestHealthAndReady_Report503WhileTheDatabaseIsDown(t *testing.T) {
	h := &healthHandler{health: deadDB{}}

	for _, tc := range []struct {
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"/health", h.handleHealth},
		{"/ready", h.handleReady},
	} {
		rr := httptest.NewRecorder()
		tc.handler(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s status = %d, want 503", tc.path, rr.Code)
		}
	}
}
