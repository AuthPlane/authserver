package connectionapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
)

// A callback whose pending resource does not belong to the provider is a
// bad request, not a server fault.
func TestHandleCallbackError_InvalidTargetIsBadRequest(t *testing.T) {
	h := &handler{obs: observability.NewNoop()}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/connect/gcal/callback?code=c&state=s", nil)
	rec := httptest.NewRecorder()

	h.handleCallbackError(rec, req, fmt.Errorf("%w: pending resource is not backed by provider", domain.ErrInvalidTarget))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
