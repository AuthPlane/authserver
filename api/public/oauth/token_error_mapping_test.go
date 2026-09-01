package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
)

// Both reuse-detection outcomes must reach the client as 400 invalid_grant
// with the SAME error_description: the presenter of a replayed token must
// not learn whether the family revocation succeeded. ErrReuseRevocationFailed
// is a distinct identity for errors.Is but carries ErrFamilyRevoked's
// message, so no handler arm or arm ordering is needed to mask it — any
// writer that emits err.Error() sends the right text.
func TestWriteTokenError_ReuseSentinelsMapToInvalidGrant(t *testing.T) {
	h := &oauthHandler{obs: observability.NewNoop()}

	cases := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{"family revoked", domain.ErrFamilyRevoked, "token family revoked due to reuse detection"},
		{"family revocation failed — same text on the wire", domain.ErrReuseRevocationFailed, "token family revoked due to reuse detection"},
		{"invalid_grant with validation detail", fmt.Errorf("%w: subject_token is required", domain.ErrInvalidGrant), "the authorization grant is invalid, expired, or revoked: subject_token is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/token", nil)
			h.writeTokenError(rec, req, tc.err)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
			}
			if body.Error != "invalid_grant" {
				t.Errorf("error = %q, want invalid_grant", body.Error)
			}
			if body.Description != tc.wantMsg {
				t.Errorf("error_description = %q, want %q", body.Description, tc.wantMsg)
			}
		})
	}
}

// TestWriteTokenError_InvalidTarget pins the wire shape of a refused exchange
// that named no resource. The service layer returns a wrapped
// domain.ErrInvalidTarget and nothing in writeTokenError names it explicitly —
// the response is produced by the trailing domain.IsError branch. That makes
// the documented contract (400 invalid_target) an emergent property, so assert
// it here: adding an explicit case for ErrInvalidTarget with a different code
// or status, as api/public/connection/handlers.go does for its own transport,
// must fail this test rather than silently change the token endpoint.
func TestWriteTokenError_InvalidTarget(t *testing.T) {
	h := &oauthHandler{obs: observability.NewNoop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/token", strings.NewReader(""))

	err := fmt.Errorf("%w: resource is required (xaa.require_resource=true)", domain.ErrInvalidTarget)
	h.writeTokenError(rec, req, err)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &body); decodeErr != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), decodeErr)
	}
	if body.Error != "invalid_target" {
		t.Errorf("error = %q, want invalid_target", body.Error)
	}
	// The error text itself must survive into error_description rather than
	// being replaced by a canned message. What that text says is the service's
	// business and is asserted end-to-end in e2e/scenarios/xaa_test.go, which
	// drives the real GrantJWTBearer instead of a hand-built error.
	if !strings.Contains(body.Description, "xaa.require_resource") {
		t.Errorf("error_description should carry the service's text, got %q", body.Description)
	}
}
