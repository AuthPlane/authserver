package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

type stubRevoker struct{ err error }

func (s stubRevoker) RevokeToken(context.Context, input.RevokeRequest) error { return s.err }

func postRevoke(t *testing.T, err error) *httptest.ResponseRecorder {
	t.Helper()
	h := &revokeHandler{revoke: stubRevoker{err: err}, obs: observability.NewNoop()}
	form := url.Values{"token": {"tok"}, "client_id": {"c"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.handleRevoke(rec, req)
	return rec
}

// A revocation a store could not record answers 503 so the client retries
// (RFC 7009 §2.2.1); a 200 would tell it a still-valid token is gone.
func TestHandleRevoke_StoreFailureIs503(t *testing.T) {
	rec := postRevoke(t, errors.New("revocation: denylist access token: store unavailable"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "temporarily_unavailable" {
		t.Errorf("error = %q, want temporarily_unavailable", body["error"])
	}
	if desc, _ := body["error_description"].(string); strings.Contains(desc, "store unavailable") {
		t.Errorf("error_description leaks the internal error: %q", body["error_description"])
	}
}

func TestHandleRevoke_StatusCodes(t *testing.T) {
	if rec := postRevoke(t, nil); rec.Code != http.StatusOK {
		t.Errorf("success: status = %d, want 200", rec.Code)
	}
	if rec := postRevoke(t, domain.ErrInvalidClient); rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid client: status = %d, want 401", rec.Code)
	}
}
