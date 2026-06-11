//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// adminConsentGrantView mirrors the subset of internal/admin/dto.ConsentGrantView
// the e2e tests read. Defined locally so the tests do not import
// internal/admin/dto (Gate 0).
type adminConsentGrantView struct {
	ID         string   `json:"id"`
	UserID     string   `json:"user_id"`
	ClientID   string   `json:"client_id"`
	ResourceID string   `json:"resource_id"`
	Scopes     []string `json:"scopes"`
}

// findActorConsentGrant calls GET /admin/users/{userID}/grants and returns
// the consent_grants row matching (clientID, resourceID), or nil if none
// is found.
func findActorConsentGrant(t *testing.T, h *e2e.TestHarness, userID, clientID, resourceID string) *adminConsentGrantView {
	t.Helper()
	resp := h.AdminRequest("GET", "/admin/users/"+userID+"/grants", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/users/%s/grants: status %d", userID, resp.StatusCode)
	}
	var body struct {
		ConsentGrants []adminConsentGrantView `json:"consent_grants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode user grants response: %v", err)
	}
	for i := range body.ConsentGrants {
		g := body.ConsentGrants[i]
		if g.ClientID == clientID && g.ResourceID == resourceID {
			return &g
		}
	}
	return nil
}
