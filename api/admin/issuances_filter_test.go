package admin

import (
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
)

// TestIssuanceMatches covers the in-memory post-filter used by handleList
// for combined-dimension queries. Each non-empty filter must
// match exactly; empty filters are wildcards. The function is also
// reused on the ?jti= point-query path so a stale JTI from a different
// (user, client, resource) tuple cannot leak through.
func TestIssuanceMatches(t *testing.T) {
	row := &resource.Issuance{
		SubjectUserID: "user-1",
		ClientID:      "client-1",
		ResourceID:    "resource-1",
	}

	cases := []struct {
		name                       string
		user, clientID, resourceID string
		want                       bool
	}{
		{"all wildcards", "", "", "", true},
		{"matching user only", "user-1", "", "", true},
		{"matching client only", "", "client-1", "", true},
		{"matching resource only", "", "", "resource-1", true},
		{"matching all three", "user-1", "client-1", "resource-1", true},
		{"mismatching user", "user-2", "", "", false},
		{"mismatching client", "", "client-2", "", false},
		{"mismatching resource", "", "", "resource-2", false},
		{"user matches but resource doesn't", "user-1", "", "resource-2", false},
		{"user+client match but resource doesn't", "user-1", "client-1", "resource-2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := issuanceMatches(row, tc.user, tc.clientID, tc.resourceID)
			if got != tc.want {
				t.Errorf("issuanceMatches(%+v, %q, %q, %q) = %v, want %v",
					row, tc.user, tc.clientID, tc.resourceID, got, tc.want)
			}
		})
	}
}
