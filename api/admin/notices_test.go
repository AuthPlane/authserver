package admin

import "testing"

// The notice fires on the combination that will break at v0.3.0: a door open
// for self-registration, and no ceiling to give the clients it creates.
func TestOperatorNotices_DefaultClientScope(t *testing.T) {
	const id = "oauth-default-client-scope-required-v0.3.0"

	tests := []struct {
		name               string
		dcrMode            string
		defaultClientScope string
		want               bool
	}{
		{"open, no ceiling", "open", "", true},
		// "" registers nothing — config validation rejects it and both
		// registration services fail closed on an unrecognized mode — so there
		// is nothing for the operator to act on.
		{"empty mode, no ceiling", "", "", false},
		{"approved_redirects, no ceiling", "approved_redirects", "", true},
		// CIMD refuses to auto-register under admin_only too, so nothing can
		// self-register and there is nothing for the operator to act on.
		{"admin_only, no ceiling", "admin_only", "", false},
		{"open, ceiling set", "open", "tools/read", false},
		{"admin_only, ceiling set", "admin_only", "tools/read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notices := operatorNotices(tt.dcrMode, tt.defaultClientScope)
			var found bool
			for _, n := range notices {
				if n.ID == id {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("notice %q present = %v, want %v (dcr.mode=%q, default_client_scope=%q)",
					id, found, tt.want, tt.dcrMode, tt.defaultClientScope)
			}
		})
	}
}

// The field is rendered by a UI that iterates it, so it must serialize as []
// rather than null when there is nothing to report.
func TestOperatorNotices_NeverNil(t *testing.T) {
	if notices := operatorNotices("admin_only", "tools/read"); notices == nil {
		t.Fatal("operatorNotices returned nil; want an empty slice so the JSON is [] not null")
	}
}

// Every notice needs the fields the UI renders, and an ID stable enough to
// dismiss or link to.
func TestOperatorNotices_AreWellFormed(t *testing.T) {
	for _, n := range operatorNotices("open", "") {
		if n.ID == "" || n.Title == "" || n.Body == "" {
			t.Errorf("notice %+v is missing id, title or body", n)
		}
		if n.Severity != "info" && n.Severity != "warning" {
			t.Errorf("notice %q severity = %q, want info or warning", n.ID, n.Severity)
		}
	}
}
