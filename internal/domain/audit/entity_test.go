package audit

import (
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	e := NewEvent(ActionTokenIssued, "user-1", "client-1", "192.168.1.1", "issued access token")

	if e.Action != ActionTokenIssued {
		t.Errorf("Action = %q, want token.issued", e.Action)
	}
	if e.ActorID != "user-1" {
		t.Errorf("ActorID = %q, want user-1", e.ActorID)
	}
	if e.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", e.ClientID)
	}
	if e.IP != "192.168.1.1" {
		t.Errorf("IP = %q, want 192.168.1.1", e.IP)
	}
	if e.Detail != "issued access token" {
		t.Errorf("Detail = %q", e.Detail)
	}
	if e.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if time.Since(e.CreatedAt) > 5*time.Second {
		t.Error("CreatedAt should be recent")
	}
}

func TestActionConstants(t *testing.T) {
	// Ensure all action constants are non-empty and distinct.
	actions := []Action{
		ActionTokenIssued,
		ActionTokenRefreshed,
		ActionTokenRevoked,
		ActionConsentGranted,
		ActionConsentDenied,
		ActionClientRegistered,
		ActionClientSuspended,
		ActionClientRevoked,
		ActionAuthDenied,
		ActionAuthLockedOut,
		ActionUserLogin,
		ActionUserLoginFailed,
		ActionUserCreated,
		ActionUserDisabled,
		ActionKeyRotated,
		ActionFamilyRevoked,
	}

	seen := make(map[Action]bool)
	for _, a := range actions {
		if a == "" {
			t.Error("action constant should not be empty")
		}
		if seen[a] {
			t.Errorf("duplicate action constant: %q", a)
		}
		seen[a] = true
	}

	if len(actions) != 16 {
		t.Errorf("expected 16 action constants, got %d", len(actions))
	}
}
