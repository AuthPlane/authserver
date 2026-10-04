package oauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
)

type fakeAudit struct{ events []audit.Event }

func (f *fakeAudit) Record(_ context.Context, e audit.Event) {
	f.events = append(f.events, e)
}

func TestRecordLockout_EmitsAuthLockedOutInTheCatalogedShape(t *testing.T) {
	f := &fakeAudit{}
	h := &loginHandler{obs: observability.NewNoop(), audit: f}

	until := time.Now().Add(15 * time.Minute)
	h.recordLockout(context.Background(), "10.0.0.1", until)

	if len(f.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(f.events))
	}
	e := f.events[0]
	if e.Action != audit.ActionAuthLockedOut {
		t.Errorf("Action = %q, want %q", e.Action, audit.ActionAuthLockedOut)
	}
	// ActorID is contracted as a user ID, client ID or "system". A lockout
	// engages on a submitted identity that need not resolve to any account, so
	// there is nothing contracted to put there. The sibling event
	// user.login_failed does fill in the resolved user id on the causes where
	// the address matched an account (user_auth.go, denyLogin).
	if e.ActorID != "" {
		t.Errorf("ActorID = %q, want empty", e.ActorID)
	}
	if e.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", e.IP)
	}
	// Detail is the cataloged `key=value` payload operators grep. It carries the
	// deadline and nothing the form posted — see
	// TestRecordLockout_DetailResistsInjectionViaTheAddress.
	wantDetail := "until=" + until.Format(time.RFC3339)
	if e.Detail != wantDetail {
		t.Errorf("Detail = %q, want %q", e.Detail, wantDetail)
	}
}

// Audit is optional; a deployment that wires none must still lock out.
func TestRecordLockout_NilAuditIsSafe(t *testing.T) {
	h := &loginHandler{obs: observability.NewNoop(), audit: nil}
	h.recordLockout(context.Background(), "10.0.0.1", time.Now())
}

// Detail is contracted as greppable key=value, and the address is arbitrary form
// input. A value containing a space and its own "until=" once produced a row
// whose first until= was attacker-chosen. The address no longer reaches the
// row at all: the handler is handed only the source IP and the deadline, so the
// poster has no way to place text in Detail. The row is pinned to exactly the
// deadline so any future addition has to be a deliberate one.
func TestRecordLockout_DetailResistsInjectionViaTheAddress(t *testing.T) {
	f := &fakeAudit{}
	h := &loginHandler{obs: observability.NewNoop(), audit: f}

	until := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	h.recordLockout(context.Background(), "10.0.0.1", until)

	detail := f.events[0].Detail
	if detail != "until=2026-08-12T10:00:00Z" {
		t.Errorf("Detail = %q, want exactly the real deadline", detail)
	}
	if strings.Contains(detail, "@") {
		t.Errorf("Detail = %q, want no address in it", detail)
	}
}
