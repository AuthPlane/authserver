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
	h.recordLockout(context.Background(), "victim@example.com", "10.0.0.1", until)

	if len(f.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(f.events))
	}
	e := f.events[0]
	if e.Action != audit.ActionAuthLockedOut {
		t.Errorf("Action = %q, want %q", e.Action, audit.ActionAuthLockedOut)
	}
	// ActorID is contracted as a user ID, client ID or "system". A submitted
	// address is none of those, and it is an indexed exact-match filter on the
	// admin audit feed — the wrong home for text the caller chooses. The sibling
	// event user.login_failed keeps the address out of ActorID for the same
	// reason; it does fill in the resolved user id on the causes where the
	// address matched an account, which is the contracted value, not the
	// caller's text (user_auth.go, denyLogin).
	if e.ActorID != "" {
		t.Errorf("ActorID = %q, want empty — the address belongs in Detail", e.ActorID)
	}
	if e.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", e.IP)
	}
	// Detail is the cataloged `key=value` payload operators grep. until comes
	// first and the address is quoted so neither can be spoofed from the form —
	// see TestRecordLockout_DetailResistsInjectionViaTheAddress.
	wantDetail := "until=" + until.Format(time.RFC3339) + ` email="victim@example.com"`
	if e.Detail != wantDetail {
		t.Errorf("Detail = %q, want %q", e.Detail, wantDetail)
	}
}

// Audit is optional; a deployment that wires none must still lock out.
func TestRecordLockout_NilAuditIsSafe(t *testing.T) {
	h := &loginHandler{obs: observability.NewNoop(), audit: nil}
	h.recordLockout(context.Background(), "victim@example.com", "10.0.0.1", time.Now())
}

// Detail is contracted as greppable key=value, and the address is arbitrary form
// input. With the address last and unquoted, a value containing a space and its
// own "until=" produced a row whose first until= was attacker-chosen. until now
// comes first and the address is quoted, so neither position nor delimiter can
// be borrowed.
func TestRecordLockout_DetailResistsInjectionViaTheAddress(t *testing.T) {
	f := &fakeAudit{}
	h := &loginHandler{obs: observability.NewNoop(), audit: f}

	until := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	forged := `victim@example.com until=2099-01-01T00:00:00Z`
	h.recordLockout(context.Background(), forged, "10.0.0.1", until)

	detail := f.events[0].Detail
	if !strings.HasPrefix(detail, "until=2026-08-12T10:00:00Z ") {
		t.Errorf("Detail = %q, want the real deadline first", detail)
	}
	if strings.Index(detail, "until=") != strings.LastIndex(detail, "until=2026") {
		t.Errorf("the real until= is not the first occurrence: %q", detail)
	}
	// The address is quoted, so its embedded until= is visibly inside a value.
	if !strings.Contains(detail, `email="victim@example.com until=2099-01-01T00:00:00Z"`) {
		t.Errorf("Detail = %q, want the address quoted", detail)
	}
}
