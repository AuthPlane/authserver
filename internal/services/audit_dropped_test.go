package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

type failingAuditStore struct{ err error }

func (f failingAuditStore) Record(context.Context, *audit.Event) error { return f.err }

func (f failingAuditStore) Query(context.Context, output.AuditFilter) ([]audit.Event, error) {
	return nil, nil
}

// newCapturedAuditService wires an AuditService whose store always fails, with a
// logger writing JSON into buf.
func newCapturedAuditService(buf *bytes.Buffer) *AuditService {
	obs := observability.NewNoop()
	obs.Logger = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewAuditService(failingAuditStore{err: errors.New("relation audit_events does not exist")}, obs)
}

// Recording is our concern, not the caller's. A store failure must not surface
// as a panic or an error — there is no error to return.
func TestAuditRecord_StoreFailureNeverFailsTheCaller(t *testing.T) {
	var buf bytes.Buffer
	svc := newCapturedAuditService(&buf)

	svc.Record(context.Background(), audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "1.2.3.4", "family=f1"))

	if !strings.Contains(buf.String(), auditDroppedMessage) {
		t.Fatalf("a dropped event was not reported; log = %s", buf.String())
	}
}

// The log line is the record's last resort, so it has to carry the whole event.
// Anything omitted here is unrecoverable.
func TestAuditRecord_DroppedEventIsLoggedInFull(t *testing.T) {
	var buf bytes.Buffer
	svc := newCapturedAuditService(&buf)

	svc.Record(context.Background(), audit.NewEvent(
		audit.ActionTokenIssued, "user-1", "client-1", "1.2.3.4", "family=f1",
	))

	var entry map[string]any
	line := strings.TrimSpace(buf.String())
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, line)
	}

	for field, want := range map[string]string{
		"action":    string(audit.ActionTokenIssued),
		"actor_id":  "user-1",
		"client_id": "client-1",
		"ip":        "1.2.3.4",
		"detail":    "family=f1",
	} {
		if got, _ := entry[field].(string); got != want {
			t.Errorf("dropped-event log %s = %q, want %q", field, got, want)
		}
	}
	for _, field := range []string{"id", "observed_at", "error"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("dropped-event log is missing %q — the event cannot be replayed without it", field)
		}
	}
	if entry["level"] != "ERROR" {
		t.Errorf("dropped-event log level = %v, want ERROR (this pages)", entry["level"])
	}
}

// An explicit-override event (backfill, import, replay) carries its own
// created_at. If it is dropped, the loss log must record the time the event
// claims, not the time we failed to write it — otherwise a replayed backfill row
// lands at the wrong moment.
func TestAuditRecord_DroppedEventHonorsExplicitCreatedAt(t *testing.T) {
	var buf bytes.Buffer
	svc := newCapturedAuditService(&buf)

	e := audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "1.2.3.4", "family=f1")
	e.CreatedAt = time.Date(2021, 6, 1, 12, 0, 0, 0, time.UTC)

	svc.Record(context.Background(), e)

	var entry map[string]any
	line := strings.TrimSpace(buf.String())
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, line)
	}
	if got, _ := entry["observed_at"].(string); got != e.CreatedAt.Format(time.RFC3339Nano) {
		t.Errorf("dropped-event observed_at = %q, want the event's own created_at %q",
			got, e.CreatedAt.Format(time.RFC3339Nano))
	}
}

// A successful record must not look like a loss.
func TestAuditRecord_SuccessDoesNotReportADrop(t *testing.T) {
	var buf bytes.Buffer
	obs := observability.NewNoop()
	obs.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	svc := NewAuditService(failingAuditStore{err: nil}, obs)

	svc.Record(context.Background(), audit.NewEvent(audit.ActionTokenIssued, "u", "c", "", ""))

	if strings.Contains(buf.String(), auditDroppedMessage) {
		t.Errorf("a successful record reported a drop; log = %s", buf.String())
	}
}
