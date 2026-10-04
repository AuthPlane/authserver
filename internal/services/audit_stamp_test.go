package services

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

type capturingAuditStore struct{ events []audit.Event }

func (c *capturingAuditStore) Record(_ context.Context, e *audit.Event) error {
	c.events = append(c.events, *e)
	return nil
}

func (c *capturingAuditStore) Query(context.Context, output.AuditFilter) ([]audit.Event, error) {
	return nil, nil
}

func TestAuditStamp_ClientIP(t *testing.T) {
	withIP := observability.WithClientIP(context.Background(), "203.0.113.7")

	cases := []struct {
		name   string
		ctx    context.Context
		event  audit.Event
		wantIP string
	}{
		{
			name:   "ctx ip fills an empty field",
			ctx:    withIP,
			event:  audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "", ""),
			wantIP: "203.0.113.7",
		},
		{
			name:   "no ctx ip leaves the field empty",
			ctx:    context.Background(),
			event:  audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "", ""),
			wantIP: "",
		},
		{
			name:   "an ip the emit site set wins",
			ctx:    withIP,
			event:  audit.NewEvent(audit.ActionAuthLockedOut, "user-1", "", "198.51.100.9", ""),
			wantIP: "198.51.100.9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &capturingAuditStore{}
			svc := NewAuditService(store, observability.NewNoop())

			svc.Record(tc.ctx, tc.event)

			if len(store.events) != 1 {
				t.Fatalf("recorded %d events, want 1", len(store.events))
			}
			if got := store.events[0].IP; got != tc.wantIP {
				t.Fatalf("IP = %q, want %q", got, tc.wantIP)
			}
		})
	}
}
