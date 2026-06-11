//go:build integration

package services_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

func TestAudit_RecordAndQuery(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	svc := services.NewAuditService(stores.Audit, obs)

	ctx := context.Background()

	// Record two events.
	svc.Record(ctx, audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "127.0.0.1", "test detail"))
	svc.Record(ctx, audit.NewEvent(audit.ActionUserLogin, "user-2", "", "192.168.1.1", ""))

	// Query all.
	events, err := svc.Query(ctx, output.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestAudit_QueryWithFilter(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	svc := services.NewAuditService(stores.Audit, obs)

	ctx := context.Background()

	svc.Record(ctx, audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "", ""))
	svc.Record(ctx, audit.NewEvent(audit.ActionUserLogin, "user-1", "", "", ""))
	svc.Record(ctx, audit.NewEvent(audit.ActionTokenRevoked, "user-2", "client-2", "", ""))

	// Filter by action.
	events, err := svc.Query(ctx, output.AuditFilter{Action: "token.issued", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 token.issued event, got %d", len(events))
	}
	if events[0].ActorID != "user-1" {
		t.Errorf("actor_id: got %q", events[0].ActorID)
	}
}
