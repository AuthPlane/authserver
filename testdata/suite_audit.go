package testdata

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/ports/output"
)

// RunAuditStoreTests runs the full AuditStore test suite.
// newStore is called once per subtest to provide a fresh, isolated store.
func RunAuditStoreTests(t *testing.T, newStore func(*testing.T) output.AuditStore) {
	t.Helper()

	t.Run("RecordAndQuery", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		e := &audit.Event{
			ID:        "evt-1",
			Action:    audit.ActionTokenIssued,
			ActorID:   "user-1",
			ClientID:  "client-1",
			IP:        "192.168.1.1",
			Detail:    "issued access token",
			CreatedAt: time.Now().UTC(),
		}

		if err := store.Record(ctx, e); err != nil {
			t.Fatalf("record: %v", err)
		}

		events, err := store.Query(ctx, output.AuditFilter{Limit: 10})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("got %d events, want 1", len(events))
		}
		if events[0].ID != "evt-1" {
			t.Errorf("got ID %q, want %q", events[0].ID, "evt-1")
		}
		if events[0].Action != audit.ActionTokenIssued {
			t.Errorf("got action %q, want %q", events[0].Action, audit.ActionTokenIssued)
		}
	})

	t.Run("QueryFilterAction", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		now := time.Now().UTC()
		events := []audit.Event{
			{ID: "evt-1", Action: audit.ActionTokenIssued, ActorID: "u1", CreatedAt: now},
			{ID: "evt-2", Action: audit.ActionUserLogin, ActorID: "u1", CreatedAt: now.Add(time.Second)},
			{ID: "evt-3", Action: audit.ActionTokenIssued, ActorID: "u2", CreatedAt: now.Add(2 * time.Second)},
		}
		for i := range events {
			if err := store.Record(ctx, &events[i]); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}

		got, err := store.Query(ctx, output.AuditFilter{
			Action: string(audit.ActionTokenIssued),
			Limit:  10,
		})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d events, want 2", len(got))
		}
	})

	t.Run("QueryFilterActorID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		now := time.Now().UTC()
		for i, actor := range []string{"u1", "u1", "u2"} {
			e := &audit.Event{
				ID:        fmt.Sprintf("evt-%d", i),
				Action:    audit.ActionUserLogin,
				ActorID:   actor,
				CreatedAt: now.Add(time.Duration(i) * time.Second),
			}
			if err := store.Record(ctx, e); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}

		got, err := store.Query(ctx, output.AuditFilter{ActorID: "u1", Limit: 10})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d events, want 2", len(got))
		}
	})

	t.Run("QueryTimeRange", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		base := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 5; i++ {
			e := &audit.Event{
				ID:        fmt.Sprintf("evt-%d", i),
				Action:    audit.ActionTokenIssued,
				ActorID:   "u1",
				CreatedAt: base.Add(time.Duration(i) * 24 * time.Hour),
			}
			if err := store.Record(ctx, e); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}

		got, err := store.Query(ctx, output.AuditFilter{
			SinceUnix: base.Add(24 * time.Hour).Unix(),
			UntilUnix: base.Add(3 * 24 * time.Hour).Unix(),
			Limit:     10,
		})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d events, want 3 (days 1,2,3)", len(got))
		}
	})

	t.Run("QueryPagination", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		now := time.Now().UTC()
		for i := 0; i < 10; i++ {
			e := &audit.Event{
				ID:        fmt.Sprintf("evt-%02d", i),
				Action:    audit.ActionTokenIssued,
				ActorID:   "u1",
				CreatedAt: now.Add(time.Duration(i) * time.Second),
			}
			if err := store.Record(ctx, e); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}

		page1, err := store.Query(ctx, output.AuditFilter{Limit: 3, Offset: 0})
		if err != nil {
			t.Fatalf("query page 1: %v", err)
		}
		if len(page1) != 3 {
			t.Fatalf("page 1: got %d, want 3", len(page1))
		}

		page2, err := store.Query(ctx, output.AuditFilter{Limit: 3, Offset: 3})
		if err != nil {
			t.Fatalf("query page 2: %v", err)
		}
		if len(page2) != 3 {
			t.Fatalf("page 2: got %d, want 3", len(page2))
		}
		if page1[0].ID == page2[0].ID {
			t.Error("page 1 and 2 overlap")
		}
	})

	// QueryFilterClientID verifies compliance matrix gap 15.14: audit query filtered by client_id.
	t.Run("QueryFilterClientID", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		now := time.Now().UTC()
		for i, cid := range []string{"cli-a", "cli-a", "cli-b"} {
			e := &audit.Event{
				ID:        fmt.Sprintf("evt-%d", i),
				Action:    audit.ActionTokenIssued,
				ClientID:  cid,
				CreatedAt: now.Add(time.Duration(i) * time.Second),
			}
			if err := store.Record(ctx, e); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}

		got, err := store.Query(ctx, output.AuditFilter{ClientID: "cli-a", Limit: 10})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d events for cli-a, want 2", len(got))
		}
	})
}
