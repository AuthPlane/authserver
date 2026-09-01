//go:build integration_postgres

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

// Every production event is built by audit.NewEvent, which leaves CreatedAt
// zero. Replicas do not share a clock, and a pod running slow would otherwise
// write rows behind a cursor that has already read past them — lost forever to
// a watermark-driven reader. The database stamps the row.
func TestAuditStore_CreatedAtComesFromTheDatabase(t *testing.T) {
	store := testdata.SetupTestPGStores(t, pgContainerDSN).Audit
	ctx := context.Background()

	before := time.Now().UTC().Add(-time.Minute)

	e := audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "", "family=f1")
	e.ID = "db-stamped"
	if !e.CreatedAt.IsZero() {
		t.Fatal("NewEvent stamped CreatedAt; the caller's clock would reach the row")
	}

	if err := store.Record(ctx, &e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if e.CreatedAt.IsZero() {
		t.Fatal("store did not stamp created_at")
	}
	if e.CreatedAt.Before(before) || e.CreatedAt.After(time.Now().UTC().Add(time.Minute)) {
		t.Errorf("created_at = %v, want the database's current time", e.CreatedAt)
	}
}

// A caller that sets CreatedAt is overriding deliberately — backfill, import, a
// test placing an event at a chosen time. The store stores it as given.
func TestAuditStore_ExplicitCreatedAtIsHonored(t *testing.T) {
	store := testdata.SetupTestPGStores(t, pgContainerDSN).Audit
	ctx := context.Background()

	at := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond)
	e := audit.NewEvent(audit.ActionTokenIssued, "user-2", "client-2", "", "backfilled")
	e.ID = "explicit-override"
	e.CreatedAt = at

	if err := store.Record(ctx, &e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !e.CreatedAt.Equal(at) {
		t.Errorf("created_at written back as %v, want the caller's %v", e.CreatedAt, at)
	}

	got, err := store.Query(ctx, output.AuditFilter{ActorID: "user-2", Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if !got[0].CreatedAt.Equal(at) {
		t.Errorf("stored created_at = %v, want %v", got[0].CreatedAt, at)
	}
}

// Rows written in sequence must read back in that sequence — the property a
// watermark cursor depends on. With caller-stamped times and skewed pods, it did
// not hold.
func TestAuditStore_CreatedAtIsMonotonicAcrossWrites(t *testing.T) {
	store := testdata.SetupTestPGStores(t, pgContainerDSN).Audit
	ctx := context.Background()

	var stamps []time.Time
	for _, id := range []string{"m1", "m2", "m3"} {
		e := audit.NewEvent(audit.ActionTokenIssued, "user-3", "client-3", "", id)
		e.ID = id
		if err := store.Record(ctx, &e); err != nil {
			t.Fatalf("Record %s: %v", id, err)
		}
		stamps = append(stamps, e.CreatedAt)
	}

	for i := 1; i < len(stamps); i++ {
		if stamps[i].Before(stamps[i-1]) {
			t.Errorf("created_at went backwards between writes %d and %d (%v -> %v)",
				i-1, i, stamps[i-1], stamps[i])
		}
	}
}

// clock_timestamp(), not NOW(): NOW() is the transaction's start time, so every
// row written in one transaction would share a stamp and a cursor could not
// order them.
func TestAuditStore_StampsAdvanceWithinATransaction(t *testing.T) {
	stores := testdata.SetupTestPGStores(t, pgContainerDSN)
	ctx := context.Background()

	var first, second time.Time
	err := stores.TransactionMgr.WithTransaction(ctx, func(txCtx context.Context) error {
		a := audit.NewEvent(audit.ActionTokenIssued, "user-4", "client-4", "", "a")
		a.ID = "tx-a"
		if err := stores.Audit.Record(txCtx, &a); err != nil {
			return err
		}
		first = a.CreatedAt

		b := audit.NewEvent(audit.ActionTokenIssued, "user-4", "client-4", "", "b")
		b.ID = "tx-b"
		if err := stores.Audit.Record(txCtx, &b); err != nil {
			return err
		}
		second = b.CreatedAt
		return nil
	})
	if err != nil {
		t.Fatalf("WithTransaction: %v", err)
	}

	if !second.After(first) {
		t.Errorf("stamps did not advance inside a transaction (%v then %v); NOW() would freeze them", first, second)
	}
}
