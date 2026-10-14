//go:build integration_postgres

package postgres_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/authplane/authserver/internal/adapters/aesmaster"
	pgadapter "github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/testdata"
)

// noopKeyCacheInvalidator satisfies the listener's cache-invalidation seam.
// These tests exercise NOTIFY delivery + reload, not cache state, so a no-op
// is sufficient (the decorator's invalidation is unit-tested separately).
type noopKeyCacheInvalidator struct{}

func (noopKeyCacheInvalidator) InvalidateCache(context.Context) error { return nil }

// testDBDSN extracts a connection string for the test database from a pool.
// LISTEN/NOTIFY in PostgreSQL is database-scoped, so the listener must connect
// to the same database where the trigger fires.
func testDBDSN(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	cc := pool.Config().ConnConfig
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cc.User, cc.Password, cc.Host, cc.Port, cc.Database)
}

func TestKeyStoreListener_ReceivesNotification(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	obs := observability.NewNoop()

	enc, err := aesmaster.New(testMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)

	// Track reload calls.
	var reloadCount atomic.Int32
	reloadFn := func(ctx context.Context) error {
		reloadCount.Add(1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// LISTEN/NOTIFY is database-scoped — use the test DB's DSN, not the container base.
	dsn := testDBDSN(t, db.Pool)

	listener := pgadapter.NewKeyStoreListener(dsn, noopKeyCacheInvalidator{}, reloadFn, obs)

	// Start listener in background.
	listenerDone := make(chan error, 1)
	go func() {
		listenerDone <- listener.Run(ctx)
	}()

	// Wait for the listener to connect: it reloads once right after LISTEN.
	waitForCount(t, &reloadCount, 1)
	base := reloadCount.Load()

	// Save a key — this triggers a NOTIFY via the database trigger.
	k := newHATestSigningKey(t, "kid-listener-test")
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save key: %v", err)
	}

	// Wait for the notification to propagate (should be <100ms).
	deadline := time.After(5 * time.Second)
	for reloadCount.Load() == base {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for listener reload callback")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	if got := reloadCount.Load(); got <= base {
		t.Errorf("expected a reload after the notification, got %d (baseline %d)", got, base)
	}

	// Cancel and verify clean shutdown.
	cancel()
	select {
	case err := <-listenerDone:
		if err != nil && err != context.Canceled {
			t.Errorf("unexpected listener error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("listener did not shut down within 5 seconds")
	}
}

func TestKeyStoreListener_MultipleNotifications(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	obs := observability.NewNoop()

	enc, err := aesmaster.New(testMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)

	var reloadCount atomic.Int32
	reloadFn := func(ctx context.Context) error {
		reloadCount.Add(1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dsn := testDBDSN(t, db.Pool)
	listener := pgadapter.NewKeyStoreListener(dsn, noopKeyCacheInvalidator{}, reloadFn, obs)

	go func() {
		_ = listener.Run(ctx)
	}()

	// Wait for the listener to connect: it reloads once right after LISTEN.
	waitForCount(t, &reloadCount, 1)
	base := reloadCount.Load()

	// Save multiple keys — each triggers a notification.
	for i, kid := range []string{"kid-multi-1", "kid-multi-2", "kid-multi-3"} {
		k := newHATestSigningKey(t, kid)
		if err := store.Save(ctx, k); err != nil {
			t.Fatalf("save key %d: %v", i, err)
		}
		// Small delay to avoid notification coalescing.
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for all notifications to propagate.
	deadline := time.After(5 * time.Second)
	for reloadCount.Load() < base+3 {
		select {
		case <-deadline:
			t.Fatalf("timeout: expected at least 3 reload calls after connecting, got %d", reloadCount.Load()-base)
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	if got := reloadCount.Load() - base; got < 3 {
		t.Errorf("expected at least 3 reload calls after connecting, got %d", got)
	}

	cancel()
}

func TestKeyStoreListener_NotifyTriggersReload_Within500ms(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	obs := observability.NewNoop()

	enc, err := aesmaster.New(testMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)

	// Track reload timing.
	reloadCh := make(chan time.Duration, 1)
	reloadFn := func(ctx context.Context) error {
		// Non-blocking send — captures first reload only.
		select {
		case reloadCh <- time.Since(time.Now()):
		default:
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dsn := testDBDSN(t, db.Pool)
	listener := pgadapter.NewKeyStoreListener(dsn, noopKeyCacheInvalidator{}, reloadFn, obs)

	go func() {
		_ = listener.Run(ctx)
	}()

	// Give the listener time to connect and issue LISTEN.
	time.Sleep(500 * time.Millisecond)

	// Measure: time from Save (which triggers NOTIFY) to reload callback.
	saveStart := time.Now()

	// Override reloadFn to capture delay from saveStart.
	reloadCh = make(chan time.Duration, 1)
	reloadTimingFn := func(ctx context.Context) error {
		delay := time.Since(saveStart)
		select {
		case reloadCh <- delay:
		default:
		}
		return nil
	}
	// We need a fresh listener to use the timing function.
	cancel()
	time.Sleep(100 * time.Millisecond)

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	listener2 := pgadapter.NewKeyStoreListener(dsn, noopKeyCacheInvalidator{}, reloadTimingFn, obs)
	go func() {
		_ = listener2.Run(ctx2)
	}()
	time.Sleep(500 * time.Millisecond)
	// Discard the reload the listener does right after LISTEN.
	select {
	case <-reloadCh:
	default:
	}

	saveStart = time.Now()
	k := newHATestSigningKey(t, "kid-timing-test")
	if err := store.Save(ctx2, k); err != nil {
		t.Fatalf("save key: %v", err)
	}

	select {
	case delay := <-reloadCh:
		t.Logf("NOTIFY → reload delay: %v", delay)
		if delay > 500*time.Millisecond {
			t.Errorf("reload delay %v exceeds 500ms threshold", delay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for reload callback")
	}

	cancel2()
}

// waitForCount waits until c reaches at least n.
func waitForCount(t *testing.T, c *atomic.Int32, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: count %d, want at least %d", c.Load(), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type countingInvalidator struct{ n atomic.Int32 }

func (c *countingInvalidator) InvalidateCache(context.Context) error {
	c.n.Add(1)
	return nil
}

// A rotation committed while the listener's connection is down sends a
// notification nobody hears. On reconnecting, the listener invalidates the
// cached key and reloads anyway, so the rotation is picked up.
func TestKeyStoreListener_ReloadsAfterReconnect(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	obs := observability.NewNoop()
	enc, err := aesmaster.New(testMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)

	var reloads atomic.Int32
	inv := &countingInvalidator{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener := pgadapter.NewKeyStoreListener(testDBDSN(t, db.Pool), inv, func(context.Context) error {
		reloads.Add(1)
		return nil
	}, obs)
	go func() { _ = listener.Run(ctx) }()
	waitForCount(t, &reloads, 1)

	// Cut the listener's connection, then rotate before it can reconnect
	// (the first reconnect waits a second).
	var dbName string
	if err := db.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatalf("current database: %v", err)
	}
	tag, err := db.Pool.Exec(ctx,
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		  WHERE datname = $1 AND query ILIKE 'LISTEN%' AND pid <> pg_backend_pid()`, dbName)
	if err != nil {
		t.Fatalf("terminate listener connection: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("terminated %d listener connections, want 1", tag.RowsAffected())
	}
	before, invBefore := reloads.Load(), inv.n.Load()
	if err := store.Save(ctx, newHATestSigningKey(t, "kid-during-outage")); err != nil {
		t.Fatalf("save during the outage: %v", err)
	}

	waitForCount(t, &reloads, before+1)
	if inv.n.Load() <= invBefore {
		t.Error("the listener reloaded after reconnecting without invalidating the cached key")
	}
}
