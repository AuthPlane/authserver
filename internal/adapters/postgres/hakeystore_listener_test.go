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

	listener := pgadapter.NewKeyStoreListener(dsn, store, reloadFn, obs)

	// Start listener in background.
	listenerDone := make(chan error, 1)
	go func() {
		listenerDone <- listener.Run(ctx)
	}()

	// Give the listener time to connect and issue LISTEN.
	time.Sleep(500 * time.Millisecond)

	// Save a key — this triggers a NOTIFY via the database trigger.
	k := newHATestSigningKey(t, "kid-listener-test")
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save key: %v", err)
	}

	// Wait for the notification to propagate (should be <100ms).
	deadline := time.After(5 * time.Second)
	for reloadCount.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for listener reload callback")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	got := reloadCount.Load()
	if got < 1 {
		t.Errorf("expected at least 1 reload call, got %d", got)
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
	listener := pgadapter.NewKeyStoreListener(dsn, store, reloadFn, obs)

	go func() {
		_ = listener.Run(ctx)
	}()

	// Give the listener time to connect.
	time.Sleep(500 * time.Millisecond)

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
	for reloadCount.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("timeout: expected at least 3 reload calls, got %d", reloadCount.Load())
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	got := reloadCount.Load()
	if got < 3 {
		t.Errorf("expected at least 3 reload calls, got %d", got)
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
	listener := pgadapter.NewKeyStoreListener(dsn, store, reloadFn, obs)

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
	listener2 := pgadapter.NewKeyStoreListener(dsn, store, reloadTimingFn, obs)
	go func() {
		_ = listener2.Run(ctx2)
	}()
	time.Sleep(500 * time.Millisecond)

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
