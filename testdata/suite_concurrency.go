package testdata

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

// RunClientOptimisticLockTests runs concurrency tests for client optimistic locking.
func RunClientOptimisticLockTests(t *testing.T, newStore func(*testing.T) output.ClientStore) {
	t.Helper()

	t.Run("Create_SetsVersion1", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("version-init")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByID(ctx, "version-init")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Version != 1 {
			t.Errorf("version: got %d, want 1", got.Version)
		}
	})

	t.Run("Update_IncrementsVersion", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("version-incr")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		// First update: version 1 → 2.
		c.Name = "Updated v2"
		c.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, c); err != nil {
			t.Fatalf("update 1: %v", err)
		}

		got, err := store.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("get after update 1: %v", err)
		}
		if got.Version != 2 {
			t.Errorf("version after update 1: got %d, want 2", got.Version)
		}

		// Second update using fetched version: version 2 → 3.
		got.Name = "Updated v3"
		got.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, got); err != nil {
			t.Fatalf("update 2: %v", err)
		}

		got2, err := store.GetByID(ctx, c.ID)
		if err != nil {
			t.Fatalf("get after update 2: %v", err)
		}
		if got2.Version != 3 {
			t.Errorf("version after update 2: got %d, want 3", got2.Version)
		}
	})

	t.Run("Update_StaleVersion_ReturnsConflict", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("version-stale")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Fetch two copies at version 1.
		copy1, _ := store.GetByID(ctx, c.ID)
		copy2, _ := store.GetByID(ctx, c.ID)

		// Update copy1 → succeeds, version becomes 2.
		copy1.Name = "Winner"
		copy1.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, copy1); err != nil {
			t.Fatalf("update copy1: %v", err)
		}

		// Update copy2 with stale version=1 → should conflict.
		copy2.Name = "Loser"
		copy2.UpdatedAt = time.Now().UTC()
		err := store.Update(ctx, copy2)
		if !errors.Is(err, domain.ErrClientConflict) {
			t.Errorf("expected ErrClientConflict, got %v", err)
		}

		// Verify winner's data persists.
		got, _ := store.GetByID(ctx, c.ID)
		if got.Name != "Winner" {
			t.Errorf("name: got %q, want %q", got.Name, "Winner")
		}
	})

	t.Run("ConcurrentUpdate_ExactlyOneWins", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		c := newTestClient("version-race")
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		const goroutines = 5
		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				// All goroutines use the same stale version=1 copy.
				stale := *c
				stale.Name = "Racer"
				stale.UpdatedAt = time.Now().UTC()
				err := store.Update(ctx, &stale)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}(i)
		}
		wg.Wait()

		var successes, conflicts int
		for _, err := range errs {
			if err == nil {
				successes++
			} else if errors.Is(err, domain.ErrClientConflict) {
				conflicts++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}
		if successes != 1 {
			t.Errorf("success count: got %d, want 1", successes)
		}
		if conflicts != goroutines-1 {
			t.Errorf("conflict count: got %d, want %d", conflicts, goroutines-1)
		}
	})
}

// RunUserOptimisticLockTests runs concurrency tests for user optimistic locking.
func RunUserOptimisticLockTests(t *testing.T, newStore func(*testing.T) output.UserStore) {
	t.Helper()

	t.Run("Create_SetsVersion1", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("uv-init", "version-init@test.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := store.GetByID(ctx, "uv-init")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Version != 1 {
			t.Errorf("version: got %d, want 1", got.Version)
		}
	})

	t.Run("Update_IncrementsVersion", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("uv-incr", "version-incr@test.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		u.Name = "Updated v2"
		u.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, u); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := store.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Version != 2 {
			t.Errorf("version after update: got %d, want 2", got.Version)
		}
	})

	t.Run("Update_StaleVersion_ReturnsConflict", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("uv-stale", "version-stale@test.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		copy1, _ := store.GetByID(ctx, u.ID)
		copy2, _ := store.GetByID(ctx, u.ID)

		copy1.Name = "Winner"
		copy1.UpdatedAt = time.Now().UTC()
		if err := store.Update(ctx, copy1); err != nil {
			t.Fatalf("update copy1: %v", err)
		}

		copy2.Name = "Loser"
		copy2.UpdatedAt = time.Now().UTC()
		err := store.Update(ctx, copy2)
		if !errors.Is(err, domain.ErrUserConflict) {
			t.Errorf("expected ErrUserConflict, got %v", err)
		}

		got, _ := store.GetByID(ctx, u.ID)
		if got.Name != "Winner" {
			t.Errorf("name: got %q, want %q", got.Name, "Winner")
		}
	})

	t.Run("ConcurrentUpdate_ExactlyOneWins", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		u := newTestUser("uv-race", "version-race@test.com")
		if err := store.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		const goroutines = 5
		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stale := *u
				stale.Name = "Racer"
				stale.UpdatedAt = time.Now().UTC()
				err := store.Update(ctx, &stale)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}()
		}
		wg.Wait()

		var successes, conflicts int
		for _, err := range errs {
			if err == nil {
				successes++
			} else if errors.Is(err, domain.ErrUserConflict) {
				conflicts++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}
		if successes != 1 {
			t.Errorf("success count: got %d, want 1", successes)
		}
		if conflicts != goroutines-1 {
			t.Errorf("conflict count: got %d, want %d", conflicts, goroutines-1)
		}
	})
}

// TransactionStores groups stores needed for transaction tests.
type TransactionStores struct {
	Client      output.ClientStore
	User        output.UserStore
	Transaction output.TransactionManager
}

// RunTransactionManagerTests runs the shared TransactionManager test suite.
func RunTransactionManagerTests(t *testing.T, newStores func(*testing.T) TransactionStores) {
	t.Helper()

	t.Run("Commit_PersistsData", func(t *testing.T) {
		s := newStores(t)
		ctx := context.Background()

		err := s.Transaction.WithTransaction(ctx, func(txCtx context.Context) error {
			c := newTestClient("tx-commit")
			return s.Client.Create(txCtx, c)
		})
		if err != nil {
			t.Fatalf("tx: %v", err)
		}

		// Verify data persisted after commit.
		got, err := s.Client.GetByID(ctx, "tx-commit")
		if err != nil {
			t.Fatalf("get after tx: %v", err)
		}
		if got.ID != "tx-commit" {
			t.Errorf("id: got %q, want %q", got.ID, "tx-commit")
		}
	})

	t.Run("Rollback_OnError", func(t *testing.T) {
		s := newStores(t)
		ctx := context.Background()

		err := s.Transaction.WithTransaction(ctx, func(txCtx context.Context) error {
			c := newTestClient("tx-rollback")
			if err := s.Client.Create(txCtx, c); err != nil {
				return err
			}
			// Return error to trigger rollback.
			return errors.New("deliberate failure")
		})
		if err == nil {
			t.Fatal("expected error from transaction")
		}

		// Verify data was rolled back.
		_, err = s.Client.GetByID(ctx, "tx-rollback")
		if !errors.Is(err, domain.ErrInvalidClient) {
			t.Errorf("expected ErrInvalidClient after rollback, got %v", err)
		}
	})

	t.Run("NestedTransaction_ReusesOuter", func(t *testing.T) {
		s := newStores(t)
		ctx := context.Background()

		err := s.Transaction.WithTransaction(ctx, func(txCtx context.Context) error {
			c := newTestClient("tx-outer")
			if err := s.Client.Create(txCtx, c); err != nil {
				return err
			}

			// Nested transaction should reuse the outer one.
			return s.Transaction.WithTransaction(txCtx, func(innerCtx context.Context) error {
				u := newTestUser("tx-inner", "inner@test.com")
				return s.User.Create(innerCtx, u)
			})
		})
		if err != nil {
			t.Fatalf("nested tx: %v", err)
		}

		// Both records should exist.
		if _, err := s.Client.GetByID(ctx, "tx-outer"); err != nil {
			t.Errorf("outer client not found: %v", err)
		}
		if _, err := s.User.GetByID(ctx, "tx-inner"); err != nil {
			t.Errorf("inner user not found: %v", err)
		}
	})

	t.Run("NestedTransaction_InnerError_RollsBackAll", func(t *testing.T) {
		s := newStores(t)
		ctx := context.Background()

		err := s.Transaction.WithTransaction(ctx, func(txCtx context.Context) error {
			c := newTestClient("tx-nest-fail")
			if err := s.Client.Create(txCtx, c); err != nil {
				return err
			}

			// Inner returns error, which propagates and rolls back the outer tx.
			return s.Transaction.WithTransaction(txCtx, func(innerCtx context.Context) error {
				return errors.New("inner failure")
			})
		})
		if err == nil {
			t.Fatal("expected error")
		}

		// Outer client should be rolled back.
		_, err = s.Client.GetByID(ctx, "tx-nest-fail")
		if !errors.Is(err, domain.ErrInvalidClient) {
			t.Errorf("expected ErrInvalidClient after nested rollback, got %v", err)
		}
	})

	t.Run("MultipleOperations_Atomic", func(t *testing.T) {
		s := newStores(t)
		ctx := context.Background()

		// Create a client first (outside tx).
		c := newTestClient("tx-multi")
		if err := s.Client.Create(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Atomically create user + update client.
		err := s.Transaction.WithTransaction(ctx, func(txCtx context.Context) error {
			u := newTestUser("tx-multi-user", "multi@test.com")
			if err := s.User.Create(txCtx, u); err != nil {
				return err
			}

			fetched, err := s.Client.GetByID(txCtx, "tx-multi")
			if err != nil {
				return err
			}
			fetched.Name = "Atomically Updated"
			fetched.UpdatedAt = time.Now().UTC()
			return s.Client.Update(txCtx, fetched)
		})
		if err != nil {
			t.Fatalf("atomic tx: %v", err)
		}

		got, _ := s.Client.GetByID(ctx, "tx-multi")
		if got.Name != "Atomically Updated" {
			t.Errorf("name: got %q, want %q", got.Name, "Atomically Updated")
		}
		if _, err := s.User.GetByID(ctx, "tx-multi-user"); err != nil {
			t.Errorf("user not found: %v", err)
		}
	})
}

// Unused import guard.
var (
	_ = client.StatusActive
	_ = user.RoleUser
)
