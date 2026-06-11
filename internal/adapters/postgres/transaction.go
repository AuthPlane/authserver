package postgres

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/authplane/authserver/internal/ports/output"
)

// txContextKey is the context key for an active pgx.Tx.
type txContextKey struct{}

// TransactionManager implements output.TransactionManager for PostgreSQL.
type TransactionManager struct {
	pool *pgxpool.Pool
}

var _ output.TransactionManager = (*TransactionManager)(nil)

// WithTransaction executes fn within a database transaction.
// If fn returns nil the transaction is committed; otherwise it is rolled back.
// Nested calls reuse the existing transaction (no savepoints).
func (tm *TransactionManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	// If already inside a transaction, just run fn — no nesting.
	if ctx.Value(txContextKey{}) != nil {
		return fn(ctx)
	}

	tx, err := tm.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	txCtx := context.WithValue(ctx, txContextKey{}, tx)

	if err := fn(txCtx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			slog.ErrorContext(ctx, "transaction rollback failed", "error", rbErr)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// txFromContext extracts the active pgx.Tx from ctx, or nil if none.
func txFromContext(ctx context.Context) pgx.Tx {
	tx, _ := ctx.Value(txContextKey{}).(pgx.Tx)
	return tx
}

// dbExecutor abstracts *pgxpool.Pool and pgx.Tx behind a common interface.
type dbExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// dbOrTx returns the transaction from ctx if present, otherwise the raw *pgxpool.Pool.
func dbOrTx(ctx context.Context, pool *pgxpool.Pool) dbExecutor {
	if tx := txFromContext(ctx); tx != nil {
		return tx
	}
	return pool
}

// beginOrJoinTx returns an existing tx from ctx if present (joined=true),
// or starts a new one (joined=false). The caller must Commit/Rollback only
// when joined is false — joined transactions are managed by the outer scope.
func beginOrJoinTx(ctx context.Context, pool *pgxpool.Pool) (tx pgx.Tx, joined bool, err error) {
	if existing := txFromContext(ctx); existing != nil {
		return existing, true, nil
	}
	tx, err = pool.Begin(ctx)
	return tx, false, err
}
