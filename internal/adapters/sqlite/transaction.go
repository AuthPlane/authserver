package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/authplane/authserver/internal/ports/output"
)

// txContextKey is the context key for an active *sql.Tx.
type txContextKey struct{}

// TransactionManager implements output.TransactionManager for SQLite.
type TransactionManager struct {
	db *sql.DB
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

	tx, err := tm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	txCtx := context.WithValue(ctx, txContextKey{}, tx)

	if err := fn(txCtx); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// txFromContext extracts the active *sql.Tx from ctx, or nil if none.
func txFromContext(ctx context.Context) *sql.Tx {
	tx, _ := ctx.Value(txContextKey{}).(*sql.Tx)
	return tx
}

// dbExecutor abstracts *sql.DB and *sql.Tx behind a common interface.
type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// dbOrTx returns the transaction from ctx if present, otherwise the raw *sql.DB.
func dbOrTx(ctx context.Context, db *sql.DB) dbExecutor {
	if tx := txFromContext(ctx); tx != nil {
		return tx
	}
	return db
}

// beginOrJoinTx returns an existing tx from ctx if present (joined=true),
// or starts a new one (joined=false). The caller must Commit/Rollback only
// when joined is false — joined transactions are managed by the outer scope.
func beginOrJoinTx(ctx context.Context, db *sql.DB) (tx *sql.Tx, joined bool, err error) {
	if existing := txFromContext(ctx); existing != nil {
		return existing, true, nil
	}
	tx, err = db.BeginTx(ctx, nil)
	return tx, false, err
}
