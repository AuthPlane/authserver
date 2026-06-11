package output

import "context"

// TransactionManager provides database transaction support for multi-step
// operations that must be atomic. Implementations wrap the underlying
// database transaction mechanism (sql.Tx for SQLite, pgx.Tx for PostgreSQL).
//
// The context passed to fn carries the transaction; adapters that need to
// participate in the transaction extract it from the context.
type TransactionManager interface {
	// WithTransaction executes fn within a database transaction.
	// If fn returns nil the transaction is committed; otherwise it is rolled back.
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}
