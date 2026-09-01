package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/audit"
)

// AuditStore persists security audit events.
type AuditStore interface {
	// Record stores an audit event.
	//
	// The store owns e.CreatedAt and writes back the value it stored: the
	// authoritative clock is the store's, not the caller's. With many replicas
	// against one database, a caller's clock can run behind a cursor that has
	// already read past it, and the row would never be seen again.
	//
	// Record is best-effort by contract: callers treat a failure as the
	// server's bug to surface loudly (see AuditService.Record), never as a
	// reason to fail the request the event describes. For the same reason,
	// call Record outside your transaction. It mechanically joins one carried
	// by ctx, but co-committing an audit row with the state change it
	// describes lets an audit-side failure abort that state change — the
	// inversion the best-effort contract exists to prevent.
	Record(ctx context.Context, e *audit.Event) error

	// Query returns audit events matching the filter.
	Query(ctx context.Context, filter AuditFilter) ([]audit.Event, error)
}

// AuditFilter constrains audit event queries.
type AuditFilter struct {
	Action    string
	ActorID   string
	ClientID  string
	SinceUnix int64 // 0 = no lower bound
	UntilUnix int64 // 0 = no upper bound
	Limit     int
	Offset    int
}
