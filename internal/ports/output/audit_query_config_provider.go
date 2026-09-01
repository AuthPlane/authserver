package output

import (
	"context"
	"time"
)

// AuditQueryConfig bounds how far back the admin audit feed may be read.
//
// It is a lookback bound and nothing more. The server does not know why the
// bound is what it is — a deployment may derive it from an operator setting, or
// a substitute provider may derive it per request — and it must never learn.
type AuditQueryConfig struct {
	// DefaultLookback is applied when the caller omits ?since=. Zero means the
	// package default.
	DefaultLookback time.Duration

	// MaxLookback is the furthest back a caller may ask. A request beyond it is
	// rejected rather than silently narrowed, so a client is never handed a
	// short answer to a long question. Zero means the package default, not
	// unbounded: a default-constructed config must never widen the scan. A
	// deployment that wants a wider window says so with an explicit value.
	MaxLookback time.Duration
}

// AuditQueryConfigProvider supplies the audit-feed lookback bound for a request.
type AuditQueryConfigProvider interface {
	Config(ctx context.Context) (AuditQueryConfig, error)
}
