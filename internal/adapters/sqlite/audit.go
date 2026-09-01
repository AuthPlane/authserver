package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// AuditStore implements output.AuditStore using SQLite.
type AuditStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.AuditStore = (*AuditStore)(nil)

const auditColumns = `id, action, actor_id, client_id, ip, detail, trace_id, created_at`

func scanAuditEvent(row interface{ Scan(...any) error }) (*audit.Event, error) {
	var e audit.Event
	var createdAt string
	if err := row.Scan(&e.ID, &e.Action, &e.ActorID, &e.ClientID, &e.IP, &e.Detail, &e.TraceID, &createdAt); err != nil {
		return nil, err
	}
	var err error
	e.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	return &e, nil
}

// Record implements output.AuditStore.
//
// The store owns created_at (see the port), unless the caller set it — an
// explicit override for backfill, import, and tests.
//
// SQLite is embedded and single-writer, so the process clock IS the store's
// clock: there is no second writer to disagree with, and strftime('now') would
// buy nothing while costing sub-millisecond precision.
func (s *AuditStore) Record(ctx context.Context, e *audit.Event) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.AuditRecord")
	defer span.End()

	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	start := time.Now()
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO audit_events (`+auditColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Action, e.ActorID, e.ClientID, e.IP, e.Detail, e.TraceID, formatTime(e.CreatedAt),
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("audit_record"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// Query implements output.AuditStore.
func (s *AuditStore) Query(ctx context.Context, filter output.AuditFilter) ([]audit.Event, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.AuditQuery")
	defer span.End()

	var where []string
	var args []any

	if filter.Action != "" {
		where = append(where, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, filter.ActorID)
	}
	if filter.ClientID != "" {
		where = append(where, "client_id = ?")
		args = append(args, filter.ClientID)
	}
	if filter.SinceUnix > 0 {
		where = append(where, "created_at >= ?")
		args = append(args, formatTime(unixToTime(filter.SinceUnix)))
	}
	if filter.UntilUnix > 0 {
		where = append(where, "created_at <= ?")
		args = append(args, formatTime(unixToTime(filter.UntilUnix)))
	}

	query := `SELECT ` + auditColumns + ` FROM audit_events` //nolint:gosec // query built from internal column constants, not user input
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ") //nolint:gosec // internal filter columns
	}
	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	start := time.Now()
	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx, query, args...)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("audit_query"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []audit.Event
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, *e)
	}
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("audit_query"))
	return events, rows.Err()
}

func unixToTime(unix int64) time.Time {
	return time.Unix(unix, 0).UTC()
}
