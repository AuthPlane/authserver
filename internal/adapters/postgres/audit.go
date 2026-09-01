package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// AuditStore implements output.AuditStore using PostgreSQL.
// Append-only writes. Query supports client_id filter (closes compliance gap 15.14).
type AuditStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.AuditStore = (*AuditStore)(nil)

const auditColumns = `id, action, actor_id, client_id, ip, detail, trace_id, created_at`

func scanAuditEvent(row interface{ Scan(...any) error }) (*audit.Event, error) {
	var e audit.Event
	if err := row.Scan(&e.ID, &e.Action, &e.ActorID, &e.ClientID, &e.IP, &e.Detail, &e.TraceID, &e.CreatedAt); err != nil {
		return nil, err
	}
	e.CreatedAt = toUTC(e.CreatedAt)
	return &e, nil
}

// Record implements output.AuditStore.
//
// created_at comes from the database, not the caller. Replicas do not share a
// clock: a pod running slow would stamp a row behind a cursor that has already
// read past it, and a watermark-driven reader would skip that row forever.
// clock_timestamp() (not NOW(), which is the transaction's start time) puts
// every row on the one clock the writers agree on, at the moment it is written.
//
// A caller that sets e.CreatedAt is overriding this deliberately — backfill,
// import, a test placing an event at a chosen time — and its value is stored as
// given. Every production path leaves it zero (see audit.NewEvent).
//
// This leaves the commit-order hazard, which no timestamp can remove: a row
// inserted inside a long transaction becomes visible after rows with later
// stamps have already been read. Readers must lag by more than the longest
// transaction.
//
// The stored value is written back to e so the caller reports what was stored.
func (s *AuditStore) Record(ctx context.Context, e *audit.Event) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.AuditRecord")
	defer span.End()

	var createdAt *time.Time // nil ⇒ the database stamps it
	if !e.CreatedAt.IsZero() {
		t := toUTC(e.CreatedAt)
		createdAt = &t
	}

	start := time.Now()
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`INSERT INTO audit_events (id, action, actor_id, client_id, ip, detail, trace_id, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7, COALESCE($8::timestamptz, clock_timestamp()))
		 RETURNING created_at`,
		e.ID, e.Action, e.ActorID, e.ClientID, e.IP, e.Detail, e.TraceID, createdAt,
	).Scan(&e.CreatedAt)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("audit_record"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert audit event: %w", err)
	}
	e.CreatedAt = toUTC(e.CreatedAt)
	return nil
}

// Query implements output.AuditStore.
func (s *AuditStore) Query(ctx context.Context, filter output.AuditFilter) ([]audit.Event, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.AuditQuery")
	defer span.End()

	var where []string
	var args []any
	argN := 1

	if filter.Action != "" {
		where = append(where, fmt.Sprintf("action = $%d", argN))
		args = append(args, filter.Action)
		argN++
	}
	if filter.ActorID != "" {
		where = append(where, fmt.Sprintf("actor_id = $%d", argN))
		args = append(args, filter.ActorID)
		argN++
	}
	if filter.ClientID != "" {
		where = append(where, fmt.Sprintf("client_id = $%d", argN))
		args = append(args, filter.ClientID)
		argN++
	}
	if filter.SinceUnix > 0 {
		where = append(where, fmt.Sprintf("created_at >= $%d", argN))
		args = append(args, time.Unix(filter.SinceUnix, 0).UTC())
		argN++
	}
	if filter.UntilUnix > 0 {
		where = append(where, fmt.Sprintf("created_at <= $%d", argN))
		args = append(args, time.Unix(filter.UntilUnix, 0).UTC())
		argN++
	}

	query := `SELECT ` + auditColumns + ` FROM audit_events`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argN)
		args = append(args, filter.Limit)
		argN++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argN)
		args = append(args, filter.Offset)
	}

	start := time.Now()
	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("audit_query"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

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
