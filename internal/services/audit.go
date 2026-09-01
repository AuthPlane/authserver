package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// AuditRecorder records security audit events.
// Services accept this interface as an optional dependency (nil-safe).
//
// Recording is always best-effort and always outside the caller's transaction.
// A failure to record is *our* bug, and it must never cost the user their
// token, their login, or their denial response. Nothing here can fail a
// request.
//
// The price of that choice is that a record can be lost — so losing one is made
// loud rather than silent. See AuditService.Record.
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Event)
}

// AuditQuerier queries stored audit events.
type AuditQuerier interface {
	Query(ctx context.Context, filter output.AuditFilter) ([]audit.Event, error)
}

// AuditService implements AuditRecorder and AuditQuerier.
type AuditService struct {
	store   output.AuditStore
	logger  *slog.Logger
	tracer  oteltrace.Tracer
	metrics *observability.Metrics
}

// NewAuditService creates a new audit service.
func NewAuditService(store output.AuditStore, obs *observability.Provider) *AuditService {
	return &AuditService{
		store:   store,
		logger:  obs.Logger,
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
}

// Record persists an audit event best-effort. It never fails the caller.
//
// A store failure emits the complete event to the structured log — every field,
// so the record survives in the log sink and can be replayed — and increments
// audit_events_dropped_total. Alert on that counter: a non-zero rate means the
// audit log is no longer a complete record of what the server did.
func (s *AuditService) Record(ctx context.Context, e audit.Event) {
	ctx, span := s.tracer.Start(ctx, "AuditService.Record")
	defer span.End()

	e = s.stamp(ctx, e)
	span.SetAttributes(attribute.String("audit.action", string(e.Action)))

	if err := s.store.Record(ctx, &e); err != nil {
		s.dropped(ctx, e, err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}

	s.log(ctx, e)
}

// stamp fills the id and correlates the event with the active trace.
func (s *AuditService) stamp(ctx context.Context, e audit.Event) audit.Event {
	if e.ID == "" {
		e.ID = crypto.GenerateRandomString(16)
	}
	if e.TraceID == "" {
		if spanCtx := oteltrace.SpanContextFromContext(ctx); spanCtx.HasTraceID() {
			e.TraceID = spanCtx.TraceID().String()
		}
	}
	return e
}

func (s *AuditService) log(ctx context.Context, e audit.Event) {
	s.logger.InfoContext(ctx, "audit",
		"action", string(e.Action),
		"actor_id", e.ActorID,
		"client_id", e.ClientID,
		"ip", e.IP,
		"detail", e.Detail,
	)
}

// auditDroppedMessage is the log message operators alert on. It is a stable
// string on purpose: log-based alerting matches it. Do not reword it casually.
const auditDroppedMessage = "audit event dropped — not persisted"

// dropped is the loss path. The operation it describes already happened and the
// user has already been served; there is nothing left to do but make sure the
// loss is neither silent nor unrecoverable.
//
// It emits every field of the event, so the record survives in the log sink and
// can be replayed into the table, and it increments audit_events_dropped_total.
// Both are alert surfaces, and this is the one place in the server where a
// non-zero rate means the audit log is no longer a complete account of what the
// server did. It should page.
func (s *AuditService) dropped(ctx context.Context, e audit.Event, err error) {
	s.logger.ErrorContext(ctx, auditDroppedMessage,
		"action", string(e.Action),
		"id", e.ID,
		"actor_id", e.ActorID,
		"client_id", e.ClientID,
		"ip", e.IP,
		"detail", e.Detail,
		"trace_id", e.TraceID,
		// The store never stamped this event, so it normally has no created_at. A
		// replay has only the moment we noticed, which is close enough to the
		// moment it happened — the store call is the next statement after the
		// operation. But an explicit-override event (backfill, import, replay)
		// carries its own created_at; honor it so a failed backfill row is logged
		// with the time it claims, not the time we failed to write it.
		"observed_at", droppedObservedAt(e).Format(time.RFC3339Nano),
		"error", err,
	)
	if s.metrics != nil && s.metrics.AuditEventsDropped != nil {
		s.metrics.AuditEventsDropped.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("action", string(e.Action)),
		))
	}
}

// droppedObservedAt is the time recorded on a dropped event. An explicit
// created_at (backfill, import, replay) is the time the event actually happened
// and is preserved; otherwise the store never stamped it and the moment we
// noticed the loss is the best available approximation.
func droppedObservedAt(e audit.Event) time.Time {
	if !e.CreatedAt.IsZero() {
		return e.CreatedAt.UTC()
	}
	return time.Now().UTC()
}

// Query returns audit events matching the filter.
func (s *AuditService) Query(ctx context.Context, filter output.AuditFilter) ([]audit.Event, error) {
	ctx, span := s.tracer.Start(ctx, "AuditService.Query")
	defer span.End()

	result, err := s.store.Query(ctx, filter)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	return result, nil
}
