package services

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// AuditRecorder records security audit events.
// Services accept this interface as an optional dependency (nil-safe).
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Event)
}

// AuditQuerier queries stored audit events.
type AuditQuerier interface {
	Query(ctx context.Context, filter output.AuditFilter) ([]audit.Event, error)
}

// AuditService implements AuditRecorder and AuditQuerier.
type AuditService struct {
	store  output.AuditStore
	logger *slog.Logger
	tracer oteltrace.Tracer
}

// NewAuditService creates a new audit service.
func NewAuditService(store output.AuditStore, obs *observability.Provider) *AuditService {
	return &AuditService{
		store:  store,
		logger: obs.Logger,
		tracer: obs.Tracer,
	}
}

// Record persists an audit event and logs it to stdout.
func (s *AuditService) Record(ctx context.Context, e audit.Event) {
	ctx, span := s.tracer.Start(ctx, "AuditService.Record")
	defer span.End()

	span.SetAttributes(attribute.String("audit.action", string(e.Action)))

	if e.ID == "" {
		e.ID = crypto.GenerateRandomString(16)
	}

	// Extract trace_id from context for correlation.
	if e.TraceID == "" {
		spanCtx := oteltrace.SpanContextFromContext(ctx)
		if spanCtx.HasTraceID() {
			e.TraceID = spanCtx.TraceID().String()
		}
	}

	if err := s.store.Record(ctx, &e); err != nil {
		s.logger.ErrorContext(ctx, "failed to record audit event",
			"action", e.Action,
			"error", err,
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}

	s.logger.InfoContext(ctx, "audit",
		"action", string(e.Action),
		"actor_id", e.ActorID,
		"client_id", e.ClientID,
		"ip", e.IP,
		"detail", e.Detail,
	)
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
