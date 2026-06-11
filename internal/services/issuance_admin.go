package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// IssuanceAdminService implements input.IssuanceAdminPort over
// output.IssuanceStore. Revoke is straight-through —
// issuances are the leaf record; there is no cascade.
type IssuanceAdminService struct {
	issuances output.IssuanceStore
	audit     AuditRecorder
	logger    *slog.Logger
	tracer    trace.Tracer
}

var _ input.IssuanceAdminPort = (*IssuanceAdminService)(nil)

// NewIssuanceAdminService constructs an IssuanceAdminService.
func NewIssuanceAdminService(
	issuances output.IssuanceStore,
	obs *observability.Provider,
	auditSvc AuditRecorder,
) *IssuanceAdminService {
	return &IssuanceAdminService{
		issuances: issuances,
		audit:     auditSvc,
		logger:    obs.Logger,
		tracer:    obs.Tracer,
	}
}

// ListForUser returns issuances for the user issued at/after since,
// newest first.
func (s *IssuanceAdminService) ListForUser(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "IssuanceAdminService.ListForUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", userID))

	if userID == "" {
		err := domain.NewInvalidRequestError("user_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	rows, err := s.issuances.ListForUser(ctx, userID, since)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for user: %w", err)
	}
	return rows, nil
}

// ListForActor returns issuances where client_id matches and issued_at
// >= since, newest first.
func (s *IssuanceAdminService) ListForActor(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "IssuanceAdminService.ListForActor")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", clientID))

	if clientID == "" {
		err := domain.NewInvalidRequestError("client_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	rows, err := s.issuances.ListForActor(ctx, clientID, since)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for actor: %w", err)
	}
	return rows, nil
}

// ListForResource returns issuances where resource_id matches and
// issued_at >= since, newest first.
func (s *IssuanceAdminService) ListForResource(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "IssuanceAdminService.ListForResource")
	defer span.End()
	span.SetAttributes(attribute.String("resource_id", resourceID))

	if resourceID == "" {
		err := domain.NewInvalidRequestError("resource_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	rows, err := s.issuances.ListForResource(ctx, resourceID, since)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for resource: %w", err)
	}
	return rows, nil
}

// GetByID returns the issuance with the given UUID, or
// domain.ErrIssuanceNotFound on miss. The store returns (nil, nil) on
// miss (parallel to GetByJTI); the sentinel mapping lives here so the
// admin handler can translate cleanly to a 404 via
// writeDomainOrInternalError.
func (s *IssuanceAdminService) GetByID(ctx context.Context, id string) (*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "IssuanceAdminService.GetByID")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	i, err := s.issuances.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get issuance by id: %w", err)
	}
	if i == nil {
		err := domain.ErrIssuanceNotFound
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return i, nil
}

// GetByJTI returns the issuance whose jti matches, or (nil, nil) on
// miss. The handler turns the (nil, nil) into list-semantics (empty
// array, not 404) for the /admin/issuances?jti=… endpoint.
func (s *IssuanceAdminService) GetByJTI(ctx context.Context, jti string) (*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "IssuanceAdminService.GetByJTI")
	defer span.End()
	span.SetAttributes(attribute.String("jti", jti))

	if jti == "" {
		err := domain.NewInvalidRequestError("jti is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	i, err := s.issuances.GetByJTI(ctx, jti)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get issuance by jti: %w", err)
	}
	return i, nil
}

// Revoke soft-deletes the issuance row by id. Idempotent. The
// introspection endpoint short-circuits on revoked_at != null once Inc
// 71 wires it, so the next /oauth/introspect reflects this.
//
// Audit detail enrichment (audit-followup B17): GetByID is called BEFORE
// Revoke so the audit row carries `subject_user_id`, `client_id`, and
// `resource_id` alongside the issuance `id`. The store returns
// (nil, nil) on miss; the detail records empty values and the storage
// Revoke is idempotent regardless.
func (s *IssuanceAdminService) Revoke(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "IssuanceAdminService.Revoke")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	row, err := s.issuances.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("lookup issuance: %w", err)
	}

	if err := s.issuances.Revoke(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke issuance: %w", err)
	}

	var subjectUserID, clientID, resourceID string
	if row != nil {
		subjectUserID = row.SubjectUserID
		clientID = row.ClientID
		resourceID = row.ResourceID
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionIssuanceRevokedAdmin,
			"admin", clientID, "",
			fmt.Sprintf("id=%s subject_user_id=%s client_id=%s resource_id=%s",
				id, subjectUserID, clientID, resourceID),
		))
	}

	s.logger.InfoContext(ctx, "issuance revoked",
		"id", id,
		"subject_user_id", subjectUserID,
		"client_id", clientID,
		"resource_id", resourceID,
	)
	return nil
}
