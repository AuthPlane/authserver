package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.SubjectMappingPort = (*SubjectMappingService)(nil)

// SubjectMappingService manages XAA subject mappings and resolves external
// IdP subjects to local user identities.
type SubjectMappingService struct {
	mappingStore output.SubjectMappingStore
	idpStore     output.IDPStore
	users        output.UserStore
	logger       *slog.Logger
	tracer       trace.Tracer
	metrics      *observability.Metrics
}

// NewSubjectMappingService creates a new subject mapping service.
//
// users is required: a mapping to a local user is only honored while that
// user is active, and an unwired store would silently skip the check.
func NewSubjectMappingService(
	mappingStore output.SubjectMappingStore,
	idpStore output.IDPStore,
	users output.UserStore,
	obs *observability.Provider,
) *SubjectMappingService {
	if users == nil {
		panic("services.NewSubjectMappingService: users is required")
	}
	return &SubjectMappingService{
		mappingStore: mappingStore,
		idpStore:     idpStore,
		users:        users,
		logger:       obs.Logger.With("component", "subject_mapping"),
		tracer:       obs.Tracer,
		metrics:      obs.Metrics,
	}
}

// CreateMapping creates a new subject mapping.
func (s *SubjectMappingService) CreateMapping(ctx context.Context, req input.CreateMappingRequest) (*xaa.SubjectMapping, error) {
	ctx, span := s.tracer.Start(ctx, "SubjectMappingService.CreateMapping")
	defer span.End()

	if req.IDPID == "" || req.IDPSubject == "" {
		return nil, fmt.Errorf("idp_id and idp_subject are required")
	}

	// Verify IdP exists.
	if _, err := s.idpStore.GetByID(ctx, req.IDPID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "idp not found")
		return nil, fmt.Errorf("idp %q: %w", req.IDPID, domain.ErrIDPNotFound)
	}

	// A mapping that names a local user must name one that exists: tokens
	// issued through it carry that user as sub.
	if req.LocalUserID != "" {
		if _, err := s.users.GetByID(ctx, req.LocalUserID); err != nil {
			span.RecordError(err)
			if errors.Is(err, domain.ErrUserNotFound) {
				span.SetStatus(codes.Error, "local user not found")
				return nil, fmt.Errorf("local_user_id %q: %w", req.LocalUserID, domain.ErrUserNotFound)
			}
			span.SetStatus(codes.Error, "local user lookup failed")
			return nil, fmt.Errorf("look up local user: %w", err)
		}
	}

	now := time.Now().UTC()
	m := xaa.SubjectMapping{
		ID:          crypto.GenerateRandomString(16),
		IDPID:       req.IDPID,
		IDPSubject:  req.IDPSubject,
		LocalUserID: req.LocalUserID,
		CreatedAt:   now,
	}

	if err := s.mappingStore.Save(ctx, m); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("save mapping: %w", err)
	}

	s.logger.InfoContext(ctx, "subject mapping created",
		"mapping_id", m.ID,
		"idp_id", m.IDPID,
		"idp_subject", m.IDPSubject,
	)

	return &m, nil
}

// ListMappings returns subject mappings, optionally filtered by IdP ID.
func (s *SubjectMappingService) ListMappings(ctx context.Context, idpID string) ([]xaa.SubjectMapping, error) {
	ctx, span := s.tracer.Start(ctx, "SubjectMappingService.ListMappings")
	defer span.End()

	var mappings []xaa.SubjectMapping
	var err error
	if idpID != "" {
		mappings, err = s.mappingStore.ListByIDP(ctx, idpID)
	} else {
		mappings, err = s.mappingStore.ListByIDP(ctx, "")
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return mappings, nil
}

// DeleteMapping removes a subject mapping by ID.
func (s *SubjectMappingService) DeleteMapping(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SubjectMappingService.DeleteMapping")
	defer span.End()

	if err := s.mappingStore.Delete(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	s.logger.InfoContext(ctx, "subject mapping deleted", "mapping_id", id)
	return nil
}

// errMappedUserInactive is returned by ResolveSubject when a mapping names a
// local user that is disabled. It is invalid_grant on the wire, like a refresh
// or code redemption for a disabled user; callers match it with errors.Is to
// audit the refusal under its own reason.
var errMappedUserInactive = fmt.Errorf("%w: the mapped local user is disabled", domain.ErrInvalidGrant)

// ResolveSubject maps an external IdP subject to a local identity.
//
// In "strict" mode, a subject mapping must exist or the request is rejected.
// In "auto_map" mode, if no mapping exists, the iss:sub pair is used.
//
// A mapping that resolves to a local user is honored only while that user is
// active: the token's sub then names a local account, and every other grant
// stops for a disabled account. A disabled user returns errMappedUserInactive;
// a user-store failure returns a plain error, so it surfaces as a server error
// rather than a refusal.
//
// A local_user_id that names no user row passes. The admin API has never
// required one to exist, so deployments use it as a stable local label; with
// no account there is no account status to honor. Introspection and the
// token-exchange liveness check treat an unknown subject the same way.
func (s *SubjectMappingService) ResolveSubject(
	ctx context.Context,
	idpID string,
	idpIssuer string,
	idpSubject string,
	subjectMode string,
) (string, error) {
	ctx, span := s.tracer.Start(ctx, "SubjectMappingService.ResolveSubject")
	defer span.End()

	// Try to find an explicit mapping.
	m, err := s.mappingStore.GetMapping(ctx, idpID, idpSubject)
	if err == nil && m != nil {
		if m.LocalUserID != "" {
			if err := s.checkLocalUserActive(ctx, m.LocalUserID); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "mapped local user inactive")
				s.metrics.XAASubjectResolutions.Add(ctx, 1, otelmetric.WithAttributes(
					attribute.String("result", "denied"),
				))
				return "", err
			}
			s.logger.InfoContext(ctx, "subject resolved via mapping",
				"idp_id", idpID,
				"local_user_id", m.LocalUserID,
			)
			s.metrics.XAASubjectResolutions.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("result", "mapped"),
			))
			return m.LocalUserID, nil
		}
		// Mapping exists but no local user ID — use iss:sub pair.
		return idpIssuer + ":" + idpSubject, nil
	}

	// No mapping found.
	if subjectMode == "strict" {
		span.SetStatus(codes.Error, "no subject mapping in strict mode")
		s.metrics.XAASubjectResolutions.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "denied"),
		))
		return "", domain.ErrSubjectMappingNotFound
	}

	// auto_map mode: use iss:sub as the identity.
	s.metrics.XAASubjectResolutions.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", "auto_map"),
	))
	return idpIssuer + ":" + idpSubject, nil
}

// checkLocalUserActive returns errMappedUserInactive when userID names a
// disabled local user or none at all — a mapping to a deleted account must not
// keep issuing tokens for it — and a wrapped store error when the lookup
// itself fails.
func (s *SubjectMappingService) checkLocalUserActive(ctx context.Context, userID string) error {
	u, err := s.users.GetByID(ctx, userID)
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		s.logger.InfoContext(ctx, "subject mapping names a local user that does not exist", "local_user_id", userID)
		return errMappedUserInactive
	case err != nil:
		return fmt.Errorf("look up mapped local user: %w", err)
	case u == nil:
		return fmt.Errorf("look up mapped local user: %w", domain.ErrStoreReturnedNoUser)
	case !u.IsActive():
		s.logger.InfoContext(ctx, "subject mapping names a disabled local user", "local_user_id", userID)
		return errMappedUserInactive
	}
	return nil
}
