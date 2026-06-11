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
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.UserAuthPort = (*UserAuthService)(nil)

// UserAuthService handles user authentication and management.
type UserAuthService struct {
	users   output.UserStore
	audit   AuditRecorder
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// NewUserAuthService creates a new user auth service.
func NewUserAuthService(users output.UserStore, obs *observability.Provider, auditor AuditRecorder) *UserAuthService {
	return &UserAuthService{
		users:   users,
		audit:   auditor,
		logger:  obs.Logger,
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
}

// Authenticate verifies email + password and returns the user.
func (s *UserAuthService) Authenticate(ctx context.Context, email, password string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "UserAuthService.Authenticate")
	defer span.End()

	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			s.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("result", "failure"),
			))
			s.metrics.AuthDenied.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("reason", "user_not_found"),
			))
			span.RecordError(domain.ErrInvalidCredentials)
			span.SetStatus(codes.Error, "invalid credentials")
			return nil, domain.ErrInvalidCredentials
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	span.SetAttributes(attribute.String("user_id", u.ID))

	if !u.IsActive() {
		s.logger.WarnContext(ctx, "authentication attempt for disabled user", "email", email)
		s.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "failure"),
		))
		s.metrics.AuthDenied.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", "user_disabled"),
		))
		span.RecordError(domain.ErrInvalidCredentials)
		span.SetStatus(codes.Error, "user disabled")
		return nil, domain.ErrInvalidCredentials
	}

	if !u.IsLocal() {
		s.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "failure"),
		))
		span.RecordError(domain.ErrInvalidCredentials)
		span.SetStatus(codes.Error, "not a local user")
		return nil, domain.ErrInvalidCredentials
	}

	if err := crypto.CompareBcrypt(u.PasswordHash, password); err != nil {
		s.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "failure"),
		))
		s.metrics.AuthDenied.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", "invalid_credentials"),
		))
		if s.audit != nil {
			s.audit.Record(ctx, audit.NewEvent(audit.ActionUserLoginFailed, "", "", "", "email="+email))
		}
		span.RecordError(domain.ErrInvalidCredentials)
		span.SetStatus(codes.Error, "invalid credentials")
		return nil, domain.ErrInvalidCredentials
	}

	s.logger.InfoContext(ctx, "user authenticated", "user_id", u.ID, "email", email)
	s.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", "success"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionUserLogin, u.ID, "", "", ""))
	}
	return u, nil
}

// GetByID returns a user by their ID.
func (s *UserAuthService) GetByID(ctx context.Context, id string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "UserAuthService.GetByID")
	defer span.End()

	u, err := s.users.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return u, nil
}

// CreateUser creates a new local user with a bcrypt-hashed password.
func (s *UserAuthService) CreateUser(ctx context.Context, email, name, password string, role user.Role) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "UserAuthService.CreateUser")
	defer span.End()

	hash, err := crypto.HashBcrypt(password)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	u := &user.User{
		ID:           crypto.GenerateRandomString(16),
		Email:        email,
		Name:         name,
		PasswordHash: hash,
		Role:         role,
		Status:       user.StatusActive,
		Provider:     user.ProviderLocal,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, u); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.logger.InfoContext(ctx, "created user", "user_id", u.ID, "email", email, "role", role)
	return u, nil
}
