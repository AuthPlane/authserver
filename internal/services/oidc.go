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
	"github.com/authplane/authserver/internal/ports/output"
)

// OIDCFacade orchestrates upstream OIDC authentication and user provisioning.
type OIDCFacade struct {
	provider output.OIDCProvider
	users    output.UserStore
	audit    AuditRecorder
	logger   *slog.Logger
	tracer   trace.Tracer
	metrics  *observability.Metrics
}

// NewOIDCFacade creates a new OIDC facade service.
func NewOIDCFacade(provider output.OIDCProvider, users output.UserStore, obs *observability.Provider, auditor AuditRecorder) *OIDCFacade {
	return &OIDCFacade{
		provider: provider,
		users:    users,
		audit:    auditor,
		logger:   obs.Logger,
		tracer:   obs.Tracer,
		metrics:  obs.Metrics,
	}
}

// AuthorizationURL delegates to the upstream provider.
func (f *OIDCFacade) AuthorizationURL(state, nonce, codeChallenge, redirectURI string) string {
	return f.provider.AuthorizationURL(state, nonce, codeChallenge, redirectURI)
}

// AuthenticateOIDC exchanges the code, provisions or updates the user, and returns the user.
func (f *OIDCFacade) AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier, redirectURI string) (*user.User, error) {
	ctx, span := f.tracer.Start(ctx, "OIDCFacade.AuthenticateOIDC")
	defer span.End()

	// 1. Exchange code and verify ID token via upstream provider.
	result, err := f.provider.ExchangeCode(ctx, code, nonce, codeVerifier, redirectURI)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		f.logger.WarnContext(ctx, "OIDC code exchange failed", "error", err)
		f.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "failure"),
		))
		if f.audit != nil {
			f.audit.Record(ctx, audit.NewEvent(audit.ActionUserOIDCLoginFailed, "", "", "", "code exchange failed"))
		}
		return nil, domain.ErrOIDCAuthFailed
	}

	span.SetAttributes(
		attribute.String("oidc.subject", result.Subject),
	)

	// 2. Look up existing user by (provider, subject).
	u, err := f.users.GetByProviderSub(ctx, user.ProviderOIDC, result.Subject)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("lookup federated user: %w", err)
	}

	if u == nil {
		// 3a. New user — provision.
		u = f.provisionUser(result)
		if err := f.users.Create(ctx, u); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("create federated user: %w", err)
		}
		f.logger.InfoContext(ctx, "OIDC user provisioned",
			"user_id", u.ID,
			"email", u.Email,
			"provider_sub", u.ProviderSub,
		)
	} else {
		// 3b. Existing user — check status and update if needed.
		if !u.IsActive() {
			f.logger.WarnContext(ctx, "OIDC login blocked for disabled user",
				"user_id", u.ID,
				"email", u.Email,
			)
			f.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("result", "failure"),
			))
			f.metrics.AuthDenied.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("reason", "user_disabled"),
			))
			if f.audit != nil {
				f.audit.Record(ctx, audit.NewEvent(audit.ActionUserOIDCLoginFailed, u.ID, "", "", "user disabled"))
			}
			span.RecordError(domain.ErrOIDCAuthFailed)
			span.SetStatus(codes.Error, "user disabled")
			return nil, domain.ErrOIDCAuthFailed
		}

		// Update email if changed upstream.
		if result.Email != "" && result.Email != u.Email {
			f.logger.InfoContext(ctx, "OIDC user email updated",
				"user_id", u.ID,
				"old_email", u.Email,
				"new_email", result.Email,
			)
			u.Email = result.Email
		}

		// Update name if changed upstream.
		if result.Name != "" && result.Name != u.Name {
			u.Name = result.Name
		}

		// Update last-login timestamp.
		u.UpdatedAt = time.Now().UTC()

		if err := f.users.Update(ctx, u); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("update federated user: %w", err)
		}
	}

	// 4. Success: emit metrics + audit.
	f.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", "success"),
	))
	if f.audit != nil {
		f.audit.Record(ctx, audit.NewEvent(audit.ActionUserOIDCLogin, u.ID, "", "", ""))
	}

	span.SetAttributes(attribute.String("user_id", u.ID))
	f.logger.InfoContext(ctx, "OIDC user authenticated",
		"user_id", u.ID,
		"email", u.Email,
	)
	return u, nil
}

func (f *OIDCFacade) provisionUser(result *output.OIDCTokenResult) *user.User {
	now := time.Now().UTC()
	return &user.User{
		ID:          crypto.GenerateRandomString(16),
		Email:       result.Email,
		Name:        result.Name,
		Role:        user.RoleUser,
		Status:      user.StatusActive,
		Provider:    user.ProviderOIDC,
		ProviderSub: result.Subject,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}
