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
func (f *OIDCFacade) AuthorizationURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	return f.provider.AuthorizationURL(ctx, state, nonce, codeChallenge)
}

// AuthenticateOIDC exchanges the code, provisions or updates the user, and returns the user.
func (f *OIDCFacade) AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier string) (*user.User, error) {
	ctx, span := f.tracer.Start(ctx, "OIDCFacade.AuthenticateOIDC")
	defer span.End()

	// 1. Exchange code and verify ID token via upstream provider.
	result, err := f.provider.ExchangeCode(ctx, code, nonce, codeVerifier)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if errors.Is(err, domain.ErrOIDCUnavailable) {
			// Infrastructure failure (config / discovery / JWKS unreachable),
			// not a user authentication failure: log at ERROR and propagate the
			// sentinel so the callback handler returns a 500, not a 401. Do not
			// record it as a failed login attempt.
			f.logger.ErrorContext(ctx, "OIDC upstream unavailable during code exchange", "error", err)
			return nil, err
		}
		f.logger.WarnContext(ctx, "OIDC code exchange failed", "error", err)
		f.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "failure"),
		))
		f.loginFailed(ctx, "", "code exchange failed")
		return nil, domain.ErrOIDCAuthFailed
	}

	span.SetAttributes(
		attribute.String("oidc.subject", result.Subject),
	)

	// 2. Look up existing user by (provider, subject).
	// The email plays no part in finding the account: an IdP need not
	// release one, and one it does release is never used to link to an
	// existing account.
	u, err := f.users.GetByProviderSub(ctx, user.ProviderOIDC, result.Subject)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		f.loginFailed(ctx, "", "reason=store_error provider_sub="+result.Subject)
		return nil, fmt.Errorf("lookup federated user: %w", err)
	}

	provisioned := false
	if u == nil {
		// 3a. New user — provision. A missing email is stored as NULL, so
		// any number of email-less federated users can exist.
		nu := f.provisionUser(result)
		if err := f.users.Create(ctx, nu); err != nil {
			// (provider, provider_sub) is unique for federated users, so a
			// concurrent first sign-in for the same identity loses here.
			// The account the other request created is this user's.
			var raced *user.User
			if errors.Is(err, domain.ErrUserAlreadyExists) {
				if existing, lerr := f.users.GetByProviderSub(ctx, user.ProviderOIDC, result.Subject); lerr == nil {
					raced = existing
				}
			}
			if raced != nil {
				u = raced
			} else {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				if errors.Is(err, domain.ErrUserAlreadyExists) {
					// The only unique column a new federated user can collide on
					// is a present email: it belongs to another account. Linking
					// by email would hand that account to whoever controls the
					// address at the IdP, so refuse.
					f.logger.WarnContext(ctx, "OIDC provisioning refused: email belongs to another account",
						"provider_sub", result.Subject)
					f.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
						attribute.String("result", "failure"),
					))
					f.loginFailed(ctx, "", "reason=email_in_use provider_sub="+result.Subject)
					return nil, domain.ErrOIDCEmailInUse
				}
				f.loginFailed(ctx, "", "reason=store_error provider_sub="+result.Subject)
				return nil, fmt.Errorf("create federated user: %w", err)
			}
		} else {
			u = nu
			provisioned = true
			f.logger.InfoContext(ctx, "OIDC user provisioned",
				"user_id", u.ID,
				"provider_sub", u.ProviderSub,
			)
		}
	}
	if !provisioned {
		// 3b. Existing user — check status and update if needed.
		if !u.IsActive() {
			f.logger.WarnContext(ctx, "OIDC login blocked for disabled user", "user_id", u.ID)
			f.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("result", "failure"),
			))
			f.metrics.AuthDenied.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("reason", reasonUserDisabled),
			))
			f.loginFailed(ctx, u.ID, "user disabled")
			span.RecordError(domain.ErrOIDCAuthFailed)
			span.SetStatus(codes.Error, "user disabled")
			return nil, domain.ErrOIDCAuthFailed
		}

		// Update email if changed upstream.
		storedEmail := u.Email
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

		err := f.users.Update(ctx, u)
		if errors.Is(err, domain.ErrUserAlreadyExists) && u.Email != storedEmail {
			// The new upstream email belongs to another account. The user is
			// still who (provider, subject) says, so the sign-in proceeds and
			// only the email change is dropped.
			f.logger.WarnContext(ctx, "OIDC email change not applied: email belongs to another account",
				"user_id", u.ID)
			u.Email = storedEmail
			err = f.users.Update(ctx, u)
		}
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			f.loginFailed(ctx, u.ID, "reason=store_error")
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
	f.logger.InfoContext(ctx, "OIDC user authenticated", "user_id", u.ID)
	return u, nil
}

// loginFailed records a user.oidc_login_failed audit row. actorID is the
// local user when one was resolved, empty before provisioning.
func (f *OIDCFacade) loginFailed(ctx context.Context, actorID, detail string) {
	if f.audit != nil {
		f.audit.Record(ctx, audit.NewEvent(audit.ActionUserOIDCLoginFailed, actorID, "", "", detail))
	}
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
