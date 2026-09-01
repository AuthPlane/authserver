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

// Values of the "reason" attribute carried by every denied local login — on the
// AuthDenied metric, on the user.login_failed audit event and on the span. They
// are the only place the cause of a denial is recorded: the response and the
// latency are deliberately identical whichever one applies. Add new causes as values
// here, not as new fields, so operator queries keep working.
const (
	// No account with that email address.
	reasonUserNotFound = "user_not_found"

	// The account exists but is not active. Expected: an admin disable.
	reasonUserDisabled = "user_disabled"

	// The account exists and is active but authenticates against an upstream
	// provider, so there is no local password to check.
	reasonUserNotLocal = "user_not_local"

	// An active local account, wrong password.
	reasonInvalidCredentials = "invalid_credentials" //nolint:gosec // G101: an audit and metric label, not a credential

	// An active local account whose stored hash is empty or malformed, so
	// nothing can authenticate against it. A data fault, not an account state:
	// alert on this one.
	reasonUnusableHash = "unusable_stored_hash"
)

// Authenticate verifies email + password and returns the user.
//
// Every failure returns domain.ErrInvalidCredentials and costs one bcrypt
// comparison at crypto.DefaultBcryptCost, whether or not there was a stored hash
// worth checking. The uniform error keeps the response from naming the cause;
// the uniform cost keeps the latency from naming it either, which it used to.
// Three of the four failure paths returned before any comparison, so a ~470x
// spread answered "does this address have an active local account?" in a single
// request — a directory-disclosure oracle on an identity provider.
func (s *UserAuthService) Authenticate(ctx context.Context, email, password string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "UserAuthService.Authenticate")
	defer span.End()

	u, err := s.users.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	actorID := ""
	if u != nil {
		actorID = u.ID
		span.SetAttributes(attribute.String("user_id", u.ID))
	}

	// Decide the denial reason, but do not act on it yet: the comparison below
	// runs on every path, including the ones that already know they will deny.
	// The nil check rather than an err check is deliberate — a store that
	// returns neither a user nor an error breaks its contract, and reporting
	// that as user_not_found is better than dereferencing it.
	reason := ""
	switch {
	case u == nil:
		reason = reasonUserNotFound
	case !u.IsActive():
		reason = reasonUserDisabled
	case !u.IsLocal():
		reason = reasonUserNotLocal
	}

	// One bcrypt comparison per call, always: the stored hash whenever the
	// account could still authenticate, a fixed dummy of the same cost on every
	// path that has already decided to deny. Selecting the input instead of
	// branching around the call is what makes the failure paths uniform by
	// construction — a later edit cannot forget to pay the cost on a new early
	// return, because there is no early return to forget it on.
	hash := crypto.DummyBcryptHash()
	if reason == "" {
		hash = u.PasswordHash
	}
	// On its own statement, deliberately: folding the call into the condition
	// below would let && short-circuit it away on the paths that already hold a
	// reason, which is precisely the defect being fixed. The result is read
	// afterwards, so the call cannot be elided.
	passwordErr := crypto.CompareBcryptUniform(hash, password)
	switch {
	case reason != "":
		// Already denied; the comparison above was for its cost alone and its
		// result is deliberately not consulted. This is what keeps the dummy
		// hash from ever admitting anybody.
	case errors.Is(passwordErr, crypto.ErrUnusableHash):
		// An active local account whose stored hash cannot be derived against.
		// A broken row rather than a wrong password, and worth saying so: the
		// account cannot log in at all and no amount of resetting the password
		// on the caller's side will change that.
		reason = reasonUnusableHash
	case passwordErr != nil:
		reason = reasonInvalidCredentials
	}

	if reason != "" {
		s.denyLogin(ctx, span, actorID, email, reason)
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

// denyLogin records one failed local authentication. Every cause funnels
// through here and emit the same action, the same metrics and the same span
// status, differing only in the reason — which stays server-side. Holding the
// denials in one function is what keeps them uniform: a divergence would have to
// be written here on purpose rather than drift into a single branch.
//
// actorID is empty when the address matched no account, which is the one case
// where there is no actor to name.
//
// Detail puts reason first and quotes the address, because the address is raw
// form input: left last and bare, a submitted value carrying a space and its own
// "reason=" would produce a row whose first reason= the attacker chose. The
// sibling auth.locked_out event on the same request was fixed the same way.
func (s *UserAuthService) denyLogin(ctx context.Context, span trace.Span, actorID, email, reason string) {
	s.logger.WarnContext(ctx, "local authentication denied", "email", email, "reason", reason)
	s.metrics.LoginAttempts.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", "failure"),
	))
	s.metrics.AuthDenied.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("reason", reason),
	))
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionUserLoginFailed, actorID, "", "",
			fmt.Sprintf("reason=%s email=%q", reason, email)))
	}
	span.RecordError(domain.ErrInvalidCredentials)
	span.SetStatus(codes.Error, reason)
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
