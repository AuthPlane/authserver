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
	dclient "github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// AdminService implements input.AdminPort.
type AdminService struct {
	clients       output.ClientStore
	users         output.UserStore
	tokens        output.TokenStore
	machineTokens output.MachineTokenStore  // optional — nil if client_credentials not configured
	revocation    output.RevocationStore    // optional — nil if not available
	txManager     output.TransactionManager // optional — nil if not available
	audit         AuditRecorder
	audits        output.AuditStore
	// grantsProvider resolves the grant types the AS honors, per request.
	// nil ⇒ no enforcement (tests). Optional, injected via WithEnabledGrants.
	grantsProvider output.EnabledGrantsProvider
	// auditQueryCfg bounds how far back the audit feed may be read, per request.
	// nil ⇒ the built-in bound, never "unbounded": an unbounded audit scan is a
	// defect regardless of who configured it.
	auditQueryCfg output.AuditQueryConfigProvider
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics
}

var _ input.AdminPort = (*AdminService)(nil)

// AdminServiceOpt configures optional AdminService dependencies.
type AdminServiceOpt func(*AdminService)

// WithMachineTokenStore sets the machine token store for token visibility.
func WithMachineTokenStore(s output.MachineTokenStore) AdminServiceOpt {
	return func(a *AdminService) { a.machineTokens = s }
}

// WithRevocationStore sets the revocation store for JTI blacklisting.
func WithRevocationStore(s output.RevocationStore) AdminServiceOpt {
	return func(a *AdminService) { a.revocation = s }
}

// WithTransactionManager sets the transaction manager for atomic multi-step operations.
func WithTransactionManager(tm output.TransactionManager) AdminServiceOpt {
	return func(a *AdminService) { a.txManager = tm }
}

// WithAuditQueryConfig injects the per-request audit-feed lookback bound.
// Omitting it leaves the built-in bound in force — the audit feed is never
// unbounded, whether or not a deployment configures it.
func WithAuditQueryConfig(p output.AuditQueryConfigProvider) AdminServiceOpt {
	return func(a *AdminService) { a.auditQueryCfg = p }
}

// WithEnabledGrants injects the per-request enabled-grants provider.
// AdminService rejects CreateClient/UpdateClient requests carrying a grant
// outside the set the provider returns so operators can't register clients that
// will only fail later at /oauth/token.
func WithEnabledGrants(p output.EnabledGrantsProvider) AdminServiceOpt {
	return func(a *AdminService) { a.grantsProvider = p }
}

// NewAdminService creates a new admin service.
func NewAdminService(
	clients output.ClientStore,
	users output.UserStore,
	tokens output.TokenStore,
	audits output.AuditStore,
	obs *observability.Provider,
	auditRec AuditRecorder,
	opts ...AdminServiceOpt,
) *AdminService {
	svc := &AdminService{
		clients: clients,
		users:   users,
		tokens:  tokens,
		audit:   auditRec,
		audits:  audits,
		logger:  obs.Logger,
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// --- Clients ---

// CreateClient implements input.AdminPort.
func (s *AdminService) CreateClient(ctx context.Context, req input.CreateClientRequest) (*input.CreateClientResponse, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.CreateClient")
	defer span.End()

	// Apply defaults and validate.
	params := dclient.CreateParams{
		Name:                    req.Name,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RegistrationSource:      dclient.SourceAdmin,
		IsAgent:                 req.IsAgent,
		AgentDescription:        req.AgentDescription,
	}
	params.Defaults()

	enabledGrants, gErr := resolveEnabledGrants(ctx, s.grantsProvider)
	if gErr != nil {
		span.RecordError(gErr)
		span.SetStatus(codes.Error, gErr.Error())
		return nil, gErr
	}
	if err := dclient.ValidateCreateParams(params, enabledGrants); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidClient, err)
	}

	now := time.Now().UTC()
	c := &dclient.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    params.Name,
		RedirectURIs:            params.RedirectURIs,
		GrantTypes:              params.GrantTypes,
		ResponseTypes:           params.ResponseTypes,
		TokenEndpointAuthMethod: params.TokenEndpointAuthMethod,
		Status:                  dclient.StatusActive,
		RegistrationSource:      dclient.SourceAdmin,
		Scope:                   req.Scope,
		IsAgent:                 params.IsAgent,
		AgentDescription:        params.AgentDescription,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	// Generate secret for confidential clients.
	var plainSecret string
	if params.TokenEndpointAuthMethod != "none" {
		plainSecret = crypto.GenerateClientSecret()
		hash, err := crypto.HashClientSecret(plainSecret)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("hash client secret: %w", err)
		}
		c.SecretHash = hash
	}

	if err := s.clients.Create(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create client: %w", err)
	}

	span.SetAttributes(attribute.String("client_id", c.ID))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientCreatedAdmin, "admin", c.ID, "", "name="+req.Name))
	}
	s.logger.InfoContext(ctx, "client created via admin",
		"client_id", c.ID,
		"name", req.Name,
		"grant_types", params.GrantTypes,
		"auth_method", params.TokenEndpointAuthMethod,
	)

	if s.metrics != nil && s.metrics.ClientsRegistered != nil {
		s.metrics.ClientsRegistered.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("source", "admin"),
		))
	}

	return &input.CreateClientResponse{
		Client:       c,
		ClientSecret: plainSecret,
	}, nil
}

// RotateClientSecret implements input.AdminPort.
func (s *AdminService) RotateClientSecret(ctx context.Context, clientID string) (*input.RotateSecretResponse, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.RotateClientSecret")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", clientID))

	c, err := s.clients.GetByID(ctx, clientID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Public clients have no secret to rotate.
	if c.IsPublic() {
		publicErr := fmt.Errorf("%w: cannot rotate secret for public client", domain.ErrInvalidClient)
		span.RecordError(publicErr)
		span.SetStatus(codes.Error, publicErr.Error())
		return nil, publicErr
	}

	// Generate new secret.
	plainSecret := crypto.GenerateClientSecret()
	hash, err := crypto.HashClientSecret(plainSecret)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("hash client secret: %w", err)
	}

	c.SecretHash = hash
	c.UpdatedAt = time.Now().UTC()

	if err := s.clients.Update(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("update client: %w", err)
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientSecretRotated, "admin", clientID, "", ""))
	}
	s.logger.InfoContext(ctx, "client secret rotated", "client_id", clientID)

	return &input.RotateSecretResponse{
		ClientID:     clientID,
		ClientSecret: plainSecret,
	}, nil
}

// UpdateClient implements input.AdminPort.
func (s *AdminService) UpdateClient(ctx context.Context, id string, req input.UpdateClientRequest) (*dclient.Client, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.UpdateClient")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", id))

	c, err := s.clients.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Apply non-nil fields.
	if req.Name != nil {
		c.Name = *req.Name
	}
	if req.RedirectURIs != nil {
		c.RedirectURIs = *req.RedirectURIs
	}
	if req.GrantTypes != nil {
		c.GrantTypes = *req.GrantTypes
	}
	if req.Scope != nil {
		c.Scope = *req.Scope
	}

	// Validate the updated state.
	params := dclient.CreateParams{
		Name:                    c.Name,
		RedirectURIs:            c.RedirectURIs,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		IsAgent:                 c.IsAgent,
		AgentDescription:        c.AgentDescription,
	}
	enabledGrants, gErr := resolveEnabledGrants(ctx, s.grantsProvider)
	if gErr != nil {
		span.RecordError(gErr)
		span.SetStatus(codes.Error, gErr.Error())
		return nil, gErr
	}
	if err := dclient.ValidateCreateParams(params, enabledGrants); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidClient, err)
	}

	c.UpdatedAt = time.Now().UTC()

	if err := s.clients.Update(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("update client: %w", err)
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientUpdated, "admin", id, "", ""))
	}
	s.logger.InfoContext(ctx, "client updated via admin", "client_id", id)

	return c, nil
}

// ListClients implements input.AdminPort.
func (s *AdminService) ListClients(ctx context.Context, filter input.ClientFilter) ([]dclient.Client, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.ListClients")
	defer span.End()

	result, err := s.clients.List(ctx, filter.Status, filter.Source, filter.Limit, filter.Offset)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return result, nil
}

// GetClient implements input.AdminPort.
func (s *AdminService) GetClient(ctx context.Context, id string) (*dclient.Client, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.GetClient")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", id))

	result, err := s.clients.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidClient) {
			err = domain.ErrClientNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return result, nil
}

// SuspendClient implements input.AdminPort.
func (s *AdminService) SuspendClient(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.SuspendClient")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", id))

	c, err := s.clients.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("get client: %w", err)
	}
	if err := c.Suspend(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("suspend: %w", err)
	}
	if err := s.clients.Update(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update client: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientSuspended, "admin", id, "", ""))
	}
	s.logger.InfoContext(ctx, "client suspended", "client_id", id)
	return nil
}

// RevokeClient implements input.AdminPort.
func (s *AdminService) RevokeClient(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.RevokeClient")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", id))

	c, err := s.clients.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("get client: %w", err)
	}
	c.Revoke()
	if err := s.clients.Update(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update client: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientRevoked, "admin", id, "", ""))
	}
	s.logger.InfoContext(ctx, "client revoked", "client_id", id)
	return nil
}

// ReactivateClient implements input.AdminPort.
func (s *AdminService) ReactivateClient(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.ReactivateClient")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", id))

	c, err := s.clients.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("get client: %w", err)
	}
	if err := c.Reactivate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("reactivate: %w", err)
	}
	if err := s.clients.Update(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update client: %w", err)
	}
	s.logger.InfoContext(ctx, "client reactivated", "client_id", id)
	return nil
}

// DeleteClient implements input.AdminPort.
func (s *AdminService) DeleteClient(ctx context.Context, id string, force bool) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.DeleteClient")
	defer span.End()
	span.SetAttributes(attribute.String("client_id", id), attribute.Bool("force", force))

	// The entire check-revoke-delete flow runs inside a transaction to prevent
	// TOCTOU races where tokens are issued between the count and the delete.
	doDelete := func(ctx context.Context) error {
		// Verify client exists.
		if _, err := s.clients.GetByID(ctx, id); err != nil {
			return err
		}

		// Check for active token families.
		activeCount, err := s.tokens.CountActiveByClientID(ctx, id)
		if err != nil {
			return fmt.Errorf("count active tokens: %w", err)
		}

		// Also check for active machine tokens (client_credentials).
		var machineCount int
		if s.machineTokens != nil {
			_, machineCount, err = s.machineTokens.List(ctx, output.MachineTokenFilter{ClientID: id, Limit: 1})
			if err != nil {
				return fmt.Errorf("count active machine tokens: %w", err)
			}
		}

		hasActiveTokens := activeCount > 0 || machineCount > 0
		if hasActiveTokens && !force {
			return domain.ErrClientHasActiveTokens
		}

		// If force, revoke all tokens first.
		if force && hasActiveTokens {
			familiesRevoked, err := s.tokens.RevokeByClientID(ctx, id)
			if err != nil {
				return fmt.Errorf("revoke client families: %w", err)
			}

			var machineRevoked int
			if s.machineTokens != nil {
				machineRevoked, err = s.machineTokens.RevokeByClientID(ctx, id)
				if err != nil {
					return fmt.Errorf("revoke machine tokens: %w", err)
				}
			}
			s.logger.InfoContext(ctx, "force-revoked client tokens",
				"client_id", id,
				"families", familiesRevoked,
				"machine_tokens", machineRevoked,
			)
		}

		// Delete the client.
		if err := s.clients.Delete(ctx, id); err != nil {
			return fmt.Errorf("delete client: %w", err)
		}
		return nil
	}

	var err error
	if s.txManager != nil {
		err = s.txManager.WithTransaction(ctx, doDelete)
	} else {
		err = doDelete(ctx)
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientDeleted, "admin", id, "", fmt.Sprintf("force=%v", force)))
	}
	s.logger.InfoContext(ctx, "client deleted", "client_id", id, "force", force)

	return nil
}

// --- Tokens ---

// ListTokens implements input.AdminPort.
func (s *AdminService) ListTokens(ctx context.Context, filter input.TokenFilter) (*input.TokenListResponse, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.ListTokens")
	defer span.End()

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	tokens := make([]input.TokenView, 0, limit)
	var totalFamilies int

	// List token families (authorization_code / refresh token flows).
	families, total, err := s.tokens.ListFamilies(ctx, output.FamilyFilter{
		ClientID: filter.ClientID,
		UserID:   filter.UserID,
		Limit:    limit,
		Offset:   filter.Offset,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list token families: %w", err)
	}
	totalFamilies = total

	for i := range families {
		f := &families[i]
		tokens = append(tokens, input.TokenView{
			JTI:       f.ID,
			Type:      "authorization_code",
			ClientID:  f.ClientID,
			UserID:    f.UserID,
			Scope:     f.Scope,
			Resource:  f.Resource,
			Status:    string(f.Status),
			CreatedAt: f.CreatedAt,
		})
	}

	// Also list machine tokens if available and filter doesn't exclude them (no user_id filter).
	totalMachine := 0
	if s.machineTokens != nil && filter.UserID == "" {
		mts, mtTotal, err := s.machineTokens.List(ctx, output.MachineTokenFilter{
			ClientID: filter.ClientID,
			Limit:    limit,
			Offset:   filter.Offset,
		})
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("list machine tokens: %w", err)
		}
		totalMachine = mtTotal
		for _, mt := range mts {
			tokens = append(tokens, input.TokenView{
				JTI:       mt.JTI,
				Type:      "client_credentials",
				ClientID:  mt.ClientID,
				Scope:     mt.Scopes.String(),
				Resource:  mt.Resource,
				Status:    "active",
				CreatedAt: mt.IssuedAt,
				ExpiresAt: &mt.ExpiresAt,
			})
		}
	}

	s.logger.InfoContext(ctx, "tokens listed",
		"families", len(families),
		"machine_tokens", totalMachine,
		"client_id", filter.ClientID,
		"user_id", filter.UserID,
	)

	return &input.TokenListResponse{
		Tokens: tokens,
		Total:  totalFamilies + totalMachine,
	}, nil
}

// ListUserTokens implements input.AdminPort.
func (s *AdminService) ListUserTokens(ctx context.Context, userID string, limit, offset int) (*input.TokenListResponse, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.ListUserTokens")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", userID))

	// Verify user exists.
	if _, err := s.users.GetByID(ctx, userID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return s.ListTokens(ctx, input.TokenFilter{
		UserID: userID,
		Limit:  limit,
		Offset: offset,
	})
}

// RevokeToken implements input.AdminPort.
func (s *AdminService) RevokeToken(ctx context.Context, jti string) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.RevokeToken")
	defer span.End()
	span.SetAttributes(attribute.String("jti", jti))

	// Try revoking as a token family first.
	family, err := s.tokens.GetFamily(ctx, jti)
	if err == nil && family != nil {
		if _, err := s.tokens.RevokeFamily(ctx, jti); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("revoke family: %w", err)
		}

		// Also blacklist JTIs via revocation store if available.
		if s.revocation != nil {
			if err := s.revocation.RevokeByFamily(ctx, jti); err != nil {
				s.logger.WarnContext(ctx, "failed to blacklist family JTIs", "family_id", jti, "error", err)
			}
		}

		if s.audit != nil {
			s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRevoked, "admin", family.ClientID, "", "family="+jti))
		}
		s.logger.InfoContext(ctx, "token family revoked via admin", "family_id", jti, "client_id", family.ClientID)
		return nil
	}

	// Try revoking as a machine token.
	if s.machineTokens != nil {
		mt, err := s.machineTokens.GetByJTI(ctx, jti)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("get machine token: %w", err)
		}
		if mt != nil {
			if err := s.machineTokens.Revoke(ctx, jti); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return fmt.Errorf("revoke machine token: %w", err)
			}
			if s.audit != nil {
				s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRevoked, "admin", mt.ClientID, "", "machine_jti="+jti))
			}
			s.logger.InfoContext(ctx, "machine token revoked via admin", "jti", jti, "client_id", mt.ClientID)
			return nil
		}
	}

	return fmt.Errorf("%w: token not found", domain.ErrInvalidGrant)
}

// --- Users ---

// CreateUser implements input.AdminPort.
func (s *AdminService) CreateUser(ctx context.Context, req input.CreateUserRequest) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.CreateUser")
	defer span.End()

	hash, err := crypto.HashBcrypt(req.Password)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	u := &user.User{
		ID:           crypto.GenerateRandomString(16),
		Email:        req.Email,
		Name:         req.Name,
		PasswordHash: hash,
		Role:         req.Role,
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

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionUserCreated, "admin", "", "", "email="+req.Email))
	}
	s.logger.InfoContext(ctx, "user created via admin", "user_id", u.ID, "email", req.Email)
	return u, nil
}

// ListUsers implements input.AdminPort.
func (s *AdminService) ListUsers(ctx context.Context) ([]user.User, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.ListUsers")
	defer span.End()

	result, err := s.users.List(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return result, nil
}

// GetUser implements input.AdminPort.
func (s *AdminService) GetUser(ctx context.Context, id string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.GetUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", id))

	result, err := s.users.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return result, nil
}

// UpdateUser implements input.AdminPort.
func (s *AdminService) UpdateUser(ctx context.Context, id string, req input.UpdateUserRequest) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.UpdateUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", id))

	u, err := s.users.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.Name != nil {
		u.Name = *req.Name
	}
	u.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, u); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("update user: %w", err)
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionUserUpdated, "admin", "", "", "user="+id))
	}
	s.logger.InfoContext(ctx, "user updated via admin", "user_id", id)

	return u, nil
}

// DeleteUser implements input.AdminPort.
func (s *AdminService) DeleteUser(ctx context.Context, id string, force bool) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.DeleteUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", id), attribute.Bool("force", force))

	// The entire check-revoke-delete flow runs inside a transaction to prevent
	// TOCTOU races where tokens are created between the count and the delete.
	doDelete := func(ctx context.Context) error {
		// Verify user exists.
		if _, err := s.users.GetByID(ctx, id); err != nil {
			return err
		}

		// Check for active token families.
		_, activeCount, err := s.tokens.ListFamilies(ctx, output.FamilyFilter{UserID: id, Status: "active", Limit: 1})
		if err != nil {
			return fmt.Errorf("count user tokens: %w", err)
		}

		if activeCount > 0 && !force {
			return domain.ErrUserHasActiveTokens
		}

		// If force, revoke all tokens first.
		if activeCount > 0 {
			count, err := s.tokens.RevokeByUserID(ctx, id)
			if err != nil {
				return fmt.Errorf("revoke user tokens: %w", err)
			}
			s.logger.InfoContext(ctx, "force-revoked user tokens", "user_id", id, "count", count)
		}

		// Delete the user.
		if err := s.users.Delete(ctx, id); err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	}

	var err error
	if s.txManager != nil {
		err = s.txManager.WithTransaction(ctx, doDelete)
	} else {
		err = doDelete(ctx)
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionUserDeleted, "admin", "", "", fmt.Sprintf("user=%s force=%v", id, force)))
	}
	s.logger.InfoContext(ctx, "user deleted", "user_id", id, "force", force)

	return nil
}

// DisableUser implements input.AdminPort.
func (s *AdminService) DisableUser(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.DisableUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", id))

	u, err := s.users.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("get user: %w", err)
	}
	if err := u.Disable(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("disable: %w", err)
	}
	if err := s.users.Update(ctx, u); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update user: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionUserDisabled, "admin", "", "", "user="+id))
	}
	s.logger.InfoContext(ctx, "user disabled", "user_id", id)
	return nil
}

// EnableUser implements input.AdminPort.
func (s *AdminService) EnableUser(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "AdminService.EnableUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", id))

	u, err := s.users.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("get user: %w", err)
	}
	if err := u.Enable(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("enable: %w", err)
	}
	if err := s.users.Update(ctx, u); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update user: %w", err)
	}
	s.logger.InfoContext(ctx, "user enabled", "user_id", id)
	return nil
}

// --- Force Logout ---

// ForceLogoutUser implements input.AdminPort.
func (s *AdminService) ForceLogoutUser(ctx context.Context, id string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.ForceLogoutUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", id))

	// Verify user exists.
	if _, err := s.users.GetByID(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}

	// Collect active family IDs so we can blacklist tracked access-token JTIs.
	var familyIDs []string
	if s.revocation != nil {
		families, _, err := s.tokens.ListFamilies(ctx, output.FamilyFilter{
			UserID: id,
			Status: "active",
			Limit:  500,
		})
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return 0, fmt.Errorf("list user token families: %w", err)
		}
		for i := range families {
			familyIDs = append(familyIDs, families[i].ID)
		}
	}

	// Revoke all token families for this user.
	count, err := s.tokens.RevokeByUserID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke user tokens: %w", err)
	}

	// Also blacklist tracked access-token JTIs for each revoked family.
	if s.revocation != nil {
		for _, familyID := range familyIDs {
			if err := s.revocation.RevokeByFamily(ctx, familyID); err != nil {
				s.logger.WarnContext(ctx, "failed to blacklist family JTIs during force logout",
					"family_id", familyID, "error", err)
			}
		}
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionForceLogout, "admin", "", "", fmt.Sprintf("user=%s revoked=%d", id, count)))
	}
	s.logger.InfoContext(ctx, "user force-logged out", "user_id", id, "tokens_revoked", count)

	return count, nil
}

// --- Audit ---

const (
	// defaultAuditSinceWindow is the lookback applied when the caller omits
	// since. Mirrors the issuances feed.
	defaultAuditSinceWindow = 24 * time.Hour

	// maxAuditSinceWindow caps the lookback. audit_events is the highest-volume
	// table in the schema; without a bound, omitting since and paging on offset
	// walks all of it.
	maxAuditSinceWindow = 30 * 24 * time.Hour

	// defaultAuditQueryLimit is the page size applied when the caller omits
	// limit. Mirrors the issuances feed.
	defaultAuditQueryLimit = 50

	// maxAuditQueryLimit caps the page size. The since window bounds how far
	// back a query reaches; this bounds how many rows one response may
	// materialize. Raise it here if a deployment needs bigger pages.
	maxAuditQueryLimit = 1000

	// maxAuditQueryOffset caps offset paging. Postgres serves a deep OFFSET by
	// scanning and discarding everything before it, so an unbounded offset is
	// an unbounded scan even inside a bounded window.
	maxAuditQueryOffset = 100_000
)

// QueryAudit implements input.AdminPort.
//
// The lookback bound is applied here rather than in the HTTP handler, so that no
// query parameter — present or added later — can route around it. The bound is a
// lookback and nothing more: this service does not know, and must not know, why
// a deployment chose the number.
func (s *AdminService) QueryAudit(ctx context.Context, filter input.AuditFilter) ([]audit.Event, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.QueryAudit")
	defer span.End()

	since, err := s.boundAuditSince(ctx, filter.Since)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	limit, offset, err := boundAuditPage(filter.Limit, filter.Offset)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	f := output.AuditFilter{
		Action:    filter.Action,
		ActorID:   filter.ActorID,
		ClientID:  filter.ClientID,
		Limit:     limit,
		Offset:    offset,
		SinceUnix: since.Unix(),
	}
	if filter.Until != nil {
		// until only ever narrows the window — it cannot route around the since
		// bound — so it is not clamped. But an until at or before the effective
		// since describes an empty interval, and returning a silently-empty page
		// for it lets a caller mistake a malformed range for "no events". Reject
		// it, consistent with the rest of the bounds telling a caller no rather
		// than handing back something it will misread.
		if !filter.Until.After(since) {
			err = domain.NewInvalidRequestError("until must be after the effective since")
			span.RecordError(err)
			return nil, err
		}
		f.UntilUnix = filter.Until.Unix()
	}
	result, err := s.audits.Query(ctx, f)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return result, nil
}

// boundAuditSince resolves the effective lower bound of an audit query.
//
// An omitted since becomes the default lookback — never "the beginning of time",
// which is what makes offset paging over audit_events unbounded today. A since
// beyond the max is rejected rather than quietly narrowed: a caller asking for
// ninety days should be told it cannot have them, not handed thirty and left to
// believe that was all there was.
func (s *AdminService) boundAuditSince(ctx context.Context, since *time.Time) (time.Time, error) {
	cfg := output.AuditQueryConfig{
		DefaultLookback: defaultAuditSinceWindow,
		MaxLookback:     maxAuditSinceWindow,
	}
	if s.auditQueryCfg != nil {
		resolved, err := s.auditQueryCfg.Config(ctx)
		if err != nil {
			return time.Time{}, fmt.Errorf("resolve audit query config: %w", err)
		}
		if resolved.DefaultLookback > 0 {
			cfg.DefaultLookback = resolved.DefaultLookback
		}
		// A zero MaxLookback keeps the built-in cap. A provider handing back a
		// default-constructed config — a deployment whose visibility setting
		// was never populated — must inherit the bound, not silently remove it.
		if resolved.MaxLookback > 0 {
			cfg.MaxLookback = resolved.MaxLookback
		}
	}

	now := time.Now().UTC()
	if cfg.MaxLookback > 0 && cfg.DefaultLookback > cfg.MaxLookback {
		cfg.DefaultLookback = cfg.MaxLookback
	}
	if since == nil {
		return now.Add(-cfg.DefaultLookback), nil
	}
	if cfg.MaxLookback > 0 && now.Sub(*since) > cfg.MaxLookback {
		return time.Time{}, domain.NewInvalidRequestError(fmt.Sprintf(
			"since exceeds the maximum audit lookback of %s", cfg.MaxLookback))
	}
	return since.UTC(), nil
}

// boundAuditPage resolves the effective page of an audit query — the sibling of
// boundAuditSince, and in the service for the same reason: no query parameter
// may route around the bound. The since window caps how far back a query
// reaches; without this, limit and offset still cap nothing, and a single
// request can ask the store to materialize or scan-and-discard an arbitrary
// number of rows. Oversized values are rejected rather than clamped: a caller
// asking for more rows than it may have should be told so, not handed a
// truncated page it will mistake for the end of the data.
func boundAuditPage(limit, offset int) (int, int, error) {
	if limit <= 0 {
		limit = defaultAuditQueryLimit
	}
	if limit > maxAuditQueryLimit {
		return 0, 0, domain.NewInvalidRequestError(fmt.Sprintf(
			"limit exceeds the maximum of %d", maxAuditQueryLimit))
	}
	if offset < 0 {
		offset = 0
	}
	if offset > maxAuditQueryOffset {
		return 0, 0, domain.NewInvalidRequestError(fmt.Sprintf(
			"offset exceeds the maximum of %d", maxAuditQueryOffset))
	}
	return limit, offset, nil
}

// --- Stats ---

// GetStats implements input.AdminPort.
func (s *AdminService) GetStats(ctx context.Context) (*input.DashboardStats, error) {
	ctx, span := s.tracer.Start(ctx, "AdminService.GetStats")
	defer span.End()

	totalClients, err := s.clients.Count(ctx, "")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("count clients: %w", err)
	}
	activeClients, err := s.clients.Count(ctx, "active")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("count active clients: %w", err)
	}
	totalUsers, err := s.users.Count(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("count users: %w", err)
	}

	dayStart := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	tokensIssued, err := s.tokens.CountIssuedSince(ctx, dayStart)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("count issued: %w", err)
	}
	tokensRevoked, err := s.tokens.CountRevokedSince(ctx, dayStart)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("count revoked: %w", err)
	}

	// Include machine tokens (client_credentials) in the totals.
	if s.machineTokens != nil {
		mtIssued, err := s.machineTokens.CountIssuedSince(ctx, dayStart)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("count machine tokens issued: %w", err)
		}
		tokensIssued += mtIssued

		mtRevoked, err := s.machineTokens.CountRevokedSince(ctx, dayStart)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("count machine tokens revoked: %w", err)
		}
		tokensRevoked += mtRevoked
	}

	return &input.DashboardStats{
		TotalClients:       totalClients,
		ActiveClients:      activeClients,
		TotalUsers:         totalUsers,
		TokensIssuedToday:  tokensIssued,
		TokensRevokedToday: tokensRevoked,
	}, nil
}
