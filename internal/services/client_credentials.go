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

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.ClientCredentialsPort = (*ClientCredentialsService)(nil)

// ClientCredentialsService implements the client_credentials grant (RFC 6749 §4.4).
// Services authenticate as themselves — no user involved, no refresh token issued.
type ClientCredentialsService struct {
	clients       output.ClientStore
	machineTokens output.MachineTokenStore
	jwks          JWKSSigningKeyProvider
	audit         AuditRecorder
	issuer        string
	tokenTTL      time.Duration
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics

	// Resource validation — all scope metadata lives on resource servers.
	resources ResourceLister

	// Issuance audit — optional. When both are set the service
	// resolves the resource= parameter through the registry (to obtain
	// resources.id for the FK) and writes the per-token audit row into
	// issuances so the admin /admin/issuances surface lists every
	// client_credentials token alongside other grant types.
	issuances        output.IssuanceStore
	resourceRegistry *ResourceRegistry

	// DPoP support (RFC 9449) — optional. When dpopStore is nil, DPoP is disabled.
	dpopStore  output.DPoPNonceStore
	dpopConfig *DPoPConfig

	// Agent identity — optional. When set, attaches agent_id/agent_chain claims.
	agentIdentity *AgentIdentityService
}

// NewClientCredentialsService creates a new client credentials service.
func NewClientCredentialsService(
	clients output.ClientStore,
	machineTokens output.MachineTokenStore,
	jwks JWKSSigningKeyProvider,
	issuer string,
	tokenTTL time.Duration,
	obs *observability.Provider,
	auditRec AuditRecorder,
	resources ResourceLister,
) *ClientCredentialsService {
	return &ClientCredentialsService{
		clients:       clients,
		machineTokens: machineTokens,
		jwks:          jwks,
		audit:         auditRec,
		issuer:        issuer,
		tokenTTL:      tokenTTL,
		logger:        obs.Logger.With("component", "client_credentials"),
		tracer:        obs.Tracer,
		metrics:       obs.Metrics,
		resources:     resources,
	}
}

// WithDPoP enables DPoP proof-of-possession support on the client credentials service.
func (s *ClientCredentialsService) WithDPoP(store output.DPoPNonceStore, cfg DPoPConfig) {
	s.dpopStore = store
	s.dpopConfig = &cfg
}

// WithIssuanceAudit enables the per-token issuance audit row write.
// Both arguments must be non-nil. The registry resolves the resource=
// parameter to *resource.Resource so resources.id is available as the FK
// target. When unset (e.g. in unit tests), Exchange retains its pre-
// behavior of emitting only the machine_tokens row.
func (s *ClientCredentialsService) WithIssuanceAudit(issuances output.IssuanceStore, registry *ResourceRegistry) {
	s.issuances = issuances
	s.resourceRegistry = registry
}

// WithAgentIdentity enables agent identity claim attachment.
func (s *ClientCredentialsService) WithAgentIdentity(ai *AgentIdentityService) {
	s.agentIdentity = ai
}

// Exchange authenticates a client and issues a machine access token.
func (s *ClientCredentialsService) Exchange(ctx context.Context, req input.ClientCredentialsRequest) (*input.ClientCredentialsResponse, error) {
	ctx, span := s.tracer.Start(ctx, "ClientCredentialsService.Exchange")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("grant_type", "client_credentials"),
	)
	start := time.Now()

	// 1. Authenticate client.
	c, err := s.authenticateClient(ctx, span, req.ClientID, req.ClientSecret)
	if err != nil {
		s.recordDenied(ctx, req.ClientID, "invalid_client")
		return nil, err
	}

	// 2. Check client is permitted for client_credentials grant.
	if !hasGrantType(c.GrantTypes, "client_credentials") {
		span.RecordError(domain.ErrUnauthorizedClient)
		span.SetStatus(codes.Error, "client_credentials grant not allowed")
		s.recordDenied(ctx, req.ClientID, "unauthorized_client")
		return nil, domain.ErrUnauthorizedClient
	}

	// 3. Determine effective scopes.
	clientScopes := scope.Parse(c.Scope)
	var effectiveScopes scope.Set

	if req.Scope != "" {
		requestedScopes := scope.Parse(req.Scope)
		// Fail closed when the request exceeds what the client is registered
		// for. Silent narrowing (Intersect) hid overbroad or buggy client
		// behavior; RFC 6749 §5.2 names invalid_scope for this case.
		if !requestedScopes.IsSubset(clientScopes) {
			span.RecordError(domain.ErrInvalidScope)
			span.SetStatus(codes.Error, "requested scope exceeds client's registered scopes")
			s.recordDenied(ctx, req.ClientID, "invalid_scope")
			return nil, domain.ErrInvalidScope
		}
		effectiveScopes = requestedScopes
	} else {
		// No scope requested — use all registered scopes.
		effectiveScopes = clientScopes
	}

	// 4. Validate resource parameter (RFC 8707).
	if req.Resource != "" && !s.isKnownResource(ctx, req.Resource) {
		resourceErr := fmt.Errorf("%w: unknown resource %q", domain.ErrInvalidScope, req.Resource)
		span.RecordError(resourceErr)
		span.SetStatus(codes.Error, resourceErr.Error())
		s.recordDenied(ctx, req.ClientID, "invalid_resource")
		return nil, resourceErr
	}

	// 5. Validate DPoP proof if present (RFC 9449).
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL, "")
		if dpopErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_dpop_proof")
			return nil, dpopErr
		}
		dpopJKT = jkt
	}

	// 6. Sign JWT access token.
	now := time.Now().UTC()
	expiry := now.Add(s.tokenTTL)
	jti := crypto.GenerateRandomString(16)

	sk, err := s.jwks.GetSigningKey(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	aud := []string{req.Resource}
	if req.Resource == "" {
		aud = []string{s.issuer}
	}

	claims := crypto.AccessTokenClaims{
		Issuer:    s.issuer,
		Subject:   req.ClientID, // RFC 9068 §2.2: sub = client_id for machine tokens
		Audience:  aud,
		ClientID:  req.ClientID,
		Scope:     effectiveScopes.String(),
		JTI:       jti,
		IssuedAt:  now.Unix(),
		Expiry:    expiry.Unix(),
		NotBefore: now.Unix(),
	}

	// DPoP binding: embed cnf.jkt in the access token (RFC 9449 §6).
	if dpopJKT != "" {
		claims.Cnf = map[string]interface{}{"jkt": dpopJKT}
	}

	// Agent identity claims (Authplane extension).
	if s.agentIdentity != nil {
		if agentErr := s.agentIdentity.AttachClaims(ctx, &claims, req.ClientID); agentErr != nil {
			span.RecordError(agentErr)
			span.SetStatus(codes.Error, agentErr.Error())
			return nil, fmt.Errorf("attach agent claims: %w", agentErr)
		}
	}

	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  jose.SignatureAlgorithm(sk.Algorithm),
		KeyID:      sk.KeyID,
	}

	accessToken, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// 7b. Persist issuance audit row. Mirrors MintIssuer.Issue so the
	// admin /admin/issuances list reflects every grant type uniformly.
	// Resource resolution failure is non-fatal (matches token.go behavior:
	// audit row is best-effort when the resource= parameter is absent or
	// not registered); insert failure aborts the request so the admin UI
	// guarantee (row visible within ~1s) is preserved.
	if s.issuances != nil && s.resourceRegistry != nil && req.Resource != "" {
		if res, resolveErr := s.resourceRegistry.Resolve(ctx, req.Resource); resolveErr == nil && res != nil {
			iss := &resource.Issuance{
				ID:            jti,
				SubjectUserID: req.ClientID, // RFC 9068 §2.2: sub = client_id for machine tokens
				ClientID:      req.ClientID,
				ResourceID:    res.ID,
				Scopes:        effectiveScopes.Slice(),
				BackendKind:   resource.BackendMint,
				Revocable:     true,
				IssuedAt:      now,
				ExpiresAt:     expiry,
				JTI:           jti,
				DPoPJKT:       dpopJKT,
				AgentID:       claims.AgentID,
			}
			iss.SetAgentChain(claims.AgentChain)
			if insertErr := s.issuances.Insert(ctx, iss); insertErr != nil {
				span.RecordError(insertErr)
				span.SetStatus(codes.Error, insertErr.Error())
				s.logger.ErrorContext(ctx, "client_credentials: issuance audit insert failed",
					"client_id", req.ClientID,
					"jti", jti,
					"error", insertErr,
				)
				return nil, fmt.Errorf("insert client_credentials issuance: %w", insertErr)
			}
		} else if resolveErr != nil {
			span.AddEvent("client_credentials_issuance_skipped_unresolved_resource")
			s.logger.WarnContext(ctx, "client_credentials: resolve resource for audit row failed",
				"client_id", req.ClientID,
				"resource", req.Resource,
				"error", resolveErr,
			)
		}
	}

	// 8. Store machine token for introspection + revocation.
	mt := token.MachineToken{
		JTI:       jti,
		ClientID:  req.ClientID,
		Scopes:    effectiveScopes,
		Resource:  req.Resource,
		IssuedAt:  now,
		ExpiresAt: expiry,
		Revoked:   false,
	}
	if err := s.machineTokens.Save(ctx, mt); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("save machine token: %w", err)
	}

	tokenType := "Bearer"
	if dpopJKT != "" {
		tokenType = "DPoP"
	}

	// 9. Emit audit event + metrics.
	s.logger.InfoContext(ctx, "client credentials token issued",
		"client_id", req.ClientID,
		"jti", jti,
		"scopes", effectiveScopes.String(),
		"token_type", tokenType,
	)

	if s.metrics != nil && s.metrics.ClientCredentialsIssued != nil {
		s.metrics.ClientCredentialsIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("client_id", req.ClientID),
		))
	}
	if s.metrics != nil && s.metrics.TokensIssued != nil {
		s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("grant_type", "client_credentials"),
		))
	}
	if s.metrics != nil && s.metrics.TokenIssuanceDuration != nil {
		s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
			attribute.String("grant_type", "client_credentials"),
		))
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionClientCredentialsIssued,
			req.ClientID, req.ClientID, "",
			fmt.Sprintf("jti=%s scopes=%s", jti, effectiveScopes.String()),
		))
	}

	return &input.ClientCredentialsResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   int(s.tokenTTL.Seconds()),
		Scope:       effectiveScopes.String(),
	}, nil
}

// authenticateClient looks up a client by ID, verifies it is active,
// and verifies the client secret (constant-time bcrypt compare).
func (s *ClientCredentialsService) authenticateClient(ctx context.Context, span trace.Span, clientID, clientSecret string) (*client.Client, error) {
	if clientID == "" || clientSecret == "" {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "missing credentials")
		return nil, domain.ErrInvalidClient
	}

	c, err := s.clients.GetByID(ctx, clientID)
	if err != nil {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "client not found")
		return nil, domain.ErrInvalidClient
	}

	if !c.IsActive() {
		span.RecordError(domain.ErrClientSuspended)
		span.SetStatus(codes.Error, "client suspended")
		return nil, domain.ErrClientSuspended
	}

	// Client credentials grant requires confidential clients only.
	if c.IsPublic() {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "public clients cannot use client_credentials")
		return nil, domain.ErrInvalidClient
	}

	if err := crypto.CompareClientSecret(c.SecretHash, clientSecret); err != nil {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "invalid client_secret")
		return nil, domain.ErrInvalidClient
	}

	return c, nil
}

// recordDenied increments the denied counter with a reason label.
func (s *ClientCredentialsService) recordDenied(ctx context.Context, clientID, reason string) {
	if s.metrics != nil && s.metrics.ClientCredentialsDenied != nil {
		s.metrics.ClientCredentialsDenied.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", reason),
		))
	}
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionClientCredentialsDenied,
			clientID, clientID, "",
			fmt.Sprintf("reason=%s", reason),
		))
	}
}

// validateDPoP validates a DPoP proof JWT and consumes its JTI for replay detection.
// Returns the JWK thumbprint (jkt) on success. If DPoP is not configured,
// the proof is silently ignored and an empty jkt is returned.
func (s *ClientCredentialsService) validateDPoP(ctx context.Context, span trace.Span, proof, method, reqURL, accessTokenHash string) (string, error) {
	if s.dpopStore == nil || s.dpopConfig == nil {
		return "", nil
	}

	result, err := crypto.ValidateProof(proof, method, reqURL, "", accessTokenHash, s.dpopConfig.ProofLifetime)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "DPoP proof validation failed")
		s.recordDPoPMetric(ctx, err)
		return "", err
	}

	// If require_nonce is set, validate the nonce from the proof against the store.
	if s.dpopConfig.RequireNonce {
		if result.Nonce == "" {
			span.RecordError(domain.ErrDPoPNonceRequired)
			span.SetStatus(codes.Error, "DPoP nonce required but missing")
			s.recordDPoPMetric(ctx, domain.ErrDPoPNonceRequired)
			return "", domain.ErrDPoPNonceRequired
		}
		if err := s.dpopStore.ValidateNonce(ctx, result.Nonce); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "DPoP nonce validation failed")
			s.recordDPoPMetric(ctx, domain.ErrDPoPNonceMismatch)
			return "", domain.ErrDPoPNonceMismatch
		}
	}

	// Consume JTI for replay detection.
	jtiExpiry := time.Now().Add(s.dpopConfig.ProofLifetime * 2)
	if err := s.dpopStore.ConsumeJTI(ctx, result.JTI, jtiExpiry); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "DPoP JTI replay")
		s.recordDPoPMetric(ctx, err)
		return "", err
	}

	s.recordDPoPMetric(ctx, nil)
	return result.JKT, nil
}

// recordDPoPMetric records DPoP proof validation result metrics.
func (s *ClientCredentialsService) recordDPoPMetric(ctx context.Context, err error) {
	if s.metrics == nil {
		return
	}
	if s.metrics.DPoPProofsValidated != nil && err == nil {
		s.metrics.DPoPProofsValidated.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "valid"),
		))
		return
	}
	if s.metrics.DPoPProofsRejected != nil && err != nil {
		reason := "unknown"
		switch {
		case errors.Is(err, domain.ErrDPoPInvalidProof):
			reason = "invalid_proof"
		case errors.Is(err, domain.ErrDPoPReplay):
			reason = "replay"
		case errors.Is(err, domain.ErrDPoPNonceRequired):
			reason = "nonce_required"
		case errors.Is(err, domain.ErrDPoPNonceMismatch):
			reason = "nonce_mismatch"
		}
		s.metrics.DPoPProofsRejected.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", reason),
		))
	}
}

// isKnownResource checks whether the resource URI is registered.
func (s *ClientCredentialsService) isKnownResource(_ context.Context, resource string) bool {
	if s.resources == nil {
		return false
	}
	for _, r := range s.resources.List() {
		if r.URI == resource {
			return true
		}
	}
	return false
}

// hasGrantType checks if the grant type is in the list.
func hasGrantType(grantTypes []string, target string) bool {
	for _, gt := range grantTypes {
		if gt == target {
			return true
		}
	}
	return false
}
