package services

import (
	"context"
	"encoding/json"
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
	domainresource "github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.JWTBearerPort = (*JWTBearerService)(nil)

// JWTBearerService implements the jwt-bearer grant type (RFC 7523) for
// MCP Enterprise-Managed Authorization (XAA).
type JWTBearerService struct {
	idpStore      output.IDPStore
	idpJWKS       output.IDPJWKSCache
	jtiStore      output.AssertionJTIStore
	clients       output.ClientStore
	machineTokens output.MachineTokenStore
	jwks          JWKSSigningKeyProvider
	audit         AuditRecorder
	issuer        string
	tokenTTL      time.Duration
	maxAge        time.Duration
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics

	// Resource validation.
	resources ResourceLister

	// Issuance audit — optional. When both are set the service
	// resolves the resource= parameter through the registry (to obtain
	// resources.id for the FK) and writes the per-token audit row into
	// issuances so the admin /admin/issuances surface lists every
	// jwt-bearer token alongside other grant types.
	issuances        output.IssuanceStore
	resourceRegistry *ResourceRegistry

	// DPoP support (RFC 9449) — optional.
	dpopStore  output.DPoPNonceStore
	dpopConfig *DPoPConfig

	// Agent identity — optional.
	agentIdentity *AgentIdentityService

	// Policy + subject mapping — optional.
	policyService  *XAAPolicyService
	mappingService *SubjectMappingService
	subjectMode    string // "auto_map" or "strict"
}

// NewJWTBearerService creates a new JWT bearer grant service.
func NewJWTBearerService(
	idpStore output.IDPStore,
	idpJWKS output.IDPJWKSCache,
	jtiStore output.AssertionJTIStore,
	clients output.ClientStore,
	machineTokens output.MachineTokenStore,
	jwks JWKSSigningKeyProvider,
	issuer string,
	tokenTTL time.Duration,
	maxAge time.Duration,
	obs *observability.Provider,
	auditRec AuditRecorder,
	resources ResourceLister,
) *JWTBearerService {
	return &JWTBearerService{
		idpStore:      idpStore,
		idpJWKS:       idpJWKS,
		jtiStore:      jtiStore,
		clients:       clients,
		machineTokens: machineTokens,
		jwks:          jwks,
		audit:         auditRec,
		issuer:        issuer,
		tokenTTL:      tokenTTL,
		maxAge:        maxAge,
		logger:        obs.Logger.With("component", "jwt_bearer"),
		tracer:        obs.Tracer,
		metrics:       obs.Metrics,
		resources:     resources,
	}
}

// WithDPoP enables DPoP proof-of-possession support.
func (s *JWTBearerService) WithDPoP(store output.DPoPNonceStore, cfg DPoPConfig) {
	s.dpopStore = store
	s.dpopConfig = &cfg
}

// WithIssuanceAudit enables the per-token issuance audit row write.
// Both arguments must be non-nil. The registry resolves the resource=
// parameter to *resource.Resource so resources.id is available as the FK
// target. When unset (e.g. in unit tests), GrantJWTBearer retains its
// pre- behavior of emitting only the machine_tokens row.
func (s *JWTBearerService) WithIssuanceAudit(issuances output.IssuanceStore, registry *ResourceRegistry) {
	s.issuances = issuances
	s.resourceRegistry = registry
}

// WithAgentIdentity enables agent identity claim attachment.
func (s *JWTBearerService) WithAgentIdentity(ai *AgentIdentityService) {
	s.agentIdentity = ai
}

// WithPolicy enables policy evaluation and subject mapping.
func (s *JWTBearerService) WithPolicy(policySvc *XAAPolicyService, mappingSvc *SubjectMappingService, subjectMode string) {
	s.policyService = policySvc
	s.mappingService = mappingSvc
	s.subjectMode = subjectMode
}

// GrantJWTBearer validates an ID-JAG assertion and issues an access token.
func (s *JWTBearerService) GrantJWTBearer(ctx context.Context, req input.JWTBearerRequest) (*input.JWTBearerResponse, error) {
	ctx, span := s.tracer.Start(ctx, "JWTBearerService.GrantJWTBearer")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
	)
	start := time.Now()

	// 1. Authenticate client.
	c, err := s.authenticateClient(ctx, span, req.ClientID, req.ClientSecret)
	if err != nil {
		s.recordDenied(ctx, req.ClientID, "invalid_client")
		return nil, err
	}

	// 2. Check client is permitted for jwt-bearer grant.
	if !hasGrantType(c.GrantTypes, "urn:ietf:params:oauth:grant-type:jwt-bearer") {
		span.RecordError(domain.ErrUnauthorizedClient)
		span.SetStatus(codes.Error, "jwt-bearer grant not allowed")
		s.recordDenied(ctx, req.ClientID, "unauthorized_client")
		return nil, domain.ErrUnauthorizedClient
	}

	// 3. Validate the assertion parameter is present.
	if req.Assertion == "" {
		assertErr := fmt.Errorf("%w: missing assertion parameter", domain.ErrAssertionInvalid)
		span.RecordError(assertErr)
		span.SetStatus(codes.Error, "missing assertion")
		s.recordDenied(ctx, req.ClientID, "missing_assertion")
		return nil, assertErr
	}

	// 4. Pre-parse the assertion to get the issuer for IdP lookup.
	//    We use the full validator which does parsing + validation in one step,
	//    but first we need the JWKS. Parse header to extract iss.
	assertionIssuer, err := extractIssuerFromJWT(req.Assertion)
	if err != nil {
		err = fmt.Errorf("%w: cannot extract issuer from assertion", domain.ErrAssertionInvalid)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid assertion header")
		s.recordDenied(ctx, req.ClientID, "invalid_assertion")
		return nil, err
	}

	// 5. Look up trusted IdP by issuer.
	idp, err := s.idpStore.GetByIssuer(ctx, assertionIssuer)
	if err != nil {
		span.RecordError(domain.ErrAssertionIssuerUntrusted)
		span.SetStatus(codes.Error, "untrusted issuer")
		s.recordDenied(ctx, req.ClientID, "untrusted_issuer")
		return nil, fmt.Errorf("%w: issuer %q", domain.ErrAssertionIssuerUntrusted, assertionIssuer)
	}

	if !idp.Enabled {
		span.RecordError(domain.ErrIDPDisabled)
		span.SetStatus(codes.Error, "IdP disabled")
		s.recordDenied(ctx, req.ClientID, "idp_disabled")
		return nil, domain.ErrIDPDisabled
	}

	span.SetAttributes(attribute.String("idp_id", idp.ID))

	// 6. Fetch JWKS for the IdP (cached).
	keys, err := s.idpJWKS.GetKeys(ctx, idp.Issuer)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "JWKS fetch failed")
		s.recordDenied(ctx, req.ClientID, "jwks_fetch_failed")
		return nil, fmt.Errorf("fetch JWKS for %q: %w", idp.Issuer, err)
	}

	// 7. Validate the ID-JAG assertion.
	assertion, err := crypto.ValidateIDJAG(req.Assertion, keys, s.issuer, s.maxAge)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "assertion validation failed")
		s.recordAssertionRejected(ctx, err)
		return nil, err
	}

	// 8. Consume JTI for replay prevention (single-use).
	jtiExpiry := time.Unix(assertion.Expiry, 0).Add(time.Minute) // buffer past expiry
	if jtiErr := s.jtiStore.ConsumeJTI(ctx, assertion.JTI, jtiExpiry); jtiErr != nil {
		span.RecordError(jtiErr)
		span.SetStatus(codes.Error, "assertion replay")
		s.recordDenied(ctx, req.ClientID, "replay")
		return nil, domain.ErrAssertionReplay
	}

	// 9. Verify client_id in assertion matches authenticated client.
	if assertion.ClientID != req.ClientID {
		span.RecordError(domain.ErrAssertionClientMismatch)
		span.SetStatus(codes.Error, "client_id mismatch")
		s.recordDenied(ctx, req.ClientID, "client_mismatch")
		return nil, domain.ErrAssertionClientMismatch
	}

	// 10. Determine effective scopes.
	//
	// Two upper bounds compose to produce the ceiling for this grant:
	//   client.Scope     — operator-set: what this AS client is registered for
	//   assertion.Scope  — IdP-set: what the user has been granted upstream
	// Their intersection is the maximum the AS may issue. Neither alone is a
	// request, so silent intersection between the two is the right semantic.
	//
	// req.Scope is the caller's explicit request. It must be a subset of the
	// composed ceiling — silent narrowing here was the MED 4-style bug that
	// hid client / assertion misconfiguration and inverted RFC 6749 §5.2
	// invalid_scope semantics. Mirrors the client_credentials fix.
	clientScopes := scope.Parse(c.Scope)
	effectiveScopes := clientScopes

	if assertion.Scope != "" {
		assertionScopes := scope.Parse(assertion.Scope)
		effectiveScopes = effectiveScopes.Intersect(assertionScopes)
		if effectiveScopes.IsEmpty() {
			span.RecordError(domain.ErrInvalidScope)
			span.SetStatus(codes.Error, "assertion scopes not allowed for client")
			s.recordDenied(ctx, req.ClientID, "invalid_scope")
			return nil, domain.ErrInvalidScope
		}
	}

	if req.Scope != "" {
		requestedScopes := scope.Parse(req.Scope)
		if !requestedScopes.IsSubset(effectiveScopes) {
			span.RecordError(domain.ErrInvalidScope)
			span.SetStatus(codes.Error, "requested scope exceeds client/assertion ceiling")
			s.recordDenied(ctx, req.ClientID, "invalid_scope")
			return nil, domain.ErrInvalidScope
		}
		effectiveScopes = requestedScopes
	}

	// 11. Validate resource parameter (RFC 8707).
	// When both assertion and request specify a resource, they must agree.
	if req.Resource != "" && assertion.Resource != "" && req.Resource != assertion.Resource {
		resourceErr := fmt.Errorf("%w: requested resource does not match assertion resource", domain.ErrInvalidScope)
		span.RecordError(resourceErr)
		span.SetStatus(codes.Error, "resource mismatch")
		s.recordDenied(ctx, req.ClientID, "invalid_resource")
		return nil, resourceErr
	}
	resource := req.Resource
	if resource == "" {
		resource = assertion.Resource
	}
	if resource != "" && !s.isKnownResource(ctx, resource) {
		unknownErr := fmt.Errorf("%w: unknown resource %q", domain.ErrInvalidScope, resource)
		span.RecordError(unknownErr)
		span.SetStatus(codes.Error, unknownErr.Error())
		s.recordDenied(ctx, req.ClientID, "invalid_resource")
		return nil, unknownErr
	}

	// 12. Policy check — evaluate XAA policies if configured.
	if s.policyService != nil {
		decision, policyErr := s.policyService.EvaluatePolicy(ctx, idp.ID, assertion, c, effectiveScopes, resource)
		if policyErr != nil {
			span.RecordError(policyErr)
			span.SetStatus(codes.Error, "policy denied")
			s.recordDenied(ctx, req.ClientID, "policy_denied")
			return nil, policyErr
		}
		// Use the policy-narrowed scopes.
		effectiveScopes = decision.EffectiveScope
	}

	// 13. Validate DPoP proof if present (RFC 9449).
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL, "")
		if dpopErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_dpop_proof")
			return nil, dpopErr
		}
		dpopJKT = jkt
	}

	// 14. Sign JWT access token.
	now := time.Now().UTC()
	expiry := now.Add(s.tokenTTL)
	jti := crypto.GenerateRandomString(16)

	sk, err := s.jwks.GetSigningKey(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	// Subject: resolve via subject mapping or fallback to iss:sub.
	var sub string
	if s.mappingService != nil {
		resolvedSub, mapErr := s.mappingService.ResolveSubject(ctx, idp.ID, assertion.Issuer, assertion.Subject, s.subjectMode)
		if mapErr != nil {
			span.RecordError(mapErr)
			span.SetStatus(codes.Error, "subject mapping failed")
			s.recordDenied(ctx, req.ClientID, "subject_mapping_failed")
			return nil, mapErr
		}
		sub = resolvedSub
	} else {
		sub = assertion.Issuer + ":" + assertion.Subject
	}

	aud := []string{resource}
	if resource == "" {
		aud = []string{s.issuer}
	}

	claims := crypto.AccessTokenClaims{
		Issuer:    s.issuer,
		Subject:   sub,
		Audience:  aud,
		ClientID:  req.ClientID,
		Scope:     effectiveScopes.String(),
		JTI:       jti,
		IssuedAt:  now.Unix(),
		Expiry:    expiry.Unix(),
		NotBefore: now.Unix(),
		Act: map[string]interface{}{
			"sub": assertion.Issuer, // provenance: IdP that vouched for this user
		},
	}

	// DPoP binding.
	if dpopJKT != "" {
		claims.Cnf = map[string]interface{}{"jkt": dpopJKT}
	}

	// Agent identity claims.
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

	// 14b. Persist issuance audit row. Mirrors MintIssuer.Issue so
	// the admin /admin/issuances list reflects every grant type uniformly.
	// Resource resolution failure is non-fatal; insert failure aborts the
	// request so the admin UI guarantee (row visible within ~1s) is
	// preserved.
	if s.issuances != nil && s.resourceRegistry != nil && resource != "" {
		if res, resolveErr := s.resourceRegistry.Resolve(ctx, resource); resolveErr == nil && res != nil {
			iss := &domainresource.Issuance{
				ID:            jti,
				SubjectUserID: sub,
				ClientID:      req.ClientID,
				ResourceID:    res.ID,
				Scopes:        effectiveScopes.Slice(),
				BackendKind:   domainresource.BackendMint,
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
				s.logger.ErrorContext(ctx, "jwt_bearer: issuance audit insert failed",
					"client_id", req.ClientID,
					"jti", jti,
					"error", insertErr,
				)
				return nil, fmt.Errorf("insert jwt_bearer issuance: %w", insertErr)
			}
		} else if resolveErr != nil {
			span.AddEvent("jwt_bearer_issuance_skipped_unresolved_resource")
			s.logger.WarnContext(ctx, "jwt_bearer: resolve resource for audit row failed",
				"client_id", req.ClientID,
				"resource", resource,
				"error", resolveErr,
			)
		}
	}

	// 15. Store machine token for introspection + revocation.
	mt := token.MachineToken{
		JTI:       jti,
		ClientID:  req.ClientID,
		Scopes:    effectiveScopes,
		Resource:  resource,
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

	// 16. Emit audit event + metrics.
	s.logger.InfoContext(ctx, "jwt-bearer token issued",
		"client_id", req.ClientID,
		"jti", jti,
		"idp_issuer", assertion.Issuer,
		"idp_subject", assertion.Subject,
		"scopes", effectiveScopes.String(),
		"token_type", tokenType,
	)

	if s.metrics != nil && s.metrics.TokensIssued != nil {
		s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
		))
	}
	if s.metrics != nil && s.metrics.TokenIssuanceDuration != nil {
		s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
			attribute.String("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
		))
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionJWTBearerIssued,
			sub, req.ClientID, "",
			fmt.Sprintf("jti=%s idp=%s scopes=%s", jti, assertion.Issuer, effectiveScopes.String()),
		))
	}

	// No refresh token per spec.
	return &input.JWTBearerResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   int(s.tokenTTL.Seconds()),
		Scope:       effectiveScopes.String(),
	}, nil
}

// authenticateClient looks up a client by ID, verifies it is active,
// and verifies the client secret (constant-time bcrypt compare).
func (s *JWTBearerService) authenticateClient(ctx context.Context, span trace.Span, clientID, clientSecret string) (*client.Client, error) {
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

	if c.IsPublic() {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "public clients cannot use jwt-bearer")
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
func (s *JWTBearerService) recordDenied(ctx context.Context, clientID, reason string) {
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionJWTBearerDenied,
			clientID, clientID, "",
			fmt.Sprintf("reason=%s", reason),
		))
	}
}

// recordAssertionRejected maps assertion validation errors to rejection reasons.
func (s *JWTBearerService) recordAssertionRejected(ctx context.Context, err error) {
	reason := "unknown"
	switch {
	case errors.Is(err, domain.ErrAssertionExpired):
		reason = "expired"
	case errors.Is(err, domain.ErrAssertionAudienceMismatch):
		reason = "audience"
	case errors.Is(err, domain.ErrAssertionTypeMismatch):
		reason = "type"
	case errors.Is(err, domain.ErrAssertionInvalid):
		reason = "invalid"
	}
	s.recordDenied(ctx, "", reason)
}

// validateDPoP validates a DPoP proof JWT and consumes its JTI for replay detection.
func (s *JWTBearerService) validateDPoP(ctx context.Context, span trace.Span, proof, method, reqURL, accessTokenHash string) (string, error) {
	if s.dpopStore == nil || s.dpopConfig == nil {
		return "", nil
	}

	result, err := crypto.ValidateProof(proof, method, reqURL, "", accessTokenHash, s.dpopConfig.ProofLifetime)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "DPoP proof validation failed")
		return "", err
	}

	if s.dpopConfig.RequireNonce {
		if result.Nonce == "" {
			span.RecordError(domain.ErrDPoPNonceRequired)
			span.SetStatus(codes.Error, "DPoP nonce required but missing")
			return "", domain.ErrDPoPNonceRequired
		}
		if err := s.dpopStore.ValidateNonce(ctx, result.Nonce); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "DPoP nonce validation failed")
			return "", domain.ErrDPoPNonceMismatch
		}
	}

	jtiExpiry := time.Now().Add(s.dpopConfig.ProofLifetime * 2)
	if err := s.dpopStore.ConsumeJTI(ctx, result.JTI, jtiExpiry); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "DPoP JTI replay")
		return "", err
	}

	return result.JKT, nil
}

// isKnownResource checks whether the resource URI is registered.
func (s *JWTBearerService) isKnownResource(_ context.Context, resource string) bool {
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

// extractIssuerFromJWT extracts the "iss" claim from a JWT without verifying the signature.
// This is used for IdP lookup before we have the JWKS.
func extractIssuerFromJWT(raw string) (string, error) {
	tok, err := jose.ParseSigned(raw, crypto.AssertionAlgorithms())
	if err != nil {
		return "", fmt.Errorf("parse JWT: %w", err)
	}

	payload := tok.UnsafePayloadWithoutVerification()

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}

	if claims.Issuer == "" {
		return "", fmt.Errorf("missing iss claim")
	}

	return claims.Issuer, nil
}
