package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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

var _ input.TokenExchangePort = (*TokenExchangeService)(nil)

// TokenExchangeService implements RFC 8693 token exchange.
// Agent exchanges a token to act on behalf of a user (impersonation) or
// alongside one (delegation). Full audit trail on delegation chain.
type TokenExchangeService struct {
	clients        output.ClientStore
	machineTokens  output.MachineTokenStore
	jwksVerify     JWKSBuildProvider
	jwksSign       JWKSSigningKeyProvider
	revocation     output.RevocationStore
	audit          AuditRecorder
	issuerProvider output.IssuerProvider
	teConfig       output.TokenExchangeConfigProvider
	logger         *slog.Logger
	tracer         trace.Tracer
	metrics        *observability.Metrics

	// DPoP support (RFC 9449) — optional.
	dpopStore  output.DPoPNonceStore
	dpopConfig output.DPoPConfigProvider

	// Agent identity — optional. When set, attaches agent_id/agent_chain claims.
	agentIdentity *AgentIdentityService

	// Resource-aware scope validation — optional. When set, scope validation checks
	// scopes against the target resource's registered scopes instead of the subject token's scopes.
	resources ResourceLister

	// Unified gate dispatch dependencies (; mandatory now).
	// When req.Resource resolves to a row in the unified table, Exchange
	// dispatches via these services. When req.Resource is empty, Exchange
	// keeps the legacy inline mint path for refresh-style exchanges that
	// target the issuer rather than a specific MCP.
	registry      *ResourceRegistry
	consentGrants output.ConsentGrantStore
	mintIssuer    *MintIssuer
	brokerIssuer  *BrokerIssuer

	// Cross-Mint fronting links. Optional — nil disables the
	// fronted-path branch in dispatchMint.
	fronting *FrontingService
}

// NewTokenExchangeService creates a new token exchange service.  makes
// the registry + consentGrants + mintIssuer + brokerIssuer arguments
// mandatory: any non-empty `resource` parameter on /oauth/token must resolve
// against the unified registry, with no inline-mint fall-through.
func NewTokenExchangeService(
	clients output.ClientStore,
	machineTokens output.MachineTokenStore,
	jwksVerify JWKSBuildProvider,
	jwksSign JWKSSigningKeyProvider,
	revocation output.RevocationStore,
	issuerProvider output.IssuerProvider,
	teConfig output.TokenExchangeConfigProvider,
	registry *ResourceRegistry,
	consentGrants output.ConsentGrantStore,
	mintIssuer *MintIssuer,
	brokerIssuer *BrokerIssuer,
	obs *observability.Provider,
	auditRec AuditRecorder,
) *TokenExchangeService {
	if issuerProvider == nil {
		panic("services.NewTokenExchangeService: issuerProvider is required")
	}
	if teConfig == nil {
		panic("NewTokenExchangeService: teConfig must not be nil")
	}
	return &TokenExchangeService{
		clients:        clients,
		machineTokens:  machineTokens,
		jwksVerify:     jwksVerify,
		jwksSign:       jwksSign,
		revocation:     revocation,
		audit:          auditRec,
		issuerProvider: issuerProvider,
		teConfig:       teConfig,
		registry:       registry,
		consentGrants:  consentGrants,
		mintIssuer:     mintIssuer,
		brokerIssuer:   brokerIssuer,
		logger:         obs.Logger.With("component", "token_exchange"),
		tracer:         obs.Tracer,
		metrics:        obs.Metrics,
	}
}

// WithDPoP enables DPoP proof-of-possession support on the token exchange service.
func (s *TokenExchangeService) WithDPoP(store output.DPoPNonceStore, cfg output.DPoPConfigProvider) {
	s.dpopStore = store
	s.dpopConfig = cfg
}

// WithAgentIdentity enables agent identity claim attachment.
func (s *TokenExchangeService) WithAgentIdentity(ai *AgentIdentityService) {
	s.agentIdentity = ai
}

// WithResourceScopes enables resource-aware scope validation on the token exchange service.
// When set, scope validation for cross-resource exchanges checks scopes against the target
// resource's registered scopes instead of requiring a strict subset of the subject token's scopes.
func (s *TokenExchangeService) WithResourceScopes(resources ResourceLister) {
	s.resources = resources
}

// WithFronting enables operator-declared cross-Mint fronting.
// When set, dispatchMint consults the FrontingService for a (source, target)
// link before applying the user-consent gate; a link makes the operator
// declaration the consent surrogate. nil keeps direct-only behavior.
func (s *TokenExchangeService) WithFronting(fr *FrontingService) {
	s.fronting = fr
}

// Exchange performs an RFC 8693 token exchange.
func (s *TokenExchangeService) Exchange(ctx context.Context, req input.TokenExchangeRequest) (*input.TokenExchangeResponse, error) {
	ctx, span := s.tracer.Start(ctx, "TokenExchangeService.Exchange")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("grant_type", "token_exchange"),
	)
	start := time.Now()

	// 0. Validate required fields.
	if req.SubjectToken == "" {
		return nil, fmt.Errorf("%w: subject_token is required", domain.ErrInvalidGrant)
	}

	// 1. Authenticate requesting client.
	actingClient, err := s.authenticateClient(ctx, span, req.ClientID, req.ClientSecret)
	if err != nil {
		s.recordDenied(ctx, req.ClientID, "invalid_client")
		return nil, err
	}

	// 2. Check client is permitted for token exchange grant.
	if !hasGrantType(actingClient.GrantTypes, token.GrantTypeTokenExchange) {
		span.RecordError(domain.ErrUnauthorizedClient)
		span.SetStatus(codes.Error, "token exchange grant not allowed")
		s.recordDenied(ctx, req.ClientID, "unauthorized_client")
		return nil, domain.ErrUnauthorizedClient
	}

	// 3. Validate subject_token_type is a known URN.
	if !token.IsValidSubjectTokenType(req.SubjectTokenType) {
		span.SetStatus(codes.Error, "invalid subject_token_type")
		s.recordDenied(ctx, req.ClientID, "invalid_request")
		return nil, domain.ErrInvalidGrant
	}

	// 4. Resolve issuer once (after all input validation) and decode subject_token.
	issuer, err := s.issuerProvider.Issuer(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer: %w", err)
	}

	// 4a. Resolve per-request token-exchange config.
	teCfg, err := s.teConfig.Config(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve token exchange config: %w", err)
	}

	subjectClaims, err := s.verifyToken(ctx, span, issuer, req.SubjectToken, "subject_token")
	if err != nil {
		s.recordDenied(ctx, req.ClientID, "invalid_subject_token")
		return nil, err
	}

	// 4b. Validate subject token was issued by this AS (issuer check).
	// Note: we do NOT check audience here. Resource-scoped tokens have
	// aud=[resource_url], not aud=[issuer]. The JWT signature verification
	// in step 4 already proves the token was issued by this AS.
	if subjectClaims.Issuer != issuer {
		span.RecordError(domain.ErrInvalidGrant)
		span.SetStatus(codes.Error, "subject token issuer does not match this AS")
		s.recordDenied(ctx, req.ClientID, "invalid_issuer")
		return nil, domain.ErrInvalidGrant
	}

	// 5. Check subject token is not revoked.
	if revokeErr := s.checkRevocation(ctx, span, subjectClaims); revokeErr != nil {
		s.recordDenied(ctx, req.ClientID, "subject_token_revoked")
		return nil, revokeErr
	}

	// 5a. Unified-dispatch fork ( +  registry-or-bust). When the
	// caller names a resource, it MUST resolve to a row in the unified
	// table; ErrResourceNotFound is final, mapped to invalid_target by the
	// handler. The legacy inline mint path below survives only for the
	// req.Resource == "" case (refresh-style exchanges that target the
	// issuer rather than a specific MCP).
	if req.Resource != "" {
		target, resolveErr := s.registry.Resolve(ctx, req.Resource)
		switch {
		case resolveErr == nil:
			return s.handleViaRegistry(ctx, span, start, req, issuer, subjectClaims, target, teCfg)
		case errors.Is(resolveErr, domain.ErrResourceNotFound):
			span.RecordError(resolveErr)
			span.SetStatus(codes.Error, "resource not found in unified registry")
			s.recordDenied(ctx, req.ClientID, "resource_not_found")
			return nil, resolveErr
		case errors.Is(resolveErr, domain.ErrAmbiguousResource):
			span.RecordError(resolveErr)
			span.SetStatus(codes.Error, "ambiguous resource identifier")
			s.recordDenied(ctx, req.ClientID, "ambiguous_resource")
			return nil, resolveErr
		default:
			span.RecordError(resolveErr)
			span.SetStatus(codes.Error, "resource resolve failed")
			s.recordDenied(ctx, req.ClientID, "resource_resolve_failed")
			return nil, fmt.Errorf("resolve resource: %w", resolveErr)
		}
	}

	// 6. Validate actor_token if present.
	var actorClaims *crypto.AccessTokenClaims
	if req.ActorToken != "" {
		if req.ActorTokenType != "" && !token.IsValidSubjectTokenType(req.ActorTokenType) {
			span.SetStatus(codes.Error, "invalid actor_token_type")
			s.recordDenied(ctx, req.ClientID, "invalid_request")
			return nil, domain.ErrInvalidGrant
		}
		ac, actorErr := s.verifyToken(ctx, span, issuer, req.ActorToken, "actor_token")
		if actorErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_actor_token")
			return nil, actorErr
		}
		actorClaims = ac
	}

	// 7. Validate requested scope.
	subjectScopes := scope.Parse(subjectClaims.Scope)

	var effectiveScopes scope.Set

	if req.Scope != "" {
		requestedScopes := scope.Parse(req.Scope)

		// Subset check against the subject token's own scopes. Prevents
		// scope escalation on refresh-style exchanges (req.Resource == "")
		// where there is no resource catalog to validate against. The
		// registry-dispatched paths (req.Resource != "") return earlier;
		// they enforce scope bounds via validateAgainstCatalog and the
		// consent_grants row, not by inspecting the subject token.
		if !requestedScopes.IsSubset(subjectScopes) {
			span.RecordError(domain.ErrInvalidScope)
			span.SetStatus(codes.Error, "scope escalation: requested scope exceeds subject scope")
			s.recordDenied(ctx, req.ClientID, "invalid_scope")
			return nil, domain.ErrInvalidScope
		}
		effectiveScopes = requestedScopes
	} else {
		// No explicit scope param — inherit the subject token's scopes.
		effectiveScopes = subjectScopes
	}

	// 8. Policy check: is this exchange authorized?
	if policyErr := s.checkPolicy(ctx, span, req.ClientID, subjectClaims, actorClaims, teCfg); policyErr != nil {
		s.recordDenied(ctx, req.ClientID, "policy_denied")
		return nil, policyErr
	}

	// 9. Chain depth check.
	// Compute the resulting act claim: extend chain when actor_token present,
	// otherwise preserve the existing act claim from the subject token.
	// This prevents delegation chain laundering via self-exchange without actor_token.
	// Strip RFC 8693 §4.1 ¶2 non-identity claims from any inner hops
	// carried by the subject token before we re-emit them. No-op today
	// (authserver never stamps them) but load-bearing once federation /
	// cross-issuer subject tokens are accepted.
	existingAct := token.ActClaimFromMap(subjectClaims.Act).SanitizeNonIdentityClaims()
	resultingAct := existingAct
	if actorClaims != nil {
		// Stamp the acting client's type on the new outermost hop.
		// Only this newly added hop is stamped; inner hops from the
		// subject token pass through unchanged (RFC 8693 §4.1 ¶6 —
		// only the outermost actor is authoritative for access
		// control; inner-hop metadata is informational only).
		actorType := "service"
		if actingClient.IsAgent {
			actorType = "agent"
		}
		resultingAct = &token.ActClaim{
			Sub:    req.ClientID, // the acting party
			Act:    existingAct,  // chain from subject token
			Extras: map[string]interface{}{"actor_type": actorType},
		}
	}
	if resultingAct != nil && resultingAct.Depth() > teCfg.MaxChainDepth {
		span.RecordError(domain.ErrTokenExchangeChainTooDeep)
		span.SetStatus(codes.Error, "delegation chain too deep")
		s.recordDenied(ctx, req.ClientID, "chain_too_deep")
		return nil, domain.ErrTokenExchangeChainTooDeep
	}

	// 10. Validate DPoP proof if present (RFC 9449).
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL)
		if dpopErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_dpop_proof")
			return nil, dpopErr
		}
		dpopJKT = jkt
	}

	// 11. Build the issued token claims.
	now := time.Now().UTC()
	expiry := now.Add(teCfg.TokenExpiry)
	jti := crypto.GenerateRandomString(16)

	sk, err := s.jwksSign.GetSigningKey(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	aud := []string{req.Resource}
	if req.Resource == "" {
		// Use subject token's audience if no resource specified.
		if len(subjectClaims.Audience) > 0 {
			aud = subjectClaims.Audience
		} else {
			aud = []string{issuer}
		}
	}

	claims := crypto.AccessTokenClaims{
		Issuer:    issuer,
		Subject:   subjectClaims.Subject, // sub is always from the subject token
		Audience:  aud,
		ClientID:  req.ClientID,
		Scope:     effectiveScopes.String(),
		JTI:       jti,
		IssuedAt:  now.Unix(),
		Expiry:    expiry.Unix(),
		NotBefore: now.Unix(),
	}

	// Propagate cnf.jkt from subject token (DPoP binding) if present and no new DPoP proof.
	if subjectClaims.Cnf != nil && dpopJKT == "" {
		claims.Cnf = subjectClaims.Cnf
	}
	// New DPoP proof overrides subject cnf.
	if dpopJKT != "" {
		claims.Cnf = map[string]interface{}{"jkt": dpopJKT}
	}

	// Propagate existing delegation chain, extending it when actor_token is present.
	if resultingAct != nil {
		claims.Act = token.ActClaimToMap(resultingAct)
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

	// 12. Store in MachineTokenStore for revocability.
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
		return nil, fmt.Errorf("save exchanged token: %w", err)
	}

	tokenType := "Bearer"
	if claims.Cnf != nil {
		if _, hasJKT := claims.Cnf["jkt"]; hasJKT {
			tokenType = "DPoP"
		}
	}

	isDelegation := resultingAct != nil

	// 13. Emit audit event + metrics.
	exchangeType := "impersonation"
	if isDelegation {
		exchangeType = "delegation"
	}

	s.logger.InfoContext(ctx, "token exchanged",
		"client_id", req.ClientID,
		"jti", jti,
		"sub", subjectClaims.Subject,
		"subject_client_id", subjectClaims.ClientID,
		"exchange_type", exchangeType,
		"scopes", effectiveScopes.String(),
		"token_type", tokenType,
	)

	if s.metrics != nil && s.metrics.TokenExchangeTotal != nil {
		s.metrics.TokenExchangeTotal.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("type", exchangeType),
		))
	}
	if s.metrics != nil && s.metrics.TokensIssued != nil {
		s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("grant_type", "token_exchange"),
		))
	}
	if s.metrics != nil && s.metrics.TokenIssuanceDuration != nil {
		s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
			attribute.String("grant_type", "token_exchange"),
		))
	}

	if s.audit != nil {
		actorClientID := ""
		if actorClaims != nil {
			actorClientID = actorClaims.ClientID
		}
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenExchanged,
			subjectClaims.Subject, req.ClientID, "",
			fmt.Sprintf("jti=%s sub=%s subject_client=%s actor_client=%s type=%s scopes=%s",
				jti, subjectClaims.Subject, subjectClaims.ClientID, actorClientID, exchangeType, effectiveScopes.String()),
		))
	}

	return &input.TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: token.TokenTypeAccessToken,
		TokenType:       tokenType,
		ExpiresIn:       int(teCfg.TokenExpiry.Seconds()),
		Scope:           effectiveScopes.String(),
	}, nil
}

// authenticateClient looks up a client, verifies it's active, and validates the secret.
func (s *TokenExchangeService) authenticateClient(ctx context.Context, span trace.Span, clientID, clientSecret string) (*client.Client, error) {
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
		span.SetStatus(codes.Error, "public clients cannot use token exchange")
		return nil, domain.ErrInvalidClient
	}

	if err := crypto.CompareClientSecret(c.SecretHash, clientSecret); err != nil {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "invalid client_secret")
		return nil, domain.ErrInvalidClient
	}

	return c, nil
}

// verifyToken parses, verifies, and validates a JWT token (subject or actor).
// issuer is resolved once by the caller (Exchange or dispatchMint) and passed
// here to avoid redundant resolution on every token verification.
func (s *TokenExchangeService) verifyToken(ctx context.Context, span trace.Span, issuer, rawToken, label string) (*crypto.AccessTokenClaims, error) {
	jwks, err := s.jwksVerify.BuildJWKS(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, fmt.Sprintf("build JWKS for %s verification", label))
		return nil, fmt.Errorf("build JWKS: %w", err)
	}

	claims, err := crypto.VerifyAccessTokenWithIssuer(rawToken, jwks, issuer)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, fmt.Sprintf("%s verification failed", label))
		return nil, domain.ErrInvalidGrant
	}

	return claims, nil
}

// checkRevocation checks if a token has been revoked.
func (s *TokenExchangeService) checkRevocation(ctx context.Context, span trace.Span, claims *crypto.AccessTokenClaims) error {
	if claims.JTI == "" {
		return nil
	}

	// Check machine token store for machine tokens (sub == client_id).
	isMachineToken := claims.Subject == claims.ClientID
	if isMachineToken && s.machineTokens != nil {
		mt, err := s.machineTokens.GetByJTI(ctx, claims.JTI)
		if err == nil && mt != nil && mt.Revoked {
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "subject token revoked")
			return domain.ErrInvalidGrant
		}
	}

	// Check revocation store for user tokens.
	if !isMachineToken && s.revocation != nil {
		revoked, err := s.revocation.IsRevoked(ctx, claims.JTI)
		if err == nil && revoked {
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "subject token revoked")
			return domain.ErrInvalidGrant
		}
	}

	return nil
}

// checkPolicy verifies that the requesting client is authorized to exchange this token.
//
// The unified-dispatch path does not call into checkPolicy — its
// operator gate uses target.Policy.Exchange.AllowedClientIDs from the resource
// row. checkPolicy survives only for the legacy mint fall-through used when
// the requested resource has no row in the unified table yet. The
// cross-client config + DB allowlist seams are retired; the only
// cross-client authorization left here is the per-token may_act claim.
func (s *TokenExchangeService) checkPolicy(_ context.Context, span trace.Span, requestingClientID string, subjectClaims, _ *crypto.AccessTokenClaims, teCfg output.TokenExchangeConfig) error {
	// Self-exchange: client is exchanging its own token.
	if requestingClientID == subjectClaims.ClientID {
		if teCfg.AllowSelfExchange {
			return nil
		}
		span.RecordError(domain.ErrTokenExchangeNotAuthorized)
		span.SetStatus(codes.Error, "self-exchange not allowed")
		return domain.ErrTokenExchangeNotAuthorized
	}

	// Cross-client exchange: check may_act claim in subject token.
	if subjectClaims.MayAct != nil {
		if actorSub, ok := subjectClaims.MayAct["sub"].(string); ok && actorSub == requestingClientID {
			return nil
		}
	}

	span.RecordError(domain.ErrTokenExchangeNotAuthorized)
	span.SetStatus(codes.Error, "cross-client exchange not authorized")
	return domain.ErrTokenExchangeNotAuthorized
}

// validateDPoP validates a DPoP proof JWT and consumes its JTI for replay detection.
//
// Token-exchange call sites never bind the proof to an access-token hash
// (the proof is bound to the request, not to a downstream credential),
// so the underlying crypto.ValidateProof's `ath` parameter is always
// empty. Kept inside this helper to keep the four callers identical.
func (s *TokenExchangeService) validateDPoP(ctx context.Context, span trace.Span, proof, method, reqURL string) (string, error) {
	if s.dpopStore == nil || s.dpopConfig == nil {
		return "", nil
	}

	dpopCfg, err := s.dpopConfig.Config(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("resolve dpop config: %w", err)
	}

	// When the resolved config reports DPoP disabled, ignore the proof and
	// issue a bearer token (no sender-constraining). The default build only
	// wires this provider when DPoP is enabled, so this is byte-identical
	// there; a substitute provider may toggle it per request.
	if !dpopCfg.Enabled {
		return "", nil
	}

	result, err := crypto.ValidateProof(proof, method, reqURL, "", "", dpopCfg.ProofLifetime)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "DPoP proof validation failed")
		return "", err
	}

	if dpopCfg.RequireNonce {
		if result.Nonce == "" {
			return "", domain.ErrDPoPNonceRequired
		}
		if err := s.dpopStore.ValidateNonce(ctx, result.Nonce); err != nil {
			return "", domain.ErrDPoPNonceMismatch
		}
	}

	jtiExpiry := time.Now().Add(dpopCfg.ProofLifetime * 2)
	if err := s.dpopStore.ConsumeJTI(ctx, result.JTI, jtiExpiry); err != nil {
		return "", err
	}

	return result.JKT, nil
}

// recordDenied increments the denied counter with a reason label.
func (s *TokenExchangeService) recordDenied(ctx context.Context, clientID, reason string) {
	s.countDenied(ctx, reason)
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenExchangeDenied,
			clientID, clientID, "",
			fmt.Sprintf("reason=%s", reason),
		))
	}
}

// countDenied increments the denial metric without emitting an audit event.
// Callers that emit their own, richer denial event use this so a single denial
// produces a single audit row.
func (s *TokenExchangeService) countDenied(ctx context.Context, reason string) {
	if s.metrics != nil && s.metrics.TokenExchangeDenied != nil {
		s.metrics.TokenExchangeDenied.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", reason),
		))
	}
}

// handleViaRegistry routes a registry-resolved exchange request to the
// matching dispatcher (Mint or Broker). Scope-catalog validation runs once
// here so both branches share the rejection. In the unified model the
// resource's own scope catalog is authoritative — there is no
// coarse-to-fine translation layer (the legacy expansion path is gone).
//
// Exception: fronted Mint→Broker exchanges. When the subject token
// resolves to a source Mint and a fronting link exists to the broker target,
// req.Scope carries SOURCE-SIDE scope names (e.g. "tool:list"), not the
// broker resource's catalog scope names (e.g. "readonly"). Catalog
// validation against the broker resource would incorrectly reject these
// source-side tokens. dispatchBroker/dispatchFrontedBroker performs its own
// scope validation via validateBrokerTargets (against subject claims) and the broker
// catalog's upstream mapping, so the pre-dispatch catalog check is skipped
// for this case only.
func (s *TokenExchangeService) handleViaRegistry(
	ctx context.Context,
	span trace.Span,
	start time.Time,
	req input.TokenExchangeRequest,
	issuer string,
	subjectClaims *crypto.AccessTokenClaims,
	target *resource.Resource,
	teCfg output.TokenExchangeConfig,
) (*input.TokenExchangeResponse, error) {
	span.SetAttributes(
		attribute.String("resource_id", target.ID),
		attribute.String("resource_slug", target.Slug),
		attribute.String("backend_kind", string(target.BackendKind)),
	)

	// Wiring guard: registry was set but the matching Issuer/ConsentGrants
	// dependencies were not. Surface as an explicit error rather than
	// silently falling through (the caller already chose this dispatch
	// path by registering the resource in the unified table).
	if s.consentGrants == nil {
		err := fmt.Errorf("token exchange: consent grant store not wired for unified dispatch")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.recordDenied(ctx, req.ClientID, "wiring_incomplete")
		return nil, err
	}

	// Skip catalog validation for fronted Mint→Broker exchanges: the
	// subject token's audience names a source Mint resource and a fronting
	// link exists to the broker target. In this case req.Scope already
	// names upstream-target scopes directly (the gateway speaks in target
	// terms), and the source-side consent recorded in the subject token's
	// scope claim is in MCP scope names. Neither side is meant to match
	// the broker target's resource catalog: validateBrokerTargets gates
	// the request against the link's ScopeMap instead — reverse-walking
	// from each requested target to the source key(s) that map to it and
	// confirming the subject token consented to at least one. For all
	// other exchanges (direct Mint, direct Broker, fronted Mint→Mint)
	// req.Scope is in target-catalog terms and the check below is correct.
	isFrontedBroker := target.IsBroker() && s.isFrontedBrokerExchange(ctx, subjectClaims.Audience, target.Slug)
	if !isFrontedBroker {
		if scopeErr := s.validateAgainstCatalog(req.Scope, target); scopeErr != nil {
			span.RecordError(scopeErr)
			span.SetStatus(codes.Error, "scope not in resource catalog")
			s.recordDenied(ctx, req.ClientID, "scope_not_in_catalog")
			return nil, scopeErr
		}
	}

	switch target.BackendKind {
	case resource.BackendMint:
		return s.dispatchMint(ctx, span, start, req, issuer, subjectClaims, target, teCfg)
	case resource.BackendBroker:
		return s.dispatchBroker(ctx, span, start, req, subjectClaims, target)
	default:
		err := fmt.Errorf("token exchange: unknown backend_kind %q for resource %q", target.BackendKind, target.Slug)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.recordDenied(ctx, req.ClientID, "unknown_backend_kind")
		return nil, err
	}
}

// isFrontedBrokerExchange returns true when the subject token's audience
// resolves to a source Mint resource AND a fronting link from that source
// to targetSlug exists. Used by handleViaRegistry to skip pre-dispatch
// catalog validation whose scope-name space (source-side) differs from the
// broker resource catalog (broker-side).
func (s *TokenExchangeService) isFrontedBrokerExchange(ctx context.Context, audience []string, targetSlug string) bool {
	source := s.resolveSourceForFronting(ctx, audience)
	if source == nil || source.Slug == targetSlug {
		return false
	}
	_, err := s.fronting.Get(ctx, source.Slug, targetSlug)
	return err == nil
}

// enforceSubjectScopeCeiling implements the RFC 8693 narrowing arm of the
// hybrid authority model (ADR-002). When the subject token carries an
// explicit scope claim, the requested scopes MUST be a subset — exchanging
// a scoped token for a broader-scoped token is rejected with invalid_scope
// regardless of what the consent / attestation gates would otherwise allow.
//
// When the subject token has no scope claim (identity-only — ID token,
// session token, federation assertion, or an AS-issued token that the AS
// chose to leave un-scoped), the ceiling does not fire. The dispatcher's
// consent grant (Mint) or agent-attestation grant (Broker) is then the sole
// authority for the resulting token's scope. This preserves the MCP /
// agent-architecture model where small identity tokens drive per-call
// scope decisions through the consent ledger.
//
// Fronted exchanges do NOT call this — the fronting-link source-coverage
// gate is the ceiling equivalent for the fronted name space (target scopes
// reverse-walked via link.ScopeMap to source scopes, then subject scope
// checked against that derived set). The two checks operate in different
// scope namespaces and would be incompatible if stacked.
func (s *TokenExchangeService) enforceSubjectScopeCeiling(
	ctx context.Context,
	span trace.Span,
	req input.TokenExchangeRequest,
	subjectClaims *crypto.AccessTokenClaims,
	dispatchLabel string,
) error {
	if subjectClaims.Scope == "" {
		return nil // identity-only subject: consent/attestation is sole authority
	}
	requestedScopes := scope.Parse(req.Scope)
	if requestedScopes.IsEmpty() {
		return nil // no scope requested: nothing to bound
	}
	subjectScopes := scope.Parse(subjectClaims.Scope)
	if !requestedScopes.IsSubset(subjectScopes) {
		span.RecordError(domain.ErrInvalidScope)
		span.SetStatus(codes.Error, "scope escalation: requested scope exceeds subject scope (hybrid ceiling)")
		s.logger.InfoContext(ctx, dispatchLabel+" dispatch denied: requested scope exceeds subject token scope",
			"client_id", req.ClientID,
			"sub", subjectClaims.Subject,
			"requested_scope", req.Scope,
			"subject_scope", subjectClaims.Scope,
		)
		s.recordDenied(ctx, req.ClientID, "subject_scope_ceiling")
		return domain.ErrInvalidScope
	}
	return nil
}

// validateAgainstCatalog checks that every fine scope in scopeStr is
// declared on target. Empty scopeStr is allowed — the issued token simply
// inherits the empty scope set rather than escalating, since downstream
// dispatchers do not expand scopes.
func (s *TokenExchangeService) validateAgainstCatalog(scopeStr string, target *resource.Resource) error {
	if scopeStr == "" {
		return nil
	}
	catalog := make(map[string]struct{}, len(target.Scopes))
	for _, sc := range target.Scopes {
		catalog[sc.Name] = struct{}{}
	}
	for _, sc := range strings.Fields(scopeStr) {
		if _, ok := catalog[sc]; !ok {
			return fmt.Errorf("%w: scope %q not in catalog for resource %q", domain.ErrScopeNotInCatalog, sc, target.Slug)
		}
	}
	return nil
}

// dispatchMint runs the unified Mint flow:
//
//  1. operator gate against target.Policy.Exchange.AllowedClientIDs.
//     Runs first (matching dispatchBroker) so operator policy fails fast
//     without consulting fronting or consent state. An empty allowlist
//     admits any client.
//  2. fronted-path detection — when a (source, target) fronting link
//     exists AND target is Mint, the operator declaration replaces
//     the user-consent gate. Skipped otherwise; direct path proceeds.
//  3. fronted scope-coverage gate, fronted path only: every requested
//     target scope must be mappable by the link and the subject_token
//     must already cover the source scope the reverse-walk derives for
//     it. On a multi-source map that is the lexicographically first
//     source and only that one — see requiredSourceScopesForTargets;
//     the fronted-broker path does NOT gate the same way.
//  4. subject-scope ceiling (ADR-002), direct path only — the fronted
//     path bounded its scopes in step 3. Applies to self-exchange too.
//  5. user-consent gate against consent_grants (user, agent, target),
//     skipped on the fronted path and on a self-exchange.
//  6. actor token verification, when an actor_token is present.
//  7. act-chain build + chain-depth check. Direct path keeps legacy
//     shape; fronted path applies Option β (issued client_id =
//     source.Slug; agent at act.act).
//  8. DPoP proof — fresh proof, else cnf.jkt inherited from the subject.
//  9. agent identity attachment.
//  10. MintIssuer.Issue → JWT + issuances row.
//  11. audit + metrics + RFC 8693 response shape (audit detail and the
//     TokenExchangeTotal counter both carry chain_kind ∈ {direct,
//     fronted} and the source/target labels).
//
// Direct-path behavior is byte-identical to pre- (same client_id,
// same act, same audit shape — the chain_kind=direct + empty via_link
// suffix on the audit detail is additive). Mint→Broker fronting is
// territory and is logged-but-ignored when seen here.
func (s *TokenExchangeService) dispatchMint(
	ctx context.Context,
	span trace.Span,
	start time.Time,
	req input.TokenExchangeRequest,
	issuer string,
	subjectClaims *crypto.AccessTokenClaims,
	target *resource.Resource,
	teCfg output.TokenExchangeConfig,
) (*input.TokenExchangeResponse, error) {
	if s.mintIssuer == nil {
		err := fmt.Errorf("token exchange: mint issuer not wired for unified Mint dispatch")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.recordDenied(ctx, req.ClientID, "wiring_incomplete")
		return nil, err
	}

	span.SetAttributes(attribute.String("dispatch", "mint"))

	agentClientID := subjectClaims.ClientID

	// Operator gate. Empty allowlist = any client may act
	// (Brief §1). When non-empty, req.ClientID must appear in the list.
	// Runs first (matching dispatchBroker) so operator policy fails fast
	// without consulting fronting / consent state — both for fronted and
	// direct paths.
	if !operatorAllowsClient(target.Policy.Exchange.AllowedClientIDs, req.ClientID) {
		span.RecordError(domain.ErrTokenExchangeNotAuthorized)
		span.SetStatus(codes.Error, "operator gate rejected client")
		s.logger.InfoContext(ctx, "mint dispatch denied: client not in operator allowlist",
			"client_id", req.ClientID,
			"resource_slug", target.Slug,
		)
		s.recordDenied(ctx, req.ClientID, "operator_gate_denied")
		return nil, domain.ErrTokenExchangeNotAuthorized
	}

	// Fronted-path detection. When a (source, target) fronting link
	// exists AND target is Mint, the operator declaration replaces the
	// third-bound user-consent gate. Resolution returns nil on any miss
	// (unwired, unresolvable, non-Mint subject, aud=issuer) — that path
	// keeps the legacy direct-path semantics byte-identical.
	//
	// Mint→Broker fronting is (Inc N+3); the link is ignored here
	// when target.IsBroker(), with a warn so operators see why the
	// declaration isn't yet honored on broker targets.
	var (
		frontedSource *resource.Resource
		frontedLink   *resource.FrontingLink
	)
	if source := s.resolveSourceForFronting(ctx, subjectClaims.Audience); source != nil && source.Slug != target.Slug {
		link, getErr := s.fronting.Get(ctx, source.Slug, target.Slug)
		switch {
		case getErr == nil && target.IsMint():
			frontedSource = source
			frontedLink = link
		case getErr == nil && !target.IsMint():
			s.logger.WarnContext(ctx, "fronting link exists but target is not Mint — ignored",
				"source_slug", source.Slug,
				"target_slug", target.Slug,
				"target_kind", string(target.BackendKind),
			)
		case errors.Is(getErr, domain.ErrFrontingLinkNotFound):
			// No link — direct path proceeds.
		default:
			span.RecordError(getErr)
			span.SetStatus(codes.Error, "fronting link lookup failed")
			s.recordDenied(ctx, req.ClientID, "fronting_lookup_failed")
			return nil, fmt.Errorf("fronting lookup: %w", getErr)
		}
	}

	// Fronted scope-coverage gate. Replaces the user-consent gate
	// when a fronting link drives the exchange: every requested target
	// scope must be present as a value somewhere in the link's ScopeMap,
	// and the subject token MUST already cover the source-side scopes the
	// reverse-walk derives. The operator declaration is the consent
	// surrogate; no consent_grants row is consulted.
	//
	// "the scopes the reverse-walk derives" is load-bearing: on a
	// multi-source map that is one specific source key per target, not
	// any covering one. dispatchFrontedBroker's equivalent gate is an
	// any-of check, so the two fronted paths can disagree on the same
	// link.
	if frontedLink != nil {
		requestedTargets := strings.Fields(req.Scope)
		requiredSources, unmapped := requiredSourceScopesForTargets(frontedLink.ScopeMap, requestedTargets)
		if len(unmapped) > 0 {
			span.SetStatus(codes.Error, "fronting: target scope not in scope_map")
			s.logger.InfoContext(ctx, "fronted dispatch denied: target scope not present in fronting link scope_map",
				"client_id", req.ClientID,
				"agent_client_id", agentClientID,
				"sub", subjectClaims.Subject,
				"source_slug", frontedSource.Slug,
				"target_slug", target.Slug,
				"unmapped_scopes", unmapped,
			)
			s.recordDenied(ctx, req.ClientID, "fronting_scope_unmapped")
			return nil, fmt.Errorf("%w: target scope(s) %v not present in fronting link scope_map (source=%s target=%s)",
				domain.ErrInvalidScope, unmapped, frontedSource.Slug, target.Slug)
		}
		subjectScopes := scope.Parse(subjectClaims.Scope)
		for _, src := range requiredSources {
			if !subjectScopes.Contains(src) {
				span.SetStatus(codes.Error, "fronting: subject token missing source scope")
				s.logger.InfoContext(ctx, "fronted dispatch denied: subject_token missing required source scope",
					"client_id", req.ClientID,
					"agent_client_id", agentClientID,
					"sub", subjectClaims.Subject,
					"source_slug", frontedSource.Slug,
					"target_slug", target.Slug,
					"missing_source_scope", src,
				)
				s.recordDenied(ctx, req.ClientID, "fronting_subject_scope_insufficient")
				return nil, fmt.Errorf("%w: subject_token missing source scope %q required by fronting link (source=%s target=%s)",
					domain.ErrInvalidScope, src, frontedSource.Slug, target.Slug)
			}
		}
	}

	// Hybrid subject-scope ceiling (ADR-002). Direct-path only — fronted
	// exchanges handled their subject-scope check above against the link's
	// scope_map in source-side names. Applies to self-exchange too: an
	// agent must not be able to widen its own token through self-exchange.
	if frontedLink == nil {
		if scopeErr := s.enforceSubjectScopeCeiling(ctx, span, req, subjectClaims, "mint"); scopeErr != nil {
			return nil, scopeErr
		}
	}

	// Self-exchange skips the consent gate (no third party involved). The
	// operator gate already ran above and restricts nothing when the
	// allowlist is empty, so in that composition only the subject-scope
	// ceiling and catalog validation bound the issued token.
	isSelfExchange := teCfg.AllowSelfExchange && req.ClientID == subjectClaims.ClientID
	if frontedLink == nil && !isSelfExchange {
		grant, getErr := s.consentGrants.Get(ctx, subjectClaims.Subject, agentClientID, target.ID)
		if getErr != nil {
			span.RecordError(getErr)
			span.SetStatus(codes.Error, getErr.Error())
			s.recordDenied(ctx, req.ClientID, "consent_lookup_failed")
			return nil, fmt.Errorf("look up consent grant: %w", getErr)
		}
		if grant == nil {
			span.SetStatus(codes.Error, "consent_required")
			s.logger.InfoContext(ctx, "mint dispatch denied: no active user consent",
				"client_id", req.ClientID,
				"agent_client_id", agentClientID,
				"sub", subjectClaims.Subject,
				"resource_slug", target.Slug,
			)
			s.recordDenied(ctx, req.ClientID, "consent_required")
			return nil, &domain.ConsentRequiredError{
				Service:      target.Slug,
				ResourceSlug: target.Slug,
				Cause:        domain.CauseConsentMissing,
			}
		}
		if missing := scopesNotConsented(grant, strings.Fields(req.Scope)); len(missing) > 0 {
			span.SetStatus(codes.Error, "consent_required:scope_insufficient")
			s.logger.InfoContext(ctx, "mint dispatch denied: requested scope not consented",
				"client_id", req.ClientID,
				"agent_client_id", agentClientID,
				"sub", subjectClaims.Subject,
				"resource_slug", target.Slug,
				"missing_scopes", missing,
			)
			s.recordDenied(ctx, req.ClientID, "scope_not_consented")
			return nil, &domain.ConsentRequiredError{
				Service:       target.Slug,
				ResourceSlug:  target.Slug,
				Cause:         domain.CauseScopeInsufficient,
				MissingScopes: missing,
			}
		}
	}
	requestedScopes := strings.Fields(req.Scope)

	// 6. Validate actor_token if present.
	var actorClaims *crypto.AccessTokenClaims
	if req.ActorToken != "" {
		if req.ActorTokenType != "" && !token.IsValidSubjectTokenType(req.ActorTokenType) {
			span.SetStatus(codes.Error, "invalid actor_token_type")
			s.recordDenied(ctx, req.ClientID, "invalid_request")
			return nil, domain.ErrInvalidGrant
		}
		ac, actorErr := s.verifyToken(ctx, span, issuer, req.ActorToken, "actor_token")
		if actorErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_actor_token")
			return nil, actorErr
		}
		actorClaims = ac
	}

	// 7. Resulting act-chain. Same shape as the legacy path so the JWT
	// 'act' claim remains byte-identical for delegation flows. The
	// fronted branch overrides this: under Option β the issued
	// JWT carries client_id = source resource's slug, and the previous
	// actor — the agent — drops to act.act.sub. Chained exchanges
	// (subject token already has act) prepend without double-inserting
	// the agent. retired the broader operator-hygiene reading of
	// "MCP-slug==client_id"; the issued-token-claim shape here is a
	// scoped Option β v0.1.x contract still in effect, scheduled for
	// revisit in v0.2 alongside SDK migration.
	existingAct := token.ActClaimFromMap(subjectClaims.Act).SanitizeNonIdentityClaims()
	var resultingAct *token.ActClaim
	issuedClientID := req.ClientID

	switch {
	case frontedLink != nil:
		// Option β: the issued JWT carries client_id = source
		// resource's slug; the agent that drove the exchange (req.ClientID
		// — the /oauth/token caller) lives at act.act. If the subject
		// token already carries an act chain (chained exchange A->B->C),
		// prepend the source as the new outermost layer — the existing
		// chain becomes the new act.act, so the agent appears once, at
		// depth 2.
		//
		// This is purely the issued-token claim shape. unwound the
		// broader "operator must satisfy MCP-slug==client_id" reading by
		// moving the agent-attestation gate to policy.runtime.client_ids;
		// only the JWT-claim shape here remains Option β.
		//
		// The inner actor's Sub uses req.ClientID rather than
		// subjectClaims.ClientID because the subject token's client_id
		// in the gateway-fanout pattern is the source slug itself
		// (the gateway IS the OAuth client at /authorize); copying it
		// would collapse act.sub and act.act.sub onto the same value.
		// req.ClientID is always the exchange initiator — the entity the
		// audit + downstream RS care about identifying.
		innerActor := existingAct
		if innerActor == nil {
			innerActor = &token.ActClaim{Sub: req.ClientID}
		}
		resultingAct = &token.ActClaim{
			Sub: frontedSource.Slug,
			Act: innerActor,
		}
		issuedClientID = frontedSource.Slug
	case actorClaims != nil:
		actingClient, lookupErr := s.clients.GetByID(ctx, req.ClientID)
		if lookupErr != nil {
			span.RecordError(lookupErr)
			span.SetStatus(codes.Error, "client lookup failed during act-chain build")
			s.recordDenied(ctx, req.ClientID, "client_lookup_failed")
			return nil, fmt.Errorf("look up acting client: %w", lookupErr)
		}
		actorType := "service"
		if actingClient.IsAgent {
			actorType = "agent"
		}
		resultingAct = &token.ActClaim{
			Sub:    req.ClientID,
			Act:    existingAct,
			Extras: map[string]interface{}{"actor_type": actorType},
		}
	default:
		resultingAct = existingAct
	}
	if resultingAct != nil && resultingAct.Depth() > teCfg.MaxChainDepth {
		span.RecordError(domain.ErrTokenExchangeChainTooDeep)
		span.SetStatus(codes.Error, "delegation chain too deep")
		s.recordDenied(ctx, req.ClientID, "chain_too_deep")
		return nil, domain.ErrTokenExchangeChainTooDeep
	}

	// 8. DPoP proof.
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL)
		if dpopErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_dpop_proof")
			return nil, dpopErr
		}
		dpopJKT = jkt
	}
	// Inherit cnf.jkt from the subject token when no fresh DPoP proof is
	// supplied (parity with the legacy path).
	if dpopJKT == "" && subjectClaims.Cnf != nil {
		if jkt, ok := subjectClaims.Cnf["jkt"].(string); ok {
			dpopJKT = jkt
		}
	}

	// 9. Agent identity. Run AttachClaims against a throwaway claims
	// struct so we can lift AgentID/AgentChain onto the IssueRequest
	// without giving MintIssuer a backreference to AgentIdentityService.
	var actMap map[string]interface{}
	if resultingAct != nil {
		actMap = token.ActClaimToMap(resultingAct)
	}
	agentClaims, err := s.extractAgentIdentity(ctx, span, req.ClientID, actMap)
	if err != nil {
		s.recordDenied(ctx, req.ClientID, "agent_identity_failed")
		return nil, err
	}

	now := time.Now().UTC()
	expiry := now.Add(teCfg.TokenExpiry)
	issueReq := IssueRequest{
		Resource:      target,
		Provider:      nil,
		SubjectUserID: subjectClaims.Subject,
		ActorClientID: issuedClientID,
		Scopes:        requestedScopes,
		AgentIdentity: agentClaims,
		DPoPJKT:       dpopJKT,
		Audience:      []string{target.URI},
		Act:           actMap,
		NotBefore:     now,
		Expiry:        expiry,
	}
	resp, err := s.mintIssuer.Issue(ctx, issueReq)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "mint issuer failed")
		s.recordDenied(ctx, req.ClientID, "mint_issue_failed")
		return nil, err
	}

	s.recordExchangeSuccess(ctx, start, "mint_dispatch")

	chainKind := "direct"
	viaLink := ""
	if frontedLink != nil {
		chainKind = "fronted"
		// ASCII arrow for grep-stability; the unicode "→" doesn't survive
		// log queries everywhere it could end up.
		viaLink = frontedSource.Slug + "->" + target.Slug
	}
	exchangeType := "impersonation"
	if resultingAct != nil && actorClaims != nil {
		exchangeType = "delegation"
	}
	s.logger.InfoContext(ctx, "token exchanged via unified mint dispatch",
		"client_id", req.ClientID,
		"agent_client_id", agentClientID,
		"sub", subjectClaims.Subject,
		"resource_slug", target.Slug,
		"issuance_id", resp.IssuanceID,
		"exchange_type", exchangeType,
		"chain_kind", chainKind,
		"via_link", viaLink,
	)
	if s.audit != nil {
		actorClientID := ""
		if actorClaims != nil {
			actorClientID = actorClaims.ClientID
		}
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenExchanged,
			subjectClaims.Subject, req.ClientID, "",
			fmt.Sprintf("jti=%s sub=%s subject_client=%s actor_client=%s type=mint_dispatch resource=%s scopes=%s chain_kind=%s via_link=%s",
				resp.IssuanceID, subjectClaims.Subject, agentClientID, actorClientID, target.Slug, req.Scope, chainKind, viaLink),
		))
	}
	if s.metrics != nil && s.metrics.TokenExchangeTotal != nil {
		sourceLabel := ""
		if frontedSource != nil {
			sourceLabel = frontedSource.Slug
		}
		s.metrics.TokenExchangeTotal.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("kind", chainKind),
			attribute.String("source", sourceLabel),
			attribute.String("target", target.Slug),
		))
	}

	return &input.TokenExchangeResponse{
		AccessToken:     resp.AccessToken,
		IssuedTokenType: token.TokenTypeAccessToken,
		TokenType:       resp.TokenType,
		ExpiresIn:       resp.ExpiresIn,
		Scope:           req.Scope,
	}, nil
}

// dispatchBroker runs the unified Broker flow:
//
//  1. reject actor_token (broker tokens are upstream-shaped — delegation
//     does not make sense over an external provider's bearer).
//  2. operator gate against target.Policy.Exchange.AllowedClientIDs.
//     An empty allowlist admits any client.
//  3. fronted-broker detection — when the subject token's aud resolves to
//     a Mint source distinct from the target, dispatch delegates to
//     dispatchFrontedBroker (gated on the link's scope_map) and none of
//     the steps below run, the agent-attestation gate included. A
//     resolvable source with no fronting_links row fails closed with
//     FrontingLinkMissingError rather than falling through.
//  4. subject-scope ceiling (ADR-002), direct-broker only.
//  5. agent-attestation gate: resolve the actor MCP as a Mint resource
//     via policy.runtime.client_ids and verify a consent_grants row
//     exists for (user, agent, actorMCP) covering every requested
//     scope (bound-C).
//  6. resolve the BrokerProvider via registry.GetWithProvider.
//  7. DPoP proof.
//  8. attach agent identity to the IssueRequest (for audit row only —
//     broker tokens cannot carry these claims on the wire).
//  9. BrokerIssuer.Issue → upstream-narrowed token + issuances row.
//  10. on ConsentRequiredError, wrap with ProviderSlug + ResourceSlug so
//     the handler can render an upstream-aware connect_url.
//  11. audit + metrics + RFC 8693 response shape.
func (s *TokenExchangeService) dispatchBroker(
	ctx context.Context,
	span trace.Span,
	start time.Time,
	req input.TokenExchangeRequest,
	subjectClaims *crypto.AccessTokenClaims,
	target *resource.Resource,
) (*input.TokenExchangeResponse, error) {
	if s.brokerIssuer == nil {
		err := fmt.Errorf("token exchange: broker issuer not wired for unified Broker dispatch")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.recordDenied(ctx, req.ClientID, "wiring_incomplete")
		return nil, err
	}

	span.SetAttributes(attribute.String("dispatch", "broker"))

	// 1. Broker resources reject delegation. The wire-format upstream
	// token cannot carry an act chain.
	if req.ActorToken != "" {
		span.RecordError(domain.ErrBrokerActorNotAllowed)
		span.SetStatus(codes.Error, "broker resource rejects actor_token")
		s.recordDenied(ctx, req.ClientID, "broker_actor_not_allowed")
		return nil, domain.ErrBrokerActorNotAllowed
	}

	agentClientID := subjectClaims.ClientID

	// 2. Operator gate. Empty allowlist = permissive (Brief §1). For
	// Broker the agent-attestation gate (step 3) provides defense in depth.
	if !operatorAllowsClient(target.Policy.Exchange.AllowedClientIDs, req.ClientID) {
		span.RecordError(domain.ErrTokenExchangeNotAuthorized)
		span.SetStatus(codes.Error, "operator gate rejected client")
		s.logger.InfoContext(ctx, "broker dispatch denied: client not in operator allowlist",
			"client_id", req.ClientID,
			"resource_slug", target.Slug,
		)
		s.recordDenied(ctx, req.ClientID, "operator_gate_denied")
		return nil, domain.ErrTokenExchangeNotAuthorized
	}

	// 3. Fronted-broker detection. Mirrors dispatchMint's fronted-path
	// detection above. When a (source, target) fronting
	// link exists, the operator declaration replaces the AS-side third-bound
	// agent-attestation gate; we delegate to dispatchFrontedBroker which
	// translates scopes via link.ScopeMap and calls BrokerIssuer.Issue.
	//
	// Fronted detection happens AFTER the operator gate (AllowedClientIDs)
	// so operator policy still applies to fronted exchanges, and AFTER the
	// actor_token rejection so wire-format invariants are uniform.
	if source := s.resolveSourceForFronting(ctx, subjectClaims.Audience); source != nil && source.Slug != target.Slug {
		link, err := s.fronting.Get(ctx, source.Slug, target.Slug)
		switch {
		case err == nil:
			return s.dispatchFrontedBroker(ctx, span, start, req, subjectClaims, target, source, link)
		case errors.Is(err, domain.ErrFrontingLinkNotFound):
			// subject's `aud` resolves to a Mint Resource (source)
			// different from the target Broker, but no fronting_links row
			// connects them. This is a misconfigured gateway — operator
			// forgot the fronting_links row, typo'd a slug, or followed a
			// stale pre- example. Fail fast with a typed error
			// pointing at the topology doc, instead of falling through to
			// the legacy bound-B path whose consent_required:
			// agent_attestation_required message points operators at the
			// wrong remediation.
			//
			// The bound-B block below is preserved as defense-in-depth for
			// the case where the subject token's `aud` doesn't resolve to a
			// Mint at all — see comment there.
			span.SetStatus(codes.Error, "fronting_link_missing")
			s.logger.InfoContext(ctx, "broker dispatch denied: fronting link missing",
				"client_id", req.ClientID,
				"source_slug", source.Slug,
				"target_slug", target.Slug,
			)
			s.recordDenied(ctx, req.ClientID, "fronting_link_missing")
			return nil, &domain.FrontingLinkMissingError{
				SourceSlug: source.Slug,
				TargetSlug: target.Slug,
			}
		default:
			span.RecordError(err)
			span.SetStatus(codes.Error, "fronting link lookup failed")
			s.recordDenied(ctx, req.ClientID, "fronting_lookup_failed")
			return nil, fmt.Errorf("fronting lookup: %w", err)
		}
	}

	// 4. Hybrid subject-scope ceiling (ADR-002). Direct-broker only — fronted
	// broker dispatch returned above and runs its own source-coverage gate
	// against the link's scope_map in source-side names. Direct broker uses
	// agent-attestation (below) as the operative authority and stacks this
	// ceiling on top when the subject token carries an explicit scope claim.
	if scopeErr := s.enforceSubjectScopeCeiling(ctx, span, req, subjectClaims, "broker"); scopeErr != nil {
		return nil, scopeErr
	}

	// 5. Agent-attestation gate. identify which Resource the
	// authenticated client represents at runtime via the explicit
	// policy.runtime.client_ids linkage. The pre- lookup string-
	// matched req.ClientID against Resource.Slug ("operator hygiene
	// convention"); that convention was unsatisfiable through public
	// admin surfaces and has been replaced by an explicit list-membership
	// check.
	//
	// Deprecation window: when no Resource lists this client_id, fall
	// back to the legacy slug==client_id resolve and warn so operators
	// see they need to migrate. Removed one release after this lands.
	actorAsResource, lookupErr := s.resolveActorMCP(ctx, req.ClientID)
	if lookupErr != nil {
		if errors.Is(lookupErr, domain.ErrResourceNotFound) {
			span.RecordError(domain.ErrTokenExchangeNotAuthorized)
			span.SetStatus(codes.Error, "actor MCP has no resource row")
			s.logger.InfoContext(ctx, "broker dispatch denied: actor MCP not registered as a resource",
				"client_id", req.ClientID,
				"resource_slug", target.Slug,
			)
			s.recordDenied(ctx, req.ClientID, "agent_attestation_unknown_actor")
			return nil, domain.ErrTokenExchangeNotAuthorized
		}
		// two or more Resources list the same client_id in
		// runtime.client_ids — operator misconfiguration, not a wire-level
		// failure. Fail closed with a distinct audit reason so operators
		// see "fix your runtime.client_ids overlap" instead of a generic
		// "resolve failed".
		if errors.Is(lookupErr, domain.ErrAmbiguousResource) {
			span.RecordError(domain.ErrTokenExchangeNotAuthorized)
			span.SetStatus(codes.Error, "actor MCP runtime.client_ids match is ambiguous")
			s.logger.WarnContext(ctx, "broker dispatch denied: actor MCP client_id maps to multiple resources",
				"client_id", req.ClientID,
				"resource_slug", target.Slug,
			)
			s.recordDenied(ctx, req.ClientID, "agent_attestation_ambiguous_actor")
			return nil, domain.ErrTokenExchangeNotAuthorized
		}
		span.RecordError(lookupErr)
		span.SetStatus(codes.Error, "actor resource resolve failed")
		s.recordDenied(ctx, req.ClientID, "actor_resolve_failed")
		return nil, fmt.Errorf("resolve actor MCP: %w", lookupErr)
	}
	if !actorAsResource.IsMint() {
		span.RecordError(domain.ErrTokenExchangeNotAuthorized)
		span.SetStatus(codes.Error, "actor MCP is not a Mint resource")
		s.recordDenied(ctx, req.ClientID, "agent_attestation_actor_not_mint")
		return nil, domain.ErrTokenExchangeNotAuthorized
	}
	attestation, err := s.consentGrants.Get(ctx, subjectClaims.Subject, agentClientID, actorAsResource.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.recordDenied(ctx, req.ClientID, "agent_attestation_lookup_failed")
		return nil, fmt.Errorf("look up agent attestation grant: %w", err)
	}
	if attestation == nil {
		span.SetStatus(codes.Error, "consent_required")
		s.logger.InfoContext(ctx, "broker dispatch denied: agent-attestation grant missing",
			"client_id", req.ClientID,
			"agent_client_id", agentClientID,
			"sub", subjectClaims.Subject,
			"resource_slug", target.Slug,
			"actor_resource_slug", actorAsResource.Slug,
		)
		s.recordDenied(ctx, req.ClientID, "agent_attestation_required")
		return nil, &domain.ConsentRequiredError{
			Service:      actorAsResource.Slug,
			ResourceSlug: actorAsResource.Slug,
			Cause:        domain.CauseConsentMissing,
		}
	}

	// 5b. bound-C: the agent-attestation grant must cover every
	// requested fine scope. Without this check, an agent attested for
	// [repo] could request [repo, admin:org] and ride the broker_grants
	// ceiling all the way to the upstream — the over-grant was
	// filed against. Mirrors dispatchMint's user-consent scope check.
	//
	// The error keys on actorAsResource.Slug (the Mint MCP), NOT the
	// upstream provider, because the failure indicates the user-to-agent
	// attestation is too narrow — the remediation is re-consent at
	// /authorize?resource=<actor_mcp>, not /connect/<provider>.
	requestedScopes := strings.Fields(req.Scope)
	if missing := scopesNotConsented(attestation, requestedScopes); len(missing) > 0 {
		span.SetStatus(codes.Error, "consent_required:scope_insufficient")
		s.logger.InfoContext(ctx, "broker dispatch denied: requested scope not covered by agent attestation",
			"client_id", req.ClientID,
			"agent_client_id", agentClientID,
			"sub", subjectClaims.Subject,
			"resource_slug", target.Slug,
			"actor_resource_slug", actorAsResource.Slug,
			"missing_scopes", missing,
		)
		s.recordDenied(ctx, req.ClientID, "broker_scope_not_consented")
		return nil, &domain.ConsentRequiredError{
			Service:       actorAsResource.Slug,
			ResourceSlug:  actorAsResource.Slug,
			Cause:         domain.CauseScopeInsufficient,
			MissingScopes: missing,
		}
	}

	// 6. Resolve provider for the broker resource.
	_, provider, err := s.registry.GetWithProvider(ctx, target.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "broker provider lookup failed")
		s.recordDenied(ctx, req.ClientID, "provider_lookup_failed")
		return nil, fmt.Errorf("resolve broker provider: %w", err)
	}
	if provider == nil {
		missingErr := fmt.Errorf("broker resource %q has no provider row", target.Slug)
		span.RecordError(missingErr)
		span.SetStatus(codes.Error, missingErr.Error())
		s.recordDenied(ctx, req.ClientID, "provider_missing")
		return nil, missingErr
	}

	// 7. DPoP proof — validated for replay even though broker tokens are
	// not AS-bound on the wire. JKT goes onto the issuance audit row.
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL)
		if dpopErr != nil {
			s.recordDenied(ctx, req.ClientID, "invalid_dpop_proof")
			return nil, dpopErr
		}
		dpopJKT = jkt
	}

	// 8. Agent identity. Same throwaway-claims pattern as Mint dispatch;
	// for Broker the act chain is intentionally nil (no delegation).
	agentClaims, err := s.extractAgentIdentity(ctx, span, req.ClientID, nil)
	if err != nil {
		s.recordDenied(ctx, req.ClientID, "agent_identity_failed")
		return nil, err
	}

	issueReq := IssueRequest{
		Resource:      target,
		Provider:      provider,
		SubjectUserID: subjectClaims.Subject,
		ActorClientID: req.ClientID,
		Scopes:        requestedScopes,
		AgentIdentity: agentClaims,
		DPoPJKT:       dpopJKT,
	}
	resp, err := s.brokerIssuer.Issue(ctx, issueReq)
	if err != nil {
		// Wrap ConsentRequiredError with the typed Provider/Resource
		// slugs so the handler can synthesize an upstream-aware
		// connect_url. Service stays parallel for legacy compatibility.
		// Cause + MissingScopes + DeniedReason are preserved from the
		// inner error so the wrapped error keeps the bound-D vs bound-E
		// discriminator and the DeniedReason (T4).
		var cre *domain.ConsentRequiredError
		if errors.As(err, &cre) {
			wrapped := &domain.ConsentRequiredError{
				Service:       provider.Slug,
				ProviderSlug:  provider.Slug,
				ResourceSlug:  target.Slug,
				Cause:         cre.Cause,
				MissingScopes: cre.MissingScopes,
				DeniedReason:  cre.DeniedReason,
			}
			s.recordDenied(ctx, req.ClientID, "broker_consent_required")
			span.SetStatus(codes.Error, "broker_consent_required")
			return nil, wrapped
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "broker issuer failed")
		s.recordDenied(ctx, req.ClientID, "broker_vend_failed")
		return nil, err
	}

	s.recordExchangeSuccess(ctx, start, "broker_dispatch")

	s.logger.InfoContext(ctx, "token exchanged via unified broker dispatch",
		"client_id", req.ClientID,
		"agent_client_id", agentClientID,
		"sub", subjectClaims.Subject,
		"resource_slug", target.Slug,
		"broker_provider_slug", provider.Slug,
		"issuance_id", resp.IssuanceID,
	)
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenExchanged,
			subjectClaims.Subject, req.ClientID, "",
			fmt.Sprintf("issuance_id=%s sub=%s subject_client=%s type=broker_dispatch resource=%s provider=%s scopes=%s",
				resp.IssuanceID, subjectClaims.Subject, agentClientID, target.Slug, provider.Slug, req.Scope),
		))
	}

	return &input.TokenExchangeResponse{
		AccessToken:     resp.AccessToken,
		IssuedTokenType: token.TokenTypeAccessToken,
		TokenType:       resp.TokenType,
		ExpiresIn:       resp.ExpiresIn,
		Scope:           req.Scope,
	}, nil
}

// dispatchFrontedBroker handles a fronted Mint→Broker token exchange.
// Caller (dispatchBroker, T8) has already verified:
//   - target.BackendKind == BackendBroker
//   - operator gate against target.Policy.Exchange.AllowedClientIDs passed
//   - actor_token absent (broker always rejects delegation on the wire)
//   - subject_token resolves a source Mint resource via resolveSourceForFronting
//   - a (source, target) fronting_link exists
//
// contract:
//   - Operator declaration replaces the AS-side third-bound check
//     (consent_grants is NOT consulted on this path).
//   - Upstream IdP consent is REQUIRED — BrokerIssuer.Issue checks
//     grant.Get and emits ConsentRequiredError if missing.
//   - The bearer returned is the upstream's access token (not an AS JWT);
//     no Option β shape applies to the wire token.
//   - Audit chain (chain_kind=fronted, target_kind=broker, via_link=A->B)
//     is emitted at the dispatch site by the caller (T9, after this task).
//
// NO AUDIT, NO METRIC EMISSION — that's T9.
func (s *TokenExchangeService) dispatchFrontedBroker(
	ctx context.Context,
	span trace.Span,
	start time.Time,
	req input.TokenExchangeRequest,
	subjectClaims *crypto.AccessTokenClaims,
	target *resource.Resource,
	source *resource.Resource,
	link *resource.FrontingLink,
) (*input.TokenExchangeResponse, error) {
	span.SetAttributes(
		attribute.String("dispatch", "broker_fronted"),
		attribute.String("source_slug", source.Slug),
		attribute.String("via_link", source.Slug+"->"+target.Slug),
	)

	// 1. Resolve the broker provider first — needed both for the IssueRequest
	// and to populate ProviderSlug on any ConsentRequiredError so the HTTP
	// handler can build the launchable /connect/<slug>?return_url URL.
	// (target.BrokerProviderID is a UUID, not a slug; using it directly would
	// point the consent redirect at a non-existent route.)
	_, provider, err := s.registry.GetWithProvider(ctx, target.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "broker provider lookup failed")
		s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "provider_lookup_failed")
		return nil, fmt.Errorf("resolve broker provider: %w", err)
	}
	if provider == nil {
		missingErr := fmt.Errorf("broker resource %q has no provider row", target.Slug)
		span.RecordError(missingErr)
		span.SetStatus(codes.Error, "broker provider missing for resource")
		s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "provider_missing")
		return nil, missingErr
	}

	// 2. Validate target-side scopes against the link's ScopeMap AND the
	// subject token's scope claim. The gateway names upstream targets
	// directly; AS verifies that (a) the operator declared this target as
	// a value somewhere in the link's ScopeMap, and (b) the source key
	// mapping to it is present in the subject claim — i.e., the user has
	// consented to the abstract MCP scope that authorizes this target.
	requested := strings.Fields(req.Scope)
	subjectScopes := scope.Parse(subjectClaims.Scope)
	translated, unmapped, missingCoverage := validateBrokerTargets(link.ScopeMap, requested, subjectScopes)
	if len(unmapped) > 0 {
		s.logger.InfoContext(ctx, "fronted broker denied: target scope not declared in scope_map",
			"source_slug", source.Slug,
			"target_slug", target.Slug,
			"unmapped", unmapped,
		)
		span.RecordError(fmt.Errorf("scope unmapped: %v", unmapped))
		span.SetStatus(codes.Error, "consent_required:scope_unmapped")
		s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "scope_unmapped")
		return nil, &domain.ConsentRequiredError{
			ProviderSlug: provider.Slug,
			ResourceSlug: target.Slug,
			Cause:        domain.CauseScopeInsufficient,
			DeniedReason: "scope_unmapped",
		}
	}
	if len(missingCoverage) > 0 {
		s.logger.InfoContext(ctx, "fronted broker denied: subject token missing source scope for requested target",
			"source_slug", source.Slug,
			"target_slug", target.Slug,
			"uncovered_targets", missingCoverage,
		)
		span.RecordError(fmt.Errorf("subject scope insufficient for targets: %v", missingCoverage))
		span.SetStatus(codes.Error, "consent_required:subject_scope_insufficient")
		s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "subject_scope_insufficient")
		return nil, &domain.ConsentRequiredError{
			ProviderSlug: provider.Slug,
			ResourceSlug: target.Slug,
			Cause:        domain.CauseScopeInsufficient,
			DeniedReason: "subject_scope_insufficient",
		}
	}

	// 3. Agent identity — same throwaway-claims pattern as dispatchBroker;
	// for Broker the act chain is intentionally nil (no delegation).
	agentClaims, err := s.extractAgentIdentity(ctx, span, req.ClientID, nil)
	if err != nil {
		span.SetStatus(codes.Error, "agent identity failed")
		s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "agent_identity_failed")
		return nil, err
	}

	// 4. Hand off to BrokerIssuer. Propagate ConsentRequiredError verbatim;
	// the dispatchBroker re-wrap (T8) will enrich ProviderSlug/ResourceSlug.
	// ActorClientID is source.Slug (Option β semantic: source mint is the actor).
	// DPoPJKT prefers the request's DPoP proof (when the agent presents one
	// at /oauth/token); falls back to the subject token's cnf.jkt for
	// chain-origin forensics. Mirrors dispatchBroker's legacy-path order so
	// DPoP issuances stay observable when the source token wasn't itself
	// AS-bound.
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL)
		if dpopErr != nil {
			s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "dpop_invalid")
			return nil, dpopErr
		}
		dpopJKT = jkt
	}
	if dpopJKT == "" && subjectClaims.Cnf != nil {
		if jkt, ok := subjectClaims.Cnf["jkt"].(string); ok {
			dpopJKT = jkt
		}
	}
	resp, err := s.brokerIssuer.Issue(ctx, IssueRequest{
		Resource:      target,
		Provider:      provider,
		Scopes:        translated,
		SubjectUserID: subjectClaims.Subject,
		ActorClientID: source.Slug,
		AgentIdentity: agentClaims,
		DPoPJKT:       dpopJKT,
	})
	if err != nil {
		var cre *domain.ConsentRequiredError
		if errors.As(err, &cre) {
			span.RecordError(err)
			span.SetStatus(codes.Error, "consent_required")
			// No countDenied here: emitFrontedBrokerDenialAudit counts, and a
			// single denial is a single increment. The metric label is the
			// specific denied reason, not a blanket broker_consent_required.
			deniedReason := cre.DeniedReason
			if deniedReason == "" {
				switch cre.Cause {
				case domain.CauseConsentMissing:
					deniedReason = "upstream_connection_missing"
				case domain.CauseScopeInsufficient:
					deniedReason = "upstream_scope_insufficient"
				default:
					deniedReason = "unknown"
				}
			}
			s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, deniedReason)
			return nil, err
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "broker vend failed")
		s.emitFrontedBrokerDenialAudit(ctx, req, subjectClaims, source, target, "broker_vend_failed")
		return nil, err
	}

	s.logger.InfoContext(ctx, "token exchanged via fronted broker dispatch",
		"user_id", subjectClaims.Subject,
		"agent_client_id", req.ClientID,
		"source_slug", source.Slug,
		"broker_provider_slug", provider.Slug,
		"resource_slug", target.Slug,
		"via_link", source.Slug+"->"+target.Slug,
		"issuance_id", resp.IssuanceID,
	)
	span.SetStatus(codes.Ok, "")

	// Emit the dispatch-site audit event (chain_kind=fronted, target_kind=broker)
	// and increment the success counter. Both are T9 additions; the logger +
	// span above remain unchanged from T8.
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenExchanged,
			subjectClaims.Subject, source.Slug, "",
			fmt.Sprintf("sub=%s subject_client=%s actor_client=%s type=broker_dispatch resource=%s scopes=%s chain_kind=fronted via_link=%s target_kind=broker issuance_id=%s",
				subjectClaims.Subject,
				subjectClaims.ClientID,
				source.Slug,
				target.Slug,
				strings.Join(translated, " "),
				source.Slug+"->"+target.Slug,
				resp.IssuanceID,
			),
		))
	}
	if s.metrics != nil && s.metrics.TokenExchangeTotal != nil {
		s.metrics.TokenExchangeTotal.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("kind", "fronted"),
			attribute.String("source", source.Slug),
			attribute.String("target", target.Slug),
		))
	}
	if s.metrics != nil && s.metrics.TokensIssued != nil {
		s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("grant_type", "token_exchange"),
		))
	}
	if s.metrics != nil && s.metrics.TokenIssuanceDuration != nil {
		s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
			attribute.String("grant_type", "token_exchange"),
		))
	}

	// 5. RFC 8693 response shape. The bearer is the upstream's access token
	// (not an AS JWT); IssuedTokenType is always access_token.
	return &input.TokenExchangeResponse{
		AccessToken:     resp.AccessToken,
		IssuedTokenType: token.TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       resp.ExpiresIn,
		Scope:           strings.Join(translated, " "),
	}, nil
}

// emitFrontedBrokerDenialAudit counts the denial and writes the single audit
// event for it: ActionTokenExchangeDenied carrying the full fronted chain
// context (chain_kind=fronted, target_kind=broker, via_link, denied_reason).
//
// It previously emitted ActionTokenExchanged — the success action — alongside a
// separate recordDenied row, so "token.exchanged" did not mean a token had been
// exchanged, and any consumer filtering on it counted denials as successes.
// Callers pass through here instead of recordDenied; countDenied keeps the
// metric.
func (s *TokenExchangeService) emitFrontedBrokerDenialAudit(
	ctx context.Context,
	req input.TokenExchangeRequest,
	subjectClaims *crypto.AccessTokenClaims,
	source, target *resource.Resource,
	deniedReason string,
) {
	s.countDenied(ctx, deniedReason)
	if s.audit == nil {
		return
	}
	s.audit.Record(ctx, audit.NewEvent(
		audit.ActionTokenExchangeDenied,
		subjectClaims.Subject, source.Slug, "",
		fmt.Sprintf("sub=%s subject_client=%s actor_client=%s type=broker_dispatch resource=%s scopes=%s chain_kind=fronted via_link=%s target_kind=broker denied_reason=%s",
			subjectClaims.Subject,
			subjectClaims.ClientID,
			source.Slug,
			target.Slug,
			req.Scope,
			source.Slug+"->"+target.Slug,
			deniedReason,
		),
	))
}

// extractAgentIdentity runs AgentIdentityService.AttachClaims against a
// throwaway claims struct and lifts the resulting AgentID and AgentChain
// into an *AgentIdentityClaims. Returns nil when the agent-identity
// service is not wired or the issuing client is not an agent.
//
// The throwaway pattern (vs. a dedicated method on AgentIdentityService)
// keeps the surface area minimal: AgentIdentityService is intentionally
// not extended here. Surface a dedicated method as a follow-up if call
// sites grow.
func (s *TokenExchangeService) extractAgentIdentity(
	ctx context.Context,
	span trace.Span,
	clientID string,
	actMap map[string]interface{},
) (*AgentIdentityClaims, error) {
	if s.agentIdentity == nil {
		return nil, nil
	}
	temp := crypto.AccessTokenClaims{Act: actMap}
	if err := s.agentIdentity.AttachClaims(ctx, &temp, clientID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "attach agent claims failed")
		return nil, fmt.Errorf("attach agent claims: %w", err)
	}
	if temp.AgentID == "" && len(temp.AgentChain) == 0 {
		return nil, nil
	}
	return &AgentIdentityClaims{
		AgentID:    temp.AgentID,
		AgentChain: temp.AgentChain,
	}, nil
}

// recordExchangeSuccess emits the shared TokenExchangeTotal /
// TokensIssued / TokenIssuanceDuration trio with the dispatch label
// distinguishing the new flows from the legacy "impersonation" /
// "delegation" / "vault_vend" labels. No new metric families are added
// in  ( ships authserver_token_exchange_*).
func (s *TokenExchangeService) recordExchangeSuccess(ctx context.Context, start time.Time, exchangeType string) {
	if s.metrics != nil && s.metrics.TokenExchangeTotal != nil {
		s.metrics.TokenExchangeTotal.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("type", exchangeType),
		))
	}
	if s.metrics != nil && s.metrics.TokensIssued != nil {
		s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("grant_type", "token_exchange"),
		))
	}
	if s.metrics != nil && s.metrics.TokenIssuanceDuration != nil {
		s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
			attribute.String("grant_type", "token_exchange"),
		))
	}
}

// scopesNotConsented returns the elements of requested that are not present
// in grant.Scopes, preserving the order of the requested slice for
// deterministic logging. Returns a nil slice when requested ⊆ grant.Scopes.
//
// A nil grant or one with an empty Scopes set returns the requested slice
// unchanged (treat as zero coverage). The "empty grant covers nothing"
// semantics matches resource.ConsentGrant.CoversScopes: a consent grant with
// Scopes=[] does NOT silently authorize a request with non-empty scope.
//
// Used at two dispatch sites: dispatchMint's user-consent
// scope-coverage branch and dispatchBroker's bound-C agent-attestation
// scope-coverage branch. The dispatch-side analog of broker_issuer.go's
// scopesNotIn helper, which mirrors the same shape over upstream scopes.
func scopesNotConsented(grant *resource.ConsentGrant, requested []string) []string {
	if grant == nil || len(grant.Scopes) == 0 {
		if len(requested) == 0 {
			return nil
		}
		out := make([]string, len(requested))
		copy(out, requested)
		return out
	}
	haveSet := make(map[string]struct{}, len(grant.Scopes))
	for _, s := range grant.Scopes {
		haveSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range requested {
		if _, ok := haveSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}

// operatorAllowsClient reports whether clientID passes the per-resource
// operator gate. Empty allowlist defaults to permissive ("any client may
// act") per Brief §1; user consent is a separate gate, skipped for Mint
// self-exchange and on fronted paths — Mint→Mint and Mint→Broker alike
// (see dispatchMint and dispatchFrontedBroker).
// May flip to strict-by-default for broker resources if customer feedback
// warrants it; the call site is shared by Mint and Broker.
func operatorAllowsClient(allowed []string, clientID string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == clientID {
			return true
		}
	}
	return false
}

// requiredSourceScopesForTargets reverse-walks a fronting link's ScopeMap to
// derive the source-side scopes a subject token must carry to reach every
// entry in targets, on the fronted Mint->Mint path. Returns (sourceScopes,
// unmappedTargets). When unmappedTargets is non-empty the caller MUST reject
// the request — a target the operator did not map cannot be requested through
// the fronted path. unmappedTargets is returned in input order; sourceScopes
// is sorted.
//
// Multi-source maps: when several source keys map to the same target this
// picks the lexicographically smallest and requires THAT one. It is neither a
// minimal cover nor an any-of check, so with ScopeMap {"a": ["t"], "b": ["t"]}
// a subject token carrying only "b" is denied target "t" — even though the
// operator declared b -> t and the user consented to b.
//
// The fronted-broker counterpart validateBrokerTargets accepts ANY covering
// source key for the same map, so the two fronted paths disagree here. The
// divergence predates the caller and is tracked as its own decision; the
// fixed pick keeps audit lines reproducible across replays, which an any-of
// check would also do. Do not describe the two paths as gating alike.
func requiredSourceScopesForTargets(m resource.ScopeMap, targets []string) ([]string, []string) {
	if len(targets) == 0 {
		return nil, nil
	}
	rev := make(map[string][]string, len(targets))
	for src, tgts := range m {
		for _, t := range tgts {
			rev[t] = append(rev[t], src)
		}
	}
	for _, sources := range rev {
		sort.Strings(sources)
	}
	srcSet := make(map[string]struct{})
	var unmapped []string
	for _, t := range targets {
		sources, ok := rev[t]
		if !ok || len(sources) == 0 {
			unmapped = append(unmapped, t)
			continue
		}
		srcSet[sources[0]] = struct{}{}
	}
	if len(unmapped) > 0 {
		return nil, unmapped
	}
	out := make([]string, 0, len(srcSet))
	for s := range srcSet {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// validateBrokerTargets gates a fronted-broker exchange where the gateway
// names the upstream **target** scopes directly. Each requested target must
// (a) appear as a value in some link.ScopeMap entry — proving the operator
// declared this target as reachable through the link — and (b) at least one
// source key mapping to it must be present in the subject token's scope
// claim — proving the user actually consented to an abstract MCP scope that
// authorizes this target.
//
// Any covering source satisfies (b). The fronted Mint->Mint counterpart
// requiredSourceScopesForTargets instead requires the lexicographically
// first source key specifically, so a multi-source map can pass here and be
// denied there. Deliberate asymmetry only in the sense that nobody has
// reconciled it yet — see that function's comment.
//
// Returns:
//   - valid: targets cleared by both gates, sorted; pass through verbatim
//     to the upstream.
//   - unmapped: targets the operator did not declare in any value list.
//   - missingCoverage: targets whose source key(s) are absent from the
//     subject token's scope claim — the user did not consent to anything
//     mapping to this target.
//
// At most one of unmapped / missingCoverage is non-empty across the input;
// when either is non-empty `valid` is nil and the caller MUST reject the
// request. The two denial paths are kept distinct so audit + telemetry can
// distinguish operator-config gaps from user-consent gaps.
//
// Helper for broker-scope resolution. Walks
// source keys with no claim binding). Forward-walk on source keys is no
// longer accepted: the gateway must speak in upstream-target terms.
func validateBrokerTargets(m resource.ScopeMap, requested []string, subjectScopes scope.Set) ([]string, []string, []string) {
	if len(requested) == 0 {
		return nil, nil, nil
	}
	// Reverse index: target → source-keys that map to it. Built per call
	// because ScopeMap mutations between calls are allowed (operator edits
	// the link via the admin API at runtime).
	rev := make(map[string][]string, len(requested))
	for src, tgts := range m {
		for _, t := range tgts {
			rev[t] = append(rev[t], src)
		}
	}
	seen := make(map[string]struct{}, len(requested))
	var unmapped, missingCoverage []string
	for _, tgt := range requested {
		sources, ok := rev[tgt]
		if !ok {
			unmapped = append(unmapped, tgt)
			continue
		}
		covered := false
		for _, src := range sources {
			if subjectScopes.Contains(src) {
				covered = true
				break
			}
		}
		if !covered {
			missingCoverage = append(missingCoverage, tgt)
			continue
		}
		seen[tgt] = struct{}{}
	}
	if len(unmapped) > 0 || len(missingCoverage) > 0 {
		return nil, unmapped, missingCoverage
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil, nil
}

// resolveActorMCP returns the Mint Resource that req.ClientID is registered
// to act AS at runtime. the canonical lookup is list-membership
// against policy.runtime.client_ids; legacy deployments that satisfied the
// retired slug==client_id convention fall through to a deprecated Resolve()
// for one release so operators have a window to migrate.
//
// Returns:
//
//   - (*Resource, nil) on a clean runtime.client_ids match
//   - (*Resource, nil) on a legacy slug==client_id match — logs a warning
//     so operators see they need to configure runtime.client_ids
//   - (nil, ErrResourceNotFound) when neither path matches (fail-closed)
//   - (nil, ErrAmbiguousResource) when two Resources list the same
//     client_id — operator misconfiguration; runtime fails closed
//
// Remove the legacy fallback one release after this lands; track via
// CHANGELOG.
func (s *TokenExchangeService) resolveActorMCP(ctx context.Context, clientID string) (*resource.Resource, error) {
	actor, err := s.registry.FindByRuntimeClientID(ctx, clientID)
	if err == nil {
		return actor, nil
	}
	if !errors.Is(err, domain.ErrResourceNotFound) {
		return nil, err
	}

	legacy, lerr := s.registry.Resolve(ctx, clientID)
	if lerr != nil {
		// Surface the original ErrResourceNotFound (not the legacy
		// fallback's error) so callers continue to see the canonical
		// fail-closed signal.
		return nil, err
	}
	s.logger.WarnContext(ctx,
		"agent-attestation: resolved actor MCP via deprecated slug==client_id convention; configure policy.runtime.client_ids on the resource",
		"client_id", clientID,
		"resource_slug", legacy.Slug,
	)
	return legacy, nil
}

// resolveSourceForFronting returns the source resource for a fronted-path
// lookup, or nil if no resolvable Mint source can be found. nil triggers
// the direct-path fall-through; never a hard error (refresh-style exchanges
// with aud=issuer must keep working).
//
// Resolution rule: walk the subject token's audience list, skip empty/issuer
// entries, attempt registry.Resolve on each, return the first Mint resource.
// On any error or non-Mint result, continue to the next audience entry; if
// nothing resolves, return nil.
func (s *TokenExchangeService) resolveSourceForFronting(ctx context.Context, audience []string) *resource.Resource {
	if s.fronting == nil || s.registry == nil {
		return nil
	}
	// Best-effort: if issuer resolution fails, treat it as empty so the
	// self-audience skip is conservative (may attempt to resolve the issuer
	// URL as a resource, which will safely fail via registry.Resolve).
	selfIssuer, err := s.issuerProvider.Issuer(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "treating issuer as empty; fronting source resolution may skip self-bound URIs",
			"error", err,
			"site", "resolveSourceForFronting",
		)
	}
	for _, aud := range audience {
		if aud == "" || aud == selfIssuer {
			continue
		}
		src, err := s.registry.Resolve(ctx, aud)
		if err != nil {
			continue
		}
		if !src.IsMint() {
			continue
		}
		return src
	}
	return nil
}
