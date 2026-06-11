package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// TokenConfig holds token lifetimes.
type TokenConfig struct {
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
}

// DPoPConfig holds DPoP proof validation settings (RFC 9449).
type DPoPConfig struct {
	ProofLifetime time.Duration // max |now - iat| for proof freshness (e.g. 60s)
	RequireNonce  bool          // when true, proofs must include a server-issued nonce
	NonceTTL      time.Duration // TTL for server-issued nonces
}

// TokenService implements input.TokenPort.
type TokenService struct {
	sessions   output.SessionStore
	tokens     output.TokenStore
	clients    output.ClientStore
	users      output.UserStore
	jwks       JWKSSigningKeyProvider
	mintIssuer *MintIssuer            // signs Mint access tokens + writes the issuances audit row.
	revocation output.RevocationStore // optional, for JTI tracking (introspection support)
	audit      AuditRecorder
	issuer     string
	config     TokenConfig
	resources  ResourceLister // resource catalog (kept for ResourceLister.List() walks)
	logger     *slog.Logger
	tracer     trace.Tracer
	metrics    *observability.Metrics

	// DPoP support (RFC 9449) — optional. When dpopStore is nil, DPoP is disabled.
	dpopStore  output.DPoPNonceStore
	dpopConfig *DPoPConfig

	// Transaction support — optional. When nil, multi-step operations are not atomic.
	txManager output.TransactionManager

	// resourceRegistry resolves a session/family resource URI to a typed
	// *resource.Resource so MintIssuer can persist the issuances audit row
	// (resources.id is the FK target). Optional: when nil, the legacy
	// behavior applies — auth-code and refresh-token grants do not write an
	// issuance row (which is the  /  audit-gap that surfaced as
	// "Issuances list is empty" in the Admin UI).
	resourceRegistry *ResourceRegistry
}

// JWKSSigningKeyProvider provides signing keys for JWT issuance.
type JWKSSigningKeyProvider interface {
	GetSigningKey(ctx context.Context) (*output.SigningKey, error)
}

var _ input.TokenPort = (*TokenService)(nil)

// NewTokenService creates a new token service.
// mintIssuer signs Mint access tokens and persists the issuances audit row;
// it must be non-nil — callers wire it in cmd/authserver/serve.go.
func NewTokenService(
	sessions output.SessionStore,
	tokens output.TokenStore,
	clients output.ClientStore,
	users output.UserStore,
	jwks JWKSSigningKeyProvider,
	mintIssuer *MintIssuer,
	issuer string,
	cfg TokenConfig,
	obs *observability.Provider,
	auditor AuditRecorder,
	revocation output.RevocationStore,
	resources ResourceLister,
) *TokenService {
	return &TokenService{
		sessions:   sessions,
		tokens:     tokens,
		clients:    clients,
		users:      users,
		jwks:       jwks,
		mintIssuer: mintIssuer,
		revocation: revocation,
		audit:      auditor,
		issuer:     issuer,
		config:     cfg,
		resources:  resources,
		logger:     obs.Logger,
		tracer:     obs.Tracer,
		metrics:    obs.Metrics,
	}
}

// WithDPoP enables DPoP proof-of-possession support on the token service.
// When enabled, clients may present a DPoP proof to bind access tokens to their key pair.
func (s *TokenService) WithDPoP(store output.DPoPNonceStore, cfg DPoPConfig) {
	s.dpopStore = store
	s.dpopConfig = &cfg
}

// WithTokenTransactions enables transactional atomicity for multi-step token operations.
func (s *TokenService) WithTokenTransactions(tm output.TransactionManager) {
	s.txManager = tm
}

// WithResourceRegistry attaches the unified ResourceRegistry so the auth-code
// and refresh-token grants can resolve their session-stored resource URI to
// a typed *resource.Resource. Without it, MintIssuer skips the issuances
// audit row insertion (the FK target resources.id is unknown), leaving the
// admin Issuances list empty for Mint tokens issued via standard OAuth grants.
// The earlier wiring rotation introduced the issuances audit row but
// deferred plumbing the registry into TokenService; this setter closes
// that gap without changing NewTokenService's signature.
func (s *TokenService) WithResourceRegistry(r *ResourceRegistry) {
	s.resourceRegistry = r
}

// ExchangeCode exchanges an authorization code + PKCE verifier for tokens.
func (s *TokenService) ExchangeCode(ctx context.Context, req input.ExchangeCodeRequest) (*input.TokenResponse, error) {
	ctx, span := s.tracer.Start(ctx, "TokenService.ExchangeCode")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("grant_type", "authorization_code"),
	)
	start := time.Now()

	// 1. Hash the code and atomically consume.
	codeHash := crypto.HashSHA256(req.Code)
	sess, err := s.sessions.ConsumeByCodeHash(ctx, codeHash)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err // ErrCodeConsumed or ErrInvalidGrant
	}

	// 2. Check session expired.
	if sess.IsExpired() {
		span.RecordError(domain.ErrInvalidGrant)
		span.SetStatus(codes.Error, "session expired")
		return nil, domain.ErrInvalidGrant
	}

	// 3. Validate client_id matches session.
	if req.ClientID != sess.ClientID {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "client_id mismatch")
		return nil, domain.ErrInvalidClient
	}

	// 4. Validate redirect_uri matches session.
	if req.RedirectURI != sess.RedirectURI {
		span.RecordError(domain.ErrInvalidGrant)
		span.SetStatus(codes.Error, "redirect_uri mismatch")
		return nil, domain.ErrInvalidGrant
	}

	// 5. Authenticate client.
	if authErr := s.authenticateClient(ctx, span, sess.ClientID, req.ClientSecret); authErr != nil {
		return nil, authErr
	}

	// 6. Verify PKCE.
	if pkceErr := crypto.VerifyS256(req.CodeVerifier, sess.CodeChallenge); pkceErr != nil {
		span.RecordError(domain.ErrInvalidPKCE)
		span.SetStatus(codes.Error, "PKCE verification failed")
		return nil, domain.ErrInvalidPKCE
	}

	// 7. Validate DPoP proof if present (RFC 9449).
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL, "")
		if dpopErr != nil {
			return nil, dpopErr
		}
		dpopJKT = jkt
	}

	// 8. Sign access token via MintIssuer. Issuance row insert
	// happens here, before the family-create transaction — issuances are
	// an audit-side record and intentionally non-atomic with refresh-family
	// rotation (mirrors today's MachineTokenStore.Save semantic).
	now := time.Now().UTC()
	expiry := now.Add(s.config.AccessTokenExpiry)
	mintResp, err := s.mintIssuer.Issue(ctx, s.buildMintRequest(ctx, now, expiry, mintParams{
		UserID:   sess.UserID,
		ClientID: sess.ClientID,
		Scope:    sess.Scope,
		Resource: sess.Resource,
		DPoPJKT:  dpopJKT,
	}))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	accessToken := mintResp.AccessToken
	jti := mintResp.IssuanceID

	// 9. Create token family and refresh token atomically to prevent
	// orphaned families if refresh token creation fails.
	familyID := crypto.GenerateRandomString(16)
	family := &token.Family{
		ID:        familyID,
		ClientID:  sess.ClientID,
		UserID:    sess.UserID,
		Scope:     sess.Scope,
		Resource:  sess.Resource,
		Status:    token.FamilyActive,
		CreatedAt: now,
	}
	var refreshPlain string
	createFamilyAndRefresh := func(txCtx context.Context) error {
		if createErr := s.tokens.CreateFamily(txCtx, family); createErr != nil {
			return fmt.Errorf("create token family: %w", createErr)
		}
		s.trackJTI(txCtx, jti, familyID, expiry)
		var refreshErr error
		refreshPlain, refreshErr = s.createRefreshToken(txCtx, span, familyID, now)
		return refreshErr
	}
	if s.txManager != nil {
		err = s.txManager.WithTransaction(ctx, createFamilyAndRefresh)
	} else {
		err = createFamilyAndRefresh(ctx)
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	tokenType := mintResp.TokenType

	s.logger.InfoContext(ctx, "tokens issued",
		"client_id", sess.ClientID,
		"user_id", sess.UserID,
		"family_id", familyID,
		"token_type", tokenType,
	)

	s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("grant_type", "authorization_code"),
	))
	s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
		attribute.String("grant_type", "authorization_code"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenIssued, sess.UserID, sess.ClientID, "", "family="+familyID))
	}

	return &input.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    int(s.config.AccessTokenExpiry.Seconds()),
		RefreshToken: refreshPlain,
		Scope:        sess.Scope,
	}, nil
}

// RefreshToken rotates a refresh token and issues a new access token.
func (s *TokenService) RefreshToken(ctx context.Context, req input.RefreshTokenRequest) (*input.TokenResponse, error) {
	ctx, span := s.tracer.Start(ctx, "TokenService.RefreshToken")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("grant_type", "refresh_token"),
	)
	start := time.Now()

	// 1. Hash the token and look up.
	rtHash := crypto.HashSHA256(req.RefreshToken)
	rt, err := s.tokens.GetRefreshTokenByHash(ctx, rtHash)
	if err != nil {
		span.RecordError(domain.ErrInvalidGrant)
		span.SetStatus(codes.Error, "refresh token not found")
		return nil, domain.ErrInvalidGrant
	}

	// 2. Check expiry.
	if rt.IsExpired() {
		span.RecordError(domain.ErrInvalidGrant)
		span.SetStatus(codes.Error, "refresh token expired")
		return nil, domain.ErrInvalidGrant
	}

	// Authenticate the caller BEFORE consuming the refresh token: otherwise
	// an attacker who holds the refresh value can burn it (and trigger
	// reuse-detection family revocation) without ever proving they are the
	// client. Reuse detection still fires for authenticated callers below,
	// so a stolen current refresh used by the right client still revokes.
	family, err := s.tokens.GetFamily(ctx, rt.FamilyID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get family: %w", err)
	}
	if !family.IsActive() {
		span.RecordError(domain.ErrFamilyRevoked)
		span.SetStatus(codes.Error, "family revoked")
		return nil, domain.ErrFamilyRevoked
	}
	if req.ClientID != family.ClientID {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "client_id mismatch")
		return nil, domain.ErrInvalidClient
	}
	if authErr := s.authenticateClient(ctx, span, family.ClientID, req.ClientSecret); authErr != nil {
		return nil, authErr
	}

	// 3. Atomically consume the refresh token. Reuse detection runs here;
	// revoking on reuse remains atomic. Now safe because the caller is
	// authenticated above.
	if consumeErr := s.consumeOrRevokeFamily(ctx, span, rt); consumeErr != nil {
		return nil, consumeErr
	}

	// 4. Check user is still active.
	if s.users != nil && family.UserID != "" {
		u, userErr := s.users.GetByID(ctx, family.UserID)
		if userErr != nil || !u.IsActive() {
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "user disabled")
			return nil, domain.ErrInvalidGrant
		}
	}

	// 5. Scope narrowing: if requested scope is provided, it must be a subset.
	effectiveScope := family.Scope
	if req.Scope != "" {
		requested := scope.Parse(req.Scope)
		original := scope.Parse(family.Scope)
		if !requested.IsSubset(original) {
			span.RecordError(domain.ErrInvalidScope)
			span.SetStatus(codes.Error, "scope not subset")
			return nil, domain.ErrInvalidScope
		}
		effectiveScope = requested.String()
	}

	// 6. Validate DPoP proof if present (RFC 9449).
	var dpopJKT string
	if req.DPoPProof != "" {
		jkt, dpopErr := s.validateDPoP(ctx, span, req.DPoPProof, req.HTTPMethod, req.HTTPURL, "")
		if dpopErr != nil {
			return nil, dpopErr
		}
		dpopJKT = jkt
	}

	// 7. Sign new access token via MintIssuer. Issuance row is
	// inserted before the rotation tx — same audit/non-atomic split as
	// ExchangeCode and as the legacy machine_tokens write.
	now := time.Now().UTC()
	expiry := now.Add(s.config.AccessTokenExpiry)
	mintResp, err := s.mintIssuer.Issue(ctx, s.buildMintRequest(ctx, now, expiry, mintParams{
		UserID:   family.UserID,
		ClientID: family.ClientID,
		Scope:    effectiveScope,
		Resource: family.Resource,
		DPoPJKT:  dpopJKT,
	}))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	accessToken := mintResp.AccessToken

	s.trackJTI(ctx, mintResp.IssuanceID, family.ID, expiry)

	// 8. Re-check family status before creating the rotated refresh token.
	// An admin force-logout could have revoked the family between step 3 and
	// now (while we were signing the JWT), creating an orphaned token.
	family, err = s.tokens.GetFamily(ctx, family.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("re-check family: %w", err)
	}
	if !family.IsActive() {
		span.RecordError(domain.ErrFamilyRevoked)
		span.SetStatus(codes.Error, "family revoked during refresh")
		return nil, domain.ErrFamilyRevoked
	}

	// 10. Create rotated refresh token.
	refreshPlain, err := s.createRefreshToken(ctx, span, family.ID, now)
	if err != nil {
		return nil, err
	}

	tokenType := mintResp.TokenType

	s.logger.InfoContext(ctx, "tokens refreshed",
		"client_id", family.ClientID,
		"user_id", family.UserID,
		"family_id", family.ID,
		"token_type", tokenType,
	)

	s.metrics.TokensRefreshed.Add(ctx, 1)
	s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
		attribute.String("grant_type", "refresh_token"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRefreshed, family.UserID, family.ClientID, "", "family="+family.ID))
	}

	return &input.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    int(s.config.AccessTokenExpiry.Seconds()),
		RefreshToken: refreshPlain,
		Scope:        effectiveScope,
	}, nil
}

// --- Extracted helpers ---

// authenticateClient looks up a client by ID, verifies it is active,
// and verifies the client secret for confidential clients.
func (s *TokenService) authenticateClient(ctx context.Context, span trace.Span, clientID, clientSecret string) error {
	c, err := s.clients.GetByID(ctx, clientID)
	if err != nil {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "client not found")
		return domain.ErrInvalidClient
	}

	if !c.IsActive() {
		span.RecordError(domain.ErrClientSuspended)
		span.SetStatus(codes.Error, "client suspended")
		return domain.ErrClientSuspended
	}

	if !c.IsPublic() {
		if clientSecret == "" {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "missing client_secret")
			return domain.ErrInvalidClient
		}
		if err := crypto.CompareClientSecret(c.SecretHash, clientSecret); err != nil {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "invalid client_secret")
			return domain.ErrInvalidClient
		}
	} else if clientSecret != "" {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "public client sent secret")
		return domain.ErrInvalidClient
	}

	return nil
}

// mintParams holds the per-request inputs TokenService passes through to
// MintIssuer for grants where the caller still works off session-level
// strings (Resource as a URI, Scope as a space-separated list).
// rotates these callers to *resource.Resource directly.
type mintParams struct {
	UserID   string
	ClientID string
	Scope    string
	Resource string
	DPoPJKT  string // JWK thumbprint for DPoP binding (RFC 9449); empty = standard Bearer
}

// buildMintRequest constructs the IssueRequest fed to MintIssuer.Issue.
// When the TokenService has been wired with a ResourceRegistry (via
// WithResourceRegistry — set in cmd/authserver/serve.go), the session
// resource URI is resolved to a typed *resource.Resource and threaded
// through so MintIssuer can persist the issuances audit row. Without
// the registry (e.g. in unit tests that didn't opt in), the auth-code
// and refresh-token grants fall back to the previously behavior of
// emitting the audience-only IssueRequest with no audit row written.
//
// AgentIdentity is intentionally nil for ExchangeCode / RefreshToken: the
// existing AgentIdentityService is consulted only by TokenExchange and
// JWTBearer ( fold those into MintIssuer too). Standard grants
// preserve their previously JWT shape — agent_id / agent_chain remain
// empty when the issuing client is not in an agent flow.
func (s *TokenService) buildMintRequest(ctx context.Context, now, expiry time.Time, p mintParams) IssueRequest {
	var audience []string
	if p.Resource != "" {
		audience = []string{p.Resource}
	}

	req := IssueRequest{
		SubjectUserID: p.UserID,
		ActorClientID: p.ClientID,
		Scopes:        strings.Fields(p.Scope),
		DPoPJKT:       p.DPoPJKT,
		Audience:      audience,
		NotBefore:     now,
		Expiry:        expiry,
	}

	// Resolve the resource to a typed pointer so MintIssuer.Issue can
	// persist the issuances audit row (FK target resources.id).
	if s.resourceRegistry != nil && p.Resource != "" {
		if res, err := s.resourceRegistry.Resolve(ctx, p.Resource); err == nil && res != nil {
			req.Resource = res
		} else if err != nil {
			// Resolve failure is non-fatal — token issuance proceeds without
			// the audit row, matching previously behavior. The error is
			// logged so operators can spot misconfigured sessions
			// (e.g. session.resource pointed at a URI not registered as a
			// resources.uri / resources.slug row).
			s.logger.WarnContext(ctx, "resolve resource for issuance audit row failed",
				"resource", p.Resource,
				"error", err,
			)
		}
	}
	return req
}

// createRefreshToken generates a random refresh token, hashes it, and stores it.
func (s *TokenService) createRefreshToken(ctx context.Context, span trace.Span, familyID string, now time.Time) (string, error) {
	refreshPlain := crypto.GenerateRandomString(32)
	refreshHash := crypto.HashSHA256(refreshPlain)
	rt := &token.RefreshToken{
		ID:        crypto.GenerateRandomString(16),
		FamilyID:  familyID,
		TokenHash: refreshHash,
		ExpiresAt: now.Add(s.config.RefreshTokenExpiry),
		CreatedAt: now,
	}
	if err := s.tokens.CreateRefreshToken(ctx, rt); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("create refresh token: %w", err)
	}
	return refreshPlain, nil
}

// trackJTI records a JTI for introspection blacklist support (best-effort).
func (s *TokenService) trackJTI(ctx context.Context, jti, familyID string, expiry time.Time) {
	if s.revocation != nil {
		if err := s.revocation.TrackJTI(ctx, jti, familyID, expiry); err != nil {
			s.logger.WarnContext(ctx, "failed to track JTI", "jti", jti, "error", err)
		}
	}
}

// validateDPoP validates a DPoP proof JWT and consumes its JTI for replay detection.
// Returns the JWK thumbprint (jkt) on success. If DPoP is not configured on this
// service, the proof is silently ignored and an empty jkt is returned.
func (s *TokenService) validateDPoP(ctx context.Context, span trace.Span, proof, method, reqURL, accessTokenHash string) (string, error) {
	if s.dpopStore == nil || s.dpopConfig == nil {
		// DPoP not enabled — ignore the proof.
		return "", nil
	}

	// Determine the server nonce to validate against (empty if not required).
	// When require_nonce is true, the middleware will have issued a nonce
	// on a prior request. The proof must include it; ValidateProof checks this.
	// We pass empty here — the middleware handles nonce issuance/validation
	// at the HTTP layer. The service validates only the proof structure.
	var serverNonce string

	result, err := crypto.ValidateProof(proof, method, reqURL, serverNonce, accessTokenHash, s.dpopConfig.ProofLifetime)
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
	jtiExpiry := time.Now().Add(s.dpopConfig.ProofLifetime * 2) // keep JTI for 2x proof lifetime
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
func (s *TokenService) recordDPoPMetric(ctx context.Context, err error) {
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

// consumeOrRevokeFamily atomically consumes a refresh token. If reuse is
// detected, the entire family is revoked and ErrFamilyRevoked is returned.
func (s *TokenService) consumeOrRevokeFamily(ctx context.Context, span trace.Span, rt *token.RefreshToken) error {
	_, err := s.tokens.ConsumeRefreshToken(ctx, rt.ID)
	if errors.Is(err, domain.ErrRefreshTokenReused) {
		// Wrap the reuse-detection revocation in a transaction so that
		// RevokeFamily + RevokeByFamily are atomic — no window for a
		// concurrent request to issue tokens from the same family.
		revokeAll := func(txCtx context.Context) error {
			if revokeErr := s.tokens.RevokeFamily(txCtx, rt.FamilyID); revokeErr != nil {
				return fmt.Errorf("revoke family during reuse detection: %w", revokeErr)
			}
			if s.revocation != nil {
				if rErr := s.revocation.RevokeByFamily(txCtx, rt.FamilyID); rErr != nil {
					s.logger.WarnContext(txCtx, "failed to revoke JTIs during reuse detection",
						"family_id", rt.FamilyID, "error", rErr,
					)
				}
			}
			return nil
		}

		var revokeErr error
		if s.txManager != nil {
			revokeErr = s.txManager.WithTransaction(ctx, revokeAll)
		} else {
			revokeErr = revokeAll(ctx)
		}
		if revokeErr != nil {
			s.logger.ErrorContext(ctx, "failed to revoke family during reuse detection",
				"family_id", rt.FamilyID,
				"error", revokeErr,
			)
		}

		s.logger.WarnContext(ctx, "refresh token reuse detected — family revoked",
			"family_id", rt.FamilyID,
			"token_id", rt.ID,
		)
		s.metrics.RefreshTokenReuse.Add(ctx, 1)
		s.metrics.TokensRevoked.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", "family_revocation"),
		))
		if s.audit != nil {
			s.audit.Record(ctx, audit.NewEvent(audit.ActionFamilyRevoked, "", "", "", "reuse_detection family="+rt.FamilyID))
		}
		span.RecordError(domain.ErrFamilyRevoked)
		span.SetStatus(codes.Error, "refresh token reuse detected")
		return domain.ErrFamilyRevoked
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("consume refresh token: %w", err)
	}
	return nil
}
