package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// TokenService implements input.TokenPort.
type TokenService struct {
	sessions    output.SessionStore
	tokens      output.TokenStore
	clients     output.ClientStore
	users       output.UserStore
	jwks        JWKSSigningKeyProvider
	mintIssuer  *MintIssuer            // signs Mint access tokens + writes the issuances audit row.
	revocation  output.RevocationStore // optional, for JTI tracking (introspection support)
	audit       AuditRecorder
	tokenConfig output.TokenConfigProvider // resolves access/refresh TTLs per request
	resources   ResourceLister             // resource catalog (kept for ResourceLister.List() walks)
	logger      *slog.Logger
	tracer      trace.Tracer
	metrics     *observability.Metrics

	// DPoP support (RFC 9449) — optional. When dpopStore is nil, DPoP is disabled.
	dpopStore  output.DPoPNonceStore
	dpopConfig output.DPoPConfigProvider

	// Transaction support — optional. When nil, multi-step operations are not atomic.
	txManager output.TransactionManager

	// resourceRegistry resolves a session/family resource URI to a typed
	// *resource.Resource so MintIssuer can persist the issuances audit row
	// (resources.id is the FK target). Optional: when nil, the legacy
	// behavior applies — auth-code and refresh-token grants do not write an
	// issuance row (which is the  /  audit-gap that surfaced as
	// "Issuances list is empty" in the Admin UI).
	resourceRegistry *ResourceRegistry

	// agentIdentity resolves the agent_id / agent_chain claims for the
	// issuing client. Optional: when nil, tokens carry neither claim.
	agentIdentity *AgentIdentityService
}

// JWKSSigningKeyProvider provides signing keys for JWT issuance.
type JWKSSigningKeyProvider interface {
	GetSigningKey(ctx context.Context) (*output.SigningKey, error)
}

var _ input.TokenPort = (*TokenService)(nil)

// NewTokenService creates a new token service.
// mintIssuer signs Mint access tokens and persists the issuances audit row;
// it must be non-nil — callers wire it in cmd/authserver/serve.go.
// tokenConfig resolves the token lifetimes (access/refresh TTL) per request.
func NewTokenService(
	sessions output.SessionStore,
	tokens output.TokenStore,
	clients output.ClientStore,
	users output.UserStore,
	jwks JWKSSigningKeyProvider,
	mintIssuer *MintIssuer,
	tokenConfig output.TokenConfigProvider,
	obs *observability.Provider,
	auditor AuditRecorder,
	revocation output.RevocationStore,
	resources ResourceLister,
) *TokenService {
	if tokenConfig == nil {
		panic("NewTokenService: tokenConfig must not be nil")
	}
	return &TokenService{
		sessions:    sessions,
		tokens:      tokens,
		clients:     clients,
		users:       users,
		jwks:        jwks,
		mintIssuer:  mintIssuer,
		revocation:  revocation,
		audit:       auditor,
		tokenConfig: tokenConfig,
		resources:   resources,
		logger:      obs.Logger,
		tracer:      obs.Tracer,
		metrics:     obs.Metrics,
	}
}

// WithDPoP enables DPoP proof-of-possession support on the token service.
// When enabled, clients may present a DPoP proof to bind access tokens to their key pair.
func (s *TokenService) WithDPoP(store output.DPoPNonceStore, cfg output.DPoPConfigProvider) {
	s.dpopStore = store
	s.dpopConfig = cfg
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

// WithAgentIdentity enables agent identity claim attachment on the
// authorization_code and refresh_token grants, matching what
// client_credentials, token exchange and jwt-bearer already do. Without
// it, a token issued to a client registered with is_agent=true carries no
// agent_id — which is the first hop of a user-consented agent flow, so
// resource servers reading agent_id saw nothing on the primary flow.
func (s *TokenService) WithAgentIdentity(ai *AgentIdentityService) {
	s.agentIdentity = ai
}

// ExchangeCode exchanges an authorization code + PKCE verifier for tokens.
//
// Every failure emits a durable denial event. The wrapper is what guarantees
// that: gating on the named return covers each existing branch and every branch
// added later, which a per-branch call cannot promise.
func (s *TokenService) ExchangeCode(ctx context.Context, req input.ExchangeCodeRequest) (resp *input.TokenResponse, err error) {
	defer func() {
		if err != nil {
			s.recordDenied(ctx, audit.ActionTokenIssueDenied, req.ClientID, err)
		}
	}()
	return s.exchangeCode(ctx, req)
}

// recordDenied emits a best-effort denial event. The reason is the OAuth error
// code the client will see, so the audit trail and the wire agree; anything not
// a domain error surfaces as server_error.
func (s *TokenService) recordDenied(ctx context.Context, action audit.Action, clientID string, err error) {
	if s.audit == nil {
		return
	}
	// The client is the actor of the denied request: record it in ActorID
	// (as well as ClientID) so actor-filtered audit queries surface denials,
	// mirroring the success events that populate the actor. When the client
	// id is unknown (e.g. omitted pre-parse), clientID is "" and both stay blank.
	s.audit.Record(ctx, audit.NewEvent(
		action, clientID, clientID, "",
		fmt.Sprintf("reason=%s", domain.ErrorCode(err)),
	))
}

func (s *TokenService) exchangeCode(ctx context.Context, req input.ExchangeCodeRequest) (*input.TokenResponse, error) {
	ctx, span := s.tracer.Start(ctx, "TokenService.ExchangeCode")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("grant_type", "authorization_code"),
	)
	start := time.Now()

	// Resolve the token lifetimes up front, before the auth code is consumed
	// below: a config-resolution error must not burn the single-use code
	// (ConsumeByCodeHash is irreversible).
	tokenCfg, err := s.tokenConfig.Config(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve token config: %w", err)
	}

	// 1. Hash the code and atomically consume.
	codeHash := crypto.HashSHA256(req.Code)
	sess, err := s.sessions.ConsumeByCodeHash(ctx, codeHash)
	if err != nil {
		// A replay: respond to it, then answer exactly as before. The store
		// returns the session alongside ErrCodeConsumed precisely for this.
		if errors.Is(err, domain.ErrCodeConsumed) && sess != nil {
			s.handleCodeReuse(ctx, span, sess, req.CodeVerifier, req.ClientID)
		}
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
	authedClient, authErr := s.authenticateClient(ctx, span, sess.ClientID, req.ClientSecret)
	if authErr != nil {
		return nil, authErr
	}

	// Resolve the agent claims off the client just authenticated. Reading
	// the loaded client rather than re-fetching keeps this infallible, so
	// no new failure mode lands downstream of the consume above.
	agentClaims := extractAgentIdentityClaimsForClient(ctx, s.agentIdentity, authedClient, nil)

	// 6. Verify PKCE.
	if pkceErr := crypto.VerifyS256(req.CodeVerifier, sess.CodeChallenge); pkceErr != nil {
		span.RecordError(domain.ErrInvalidPKCE)
		span.SetStatus(codes.Error, "PKCE verification failed")
		return nil, domain.ErrInvalidPKCE
	}

	// 6.4. RFC 8707 §2.2: a resource named in the token request must be one
	// this grant covers. After PKCE for the same reason step 6.5 is: the
	// refusal is observable, and whether a given resource is registered — and
	// whether it is the one this code was authorized for — must not be
	// readable by a caller who has not proved it holds the code. A public
	// client presents no secret, so PKCE is that proof.
	//
	// Placing it earlier costs nothing to move: the code is consumed at step 1
	// either way, so a late refusal does not spend anything a caller would
	// otherwise keep.
	if resErr := s.validateRequestedResource(ctx, req.Resource, sess.Resource); resErr != nil {
		span.RecordError(resErr)
		span.SetStatus(codes.Error, "requested resource not authorized by this grant")
		return nil, resErr
	}

	// 6.5. Check the subject is still active, matching RefreshToken. After
	// PKCE, not after authenticateClient: a public client presents no secret,
	// so PKCE is the only proof the caller legitimately holds this code, and
	// the account-status difference must not be observable without it.
	//
	// The code was consumed at step 1 and stays consumed. Do NOT move this check
	// above ConsumeByCodeHash to spare the code: an unburned code could be probed
	// repeatedly, which reopens the account-status oracle PKCE placement closes.
	// That prohibition stands even if SessionStore later grows a non-consuming
	// read by code hash — today it has none, which is the mechanical reason the
	// hoist is impossible, but it is not the reason it is forbidden.
	//
	// So a store outage here spends the code and answers 5xx. That is the
	// fail-closed answer: with the store unreachable the subject's status is
	// unknowable, and this grant refuses rather than guesses.
	//
	// In a single process the exposure is narrow: this lookup and
	// SessionMiddleware's read one WithUserCache-wrapped DataStore
	// (cmd/authserver/serve.go), so they degrade together — a warm entry serves
	// /authorize, /consent and this redemption without touching the store, a
	// cold one is stopped at the middleware before a code exists, and a code
	// burns only in the seam between them.
	//
	// That bound does not survive more than one instance, which is the shape
	// the deploy docs recommend. The cache is per process, and this redemption
	// is a back-channel call with no affinity to the browser that walked
	// /authorize: it routinely lands on an instance that never served the
	// front-channel and may hold no entry at all. A cold instance reaches the
	// dead store and burns the code the warm one issued.
	//
	// One case per reason so the span names what happened. Two of the four are
	// denials — a wiped row and a disabled account — and both return the same
	// invalid_grant, indistinguishable to the caller. The other two decided
	// nothing about the account (the store was unreachable, or answered with
	// neither user nor error) and surface as server faults.
	if s.users != nil && sess.UserID != "" {
		u, userErr := s.users.GetByID(ctx, sess.UserID)
		switch {
		case errors.Is(userErr, domain.ErrUserNotFound):
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "user not found")
			return nil, domain.ErrInvalidGrant
		case errors.Is(userErr, domain.ErrStoreReturnedNoUser):
			// How a broken store arrives through storage.WithUserCache, which
			// converts its (nil, nil) into this error. Ahead of the generic arm
			// because that one would swallow it and report a lookup failure —
			// telling an operator the database is down when the store is
			// defective.
			span.RecordError(domain.ErrStoreReturnedNoUser)
			span.SetStatus(codes.Error, "user store returned no user")
			return nil, fmt.Errorf("resolve subject: %w", userErr)
		case userErr != nil:
			span.RecordError(userErr)
			span.SetStatus(codes.Error, "user lookup failed")
			return nil, fmt.Errorf("resolve subject: %w", userErr)
		case u == nil:
			// The same defect from an unwrapped store, where the nil arrives
			// raw. Answers exactly as the arm above: wrapped and unwrapped have
			// to agree, and 500 is the answer both should give.
			span.RecordError(domain.ErrStoreReturnedNoUser)
			span.SetStatus(codes.Error, "user store returned no user")
			return nil, fmt.Errorf("resolve subject: %w", domain.ErrStoreReturnedNoUser)
		case !u.IsActive():
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "user disabled")
			return nil, domain.ErrInvalidGrant
		}
		// Subject resolved and active; fall through to mint.
	}

	// 7. Validate DPoP proof if present (RFC 9449). After PKCE, so after the
	// consume at step 1: a refused proof spends the code and the use_dpop_nonce
	// retry §8 mandates then fails. Accepted because nothing before step 1
	// proves anything about the caller, and validating earlier would put an
	// ECDSA verification and the ConsumeJTI insert behind no authentication on
	// an endpoint with no rate limiter. Every other grant validates DPoP after
	// authenticating the client; this one stays with them.
	//
	// Bounded in practice: dpop.require_nonce is false by default, and when on,
	// the rejected response still carries a fresh DPoP-Nonce (DPoPNonceMiddleware
	// sets it on every token response, errors included), so a client that caches
	// it pays one re-authorization per nonce lifetime, not one per exchange.
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
	expiry := now.Add(tokenCfg.AccessTokenExpiry)
	mintResp, err := s.mintIssuer.Issue(ctx, s.buildMintRequest(ctx, now, expiry, mintParams{
		UserID:        sess.UserID,
		ClientID:      sess.ClientID,
		Scope:         sess.Scope,
		Resource:      sess.Resource,
		DPoPJKT:       dpopJKT,
		AgentIdentity: agentClaims,
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
		ID:       familyID,
		ClientID: sess.ClientID,
		UserID:   sess.UserID,
		Scope:    sess.Scope,
		Resource: sess.Resource,
		Status:   token.FamilyActive,
		// The authorization this family came from. Written here, inside the
		// same INSERT that creates the family, so the link cannot exist
		// without the family or the family without the link. A replayed code
		// is resolved to exactly this family.
		AuthSessionID: sess.ID,
		CreatedAt:     now,
	}
	var refreshPlain string
	createFamilyAndRefresh := func(txCtx context.Context) error {
		if createErr := s.tokens.CreateFamily(txCtx, family); createErr != nil {
			return fmt.Errorf("create token family: %w", createErr)
		}
		s.trackJTI(txCtx, jti, familyID, expiry)
		var refreshErr error
		refreshPlain, refreshErr = s.createRefreshToken(txCtx, span, familyID, now, tokenCfg.RefreshTokenExpiry)
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

	// auth_session_id is the join key between this line and the reuse WARN in
	// handleCodeReuse: an operator who sees a credentialed replay that found no
	// family needs to know whether one was committed moments later, and which.
	s.logger.InfoContext(ctx, "tokens issued",
		"client_id", sess.ClientID,
		"user_id", sess.UserID,
		"family_id", familyID,
		"auth_session_id", sess.ID,
		"token_type", tokenType,
	)

	s.metrics.TokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("grant_type", "authorization_code"),
	))
	s.recordAgentTokenIssued(ctx, agentClaims)
	s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
		attribute.String("grant_type", "authorization_code"),
	))

	// Audit stays outside the transaction and best-effort: failing to record is
	// our bug, and must never cost the user their token. The cost of that choice
	// — a token with no row — is made loud rather than silent (AuditService.Record).
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenIssued, sess.UserID, sess.ClientID, "", "family="+familyID))
	}

	return &input.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    int(tokenCfg.AccessTokenExpiry.Seconds()),
		RefreshToken: refreshPlain,
		Scope:        sess.Scope,
	}, nil
}

// RefreshToken rotates a refresh token and issues a new access token.
func (s *TokenService) RefreshToken(ctx context.Context, req input.RefreshTokenRequest) (resp *input.TokenResponse, err error) {
	defer func() {
		if err != nil {
			s.recordDenied(ctx, audit.ActionTokenRefreshDenied, req.ClientID, err)
		}
	}()
	return s.refreshToken(ctx, req)
}

func (s *TokenService) refreshToken(ctx context.Context, req input.RefreshTokenRequest) (*input.TokenResponse, error) {
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
	authedClient, authErr := s.authenticateClient(ctx, span, family.ClientID, req.ClientSecret)
	if authErr != nil {
		return nil, authErr
	}

	// RFC 8707 §2.2, same rule as the authorization-code path. Placed before
	// the consume below so a refused resource does not also spend the refresh
	// token.
	if resErr := s.validateRequestedResource(ctx, req.Resource, family.Resource); resErr != nil {
		span.RecordError(resErr)
		span.SetStatus(codes.Error, "requested resource not authorized by this family")
		return nil, resErr
	}

	// Resolve the agent claims off the client just authenticated, before the
	// consume below, for the same reason the token config is resolved here:
	// nothing that can fail may run after ConsumeRefreshToken has burned the
	// old token. Reading the already-loaded client keeps this infallible and
	// costs no extra client-store round trip.
	agentClaims := extractAgentIdentityClaimsForClient(ctx, s.agentIdentity, authedClient, nil)

	// Scope, bounded twice: by what the family was granted at consent
	// (RFC 6749 §6) and by the client's ceiling as it stands now. The family
	// froze its scope at the original authorization; an operator who has
	// since narrowed the client through PATCH /admin/clients/{id} expects the
	// narrowing to bind here too, not only at /oauth/authorize. Resolved
	// before the consume so a refused scope leaves the refresh token
	// unspent — the client can retry within bounds rather than losing the
	// family to a typo.
	effectiveScope, scopeErr := refreshScope(req.Scope, family.Scope, authedClient)
	if scopeErr != nil {
		span.RecordError(scopeErr)
		span.SetStatus(codes.Error, scopeErr.Error())
		return nil, scopeErr
	}

	// Resolve the token lifetimes before the refresh token is consumed below:
	// a config-resolution error must not burn the old refresh token
	// (ConsumeRefreshToken is irreversible). Mirrors ExchangeCode.
	tokenCfg, err := s.tokenConfig.Config(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve token config: %w", err)
	}

	// 3. Atomically consume the refresh token (one conditional UPDATE, so
	// concurrent presenters race safely). Reuse detection runs here; on
	// reuse the family half commits on its own, then the JTI denylist is
	// attempted. Now safe because the caller is authenticated above.
	if consumeErr := s.consumeOrRevokeFamily(ctx, span, rt); consumeErr != nil {
		return nil, consumeErr
	}

	// 4. Check user is still active.
	//
	// One arm per reason. The caller sees the same invalid_grant from all of
	// them — it must not be able to tell a wiped row from a disabled account —
	// but the span names which happened, because an operator chasing "user
	// disabled" should not be sent to the admin audit trail for a disable that
	// never occurred. The u == nil arm is also the guard that keeps a store
	// breaking its contract from panicking here; the collapsed condition this
	// replaced evaluated u.IsActive() whenever userErr was nil.
	//
	// All four stay 400. Answering 500 for the store-side ones would be more
	// honest, but the token is already consumed above, and a 5xx invites the
	// retry that presents a spent token and revokes the family. Separating
	// them properly means moving this check above the consume, which is a
	// tracked decision rather than a detail of this check.
	if s.users != nil && family.UserID != "" {
		u, userErr := s.users.GetByID(ctx, family.UserID)
		switch {
		case errors.Is(userErr, domain.ErrUserNotFound):
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "user not found")
			return nil, domain.ErrInvalidGrant
		case errors.Is(userErr, domain.ErrStoreReturnedNoUser):
			// How a broken store arrives through storage.WithUserCache. Ahead
			// of the generic arm, which would report a lookup failure and point
			// an operator at a database outage that never happened.
			span.RecordError(domain.ErrStoreReturnedNoUser)
			span.SetStatus(codes.Error, "user store returned no user")
			return nil, domain.ErrInvalidGrant
		case userErr != nil:
			span.RecordError(userErr)
			span.SetStatus(codes.Error, "user lookup failed")
			return nil, domain.ErrInvalidGrant
		case u == nil:
			// The same defect from an unwrapped store, where the nil arrives raw.
			span.RecordError(domain.ErrStoreReturnedNoUser)
			span.SetStatus(codes.Error, "user store returned no user")
			return nil, domain.ErrInvalidGrant
		case !u.IsActive():
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "user disabled")
			return nil, domain.ErrInvalidGrant
		}
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
	// ExchangeCode and as the legacy machine_tokens write. Token lifetimes
	// were resolved before the consume above (resolve-before-consume).
	now := time.Now().UTC()
	expiry := now.Add(tokenCfg.AccessTokenExpiry)
	mintResp, err := s.mintIssuer.Issue(ctx, s.buildMintRequest(ctx, now, expiry, mintParams{
		UserID:        family.UserID,
		ClientID:      family.ClientID,
		Scope:         effectiveScope,
		Resource:      family.Resource,
		DPoPJKT:       dpopJKT,
		AgentIdentity: agentClaims,
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
		// The token minted above is never returned, but its issuance row
		// was written before the revocation's cascade could see it and
		// its jti was tracked after the denylist ran. Revoke the row so
		// the issuance log does not show a live token nobody holds.
		if mintResp.IssuanceID != "" && s.mintIssuer != nil && s.mintIssuer.issuances != nil {
			if rerr := s.mintIssuer.issuances.Revoke(ctx, mintResp.IssuanceID); rerr != nil {
				s.logger.ErrorContext(ctx, "refresh refused after mint but its issuance row could not be revoked",
					"jti", mintResp.IssuanceID, "family_id", family.ID, "error", rerr)
			}
		}
		return nil, domain.ErrFamilyRevoked
	}

	// 10. Create rotated refresh token.
	refreshPlain, err := s.createRefreshToken(ctx, span, family.ID, now, tokenCfg.RefreshTokenExpiry)
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
	s.recordAgentTokenIssued(ctx, agentClaims)
	s.metrics.TokenIssuanceDuration.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(
		attribute.String("grant_type", "refresh_token"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRefreshed, family.UserID, family.ClientID, "", "family="+family.ID))
	}

	return &input.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    int(tokenCfg.AccessTokenExpiry.Seconds()),
		RefreshToken: refreshPlain,
		Scope:        effectiveScope,
	}, nil
}

// --- Extracted helpers ---

// authenticateClient looks up a client by ID, verifies it is active,
// and verifies the client secret for confidential clients. The loaded
// client is returned so callers can read it without a second store
// round trip — matching ClientCredentialsService, TokenExchangeService
// and JWTBearerService, whose authenticateClient already does this.
// refreshScope resolves the scope a refreshed access token carries.
//
// The family bounds the request the way RFC 6749 §6 describes: a requested
// scope wider than the original grant is refused. The client's current
// ceiling then bounds the result. An explicit request outside the ceiling is
// refused, matching what /oauth/authorize would say to the same request; an
// omitted request is narrowed to the intersection, so a session an operator
// has since restricted continues with what remains rather than being cut
// off. An intersection with nothing left is refused, since a token carrying
// no scope hides the cause behind a string of 403s.
//
// An empty ceiling does not bound, for the same reason as on the authorize
// path: clients created through dynamic registration or CIMD before
// oauth.default_client_scope existed have none, and refusing them here
// would end every one of their sessions on upgrade. v0.3.0 closes that.
func refreshScope(requested, familyScope string, c *client.Client) (string, error) {
	granted := scope.Parse(familyScope)
	ceiling := scope.Parse(c.Scope)

	if requested != "" {
		asked := scope.Parse(requested)
		if !asked.IsSubset(granted) {
			return "", domain.ErrInvalidScope
		}
		if !ceiling.IsEmpty() && !asked.IsSubset(ceiling) {
			return "", scopeDenialError(c, ceiling)
		}
		return asked.String(), nil
	}

	// Nothing requested: the family's scope stands unless the ceiling cuts
	// it. Returned as stored rather than re-serialized, so the wire value
	// keeps the order the consent recorded — the same string this path has
	// always echoed.
	if ceiling.IsEmpty() || granted.IsSubset(ceiling) {
		return familyScope, nil
	}
	narrowed := granted.Intersect(ceiling)
	if narrowed.IsEmpty() {
		return "", scopeDenialError(c, ceiling)
	}
	return narrowed.String(), nil
}

func (s *TokenService) authenticateClient(ctx context.Context, span trace.Span, clientID, clientSecret string) (*client.Client, error) {
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

	if !c.IsPublic() {
		if clientSecret == "" {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "missing client_secret")
			return nil, domain.ErrInvalidClient
		}
		if err := crypto.CompareClientSecret(c.SecretHash, clientSecret); err != nil {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "invalid client_secret")
			return nil, domain.ErrInvalidClient
		}
	} else if clientSecret != "" {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "public client sent secret")
		return nil, domain.ErrInvalidClient
	}

	return c, nil
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

	// AgentIdentity is the agent_id / agent_chain pair resolved from the
	// authenticated client. nil when the client is not an agent or the
	// service was not wired with an AgentIdentityService.
	AgentIdentity *AgentIdentityClaims
}

// validateRequestedResource enforces RFC 8707 §2.2 at the token endpoint: a
// resource named in the token request must be one the authorization grant
// already covers.
//
// Silently ignoring it — which is what happened before this existed — hands the
// client a token audienced somewhere else and no error. The client only learns
// at the resource server, as a 401 with nothing in it pointing back at the
// resource parameter it sent.
//
// The comparison is on resource identity, not on the string the client happened
// to send. Both sides go through the registry first, because the authorize step
// stores the resolved identifier: a client that echoes back its own original
// spelling (a trailing slash, say, which resolution drops) is asking for the
// same resource and must not be refused for it.
//
// An empty requested value means the client omitted the parameter, which RFC
// 8707 permits; the grant's own resource still applies.
func (s *TokenService) validateRequestedResource(ctx context.Context, requested, authorized string) error {
	if requested == "" || requested == authorized {
		return nil
	}

	// MCP-CORE-031 asks implementations to accept a resource whose scheme or
	// host differs only in case, so the comparison folds those two components
	// and nothing else. Path, query and fragment stay byte-exact: a trailing
	// slash is a different path, and the compliance statement says so.
	if resourceIdentityEqual(requested, authorized) {
		return nil
	}

	if s.resourceRegistry != nil {
		requestedRes, err := s.resourceRegistry.Resolve(ctx, requested)
		if err != nil || requestedRes == nil {
			return fmt.Errorf("%w: resource %q is not a registered resource", domain.ErrInvalidTarget, requested)
		}
		if authorized != "" {
			if authorizedRes, aErr := s.resourceRegistry.Resolve(ctx, authorized); aErr == nil &&
				authorizedRes != nil && authorizedRes.ID == requestedRes.ID {
				return nil
			}
		}
	}

	return fmt.Errorf("%w: resource %q was not authorized by this grant", domain.ErrInvalidTarget, requested)
}

// resourceIdentityEqual reports whether two resource identifiers name the same
// resource once case is folded in the two components where RFC 3986 §6.2.2.1
// makes case insignificant — the scheme and the host. Everything else is
// compared byte for byte.
//
// It exists so that MCP-CORE-031 ("SHOULD accept uppercase scheme and host for
// interoperability") does not turn into a refusal, without also swallowing a
// path difference that names a genuinely different resource.
func resourceIdentityEqual(a, b string) bool {
	au, aErr := url.Parse(a)
	bu, bErr := url.Parse(b)
	if aErr != nil || bErr != nil {
		return false
	}
	au.Scheme, bu.Scheme = strings.ToLower(au.Scheme), strings.ToLower(bu.Scheme)
	au.Host, bu.Host = strings.ToLower(au.Host), strings.ToLower(bu.Host)
	return au.String() == bu.String()
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
// p.AgentIdentity is resolved by the caller, off the client authenticateClient
// already loaded, so a client registered with is_agent=true gets agent_id on
// its authorization_code and refresh_token access tokens — the first hop of a
// user-consented agent flow.
//
// Neither grant builds an RFC 8693 'act' chain, so agent_chain stays empty
// here. It is populated only where an 'act' claim exists: token exchange
// builds one per delegation hop, and jwt-bearer sets a single-entry 'act'
// carrying the asserting IdP as provenance (see jwt_bearer.go) — which is
// not a delegation chain despite feeding the same field.
//
// client_credentials, jwt-bearer and token exchange resolve the same claims,
// but still by client id — rotating them onto the already-authenticated
// client is a follow-up, not part of this fix.
func (s *TokenService) buildMintRequest(ctx context.Context, now, expiry time.Time, p mintParams) IssueRequest {
	var audience []string
	if p.Resource != "" {
		audience = []string{p.Resource}
	}

	req := IssueRequest{
		SubjectUserID: p.UserID,
		ActorClientID: p.ClientID,
		Scopes:        strings.Fields(p.Scope),
		AgentIdentity: p.AgentIdentity,
		DPoPJKT:       p.DPoPJKT,
		// The client the user consented to is the one being issued to:
		// this is the first hop, the token the rest of a chain derives
		// from. Recorded so consent revocation seeds on it by the same
		// column as every later hop, not by the legacy client_id fallback.
		ConsentClientID: p.ClientID,
		Audience:        audience,
		NotBefore:       now,
		Expiry:          expiry,
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

// recordAgentTokenIssued counts an agent token once the grant has actually
// issued one. It sits next to TokensIssued / TokensRefreshed so the
// agent-scoped counter can never exceed the total-token counter for the same
// requests.
//
// Both grants resolve their agent claims well before they finish: ahead of
// PKCE verification and DPoP in exchangeCode, and ahead of the refresh-token
// consume in refreshToken. Either can still fail after minting — a failed
// refresh-family transaction, a family revoked mid-flight — so counting at
// resolution, or even right after MintIssuer returns, would credit tokens the
// caller never receives.
func (s *TokenService) recordAgentTokenIssued(ctx context.Context, agentClaims *AgentIdentityClaims) {
	if s.agentIdentity == nil || agentClaims == nil {
		return
	}
	s.agentIdentity.RecordIssued(ctx, len(agentClaims.AgentChain) > 0)
}

// createRefreshToken generates a random refresh token, hashes it, and stores it.
func (s *TokenService) createRefreshToken(ctx context.Context, span trace.Span, familyID string, now time.Time, refreshExpiry time.Duration) (string, error) {
	refreshPlain := crypto.GenerateRandomString(32)
	refreshHash := crypto.HashSHA256(refreshPlain)
	rt := &token.RefreshToken{
		ID:        crypto.GenerateRandomString(16),
		FamilyID:  familyID,
		TokenHash: refreshHash,
		ExpiresAt: now.Add(refreshExpiry),
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

	// Determine the server nonce to validate against (empty if not required).
	// When require_nonce is true, the middleware will have issued a nonce
	// on a prior request. The proof must include it; ValidateProof checks this.
	// We pass empty here — the middleware handles nonce issuance/validation
	// at the HTTP layer. The service validates only the proof structure.
	var serverNonce string

	result, err := crypto.ValidateProof(proof, method, reqURL, serverNonce, accessTokenHash, dpopCfg.ProofLifetime)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "DPoP proof validation failed")
		s.recordDPoPMetric(ctx, err)
		return "", err
	}

	// If require_nonce is set, validate the nonce from the proof against the store.
	if dpopCfg.RequireNonce {
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
	jtiExpiry := time.Now().Add(dpopCfg.ProofLifetime * 2) // keep JTI for 2x proof lifetime
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

// consumeOrRevokeFamily consumes a refresh token. If reuse is detected, the
// family is revoked (revokeFamilyOnReuse) and ErrFamilyRevoked is returned;
// if the family revocation itself fails, ErrReuseRevocationFailed is
// returned.
func (s *TokenService) consumeOrRevokeFamily(ctx context.Context, span trace.Span, rt *token.RefreshToken) error {
	_, err := s.tokens.ConsumeRefreshToken(ctx, rt.ID)
	// Consumed: the token was current and is now spent — the normal
	// rotation step, nothing to revoke.
	if err == nil {
		return nil
	}
	// Any error other than "already consumed" is a store failure, not a
	// replay: surface it to the caller without touching the family.
	if !errors.Is(err, domain.ErrRefreshTokenReused) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("consume refresh token: %w", err)
	}
	return s.revokeFamilyOnReuse(ctx, span, rt)
}

// reuseTarget describes one reuse-detection response so both halves report
// identically no matter which path detected the reuse. Every user-visible
// string is a field rather than derived, so the refresh path's log lines,
// audit details and metric labels stay byte-identical to what #187 shipped —
// the runbook queries and dashboards depend on them.
type reuseTarget struct {
	familyID     string
	path         string // RevocationFailures{path}
	detailPrefix string // audit detail prefix
	revokeReason string // TokensRevoked{reason}
	logRevoked   string // WARN emitted when the family is revoked
	logFamilyErr string // ERROR emitted when the family half fails
	logJTIErr    string // ERROR emitted when the denylist half fails
	logKV        []any  // extra log fields identifying what was replayed
}

// refreshReuseTarget reproduces exactly what the refresh path emitted before
// this became a descriptor. Do not change these values.
func refreshReuseTarget(rt *token.RefreshToken) reuseTarget {
	return reuseTarget{
		familyID:     rt.FamilyID,
		path:         "reuse",
		detailPrefix: "reuse_detection",
		revokeReason: "family_revocation",
		logRevoked:   "refresh token reuse detected — family revoked",
		logFamilyErr: "failed to revoke family during reuse detection",
		logJTIErr:    "JTI denylist failed during reuse detection",
		logKV:        []any{"token_id", rt.ID},
	}
}

// codeReuseTarget is the authorization-code counterpart of refreshReuseTarget.
// Its path label is reserved on RevocationFailures; its detail prefix keeps
// the refresh path's runbook queries (reuse_detection …) from matching.
func codeReuseTarget(familyID, sessionID string) reuseTarget {
	return reuseTarget{
		familyID:     familyID,
		path:         "code_reuse",
		detailPrefix: "code_reuse",
		revokeReason: "code_reuse",
		logRevoked:   "authorization code reuse detected — family revoked",
		logFamilyErr: "failed to revoke family during code reuse detection",
		logJTIErr:    "JTI denylist failed during code reuse detection",
		logKV:        []any{"session_id", sessionID},
	}
}

// runReuseHalves runs the family half then the denylist half and reports each
// as it happened. The denylist runs even when the family half failed —
// deliberately: it cuts the stolen access token of a replayer who can no
// longer refresh. Neither half decides anything about the caller's error.
func (s *TokenService) runReuseHalves(ctx context.Context, span trace.Span, tgt reuseTarget) (familyRevoked, jtisDenylisted bool) {
	familyRevoked = s.revokeFamilyHalf(ctx, span, tgt)
	jtisDenylisted = s.denylistFamilyJTIs(ctx, span, tgt)
	return familyRevoked, jtisDenylisted
}

// revokeFamilyOnReuse is the reuse-detection response: revoke the family,
// denylist its access-token JTIs, and report each half as it happened.
// The halves run family first, denylist always — even after a family
// failure — deliberately NOT in one transaction, and each reports its own
// outcome; only the family half decides the sentinel and the span status.
// The full weighing (why no transaction, backend divergence, the
// crash-atomicity cost) is in
// docs/guides/operate/token-design-internals.md § reuse detection.
//
// Returns ErrFamilyRevoked when the family is revoked (whether or not the
// denylist half succeeded) and ErrReuseRevocationFailed when it is not.
func (s *TokenService) revokeFamilyOnReuse(ctx context.Context, span trace.Span, rt *token.RefreshToken) error {
	// The detection happened whether or not the store lets us act on it.
	s.metrics.RefreshTokenReuse.Add(ctx, 1)

	familyRevoked, jtisDenylisted := s.runReuseHalves(ctx, span, refreshReuseTarget(rt))

	// Only the family half decides the error: a live family (its current
	// refresh token keeps rotating) outweighs the ≤ exp residue of a
	// failed denylist.
	if !familyRevoked {
		span.SetStatus(codes.Error, "refresh token reuse detected, family revocation failed")
		return domain.ErrReuseRevocationFailed
	}
	status := "refresh token reuse detected"
	if !jtisDenylisted {
		status += ", JTI denylist failed"
	}
	span.RecordError(domain.ErrFamilyRevoked)
	span.SetStatus(codes.Error, status)
	return domain.ErrFamilyRevoked
}

// revokeFamilyHalf revokes the family (family row + every refresh token,
// atomic on its own) and reports its own outcome either way. Knows nothing
// about the denylist half. Returns true when revoked.
func (s *TokenService) revokeFamilyHalf(ctx context.Context, span trace.Span, tgt reuseTarget) bool {
	revoked, err := s.tokens.RevokeFamily(ctx, tgt.familyID)
	if err != nil {
		s.reportReuseHalfFailure(ctx, span, tgt, "family", tgt.logFamilyErr, audit.ActionFamilyRevocationFailed, err)
		return false
	}
	// The store revoked nothing: no active row matched. Whoever got there
	// first — a concurrent detection, an admin revoke, a force-logout, or a
	// cascade that deleted the family — reported it; this half succeeded
	// because the family is not live either way.
	if !revoked {
		s.logger.InfoContext(ctx, "family already revoked — nothing to report",
			append([]any{"family_id", tgt.familyID}, tgt.logKV...)...)
		return true
	}
	s.logger.WarnContext(ctx, tgt.logRevoked,
		append([]any{"family_id", tgt.familyID}, tgt.logKV...)...)
	s.metrics.TokensRevoked.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("reason", tgt.revokeReason),
	))
	s.auditReuse(ctx, audit.ActionFamilyRevoked, tgt.detailPrefix+" family="+tgt.familyID)
	return true
}

// denylistFamilyJTIs denylists the family's tracked access-token JTIs and
// reports its own failure. Knows nothing about the family half. Returns true
// when the JTIs are denylisted — including when there is no revocation store,
// in which case there is nothing to denylist.
func (s *TokenService) denylistFamilyJTIs(ctx context.Context, span trace.Span, tgt reuseTarget) bool {
	if s.revocation == nil {
		return true
	}
	err := s.revocation.RevokeByFamily(ctx, tgt.familyID)
	if err == nil {
		return true
	}
	s.reportReuseHalfFailure(ctx, span, tgt, "jti", tgt.logJTIErr, audit.ActionFamilyDenylistFailed, err)
	return false
}

// reportReuseHalfFailure reports one half's failure the same way for both
// halves: ERROR log, RevocationFailures{path,half}, span error, and the half's
// own audit row. The audit detail and the counter derive `half` from the same
// argument, so the runbook's detail-string queries cannot drift from the
// metric labels.
func (s *TokenService) reportReuseHalfFailure(ctx context.Context, span trace.Span, tgt reuseTarget, half, logMsg string, action audit.Action, err error) {
	// Built in two explicit steps: a nested append could alias the descriptor's
	// backing array if logKV is ever created with spare capacity.
	kv := append([]any{"family_id", tgt.familyID}, tgt.logKV...)
	kv = append(kv, "error", err)
	s.logger.ErrorContext(ctx, logMsg, kv...)
	s.metrics.RevocationFailures.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("path", tgt.path),
		attribute.String("half", half),
	))
	span.RecordError(err)
	s.auditReuse(ctx, action, tgt.detailPrefix+" family="+tgt.familyID+" path="+tgt.path+" half="+half)
}

// auditReuse writes a reuse-detection audit row (best-effort, nil-safe).
func (s *TokenService) auditReuse(ctx context.Context, action audit.Action, detail string) {
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(action, "", "", "", detail))
	}
}

// handleCodeReuse responds to a replayed authorization code. Best-effort and
// silent by design: it never changes the error exchangeCode returns, because
// what the client sees on a replay must not depend on whether revocation
// worked.
//
// The detection is recorded unconditionally. Revocation is gated on the
// replayer proving they could plausibly have been the original client: PKCE
// is mandatory (authorize.go:110), so a replayer without the verifier could
// never have redeemed this code, and the same is true of a caller presenting
// a different client_id than the one the session was issued to. Revoking on
// either replayer's say-so would hand anyone who finds a spent code a
// credential-free logout button for its owner. Full reasoning in
// docs/guides/operate/token-design-internals.md § authorization-code reuse
// detection.
//
// The metric and audit "verifier" label folds a client_id mismatch into
// "invalid" — it does not get its own value — so verifier="valid"|"invalid"
// keeps meaning exactly what it always has: existing dashboards and alerts
// built on those two values do not need to learn a third.
func (s *TokenService) handleCodeReuse(ctx context.Context, span trace.Span, sess *session.AuthSession, verifier, clientID string) {
	verifierOK := crypto.VerifyS256(verifier, sess.CodeChallenge) == nil
	clientOK := clientID == sess.ClientID
	credentialed := verifierOK && clientOK
	label := "invalid"
	if credentialed {
		label = "valid"
	}

	s.metrics.AuthCodeReuse.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("verifier", label),
	))
	// Attributed to the user and client the code was issued to, as
	// token.issued is, so the row surfaces in the actor- and client-filtered
	// audit views. The client_id the replayer presented is on the
	// token_issue.denied row of the same request.
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionAuthCodeReused, sess.UserID, sess.ClientID, "",
			"code_reuse session="+sess.ID+" verifier="+label))
	}

	if !credentialed {
		s.logger.WarnContext(ctx, "authorization code reuse detected — replayer not credentialed, nothing revoked",
			"session_id", sess.ID,
			"client_id", sess.ClientID,
			"verifier_ok", verifierOK,
			"client_ok", clientOK,
		)
		return
	}

	fam, err := s.tokens.GetFamilyByAuthSessionID(ctx, sess.ID)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidGrant) {
			// No family is linked to this session, and this path cannot tell
			// apart the two causes:
			//
			//   - The first redemption aborted before step 9. Every failure
			//     between the consume and the family INSERT burns the code
			//     without minting — PKCE, DPoP, the subject lookup, the mint.
			//     Nothing exists, and nothing needs revoking.
			//   - The first redemption is still in flight and has not
			//     committed its family. Tokens are about to exist, and this
			//     replay will not have revoked them.
			//
			// So the line reports what was observed — nothing was revoked —
			// and not the conclusion that there was nothing to revoke, which
			// the second case makes false. To tell them apart, correlate
			// against a "tokens issued" line carrying the same
			// auth_session_id.
			//
			// It logs at all because the counter increments before this
			// branch: without it, verifier="valid" — the strongest signal the
			// server emits, and the one the runbook pages on — can fire with
			// no matching line anywhere in the log. And the replayer that
			// reaches it can be the legitimate client: someone holding only
			// the code redeems it first, fails PKCE at step 6 and burns it
			// without minting, then the owner's own exchange lands here with
			// the genuine verifier. verifier="valid" on this branch means the
			// code leaked, not that the verifier did.
			s.logger.WarnContext(ctx, "authorization code reuse detected — credentialed replay, no family linked to the session, nothing revoked",
				"session_id", sess.ID,
				"client_id", sess.ClientID,
			)
			return
		}
		s.logger.ErrorContext(ctx, "authorization code reuse detected — family lookup failed",
			"session_id", sess.ID,
			"error", err,
		)
		span.RecordError(err)
		return
	}

	tgt := codeReuseTarget(fam.ID, sess.ID)

	// A family is revoked once: RevokeFamily is a no-op on a revoked family,
	// and re-running that half would report a revocation that did not
	// happen. The denylist half still runs — it is idempotent, and a denylist
	// that failed on an earlier replay is retried here instead of leaving the
	// family's access tokens live until exp.
	if !fam.IsActive() {
		s.logger.WarnContext(ctx, "authorization code reuse detected — family already revoked",
			"session_id", sess.ID,
			"client_id", sess.ClientID,
			"family_id", fam.ID,
		)
		s.denylistFamilyJTIs(ctx, span, tgt)
		return
	}

	// Both halves report themselves. Their outcome does not reach the caller:
	// the client sees ErrCodeConsumed either way.
	s.runReuseHalves(ctx, span, tgt)
}
