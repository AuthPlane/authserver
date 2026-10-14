package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// RevocationService implements input.RevocationPort (RFC 7009).
type RevocationService struct {
	tokens         output.TokenStore
	clients        output.ClientStore
	machineTokens  output.MachineTokenStore // optional: for machine token revocation
	jwks           JWKSBuildProvider        // optional: for JWT parsing during machine token revocation
	revocation     output.RevocationStore   // optional, for JTI blacklisting (introspection support)
	issuances      output.IssuanceStore     // optional: issuance rows of registered-resource tokens
	audit          AuditRecorder
	issuerProvider output.IssuerProvider
	logger         *slog.Logger
	tracer         trace.Tracer
	metrics        *observability.Metrics
}

var _ input.RevocationPort = (*RevocationService)(nil)

// NewRevocationService creates a new revocation service.
func NewRevocationService(
	tokens output.TokenStore,
	clients output.ClientStore,
	machineTokens output.MachineTokenStore,
	jwks JWKSBuildProvider,
	issuerProvider output.IssuerProvider,
	obs *observability.Provider,
	auditor AuditRecorder,
	revocation output.RevocationStore,
) *RevocationService {
	if issuerProvider == nil {
		panic("services.NewRevocationService: issuerProvider is required")
	}
	return &RevocationService{
		tokens:         tokens,
		clients:        clients,
		machineTokens:  machineTokens,
		jwks:           jwks,
		revocation:     revocation,
		audit:          auditor,
		issuerProvider: issuerProvider,
		logger:         obs.Logger,
		tracer:         obs.Tracer,
		metrics:        obs.Metrics,
	}
}

// WithIssuanceStore attaches the issuance log, so revoking a token minted
// for a registered resource also sets revoked_at on its issuance row, which
// introspection and token exchange both honor. Set in
// cmd/authserver/serve.go and in the e2e harness.
func (s *RevocationService) WithIssuanceStore(store output.IssuanceStore) {
	s.issuances = store
}

// RevokeToken revokes a token. Per RFC 7009, the response is 200 for any
// token the server can answer about, including unknown, foreign and already
// revoked ones. A client authentication failure returns ErrInvalidClient.
// Any other error means a store could not record the revocation, and the
// token may still be valid: the handler answers 503 so the client retries
// (RFC 7009 §2.2.1) instead of being told the token is gone.
func (s *RevocationService) RevokeToken(ctx context.Context, req input.RevokeRequest) error {
	ctx, span := s.tracer.Start(ctx, "RevocationService.RevokeToken")
	defer span.End()

	span.SetAttributes(attribute.String("client_id", req.ClientID))

	// 1. Authenticate client.
	c, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "client not found")
		return domain.ErrInvalidClient
	}

	// A suspended or revoked client keeps no standing to revoke. How that
	// refusal is expressed depends on whether the caller proved anything:
	// status is only disclosed to someone who already knows the secret.
	//
	// Public clients stay welcome here — unlike introspection, RFC 7009
	// revocation is advertised with "none" among its auth methods and a public
	// client revoking its own token is the intended flow.
	if c.IsPublic() {
		// A public client_id is public by construction: it travels in browser
		// redirects and in the authorize URL. Answering invalid_client for a
		// suspended one and 200 for an active one would turn this endpoint into
		// an anonymous client-status oracle. An inactive public client instead
		// gets the ordinary RFC 7009 200 and revokes nothing.
		if !c.IsActive() {
			s.logger.WarnContext(ctx, "revocation attempt by inactive public client",
				"client_id", req.ClientID,
			)
			return nil
		}
	} else {
		// Not cost-equalized, for the reasons spelled out on
		// IntrospectionService.authenticateCaller: the padding costs a bcrypt
		// derivation on a path that needs no credential, and this endpoint has
		// no per-caller bound to contain it.
		if req.ClientSecret == "" {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "missing client_secret")
			return domain.ErrInvalidClient
		}
		if bcryptErr := crypto.CompareClientSecret(c.SecretHash, req.ClientSecret); bcryptErr != nil {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "invalid client_secret")
			return domain.ErrInvalidClient
		}
		// Only now, with the secret proven, may the status be revealed: the
		// caller has demonstrated it is the client, so it learns nothing new.
		if !c.IsActive() {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "client not active")
			return domain.ErrInvalidClient
		}
	}

	// 2. Hash token and try to find as refresh token. Not-found is
	// ErrInvalidGrant; anything else is a store that could not answer.
	tokenHash := crypto.HashSHA256(req.Token)
	rt, err := s.tokens.GetRefreshTokenByHash(ctx, tokenHash)
	if errors.Is(err, domain.ErrInvalidGrant) {
		// Not a refresh token: try it as an access token.
		return s.revokeAccessToken(ctx, span, req)
	}
	if err != nil {
		return s.storeFault(span, "look up refresh token", err)
	}

	// 3. Verify the token belongs to the requesting client.
	family, err := s.tokens.GetFamily(ctx, rt.FamilyID)
	if errors.Is(err, domain.ErrInvalidGrant) {
		return nil
	}
	if err != nil {
		return s.storeFault(span, "look up token family", err)
	}
	if family.ClientID != req.ClientID {
		// Token belongs to different client — don't revoke, but still return 200.
		s.logger.WarnContext(ctx, "revocation attempt for token owned by different client",
			"requesting_client", req.ClientID,
			"owning_client", family.ClientID,
		)
		return nil
	}

	// 4. Revoke the entire family. revoked is false when it already was.
	// The family row commits on its own, so this call records the revocation
	// now: if the denylist write below fails, the retry finds the family
	// already revoked and must not be the first to report it.
	revoked, err := s.tokens.RevokeFamily(ctx, rt.FamilyID)
	if err != nil {
		return s.storeFault(span, "revoke token family", err)
	}
	if revoked {
		s.logger.InfoContext(ctx, "token family revoked via revocation endpoint",
			"family_id", rt.FamilyID,
			"client_id", req.ClientID,
		)
		s.metrics.TokensRevoked.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", "explicit"),
		))
		if s.audit != nil {
			s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRevoked, "", req.ClientID, "", "family="+rt.FamilyID))
		}
	}

	// 4b. Blacklist all access token JTIs for this family. Runs even for a
	// family already revoked, so a denylist write that failed before is
	// retried; it is idempotent.
	if s.revocation != nil {
		if err := s.revocation.RevokeByFamily(ctx, rt.FamilyID); err != nil {
			return s.storeFault(span, "denylist token family", err)
		}
	}
	return nil
}

// storeFault records a revocation a store could not complete. The caller
// gets an error, not the RFC 7009 200, because the token may still be valid.
func (s *RevocationService) storeFault(span trace.Span, step string, err error) error {
	span.RecordError(err)
	span.SetStatus(codes.Error, step+" failed")
	return fmt.Errorf("revocation: %s: %w", step, err)
}

// revokeAccessToken revokes a JWT access token the caller owns in every
// place a revocation is recorded: its machine_tokens row (client_credentials,
// jwt-bearer and resource-less exchange tokens), its issuance row (any token
// minted for a registered resource, whatever the grant), and the JTI
// denylist until the token's own exp (every token, including those with
// neither row). A token that is not a valid JWT from this AS, or
// that another client owns, is left alone with the RFC 7009 200. Only a
// store that actually changed is counted and audited.
func (s *RevocationService) revokeAccessToken(ctx context.Context, span trace.Span, req input.RevokeRequest) error {
	if s.jwks == nil {
		s.logger.DebugContext(ctx, "token not found for revocation (may be access token or unknown)")
		return nil
	}
	jwks, err := s.jwks.BuildJWKS(ctx)
	if err != nil {
		return s.storeFault(span, "build JWKS", err)
	}
	issuer, err := s.issuerProvider.Issuer(ctx)
	if err != nil {
		return s.storeFault(span, "resolve issuer", err)
	}
	claims, err := crypto.VerifyAccessTokenWithIssuer(req.Token, jwks, issuer)
	if err != nil {
		s.logger.DebugContext(ctx, "revocation: token is not a valid JWT from this AS")
		return nil
	}
	if claims.ClientID != req.ClientID {
		s.logger.WarnContext(ctx, "revocation: access token owned by different client",
			"requesting_client", req.ClientID,
			"owning_client", claims.ClientID,
		)
		return nil
	}

	// Read every record first, so the call can tell whether the token was
	// already revoked anywhere before it wrote anything.
	var mt *token.MachineToken
	if s.machineTokens != nil {
		if mt, err = s.machineTokens.GetByJTI(ctx, claims.JTI); err != nil {
			return s.storeFault(span, "look up machine token", err)
		}
	}
	var iss *resource.Issuance
	if s.issuances != nil {
		if iss, err = s.issuances.GetByJTI(ctx, claims.JTI); err != nil {
			return s.storeFault(span, "look up issuance", err)
		}
	}
	denied := false
	if s.revocation != nil {
		if denied, err = s.revocation.IsRevoked(ctx, claims.JTI); err != nil {
			return s.storeFault(span, "look up denylist", err)
		}
	}
	// The call that first revokes the token audits and counts it, once,
	// even when a later write fails and the client retries: each write
	// commits on its own, and the token is refused as soon as one lands.
	// A call that only completes an earlier revocation records nothing new.
	first := (mt == nil || !mt.Revoked) && (iss == nil || !iss.IsRevoked()) && !denied

	var revokedIn []string
	fail := func(step string, err error) error {
		if first && len(revokedIn) > 0 {
			// The write may have failed because the request was canceled;
			// the audit row for what did land must still be written, since
			// no retry will write it.
			s.recordAccessTokenRevoked(context.WithoutCancel(ctx), req.ClientID, claims.JTI, revokedIn)
		}
		return s.storeFault(span, step, err)
	}
	if mt != nil && !mt.Revoked {
		if err := s.machineTokens.Revoke(ctx, claims.JTI); err != nil {
			return fail("revoke machine token", err)
		}
		revokedIn = append(revokedIn, "machine_token")
	}
	if iss != nil && !iss.IsRevoked() {
		if err := s.issuances.Revoke(ctx, iss.ID); err != nil {
			return fail("revoke issuance", err)
		}
		revokedIn = append(revokedIn, "issuance")
	}
	if s.revocation != nil && !denied {
		if err := s.revocation.RevokeJTI(ctx, claims.JTI, time.Unix(claims.Expiry, 0)); err != nil {
			return fail("denylist access token", err)
		}
		revokedIn = append(revokedIn, "denylist")
	}

	switch {
	case len(revokedIn) == 0:
		s.logger.DebugContext(ctx, "revocation: access token already revoked", "jti", claims.JTI)
	case first:
		s.recordAccessTokenRevoked(ctx, req.ClientID, claims.JTI, revokedIn)
	default:
		s.logger.InfoContext(ctx, "revocation: completed an earlier access-token revocation",
			"jti", claims.JTI, "client_id", req.ClientID, "revoked_in", strings.Join(revokedIn, ","))
	}
	return nil
}

// recordAccessTokenRevoked logs, counts and audits the call that first
// revoked an access token, naming the records it wrote.
func (s *RevocationService) recordAccessTokenRevoked(ctx context.Context, clientID, jti string, revokedIn []string) {
	stores := strings.Join(revokedIn, ",")
	s.logger.InfoContext(ctx, "access token revoked via revocation endpoint",
		"jti", jti, "client_id", clientID, "revoked_in", stores)

	reason := "explicit_access"
	if slices.Contains(revokedIn, "machine_token") {
		reason = "explicit_machine"
	}
	s.metrics.TokensRevoked.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("reason", reason),
	))
	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRevoked, "", clientID, "",
			fmt.Sprintf("access_token jti=%s revoked_in=%s", jti, stores)))
	}
}
