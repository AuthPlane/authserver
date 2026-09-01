package services

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
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

// RevokeToken revokes a token. Per RFC 7009, the response is always 200
// except for client authentication failures.
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

	// 2. Hash token and try to find as refresh token.
	tokenHash := crypto.HashSHA256(req.Token)
	rt, err := s.tokens.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		// Not found as refresh token → try machine token revocation via JWT parsing.
		s.tryRevokeMachineToken(ctx, span, req)
		return nil
	}

	// 3. Verify the token belongs to the requesting client.
	family, err := s.tokens.GetFamily(ctx, rt.FamilyID)
	if err != nil {
		return nil // silently succeed
	}
	if family.ClientID != req.ClientID {
		// Token belongs to different client — don't revoke, but still return 200.
		s.logger.WarnContext(ctx, "revocation attempt for token owned by different client",
			"requesting_client", req.ClientID,
			"owning_client", family.ClientID,
		)
		return nil
	}

	// 4. Revoke the entire family.
	if _, err := s.tokens.RevokeFamily(ctx, rt.FamilyID); err != nil {
		s.logger.ErrorContext(ctx, "failed to revoke family", "family_id", rt.FamilyID, "error", err)
		return nil // still return 200 per RFC 7009
	}

	// 4b. Blacklist all access token JTIs for this family.
	if s.revocation != nil {
		if err := s.revocation.RevokeByFamily(ctx, rt.FamilyID); err != nil {
			s.logger.WarnContext(ctx, "failed to revoke JTIs by family",
				"family_id", rt.FamilyID, "error", err,
			)
		}
	}

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

	return nil
}

// tryRevokeMachineToken attempts to parse the token as a JWT and revoke it
// as a machine token. Best-effort: errors are silently ignored per RFC 7009.
func (s *RevocationService) tryRevokeMachineToken(ctx context.Context, _ trace.Span, req input.RevokeRequest) {
	if s.machineTokens == nil || s.jwks == nil {
		s.logger.DebugContext(ctx, "token not found for revocation (may be access token or unknown)")
		return
	}

	// Try to parse and verify the JWT to extract JTI.
	jwks, err := s.jwks.BuildJWKS(ctx)
	if err != nil {
		s.logger.DebugContext(ctx, "revocation: failed to build JWKS for machine token check")
		return
	}

	issuer, err := s.issuerProvider.Issuer(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "revocation: failed to resolve issuer for machine token check",
			"error", err,
		)
		return
	}
	claims, err := crypto.VerifyAccessTokenWithIssuer(req.Token, jwks, issuer)
	if err != nil {
		s.logger.DebugContext(ctx, "revocation: token is not a valid JWT from this AS")
		return
	}

	// Only revoke if the token belongs to the requesting client.
	if claims.ClientID != req.ClientID {
		s.logger.WarnContext(ctx, "revocation: machine token owned by different client",
			"requesting_client", req.ClientID,
			"owning_client", claims.ClientID,
		)
		return
	}

	// Revoke via MachineTokenStore.
	if err := s.machineTokens.Revoke(ctx, claims.JTI); err != nil {
		s.logger.WarnContext(ctx, "revocation: failed to revoke machine token",
			"jti", claims.JTI,
			"error", err,
		)
		return
	}

	s.logger.InfoContext(ctx, "machine token revoked via revocation endpoint",
		"jti", claims.JTI,
		"client_id", req.ClientID,
	)

	s.metrics.TokensRevoked.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("reason", "explicit_machine"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenRevoked, "", req.ClientID, "", "machine_token jti="+claims.JTI))
	}
}
