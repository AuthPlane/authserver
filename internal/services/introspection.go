package services

import (
	"context"
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
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// JWKSBuildProvider provides the JWKS key set for JWT verification.
type JWKSBuildProvider interface {
	BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// IntrospectionService implements input.IntrospectionPort (RFC 7662).
type IntrospectionService struct {
	jwks          JWKSBuildProvider
	revocation    output.RevocationStore
	machineTokens output.MachineTokenStore // optional: for machine token revocation checks
	clients       output.ClientStore
	users         output.UserStore
	audit         AuditRecorder
	issuer        string
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics
}

var _ input.IntrospectionPort = (*IntrospectionService)(nil)

// NewIntrospectionService creates a new introspection service.
func NewIntrospectionService(
	jwks JWKSBuildProvider,
	revocation output.RevocationStore,
	machineTokens output.MachineTokenStore,
	clients output.ClientStore,
	users output.UserStore,
	issuer string,
	obs *observability.Provider,
	auditor AuditRecorder,
) *IntrospectionService {
	return &IntrospectionService{
		jwks:          jwks,
		revocation:    revocation,
		machineTokens: machineTokens,
		clients:       clients,
		users:         users,
		audit:         auditor,
		issuer:        issuer,
		logger:        obs.Logger,
		tracer:        obs.Tracer,
		metrics:       obs.Metrics,
	}
}

// IntrospectToken validates a token and returns its active status and claims.
// Per RFC 7662 §2.2: invalid/expired/revoked tokens return {active: false}, not errors.
// Only client authentication failures return errors.
func (s *IntrospectionService) IntrospectToken(ctx context.Context, req input.IntrospectRequest) (*input.IntrospectResponse, error) {
	ctx, span := s.tracer.Start(ctx, "IntrospectionService.IntrospectToken")
	defer span.End()

	span.SetAttributes(attribute.String("client_id", req.ClientID))
	start := time.Now()

	// 1. Authenticate the requesting client.
	c, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		span.RecordError(domain.ErrInvalidClient)
		span.SetStatus(codes.Error, "client not found")
		s.recordMetric(ctx, start, "error")
		return nil, domain.ErrInvalidClient
	}

	if !c.IsPublic() {
		if req.ClientSecret == "" {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "missing client_secret")
			s.recordMetric(ctx, start, "error")
			return nil, domain.ErrInvalidClient
		}
		if bcryptErr := crypto.CompareClientSecret(c.SecretHash, req.ClientSecret); bcryptErr != nil {
			span.RecordError(domain.ErrInvalidClient)
			span.SetStatus(codes.Error, "invalid client_secret")
			s.recordMetric(ctx, start, "error")
			return nil, domain.ErrInvalidClient
		}
	}

	// 2. Parse and verify the JWT.
	jwks, err := s.jwks.BuildJWKS(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to build JWKS for introspection", "error", err)
		s.recordMetric(ctx, start, "inactive")
		return &input.IntrospectResponse{Active: false}, nil
	}

	claims, err := crypto.VerifyAccessTokenWithIssuer(req.Token, jwks, s.issuer)
	if err != nil {
		s.logger.DebugContext(ctx, "introspection: token verification failed", "error", err)
		s.recordMetric(ctx, start, "inactive")
		return &input.IntrospectResponse{Active: false}, nil
	}

	// 3. Determine if this is a machine token by checking the machine token store.
	// Machine tokens include client_credentials, jwt-bearer, and token exchange grants.
	// Previously used sub == client_id heuristic, but jwt-bearer tokens have federated subjects.
	isMachineToken := false
	if s.machineTokens != nil && claims.JTI != "" {
		mt, mtErr := s.machineTokens.GetByJTI(ctx, claims.JTI)
		if mtErr == nil && mt != nil {
			isMachineToken = true
			if mt.Revoked {
				s.logger.InfoContext(ctx, "introspection: machine token revoked", "jti", claims.JTI, "client_id", claims.ClientID)
				s.recordMetric(ctx, start, "inactive")
				return &input.IntrospectResponse{Active: false}, nil
			}
		}
	}

	// 4. Check revocation for non-machine tokens via RevocationStore JTI blacklist.
	if !isMachineToken && s.revocation != nil && claims.JTI != "" {
		revoked, revErr := s.revocation.IsRevoked(ctx, claims.JTI)
		if revErr != nil {
			s.logger.WarnContext(ctx, "introspection: revocation check failed", "jti", claims.JTI, "error", revErr)
			s.recordMetric(ctx, start, "inactive")
			return &input.IntrospectResponse{Active: false}, nil
		}
		if revoked {
			s.logger.InfoContext(ctx, "introspection: token revoked", "jti", claims.JTI, "client_id", claims.ClientID)
			s.recordMetric(ctx, start, "inactive")
			return &input.IntrospectResponse{Active: false}, nil
		}
	}

	// 5. Check that the issuing client is still active.
	issuingClient, err := s.clients.GetByID(ctx, claims.ClientID)
	if err != nil || !issuingClient.IsActive() {
		s.logger.InfoContext(ctx, "introspection: issuing client suspended or not found",
			"issuing_client_id", claims.ClientID,
		)
		s.recordMetric(ctx, start, "inactive")
		return &input.IntrospectResponse{Active: false}, nil
	}

	// 6. Check that the subject user is still active (skip for machine tokens).
	if !isMachineToken && s.users != nil && claims.Subject != "" {
		u, userErr := s.users.GetByID(ctx, claims.Subject)
		if userErr != nil || !u.IsActive() {
			s.logger.InfoContext(ctx, "introspection: subject user disabled or not found",
				"sub", claims.Subject,
			)
			s.recordMetric(ctx, start, "inactive")
			return &input.IntrospectResponse{Active: false}, nil
		}
	}

	// 7. Token is active — build response.
	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}

	// Determine token type and DPoP confirmation from claims.
	tokenType := "Bearer"
	var cnf map[string]interface{}
	if claims.Cnf != nil {
		if _, hasJKT := claims.Cnf["jkt"]; hasJKT {
			tokenType = "DPoP"
			cnf = claims.Cnf
		}
	}

	s.logger.InfoContext(ctx, "token introspected",
		"jti", claims.JTI,
		"client_id", claims.ClientID,
		"sub", claims.Subject,
		"requesting_client", req.ClientID,
		"token_type", tokenType,
	)
	s.recordMetric(ctx, start, "active")

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenIntrospected, "", req.ClientID, "",
			"jti="+claims.JTI+" issuing_client="+claims.ClientID,
		))
	}

	return &input.IntrospectResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		Sub:       claims.Subject,
		Aud:       aud,
		Iss:       claims.Issuer,
		Exp:       claims.Expiry,
		Iat:       claims.IssuedAt,
		Jti:       claims.JTI,
		TokenType: tokenType,
		Cnf:       cnf,
	}, nil
}

func (s *IntrospectionService) recordMetric(ctx context.Context, start time.Time, result string) {
	s.metrics.IntrospectionDuration.Record(ctx, time.Since(start).Seconds())
	s.metrics.IntrospectionTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", result),
	))
}
