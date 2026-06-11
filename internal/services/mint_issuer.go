package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// MintIssuer is the AS-signs-its-own-token half of the unified Issuer
// model (the architecture doc). It replaces TokenService.signAccessToken,
// extracting JWT construction + persistence into a standalone service so
// every Mint code path emits an issuances audit row uniformly with
// BrokerIssuer.
//
// Wired in cmd/authserver/serve.go and consumed by TokenService
// (ExchangeCode, RefreshToken) directly until a follow-up routes Mint
// requests through internal/issuer.Registry alongside BrokerIssuer.
//
// No metrics here: the legacy TokenService.TokensIssued /
// TokenIssuanceDuration instruments stay with the caller, and a
// dedicated authserver_mint_issue_* family lands with the wiring
// rotation in a follow-up. Tracing, structured logging, and audit
// (caller-side) are the observability surfaces here — matches
// BrokerIssuer.
type MintIssuer struct {
	keys      JWKSSigningKeyProvider
	issuances output.IssuanceStore
	issuer    string
	logger    *slog.Logger
	tracer    trace.Tracer
}

// Compile-time substitution gate: MintIssuer must satisfy the unified
// Issuer interface so internal/issuer.Registry can dispatch to it.
var _ Issuer = (*MintIssuer)(nil)

// NewMintIssuer constructs a MintIssuer over the given signing-key
// provider and issuance store. issuer is the AS issuer URL (used as the
// 'iss' claim and as the audience fallback when the request supplies
// neither Audience nor Resource).
func NewMintIssuer(
	keys JWKSSigningKeyProvider,
	issuances output.IssuanceStore,
	issuer string,
	obs *observability.Provider,
) *MintIssuer {
	return &MintIssuer{
		keys:      keys,
		issuances: issuances,
		issuer:    issuer,
		logger:    obs.Logger.With("component", "mint_issuer"),
		tracer:    obs.Tracer,
	}
}

// Kind reports the BackendKind this Issuer handles. Used by
// internal/issuer.Registry for self-registration.
func (m *MintIssuer) Kind() resource.BackendKind { return resource.BackendMint }

// Issue produces an AS-signed access token for the request and persists
// the matching issuance audit row. Behavior parity with the previous
// TokenService.signAccessToken is required for v0.1.0-rc1: same claims,
// same audience-fallback semantics, same may_act / cnf shape. The new
// surface is the issuance row and the explicit AgentIdentity field —
// AgentID and AgentChain on the JWT now flow from the request, so a
// single code path owns the agent-claim contract.
func (m *MintIssuer) Issue(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	ctx, span := m.tracer.Start(ctx, "MintIssuer.Issue")
	defer span.End()

	if req.Expiry.IsZero() {
		err := errors.New("mint issuer requires a non-zero Expiry")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	now := time.Now().UTC()
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = now
	}

	aud := mintAudience(req, m.issuer)

	span.SetAttributes(
		attribute.String("subject_user_id", req.SubjectUserID),
		attribute.String("actor_client_id", req.ActorClientID),
		attribute.String("audience", strings.Join(aud, " ")),
		attribute.Int("scope_count", len(req.Scopes)),
		attribute.Bool("dpop_bound", req.DPoPJKT != ""),
	)
	if req.Resource != nil {
		span.SetAttributes(
			attribute.String("resource_id", req.Resource.ID),
			attribute.String("resource_slug", req.Resource.Slug),
		)
	}

	sk, err := m.keys.GetSigningKey(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		m.logger.ErrorContext(ctx, "mint issue: signing key fetch failed",
			"actor_client_id", req.ActorClientID,
			"subject_user_id", req.SubjectUserID,
			"error", err,
		)
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	jti := crypto.GenerateRandomString(16)
	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  jose.SignatureAlgorithm(sk.Algorithm),
		KeyID:      sk.KeyID,
	}

	claims := crypto.AccessTokenClaims{
		Issuer:     m.issuer,
		Subject:    req.SubjectUserID,
		Audience:   aud,
		ClientID:   req.ActorClientID,
		Scope:      strings.Join(req.Scopes, " "),
		JTI:        jti,
		IssuedAt:   now.Unix(),
		Expiry:     req.Expiry.Unix(),
		NotBefore:  notBefore.Unix(),
		Act:        req.Act,
		AgentID:    agentIDOf(req.AgentIdentity),
		AgentChain: agentChainOf(req.AgentIdentity),
	}
	if req.DPoPJKT != "" {
		claims.Cnf = map[string]interface{}{"jkt": req.DPoPJKT}
	}

	signed, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		m.logger.ErrorContext(ctx, "mint issue: sign failed",
			"actor_client_id", req.ActorClientID,
			"subject_user_id", req.SubjectUserID,
			"error", err,
		)
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// Persist the issuance audit row when the caller resolved the target
	// Resource. The issuances.resource_id column is FK NOT NULL → resources
	// (the data model / migrations 001_initial), so the row can only be
	// written when the caller supplied a real Resource.ID. The audit row
	// is left empty for legacy TokenService callers that still work off
	// a session-URI string (ExchangeCode, RefreshToken); a follow-up
	// closes that gap when ResourceRegistry replaces ResourceLister and every
	// grant flow resolves a *resource.Resource before issuing. Behavior
	// parity is preserved: the same callers had no issuances row previously
	// either (the legacy machine_tokens path via trackJTI is the audit
	// surface for them).
	if req.Resource != nil {
		iss := &resource.Issuance{
			ID:            jti,
			SubjectUserID: req.SubjectUserID,
			ClientID:      req.ActorClientID,
			ResourceID:    req.Resource.ID,
			Scopes:        req.Scopes,
			BackendKind:   resource.BackendMint,
			Revocable:     true,
			IssuedAt:      now,
			ExpiresAt:     req.Expiry,
			JTI:           jti,
			DPoPJKT:       req.DPoPJKT,
			AgentID:       agentIDOf(req.AgentIdentity),
		}
		iss.SetAgentChain(agentChainOf(req.AgentIdentity))
		if err := m.issuances.Insert(ctx, iss); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			m.logger.ErrorContext(ctx, "mint issue: issuance insert failed",
				"actor_client_id", req.ActorClientID,
				"subject_user_id", req.SubjectUserID,
				"jti", jti,
				"error", err,
			)
			return nil, fmt.Errorf("insert mint issuance: %w", err)
		}
	} else {
		span.AddEvent("mint_issuance_skipped_unresolved_resource")
		m.logger.DebugContext(ctx, "mint issue: skipped issuance audit row (no resolved Resource)",
			"actor_client_id", req.ActorClientID,
			"subject_user_id", req.SubjectUserID,
			"jti", jti,
		)
	}

	tokenType := "Bearer"
	if req.DPoPJKT != "" {
		tokenType = "DPoP"
	}

	expiresIn := int(req.Expiry.Sub(now).Seconds())

	m.logger.InfoContext(ctx, "mint token issued",
		"actor_client_id", req.ActorClientID,
		"subject_user_id", req.SubjectUserID,
		"issuance_id", jti,
		"token_type", tokenType,
	)

	return &IssueResponse{
		AccessToken: signed,
		TokenType:   tokenType,
		ExpiresIn:   expiresIn,
		IssuanceID:  jti,
	}, nil
}

// mintAudience resolves the 'aud' claim with three-tier precedence:
//  1. req.Audience verbatim when non-empty.
//  2. []string{req.Resource.URI} when Resource has a non-empty URI.
//  3. []string{issuer} as the legacy token-as-issuer fallback.
//
// Matches the legacy TokenService.signAccessToken fallback so behavior
// parity holds for v0.1.0-rc1.
func mintAudience(req IssueRequest, issuer string) []string {
	if len(req.Audience) > 0 {
		return req.Audience
	}
	if req.Resource != nil && req.Resource.URI != "" {
		return []string{req.Resource.URI}
	}
	return []string{issuer}
}
