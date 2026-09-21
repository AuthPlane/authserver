package services

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const maxAgentChainLength = 8

// AgentIdentityService attaches Authplane agent identity claims to access tokens.
// It reads the issuing client's agent status from the client store and, if the
// client is an agent, adds agent_id and (for delegation) agent_chain claims.
type AgentIdentityService struct {
	clients output.ClientStore
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// NewAgentIdentityService creates a new agent identity service.
func NewAgentIdentityService(
	clients output.ClientStore,
	obs *observability.Provider,
) *AgentIdentityService {
	return &AgentIdentityService{
		clients: clients,
		logger:  obs.Logger.With("component", "agent_identity"),
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
}

// AttachClaims enriches access token claims with agent identity information.
//
// If the issuing client has is_agent=true, sets agent_id = client_id.
// If an act chain is present (delegation), builds agent_chain as an ordered
// list [root_client_id, ..., acting_agent_id] from shallowest to deepest.
// Chain is capped at maxAgentChainLength entries for defensive truncation.
//
// The claims struct is modified in-place and returned.
func (s *AgentIdentityService) AttachClaims(
	ctx context.Context,
	claims *crypto.AccessTokenClaims,
	issuingClientID string,
) error {
	ctx, span := s.tracer.Start(ctx, "AgentIdentityService.AttachClaims")
	defer span.End()

	span.SetAttributes(attribute.String("client_id", issuingClientID))

	// Look up issuing client.
	c, err := s.clients.GetByID(ctx, issuingClientID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Count and log only when a claim was actually attached — the counter is
	// agent-scoped, so an unconditional increment here would make every token
	// from every client an "agent token".
	//
	// This counts at resolution, not issuance, which is the asymmetry
	// RecordIssued documents: token exchange resolves well before
	// mintIssuer.Issue, so a mint failure leaves the increment and this log
	// line behind for a token the caller never receives. Preserved as-is
	// because changing it would alter three grants this fix does not touch;
	// the rotation onto RecordIssued is the follow-up that fixes it.
	if s.attachClaimsForClient(ctx, claims, c) {
		s.logger.InfoContext(ctx, "attached agent_id claim",
			"client_id", c.ID,
			"chain_length", len(claims.AgentChain),
		)
		s.RecordIssued(ctx, len(claims.AgentChain) > 0)
	}
	return nil
}

// AttachClaimsForClient is AttachClaims for callers that already hold the
// issuing client, so the grant does not pay a second client-store round
// trip per token. It is also the infallible half of the pair: with no
// lookup left to do, there is no error to return — which lets a grant
// resolve agent claims before it reaches an irreversible step (consuming
// an authorization code or a refresh token) rather than after.
//
// Resolution and issuance are separate here: this method does NOT count
// the token as issued, because a caller that resolves claims early has
// not issued anything yet and may still reject the request. Such callers
// must call RecordIssued once the token is actually minted.
//
// The claims struct is modified in-place.
func (s *AgentIdentityService) AttachClaimsForClient(
	ctx context.Context,
	claims *crypto.AccessTokenClaims,
	c *client.Client,
) {
	ctx, span := s.tracer.Start(ctx, "AgentIdentityService.AttachClaimsForClient")
	defer span.End()
	if c != nil {
		span.SetAttributes(attribute.String("client_id", c.ID))
	}
	// Debug, not Info: this runs before the grant's remaining checks, so the
	// line can precede a request that is rejected and never mints a token.
	// The Info line belongs at the issuance site.
	if s.attachClaimsForClient(ctx, claims, c) {
		s.logger.DebugContext(ctx, "resolved agent identity",
			"client_id", c.ID,
			"chain_length", len(claims.AgentChain),
		)
	}
}

// RecordIssued emits the agent-token issuance metric. It is separate from
// claim attachment so a caller can count at issuance rather than at
// resolution: a grant that resolves claims ahead of its remaining checks (a
// failed PKCE verification, a refresh-token reuse that revokes the family)
// would otherwise inflate the counter with tokens that were never minted.
//
// Only the authorization_code and refresh_token grants count this way today.
// client_credentials, jwt-bearer and token exchange still go through
// AttachClaims, which counts at resolution — so their increments can still
// outrun issuance when a later step fails (a mint error, a failed issuance
// insert, a fronted-broker denial). Rotating them onto this method is the
// follow-up that makes the counter mean one thing everywhere; until then the
// instrument mixes both semantics and carries no grant_type attribute to
// separate them.
func (s *AgentIdentityService) RecordIssued(ctx context.Context, hasChain bool) {
	if s.metrics == nil || s.metrics.AgentTokensIssued == nil {
		return
	}
	s.metrics.AgentTokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.Bool("has_chain", hasChain),
	))
}

// attachClaimsForClient is the span-free, metric-free core shared by both
// exported entry points. It reports whether it attached anything, so callers
// gate their own logging and metrics on the is_agent decision instead of
// re-reading a field they own (a caller that pre-populated claims.AgentID
// from a subject token would otherwise look like an agent to us).
//
// Logging is left to the callers: whether an attachment is worth an Info
// line depends on whether the caller is about to issue a token or merely
// resolving ahead of checks that may still reject the request.
func (s *AgentIdentityService) attachClaimsForClient(
	ctx context.Context,
	claims *crypto.AccessTokenClaims,
	c *client.Client,
) bool {
	if c == nil || !c.IsAgent {
		return false
	}

	// Set agent_id for agent clients.
	claims.AgentID = c.ID

	// Build agent_chain from act claim if present (delegation scenario).
	// The act chain already includes the acting agent as the outermost sub
	// (set by token_exchange.go), so we don't need to append issuingClientID.
	if claims.Act != nil {
		chain := buildAgentChain(claims.Act)

		if len(chain) > maxAgentChainLength {
			// Warn regardless of caller: a chain over the cap is an anomaly
			// worth surfacing whether or not the token ends up issued.
			s.logger.WarnContext(ctx, "agent_chain truncated at max length",
				"client_id", c.ID,
				"original_length", len(chain),
				"max_length", maxAgentChainLength,
			)
			chain = chain[:maxAgentChainLength]
		}

		claims.AgentChain = chain
	}
	return true
}

// buildAgentChain extracts an ordered list of client_ids from a nested act claim.
// Returns [deepest_actor, ..., shallowest_actor] which is then reversed to
// [root, ..., leaf] before being set on the token.
func buildAgentChain(actMap map[string]interface{}) []string {
	// Parse the act claim to get the structured chain.
	actClaim := token.ActClaimFromMap(actMap)
	if actClaim == nil {
		return nil
	}

	// Flatten the chain: walk from outermost to innermost.
	var chain []string
	current := actClaim
	for current != nil {
		chain = append(chain, current.Sub)
		current = current.Act
	}

	// Reverse to get [root, ..., leaf] order (shallowest to deepest).
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	return chain
}

// extractAgentIdentityClaims runs AttachClaims against a throwaway claims
// struct and lifts the resulting AgentID and AgentChain into the
// *AgentIdentityClaims that IssueRequest carries. Returns nil when the
// agent-identity service is not wired or the issuing client is not an agent.
//
// Token exchange is the only caller: it is the one grant that reaches
// MintIssuer without already holding the authenticated client. The
// authorization_code and refresh_token grants use the ForClient sibling
// below; client_credentials and jwt-bearer call AttachClaims directly and
// sign their own tokens. Rotating those last two onto this pair is the
// follow-up that would make one implementation own the contract.
//
// actMap is the RFC 8693 'act' chain the caller built, or nil — a nil chain
// yields agent_id with no agent_chain.
func extractAgentIdentityClaims(
	ctx context.Context,
	ai *AgentIdentityService,
	span trace.Span,
	clientID string,
	actMap map[string]interface{},
) (*AgentIdentityClaims, error) {
	if ai == nil {
		return nil, nil
	}
	temp := crypto.AccessTokenClaims{Act: actMap}
	if err := ai.AttachClaims(ctx, &temp, clientID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "attach agent claims failed")
		return nil, fmt.Errorf("attach agent claims: %w", err)
	}
	return liftAgentIdentityClaims(temp), nil
}

// extractAgentIdentityClaimsForClient is extractAgentIdentityClaims for a
// caller that already holds the issuing client. It performs no store
// lookup and therefore cannot fail, so a grant can resolve agent claims
// before its irreversible consume step.
func extractAgentIdentityClaimsForClient(
	ctx context.Context,
	ai *AgentIdentityService,
	c *client.Client,
	actMap map[string]interface{},
) *AgentIdentityClaims {
	if ai == nil || c == nil {
		return nil
	}
	temp := crypto.AccessTokenClaims{Act: actMap}
	ai.AttachClaimsForClient(ctx, &temp, c)
	return liftAgentIdentityClaims(temp)
}

// liftAgentIdentityClaims converts the enriched claims struct into the
// IssueRequest DTO, collapsing "no agent claims set" to nil.
func liftAgentIdentityClaims(temp crypto.AccessTokenClaims) *AgentIdentityClaims {
	if temp.AgentID == "" && len(temp.AgentChain) == 0 {
		return nil
	}
	return &AgentIdentityClaims{
		AgentID:    temp.AgentID,
		AgentChain: temp.AgentChain,
	}
}
