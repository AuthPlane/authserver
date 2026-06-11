package services

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
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

	if !c.IsAgent {
		return nil
	}

	// Set agent_id for agent clients.
	claims.AgentID = issuingClientID

	s.logger.InfoContext(ctx, "attached agent_id claim",
		"client_id", issuingClientID,
	)

	// Build agent_chain from act claim if present (delegation scenario).
	// The act chain already includes the acting agent as the outermost sub
	// (set by token_exchange.go), so we don't need to append issuingClientID.
	if claims.Act != nil {
		chain := buildAgentChain(claims.Act)

		if len(chain) > maxAgentChainLength {
			s.logger.WarnContext(ctx, "agent_chain truncated at max length",
				"client_id", issuingClientID,
				"original_length", len(chain),
				"max_length", maxAgentChainLength,
			)
			chain = chain[:maxAgentChainLength]
		}

		claims.AgentChain = chain

		s.logger.InfoContext(ctx, "attached agent_chain claim",
			"client_id", issuingClientID,
			"chain_length", len(chain),
		)
	}

	if s.metrics != nil && s.metrics.AgentTokensIssued != nil {
		s.metrics.AgentTokensIssued.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.Bool("has_chain", claims.AgentChain != nil),
		))
	}

	return nil
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
