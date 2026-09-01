package output

import "context"

// AgentsConfig is the per-request agent-identity feature config.
type AgentsConfig struct {
	EnableJWKSListing bool // expose agent client IDs in the JWKS endpoint
	// AgentIdentityEnabled advertises authplane_agent_identity_supported in
	// the discovery document. The static default returns true, preserving the
	// previously hardcoded behavior.
	AgentIdentityEnabled bool
}

// AgentsConfigProvider supplies agent-identity config for a request.
type AgentsConfigProvider interface {
	Config(ctx context.Context) (AgentsConfig, error)
}
