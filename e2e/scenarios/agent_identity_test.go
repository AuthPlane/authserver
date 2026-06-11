//go:build e2e

package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/domain/token"
)

// TestAgentIdentity_ClientCredentials_AgentID verifies that an agent client
// receives agent_id in its client_credentials access token JWT.
func TestAgentIdentity_ClientCredentials_AgentID(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, scopes)

	h.RegisterScope(h.Issuer, "tools/echo", "Echo tool")

	// Register an agent client.
	agentID, agentSecret := h.RegisterAgentClient(
		[]string{"client_credentials"},
		"tools/echo",
		"Test Agent for E2E",
	)

	// Exchange for a machine token.
	tr := h.ClientCredentialsExchange(agentID, agentSecret, "tools/echo", "")
	if tr.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}

	// Parse the JWT and verify agent_id claim.
	claims := parseJWTClaims(t, tr.AccessToken)
	if claims["agent_id"] != agentID {
		t.Errorf("agent_id = %v, want %q", claims["agent_id"], agentID)
	}

	// agent_chain should be absent (no delegation).
	if claims["agent_chain"] != nil {
		t.Errorf("agent_chain should be nil for non-delegated token, got %v", claims["agent_chain"])
	}
}

// TestAgentIdentity_RegularClient_NoAgentClaims verifies that a regular
// (non-agent) client does NOT get agent_id in its JWT.
func TestAgentIdentity_RegularClient_NoAgentClaims(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, scopes)

	h.RegisterScope(h.Issuer, "tools/echo", "Echo tool")

	// Register a regular (non-agent) client.
	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")
	if tr.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}

	claims := parseJWTClaims(t, tr.AccessToken)
	if claims["agent_id"] != nil {
		t.Errorf("agent_id should be nil for regular client, got %v", claims["agent_id"])
	}
	if claims["agent_chain"] != nil {
		t.Errorf("agent_chain should be nil for regular client, got %v", claims["agent_chain"])
	}
}

// TestAgentIdentity_Delegation_AgentChain verifies that delegation (token exchange
// with an actor) produces an agent_chain claim on the resulting JWT when the
// requesting client is an agent. Uses self-exchange (same client for subject and
// actor) to avoid cross-client authorization constraints.
func TestAgentIdentity_Delegation_AgentChain(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials:        true,
		EnableTokenExchange:            true,
		TokenExchangeAllowSelfExchange: true,
	}, scopes)

	h.RegisterScope(h.Issuer, "tools/echo", "Echo tool")

	// Register a single agent client (self-exchange).
	agentID, agentSecret := h.RegisterAgentClient(
		[]string{"client_credentials", token.GrantTypeTokenExchange},
		"tools/echo",
		"Delegating Agent",
	)

	// 1. Get a subject token.
	subjectTR := h.ClientCredentialsExchange(agentID, agentSecret, "tools/echo", "")
	// 2. Get an actor token.
	actorTR := h.ClientCredentialsExchange(agentID, agentSecret, "tools/echo", "")

	// 3. Self-exchange with actor → delegation.
	delegated := h.TokenExchange(
		agentID, agentSecret,
		subjectTR.AccessToken, token.TokenTypeAccessToken,
		actorTR.AccessToken, token.TokenTypeAccessToken,
		"",
	)
	if delegated.AccessToken == "" {
		t.Fatal("expected non-empty delegated access_token")
	}

	// 4. Parse JWT and verify agent claims.
	claims := parseJWTClaims(t, delegated.AccessToken)

	// agent_id should be the agent's client_id (it's the issuing client).
	if claims["agent_id"] != agentID {
		t.Errorf("agent_id = %v, want %q", claims["agent_id"], agentID)
	}

	// agent_chain should be present with the agent's client_id (from act claim).
	chainRaw, ok := claims["agent_chain"].([]interface{})
	if !ok {
		t.Fatalf("agent_chain expected []interface{}, got %T", claims["agent_chain"])
	}
	if len(chainRaw) != 1 {
		t.Fatalf("agent_chain length = %d, want 1", len(chainRaw))
	}
	if chainRaw[0] != agentID {
		t.Errorf("agent_chain[0] = %v, want %q", chainRaw[0], agentID)
	}

	// act claim should also be present (standard delegation).
	actMap, ok := claims["act"].(map[string]interface{})
	if !ok {
		t.Fatalf("act expected map, got %T", claims["act"])
	}
	if actMap["sub"] != agentID {
		t.Errorf("act.sub = %v, want %q", actMap["sub"], agentID)
	}
}

// TestAgentIdentity_DCR_AgentFields verifies that DCR correctly sets and returns agent fields.
func TestAgentIdentity_DCR_AgentFields(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)

	// Register an agent client via DCR.
	agentID, _ := h.RegisterAgentClient(
		[]string{"authorization_code"},
		"",
		"My Test Agent",
	)

	if agentID == "" {
		t.Fatal("expected non-empty agent client_id")
	}
}

// TestAgentIdentity_ASMetadata_Supported verifies that agent identity support
// is advertised in AS metadata.
func TestAgentIdentity_ASMetadata_Supported(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, []string{"tools/echo"})

	resp, err := http.Get(h.Issuer + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET AS metadata: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var metadata map[string]interface{}
	if err := json.Unmarshal(body, &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	supported, ok := metadata["authplane_agent_identity_supported"].(bool)
	if !ok || !supported {
		t.Errorf("authplane_agent_identity_supported = %v, want true", metadata["authplane_agent_identity_supported"])
	}
}
