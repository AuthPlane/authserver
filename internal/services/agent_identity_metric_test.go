package services

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
)

// fixedClientStore returns the same client for every GetByID, so a test can
// drive AttachClaims against an agent / non-agent client without a database.
type fixedClientStore struct {
	noopClientStore
	c *client.Client
}

func (s fixedClientStore) GetByID(_ context.Context, _ string) (*client.Client, error) {
	return s.c, nil
}

// TestAgentIdentity_MetricCountsAgentsOnly pins that
// authplane_agent_tokens_issued_total is agent-scoped.
//
// The counter sits behind the is_agent check, which is easy to lose when the
// attachment logic is refactored: attaching claims is a no-op for a non-agent
// client, so nothing else in the code path signals that the increment should
// not happen. Without this assertion, a deployment with zero agent clients
// would silently report every client_credentials / jwt-bearer / token-exchange
// token as an agent token.
func TestAgentIdentity_MetricCountsAgentsOnly(t *testing.T) {
	const instrument = "authplane_agent_tokens_issued_total"

	newSvc := func(t *testing.T, c *client.Client) (*AgentIdentityService, *metricCollector) {
		t.Helper()
		mc := newMetricCollector(t)
		obs := observability.NewNoop()
		obs.Metrics.AgentTokensIssued = mc.int64Counter(t, instrument)
		return NewAgentIdentityService(fixedClientStore{c: c}, obs), mc
	}

	t.Run("non-agent client is not counted", func(t *testing.T) {
		svc, mc := newSvc(t, &client.Client{ID: "regular-client", IsAgent: false})

		var claims crypto.AccessTokenClaims
		if err := svc.AttachClaims(context.Background(), &claims, "regular-client"); err != nil {
			t.Fatalf("attach: %v", err)
		}

		if claims.AgentID != "" {
			t.Errorf("agent_id on non-agent client: got %q, want empty", claims.AgentID)
		}
		if dp := mc.dataPoints(t, instrument); len(dp) != 0 {
			t.Errorf("%s recorded %d data point(s) for a non-agent client, want 0", instrument, len(dp))
		}
	})

	t.Run("agent client is counted once", func(t *testing.T) {
		svc, mc := newSvc(t, &client.Client{ID: "agent-client", IsAgent: true})

		var claims crypto.AccessTokenClaims
		if err := svc.AttachClaims(context.Background(), &claims, "agent-client"); err != nil {
			t.Fatalf("attach: %v", err)
		}

		if claims.AgentID != "agent-client" {
			t.Errorf("agent_id: got %q, want %q", claims.AgentID, "agent-client")
		}
		dp := mc.dataPoints(t, instrument)
		if len(dp) != 1 {
			t.Fatalf("%s recorded %d data point(s), want 1", instrument, len(dp))
		}
		if dp[0].Value != 1 {
			t.Errorf("%s value = %d, want 1", instrument, dp[0].Value)
		}
	})

	// AttachClaimsForClient is the early-resolution half used by the
	// authorization_code / refresh_token grants: it must never count, since
	// those grants can still reject the request after resolving.
	t.Run("AttachClaimsForClient never counts", func(t *testing.T) {
		svc, mc := newSvc(t, nil)

		var claims crypto.AccessTokenClaims
		svc.AttachClaimsForClient(context.Background(), &claims,
			&client.Client{ID: "agent-client", IsAgent: true})

		if claims.AgentID != "agent-client" {
			t.Errorf("agent_id: got %q, want %q", claims.AgentID, "agent-client")
		}
		if dp := mc.dataPoints(t, instrument); len(dp) != 0 {
			t.Errorf("%s recorded %d data point(s) at resolution time, want 0", instrument, len(dp))
		}
	})
}
