package resource_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

func TestIssuance_AgentChain_TruncatedAt8(t *testing.T) {
	chain := make([]string, 9)
	for i := range chain {
		chain[i] = "agent-" + strconv.Itoa(i)
	}

	var iss resource.Issuance
	iss.SetAgentChain(chain)

	if len(iss.AgentChain) != resource.MaxAgentChainLength {
		t.Fatalf("got len=%d, want %d (matches services/agent_identity.go::maxAgentChainLength)",
			len(iss.AgentChain), resource.MaxAgentChainLength)
	}
	if resource.MaxAgentChainLength != 8 {
		t.Fatalf("MaxAgentChainLength = %d, want 8", resource.MaxAgentChainLength)
	}
	for i := 0; i < resource.MaxAgentChainLength; i++ {
		want := "agent-" + strconv.Itoa(i)
		if iss.AgentChain[i] != want {
			t.Errorf("chain[%d] = %q, want %q (truncation should keep the prefix)", i, iss.AgentChain[i], want)
		}
	}
}

func TestIssuance_AgentChain_ShortChainUnchanged(t *testing.T) {
	chain := []string{"root", "leaf"}
	var iss resource.Issuance
	iss.SetAgentChain(chain)
	if len(iss.AgentChain) != 2 {
		t.Errorf("short chain should not be truncated, got len=%d", len(iss.AgentChain))
	}
	if iss.AgentChain[0] != "root" || iss.AgentChain[1] != "leaf" {
		t.Errorf("chain order altered: %v", iss.AgentChain)
	}
}

func TestIssuance_AgentChain_NilStaysNil(t *testing.T) {
	var iss resource.Issuance
	iss.SetAgentChain(nil)
	if iss.AgentChain != nil {
		t.Errorf("nil chain should round-trip as nil, got %v", iss.AgentChain)
	}
}

func TestIssuance_IsRevoked(t *testing.T) {
	iss := resource.Issuance{}
	if iss.IsRevoked() {
		t.Error("nil RevokedAt should mean active")
	}
	now := time.Now()
	iss.RevokedAt = &now
	if !iss.IsRevoked() {
		t.Error("non-nil RevokedAt should mean revoked")
	}
}
