//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestAdminHelpers_Smoke is the wiring smoke test for the harness's
// Admin* helpers introduced. It exercises each helper
// against the live admin HTTP API and asserts only on the round-trip
// shape — no internal stores, no internal/* imports. This file is the
// reference template that the sub-tasks should pattern-match
// when migrating away from h.Seed* and h.*Store() calls.
//
// Coverage:
//   - AdminCreateBrokerProvider + AdminGetBrokerProviderBySlug
//   - AdminCreateResource (mint + broker variants — broker uses the
// broker_provider_slug shortcut so we never need to thread
//     a UUID)
//   - AdminGetResourceBySlug
//   - AdminAddAllowedClient + AdminListAllowedClients +
//     AdminRemoveAllowedClient (idempotency check on each)
//   - AdminAddAllowedReturnURL + AdminListAllowedReturnURLs +
//     AdminRemoveAllowedReturnURL (broker-only)
func TestAdminHelpers_Smoke(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
	}, []string{"tools/echo"})

	// 1. Broker provider lifecycle via the helpers.
	bpID := h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        "smoke-bp",
		DisplayName: "Smoke BP",
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "smoke-client",
			"client_secret_env": "CONNECTOR_SMOKE_SECRET",
		},
	})
	if bpID == "" {
		t.Fatal("AdminCreateBrokerProvider returned empty id")
	}

	bp := h.AdminGetBrokerProviderBySlug("smoke-bp")
	if bp.ID != bpID {
		t.Errorf("AdminGetBrokerProviderBySlug.ID: got %q, want %q", bp.ID, bpID)
	}
	if bp.Slug != "smoke-bp" {
		t.Errorf("AdminGetBrokerProviderBySlug.Slug: got %q, want %q", bp.Slug, "smoke-bp")
	}

	// 2. Mint resource via the helper.
	mintID := h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        "smoke-mint",
		BackendKind: "mint",
		DisplayName: "Smoke Mint",
		Scopes:      []e2e.AdminScope{{Name: "tools/echo"}},
	})
	if mintID == "" {
		t.Fatal("AdminCreateResource (mint) returned empty id")
	}
	mint := h.AdminGetResourceBySlug("smoke-mint")
	if mint.ID != mintID || mint.BackendKind != "mint" {
		t.Errorf("mint round-trip: got id=%q kind=%q, want id=%q kind=%q",
			mint.ID, mint.BackendKind, mintID, "mint")
	}

	// 3. Broker resource referencing the provider by SLUG.
	brokerID := h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               "smoke-broker",
		URI:                "https://smoke.example/api",
		BackendKind:        "broker",
		BrokerProviderSlug: "smoke-bp",
		DisplayName:        "Smoke Broker",
	})
	broker := h.AdminGetResourceBySlug("smoke-broker")
	if broker.ID != brokerID || broker.BrokerProviderID != bpID {
		t.Errorf("broker round-trip: got id=%q provider=%q, want id=%q provider=%q",
			broker.ID, broker.BrokerProviderID, brokerID, bpID)
	}

	// 4. policy.exchange.allowed_client_ids — register a client first so the
	// AS will accept it, then add/list/remove via the helpers.
	clientID, _ := h.RegisterConfidentialClient([]string{"authorization_code"}, "openid")

	added := h.AdminAddAllowedClient("smoke-mint", clientID)
	if len(added) != 1 || added[0] != clientID {
		t.Errorf("AdminAddAllowedClient: got %v, want [%s]", added, clientID)
	}

	// Idempotent: repeated add returns the same list.
	addedAgain := h.AdminAddAllowedClient("smoke-mint", clientID)
	if len(addedAgain) != 1 {
		t.Errorf("idempotent AdminAddAllowedClient: got %v, want one entry", addedAgain)
	}

	listed := h.AdminListAllowedClients("smoke-mint")
	if len(listed) != 1 || listed[0] != clientID {
		t.Errorf("AdminListAllowedClients: got %v, want [%s]", listed, clientID)
	}

	removed := h.AdminRemoveAllowedClient("smoke-mint", clientID)
	if len(removed) != 0 {
		t.Errorf("AdminRemoveAllowedClient: got %v, want []", removed)
	}

	// 5. policy.connect.allowed_return_urls — broker resource only.
	const target = "https://app.example.com/connected"
	addedURL := h.AdminAddAllowedReturnURL("smoke-broker", target)
	if len(addedURL) != 1 || addedURL[0] != target {
		t.Errorf("AdminAddAllowedReturnURL: got %v, want [%s]", addedURL, target)
	}

	listedURL := h.AdminListAllowedReturnURLs("smoke-broker")
	if len(listedURL) != 1 {
		t.Errorf("AdminListAllowedReturnURLs: got %v, want one entry", listedURL)
	}

	removedURL := h.AdminRemoveAllowedReturnURL("smoke-broker", target)
	if len(removedURL) != 0 {
		t.Errorf("AdminRemoveAllowedReturnURL: got %v, want []", removedURL)
	}
}
