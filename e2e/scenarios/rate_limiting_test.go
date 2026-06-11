//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/config"
)

func TestRateLimiting(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		Resources: []config.ResourceConfigUnified{
			{Slug: "test-mcp", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test-mcp", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
		RateLimit: &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 5,
			Burst:             5,
		},
	})

	// Send burst+1 requests rapidly.
	got429 := false
	for i := 0; i < 10; i++ {
		resp, err := http.Get(h.Issuer + "/health")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}

	if !got429 {
		t.Fatal("expected 429 after exceeding rate limit burst")
	}
}
