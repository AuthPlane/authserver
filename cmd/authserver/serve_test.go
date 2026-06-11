package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/domain/resource"
)

func TestResourceConfigUnified_BrokerWithoutProviderRef_FailsAtSeed(t *testing.T) {
	r := config.ResourceConfigUnified{
		Slug:        "github-repo",
		URI:         "https://api.github.com",
		BackendKind: "broker",
	}
	_, err := resourceConfigUnifiedToDomain(r, map[string]string{})
	if err == nil {
		t.Fatal("expected error for broker resource missing provider ref")
	}
	if !strings.Contains(err.Error(), "broker_provider_id") || !strings.Contains(err.Error(), "broker_provider_slug") {
		t.Errorf("error should mention both id and slug fields, got: %v", err)
	}
}

func TestResourceConfigUnified_BothProviderRefs_FailsAtSeed(t *testing.T) {
	r := config.ResourceConfigUnified{
		Slug:               "github-repo",
		URI:                "https://api.github.com",
		BackendKind:        "broker",
		BrokerProviderID:   "bp_abc",
		BrokerProviderSlug: "github",
	}
	_, err := resourceConfigUnifiedToDomain(r, map[string]string{"github": "bp_abc"})
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion, got: %v", err)
	}
}

func TestResourceConfigUnified_BrokerProviderSlug_ResolvesViaIndex(t *testing.T) {
	r := config.ResourceConfigUnified{
		Slug:               "github-repo",
		URI:                "https://api.github.com",
		BackendKind:        "broker",
		BrokerProviderSlug: "github",
		Scopes: []config.ScopeConfig{
			{Name: "repo", Upstream: "repo", Description: "Read/write repo"},
		},
		Policy: config.PolicyConfig{
			Connect: config.ConnectPolicyConfig{AllowedReturnURLs: []string{"https://app/x"}},
		},
	}
	dom, err := resourceConfigUnifiedToDomain(r, map[string]string{"github": "bp_abc123"})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if dom.BrokerProviderID != "bp_abc123" {
		t.Errorf("BrokerProviderID: got %q, want bp_abc123", dom.BrokerProviderID)
	}
	if dom.BackendKind != resource.BackendBroker {
		t.Errorf("BackendKind: got %q", dom.BackendKind)
	}
	if len(dom.Scopes) != 1 || dom.Scopes[0].Upstream != "repo" {
		t.Errorf("Scopes: got %+v", dom.Scopes)
	}
	if got := dom.Policy.Connect.AllowedReturnURLs; len(got) != 1 || got[0] != "https://app/x" {
		t.Errorf("Connect.AllowedReturnURLs: got %v", got)
	}
}

func TestResourceConfigUnified_BrokerProviderSlug_UnknownFails(t *testing.T) {
	r := config.ResourceConfigUnified{
		Slug:               "github-repo",
		URI:                "https://api.github.com",
		BackendKind:        "broker",
		BrokerProviderSlug: "unknown",
	}
	_, err := resourceConfigUnifiedToDomain(r, map[string]string{"github": "bp_abc"})
	if err == nil {
		t.Fatal("expected error for unknown broker_provider_slug")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention the missing slug, got: %v", err)
	}
}

func TestResourceConfigUnified_MintShape(t *testing.T) {
	r := config.ResourceConfigUnified{
		Slug:        "tasks-mcp",
		URI:         "https://tasks.example.com",
		BackendKind: "mint",
		DisplayName: "Tasks",
		Scopes: []config.ScopeConfig{
			{Name: "tasks:list", Description: "List"},
		},
		Policy: config.PolicyConfig{
			Exchange: config.ExchangePolicyConfig{AllowedClientIDs: []string{"agent-1"}},
		},
	}
	dom, err := resourceConfigUnifiedToDomain(r, nil)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if dom.BackendKind != resource.BackendMint {
		t.Errorf("BackendKind: got %q", dom.BackendKind)
	}
	if dom.BrokerProviderID != "" {
		t.Errorf("Mint should have empty BrokerProviderID, got %q", dom.BrokerProviderID)
	}
	if got := dom.Policy.Exchange.AllowedClientIDs; len(got) != 1 || got[0] != "agent-1" {
		t.Errorf("Exchange.AllowedClientIDs: got %v", got)
	}
}

func TestResourceConfigUnified_InvalidBackendKindFails(t *testing.T) {
	r := config.ResourceConfigUnified{
		Slug:        "x",
		BackendKind: "hybrid",
	}
	_, err := resourceConfigUnifiedToDomain(r, nil)
	if err == nil || !strings.Contains(err.Error(), "backend_kind") {
		t.Fatalf("expected backend_kind rejection, got: %v", err)
	}
}

// TestWarnIfCORSDisabled covers startup validation. When the server
// boots with AUTHPLANE_SERVER_ALLOWED_ORIGINS empty, a one-line warning must
// fire so operators don't silently break browser-based MCP clients.
func TestWarnIfCORSDisabled(t *testing.T) {
	tests := []struct {
		name           string
		allowedOrigins []string
		wantWarn       bool
	}{
		{
			name:           "empty origins emits warning",
			allowedOrigins: nil,
			wantWarn:       true,
		},
		{
			name:           "empty slice emits warning",
			allowedOrigins: []string{},
			wantWarn:       true,
		},
		{
			name:           "wildcard origin suppresses warning",
			allowedOrigins: []string{"*"},
			wantWarn:       false,
		},
		{
			name:           "explicit origin suppresses warning",
			allowedOrigins: []string{"https://app.example.com"},
			wantWarn:       false,
		},
		{
			name:           "multiple origins suppress warning",
			allowedOrigins: []string{"https://a.example.com", "https://b.example.com"},
			wantWarn:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			warnIfCORSDisabled(logger, tt.allowedOrigins)

			out := buf.String()
			gotWarn := strings.Contains(out, "level=WARN") &&
				strings.Contains(out, "CORS is disabled")

			if gotWarn != tt.wantWarn {
				t.Fatalf("warnIfCORSDisabled wantWarn=%v, gotWarn=%v\nlog output:\n%s",
					tt.wantWarn, gotWarn, out)
			}

			if tt.wantWarn {
				// Verify exactly one warning record and that it includes the
				// remediation hint operators need.
				if got := strings.Count(out, "level=WARN"); got != 1 {
					t.Errorf("expected exactly 1 warning record, got %d\noutput:\n%s", got, out)
				}
				if !strings.Contains(out, "AUTHPLANE_SERVER_ALLOWED_ORIGINS") {
					t.Errorf("warning should name the env var\noutput:\n%s", out)
				}
				if !strings.Contains(out, "preflight") {
					t.Errorf("warning should explain the failure mode (CORS preflight)\noutput:\n%s", out)
				}
				if !strings.Contains(out, "local dev") || !strings.Contains(out, "production") {
					t.Errorf("warning should give remediation for both dev and prod\noutput:\n%s", out)
				}
			}
		})
	}
}
