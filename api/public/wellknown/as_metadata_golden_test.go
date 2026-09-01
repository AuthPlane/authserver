package wellknown_test

// Golden / characterization test for the AS metadata discovery document.
//
// It pins the exact JSON body emitted by GET
// /.well-known/oauth-authorization-server and its alias
// /.well-known/openid-configuration across several boot configurations. It is
// the primary anti-regression guarantee for the provider-driven hexagonal
// refactor of the discovery path: the captured testdata/*.golden.json files
// were captured against the pre-refactor handler and must remain byte-identical
// now that the document is assembled by ASMetadataService behind ASMetadataPort.
//
// Regenerate goldens with:  go test ./api/public/wellknown/ -run Golden -update
//
// WARNING: -update blindly overwrites the goldens with the CURRENT output. Only
// run it for an INTENTIONAL, reviewed change to the discovery document — never
// to silence an unexpected diff. The goldens are the characterization contract;
// a field-order or value regression slipped in alongside a careless -update
// would be recorded as the new "expected" and pass silently.
//
// The boot configurations below are wired through the same static providers the
// production binary uses, so the document this test pins is the document the
// service actually produces.

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/authplane/authserver/api/public/wellknown"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
)

var updateGolden = flag.Bool("update", false, "update golden files")

// stubJWKS satisfies wellknown.JWKSProvider so RegisterRoutes wires the JWKS
// route alongside the discovery routes under test.
type stubJWKS struct{}

func (stubJWKS) BuildJWKSDocument(_ context.Context) ([]byte, error) {
	return []byte(`{"keys":[]}`), nil
}

const (
	gtClientCredentials = "client_credentials"
	gtTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	gtJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// goldenConfig captures the capability boot values whose mapping onto the
// discovery document the refactor must preserve.
type goldenConfig struct {
	clientCredentials bool
	tokenExchange     bool
	jwtBearer         bool
	introspection     bool
	dpop              bool
	agentIdentity     bool
	cimd              bool
}

func (c goldenConfig) grants() []string {
	grants := []string{"authorization_code", "refresh_token"}
	if c.clientCredentials {
		grants = append(grants, gtClientCredentials)
	}
	if c.tokenExchange {
		grants = append(grants, gtTokenExchange)
	}
	if c.jwtBearer {
		grants = append(grants, gtJWTBearer)
	}
	return grants
}

func (c goldenConfig) service() input.ASMetadataPort {
	return services.NewASMetadataService(
		static.NewIssuerProvider("https://auth.example.com"),
		static.NewEnabledGrantsProvider(c.grants()),
		static.NewCIMDConfigProvider(output.CIMDConfig{Enabled: c.cimd}),
		static.NewDPoPConfigProvider(output.DPoPConfig{Enabled: c.dpop}),
		static.NewOAuthConfigProvider(output.OAuthConfig{IntrospectionEnabled: c.introspection}),
		static.NewAgentsConfigProvider(output.AgentsConfig{AgentIdentityEnabled: c.agentIdentity}),
		services.NewStaticResourceLister([]services.ResourceInfo{
			{URI: "https://mcp.example.com", Scopes: []string{"tools/query_database", "tools/create_ticket"}},
		}),
		observability.NewNoop(),
	)
}

func goldenConfigs() map[string]goldenConfig {
	return map[string]goldenConfig{
		"all_on": {
			clientCredentials: true, tokenExchange: true, jwtBearer: true,
			introspection: true, dpop: true, agentIdentity: true, cimd: true,
		},
		"all_off": {},
		"mixed": {
			clientCredentials: true,
			introspection:     true,
			dpop:              true,
			cimd:              true,
		},
	}
}

var goldenRoutes = []string{
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
}

func TestASMetadataGolden(t *testing.T) {
	for name, cfg := range goldenConfigs() {
		for _, route := range goldenRoutes {
			t.Run(name+route, func(t *testing.T) {
				mux := http.NewServeMux()
				wellknown.RegisterRoutes(mux, wellknown.Deps{
					JWKS:       stubJWKS{},
					ASMetadata: cfg.service(),
				}, observability.NewNoop())

				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route, nil)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200", rec.Code)
				}
				// The discovery document must stay cacheable (RFC 8414 docs are
				// long-lived); the golden compares only the body, so pin the
				// Cache-Control header here too.
				if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
					t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
				}
				got := rec.Body.Bytes()

				// One golden per (config, route) — both routes share a handler,
				// so capturing each proves the alias stays byte-identical too.
				safeRoute := filepath.Base(route)
				goldenPath := filepath.Join("testdata", "as_metadata_"+name+"_"+safeRoute+".golden.json")

				if *updateGolden {
					if err := os.MkdirAll("testdata", 0o755); err != nil {
						t.Fatalf("mkdir testdata: %v", err)
					}
					if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
						t.Fatalf("write golden: %v", err)
					}
					return
				}

				want, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("read golden (run with -update to create): %v", err)
				}
				if string(got) != string(want) {
					t.Errorf("discovery document drifted from golden %s\n--- got ---\n%s\n--- want ---\n%s",
						goldenPath, got, want)
				}
			})
		}
	}
}
