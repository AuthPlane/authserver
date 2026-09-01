package services

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// --- test doubles (unique names; the integration-tagged helpers are not built
// in the unit configuration) ---

type asMetaIssuer string

func (i asMetaIssuer) Issuer(context.Context) (string, error) { return string(i), nil }

type asMetaErrIssuer struct{}

func (asMetaErrIssuer) Issuer(context.Context) (string, error) {
	return "", errors.New("issuer boom")
}

type asMetaGrants struct {
	grants []string
	err    error
}

func (g asMetaGrants) Get(context.Context) ([]string, error) { return g.grants, g.err }

type asMetaCIMD struct {
	cfg output.CIMDConfig
	err error
}

func (c asMetaCIMD) Config(context.Context) (output.CIMDConfig, error) { return c.cfg, c.err }

type asMetaDPoP struct {
	cfg output.DPoPConfig
	err error
}

func (d asMetaDPoP) Config(context.Context) (output.DPoPConfig, error) { return d.cfg, d.err }

type asMetaOAuth struct {
	cfg output.OAuthConfig
	err error
}

func (o asMetaOAuth) Config(context.Context) (output.OAuthConfig, error) { return o.cfg, o.err }

type asMetaAgents struct {
	cfg output.AgentsConfig
	err error
}

func (a asMetaAgents) Config(context.Context) (output.AgentsConfig, error) { return a.cfg, a.err }

func asMetaResources() ResourceLister {
	return NewStaticResourceLister([]ResourceInfo{
		{URI: "https://mcp1.example.com", Scopes: []string{"tools/query", "tools/shared"}},
		{URI: "https://mcp2.example.com", Scopes: []string{"tools/create", "tools/shared"}},
	})
}

func TestASMetadataService_FullAssembly(t *testing.T) {
	t.Parallel()

	svc := NewASMetadataService(
		asMetaIssuer("https://auth.example.com"),
		asMetaGrants{grants: []string{"authorization_code", "refresh_token", "client_credentials", grantTypeJWTBearer}},
		asMetaCIMD{cfg: output.CIMDConfig{Enabled: true}},
		asMetaDPoP{cfg: output.DPoPConfig{Enabled: true}},
		asMetaOAuth{cfg: output.OAuthConfig{IntrospectionEnabled: true}},
		asMetaAgents{cfg: output.AgentsConfig{AgentIdentityEnabled: true}},
		asMetaResources(),
		observability.NewNoop(),
	)

	md, err := svc.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	if md.Issuer != "https://auth.example.com" {
		t.Errorf("issuer = %q", md.Issuer)
	}
	if md.TokenEndpoint != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint = %q", md.TokenEndpoint)
	}
	if md.IntrospectionEndpoint != "https://auth.example.com/oauth/introspect" {
		t.Errorf("introspection_endpoint = %q", md.IntrospectionEndpoint)
	}
	if !slices.Equal(md.IntrospectionEndpointAuthMethods, []string{"client_secret_basic", "client_secret_post"}) {
		t.Errorf("introspection auth methods = %v", md.IntrospectionEndpointAuthMethods)
	}
	if !md.ClientIDMetadataDocumentSupported {
		t.Error("CIMD should be advertised")
	}
	if !slices.Equal(md.DPoPSigningAlgValuesSupported, []string{"ES256", "RS256", "PS256"}) {
		t.Errorf("dpop algs = %v", md.DPoPSigningAlgValuesSupported)
	}
	if !md.AgentIdentitySupported {
		t.Error("agent identity should be advertised")
	}
	if !md.IdentityAssertionSupported {
		t.Error("identity_assertion should be true when jwt-bearer is enabled")
	}
	// scopes deduped, first-seen order preserved.
	if !slices.Equal(md.ScopesSupported, []string{"tools/query", "tools/shared", "tools/create"}) {
		t.Errorf("scopes = %v", md.ScopesSupported)
	}
}

func TestASMetadataService_AllDisabled(t *testing.T) {
	t.Parallel()

	svc := NewASMetadataService(
		asMetaIssuer("https://auth.example.com"),
		asMetaGrants{grants: []string{"authorization_code", "refresh_token"}},
		asMetaCIMD{cfg: output.CIMDConfig{Enabled: false}},
		asMetaDPoP{cfg: output.DPoPConfig{Enabled: false}},
		asMetaOAuth{cfg: output.OAuthConfig{IntrospectionEnabled: false}},
		asMetaAgents{cfg: output.AgentsConfig{AgentIdentityEnabled: false}},
		NewStaticResourceLister(nil),
		observability.NewNoop(),
	)

	md, err := svc.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	if md.IntrospectionEndpoint != "" {
		t.Errorf("introspection_endpoint should be empty, got %q", md.IntrospectionEndpoint)
	}
	if md.IntrospectionEndpointAuthMethods != nil {
		t.Errorf("introspection auth methods should be nil, got %v", md.IntrospectionEndpointAuthMethods)
	}
	if md.ClientIDMetadataDocumentSupported {
		t.Error("CIMD should not be advertised")
	}
	if md.DPoPSigningAlgValuesSupported != nil {
		t.Errorf("dpop algs should be nil, got %v", md.DPoPSigningAlgValuesSupported)
	}
	if md.AgentIdentitySupported {
		t.Error("agent identity should not be advertised")
	}
	if md.IdentityAssertionSupported {
		t.Error("identity_assertion should be false without jwt-bearer")
	}
	if md.ScopesSupported != nil {
		t.Errorf("scopes should be nil, got %v", md.ScopesSupported)
	}
	// Static fields are always present.
	if !slices.Equal(md.ResponseTypesSupported, []string{"code"}) {
		t.Errorf("response_types = %v", md.ResponseTypesSupported)
	}
	if !md.ResourceIndicatorsSupported {
		t.Error("resource_indicators_supported should be true")
	}
}

func TestASMetadataService_IssuerError_ReturnsError(t *testing.T) {
	t.Parallel()

	svc := NewASMetadataService(
		asMetaErrIssuer{},
		asMetaGrants{grants: []string{"authorization_code", "refresh_token"}},
		asMetaCIMD{}, asMetaDPoP{}, asMetaOAuth{}, asMetaAgents{},
		NewStaticResourceLister(nil),
		observability.NewNoop(),
	)

	if _, err := svc.Metadata(context.Background()); err == nil {
		t.Fatal("expected error when issuer resolution fails")
	}
}

func TestASMetadataService_GrantsError_FallsBackToBaseline(t *testing.T) {
	t.Parallel()

	svc := NewASMetadataService(
		asMetaIssuer("https://auth.example.com"),
		asMetaGrants{err: errors.New("grants boom")},
		asMetaCIMD{}, asMetaDPoP{}, asMetaOAuth{}, asMetaAgents{},
		NewStaticResourceLister(nil),
		observability.NewNoop(),
	)

	md, err := svc.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata should not fail on grants error: %v", err)
	}
	if !slices.Equal(md.GrantTypesSupported, baselineGrantTypes) {
		t.Errorf("grants = %v, want baseline %v", md.GrantTypesSupported, baselineGrantTypes)
	}
}

func TestASMetadataService_EmptyGrants_FallsBackToBaseline(t *testing.T) {
	t.Parallel()

	// A provider returning an empty (non-error) list must not emit an empty
	// grant_types_supported — the always-enabled grants stay advertised.
	svc := NewASMetadataService(
		asMetaIssuer("https://auth.example.com"),
		asMetaGrants{grants: []string{}},
		asMetaCIMD{}, asMetaDPoP{}, asMetaOAuth{}, asMetaAgents{},
		NewStaticResourceLister(nil),
		observability.NewNoop(),
	)

	md, err := svc.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !slices.Equal(md.GrantTypesSupported, baselineGrantTypes) {
		t.Errorf("grants = %v, want baseline %v", md.GrantTypesSupported, baselineGrantTypes)
	}
}

func TestASMetadataService_CapabilityErrors_DegradeToFalse(t *testing.T) {
	t.Parallel()

	boom := errors.New("provider boom")
	svc := NewASMetadataService(
		asMetaIssuer("https://auth.example.com"),
		asMetaGrants{grants: []string{"authorization_code", "refresh_token"}},
		asMetaCIMD{err: boom},
		asMetaDPoP{err: boom},
		asMetaOAuth{err: boom},
		asMetaAgents{err: boom},
		NewStaticResourceLister([]ResourceInfo{{URI: "x", Scopes: []string{"a"}}}),
		observability.NewNoop(),
	)

	md, err := svc.Metadata(context.Background())
	if err != nil {
		t.Fatalf("capability provider errors must not fail the document: %v", err)
	}
	if md.ClientIDMetadataDocumentSupported || md.AgentIdentitySupported ||
		md.IntrospectionEndpoint != "" || md.DPoPSigningAlgValuesSupported != nil {
		t.Errorf("capabilities should all degrade to false/empty on provider error: %+v", md)
	}
}

func TestASMetadataService_ScopesError_OmitsScopes(t *testing.T) {
	t.Parallel()

	svc := NewASMetadataService(
		asMetaIssuer("https://auth.example.com"),
		asMetaGrants{grants: []string{"authorization_code", "refresh_token"}},
		asMetaCIMD{}, asMetaDPoP{}, asMetaOAuth{}, asMetaAgents{},
		errResourceLister{},
		observability.NewNoop(),
	)

	md, err := svc.Metadata(context.Background())
	if err != nil {
		t.Fatalf("scope lookup error must not fail the document: %v", err)
	}
	if md.ScopesSupported != nil {
		t.Errorf("scopes should be omitted on lookup error, got %v", md.ScopesSupported)
	}
}

type errResourceLister struct{}

func (errResourceLister) List(context.Context) ([]ResourceInfo, error) {
	return nil, errors.New("resource lookup boom")
}
