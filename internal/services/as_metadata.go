package services

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.ASMetadataPort = (*ASMetadataService)(nil)

//nolint:gosec // G101 false positive: this is an OAuth grant-type URN, not a credential.
const grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// baselineGrantTypes is the grant set discovery falls back to when the
// EnabledGrantsProvider errors. Discovery is critical infrastructure — a
// transient provider failure must degrade to the always-present grants rather
// than fail the whole document.
var baselineGrantTypes = []string{"authorization_code", "refresh_token"}

// ASMetadataService assembles the authorization-server discovery document from
// output ports, resolving every capability per request. In the default
// deployment the providers are static (boot values), so the document is
// behavior-identical to the previous inline handler; substitute providers can
// resolve capabilities per request without touching this service.
//
// Degradation policy: capability lookups (CIMD, DPoP, introspection,
// agent-identity) degrade to false + log on provider error; the grant set
// degrades to the baseline + log; only an issuer-resolution failure is fatal
// (the document cannot be built without it).
type ASMetadataService struct {
	issuer    output.IssuerProvider
	grants    output.EnabledGrantsProvider
	cimd      output.CIMDConfigProvider
	dpop      output.DPoPConfigProvider
	oauth     output.OAuthConfigProvider
	agents    output.AgentsConfigProvider
	resources ResourceLister
	logger    *slog.Logger
}

// NewASMetadataService wires the discovery-document assembler. All arguments are
// interface-typed output ports (plus the shared ResourceLister); pass the static
// adapters for the default deployment.
func NewASMetadataService(
	issuer output.IssuerProvider,
	grants output.EnabledGrantsProvider,
	cimd output.CIMDConfigProvider,
	dpop output.DPoPConfigProvider,
	oauth output.OAuthConfigProvider,
	agents output.AgentsConfigProvider,
	resources ResourceLister,
	obs *observability.Provider,
) *ASMetadataService {
	return &ASMetadataService{
		issuer:    issuer,
		grants:    grants,
		cimd:      cimd,
		dpop:      dpop,
		oauth:     oauth,
		agents:    agents,
		resources: resources,
		// Callers pass an already component-scoped provider
		// (obs.WithComponent("as-metadata")), so don't re-tag the component here.
		logger: obs.Logger,
	}
}

// Metadata resolves and assembles the discovery document for the request.
func (s *ASMetadataService) Metadata(ctx context.Context) (*input.ASMetadata, error) {
	issuer, err := s.issuer.Issuer(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer: %w", err)
	}

	grants := s.resolveGrants(ctx)

	md := &input.ASMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth/authorize",
		TokenEndpoint:                     issuer + "/oauth/token",
		RegistrationEndpoint:              issuer + "/oauth/register",
		RevocationEndpoint:                issuer + "/oauth/revoke",
		JWKSURI:                           issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               grants,
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
		RevocationEndpointAuthMethods:     []string{"none", "client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   s.resolveScopes(ctx),
		ResourceIndicatorsSupported:       true,
		IdentityAssertionSupported:        slices.Contains(grants, grantTypeJWTBearer),
	}

	if s.cimdEnabled(ctx) {
		md.ClientIDMetadataDocumentSupported = true
	}
	if s.introspectionEnabled(ctx) {
		md.IntrospectionEndpoint = issuer + "/oauth/introspect"
		md.IntrospectionEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post"}
	}
	if s.dpopEnabled(ctx) {
		md.DPoPSigningAlgValuesSupported = []string{"ES256", "RS256", "PS256"}
	}
	if s.agentIdentityEnabled(ctx) {
		md.AgentIdentitySupported = true
	}

	return md, nil
}

func (s *ASMetadataService) resolveGrants(ctx context.Context) []string {
	if s.grants == nil {
		return slices.Clone(baselineGrantTypes)
	}
	grants, err := s.grants.Get(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "resolve enabled grants failed; falling back to baseline grant types", "error", err)
		return slices.Clone(baselineGrantTypes)
	}
	// grant_types_supported is an always-present field carrying the always-enabled
	// authorization_code/refresh_token grants; never emit an empty/null list even
	// if a provider returns one.
	if len(grants) == 0 {
		return slices.Clone(baselineGrantTypes)
	}
	return grants
}

func (s *ASMetadataService) resolveScopes(ctx context.Context) []string {
	if s.resources == nil {
		return nil
	}
	// scopes_supported is OPTIONAL (RFC 8414 §2). A resource-lookup failure must
	// not take down the whole document — degrade by omitting scopes_supported.
	infos, err := s.resources.List(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "collect resource scopes failed; omitting scopes_supported from discovery document", "error", err)
		return nil
	}
	seen := make(map[string]bool)
	var scopes []string
	for _, rs := range infos {
		for _, sc := range rs.Scopes {
			if !seen[sc] {
				seen[sc] = true
				scopes = append(scopes, sc)
			}
		}
	}
	return scopes
}

func (s *ASMetadataService) cimdEnabled(ctx context.Context) bool {
	if s.cimd == nil {
		return false
	}
	cfg, err := s.cimd.Config(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "resolve CIMD config failed; advertising client_id_metadata_document_supported=false", "error", err)
		return false
	}
	return cfg.Enabled
}

func (s *ASMetadataService) introspectionEnabled(ctx context.Context) bool {
	if s.oauth == nil {
		return false
	}
	cfg, err := s.oauth.Config(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "resolve OAuth config failed; omitting introspection_endpoint from discovery document", "error", err)
		return false
	}
	return cfg.IntrospectionEnabled
}

func (s *ASMetadataService) dpopEnabled(ctx context.Context) bool {
	if s.dpop == nil {
		return false
	}
	cfg, err := s.dpop.Config(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "resolve DPoP config failed; omitting dpop_signing_alg_values_supported from discovery document", "error", err)
		return false
	}
	return cfg.Enabled
}

func (s *ASMetadataService) agentIdentityEnabled(ctx context.Context) bool {
	if s.agents == nil {
		return false
	}
	cfg, err := s.agents.Config(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "resolve agents config failed; advertising authplane_agent_identity_supported=false", "error", err)
		return false
	}
	return cfg.AgentIdentityEnabled
}
