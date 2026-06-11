package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

func TestRequiredSourceScopesForTargets(t *testing.T) {
	link := &resource.FrontingLink{
		ScopeMap: resource.ScopeMap{
			"A": {"AA"},
			"B": {"BB", "CC"}, // 1:N
			"D": {"AA"},       // duplicate target — multiple sources cover same target
		},
	}
	tests := []struct {
		name         string
		targets      []string
		wantSources  []string
		wantUnmapped []string
	}{
		{"single target — deterministic pick A over D", []string{"AA"}, []string{"A"}, nil},
		{"split targets each map to distinct sources", []string{"AA", "BB"}, []string{"A", "B"}, nil},
		{"unmapped target", []string{"ZZ"}, nil, []string{"ZZ"}},
		{"empty", nil, nil, nil},
		{"1:N satisfied by single source", []string{"BB", "CC"}, []string{"B"}, nil},
		{"mixed mapped + unmapped reports unmapped", []string{"AA", "ZZ"}, nil, []string{"ZZ"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSrc, gotUnmapped := requiredSourceScopesForTargets(link.ScopeMap, tt.targets)
			sort.Strings(gotSrc)
			if !reflect.DeepEqual(gotSrc, tt.wantSources) {
				t.Errorf("source scopes: got %v, want %v", gotSrc, tt.wantSources)
			}
			sort.Strings(gotUnmapped)
			if !reflect.DeepEqual(gotUnmapped, tt.wantUnmapped) {
				t.Errorf("unmapped: got %v, want %v", gotUnmapped, tt.wantUnmapped)
			}
		})
	}
}

func TestValidateBrokerTargets(t *testing.T) {
	link := resource.ScopeMap{
		"tool:list":   {"calendar.readonly"},
		"tool:create": {"calendar.events"},
		"tool:admin":  {"calendar.events", "calendar.admin"}, // 1:N source side
	}
	tests := []struct {
		name               string
		requested          []string // target-side scopes from req
		subjectScopes      []string // scopes present in the subject token claim
		wantValid          []string // targets that passed both gates (sorted)
		wantUnmapped       []string // targets not declared in any value list
		wantMissingCovered []string // targets whose source key(s) are absent from subject claim
	}{
		{
			name:          "single target covered by exact source",
			requested:     []string{"calendar.readonly"},
			subjectScopes: []string{"tool:list"},
			wantValid:     []string{"calendar.readonly"},
		},
		{
			name:          "two distinct targets each covered by its own source",
			requested:     []string{"calendar.readonly", "calendar.events"},
			subjectScopes: []string{"tool:list", "tool:create"},
			wantValid:     []string{"calendar.events", "calendar.readonly"},
		},
		{
			name:          "1:N target covered by alternate source key",
			requested:     []string{"calendar.events"},
			subjectScopes: []string{"tool:admin"}, // tool:admin maps to events too
			wantValid:     []string{"calendar.events"},
		},
		{
			name:          "covered when at least one mapping source is in claim",
			requested:     []string{"calendar.events", "calendar.admin"},
			subjectScopes: []string{"tool:admin"},
			wantValid:     []string{"calendar.admin", "calendar.events"},
		},
		{
			name:          "target not declared in any value list",
			requested:     []string{"calendar.readonly", "calendar.bogus"},
			subjectScopes: []string{"tool:list"}, // covers calendar.readonly so only the bogus one fails
			wantUnmapped:  []string{"calendar.bogus"},
		},
		{
			name:               "target declared but no source key in subject claim",
			requested:          []string{"calendar.events"},
			subjectScopes:      []string{"unrelated:scope"},
			wantMissingCovered: []string{"calendar.events"},
		},
		{
			name:               "mixed unmapped + missing-coverage both reported",
			requested:          []string{"calendar.bogus", "calendar.events"},
			subjectScopes:      []string{"unrelated:scope"},
			wantUnmapped:       []string{"calendar.bogus"},
			wantMissingCovered: []string{"calendar.events"},
		},
		{
			name: "empty input",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subjectSet := scope.New(tt.subjectScopes...)
			gotValid, gotUnmapped, gotMissingCov := validateBrokerTargets(link, tt.requested, subjectSet)
			if !reflect.DeepEqual(gotValid, tt.wantValid) {
				t.Errorf("valid: got %v, want %v", gotValid, tt.wantValid)
			}
			sort.Strings(gotUnmapped)
			if !reflect.DeepEqual(gotUnmapped, tt.wantUnmapped) {
				t.Errorf("unmapped: got %v, want %v", gotUnmapped, tt.wantUnmapped)
			}
			sort.Strings(gotMissingCov)
			if !reflect.DeepEqual(gotMissingCov, tt.wantMissingCovered) {
				t.Errorf("missingCoverage: got %v, want %v", gotMissingCov, tt.wantMissingCovered)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Task B — dispatchMint fronted-path unit tests.
//
// These tests exercise the fronted branch added to dispatchMint: scope-coverage
// gate (replacing user-consent), Option β client_id+act shape, audit chain_kind
// fields, and the regression guard that the direct path stays byte-identical
// when no link is present.
//
// The harness assembles a TokenExchangeService over in-memory fakes and a real
// MintIssuer, then drives dispatchMint directly so the test surface stays at
// the service-method boundary the fronted-path branch lives in. Existing
// helpers from broker_issuer_test.go (mockSigningKeyProvider, mockIssuanceStore,
// captureAuditRecorder) and resource_admin_test.go (fakeResourceStore) are
// reused; new fakes are limited to a counting ConsentGrantStore so the "no
// consent lookup on fronted path" assertion is exact, and a slug+URI capable
// resource store wrapper.
// -----------------------------------------------------------------------------

// trackingResourceStore wraps fakeResourceStore with a Resolve implementation
// that matches by slug or URI — the registry's lookup contract (slug-or-URI)
// requires it. fakeResourceStore.Resolve is a stub, so we override here
// rather than mutating the shared fixture used by other tests.
type trackingResourceStore struct {
	*fakeResourceStore
}

func (s *trackingResourceStore) Resolve(_ context.Context, slugOrURI string) ([]*resource.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.byID {
		if r.Slug == slugOrURI || (r.URI != "" && r.URI == slugOrURI) {
			cp := *r
			return []*resource.Resource{&cp}, nil
		}
	}
	return nil, nil
}

// countingConsentGrantStore is a minimal output.ConsentGrantStore that records
// Get-call counts (so we can assert zero on the fronted path) and serves
// pre-seeded grants for the direct-path regression guard.
type countingConsentGrantStore struct {
	mu     sync.Mutex
	getN   int
	grants map[string]*resource.ConsentGrant // key: user|client|resource
}

func newCountingConsentGrantStore() *countingConsentGrantStore {
	return &countingConsentGrantStore{grants: make(map[string]*resource.ConsentGrant)}
}

func cgKey(userID, clientID, resourceID string) string {
	return userID + "|" + clientID + "|" + resourceID
}

func (s *countingConsentGrantStore) Get(_ context.Context, userID, clientID, resourceID string) (*resource.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getN++
	g, ok := s.grants[cgKey(userID, clientID, resourceID)]
	if !ok {
		return nil, nil
	}
	cp := *g
	return &cp, nil
}

func (s *countingConsentGrantStore) seed(g *resource.ConsentGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.grants[cgKey(g.UserID, g.ClientID, g.ResourceID)] = &cp
}

func (s *countingConsentGrantStore) GetByID(_ context.Context, _ string) (*resource.ConsentGrant, error) {
	return nil, nil
}
func (s *countingConsentGrantStore) Upsert(_ context.Context, _ *resource.ConsentGrant) error {
	return nil
}
func (s *countingConsentGrantStore) Revoke(_ context.Context, _ string) error { return nil }
func (s *countingConsentGrantStore) ListForUser(_ context.Context, _ string) ([]*resource.ConsentGrant, error) {
	return nil, nil
}

// noopClientStore satisfies output.ClientStore for tests where the client
// lookup is never reached. dispatchMint only calls clients.GetByID inside
// the actor_token-driven branch of the act-chain switch; the fronted-path
// and the no-actor direct path both bypass it.
type noopClientStore struct{}

func (noopClientStore) Create(_ context.Context, _ *client.Client) error { return nil }
func (noopClientStore) GetByID(_ context.Context, _ string) (*client.Client, error) {
	return nil, errors.New("clients.GetByID should not be called in this test")
}
func (noopClientStore) GetByCIMDURL(_ context.Context, _ string) (*client.Client, error) {
	return nil, nil
}
func (noopClientStore) Update(_ context.Context, _ *client.Client) error { return nil }
func (noopClientStore) List(_ context.Context, _, _ string, _, _ int) ([]client.Client, error) {
	return nil, nil
}
func (noopClientStore) Count(_ context.Context, _ string) (int, error) { return 0, nil }
func (noopClientStore) ListAgents(_ context.Context) ([]client.Client, error) {
	return nil, nil
}
func (noopClientStore) Delete(_ context.Context, _ string) error { return nil }

// frontingFixture bundles every dependency dispatchMint reaches into, so
// individual tests can mutate just what they care about (scope_map shape,
// subject scopes, presence of consent grant) and call dispatchMint directly.
type frontingFixture struct {
	t              *testing.T
	svc            *TokenExchangeService
	signingKey     *output.SigningKey
	resources      *trackingResourceStore
	frontingLinks  *fakeFrontingLinkStore
	consentStore   *countingConsentGrantStore
	issuances      *mockIssuanceStore
	auditRec       *captureAuditRecorder
	source, target *resource.Resource
}

func newFrontingFixture(t *testing.T) *frontingFixture {
	t.Helper()
	obs := observability.NewNoop()

	resources := &trackingResourceStore{fakeResourceStore: newFakeResourceStore()}
	frontingLinks := newFakeFrontingLinkStore()
	consentStore := newCountingConsentGrantStore()
	auditRec := &captureAuditRecorder{}

	registry := NewResourceRegistry(resources, &mockBrokerProviderStore{}, obs)
	frontingSvc := NewFrontingService(frontingLinks, resources, nil, obs, auditRec)

	signingKey := newTestSigningKey(t)
	keyProv := &mockSigningKeyProvider{key: signingKey}

	issuances := &mockIssuanceStore{}
	mintIssuer := NewMintIssuer(keyProv, issuances, teFrontingIssuer, obs)

	svc := &TokenExchangeService{
		clients:       noopClientStore{},
		jwksSign:      keyProv,
		audit:         auditRec,
		issuer:        teFrontingIssuer,
		config:        TokenExchangeConfig{MaxChainDepth: 5, TokenExpiry: 15 * time.Minute},
		logger:        obs.Logger,
		tracer:        obs.Tracer,
		metrics:       obs.Metrics,
		registry:      registry,
		consentGrants: consentStore,
		mintIssuer:    mintIssuer,
		fronting:      frontingSvc,
	}

	return &frontingFixture{
		t:             t,
		svc:           svc,
		signingKey:    signingKey,
		resources:     resources,
		frontingLinks: frontingLinks,
		consentStore:  consentStore,
		issuances:     issuances,
		auditRec:      auditRec,
	}
}

const teFrontingIssuer = "https://auth.test.example.com"

// seedResource creates a Mint resource with the given slug, URI, and scope
// catalog and inserts it into the in-memory store.
func (f *frontingFixture) seedResource(slug, uri string, scopeNames []string) *resource.Resource {
	f.t.Helper()
	r := &resource.Resource{
		ID:          "rid-" + slug,
		Slug:        slug,
		DisplayName: slug,
		URI:         uri,
		BackendKind: resource.BackendMint,
	}
	for _, n := range scopeNames {
		r.Scopes = append(r.Scopes, resource.Scope{Name: n})
	}
	if err := f.resources.Create(context.Background(), r); err != nil {
		f.t.Fatalf("seed resource %q: %v", slug, err)
	}
	return r
}

// seedFrontingLink writes a fronting_links row for (source, target).
func (f *frontingFixture) seedFrontingLink(sourceSlug, targetSlug string, sm resource.ScopeMap) {
	f.t.Helper()
	link := &resource.FrontingLink{
		SourceSlug: sourceSlug,
		TargetSlug: targetSlug,
		ScopeMap:   sm,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  "admin",
	}
	if err := f.frontingLinks.Create(context.Background(), link); err != nil {
		f.t.Fatalf("seed fronting link: %v", err)
	}
}

// seedConsentGrant writes a consent_grants row keyed on (user, agent, target).
func (f *frontingFixture) seedConsentGrant(userID, agentClientID, resourceID string, scopes []string) {
	f.t.Helper()
	f.consentStore.seed(&resource.ConsentGrant{
		ID:         "cg-" + userID + "-" + agentClientID + "-" + resourceID,
		UserID:     userID,
		ClientID:   agentClientID,
		ResourceID: resourceID,
		Scopes:     scopes,
		CreatedAt:  time.Now().UTC(),
	})
}

// dispatchMintFronted calls svc.dispatchMint with the supplied claims and
// request, returning the response and decoded claims for assertion. Builds
// the trace span and start time inside; tests don't care about them.
func (f *frontingFixture) dispatchMintFronted(req input.TokenExchangeRequest, claims *crypto.AccessTokenClaims, target *resource.Resource) (*input.TokenExchangeResponse, *crypto.AccessTokenClaims, error) {
	f.t.Helper()
	ctx, span := f.svc.tracer.Start(context.Background(), "test.dispatchMint")
	defer span.End()
	resp, err := f.svc.dispatchMint(ctx, span, time.Now(), req, claims, target)
	if err != nil || resp == nil {
		return resp, nil, err
	}
	parsed := decodeMintToken(f.t, resp.AccessToken, f.signingKey)
	return resp, parsed, nil
}

// -- Common test setup --

const (
	frSourceSlug = "mcp-gw"
	frTargetSlug = "rest-api"
	frSourceURI  = "https://mcp-gw.example.com"
	frTargetURI  = "https://rest-api.example.com"
	frUserID     = "user-1"
	frAgentID    = "agent-x"
)

// stdFixture seeds two Mint resources (source + target) with disjoint scope
// catalogs and returns the prepared fixture. Individual tests then add the
// fronting link, subject token, and consent grant they need.
func stdFixture(t *testing.T) *frontingFixture {
	f := newFrontingFixture(t)
	f.source = f.seedResource(frSourceSlug, frSourceURI, []string{"A", "B", "C"})
	f.target = f.seedResource(frTargetSlug, frTargetURI, []string{"AA", "BB", "CC"})
	return f
}

func subjectClaimsForFronting(scopeStr, agentClientID string, audience []string) *crypto.AccessTokenClaims {
	now := time.Now().UTC()
	return &crypto.AccessTokenClaims{
		Issuer:    teFrontingIssuer,
		Subject:   frUserID,
		Audience:  audience,
		ClientID:  agentClientID,
		Scope:     scopeStr,
		JTI:       "subj-" + crypto.GenerateRandomString(8),
		IssuedAt:  now.Unix(),
		Expiry:    now.Add(1 * time.Hour).Unix(),
		NotBefore: now.Unix(),
	}
}

// -- B.5.1 Happy path: Option β shape --

func TestDispatchMint_Fronted_HappyPath_OptionBeta(t *testing.T) {
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{
		"A": {"AA"}, "B": {"BB"},
	})
	// No consent_grants row seeded — fronted path must not consult it.

	subj := subjectClaimsForFronting("A B", frAgentID, []string{frSourceURI})
	resp, parsed, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA BB",
	}, subj, f.target)
	if err != nil {
		t.Fatalf("dispatchMint: %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if parsed.Subject != frUserID {
		t.Errorf("sub = %q, want %q", parsed.Subject, frUserID)
	}
	if got := strings.Join(parsed.Audience, ","); got != frTargetURI {
		t.Errorf("aud = %v, want [%q]", parsed.Audience, frTargetURI)
	}
	wantScopes := []string{"AA", "BB"}
	gotScopes := strings.Fields(parsed.Scope)
	sort.Strings(gotScopes)
	if !reflect.DeepEqual(gotScopes, wantScopes) {
		t.Errorf("scope = %v, want %v", gotScopes, wantScopes)
	}
	if parsed.ClientID != frSourceSlug {
		t.Errorf("client_id = %q, want %q (Option β: source.Slug)", parsed.ClientID, frSourceSlug)
	}
	if parsed.Act == nil {
		t.Fatal("act claim missing on fronted token")
	}
	if got, _ := parsed.Act["sub"].(string); got != frSourceSlug {
		t.Errorf("act.sub = %v, want %q (Option β outer hop)", parsed.Act["sub"], frSourceSlug)
	}
	innerAct, _ := parsed.Act["act"].(map[string]interface{})
	if innerAct == nil {
		t.Fatal("act.act missing — agent should be at depth 2")
	}
	if got, _ := innerAct["sub"].(string); got != frAgentID {
		t.Errorf("act.act.sub = %v, want %q (the agent at depth 2)", innerAct["sub"], frAgentID)
	}
	// Critical: zero consent_grants lookups on the fronted path.
	if got := f.consentStore.getN; got != 0 {
		t.Errorf("consent_grants.Get called %d times on fronted path; want 0", got)
	}
}

// TestDispatchMint_Fronted_InnerActorIsRequester pins the regression that surfaced
// in the e2e merge gate: the inner actor (`act.act.sub`) must be the
// /oauth/token caller (`req.ClientID`), NOT the subject token's `client_id`. In a
// gateway-fanout topology where the GW mints its own token and an agent later
// exchanges it, those two values diverge — without this test, every other Task B
// fixture sets them equal and the bug stays invisible.
func TestDispatchMint_Fronted_InnerActorIsRequester(t *testing.T) {
	const (
		gwAsSubjectClient = "mcp-gw"       // who the GW token was issued to
		exchangingAgent   = "agent-fanout" // who calls /oauth/token
	)
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{
		"A": {"AA"}, "B": {"BB"},
	})

	subj := subjectClaimsForFronting("A B", gwAsSubjectClient, []string{frSourceURI})
	_, parsed, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: exchangingAgent,
		Resource: frTargetSlug,
		Scope:    "AA BB",
	}, subj, f.target)
	if err != nil {
		t.Fatalf("dispatchMint: %v", err)
	}
	if parsed.ClientID != frSourceSlug {
		t.Errorf("client_id = %q, want %q (Option β: source slug)", parsed.ClientID, frSourceSlug)
	}
	if got, _ := parsed.Act["sub"].(string); got != frSourceSlug {
		t.Errorf("act.sub = %v, want %q", parsed.Act["sub"], frSourceSlug)
	}
	innerAct, _ := parsed.Act["act"].(map[string]interface{})
	if innerAct == nil {
		t.Fatal("act.act missing")
	}
	if got, _ := innerAct["sub"].(string); got != exchangingAgent {
		t.Errorf("act.act.sub = %v, want %q (req.ClientID — the exchanger). Got %q would mean the inner actor was sourced from subjectClaims.ClientID, masking the gateway-fanout pattern.",
			innerAct["sub"], exchangingAgent, got)
	}
}

// -- B.5.2 Subject token missing source-side scope --

func TestDispatchMint_Fronted_MissingSourceScope(t *testing.T) {
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{
		"A": {"AA"}, "B": {"BB"},
	})

	// Subject token only carries A — request asks for BB which needs B.
	subj := subjectClaimsForFronting("A", frAgentID, []string{frSourceURI})
	_, _, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "BB",
	}, subj, f.target)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("error does not wrap ErrInvalidScope: %v", err)
	}
	if !strings.Contains(err.Error(), "missing source scope") {
		t.Errorf("error message missing 'missing source scope': %v", err)
	}
	if !strings.Contains(err.Error(), frSourceSlug) {
		t.Errorf("error message missing source slug %q: %v", frSourceSlug, err)
	}
	// The fronted path must NOT degrade to a ConsentRequiredError.
	var cre *domain.ConsentRequiredError
	if errors.As(err, &cre) {
		t.Errorf("fronted path must not surface ConsentRequiredError on missing source scope, got %+v", cre)
	}
}

// -- B.5.3 Target scope not present in scope_map --

func TestDispatchMint_Fronted_UnmappedTargetScope(t *testing.T) {
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{
		"A": {"AA"}, "B": {"BB"},
	})
	// CC is in target catalog but not in the link's ScopeMap values.

	subj := subjectClaimsForFronting("A", frAgentID, []string{frSourceURI})
	_, _, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "CC",
	}, subj, f.target)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("error does not wrap ErrInvalidScope: %v", err)
	}
	if !strings.Contains(err.Error(), "not present in fronting link scope_map") {
		t.Errorf("error message missing scope_map mention: %v", err)
	}
}

// -- B.5.4 1:N expansion (one source covers several target scopes) --

func TestDispatchMint_Fronted_OneToManyExpansion(t *testing.T) {
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{
		"A": {"AA", "BB"},
	})

	subj := subjectClaimsForFronting("A", frAgentID, []string{frSourceURI})
	_, parsed, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA BB",
	}, subj, f.target)
	if err != nil {
		t.Fatalf("dispatchMint: %v", err)
	}
	gotScopes := strings.Fields(parsed.Scope)
	sort.Strings(gotScopes)
	want := []string{"AA", "BB"}
	if !reflect.DeepEqual(gotScopes, want) {
		t.Errorf("scope = %v, want %v", gotScopes, want)
	}
	if got, _ := parsed.Act["sub"].(string); got != frSourceSlug {
		t.Errorf("act.sub = %v, want %q", parsed.Act["sub"], frSourceSlug)
	}
}

// -- B.5.5 Chained act prepend (subject token already has act) --

func TestDispatchMint_Fronted_ActChainPrepend(t *testing.T) {
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{
		"A": {"AA"},
	})

	priorAct := token.ActClaimToMap(&token.ActClaim{Sub: "prior-agent"})
	subj := subjectClaimsForFronting("A", frAgentID, []string{frSourceURI})
	subj.Act = priorAct

	_, parsed, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA",
	}, subj, f.target)
	if err != nil {
		t.Fatalf("dispatchMint: %v", err)
	}
	if got, _ := parsed.Act["sub"].(string); got != frSourceSlug {
		t.Errorf("act.sub = %v, want %q (source)", parsed.Act["sub"], frSourceSlug)
	}
	innerAct, _ := parsed.Act["act"].(map[string]interface{})
	if innerAct == nil {
		t.Fatal("act.act missing on chained prepend")
	}
	if got, _ := innerAct["sub"].(string); got != "prior-agent" {
		t.Errorf("act.act.sub = %v, want %q (existing chain preserved)", innerAct["sub"], "prior-agent")
	}
	// The agent (subjectClaims.ClientID) must NOT appear as an extra layer.
	if deeper, ok := innerAct["act"].(map[string]interface{}); ok {
		if got, _ := deeper["sub"].(string); got == frAgentID {
			t.Errorf("agent %q must not be inserted as a third layer when subject already has act, got chain depth ≥3", frAgentID)
		}
	}
}

// -- B.5.6 Direct-path regression guard (no fronting link) --

func TestDispatchMint_Direct_NoLink_RegressionGuard(t *testing.T) {
	f := stdFixture(t)
	// No fronting link seeded.
	f.seedConsentGrant(frUserID, frAgentID, f.target.ID, []string{"AA", "BB"})

	subj := subjectClaimsForFronting("AA BB", frAgentID, []string{frSourceURI})
	resp, parsed, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA BB",
	}, subj, f.target)
	if err != nil {
		t.Fatalf("dispatchMint (direct path): %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if parsed.ClientID != frAgentID {
		t.Errorf("direct path client_id = %q, want %q (the agent)", parsed.ClientID, frAgentID)
	}
	if parsed.Act != nil {
		t.Errorf("direct path act should be nil (no actor_token), got %v", parsed.Act)
	}
	gotScopes := strings.Fields(parsed.Scope)
	sort.Strings(gotScopes)
	want := []string{"AA", "BB"}
	if !reflect.DeepEqual(gotScopes, want) {
		t.Errorf("scope = %v, want %v", gotScopes, want)
	}
	// Direct path MUST consult consent_grants — exactly once.
	if got := f.consentStore.getN; got != 1 {
		t.Errorf("consent_grants.Get called %d times on direct path; want 1", got)
	}
}

// -- B.5.7 Audit chain_kind=fronted --

func TestDispatchMint_Audit_FrontedKind(t *testing.T) {
	f := stdFixture(t)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap{"A": {"AA"}})

	subj := subjectClaimsForFronting("A", frAgentID, []string{frSourceURI})
	if _, _, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA",
	}, subj, f.target); err != nil {
		t.Fatalf("dispatchMint: %v", err)
	}

	ev := lastTokenExchangedEvent(t, f.auditRec.take())
	for _, want := range []string{"chain_kind=fronted", "via_link=" + frSourceSlug + "->" + frTargetSlug} {
		if !strings.Contains(ev.Detail, want) {
			t.Errorf("audit detail %q missing %q", ev.Detail, want)
		}
	}
}

// -- B.5.8 Audit chain_kind=direct (regression guard for the legacy shape) --

func TestDispatchMint_Audit_DirectKind(t *testing.T) {
	f := stdFixture(t)
	f.seedConsentGrant(frUserID, frAgentID, f.target.ID, []string{"AA"})

	subj := subjectClaimsForFronting("AA", frAgentID, []string{frSourceURI})
	if _, _, err := f.dispatchMintFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frTargetSlug,
		Scope:    "AA",
	}, subj, f.target); err != nil {
		t.Fatalf("dispatchMint: %v", err)
	}

	ev := lastTokenExchangedEvent(t, f.auditRec.take())
	if !strings.Contains(ev.Detail, "chain_kind=direct") {
		t.Errorf("audit detail %q missing chain_kind=direct", ev.Detail)
	}
	// Empty via_link suffix on the direct path — pinned so a future change
	// that defaults via_link to a non-empty placeholder fails loudly.
	if !strings.Contains(ev.Detail, "via_link=") {
		t.Errorf("audit detail %q missing via_link= (empty)", ev.Detail)
	}
	if strings.Contains(ev.Detail, "via_link="+frSourceSlug) {
		t.Errorf("audit detail %q must not carry a fronting via_link on the direct path", ev.Detail)
	}
}

// lastTokenExchangedEvent returns the most recent ActionTokenExchanged event
// or fails the test. Filters denials and other actions out.
func lastTokenExchangedEvent(t *testing.T, events []audit.Event) audit.Event {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == audit.ActionTokenExchanged {
			return events[i]
		}
	}
	t.Fatalf("no ActionTokenExchanged event; got %d events", len(events))
	return audit.Event{}
}

// -- input ports type alias guard ----------------------------------------------
// Kept inline so the unused-imports linter does not flag input/output even when
// individual tests above don't directly reference them. Removing this would be
// safe; it's a lightweight assertion that input.TokenExchangeRequest hasn't
// drifted in a way that breaks the dispatchMint signature this file uses.
var _ input.TokenExchangeRequest = input.TokenExchangeRequest{}
var _ output.ConsentGrantStore = (*countingConsentGrantStore)(nil)

// =============================================================================
// — Broker-flavored fixture for fronted-broker dispatch tests.
//
// brokerFixture extends frontingFixture with:
//   - a Broker resource (brokerTarget) backed by a BrokerProvider (provider),
//   - a simpleBrokerGrantStore that T7+ tests seed via seedActiveGrant,
//   - a stubBrokerAdapter (reused from broker_issuer_test.go) registered in
//     a fresh brokerproto.Registry,
//   - a wired BrokerIssuer injected into svc.brokerIssuer so dispatchBroker
//     can resolve through the live code path.
//
// The mint-side bits (source mint resource, frontingLinks store) are inherited
// via composition — call seedFrontingLink(frSourceSlug, frBrokerTargetSlug, sm)
// to hook the two together for fronted-broker tests.
//
// Choice: composition over parallel struct. brokerFixture embeds
// *frontingFixture so all mint-side helper methods (seedFrontingLink,
// seedConsentGrant, dispatchMintFronted) remain available without duplication.
// The only mutation to frontingFixture is assigning svc.brokerIssuer and
// re-building svc.registry with a broker-provider-aware store; this is safe
// because newFrontingFixture() leaves brokerIssuer nil and uses a stub
// provider store with nil functions (never called by mint tests).
// =============================================================================

// simpleBrokerGrantStore is an in-memory output.BrokerGrantStore keyed on
// (userID, providerID). Sufficient for the fronted-broker dispatch tests
// which only need Get and UpdateWithVersion (for credential rotation).
type simpleBrokerGrantStore struct {
	mu     sync.Mutex
	grants map[string]*resource.BrokerGrant // key: userID + "|" + providerID
}

func newSimpleBrokerGrantStore() *simpleBrokerGrantStore {
	return &simpleBrokerGrantStore{
		grants: make(map[string]*resource.BrokerGrant),
	}
}

func bgKey(userID, providerID string) string { return userID + "|" + providerID }

func (s *simpleBrokerGrantStore) put(g *resource.BrokerGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.grants[bgKey(g.UserID, g.BrokerProviderID)] = &cp
}

func (s *simpleBrokerGrantStore) Get(_ context.Context, userID, providerID string) (*resource.BrokerGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[bgKey(userID, providerID)]
	if !ok {
		return nil, nil
	}
	cp := *g
	return &cp, nil
}

func (s *simpleBrokerGrantStore) GetByID(_ context.Context, _ string) (*resource.BrokerGrant, error) {
	return nil, errors.New("simpleBrokerGrantStore: GetByID not implemented")
}

func (s *simpleBrokerGrantStore) Create(_ context.Context, g *resource.BrokerGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.grants[bgKey(g.UserID, g.BrokerProviderID)] = &cp
	return nil
}

func (s *simpleBrokerGrantStore) Upsert(_ context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.grants[bgKey(g.UserID, g.BrokerProviderID)] = &cp
	return &cp, nil
}

func (s *simpleBrokerGrantStore) UpdateWithVersion(_ context.Context, g *resource.BrokerGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *g
	s.grants[bgKey(g.UserID, g.BrokerProviderID)] = &cp
	return nil
}

func (s *simpleBrokerGrantStore) Revoke(_ context.Context, _ string) error { return nil }

func (s *simpleBrokerGrantStore) ListForUser(_ context.Context, _ string) ([]*resource.BrokerGrant, error) {
	return nil, nil
}

// staticBrokerProviderStore is a minimal output.BrokerProviderStore that serves
// a single pre-registered provider for GetByID / GetBySlug. Used by the broker
// fixture to make ResourceRegistry.GetWithProvider resolve the test provider
// without a database.
type staticBrokerProviderStore struct {
	provider *resource.BrokerProvider
}

func (s *staticBrokerProviderStore) GetByID(_ context.Context, id string) (*resource.BrokerProvider, error) {
	if s.provider != nil && s.provider.ID == id {
		cp := *s.provider
		return &cp, nil
	}
	return nil, domain.ErrResourceNotFound
}

func (s *staticBrokerProviderStore) GetBySlug(_ context.Context, slug string) (*resource.BrokerProvider, error) {
	if s.provider != nil && s.provider.Slug == slug {
		cp := *s.provider
		return &cp, nil
	}
	return nil, domain.ErrResourceNotFound
}

func (s *staticBrokerProviderStore) List(_ context.Context) ([]*resource.BrokerProvider, error) {
	if s.provider == nil {
		return nil, nil
	}
	cp := *s.provider
	return []*resource.BrokerProvider{&cp}, nil
}

func (s *staticBrokerProviderStore) Create(_ context.Context, _ *resource.BrokerProvider) error {
	return errors.New("staticBrokerProviderStore: Create not implemented")
}

func (s *staticBrokerProviderStore) Update(_ context.Context, _ *resource.BrokerProvider) error {
	return errors.New("staticBrokerProviderStore: Update not implemented")
}

func (s *staticBrokerProviderStore) Delete(_ context.Context, _ string) error {
	return errors.New("staticBrokerProviderStore: Delete not implemented")
}

// brokerFixture extends frontingFixture with broker machinery. Use
// stdBrokerFixture(t) to construct it.
type brokerFixture struct {
	*frontingFixture
	provider     *resource.BrokerProvider
	brokerTarget *resource.Resource
	adapter      *stubBrokerAdapter
	brokerGrants *simpleBrokerGrantStore
}

const (
	frBrokerTargetSlug = "google-cal"
	frBrokerTargetURI  = "https://calendar.google.com/api"
	frBrokerProviderID = "prov-google"
	frBrokerProvSlug   = "google"
)

// stdBrokerFixture extends the mint-side fronting fixture (stdFixture) with
// broker machinery: a Broker target Resource with a BrokerProvider, a
// stubBrokerAdapter registered in a fresh brokerproto.Registry, a
// simpleBrokerGrantStore for grant seeding, and a fully-wired BrokerIssuer
// injected into svc.brokerIssuer.
//
// The mint-side source resource (frSourceSlug) and frontingLinks store are
// inherited from stdFixture. Call seedFrontingLink(frSourceSlug,
// frBrokerTargetSlug, sm) to create the fronting link the T7+ tests need.
func stdBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	mintF := stdFixture(t)

	provider := &resource.BrokerProvider{
		ID:       frBrokerProviderID,
		Slug:     frBrokerProvSlug,
		Protocol: resource.ProtocolOAuth,
	}
	target := &resource.Resource{
		ID:               "res-" + frBrokerTargetSlug,
		Slug:             frBrokerTargetSlug,
		DisplayName:      "Google Calendar",
		URI:              frBrokerTargetURI,
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: provider.ID,
		Scopes: []resource.Scope{
			{Name: "readonly", Upstream: "calendar.readonly"},
			{Name: "events", Upstream: "calendar.events"},
		},
	}

	// Register broker target in the shared resource store so registry lookups
	// (both Resolve and GetByID) work. trackingResourceStore.Create delegates
	// to fakeResourceStore.Create which indexes by ID and slug.
	if err := mintF.resources.Create(context.Background(), target); err != nil {
		t.Fatalf("stdBrokerFixture: seed broker target resource: %v", err)
	}

	// Build a broker-protocol-aware registry and adapter.
	obs := observability.NewNoop()
	reg := brokerproto.NewRegistry()
	adapter := &stubBrokerAdapter{name: string(resource.ProtocolOAuth)}
	if err := reg.Register(adapter); err != nil {
		t.Fatalf("stdBrokerFixture: register stub adapter: %v", err)
	}

	// Build a simple grant store.
	brokerGrants := newSimpleBrokerGrantStore()

	// Re-build ResourceRegistry with a provider store that serves our test
	// provider. The existing svc.registry used a nil-function mockBrokerProviderStore
	// that was fine for mint-only tests; broker dispatch calls GetByID on the
	// provider store, so we need a real implementation here.
	providerStore := &staticBrokerProviderStore{provider: provider}
	newRegistry := NewResourceRegistry(mintF.resources, providerStore, obs)
	mintF.svc.registry = newRegistry

	// Wire a BrokerIssuer into svc. The mockDataEncryptor default behavior
	// (identity transform) is intentional — CredentialData stored in
	// simpleBrokerGrantStore is already "plaintext" from the adapter's
	// perspective (no real encryption in unit tests).
	enc := &mockDataEncryptor{}
	brokerIssuer := NewBrokerIssuer(brokerGrants, enc, mintF.issuances, reg, obs, mintF.auditRec)
	mintF.svc.brokerIssuer = brokerIssuer

	return &brokerFixture{
		frontingFixture: mintF,
		provider:        provider,
		brokerTarget:    target,
		adapter:         adapter,
		brokerGrants:    brokerGrants,
	}
}

// seedActiveGrant inserts a BrokerGrant for (userID, provider) with the
// supplied granted scopes. CredentialData is a raw plaintext token that the
// mockDataEncryptor passes through transparently so the stubBrokerAdapter
// receives it unchanged.
func (f *brokerFixture) seedActiveGrant(userID string, scopesGranted []string) {
	f.t.Helper()
	f.brokerGrants.put(&resource.BrokerGrant{
		ID:               "grant-" + userID,
		UserID:           userID,
		BrokerProviderID: f.provider.ID,
		ScopesGranted:    scopesGranted,
		CredentialData:   []byte(`{"refresh_token":"rt-x"}`),
		EncBackend:       "mock",
		Version:          1,
	})
}

// Interface-satisfaction guards — compile-time checks that the new stores
// satisfy their respective output port interfaces.
var _ output.BrokerGrantStore = (*simpleBrokerGrantStore)(nil)
var _ output.BrokerProviderStore = (*staticBrokerProviderStore)(nil)

// =============================================================================
// — dispatchFrontedBroker unit tests.
//
// Five cases covering: happy path (no consent_grants lookup), upstream
// consent missing (ConsentRequiredError from BrokerIssuer), upstream scope
// insufficient (ConsentRequiredError from BrokerIssuer), source scope
// unmapped in link.ScopeMap (early rejection before adapter call), and
// upstream invalid_grant (ConsentRequiredError with DeniedReason).
// =============================================================================

// noopSpan returns a no-op trace.Span using the test noop tracer. It allows
// tests to call dispatchFrontedBroker directly without a real trace context.
func noopSpan() trace.Span {
	_, span := observability.NewNoopTracer().Start(context.Background(), "noop")
	return span
}

// mustGetFrontingLink retrieves the fronting link (src→tgt) from the fixture's
// in-memory store, failing the test if the link is absent.
func mustGetFrontingLink(t *testing.T, f *brokerFixture, src, tgt string) *resource.FrontingLink {
	t.Helper()
	link, err := f.frontingLinks.Get(context.Background(), src, tgt)
	if err != nil {
		t.Fatalf("mustGetFrontingLink(%q, %q): %v", src, tgt, err)
	}
	return link
}

func TestDispatchFrontedBroker_HappyPath(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})
	f.adapter.vendAccessToken = "upstream-token-xyz"
	f.adapter.vendExpiresIn = 1800

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	link := mustGetFrontingLink(t, f, frSourceSlug, frBrokerTargetSlug)

	resp, err := f.svc.dispatchFrontedBroker(
		context.Background(),
		noopSpan(),
		time.Now(),
		input.TokenExchangeRequest{
			ClientID: frAgentID,
			Resource: frBrokerTargetSlug,
			Scope:    "readonly",
		},
		subj,
		f.brokerTarget,
		f.source,
		link,
	)
	if err != nil {
		t.Fatalf("dispatchFrontedBroker: %v", err)
	}
	if resp == nil || resp.AccessToken != "upstream-token-xyz" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "upstream-token-xyz")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != 1800 {
		t.Errorf("ExpiresIn = %d, want 1800", resp.ExpiresIn)
	}
	if f.adapter.vendCalls != 1 {
		t.Errorf("adapter.vendCalls = %d, want 1", f.adapter.vendCalls)
	}
	// Critical: zero consent_grants lookups on the fronted broker path.
	if got := f.consentStore.getN; got != 0 {
		t.Errorf("consent_grants.Get called %d times on fronted broker path; want 0", got)
	}
}

func TestDispatchFrontedBroker_NoUpstreamConnection(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	// NO seedActiveGrant — grant.Get returns nil → BrokerIssuer emits ConsentRequiredError.

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	link := mustGetFrontingLink(t, f, frSourceSlug, frBrokerTargetSlug)

	_, err := f.svc.dispatchFrontedBroker(context.Background(), noopSpan(), time.Now(),
		input.TokenExchangeRequest{ClientID: frAgentID, Resource: frBrokerTargetSlug, Scope: "readonly"},
		subj, f.brokerTarget, f.source, link)
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
}

func TestDispatchFrontedBroker_UpstreamScopeInsufficient(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:create": {"events"},
	})
	// User's grant is for readonly only; mapping requires events.
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})

	subj := subjectClaimsForFronting("tool:create", frAgentID, []string{frSourceURI})
	link := mustGetFrontingLink(t, f, frSourceSlug, frBrokerTargetSlug)

	_, err := f.svc.dispatchFrontedBroker(context.Background(), noopSpan(), time.Now(),
		input.TokenExchangeRequest{ClientID: frAgentID, Resource: frBrokerTargetSlug, Scope: "events"},
		subj, f.brokerTarget, f.source, link)
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
}

func TestDispatchFrontedBroker_ScopeUnmapped(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
		// NO entry for tool:bogus.
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly", "calendar.events"})

	subj := subjectClaimsForFronting("tool:bogus", frAgentID, []string{frSourceURI})
	link := mustGetFrontingLink(t, f, frSourceSlug, frBrokerTargetSlug)

	_, err := f.svc.dispatchFrontedBroker(context.Background(), noopSpan(), time.Now(),
		input.TokenExchangeRequest{ClientID: frAgentID, Resource: frBrokerTargetSlug, Scope: "tool:bogus"},
		subj, f.brokerTarget, f.source, link)
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	if cre.DeniedReason != "scope_unmapped" {
		t.Errorf("DeniedReason = %q, want %q", cre.DeniedReason, "scope_unmapped")
	}
	// ProviderSlug must be the broker provider's slug, NOT the UUID FK
	// (target.BrokerProviderID). A UUID here would make the consent redirect
	// point at a non-existent /connect/<uuid> route.
	if cre.ProviderSlug != frBrokerProvSlug {
		t.Errorf("ProviderSlug = %q, want %q (broker provider slug, not UUID)", cre.ProviderSlug, frBrokerProvSlug)
	}
	// Adapter must NOT have been called when scopes don't even map.
	if f.adapter.vendCalls != 0 {
		t.Errorf("adapter.vendCalls = %d, want 0 on unmapped path", f.adapter.vendCalls)
	}
}

func TestDispatchFrontedBroker_RefreshInvalidGrant(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})
	f.adapter.vendErr = fmt.Errorf("upstream rejected: %w", output.ErrUpstreamInvalidGrant)

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	link := mustGetFrontingLink(t, f, frSourceSlug, frBrokerTargetSlug)

	_, err := f.svc.dispatchFrontedBroker(context.Background(), noopSpan(), time.Now(),
		input.TokenExchangeRequest{ClientID: frAgentID, Resource: frBrokerTargetSlug, Scope: "readonly"},
		subj, f.brokerTarget, f.source, link)
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("err = %v, want ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
	if cre.DeniedReason != "invalid_grant" {
		t.Errorf("DeniedReason = %q, want %q", cre.DeniedReason, "invalid_grant")
	}
}

// =============================================================================
// — dispatchBroker fronted-detection integration tests.
//
// These tests drive dispatchBroker (the public entry point) instead of
// dispatchFrontedBroker directly, verifying that the detection hook routes
// correctly when a fronting link is present.
//
// The second "no link / direct path" scenario is covered by the
// TestDispatchMint_Direct_NoLink_RegressionGuard which already pins the
// fronting.Get → ErrFrontingLinkNotFound fallthrough at the same detection
// site reused here. Duplicating that scenario against dispatchBroker would
// require seeding the full direct-broker path (agent-attestation grant +
// actor resource row), which is non-trivial; the symmetry argument is sound.
// =============================================================================

// dispatchBrokerFronted calls svc.dispatchBroker via the exported Exchange
// path, passing pre-decoded subjectClaims to bypass JWT verification. It
// mirrors dispatchMintFronted but targets the broker dispatch branch.
func (f *brokerFixture) dispatchBrokerFronted(req input.TokenExchangeRequest, claims *crypto.AccessTokenClaims) (*input.TokenExchangeResponse, error) {
	f.t.Helper()
	ctx, span := f.svc.tracer.Start(context.Background(), "test.dispatchBroker")
	defer span.End()
	target, err := f.svc.registry.Resolve(ctx, req.Resource)
	if err != nil {
		return nil, fmt.Errorf("dispatchBrokerFronted: resolve target %q: %w", req.Resource, err)
	}
	return f.svc.dispatchBroker(ctx, span, time.Now(), req, claims, target)
}

func TestDispatchBroker_FrontedDetection_RoutesToFrontedHelper(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})
	f.adapter.vendAccessToken = "ut-1"

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	resp, err := f.dispatchBrokerFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frBrokerTargetSlug,
		Scope:    "readonly",
	}, subj)
	if err != nil {
		t.Fatalf("dispatchBroker: %v", err)
	}
	if resp.AccessToken != "ut-1" {
		t.Errorf("AccessToken = %q, want fronted-broker upstream token %q", resp.AccessToken, "ut-1")
	}
	// Direct path's agent-attestation gate must NOT have been consulted.
	if got := f.consentStore.getN; got != 0 {
		t.Errorf("consent_grants.Get called %d times on fronted broker path; want 0", got)
	}
}

// =============================================================================
// — dispatchFrontedBroker audit + metric emission tests.
//
// Two cases: success-path audit event carries the fronted-broker detail
// format (type=broker_dispatch, chain_kind=fronted, target_kind=broker,
// via_link), and the denial-path audit event carries denied_reason= when
// BrokerIssuer emits ConsentRequiredError with CauseConsentMissing (the
// "no upstream connection" scenario).
// =============================================================================

func TestDispatchFrontedBroker_Audit_Success(t *testing.T) {
	mc := newMetricCollector(t)

	f := stdBrokerFixture(t)
	// Hot-swap the single counter so we can inspect its data points after
	// the dispatch. Pattern mirrors TestDispatchMint_Metric_LabelsOnSuccess.
	f.svc.metrics.TokenExchangeTotal = mc.int64Counter(t, "authplane_token_exchange_total")

	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})
	f.adapter.vendAccessToken = "ut-1"

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	if _, err := f.dispatchBrokerFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frBrokerTargetSlug,
		Scope:    "readonly",
	}, subj); err != nil {
		t.Fatalf("dispatchBrokerFronted: %v", err)
	}

	// Find the dispatch-site audit event (ActionTokenExchanged) emitted by
	// dispatchFrontedBroker on the success path. BrokerIssuer.Issue also
	// emits its own audit row; we look for the one that carries broker_dispatch
	// chain metadata to identify the dispatch-site emission specifically.
	events := f.auditRec.take()
	found := false
	for _, ev := range events {
		if ev.Action != audit.ActionTokenExchanged {
			continue
		}
		if !strings.Contains(ev.Detail, "type=broker_dispatch") {
			continue
		}
		// This is the dispatch-site event — assert all required fragments.
		for _, want := range []string{
			"type=broker_dispatch",
			"chain_kind=fronted",
			"target_kind=broker",
			"via_link=" + frSourceSlug + "->" + frBrokerTargetSlug,
		} {
			if !strings.Contains(ev.Detail, want) {
				t.Errorf("audit detail %q missing fragment %q", ev.Detail, want)
			}
		}
		found = true
	}
	if !found {
		t.Fatalf("no ActionTokenExchanged audit event with type=broker_dispatch found; got %d events", len(events))
	}

	// Assert that TokenExchangeTotal was incremented with the fronted-broker
	// source/target labels (kind=fronted, source=<frSourceSlug>,
	// target=<frBrokerTargetSlug>). Mirrors the assertion shape used by
	// TestDispatchMint_Metric_LabelsOnSuccess for the fronted-mint path.
	points := mc.dataPoints(t, "authplane_token_exchange_total")
	if !pointHasAttrs(t, points, map[string]string{
		"kind":   "fronted",
		"source": frSourceSlug,
		"target": frBrokerTargetSlug,
	}, 1) {
		t.Errorf("TokenExchangeTotal missing fronted-broker data point {kind=fronted,source=%s,target=%s}; got %s",
			frSourceSlug, frBrokerTargetSlug, debugPoints(points))
	}
}

// TestDispatchFrontedBroker_SubjectClient_IsSubjectTokenClient pins that the
// subject_client= audit field carries the client that the subject_token was
// issued to (subjectClaims.ClientID), NOT the agent currently calling /token
// (req.ClientID). In a gateway-fanout topology these two values diverge.
// Mirrors TestDispatchMint_Fronted_InnerActorIsRequester for the broker side.
func TestDispatchFrontedBroker_SubjectClient_IsSubjectTokenClient(t *testing.T) {
	const (
		gwAsSubjectClient = "mcp-gw-client" // who the subject token was issued to
		exchangingAgent   = "agent-fanout"  // who is now calling /oauth/token
	)

	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	f.seedActiveGrant(frUserID, []string{"calendar.readonly"})
	f.adapter.vendAccessToken = "ut-diverge"

	// Subject token was issued to gwAsSubjectClient; the agent calling /token
	// is exchangingAgent. These are intentionally DIFFERENT so that a bug
	// (using req.ClientID for subject_client) produces a wrong assertion.
	subj := subjectClaimsForFronting("tool:list", gwAsSubjectClient, []string{frSourceURI})
	if _, err := f.dispatchBrokerFronted(input.TokenExchangeRequest{
		ClientID: exchangingAgent,
		Resource: frBrokerTargetSlug,
		Scope:    "readonly",
	}, subj); err != nil {
		t.Fatalf("dispatchBrokerFronted: %v", err)
	}

	events := f.auditRec.take()
	for _, ev := range events {
		if ev.Action != audit.ActionTokenExchanged {
			continue
		}
		if !strings.Contains(ev.Detail, "type=broker_dispatch") {
			continue
		}
		// subject_client must be the subject token's client, not the caller.
		wantSubjectClient := "subject_client=" + gwAsSubjectClient
		if !strings.Contains(ev.Detail, wantSubjectClient) {
			t.Errorf("audit detail %q: subject_client must be the subject token's client (%q), not req.ClientID (%q)",
				ev.Detail, gwAsSubjectClient, exchangingAgent)
		}
		// Sanity: actor_client is source.Slug per Option β semantics.
		wantActorClient := "actor_client=" + frSourceSlug
		if !strings.Contains(ev.Detail, wantActorClient) {
			t.Errorf("audit detail %q: actor_client must be source slug %q", ev.Detail, frSourceSlug)
		}
		return
	}
	t.Fatal("no ActionTokenExchanged audit event with type=broker_dispatch found")
}

func TestDispatchFrontedBroker_Audit_DenialEmitsDeniedReason(t *testing.T) {
	f := stdBrokerFixture(t)
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap{
		"tool:list": {"readonly"},
	})
	// No seedActiveGrant — BrokerIssuer.Issue returns ConsentRequiredError
	// with Cause=CauseConsentMissing, DeniedReason="" (empty). T9 maps this
	// to "upstream_connection_missing" in the dispatch-site audit emission.

	subj := subjectClaimsForFronting("tool:list", frAgentID, []string{frSourceURI})
	if _, err := f.dispatchBrokerFronted(input.TokenExchangeRequest{
		ClientID: frAgentID,
		Resource: frBrokerTargetSlug,
		Scope:    "readonly",
	}, subj); err == nil {
		t.Fatal("expected denial error, got nil")
	}

	events := f.auditRec.take()
	found := false
	for _, ev := range events {
		if ev.Action == audit.ActionTokenExchanged &&
			strings.Contains(ev.Detail, "denied_reason=upstream_connection_missing") {
			found = true
		}
	}
	if !found {
		t.Errorf("no ActionTokenExchanged audit event with denied_reason=upstream_connection_missing; got %d events", len(events))
	}
}
