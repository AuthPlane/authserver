// Package dto holds the JSON wire-shape views for the unified-resource
// admin surface. The views are shared by:
//
//   - api/admin (HTTP handlers serving /admin/resources, /admin/broker-providers,
//     /admin/grants, /admin/issuances)
//   - cmd/authserver (CLI subcommands for the same admin surface)
//
// Both layers must emit byte-identical JSON for the same domain entity, so
// the shapes + conversion functions live in one place. This package depends
// only on internal/domain/resource + internal/ports/input — no HTTP, no
// cobra, no transport-specific code — so either driving adapter can import
// it without pulling the other's deps along.
//
// Hexagonal note: this is an "outbound DTO" package; it sits next to the
// domain rather than inside any adapter because it's reused across two
// adapter layers.
package dto

import (
	"encoding/json"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

// --- Unified Resource + Broker Provider views ---

// ScopeView is the wire-level form of a scope on a unified Resource.
// Carries the optional `upstream` mapping used by Broker resources;
// Mint resources omit it.
type ScopeView struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
}

// ExchangePolicyView is the JSON form of resource.ExchangePolicy.
type ExchangePolicyView struct {
	AllowedClientIDs []string `json:"allowed_client_ids"`
}

// RuntimePolicyView is the JSON form of resource.RuntimePolicy. Lists the
// OAuth client_ids authorized to act AS this Resource at runtime.
type RuntimePolicyView struct {
	ClientIDs []string `json:"client_ids"`
}

// ConnectPolicyView is the JSON form of resource.ConnectPolicy.
type ConnectPolicyView struct {
	AllowedReturnURLs []string `json:"allowed_return_urls"`
}

// PolicyView is the JSON form of resource.Policy. Connect is a pointer so
// `omitempty` actually fires for Mint resources (which have no Connect
// policy semantics — see the design §6); a struct-typed field with omitempty is a
// no-op in encoding/json, which is why this field is *ConnectPolicyView.
type PolicyView struct {
	Exchange ExchangePolicyView `json:"exchange"`
	Runtime  RuntimePolicyView  `json:"runtime"`
	Connect  *ConnectPolicyView `json:"connect,omitempty"`
}

// ResourceView is the sanitized JSON representation of a unified Resource.
// For Mint resources broker_provider_id is "" and the connect policy is
// omitted from the wire form.
type ResourceView struct {
	ID               string      `json:"id"`
	Slug             string      `json:"slug"`
	URI              string      `json:"uri"`
	BackendKind      string      `json:"backend_kind"`
	BrokerProviderID string      `json:"broker_provider_id"`
	DisplayName      string      `json:"display_name"`
	Scopes           []ScopeView `json:"scopes"`
	Policy           PolicyView  `json:"policy"`
	CreatedAt        string      `json:"created_at"`
	UpdatedAt        string      `json:"updated_at"`
}

// BrokerProviderView is the sanitized JSON representation of a
// BrokerProvider. `config_data` is a JSON RawMessage round-tripped
// byte-for-byte; the admin layer never inspects it.
type BrokerProviderView struct {
	ID          string          `json:"id"`
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Protocol    string          `json:"protocol"`
	ConfigData  json.RawMessage `json:"config_data"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

// --- Grant + Issuance views ---

// ConsentGrantView is the wire-level form of a consent_grants row. The
// admin surface shows full history (active + revoked); RevokedAt is a
// pointer + omitempty so the field is absent for active rows.
type ConsentGrantView struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	ClientID   string     `json:"client_id"`
	ResourceID string     `json:"resource_id"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  string     `json:"created_at"`
	UpdatedAt  string     `json:"updated_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// BrokerGrantView is the wire-level form of a broker_grants row.
//
// SECURITY: credential_data is NEVER part of this struct. The encrypted
// upstream credential must never appear in any admin response — defense
// in depth even against an admin reading the JSON. The runtime
// regression test TestAdmin_BrokerGrantViews_NeverLeakCredentialData
// asserts the field key is absent from every admin response that
// returns broker_grant data; type-system absence here is the primary
// guard. If a future contributor reaches to add the field "for
// completeness", STOP — see the design
type BrokerGrantView struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	BrokerProviderID string     `json:"broker_provider_id"`
	ScopesGranted    []string   `json:"scopes_granted"`
	Version          int64      `json:"version"`
	EncBackend       string     `json:"enc_backend"`
	CreatedAt        string     `json:"created_at"`
	UpdatedAt        string     `json:"updated_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// UserGrantsView is the JSON body for GET /admin/users/{id}/grants and
// for the equivalent CLI form. Each list defaults to an empty array on
// the wire (not null) so client tooling always parses an array.
type UserGrantsView struct {
	ConsentGrants []ConsentGrantView `json:"consent_grants"`
	BrokerGrants  []BrokerGrantView  `json:"broker_grants"`
}

// IssuanceView is the wire-level form of an issuances row. AgentChain is
// non-nil empty by default for the same reason as Scopes.
type IssuanceView struct {
	ID            string     `json:"id"`
	JTI           string     `json:"jti"`
	SubjectUserID string     `json:"subject_user_id"`
	ClientID      string     `json:"client_id"`
	ResourceID    string     `json:"resource_id"`
	Scopes        []string   `json:"scopes"`
	BackendKind   string     `json:"backend_kind"`
	Revocable     bool       `json:"revocable"`
	IssuedAt      string     `json:"issued_at"`
	ExpiresAt     string     `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	DPoPJKT       string     `json:"dpop_jkt,omitempty"`
	AgentID       string     `json:"agent_id,omitempty"`
	AgentChain    []string   `json:"agent_chain"`
}

// IssuanceListResponse is the JSON body for GET /admin/issuances.
// `since` is the effective window-start time used by the underlying
// query; for the ?jti=… form it is the zero value (no window applied).
type IssuanceListResponse struct {
	Issuances []IssuanceView `json:"issuances"`
	Since     string         `json:"since"`
	Count     int            `json:"count"`
}

// --- Conversion helpers ---

// ScopeToView converts a domain Scope (with optional Upstream) to its
// wire-level view, preserving the Upstream mapping used by Broker
// resources. Mint resources omit the Upstream field on the wire (omitempty).
func ScopeToView(s resource.Scope) ScopeView {
	return ScopeView{
		Name:        s.Name,
		Description: s.Description,
		Upstream:    s.Upstream,
	}
}

// ScopesToViews converts domain scopes to the unified-resource wire form.
func ScopesToViews(scopes []resource.Scope) []ScopeView {
	out := make([]ScopeView, len(scopes))
	for i, sc := range scopes {
		out[i] = ScopeToView(sc)
	}
	return out
}

// ScopeFromView converts a wire-level ScopeView to its domain form.
func ScopeFromView(v ScopeView) resource.Scope {
	return resource.Scope{
		Name:        v.Name,
		Description: v.Description,
		Upstream:    v.Upstream,
	}
}

// ScopesFromViews converts a wire slice to a domain slice.
func ScopesFromViews(views []ScopeView) []resource.Scope {
	if views == nil {
		return nil
	}
	out := make([]resource.Scope, len(views))
	for i, v := range views {
		out[i] = ScopeFromView(v)
	}
	return out
}

// PolicyFromView converts a wire-level PolicyView to a domain Policy.
// Slice fields are normalized to non-nil empty slices on the wire-out
// path (PolicyToView); on the wire-in path we preserve whatever the
// caller sent so the "wipe = explicit empty value" semantics survive.
func PolicyFromView(v PolicyView) resource.Policy {
	out := resource.Policy{
		Exchange: resource.ExchangePolicy{AllowedClientIDs: v.Exchange.AllowedClientIDs},
		Runtime:  resource.RuntimePolicy{ClientIDs: v.Runtime.ClientIDs},
	}
	if v.Connect != nil {
		out.Connect = resource.ConnectPolicy{AllowedReturnURLs: v.Connect.AllowedReturnURLs}
	}
	return out
}

// PolicyToView converts a domain Policy to its wire form. The connect
// block is emitted only for resources that own connect semantics
// (Broker), per the design §6. Array fields default to non-nil empty slices so
// the wire form is always `[]` instead of JSON `null` for empty
// allowlists — matters because admin UI / tooling parses these as arrays.
func PolicyToView(p resource.Policy, includeConnect bool) PolicyView {
	allowedClients := p.Exchange.AllowedClientIDs
	if allowedClients == nil {
		allowedClients = []string{}
	}
	runtimeClients := p.Runtime.ClientIDs
	if runtimeClients == nil {
		runtimeClients = []string{}
	}
	out := PolicyView{
		Exchange: ExchangePolicyView{AllowedClientIDs: allowedClients},
		Runtime:  RuntimePolicyView{ClientIDs: runtimeClients},
	}
	if includeConnect {
		urls := p.Connect.AllowedReturnURLs
		if urls == nil {
			urls = []string{}
		}
		out.Connect = &ConnectPolicyView{AllowedReturnURLs: urls}
	}
	return out
}

// ResourceToView converts a domain Resource to the wire-level ResourceView.
func ResourceToView(r *resource.Resource) ResourceView {
	scopes := ScopesToViews(r.Scopes)
	if scopes == nil {
		scopes = []ScopeView{}
	}
	return ResourceView{
		ID:               r.ID,
		Slug:             r.Slug,
		URI:              r.URI,
		BackendKind:      string(r.BackendKind),
		BrokerProviderID: r.BrokerProviderID,
		DisplayName:      r.DisplayName,
		Scopes:           scopes,
		Policy:           PolicyToView(r.Policy, r.IsBroker()),
		CreatedAt:        r.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:        r.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// BrokerProviderToView converts a domain BrokerProvider to its wire form.
// If ConfigData is nil/empty the wire form carries an empty JSON object
// so callers always see a valid JSON value.
func BrokerProviderToView(p *resource.BrokerProvider) BrokerProviderView {
	cfg := json.RawMessage(p.ConfigData)
	if len(cfg) == 0 {
		cfg = json.RawMessage("{}")
	}
	return BrokerProviderView{
		ID:          p.ID,
		Slug:        p.Slug,
		DisplayName: p.DisplayName,
		Protocol:    string(p.Protocol),
		ConfigData:  cfg,
		CreatedAt:   p.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   p.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// ConsentGrantToView converts a domain ConsentGrant to its wire form.
func ConsentGrantToView(g *resource.ConsentGrant) ConsentGrantView {
	scopes := g.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return ConsentGrantView{
		ID:         g.ID,
		UserID:     g.UserID,
		ClientID:   g.ClientID,
		ResourceID: g.ResourceID,
		Scopes:     scopes,
		CreatedAt:  g.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:  g.UpdatedAt.UTC().Format(time.RFC3339),
		RevokedAt:  g.RevokedAt,
	}
}

// BrokerGrantToView converts a domain BrokerGrant to its wire form.
// CredentialData is dropped — see BrokerGrantView.
func BrokerGrantToView(g *resource.BrokerGrant) BrokerGrantView {
	scopes := g.ScopesGranted
	if scopes == nil {
		scopes = []string{}
	}
	return BrokerGrantView{
		ID:               g.ID,
		UserID:           g.UserID,
		BrokerProviderID: g.BrokerProviderID,
		ScopesGranted:    scopes,
		Version:          g.Version,
		EncBackend:       g.EncBackend,
		CreatedAt:        g.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:        g.UpdatedAt.UTC().Format(time.RFC3339),
		RevokedAt:        g.RevokedAt,
	}
}

// UserGrantsToView converts an input.UserGrants struct to its wire form.
// Both halves default to non-nil empty slices.
func UserGrantsToView(u input.UserGrants) UserGrantsView {
	consents := make([]ConsentGrantView, len(u.Consent))
	for i, g := range u.Consent {
		consents[i] = ConsentGrantToView(g)
	}
	brokers := make([]BrokerGrantView, len(u.Broker))
	for i, g := range u.Broker {
		brokers[i] = BrokerGrantToView(g)
	}
	return UserGrantsView{ConsentGrants: consents, BrokerGrants: brokers}
}

// IssuanceToView converts a domain Issuance to its wire form.
func IssuanceToView(i *resource.Issuance) IssuanceView {
	scopes := i.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	chain := i.AgentChain
	if chain == nil {
		chain = []string{}
	}
	return IssuanceView{
		ID:            i.ID,
		JTI:           i.JTI,
		SubjectUserID: i.SubjectUserID,
		ClientID:      i.ClientID,
		ResourceID:    i.ResourceID,
		Scopes:        scopes,
		BackendKind:   string(i.BackendKind),
		Revocable:     i.Revocable,
		IssuedAt:      i.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:     i.ExpiresAt.UTC().Format(time.RFC3339),
		RevokedAt:     i.RevokedAt,
		DPoPJKT:       i.DPoPJKT,
		AgentID:       i.AgentID,
		AgentChain:    chain,
	}
}

// IssuancesToViews converts a slice of domain issuances to wire form.
// Output is non-nil empty so callers always see a JSON array.
func IssuancesToViews(rows []*resource.Issuance) []IssuanceView {
	out := make([]IssuanceView, len(rows))
	for i, row := range rows {
		out[i] = IssuanceToView(row)
	}
	return out
}

// --- Fronting links ---

// FrontingLinkView is the wire-level shape of a fronting_links row. ScopeMap
// is emitted as a JSON object { source_scope: [target_scope, ...] } per the
// canonical 1:N wire shape.
type FrontingLinkView struct {
	SourceSlug string              `json:"source_slug"`
	TargetSlug string              `json:"target_slug"`
	ScopeMap   map[string][]string `json:"scope_map"`
	CreatedAt  string              `json:"created_at"`
	CreatedBy  string              `json:"created_by"`
}

// FrontingLinkToView converts a domain FrontingLink to its wire form. ScopeMap
// is normalized: nil → empty object on the wire so callers always parse a
// JSON object (matches the Resource scopes / agent_chain non-nil convention).
func FrontingLinkToView(l *resource.FrontingLink) FrontingLinkView {
	scopeMap := map[string][]string(l.ScopeMap)
	if scopeMap == nil {
		scopeMap = map[string][]string{}
	}
	// Normalize nil-valued slice to empty so the wire shape is stable. The
	// service layer rejects empty target lists at validation, but the
	// conversion helper stays defensive in case callers ever round-trip a
	// view through the domain.
	for k, v := range scopeMap {
		if v == nil {
			scopeMap[k] = []string{}
		}
	}
	return FrontingLinkView{
		SourceSlug: l.SourceSlug,
		TargetSlug: l.TargetSlug,
		ScopeMap:   scopeMap,
		CreatedAt:  l.CreatedAt.UTC().Format(time.RFC3339),
		CreatedBy:  l.CreatedBy,
	}
}

// FrontingLinksToViews converts a slice of domain links to wire form, always
// returning a non-nil slice so the JSON form is `[]` and not `null`.
func FrontingLinksToViews(links []*resource.FrontingLink) []FrontingLinkView {
	out := make([]FrontingLinkView, len(links))
	for i, l := range links {
		out[i] = FrontingLinkToView(l)
	}
	return out
}

// ResourceFrontingView bundles the two-direction lookup served by
// GET /admin/resources/{slug}/fronting. Each half is a non-nil slice so
// callers always see a JSON array. §Admin API.
type ResourceFrontingView struct {
	Slug      string             `json:"slug"`
	Fronts    []FrontingLinkView `json:"fronts"`     // outbound: this resource is the source
	FrontedBy []FrontingLinkView `json:"fronted_by"` // inbound: this resource is the target
}

// ResourceFrontingFromLinks splits a flat list (typically from
// FrontingService.ListForResource) into the outbound + inbound halves used
// by the per-resource fronting view.
func ResourceFrontingFromLinks(slug string, all []*resource.FrontingLink) ResourceFrontingView {
	out := ResourceFrontingView{
		Slug:      slug,
		Fronts:    []FrontingLinkView{},
		FrontedBy: []FrontingLinkView{},
	}
	for _, l := range all {
		view := FrontingLinkToView(l)
		switch {
		case l.SourceSlug == slug:
			out.Fronts = append(out.Fronts, view)
		case l.TargetSlug == slug:
			out.FrontedBy = append(out.FrontedBy, view)
		}
	}
	return out
}
