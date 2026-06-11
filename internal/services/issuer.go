package services

import (
	"context"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

// Issuer is the protocol-uniform handle TokenExchangeService uses
// to dispatch token issuance based on Resource.BackendKind. Both
// MintIssuer and BrokerIssuer satisfy this interface and
// register themselves into internal/issuer.Registry — the dispatch site
// then does registry.Lookup(kind).Issue(ctx, req), with no switch on the
// discriminator (see ADR-001 and the brokerproto.Registry exemplar).
//
// This interface is a service-to-service abstraction — the Mint and Broker
// implementations live in this package — which is why it lives in
// internal/services/ rather than internal/ports/output/. Same placement
// rationale as JWKSSigningKeyProvider and AuditRecorder.
//
// At v0.1.0-rc1 the request and response shapes are union types: every
// Issuer accepts an IssueRequest carrying the union of fields both
// branches need, and ignores the fields it does not.  may extend
// IssueRequest with Mint-only fields without breaking BrokerIssuer.
type Issuer interface {
	// Kind reports the BackendKind this Issuer handles. The Registry uses
	// this for self-registration; callers ordinarily look up by kind so
	// they never call Kind() directly.
	Kind() resource.BackendKind

	// Issue produces an access token for the request's Resource. Returns
	// the issued token plus its persisted IssuanceID (forensic
	// cross-reference).
	//
	// Error semantics that callers should expect to surface:
	//   - domain.ErrConsentRequired         — broker grant missing or
	//                                         insufficient (caller maps
	//                                         to MCP SEP-1036
	//                                         consent_url response).
	//   - domain.ErrAdapterNotRegistered    — Resource references a
	//                                         protocol with no registered
	//                                         BrokerProtocol adapter.
	//   - domain.ErrEncryptionFailed /
	//     domain.ErrEncryptorUnavailable    — encryption-side failures.
	//
	// Other errors are returned wrapped (errors.Is is preserved).
	Issue(ctx context.Context, req IssueRequest) (*IssueResponse, error)
}

// IssueRequest is the unified token-issuance request shape consumed by
// every Issuer. Mint and Broker each ignore the fields they do not need:
//
//   - Mint ignores Provider (always nil for Mint resources).
//
//   - Broker ignores DPoPJKT — broker tokens are upstream-shaped and the
//     AS does not bind them to a DPoP key.
//
//     (MintIssuer extraction) may add Mint-only fields here (e.g.
//
// Act, NotBefore, Expiry) without breaking BrokerIssuer. The
// shape is deliberately a single struct (not a generic / sum type) so the
// Issuer interface can stay parameter-free.
type IssueRequest struct {
	// Resource is the resolved unified resource — Mint or Broker — that
	// the access token is being issued for. Required.
	Resource *resource.Resource

	// Provider is the resolved BrokerProvider when Resource.IsBroker(),
	// nil for Mint resources. The caller ( TokenExchangeService)
	// resolves both via ResourceRegistry.GetWithProvider before calling
	// Issue.
	Provider *resource.BrokerProvider

	// SubjectUserID is the end user the token represents. Maps to the
	// 'sub' claim on Mint and to the user_id key on Broker grants.
	SubjectUserID string

	// ActorClientID is the OAuth client that initiated the exchange (the
	// MCP at /oauth/token). Audited but not part of the issued token's
	// 'sub'.
	ActorClientID string

	// Scopes is the requested fine-grained scope list. The caller must
	// have already validated each scope is in the resource's catalog.
	Scopes []string

	// AgentIdentity carries the agent_id and agent_chain claims attached
	// by AgentIdentityService, when the actor is an agent client. May be
	// nil for non-agent flows. Persisted on the issuances row by both
	// Issuer implementations so chain-origin forensics work uniformly
	// across Mint and Broker.
	AgentIdentity *AgentIdentityClaims

	// DPoPJKT is the SHA-256 thumbprint of the DPoP confirmation key when
	// the request is DPoP-bound. Mint records it as the 'cnf.jkt' claim;
	// BrokerIssuer ignores it (broker tokens are not AS-bound on the wire)
	// but persists it on the issuance row for audit symmetry.
	DPoPJKT string

	// --- Mint-only fields. BrokerIssuer ignores all of them. ---

	// Audience overrides the audience claim derived from Resource.URI. When
	// non-empty, MintIssuer uses it verbatim; otherwise MintIssuer derives
	// audience from Resource.URI when Resource is non-nil, falling back to
	// []string{issuer} when neither is set. The override exists so callers
	// like TokenService — which today carry the audience as a session URI
	// string and have no *resource.Resource to pass — can request a token
	// without resolving the full Resource row first.
	Audience []string

	// Act is the RFC 8693 §4.1 delegation chain claim ('act'). MintIssuer
	// copies it onto the JWT verbatim.
	Act map[string]interface{}

	// NotBefore overrides the 'nbf' claim. Zero value means "use now".
	NotBefore time.Time

	// Expiry sets the 'exp' claim and the issuance row's ExpiresAt.
	// Mandatory for Mint; caller computes the per-grant TTL.
	Expiry time.Time
}

// AgentIdentityClaims is the service-layer DTO for the agent_id /
// agent_chain pair carried on Authplane access tokens (per
// internal/services/agent_identity.go). 's BrokerIssuer cannot put
// these on the upstream wire — broker tokens are upstream-shaped — but it
// persists them on the issuance audit row so "every upstream token vended
// in this Agent's delegation history" remains a single indexed query
// against the issuances table.
//
// AgentChain is shallowest-to-deepest [root, ..., leaf], matching
// AgentIdentityService.AttachClaims and the resource.Issuance shape.
type AgentIdentityClaims struct {
	AgentID    string
	AgentChain []string
}

// IssueResponse is the unified Issuer response. TokenType is "Bearer" for
// every broker token (the AS does not DPoP-bind upstream credentials) and
// either "Bearer" or "DPoP" for Mint tokens ( wires that branch).
type IssueResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	IssuanceID  string
}
