package resource

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/authplane/authserver/internal/domain"
)

// BackendKind discriminates how the AS produces tokens for a Resource.
// Mint resources are signed locally by the AS; Broker resources are vended
// by a BrokerProtocol adapter against an upstream provider.
type BackendKind string

const (
	BackendMint   BackendKind = "mint"
	BackendBroker BackendKind = "broker"
)

// Resource is the unified authorization target. A token is issued for exactly
// one Resource (single audience in v4.1). Mint Resources have empty
// BrokerProviderID; Broker Resources reference a BrokerProvider row that
// owns the upstream wire-protocol details. See the architecture doc
type Resource struct {
	ID               string
	Slug             string
	DisplayName      string
	URI              string
	BackendKind      BackendKind
	BrokerProviderID string
	Scopes           []Scope
	Policy           Policy
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Policy carries the per-Resource operator policy applied at exchange and
// connect time. Sub-policies default to their zero values; see each field
// for default semantics (Exchange: permissive, Runtime: strict, Connect:
// broker-only).
type Policy struct {
	Exchange ExchangePolicy
	Runtime  RuntimePolicy
	Connect  ConnectPolicy
}

// ExchangePolicy gates which clients may act as the actor at /oauth/token
// when exchanging for this Resource. Empty AllowedClientIDs means any client
// is permitted.
type ExchangePolicy struct {
	AllowedClientIDs []string
}

// RuntimePolicy lists the OAuth client_ids authorized to act AS this
// Resource at runtime. Used by the broker dispatch agent-attestation gate
// (token_exchange.go) to identify which Resource an authenticated client
// represents on the wire.
//
// Empty ClientIDs is STRICT: no client may act as this Resource (default-
// deny). This is the opposite default of ExchangePolicy.AllowedClientIDs
// because the runtime gate has no other layer to fall back on — permissive
// empty would defeat the gate..
//
// Multi-entry models multi-tier deployments (prod/canary/dev gateways) where
// each tier authenticates with its own credentials but maps to the same
// Resource record.
type RuntimePolicy struct {
	ClientIDs []string
}

// ConnectPolicy validates the return_url supplied to broker connect flows.
// Match semantics are exact strings or loopback-port wildcards; concrete
// matching lives in the connect handler.
type ConnectPolicy struct {
	AllowedReturnURLs []string
}

// IsMint reports whether this Resource is signed locally by the AS.
func (r *Resource) IsMint() bool { return r.BackendKind == BackendMint }

// IsBroker reports whether this Resource is vended via a broker adapter.
func (r *Resource) IsBroker() bool { return r.BackendKind == BackendBroker }

// slugPattern mirrors the SQL CHECK on resources.slug
// (the resource-unification design).
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Validate checks that the Resource is well-formed: slug shape, broker_provider
// consistency, optional URI shape, and scope-name well-formedness. Mirrors the
// SQL CHECK constraint on the resources table plus the audit-finding hardening
// (B13: URI shape; B14: scope name uniqueness + non-empty).
func (r *Resource) Validate() error {
	if r.Slug == "" {
		return domain.ErrInvalidSlug
	}
	if !slugPattern.MatchString(r.Slug) {
		return domain.ErrInvalidSlug
	}
	switch r.BackendKind {
	case BackendMint:
		if r.BrokerProviderID != "" {
			return fmt.Errorf("mint resource must not reference a broker provider")
		}
	case BackendBroker:
		if r.BrokerProviderID == "" {
			return fmt.Errorf("broker resource must reference a broker provider")
		}
	default:
		return fmt.Errorf("backend_kind must be mint or broker, got %q", r.BackendKind)
	}
	if err := validateResourceURI(r.URI); err != nil {
		return err
	}
	if err := validateResourceScopes(r.Scopes); err != nil {
		return err
	}
	return nil
}

// validateResourceURI parses URI when set. Empty URI is allowed (Resource.URI
// is optional — the slug is the canonical identifier). When non-empty it must
// be an absolute URL with an http/https scheme; this catches operator typos
// before they break Protected Resource Metadata downstream.
//
// Audit finding B13. Previously, callers that left URI empty continue to pass.
func validateResourceURI(uri string) error {
	if uri == "" {
		return nil
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("uri must be a valid URL: %w", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("uri must be absolute (include scheme + host)")
	}
	switch u.Scheme {
	case "http", "https":
		// ok
	default:
		return fmt.Errorf("uri scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("uri must include a host")
	}
	return nil
}

// validateResourceScopes ensures each scope has a non-empty name and that
// names are unique within a single Resource. Mint exchange and Broker upstream-
// mapping behavior is undefined on duplicate names; reject up front.
//
// Audit finding B14.
func validateResourceScopes(scopes []Scope) error {
	if len(scopes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(scopes))
	for i, s := range scopes {
		if s.Name == "" {
			return fmt.Errorf("scopes[%d].name must not be empty", i)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("scopes[%d].name %q duplicates an earlier entry", i, s.Name)
		}
		seen[s.Name] = struct{}{}
	}
	return nil
}

// NormalizeSlug lowercases s and validates it against the slug regex. On
// rejection it returns ("", ErrInvalidSlug). Callers persist the returned
// canonical form, never the raw input.
func NormalizeSlug(s string) (string, error) {
	canonical := strings.ToLower(s)
	if !slugPattern.MatchString(canonical) {
		return "", domain.ErrInvalidSlug
	}
	return canonical, nil
}
