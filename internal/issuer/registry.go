// Package issuer holds the Issuer registry consulted by
// internal/services/token_exchange.go at request time to
// dispatch token issuance by Resource.BackendKind. The registry lives
// outside internal/services/ so the services package stays free of the
// startup-only registration dance; see ADR-001 and the
// internal/brokerproto.Registry exemplar (which mirrors this shape for
// BrokerProtocol adapters).
//
// Both MintIssuer and BrokerIssuer implement
// services.Issuer and self-register here in cmd/authserver/serve.go.
// TokenExchangeService then does:
//
//	iss, err := registry.Lookup(res.BackendKind)
//	if err != nil { ... }
//	resp, err := iss.Issue(ctx, req)
//
// — no switch on the discriminator (the project standard for runtime
// polymorphism, locked in audit follow-up before ).
package issuer

import (
	"fmt"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/services"
)

// Registry holds the set of registered Issuers keyed by their Kind().
// Registration happens at startup (single-threaded, in
// cmd/authserver/serve.go); Lookup is read-only at request time. Because
// the underlying map is effectively immutable after wiring completes, the
// Registry is safe for concurrent reads without an additional mutex —
// matches internal/brokerproto.Registry's concurrency contract.
type Registry struct {
	issuers map[resource.BackendKind]services.Issuer
}

// NewRegistry returns an empty Registry ready to receive Register calls.
func NewRegistry() *Registry {
	return &Registry{issuers: make(map[resource.BackendKind]services.Issuer)}
}

// Register adds iss to the registry under iss.Kind(). Returns an error if
// an Issuer for the same kind is already registered.
func (r *Registry) Register(iss services.Issuer) error {
	kind := iss.Kind()
	if _, exists := r.issuers[kind]; exists {
		return fmt.Errorf("issuer for backend_kind %q already registered", kind)
	}
	r.issuers[kind] = iss
	return nil
}

// Lookup returns the Issuer registered for kind, or
// domain.ErrAdapterNotRegistered if none is registered. Reuses the
// existing sentinel so callers can errors.Is the same value they already
// handle for brokerproto misses; if a dedicated ErrIssuerNotRegistered
// becomes useful for distinct caller behavior,  may introduce it.
func (r *Registry) Lookup(kind resource.BackendKind) (services.Issuer, error) {
	iss, ok := r.issuers[kind]
	if !ok {
		return nil, domain.ErrAdapterNotRegistered
	}
	return iss, nil
}
