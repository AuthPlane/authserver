// Package brokerproto holds the BrokerProtocol adapter registry that
// internal/services/broker_issuer.go consults at request time to dispatch
// upstream-token vending by protocol name. The registry lives outside
// internal/ports/output/ so the ports directory stays pure-interface.
//
// The package mirrors the shape of internal/signing/ and
// internal/encryption/: a small wiring helper that sits between cmd/ and
// internal/adapters/, depending only on internal/ports/output and
// internal/domain.
package brokerproto

import (
	"fmt"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/ports/output"
)

// Registry holds the set of registered BrokerProtocol adapters keyed by
// their Name(). Registration happens at startup (single-threaded, in
// cmd/authserver/serve.go); Lookup is read-only at request time. Because
// the underlying map is effectively immutable after wiring completes, the
// Registry is safe for concurrent reads without an additional mutex.
type Registry struct {
	adapters map[string]output.BrokerProtocol
}

// NewRegistry returns an empty Registry ready to receive Register calls.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]output.BrokerProtocol)}
}

// Register adds a to the registry under a.Name(). Returns an error if an
// adapter with the same name is already registered.
func (r *Registry) Register(a output.BrokerProtocol) error {
	name := a.Name()
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("broker protocol adapter %q already registered", name)
	}
	r.adapters[name] = a
	return nil
}

// Lookup returns the adapter registered under name, or
// domain.ErrAdapterNotRegistered if none is registered. The error sentinel
// is the canonical one from internal/domain so callers can switch on it
// uniformly with the rest of the domain error surface.
func (r *Registry) Lookup(name string) (output.BrokerProtocol, error) {
	a, ok := r.adapters[name]
	if !ok {
		return nil, domain.ErrAdapterNotRegistered
	}
	return a, nil
}
