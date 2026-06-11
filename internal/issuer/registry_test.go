package issuer

import (
	"context"
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/services"
)

// stubIssuer is a no-op services.Issuer used to exercise the registry.
// Only Kind() is meaningful; Issue panics if invoked from a registry
// test (none of these tests reach the dispatch path).
type stubIssuer struct {
	kind resource.BackendKind
}

func (s *stubIssuer) Kind() resource.BackendKind { return s.kind }

func (s *stubIssuer) Issue(context.Context, services.IssueRequest) (*services.IssueResponse, error) {
	panic("stubIssuer.Issue must not be called from registry tests")
}

// Compile-time assertion that the stub satisfies services.Issuer.
var _ services.Issuer = (*stubIssuer)(nil)

func TestRegistry_Register_DuplicateKind(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&stubIssuer{kind: resource.BackendBroker}); err != nil {
		t.Fatalf("first Register should succeed, got %v", err)
	}
	if err := reg.Register(&stubIssuer{kind: resource.BackendBroker}); err == nil {
		t.Fatal("duplicate Register should fail, got nil error")
	}
}

func TestRegistry_Lookup_NotFound(t *testing.T) {
	reg := NewRegistry()
	got, err := reg.Lookup(resource.BackendMint)
	if got != nil {
		t.Errorf("expected nil issuer on miss, got %v", got)
	}
	if !errors.Is(err, domain.ErrAdapterNotRegistered) {
		t.Fatalf("expected domain.ErrAdapterNotRegistered, got %v", err)
	}
}

func TestRegistry_Lookup_Found(t *testing.T) {
	reg := NewRegistry()
	want := &stubIssuer{kind: resource.BackendMint}
	if err := reg.Register(want); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := reg.Lookup(resource.BackendMint)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != want {
		t.Errorf("Lookup returned %v, want %v (same pointer)", got, want)
	}
}

func TestRegistry_DistinctKinds_Coexist(t *testing.T) {
	reg := NewRegistry()
	mint := &stubIssuer{kind: resource.BackendMint}
	broker := &stubIssuer{kind: resource.BackendBroker}
	if err := reg.Register(mint); err != nil {
		t.Fatalf("Register mint: %v", err)
	}
	if err := reg.Register(broker); err != nil {
		t.Fatalf("Register broker: %v", err)
	}
	gotMint, err := reg.Lookup(resource.BackendMint)
	if err != nil || gotMint != mint {
		t.Errorf("Lookup mint = (%v, %v), want (%v, nil)", gotMint, err, mint)
	}
	gotBroker, err := reg.Lookup(resource.BackendBroker)
	if err != nil || gotBroker != broker {
		t.Errorf("Lookup broker = (%v, %v), want (%v, nil)", gotBroker, err, broker)
	}
}
