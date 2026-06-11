package brokerproto

import (
	"context"
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// stubBrokerProtocol is a no-op BrokerProtocol used to exercise the
// registry. Only Name() is meaningful; the other methods are present to
// satisfy the interface and panic if accidentally invoked from a test.
type stubBrokerProtocol struct {
	name string
}

func (s *stubBrokerProtocol) Name() string { return s.name }

func (s *stubBrokerProtocol) BuildConnectURL(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	string, string, string, []string,
) (string, *resource.ConnectPendingState, error) {
	panic("stubBrokerProtocol.BuildConnectURL must not be called")
}

func (s *stubBrokerProtocol) HandleCallback(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	string, string, *resource.ConnectPendingState,
) ([]byte, []string, error) {
	panic("stubBrokerProtocol.HandleCallback must not be called")
}

func (s *stubBrokerProtocol) Vend(
	context.Context, *resource.BrokerProvider, *resource.Resource,
	[]byte, []string,
) (string, int, []byte, error) {
	panic("stubBrokerProtocol.Vend must not be called")
}

func (s *stubBrokerProtocol) Revoke(context.Context, *resource.BrokerProvider, []byte) error {
	panic("stubBrokerProtocol.Revoke must not be called")
}

// Compile-time assertion that the stub satisfies BrokerProtocol.
var _ output.BrokerProtocol = (*stubBrokerProtocol)(nil)

func TestRegistry_Register_DuplicateName(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&stubBrokerProtocol{name: "oauth"}); err != nil {
		t.Fatalf("first Register should succeed, got %v", err)
	}
	if err := reg.Register(&stubBrokerProtocol{name: "oauth"}); err == nil {
		t.Fatal("duplicate Register should fail, got nil error")
	}
}

func TestRegistry_Lookup_NotFound(t *testing.T) {
	reg := NewRegistry()
	got, err := reg.Lookup("missing")
	if got != nil {
		t.Errorf("expected nil adapter on miss, got %v", got)
	}
	if !errors.Is(err, domain.ErrAdapterNotRegistered) {
		t.Fatalf("expected domain.ErrAdapterNotRegistered, got %v", err)
	}
}

func TestRegistry_Lookup_Found(t *testing.T) {
	reg := NewRegistry()
	want := &stubBrokerProtocol{name: "api_key"}
	if err := reg.Register(want); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := reg.Lookup("api_key")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != want {
		t.Errorf("Lookup returned %v, want %v (same pointer)", got, want)
	}
}
