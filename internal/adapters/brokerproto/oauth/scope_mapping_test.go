package oauth

import (
	"reflect"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
)

func TestMapScopes_NilResource(t *testing.T) {
	if got := mapScopes(nil, []string{"a", "b"}); got != nil {
		t.Fatalf("mapScopes(nil, ...) = %v, want nil", got)
	}
}

func TestMapScopes_EmptyRequested(t *testing.T) {
	r := &resource.Resource{Scopes: []resource.Scope{{Name: "calendar:read", Upstream: "https://example.com/cal.ro"}}}
	if got := mapScopes(r, nil); got != nil {
		t.Fatalf("mapScopes(_, nil) = %v, want nil", got)
	}
}

func TestMapScopes_FineToUpstream(t *testing.T) {
	r := &resource.Resource{Scopes: []resource.Scope{
		{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"},
		{Name: "calendar:write", Upstream: "https://www.googleapis.com/auth/calendar.events"},
	}}
	got := mapScopes(r, []string{"calendar:read"})
	want := []string{"https://www.googleapis.com/auth/calendar.readonly"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapScopes() = %v, want %v", got, want)
	}
}

func TestMapScopes_PassthroughEmptyUpstream(t *testing.T) {
	// defensive path: a Broker scope without an Upstream override is
	// passed through verbatim. The adapter should never see Mint resources
	// (BrokerIssuer guards), but covering the path keeps Mint→Broker mistakes
	// from silently dropping scopes.
	r := &resource.Resource{Scopes: []resource.Scope{
		{Name: "tasks:read", Upstream: ""},
	}}
	got := mapScopes(r, []string{"tasks:read"})
	want := []string{"tasks:read"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapScopes() passthrough = %v, want %v", got, want)
	}
}

func TestMapScopes_DropsUnknownFineScope(t *testing.T) {
	// Defense in depth: BrokerIssuer's catalog check rejects unknown
	// scopes before Vend, but the adapter must not forward unknown scopes if
	// it ever sees them — that would let upstream over-grant relative to the
	// MCP's declared catalog.
	r := &resource.Resource{Scopes: []resource.Scope{
		{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"},
	}}
	got := mapScopes(r, []string{"calendar:read", "secrets:exfil"})
	want := []string{"https://www.googleapis.com/auth/calendar.readonly"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapScopes() with unknown scope = %v, want %v", got, want)
	}
}

func TestMapScopes_PreservesInputOrder(t *testing.T) {
	r := &resource.Resource{Scopes: []resource.Scope{
		{Name: "a", Upstream: "A"},
		{Name: "b", Upstream: "B"},
		{Name: "c", Upstream: "C"},
	}}
	got := mapScopes(r, []string{"c", "a", "b"})
	want := []string{"C", "A", "B"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapScopes() order = %v, want %v", got, want)
	}
}

func TestMapScopes_MixedMappingAndPassthrough(t *testing.T) {
	r := &resource.Resource{Scopes: []resource.Scope{
		{Name: "calendar:read", Upstream: "https://www.googleapis.com/auth/calendar.readonly"},
		{Name: "openid", Upstream: ""},
	}}
	got := mapScopes(r, []string{"openid", "calendar:read"})
	want := []string{"openid", "https://www.googleapis.com/auth/calendar.readonly"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapScopes() mixed = %v, want %v", got, want)
	}
}
