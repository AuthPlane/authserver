package output

import (
	"errors"
	"fmt"
	"testing"
)

func TestBrokerProtocolSentinels_Identity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sentinel error
	}{
		{"InvalidGrant", ErrUpstreamInvalidGrant},
		{"Unavailable", ErrUpstreamUnavailable},
		{"ScopeDowngrade", ErrUpstreamScopeDowngrade},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sentinel == nil {
				t.Fatalf("%s sentinel is nil", tc.name)
			}
			// Identity check via errors.Is — wrapping must round-trip.
			wrapped := fmt.Errorf("upstream call failed: %w", tc.sentinel)
			if !errors.Is(wrapped, tc.sentinel) {
				t.Errorf("errors.Is(wrap, %s) = false, want true", tc.name)
			}
		})
	}
}

func TestBrokerProtocolSentinels_Distinct(t *testing.T) {
	// Each sentinel must be distinct from the others — adapter callers
	// switch on identity to map to the right ConsentRequiredError shape.
	if errors.Is(ErrUpstreamInvalidGrant, ErrUpstreamUnavailable) {
		t.Error("InvalidGrant should not match Unavailable")
	}
	if errors.Is(ErrUpstreamUnavailable, ErrUpstreamScopeDowngrade) {
		t.Error("Unavailable should not match ScopeDowngrade")
	}
	if errors.Is(ErrUpstreamScopeDowngrade, ErrUpstreamInvalidGrant) {
		t.Error("ScopeDowngrade should not match InvalidGrant")
	}
}
