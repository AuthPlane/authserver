package static

import (
	"context"
	"slices"
	"testing"
)

func TestEnabledGrantsProvider_GetReturnsClone(t *testing.T) {
	seed := []string{"authorization_code", "refresh_token"}
	p := NewEnabledGrantsProvider(seed)

	got, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !slices.Equal(got, seed) {
		t.Fatalf("Get: got %v, want %v", got, seed)
	}

	// Mutating the returned slice must not affect the provider's backing array.
	got[0] = "mutated"
	again, _ := p.Get(context.Background())
	if again[0] != "authorization_code" {
		t.Errorf("returned slice aliases the provider's array: %v", again)
	}
}
