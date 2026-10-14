package main

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The JWKS document cache expires, so a key change nobody announced is
// published without one.
func TestJWKSCache_Expires(t *testing.T) {
	if jwksCacheTTL != 60*time.Second {
		t.Errorf("jwksCacheTTL = %v, want 60s", jwksCacheTTL)
	}
	c := newJWKSCache(50 * time.Millisecond)
	ctx := context.Background()
	if err := c.Store(ctx, "jwks", &jose.JSONWebKeySet{}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got, _ := c.Load(ctx, "jwks"); got != nil {
		t.Errorf("Load after the TTL = %v, want nothing", got)
	}
}
