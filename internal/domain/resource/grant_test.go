package resource_test

import (
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

func TestConsentGrant_CoversScopes(t *testing.T) {
	g := resource.ConsentGrant{
		Scopes: []string{"read", "write"},
	}

	t.Run("empty requested is covered", func(t *testing.T) {
		if !g.CoversScopes(nil) {
			t.Error("nil requested should be covered")
		}
		if !g.CoversScopes([]string{}) {
			t.Error("empty requested should be covered")
		}
	})

	t.Run("subset is covered", func(t *testing.T) {
		if !g.CoversScopes([]string{"read"}) {
			t.Error("single subset scope should be covered")
		}
		if !g.CoversScopes([]string{"read", "write"}) {
			t.Error("full set should be covered")
		}
	})

	t.Run("superset is not covered", func(t *testing.T) {
		if g.CoversScopes([]string{"read", "write", "admin"}) {
			t.Error("superset scope should not be covered")
		}
	})

	t.Run("disjoint is not covered", func(t *testing.T) {
		if g.CoversScopes([]string{"admin"}) {
			t.Error("disjoint scope should not be covered")
		}
	})

	t.Run("empty granted does not cover any scope", func(t *testing.T) {
		empty := resource.ConsentGrant{Scopes: nil}
		if empty.CoversScopes([]string{"read"}) {
			t.Error("empty granted should not cover non-empty request")
		}
		if !empty.CoversScopes(nil) {
			t.Error("empty granted should still cover empty request")
		}
	})
}

func TestConsentGrant_IsRevoked_RevokedAtNil(t *testing.T) {
	g := resource.ConsentGrant{}
	if g.IsRevoked() {
		t.Error("nil RevokedAt should mean active")
	}
	now := time.Now()
	g.RevokedAt = &now
	if !g.IsRevoked() {
		t.Error("non-nil RevokedAt should mean revoked")
	}
}

func TestBrokerGrant_IsRevoked(t *testing.T) {
	g := resource.BrokerGrant{}
	if g.IsRevoked() {
		t.Error("nil RevokedAt should mean active")
	}
	now := time.Now()
	g.RevokedAt = &now
	if !g.IsRevoked() {
		t.Error("non-nil RevokedAt should mean revoked")
	}
}
