package main

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
)

// cachingStore is a key store that caches the current key, like the
// postgres_key decorator.
type cachingStore struct {
	invalidations int
	listed        int
}

func (s *cachingStore) LoadCurrent(context.Context) (*output.SigningKey, error)  { return nil, nil }
func (s *cachingStore) LoadPrevious(context.Context) (*output.SigningKey, error) { return nil, nil }
func (s *cachingStore) Save(context.Context, *output.SigningKey) error           { return nil }
func (s *cachingStore) CreateIfAbsent(context.Context, *output.SigningKey) error { return nil }
func (s *cachingStore) ListActive(context.Context) ([]*output.SigningKey, error) {
	s.listed++
	return []*output.SigningKey{}, nil
}
func (s *cachingStore) InvalidateCache(context.Context) error {
	s.invalidations++
	return nil
}

// SIGHUP drops the cached signing key, so the next token is signed with the
// stored current key, and rebuilds the JWKS.
func TestReloadSigningKeys_InvalidatesTheSigningKeyCache(t *testing.T) {
	store := &cachingStore{}
	obs := observability.NewNoop()
	jwksSvc := services.NewJWKSService(store, nil, "ES256", obs)

	reloadSigningKeys(context.Background(), store, jwksSvc, obs.Logger)

	if store.invalidations != 1 {
		t.Errorf("signing-key cache invalidations = %d, want 1", store.invalidations)
	}
	if store.listed != 1 {
		t.Errorf("JWKS reloads = %d, want 1", store.listed)
	}
}
