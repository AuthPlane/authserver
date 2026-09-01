package cache

import (
	"context"
	"sync"

	"github.com/authplane/authserver/internal/ports/output"
)

// memory is a process-global, keyed in-memory cache. It holds one value per key
// and ignores ctx (no context-based partitioning). A single fixed key serves
// the single-slot case (e.g. the current signing key or the JWKS document);
// many keys serve the multi-key case (e.g. one entry per id or issuer).
type memory[T any] struct {
	mu sync.RWMutex
	m  map[string]T
}

var _ output.Cache[any] = (*memory[any])(nil)

// NewMemory returns a process-global keyed in-memory cache.
func NewMemory[T any]() output.Cache[T] {
	return &memory[T]{m: make(map[string]T)}
}

// Load returns the value stored under key, or the zero value if absent.
func (g *memory[T]) Load(_ context.Context, key string) (T, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.m[key], nil
}

// Store sets the value for key.
func (g *memory[T]) Store(_ context.Context, key string, v T) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.m[key] = v
	return nil
}

// Invalidate removes the value for key.
func (g *memory[T]) Invalidate(_ context.Context, key string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.m, key)
	return nil
}
