package output

import (
	"context"
)

// Cache is a keyed value store holding one value of type T per string key. ctx
// is threaded so an implementation can additionally partition entries by a value
// read from it (the in-memory implementations ignore ctx).
type Cache[T any] interface {
	// Load returns the value stored under key, or the zero value if absent.
	Load(ctx context.Context, key string) (T, error)
	// Store sets the value for key.
	Store(ctx context.Context, key string, v T) error
	// Invalidate removes the value for key.
	Invalidate(ctx context.Context, key string) error
}
