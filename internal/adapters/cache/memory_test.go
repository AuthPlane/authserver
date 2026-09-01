package cache_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/cache"
)

func TestMemory_SingleKey_StoreLoadInvalidate(t *testing.T) {
	c := cache.NewMemory[*int]()
	ctx := context.Background()

	// Absent key loads as the zero value (nil for a pointer type).
	if got, err := c.Load(ctx, "current"); err != nil || got != nil {
		t.Fatalf("Load absent = %v, %v; want nil, nil", got, err)
	}

	v := 42
	if err := c.Store(ctx, "current", &v); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := c.Load(ctx, "current")
	if err != nil || got == nil || *got != 42 {
		t.Fatalf("Load = %v, %v; want 42", got, err)
	}

	if err := c.Invalidate(ctx, "current"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if got, _ := c.Load(ctx, "current"); got != nil {
		t.Fatalf("Load after Invalidate = %v, want nil", got)
	}
}

func TestMemory_MultiKey_IsolatesByKey(t *testing.T) {
	c := cache.NewMemory[*string]()
	ctx := context.Background()

	a, b := "alice", "bob"
	if err := c.Store(ctx, "u1", &a); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(ctx, "u2", &b); err != nil {
		t.Fatal(err)
	}

	got1, _ := c.Load(ctx, "u1")
	got2, _ := c.Load(ctx, "u2")
	if got1 == nil || *got1 != "alice" {
		t.Fatalf("Load u1 = %v, want alice", got1)
	}
	if got2 == nil || *got2 != "bob" {
		t.Fatalf("Load u2 = %v, want bob", got2)
	}

	// Invalidating one key leaves the other intact.
	if err := c.Invalidate(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Load(ctx, "u1"); got != nil {
		t.Fatalf("Load u1 after invalidate = %v, want nil", got)
	}
	if got, _ := c.Load(ctx, "u2"); got == nil || *got != "bob" {
		t.Fatalf("Load u2 = %v, want bob (untouched)", got)
	}
}
