package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryTTLBounded_Expiry(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	c := &memoryTTLBounded[*int]{
		ttl:     time.Minute,
		maxSize: 8,
		now:     func() time.Time { return clock },
		m:       make(map[string]ttlEntry[*int]),
	}
	ctx := context.Background()

	v := 1
	_ = c.Store(ctx, "k", &v)

	clock = base.Add(30 * time.Second)
	if got, _ := c.Load(ctx, "k"); got == nil || *got != 1 {
		t.Fatalf("before expiry = %v, want 1", got)
	}
	clock = base.Add(2 * time.Minute)
	if got, _ := c.Load(ctx, "k"); got != nil {
		t.Fatalf("after expiry = %v, want nil", got)
	}
}

func TestMemoryTTLBounded_EvictsNearestExpiryWhenFull(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	c := &memoryTTLBounded[*int]{
		ttl:     time.Hour,
		maxSize: 2,
		now:     func() time.Time { return clock },
		m:       make(map[string]ttlEntry[*int]),
	}
	ctx := context.Background()

	a, b, d := 1, 2, 3
	_ = c.Store(ctx, "a", &a) // expiresAt base+1h
	clock = base.Add(time.Minute)
	_ = c.Store(ctx, "b", &b) // expiresAt base+1h1m
	clock = base.Add(2 * time.Minute)
	_ = c.Store(ctx, "c", &d) // full → evict nearest expiry ("a")

	if got, _ := c.Load(ctx, "a"); got != nil {
		t.Fatalf("a should have been evicted (nearest expiry), got %v", got)
	}
	if got, _ := c.Load(ctx, "b"); got == nil || *got != 2 {
		t.Fatalf("b should remain, got %v", got)
	}
	if got, _ := c.Load(ctx, "c"); got == nil || *got != 3 {
		t.Fatalf("c should be present, got %v", got)
	}
}

func TestMemoryTTLBounded_UpdateExistingKeyDoesNotEvict(t *testing.T) {
	c := NewMemoryTTLBounded[*int](time.Hour, 2)
	ctx := context.Background()

	a, b, a2 := 1, 2, 11
	_ = c.Store(ctx, "a", &a)
	_ = c.Store(ctx, "b", &b)
	_ = c.Store(ctx, "a", &a2) // re-store existing key: at capacity but no eviction

	if got, _ := c.Load(ctx, "a"); got == nil || *got != 11 {
		t.Fatalf("a = %v, want 11", got)
	}
	if got, _ := c.Load(ctx, "b"); got == nil || *got != 2 {
		t.Fatalf("b = %v, want 2 (not evicted on same-key update)", got)
	}
}

func TestNewMemoryTTLBounded_StoreLoadInvalidate(t *testing.T) {
	c := NewMemoryTTLBounded[*string](time.Hour, 16)
	ctx := context.Background()

	if got, _ := c.Load(ctx, "k"); got != nil {
		t.Fatalf("absent = %v, want nil", got)
	}
	s := "v"
	_ = c.Store(ctx, "k", &s)
	if got, _ := c.Load(ctx, "k"); got == nil || *got != "v" {
		t.Fatalf("load = %v, want v", got)
	}
	_ = c.Invalidate(ctx, "k")
	if got, _ := c.Load(ctx, "k"); got != nil {
		t.Fatalf("after invalidate = %v, want nil", got)
	}
}
