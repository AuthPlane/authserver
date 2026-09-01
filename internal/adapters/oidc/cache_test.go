package oidc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTTLCache_LoadFetchesOnceThenServesFromCache(t *testing.T) {
	c := newTTLCache[int](time.Hour, time.Hour)
	var calls atomic.Int32
	fetch := func() (int, error) {
		calls.Add(1)
		return 42, nil
	}

	for i := 0; i < 3; i++ {
		v, err := c.Load(context.Background(), "k", fetch)
		if err != nil || v != 42 {
			t.Fatalf("load[%d] = (%d, %v), want (42, nil)", i, v, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("fetch called %d times, want 1 (cached)", got)
	}
}

func TestTTLCache_FreshExpires(t *testing.T) {
	c := newTTLCache[int](5*time.Millisecond, time.Hour)
	c.Store(context.Background(), "k", 7)

	if v, ok := c.Fresh(context.Background(), "k"); !ok || v != 7 {
		t.Fatalf("fresh right after store = (%d, %v), want (7, true)", v, ok)
	}
	time.Sleep(10 * time.Millisecond)
	if _, ok := c.Fresh(context.Background(), "k"); ok {
		t.Error("fresh after TTL should be false")
	}
	// peek still returns the expired value (for the stale fallback).
	if v, ok := c.Peek(context.Background(), "k"); !ok || v != 7 {
		t.Errorf("peek after TTL = (%d, %v), want (7, true)", v, ok)
	}
}

func TestTTLCache_LoadErrorNotCached(t *testing.T) {
	c := newTTLCache[int](time.Hour, time.Hour)
	boom := errors.New("boom")
	if _, err := c.Load(context.Background(), "k", func() (int, error) { return 0, boom }); !errors.Is(err, boom) {
		t.Fatalf("load error = %v, want boom", err)
	}
	if _, ok := c.Peek(context.Background(), "k"); ok {
		t.Error("a failed fetch must not populate the cache")
	}
}

func TestTTLCache_SingleflightCollapsesConcurrentMisses(t *testing.T) {
	c := newTTLCache[int](time.Hour, time.Hour)
	var calls atomic.Int32
	release := make(chan struct{})
	fetch := func() (int, error) {
		calls.Add(1)
		<-release // hold the flight so concurrent callers join it
		return 99, nil
	}

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if v, err := c.Load(context.Background(), "k", fetch); err != nil || v != 99 {
				t.Errorf("concurrent load = (%d, %v), want (99, nil)", v, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond) // let the goroutines reach load
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("fetch called %d times under concurrency, want 1 (singleflight)", got)
	}
}

func TestTTLCache_PeekBoundedByMaxStale(t *testing.T) {
	// TTL 5ms, stale window 10ms: Peek serves the value while within the stale
	// window after expiry, then stops once it is too stale.
	c := newTTLCache[int](5*time.Millisecond, 10*time.Millisecond)
	c.Store(context.Background(), "k", 7)

	time.Sleep(8 * time.Millisecond) // expired (>5ms) but within stale window (<15ms total)
	if v, ok := c.Peek(context.Background(), "k"); !ok || v != 7 {
		t.Fatalf("peek within stale window = (%d, %v), want (7, true)", v, ok)
	}

	time.Sleep(15 * time.Millisecond) // now well past expiry + maxStale
	if _, ok := c.Peek(context.Background(), "k"); ok {
		t.Error("peek past maxStale should return false")
	}
}
