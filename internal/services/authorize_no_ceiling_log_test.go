package services

import (
	"fmt"
	"sync"
	"testing"
)

// /oauth/authorize is unauthenticated, so a per-request warning is something
// any holder of a public client_id can drive at the rate limiter's ceiling.
// The diagnostic is a set of clients, not a stream of requests.
func TestShouldLogNoCeiling_OncePerClient(t *testing.T) {
	s := &AuthorizeService{}

	if !s.shouldLogNoCeiling("client-a") {
		t.Fatal("first sighting of a client must log")
	}
	for i := range 100 {
		if s.shouldLogNoCeiling("client-a") {
			t.Fatalf("repeat request %d logged again; the warning must be once per client", i)
		}
	}
	if !s.shouldLogNoCeiling("client-b") {
		t.Fatal("a different client must log: the point is naming which clients need a ceiling")
	}
}

// Open dynamic registration makes client_ids attacker-supplied, so the set
// behind the warning is a memory amplifier on the same unauthenticated path
// the log rate had to be bounded on.
//
// This asserts the size of the set, not just the return value. An earlier
// version of shouldLogNoCeiling stored the entry and *then* checked the cap,
// which silenced the log while the map grew without limit — a test that only
// watched the return value passed against it.
func TestShouldLogNoCeiling_BoundedSet(t *testing.T) {
	s := &AuthorizeService{}
	const over = maxNoCeilingClientsLogged + 5000

	logged := 0
	for i := range over {
		if s.shouldLogNoCeiling(fmt.Sprintf("client-%d", i)) {
			logged++
		}
	}

	if logged != maxNoCeilingClientsLogged {
		t.Errorf("logged %d clients, want %d", logged, maxNoCeilingClientsLogged)
	}
	if got := len(s.noCeilingLogged); got != maxNoCeilingClientsLogged {
		t.Errorf("the set holds %d entries after %d distinct clients, want it capped at %d — "+
			"silencing the log while still storing bounds nothing",
			got, over, maxNoCeilingClientsLogged)
	}
}

// The cap is checked and the entry inserted under one lock, so concurrent
// callers cannot race past it. Run with -race.
func TestShouldLogNoCeiling_ConcurrentStaysBounded(t *testing.T) {
	s := &AuthorizeService{}
	const workers, each = 16, 500

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := range workers {
		go func() {
			defer wg.Done()
			for i := range each {
				s.shouldLogNoCeiling(fmt.Sprintf("w%d-c%d", w, i))
			}
		}()
	}
	wg.Wait()

	if got := len(s.noCeilingLogged); got > maxNoCeilingClientsLogged {
		t.Errorf("the set holds %d entries after concurrent access, want at most %d",
			got, maxNoCeilingClientsLogged)
	}
}
