package shared

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/config"
)

// testLockoutCfg returns a config with a small threshold and short durations so
// tests do not sleep for the production 15 minutes.
func testLockoutCfg() config.RateLimitConfig {
	return config.RateLimitConfig{
		AuthFailMax:    3,
		AuthFailWindow: 10 * time.Second,
		AuthLockout:    time.Minute,
	}
}

func TestAuthLockout_LocksTheIdentityThatFailed(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	for i := 0; i < 3; i++ {
		a.RecordFailure("victim@example.com", "10.0.0.1")
	}

	if _, locked := a.LockedUntil("victim@example.com", "10.0.0.1"); !locked {
		t.Fatal("identity should be locked out after 3 failures")
	}
}

// The defect this ticket exists to fix: behind a reverse proxy every request
// carries the same source address, so an IP-keyed lockout locks everyone.
func TestAuthLockout_OneIdentityDoesNotLockAnother_SameIP(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	const sharedIP = "10.0.0.1" // the reverse proxy, as far as the server can tell
	for i := 0; i < 3; i++ {
		a.RecordFailure("attacker@example.com", sharedIP)
	}

	if _, locked := a.LockedUntil("attacker@example.com", sharedIP); !locked {
		t.Fatal("the failing identity should be locked out")
	}
	if _, locked := a.LockedUntil("victim@example.com", sharedIP); locked {
		t.Fatal("a different identity from the same address must not be locked out")
	}
}

func TestAuthLockout_IdentityIsNormalized(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	// Same account, three spellings. Without normalization each spelling would
	// get its own three-failure budget.
	a.RecordFailure("  User@Example.com  ", "10.0.0.1")
	a.RecordFailure("USER@EXAMPLE.COM", "10.0.0.1")
	a.RecordFailure("user@example.com", "10.0.0.1")

	if _, locked := a.LockedUntil("user@example.com", "10.0.0.1"); !locked {
		t.Fatal("the three spellings should share one failure budget")
	}
}

func TestAuthLockout_SuccessResetsTheCounter(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	a.RecordFailure("user@example.com", "10.0.0.1")
	a.RecordFailure("user@example.com", "10.0.0.1")
	a.Reset("user@example.com", "10.0.0.1")
	a.RecordFailure("user@example.com", "10.0.0.1")

	if _, locked := a.LockedUntil("user@example.com", "10.0.0.1"); locked {
		t.Fatal("a successful login should clear accumulated failures")
	}
}

func TestAuthLockout_WindowExpiryResetsTheCounter(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.AuthFailWindow = 20 * time.Millisecond
	a := NewAuthLockout(t.Context(), cfg, nil)

	a.RecordFailure("user@example.com", "10.0.0.1")
	a.RecordFailure("user@example.com", "10.0.0.1")

	time.Sleep(40 * time.Millisecond)

	a.RecordFailure("user@example.com", "10.0.0.1")
	if _, locked := a.LockedUntil("user@example.com", "10.0.0.1"); locked {
		t.Fatal("failures outside the window should not accumulate")
	}
}

// The audit event is emitted off `engaged`, so a second report would duplicate it.
//
// This also pins the deadline RecordFailure returns. Attempts arriving during an
// active lockout must not push it out: an attacker keeping up a failure stream
// would otherwise hold the account locked forever. Without the deadline
// assertions below, a mutation that re-stamps lockedUntil on every attempt keeps
// every test in this file green.
func TestAuthLockout_EngagedIsReportedExactlyOnce(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	var engagedCount int
	var deadline time.Time
	for i := 0; i < 6; i++ {
		until, engaged := a.RecordFailure("user@example.com", "10.0.0.1")
		if engaged {
			engagedCount++
			deadline = until
			continue
		}
		if engagedCount > 0 && !until.Equal(deadline) {
			t.Fatalf("attempt %d moved the deadline from %v to %v", i+1, deadline, until)
		}
	}

	if engagedCount != 1 {
		t.Fatalf("engaged reported %d times, want exactly 1", engagedCount)
	}
	if deadline.IsZero() {
		t.Fatal("the engaging call should return the lockout deadline, not a zero time")
	}
}

func TestAuthLockout_LockedUntilReportsRealRemainingTime(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.AuthLockout = 15 * time.Minute
	a := NewAuthLockout(t.Context(), cfg, nil)

	for i := 0; i < 3; i++ {
		a.RecordFailure("user@example.com", "10.0.0.1")
	}

	until, locked := a.LockedUntil("user@example.com", "10.0.0.1")
	if !locked {
		t.Fatal("should be locked out")
	}
	// The old middleware hardcoded Retry-After: 60 regardless of AuthLockout.
	if remaining := time.Until(until); remaining < 14*time.Minute {
		t.Fatalf("remaining lockout = %v, want close to the configured 15m", remaining)
	}
}

func TestAuthLockout_ExpiredLockoutIsNotLocked(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.AuthLockout = 20 * time.Millisecond
	a := NewAuthLockout(t.Context(), cfg, nil)

	for i := 0; i < 3; i++ {
		a.RecordFailure("user@example.com", "10.0.0.1")
	}
	time.Sleep(40 * time.Millisecond)

	if _, locked := a.LockedUntil("user@example.com", "10.0.0.1"); locked {
		t.Fatal("lockout should have expired")
	}
}

func TestAuthLockout_DisabledConfigNeverLocks(t *testing.T) {
	// AuthFailMax == 0 means the feature is not configured; it must not lock on
	// the very first failure.
	a := NewAuthLockout(t.Context(), config.RateLimitConfig{}, nil)

	if _, engaged := a.RecordFailure("user@example.com", "10.0.0.1"); engaged {
		t.Fatal("a zero AuthFailMax must disable the lockout, not trip it instantly")
	}
	// Observable behavior only. No entry is ever created, so this passes with or
	// without LockedUntil's own AuthFailMax guard — that guard is
	// defense-in-depth against a future caller and is not reachable from here.
	if _, locked := a.LockedUntil("user@example.com", "10.0.0.1"); locked {
		t.Fatal("a zero AuthFailMax must never lock")
	}
}

func TestAuthLockout_SweepEvictsEntriesPastTheirWindow(t *testing.T) {
	cfg := testLockoutCfg() // AuthFailWindow 10s
	a := NewAuthLockout(t.Context(), cfg, nil)

	// One failure — below the threshold, so this entry is never locked. A cleanup
	// predicate that only deleted entries at zero failures would leave an entry
	// like this one in the map for the process lifetime.
	a.RecordFailure("drive-by@example.com", "10.0.0.1")

	a.sweep(time.Now().Add(time.Hour))

	a.mu.Lock()
	n := len(a.states)
	a.mu.Unlock()
	if n != 0 {
		t.Fatalf("sweep left %d stale entries, want 0", n)
	}
}

func TestAuthLockout_SweepKeepsLiveEntries(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	a.RecordFailure("recent@example.com", "10.0.0.1") // inside its window
	for i := 0; i < 3; i++ {
		a.RecordFailure("locked@example.com", "10.0.0.1") // locked for a minute
	}

	a.sweep(time.Now())

	if _, locked := a.LockedUntil("locked@example.com", "10.0.0.1"); !locked {
		t.Error("sweep must not release a live lockout")
	}
	a.mu.Lock()
	n := len(a.states)
	a.mu.Unlock()
	if n != 2 {
		t.Fatalf("sweep kept %d entries, want 2", n)
	}
}

func TestAuthLockout_EntryCapStopsUnboundedGrowth(t *testing.T) {
	// Through config, not by writing a.maxEntries after construction: the
	// cleanup goroutine is already running and reads that field under the mutex.
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 4 // keep the test fast; production uses maxTrackedIdentities
	a := NewAuthLockout(t.Context(), cfg, nil)

	// Lock one real identity first, so we can prove the cap does not release it.
	for i := 0; i < 3; i++ {
		a.RecordFailure("victim@example.com", "10.0.0.1")
	}

	// Now flood with attacker-invented identities.
	for i := 0; i < 100; i++ {
		a.RecordFailure(fmt.Sprintf("junk-%d@example.com", i), "10.0.0.1")
	}

	a.mu.Lock()
	n := len(a.states)
	a.mu.Unlock()
	if n > 4 {
		t.Fatalf("map grew to %d entries past the cap of 4", n)
	}
	if _, locked := a.LockedUntil("victim@example.com", "10.0.0.1"); !locked {
		t.Error("reaching the cap must not release an identity that is already locked")
	}
}

// The cap is an operator knob because the live set scales with auth_fail_window;
// a hardcoded constant would leave anyone who widens that window silently unable
// to track new identities. Pin that the config value is the one in force.
func TestAuthLockout_CapComesFromConfig(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 5
	a := NewAuthLockout(t.Context(), cfg, nil)

	if a.maxEntries != 5 {
		t.Fatalf("maxEntries = %d, want the configured 5", a.maxEntries)
	}

	for i := 0; i < 50; i++ {
		a.RecordFailure(fmt.Sprintf("junk-%d@example.com", i), "10.0.0.1")
	}

	a.mu.Lock()
	n := len(a.states)
	a.mu.Unlock()
	if n != 5 {
		t.Fatalf("map holds %d entries, want the configured cap of 5", n)
	}
}

// A zero cap must not read as "track nothing". The admission guard is
// `len(states) >= maxEntries`, true forever at zero, which would disable the
// lockout entirely and silently — a security control failing off because a field
// was left unset.
func TestAuthLockout_UnsetCapFallsBackToTheDefault(t *testing.T) {
	for _, configured := range []int{0, -1} {
		cfg := testLockoutCfg()
		cfg.MaxTrackedIdentities = configured
		a := NewAuthLockout(t.Context(), cfg, nil)

		if a.maxEntries != maxTrackedIdentities {
			t.Errorf("MaxTrackedIdentities=%d gave maxEntries=%d, want the default %d",
				configured, a.maxEntries, maxTrackedIdentities)
		}
		// And the control still works, rather than dropping every failure.
		for i := 0; i < 3; i++ {
			a.RecordFailure("user@example.com", "10.0.0.1")
		}
		if _, locked := a.LockedUntil("user@example.com", "10.0.0.1"); !locked {
			t.Errorf("MaxTrackedIdentities=%d disabled tracking entirely", configured)
		}
	}
}

// Under a SUSTAINED flood the map never drops below the cap, so a latch that
// only re-arms on the way down reports the degradation exactly once for the
// whole process lifetime. Each sweep must re-report while still at capacity:
// that is what makes it alertable, and the sweep interval is what bounds it.
func TestAuthLockout_SweepReWarnsWhileStillAtCapacity(t *testing.T) {
	var buf bytes.Buffer
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 2
	a := NewAuthLockout(t.Context(), cfg, slog.New(slog.NewTextHandler(&buf, nil)))

	// Fill to capacity with entries a sweep will NOT reclaim: both are locked,
	// which is precisely the sustained case — the map cannot drain on its own.
	for _, id := range []string{"a@example.com", "b@example.com"} {
		for i := 0; i < 3; i++ {
			a.RecordFailure(id, "10.0.0.1")
		}
	}

	// First rejection warns once, and not once per rejected request.
	for i := 0; i < 10; i++ {
		a.RecordFailure(fmt.Sprintf("junk-%d@example.com", i), "10.0.0.1")
	}
	if got := strings.Count(buf.String(), "at capacity"); got != 1 {
		t.Fatalf("a burst of %d rejections logged %d warnings, want exactly 1", 10, got)
	}

	// The sweep speaks up too, with its OWN message: the map is full. That is a
	// different fact from "a newcomer was turned away", and it used to share one
	// string and one latch with it — which is what made the refusal line
	// unreachable once any sweep had run.
	a.sweep(time.Now())
	if got := strings.Count(buf.String(), "evicting unlocked entries"); got != 1 {
		t.Fatalf("sweep at capacity logged its own line %d times, want 1", got)
	}

	// The sweep re-arms the refusal latch, so the next rejection reports again —
	// a sustained degradation keeps signaling instead of going quiet forever.
	buf.Reset()
	a.RecordFailure("junk-more@example.com", "10.0.0.1")
	if got := strings.Count(buf.String(), "refusing"); got != 1 {
		t.Fatalf("post-sweep rejection logged %d refusal warnings, want 1 — the latch must re-arm", got)
	}

	// But still one per sweep, not one per request.
	for i := 0; i < 10; i++ {
		a.RecordFailure("junk-again@example.com", "10.0.0.1")
	}
	if got := strings.Count(buf.String(), "refusing"); got != 1 {
		t.Fatalf("a further burst logged %d refusal warnings, want the latch held at 1", got)
	}

	// And once the pressure clears, the sweep falls silent.
	buf.Reset()
	a.sweep(time.Now().Add(time.Hour))
	if got := strings.Count(buf.String(), "at capacity"); got != 0 {
		t.Fatalf("sweep warned %d times after draining the map, want silence", got)
	}
}

// The entry cap bounds how MANY keys exist; only this bounds how large one can
// be. The identity is untrusted form input under a 64KB body cap, so without
// truncation a 250k-entry bound would admit 16 GB.
func TestAuthLockout_IdentityIsTruncatedToTheMaximum(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	huge := strings.Repeat("x", 64_000) + "@example.com"
	a.RecordFailure(huge, "10.0.0.1")

	a.mu.Lock()
	defer a.mu.Unlock()
	for key := range a.states {
		// key is identity + NUL + ip
		if got := len(key); got > MaxIdentityLen+1+len("10.0.0.1") {
			t.Fatalf("map key is %d bytes, want at most %d", got, MaxIdentityLen+1+len("10.0.0.1"))
		}
	}
}

// Two over-length identities sharing a prefix collapse onto one key. That is the
// intended outcome — neither can address an account — and it is what keeps a
// flood of long strings from multiplying entries as well as bytes.
func TestAuthLockout_OverLongIdentitiesShareOneKey(t *testing.T) {
	a := NewAuthLockout(t.Context(), testLockoutCfg(), nil)

	prefix := strings.Repeat("y", MaxIdentityLen)
	a.RecordFailure(prefix+"-one@example.com", "10.0.0.1")
	a.RecordFailure(prefix+"-two@example.com", "10.0.0.1")

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.states) != 1 {
		t.Fatalf("kept %d entries for two over-length identities, want 1", len(a.states))
	}
}

// A zero duration must not read as "off". Both fail worse than a zero cap
// because they fail incoherently: AuthLockout at zero makes RecordFailure
// report engaged — firing the audit event — while LockedUntil says not-locked
// at the same instant, and AuthFailWindow at zero resets the counter on every
// failure so no lockout ever engages at all.
func TestAuthLockout_ZeroDurationsFallBackToDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.RateLimitConfig
	}{
		{"zero lockout", config.RateLimitConfig{AuthFailMax: 3, AuthFailWindow: time.Minute}},
		{"zero window", config.RateLimitConfig{AuthFailMax: 3, AuthLockout: time.Minute}},
		{"both zero", config.RateLimitConfig{AuthFailMax: 3}},
		{"negative", config.RateLimitConfig{AuthFailMax: 3, AuthFailWindow: -1, AuthLockout: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAuthLockout(t.Context(), tc.cfg, nil)

			var engaged bool
			for i := 0; i < 3; i++ {
				_, engaged = a.RecordFailure("victim@example.com", "10.0.0.1")
			}
			if !engaged {
				t.Fatal("three failures did not engage the lockout")
			}
			// The incoherence the guard exists to prevent: engaged reported, but
			// the identity walks straight back in.
			if _, locked := a.LockedUntil("victim@example.com", "10.0.0.1"); !locked {
				t.Error("lockout engaged but the identity is not locked — a zero duration read as off")
			}
		})
	}
}

// The point of evicting instead of refusing: a full map must not switch the
// control off. Before this, an attacker who kept the map at capacity stopped
// every account they had not already touched from accumulating a single
// failure — brute force with no lockout at all, at roughly four source
// addresses under the shipped rate limit.
func TestAuthLockout_AtCapacityANewIdentityIsStillProtected(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 8
	a := NewAuthLockout(t.Context(), cfg, nil)

	// Fill past the cap with junk, the way a flood of invented addresses would.
	for i := 0; i < 200; i++ {
		a.RecordFailure(fmt.Sprintf("junk-%d@example.com", i), "10.0.0.1")
	}

	// A real account now shows up and fails its way to the threshold.
	for i := 0; i < 3; i++ {
		a.RecordFailure("victim@example.com", "10.0.0.1")
	}

	if _, locked := a.LockedUntil("victim@example.com", "10.0.0.1"); !locked {
		t.Fatal("a full map left a new identity unprotected — the flood switched the lockout off")
	}
}

// Eviction must never release a lockout. Oldest-first would have done exactly
// that: a locked victim's entry is older than the flood that follows it, so it
// would be the first candidate.
func TestAuthLockout_EvictionNeverReleasesALockedIdentity(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 4
	a := NewAuthLockout(t.Context(), cfg, nil)

	// Lock two identities first, so they are the OLDEST entries in the map.
	for _, id := range []string{"locked-a@example.com", "locked-b@example.com"} {
		for i := 0; i < 3; i++ {
			a.RecordFailure(id, "10.0.0.1")
		}
	}

	// Then flood well past the cap.
	for i := 0; i < 500; i++ {
		a.RecordFailure(fmt.Sprintf("junk-%d@example.com", i), "10.0.0.1")
	}

	for _, id := range []string{"locked-a@example.com", "locked-b@example.com"} {
		if _, locked := a.LockedUntil(id, "10.0.0.1"); !locked {
			t.Errorf("%s was released by eviction — a flood must not clear a lockout", id)
		}
	}
}

// When every tracked identity is locked there is nothing safe to evict, and
// refusing is the correct end of the trade: the map holds only real lockouts.
func TestAuthLockout_RefusesWhenEveryEntryIsLocked(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 3
	a := NewAuthLockout(t.Context(), cfg, nil)

	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("locked-%d@example.com", i)
		for j := 0; j < 3; j++ {
			a.RecordFailure(id, "10.0.0.1")
		}
	}

	// Every slot is a live lockout, so a newcomer cannot be admitted.
	for i := 0; i < 3; i++ {
		a.RecordFailure("newcomer@example.com", "10.0.0.1")
	}
	if _, locked := a.LockedUntil("newcomer@example.com", "10.0.0.1"); locked {
		t.Fatal("admitted an identity by evicting a locked one")
	}

	a.mu.Lock()
	n := len(a.states)
	a.mu.Unlock()
	if n != 3 {
		t.Fatalf("map holds %d entries, want the cap of 3", n)
	}
}

// The eviction budget must bound work done, not candidates found. Counting only
// unlocked entries turns "sample 64" into "scan until you find 64", which on a
// mostly-locked map walks most of the table under the mutex, on the login path.
//
// The map here is entirely locked, so there is no candidate at all: a bounded
// scan visits at most sampleSize entries and gives up; an unbounded one visits
// every entry. The instrumentation counts iterations directly, because the
// difference is invisible in the result — both return false.
func TestAuthLockout_EvictionScanIsBoundedWhenEverythingIsLocked(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 5000
	a := NewAuthLockout(t.Context(), cfg, nil)

	// Fill the map with locked identities only.
	for i := 0; i < 5000; i++ {
		id := fmt.Sprintf("locked-%d@example.com", i)
		for j := 0; j < 3; j++ {
			a.RecordFailure(id, "10.0.0.1")
		}
	}
	a.mu.Lock()
	total := len(a.states)
	a.mu.Unlock()
	if total < 4000 {
		t.Fatalf("setup produced only %d entries, want the map full", total)
	}

	a.mu.Lock()
	_, visited := a.evictOneLocked(time.Now())
	a.mu.Unlock()

	// Bounded above: 64 samples plus the iteration that trips the budget.
	if visited > 65 {
		t.Errorf("eviction visited %d of %d entries — the budget counts candidates, not work", visited, total)
	}
	// And bounded below, which is the half that catches the real bug. If the
	// budget is counted after the locked check, an all-locked map increments it
	// zero times while walking every entry — the counter reports 0 and an
	// upper-bound assertion alone waves it through.
	if visited == 0 {
		t.Errorf("eviction reported 0 visits over %d entries — the counter is not counting the walk", total)
	}
}

// Eviction happens only at the bound. Running it on every insert would discard
// a tracked identity each time a new one appears, which is worse than the cap
// it is meant to enforce.
func TestAuthLockout_DoesNotEvictBelowTheBound(t *testing.T) {
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 100
	a := NewAuthLockout(t.Context(), cfg, nil)

	for i := 0; i < 40; i++ {
		a.RecordFailure(fmt.Sprintf("user-%d@example.com", i), "10.0.0.1")
	}

	a.mu.Lock()
	n := len(a.states)
	a.mu.Unlock()
	if n != 40 {
		t.Fatalf("map holds %d entries after 40 distinct identities, want 40 — something evicted below the bound", n)
	}
}

// The threat model tells operators to alert on the refusal warning, so it has
// to be reachable. It was not: both warnings shared one latch and the sweep set
// it, so any sweep over a full map — the ordinary state under the flood
// eviction exists to absorb — silenced the refusal line for good, while the
// sweep kept claiming entries were being admitted.
func TestAuthLockout_RefusalWarningSurvivesASweep(t *testing.T) {
	var logs bytes.Buffer
	cfg := testLockoutCfg()
	cfg.MaxTrackedIdentities = 2
	a := NewAuthLockout(t.Context(), cfg, slog.New(slog.NewTextHandler(&logs, nil)))

	// Fill the map with locked identities: nothing is evictable.
	for _, id := range []string{"a@example.com", "b@example.com"} {
		for i := 0; i < 3; i++ {
			a.RecordFailure(id, "10.0.0.1")
		}
	}

	a.sweep(time.Now())

	logs.Reset()
	a.RecordFailure("newcomer@example.com", "10.0.0.1")
	if !strings.Contains(logs.String(), "refusing") {
		t.Fatalf("a refused identity after a sweep logged nothing:\n%q", logs.String())
	}

	// Still at most one line per sweep, not one per rejected request.
	logs.Reset()
	for i := 0; i < 10; i++ {
		a.RecordFailure("newcomer@example.com", "10.0.0.1")
	}
	if n := strings.Count(logs.String(), "refusing"); n != 0 {
		t.Errorf("10 further refusals logged %d times, want 0 until the next sweep", n)
	}
}
