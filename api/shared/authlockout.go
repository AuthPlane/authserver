package shared

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/authplane/authserver/internal/config"
)

// maxTrackedIdentities is the fallback bound on the lockout map, used when the
// configured RateLimitConfig.MaxTrackedIdentities is unset.
//
// The key contains the submitted identity, so the set of possible keys is
// chosen by whoever is posting the form, not by the server — anyone can mint
// fresh entries with made-up addresses. Past this many live entries the tracker
// makes room by evicting an entry that is NOT currently locked, rather than
// letting the map consume the process or refusing the newcomer — see
// evictOneLocked. A lockout already in force is never evicted; only when every
// tracked identity is locked is there nothing safe to drop, and only then is a
// newcomer turned away.
//
// The number is sized against MEMORY, and only memory. It is not a barrier an
// attacker has to climb, and an earlier version of this comment implied it was:
// it quoted a "3.8x margin" computed against a single source address, when the
// per-address rate limit is the only thing that number divides by. Four
// addresses, each staying politely inside the shipped 100 rps, sustain enough
// new identities to hold this map at capacity indefinitely — an entry lives for
// AuthFailWindow plus one sweep, so 250k of them needs ~379/s. The CSRF nonce
// does not raise the cost either: it is a stateless MAC good for 12 hours, so a
// POST costs one request.
//
// That is fine, because being at capacity no longer disables anything — see
// evictOneLocked. It was NOT fine while the bound refused new identities: a
// full map then meant no lockout for any account the attacker had not already
// touched.
//
// 250k is ~41 MB at roughly 163 B/entry, which a 256 MB container absorbs
// without noticing. That per-entry figure only holds because MaxIdentityLen
// bounds the key: a cap on the NUMBER of entries is not a cap on memory when
// the caller chooses the key's length — an unbounded identity would put
// 250k x 64 KB, 16 GB, inside a bound that claims 41 MB.
//
// Oldest-first eviction was considered and rejected. A locked victim's entry is
// by construction OLDER than the flood that arrives after it, so evicting by age
// would drop exactly the locked entries — turning a memory nuisance into a
// lockout bypass at one request per cleared lockout. evictOneLocked never
// touches a locked entry, which is what makes eviction safe here.
const maxTrackedIdentities = 250_000

// sweepInterval is how often dead entries are discarded.
//
// It is coupled to the cap: an entry that never locks still survives until it
// falls out of AuthFailWindow AND a sweep runs, so the live set is sized by
// AuthFailWindow+sweepInterval. Shortening the sweep shrinks the live set
// directly — at the shipped 10m window, going from 5m to 60s takes the resident
// set from 15m to 11m of an attacker's output, about a quarter off. It also
// bounds the at-capacity warning below to at most one line a minute.
const sweepInterval = 60 * time.Second

// MaxIdentityLen is the longest submitted identity the lockout will key on:
// 254 bytes, the RFC 5321 ceiling for an email address.
//
// It exists because the identity is untrusted input that becomes a map key. The
// request body cap is 64 KB and nothing between the form and here shortens the
// field, so without this the entry cap would bound the number of entries while
// each one could hold 64 KB. Callers should reject an over-length identity
// outright; this is the backstop that keeps the map's memory bound true either
// way.
const MaxIdentityLen = 254

// defaultAuthLockout and defaultAuthFailWindow mirror internal/config's
// defaults. They exist so a zero value can never mean "off" — see the guards in
// NewAuthLockout. Duplicated rather than imported to keep this type free of a
// dependency on the loader's shape.
const (
	defaultAuthLockout    = 15 * time.Minute
	defaultAuthFailWindow = 10 * time.Minute
)

// AuthLockout counts failed authentication attempts and locks the identity that
// failed them — never the transport address alone.
//
// Keying on the address alone is the defect this replaces: behind the documented
// reverse-proxy deployment every request presents the proxy's address, so a
// single lockout key covers every user. The key here is identity + address, so
// behind a proxy it degrades to identity-only (still correct — one account's
// failures cannot lock another) and, exposed directly, an attacker cannot lock a
// victim out at the victim's own address.
//
// This type is deliberately separate from RateLimiter. Throughput limiting and
// account lockout are different controls with different keys, different
// lifetimes and different scopes; sharing one middleware is what let a login
// failure take down JWKS. Keeping them apart makes that mistake unrepresentable.
//
// The tracked set is BOUNDED (see maxTrackedIdentities). The key space belongs
// to the caller, so a flood of invented identities can fill the map — but at
// the bound the tracker evicts an unlocked entry rather than refusing the
// newcomer, so a flood cannot switch the control off for accounts it has not
// touched. What it can do is reset somebody's partial failure count, and only
// by refilling the whole map to do it again. Lockouts already in force are
// never evicted. If every tracked identity is locked there is nothing safe to
// drop, and the tracker refuses and warns once per sweep.
//
// All methods are safe for concurrent use.
type AuthLockout struct {
	cfg    config.RateLimitConfig
	logger *slog.Logger
	mu     sync.Mutex
	states map[string]*failState
	// maxEntries is the live cap; a field rather than the bare constant so
	// tests can drive the boundary without allocating 250k entries.
	maxEntries int
	// refusingWarned keeps the refusal warning to one line per sweep rather than
	// one per rejected request. sweep only ever CLEARS it — a latch that both
	// warnings shared, with the sweep setting it, made the refusal line
	// unreachable: any sweep over a full map latched it, and a full map is the
	// ordinary state under the flood eviction exists to absorb.
	refusingWarned bool
}

type failState struct {
	failCount    int
	firstFailure time.Time
	lockedUntil  time.Time
}

// NewAuthLockout creates a lockout tracker. The context controls the lifetime of
// the background cleanup goroutine.
//
// The logger is injected rather than taken from slog's package default: nothing
// in this repo calls slog.SetDefault, so a package-global slog.Warn lands on the
// default handler — text, on stderr — while the application logs JSON to stdout.
// An operator scraping stdout would never see the capacity warning. A nil logger
// falls back to slog.Default() so a caller that forgets one degrades to a
// misrouted log line instead of a nil-pointer panic on a security path.
func NewAuthLockout(ctx context.Context, cfg config.RateLimitConfig, logger *slog.Logger) *AuthLockout {
	if logger == nil {
		logger = slog.Default()
	}
	// A misconfigured or zero cap must not read as "track nothing": the guard is
	// `len(states) >= maxEntries`, which at zero is true forever and would turn
	// the lockout off entirely, silently. A security control may fail open under
	// pressure; it may not fail open because a field was left unset.
	maxEntries := cfg.MaxTrackedIdentities
	if maxEntries <= 0 {
		maxEntries = maxTrackedIdentities
	}

	// The same argument applies to the two durations, and they fail worse than
	// the cap because they fail *incoherently*.
	//
	// AuthLockout at zero makes RecordFailure engage — the audit event fires and
	// the log says "auth lockout engaged" — while LockedUntil reports not-locked
	// at that same instant, because the deadline is now.Add(0). The operator
	// reads lockout events in the audit feed for a control blocking nobody.
	//
	// AuthFailWindow at zero fails the other way: now.Sub(firstFailure) > 0 holds
	// on the second failure, so the counter resets every time and no lockout ever
	// engages. Silent, with no event at all to notice it by.
	//
	// A parsed config cannot reach here at zero — Config.Validate refuses to
	// start on either, naming auth_fail_max as the switch an operator who wants
	// the lockout off actually wants. This guards the other door: a struct
	// literal from a test or an embedder that never passes through that loader,
	// where refusing to start is not a choice a library gets to make.
	if cfg.AuthLockout <= 0 {
		cfg.AuthLockout = defaultAuthLockout
	}
	if cfg.AuthFailWindow <= 0 {
		cfg.AuthFailWindow = defaultAuthFailWindow
	}

	a := &AuthLockout{
		cfg:        cfg,
		logger:     logger,
		states:     make(map[string]*failState),
		maxEntries: maxEntries,
	}
	go a.cleanupLoop(ctx)
	return a
}

// lockoutKey combines the normalized identity with the source address.
//
// Normalization matters: without it "User@Example.com" and "user@example.com"
// are two separate failure budgets for one account.
//
// The NUL separator makes the pair unambiguous, but not because identity is
// NUL-free — it is untrusted form input, and neither TrimSpace nor ToLower
// strips a NUL. It works because `ip` comes from ClientIP (the host part of
// RemoteAddr) and never contains one, so the LAST NUL in the key is always the
// separator. Anything put in the second slot later must hold that property, or
// two different pairs could share a key.
//
// The identity is truncated to MaxIdentityLen. Callers are expected to reject
// an over-length identity before they get here (see the login handler), but the
// map must not depend on that: the entry cap bounds how many keys exist, and
// only this bounds how large one can be. Truncation rather than rejection is
// deliberate — everything past the limit is unaddressable garbage, so collapsing
// it onto one key is the outcome we want.
func lockoutKey(identity, ip string) string {
	id := strings.ToLower(strings.TrimSpace(identity))
	if len(id) > MaxIdentityLen {
		id = id[:MaxIdentityLen]
	}
	return id + "\x00" + ip
}

// RecordFailure counts one failed authentication attempt.
//
// It returns the lockout deadline and whether this call is the one that engaged
// the lockout. `engaged` is true exactly once per lockout — callers emit the
// audit event off it, and a lockout that reported itself on every subsequent
// blocked request would write one event per request for its whole duration.
//
// A third outcome hides behind the same (zero, false) return: if the tracked set
// is at capacity and this identity is not already in it, the failure is NOT
// counted — it is dropped, and repeating it will never lock the identity while
// the flood lasts. A caller cannot tell that apart from "counted, still below
// the threshold", deliberately: there is nothing useful a request handler could
// do differently, and branching on it would leak the degraded state to the party
// causing it. The condition is reported to the operator on the logger instead.
func (a *AuthLockout) RecordFailure(identity, ip string) (until time.Time, engaged bool) {
	if a.cfg.AuthFailMax <= 0 {
		return time.Time{}, false
	}

	key := lockoutKey(identity, ip)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	v, ok := a.states[key]
	if !ok {
		if len(a.states) >= a.maxEntries {
			// Only at the bound — evicting below it would discard a tracked
			// identity on every insert.
			if evicted, _ := a.evictOneLocked(now); !evicted {
				// Nothing evictable: every tracked identity is locked. Refusing
				// here is the safe end of the trade — the map holds only real
				// lockouts, and admitting more would mean dropping one of them.
				if !a.refusingWarned {
					a.refusingWarned = true
					a.warnAtCapacityRefusing()
				}
				return time.Time{}, false
			}
		}
		v = &failState{}
		a.states[key] = v
	}

	// Already locked: the deadline does not extend on further attempts, or an
	// attacker could hold an account locked indefinitely by keeping up the
	// failures.
	if now.Before(v.lockedUntil) {
		return v.lockedUntil, false
	}

	// Failures outside the window do not accumulate.
	if v.failCount > 0 && now.Sub(v.firstFailure) > a.cfg.AuthFailWindow {
		v.failCount = 0
	}
	if v.failCount == 0 {
		v.firstFailure = now
	}
	v.failCount++

	if v.failCount >= a.cfg.AuthFailMax {
		v.lockedUntil = now.Add(a.cfg.AuthLockout)
		v.failCount = 0
		return v.lockedUntil, true
	}
	return time.Time{}, false
}

// LockedUntil reports whether the identity is currently locked out, and until
// when. The deadline is returned rather than a bare bool so callers can send a
// truthful Retry-After instead of a fixed guess.
func (a *AuthLockout) LockedUntil(identity, ip string) (until time.Time, locked bool) {
	if a.cfg.AuthFailMax <= 0 {
		return time.Time{}, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	v, ok := a.states[lockoutKey(identity, ip)]
	if !ok {
		return time.Time{}, false
	}
	if time.Now().Before(v.lockedUntil) {
		return v.lockedUntil, true
	}
	return time.Time{}, false
}

// Reset clears accumulated failures after a successful authentication.
//
// Without it a user who mistypes nine times and succeeds on the tenth carries
// nine failures forward and locks out on their next mistake.
//
// It drops an ACTIVE lockout too, not just accumulated failures. That is only
// safe because callers check LockedUntil before attempting authentication, so a
// locked identity never reaches a success path. A caller that validated
// credentials first would hand an attacker a way to clear their own lockout.
func (a *AuthLockout) Reset(identity, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.states, lockoutKey(identity, ip))
}

// warnAtCapacityFull reports that the map is full. This is the ordinary
// at-capacity state: eviction is working and newcomers are still tracked.
// Caller holds a.mu.
//
// Kept distinct from warnAtCapacityRefusing because the two mean different
// things to an operator: this one is a flood being absorbed, the other is the
// lockout turning someone away. One shared string made an alert on it page for
// the benign case.
func (a *AuthLockout) warnAtCapacityFull() {
	a.logger.Warn("auth lockout tracker at capacity — evicting unlocked entries to admit new identities",
		"max_entries", a.maxEntries)
}

// warnAtCapacityRefusing reports the degraded state: full AND every tracked
// identity locked, so a newcomer was turned away. Caller holds a.mu.
func (a *AuthLockout) warnAtCapacityRefusing() {
	a.logger.Warn("auth lockout tracker at capacity with every identity locked — refusing to track new identities",
		"max_entries", a.maxEntries)
}

// cleanupLoop periodically discards entries that can no longer affect a decision.
func (a *AuthLockout) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sweep(time.Now())
		}
	}
}

// evictOneLocked frees a slot by discarding one tracked identity, and reports
// whether it managed to. Callers must hold a.mu.
//
// This is what keeps a full map from switching the control off. Refusing new
// identities at the bound sounds conservative and is not: the key space belongs
// to whoever posts the form, so an attacker who keeps the map full stops every
// account they have not already touched from ever accumulating a failure. The
// bound is there to cap memory, not to decide who gets protected.
//
// A LOCKED entry is never a candidate. That is the whole difference between
// this and the oldest-first eviction rejected earlier: a locked victim's entry
// is by construction older than the flood arriving after it, so evicting by age
// would clear exactly the lockouts worth keeping, at one request each. Here the
// worst an attacker achieves is resetting somebody's partial count — and they
// must refill the entire map to do it again.
//
// Candidates are sampled rather than scanned. Go randomizes map iteration
// order, so a fixed number of entries gives an unbiased sample at constant
// cost; scanning 250k entries on every insert while holding the mutex would
// turn a memory bound into a latency one, on the login path, under contention.
// Among the sample the lowest failure count goes, so the identity closest to
// locking out survives.
//
// The budget counts every entry LOOKED AT, locked ones included. Counting only
// candidates reads as "sample until you find eight", which is not a bound at
// all: a mostly-locked map would walk most of 250k under the mutex on every new
// identity, and an all-locked one would scan it whole and still find nothing —
// exactly the latency the paragraph above says this avoids.
//
// The cost of that bound is that a sample can come up empty while evictable
// entries exist, and the tracker then refuses the newcomer. sampleSize is set
// against how expensive it is to reach a map that locked: holding N identities
// locked costs auth_fail_max requests each, repeated every auth_lockout, so 90%
// of the default cap is ~2,500 requests/second sustained forever — twenty-five
// source addresses at the shipped per-address limit, against four for the junk
// fill this eviction exists to survive. At 64 samples a 90%-locked map misses a
// victim 0.1% of the time; at 8 it was 43%. A 99%-locked map still misses about
// half the time, and at that point the map holds a quarter-million real
// lockouts and refusing is the honest answer.
func (a *AuthLockout) evictOneLocked(now time.Time) (evicted bool, visited int) {
	const sampleSize = 64

	var (
		victim string
		lowest int
		found  bool
	)
	for key, v := range a.states {
		// Counted before the locked check, not after: the budget bounds work
		// done, not candidates found. Returned so a test can assert the bound —
		// it is invisible in the result, since a bounded and an unbounded scan
		// of an all-locked map both come back empty-handed.
		if visited++; visited > sampleSize {
			break
		}
		if now.Before(v.lockedUntil) {
			continue // locked — never a candidate
		}
		if !found || v.failCount < lowest {
			victim, lowest, found = key, v.failCount, true
		}
	}
	if !found {
		return false, visited
	}
	delete(a.states, victim)
	return true, visited
}

// sweep removes every entry that is neither locked nor inside its failure
// window. Split out from cleanupLoop so it can be driven directly from tests.
func (a *AuthLockout) sweep(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for key, v := range a.states {
		if now.Before(v.lockedUntil) {
			continue // still locked
		}
		if v.failCount > 0 && now.Sub(v.firstFailure) <= a.cfg.AuthFailWindow {
			continue // failures still count toward a future lockout
		}
		delete(a.states, key)
	}

	// Re-arm, or re-report. Latching on the first rejection alone meant a
	// SUSTAINED flood — where the map never drops below the cap — produced
	// exactly one warning for the process lifetime while the lockout stayed
	// degraded indefinitely. Warning again from each sweep turns that into a
	// repeating signal an operator can alert on, still bounded to one line per
	// sweepInterval rather than one per rejected request.
	// Re-arm the refusal warning unconditionally: it reports a state the login
	// path observes, and this sweep must not decide it has already been said.
	a.refusingWarned = false

	if len(a.states) >= a.maxEntries {
		a.warnAtCapacityFull()
	}
}
