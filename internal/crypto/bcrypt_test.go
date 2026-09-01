package crypto

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestHashBcrypt(t *testing.T) {
	hash, err := HashBcrypt("my-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if hash == "my-secret" {
		t.Fatal("hash equals plaintext")
	}
}

func TestCompareBcryptValid(t *testing.T) {
	hash, err := HashBcrypt("my-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := CompareBcrypt(hash, "my-secret"); err != nil {
		t.Errorf("compare valid: %v", err)
	}
}

func TestCompareBcryptInvalid(t *testing.T) {
	hash, err := HashBcrypt("my-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := CompareBcrypt(hash, "wrong-secret"); err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestHashBcryptDifferentResults(t *testing.T) {
	h1, _ := HashBcrypt("same")
	h2, _ := HashBcrypt("same")
	if h1 == h2 {
		t.Error("two hashes of same input should differ (different salts)")
	}
}

// The dummy hash is load-bearing for the constant-time login: if it stops
// parsing, or drifts off DefaultBcryptCost, CompareBcrypt against it returns
// early and the failure paths that rely on it get fast again — silently, with
// every other test still green. init() panics on both, so reaching this test at
// all proves the constant parses; the assertions state the contract explicitly
// and pin the cost.
func TestDummyBcryptHash_IsRealAndAtDefaultCost(t *testing.T) {
	h := DummyBcryptHash()
	if err := CompareBcryptUniform(h, "guess"); errors.Is(err, ErrUnusableHash) {
		t.Fatalf("dummy hash is not derivable: %q", h)
	}
	if cost, err := bcryptCostOf(h); err != nil || cost != DefaultBcryptCost {
		t.Fatalf("dummy hash cost = %d (err %v), want %d", cost, err, DefaultBcryptCost)
	}
}

// A caller that mistakes the dummy for a usable credential would let anyone in.
// Nothing in the tree does, and nothing should start.
func TestDummyBcryptHash_NeverMatchesAPassword(t *testing.T) {
	for _, pw := range []string{"", "password", "admin", DummyBcryptHash()} {
		if err := CompareBcrypt(DummyBcryptHash(), pw); err == nil {
			t.Errorf("dummy hash accepted %q", pw)
		}
	}
}

// A hash with a legal $2a$12$ prefix and a salt outside bcrypt's alphabet is the
// case no structural pre-check catches: bcrypt.Cost reports 12 with no error,
// and the comparison still bails in well under a microsecond. Held against a
// real comparison, that gap is the whole oracle, so CompareBcryptUniform has to
// pay it back rather than detect it.
const unusableSaltHash = "$2a$12$++++++++++++++++++++++uGRXfZQKPzHRZ1YHYQGCLmFPBw8mLLC"

// realHash derives once per test binary rather than once per test.
var realHash = sync.OnceValue(func() string {
	h, err := HashBcrypt("the-password")
	if err != nil {
		panic("hash fixture: " + err.Error())
	}
	return h
})

func TestCompareBcryptUniform_DerivesWhateverTheHashLooksLike(t *testing.T) {
	if testing.Short() {
		t.Skip("measures real bcrypt work")
	}
	real := realHash()

	// Warm-up: the first derivation in a process pays for lazy setup.
	_ = CompareBcryptUniform(real, "guess")

	tests := []struct {
		name string
		hash string
	}{
		{"real hash, wrong password", real},
		{"empty", ""},
		{"truncated", real[:20]},
		{"legal prefix, illegal salt", unusableSaltHash},
		{"not bcrypt at all", "plaintext-password"},
	}

	// Probes and median, matching the sibling assertion in
	// internal/services/user_auth_timing_test.go. A single sample per shape
	// would break the build on any CI runner that preempted one comparison or
	// paused it for GC — the band is there to catch a shape skipping derivation
	// entirely, not to measure the machine.
	const probes = 5
	var slowest, fastest time.Duration
	for _, tt := range tests {
		samples := make([]time.Duration, 0, probes)
		for i := 0; i < probes; i++ {
			start := time.Now()
			err := CompareBcryptUniform(tt.hash, "guess")
			samples = append(samples, time.Since(start))
			if err == nil {
				t.Fatalf("%s: comparison succeeded, want a denial", tt.name)
			}
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		d := samples[probes/2]
		if fastest == 0 || d < fastest {
			fastest = d
		}
		if d > slowest {
			slowest = d
		}
		t.Logf("%-30s %v", tt.name, d)
	}
	// Bare CompareBcrypt spreads these by ~300000x. Every one now derives once.
	if ratio := float64(slowest) / float64(fastest); ratio > 5 {
		t.Errorf("comparisons differ by %.1fx (%v vs %v), want at most 5x — "+
			"a hash shape is skipping derivation", ratio, slowest, fastest)
	}
}

// The unusable shapes have to be tellable apart from a wrong password, or a
// broken row looks like a user who keeps mistyping.
func TestCompareBcryptUniform_ReportsUnusableHashes(t *testing.T) {
	real := realHash()
	mismatch := CompareBcryptUniform(real, "wrong")
	if !errors.Is(mismatch, bcrypt.ErrMismatchedHashAndPassword) {
		t.Errorf("wrong password: err = %v, want a bcrypt mismatch", mismatch)
	}
	if errors.Is(mismatch, ErrUnusableHash) {
		t.Errorf("a wrong password was reported as an unusable hash: %v", mismatch)
	}
	for _, h := range []string{"", real[:20], unusableSaltHash, "plaintext-password"} {
		if err := CompareBcryptUniform(h, "guess"); !errors.Is(err, ErrUnusableHash) {
			t.Errorf("hash %q: err = %v, want ErrUnusableHash", h, err)
		}
	}
	if err := CompareBcryptUniform(real, "the-password"); err != nil {
		t.Errorf("correct password: err = %v, want nil", err)
	}
}

// The repair path compares against the dummy internally. If that result could
// escape, whoever held the dummy's plaintext would authenticate as every account
// whose stored hash happens to be broken.
func TestCompareBcryptUniform_DummyResultCannotEscape(t *testing.T) {
	for _, pw := range []string{"", "guess", DummyBcryptHash()} {
		if err := CompareBcryptUniform(unusableSaltHash, pw); err == nil {
			t.Errorf("password %q was admitted against an underivable hash", pw)
		}
	}
}

// bcryptCostOf reads the cost straight from the hash. Nothing in the package
// exposes it — CompareBcryptUniform reports derivability, not cost — so the
// assertion that the dummy sits at DefaultBcryptCost has to go to bcrypt itself.
func bcryptCostOf(hash string) (int, error) {
	return bcrypt.Cost([]byte(hash))
}
