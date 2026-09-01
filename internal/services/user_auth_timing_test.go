package services

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// fakeUserStore serves a fixed set of accounts by email. Only GetByEmail is
// implemented; anything else on the port panics on a nil embedded interface,
// which is the intent — these tests exercise one method.
type fakeUserStore struct {
	output.UserStore
	byEmail map[string]*user.User
}

func (f fakeUserStore) GetByEmail(_ context.Context, email string) (*user.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

const (
	emailMissing    = "missing@example.com"
	emailDisabled   = "disabled@example.com"
	emailFederated  = "federated@example.com"
	emailActive     = "active@example.com"
	emailNoPassword = "nopassword@example.com"
	probePassword   = "not-the-right-password"
	fixturePassword = "the-real-password"
)

// fixtureHash is derived once per test binary, not once per fixture. Every test
// in this file builds a fixture, and a cost-12 derivation on each call spent
// roughly two seconds of the package's runtime re-deriving a constant — real
// money on a suite that also runs under -race.
var fixtureHash = sync.OnceValue(func() string {
	h, err := crypto.HashBcrypt(fixturePassword)
	if err != nil {
		// Only reachable if bcrypt itself is broken, in which case every test
		// in this file is meaningless.
		panic("hash fixture password: " + err.Error())
	}
	return h
})

// newAuthTimingFixture builds one account per failure path, all sharing a real
// cost-12 hash so the only thing that can differ between paths is the code under
// test.
func newAuthTimingFixture(t *testing.T) (*UserAuthService, *captureAuditRecorder) {
	t.Helper()

	hash := fixtureHash()

	store := fakeUserStore{byEmail: map[string]*user.User{
		emailDisabled: {
			ID: "u-disabled", Email: emailDisabled, PasswordHash: hash,
			Status: user.StatusDisabled, Provider: user.ProviderLocal,
		},
		emailFederated: {
			ID: "u-federated", Email: emailFederated,
			Status: user.StatusActive, Provider: user.ProviderOIDC,
		},
		emailActive: {
			ID: "u-active", Email: emailActive, PasswordHash: hash,
			Status: user.StatusActive, Provider: user.ProviderLocal,
		},
		// An active local account whose stored hash is missing. Reachable
		// through data repair or a partial import, and it is the one shape that
		// would otherwise slip past the fix: the real hash gets selected, then
		// bcrypt rejects it before deriving anything.
		emailNoPassword: {
			ID: "u-nopassword", Email: emailNoPassword,
			Status: user.StatusActive, Provider: user.ProviderLocal,
		},
	}}

	rec := &captureAuditRecorder{}
	return NewUserAuthService(store, observability.NewNoop(), rec), rec
}

// TestAuthenticate_FailurePathsCostTheSame is the regression test for the login
// timing oracle: three of the four failure paths used to return before any
// bcrypt comparison, so an unknown address answered in ~0.4ms where a wrong
// password took ~190ms. The response never differed; the latency did, by ~470x,
// which is a directory-disclosure primitive on an identity provider.
//
// The band below is loose on purpose. Every path now runs one cost-12
// comparison, so the medians land within a few percent of each other on an idle
// machine; 5x leaves room for a loaded CI runner without coming anywhere near
// the two orders of magnitude the defect produced.
func TestAuthenticate_FailurePathsCostTheSame(t *testing.T) {
	if testing.Short() {
		t.Skip("measures real bcrypt work; several seconds")
	}

	svc, _ := newAuthTimingFixture(t)
	ctx := context.Background()

	paths := []struct {
		name  string
		email string
	}{
		{"unknown address", emailMissing},
		{"disabled account", emailDisabled},
		{"federated account", emailFederated},
		{"active account, wrong password", emailActive},
		{"active account, no stored hash", emailNoPassword},
	}

	// One discarded round trip: the first bcrypt call in a process pays for page
	// faults and lazy initialisation that nothing after it does.
	if _, err := svc.Authenticate(ctx, emailActive, probePassword); err == nil {
		t.Fatal("warm-up probe should have been denied")
	}

	const probes = 5
	medians := make(map[string]time.Duration, len(paths))
	for _, p := range paths {
		samples := make([]time.Duration, 0, probes)
		for i := 0; i < probes; i++ {
			start := time.Now()
			_, err := svc.Authenticate(ctx, p.email, probePassword)
			samples = append(samples, time.Since(start))
			if err != domain.ErrInvalidCredentials {
				t.Fatalf("%s: err = %v, want ErrInvalidCredentials", p.name, err)
			}
		}
		// Median rather than mean: a GC pause during one probe should not move
		// the number the assertion reads.
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		medians[p.name] = samples[probes/2]
	}

	slowest, fastest := paths[0].name, paths[0].name
	for name, d := range medians {
		if d > medians[slowest] {
			slowest = name
		}
		if d < medians[fastest] {
			fastest = name
		}
	}

	const maxRatio = 5.0
	ratio := float64(medians[slowest]) / float64(medians[fastest])
	if ratio > maxRatio {
		for _, p := range paths {
			t.Logf("%-32s %v", p.name, medians[p.name])
		}
		t.Errorf("failure paths differ by %.1fx (%s %v vs %s %v), want at most %.0fx — "+
			"a path is returning before its bcrypt comparison",
			ratio, slowest, medians[slowest], fastest, medians[fastest], maxRatio)
	}
}

// Every denial has to leave a row in the audit store, not just a metric. The
// unknown-address probe is the one an enumeration campaign generates, and it was
// the only one recording nothing durable.
func TestAuthenticate_EveryDenialIsAudited(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		wantReason string
		wantActor  string
	}{
		{"unknown address", emailMissing, "reason=user_not_found", ""},
		{"disabled account", emailDisabled, "reason=user_disabled", "u-disabled"},
		{"federated account", emailFederated, "reason=user_not_local", "u-federated"},
		{"wrong password", emailActive, "reason=invalid_credentials", "u-active"},
		{"no stored hash", emailNoPassword, "reason=unusable_stored_hash", "u-nopassword"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, rec := newAuthTimingFixture(t)

			if _, err := svc.Authenticate(context.Background(), tt.email, probePassword); err != domain.ErrInvalidCredentials {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}

			ev, ok := findAction(rec.take(), audit.ActionUserLoginFailed)
			if !ok {
				t.Fatal("the denial recorded no user.login_failed event")
			}
			if !strings.Contains(ev.Detail, tt.wantReason) {
				t.Errorf("detail = %q, want it to contain %q", ev.Detail, tt.wantReason)
			}
			if !strings.HasPrefix(ev.Detail, tt.wantReason+" ") {
				t.Errorf("detail = %q, want it to lead with %q", ev.Detail, tt.wantReason)
			}
			if !strings.Contains(ev.Detail, `email="`+tt.email+`"`) {
				t.Errorf("detail = %q, want it to name the submitted address, quoted", ev.Detail)
			}
			// The address that matched no account has no actor to name; the
			// others do, and a trail that omits the user id makes a
			// per-account failure count impossible to build.
			if ev.ActorID != tt.wantActor {
				t.Errorf("actor_id = %q, want %q", ev.ActorID, tt.wantActor)
			}
		})
	}
}

// The fix must not have cost the success path its outcome.
func TestAuthenticate_CorrectPasswordStillSucceeds(t *testing.T) {
	svc, rec := newAuthTimingFixture(t)

	u, err := svc.Authenticate(context.Background(), emailActive, fixturePassword)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.ID != "u-active" {
		t.Errorf("user id = %q, want u-active", u.ID)
	}
	if _, ok := findAction(rec.take(), audit.ActionUserLogin); !ok {
		t.Error("a successful login recorded no user.login event")
	}
}

// The dummy hash is compared against on every denying path, so what happens to
// its result matters as much as the timing it buys. An active local account
// with no derivable stored hash is the one shape where the dummy could have
// been the thing compared while the outcome was still undecided — if its result
// were consulted there, whoever held its discarded plaintext would be logged in
// as that account. Authenticate settles the denial before comparing, so no
// submitted password can reach a success.
func TestAuthenticate_UnusableStoredHashNeverAdmits(t *testing.T) {
	svc, _ := newAuthTimingFixture(t)

	// The dummy's own hash string included: it is a public constant, and a
	// caller passing it back is the cheapest shape the mistake would take.
	for _, pw := range []string{"", "the-real-password", "admin", crypto.DummyBcryptHash()} {
		if _, err := svc.Authenticate(context.Background(), emailNoPassword, pw); err != domain.ErrInvalidCredentials {
			t.Errorf("password %q: err = %v, want ErrInvalidCredentials", pw, err)
		}
	}
}

// Detail is contracted as greppable key=value and the address is raw form input.
// With the address first and unquoted, a submitted value carrying a space and
// its own "reason=" produced a row whose first reason= the attacker chose — so a
// probe against a nonexistent address could file itself as a wrong password.
// The sibling auth.locked_out event was fixed the same way; see
// TestRecordLockout_DetailResistsInjectionViaTheAddress.
func TestAuthenticate_AuditDetailResistsInjectionViaTheAddress(t *testing.T) {
	svc, rec := newAuthTimingFixture(t)

	forged := `attacker@example.com reason=invalid_credentials`
	if _, err := svc.Authenticate(context.Background(), forged, probePassword); err != domain.ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}

	ev, ok := findAction(rec.take(), audit.ActionUserLoginFailed)
	if !ok {
		t.Fatal("the denial recorded no user.login_failed event")
	}
	if !strings.HasPrefix(ev.Detail, "reason=user_not_found ") {
		t.Errorf("detail = %q, want the real reason first", ev.Detail)
	}
	// Quoting is what stops the borrowed delimiter: the whole address, spaces
	// and all, has to sit inside one quoted value.
	if !strings.Contains(ev.Detail, `email="`+forged+`"`) {
		t.Errorf("detail = %q, want the address quoted whole", ev.Detail)
	}
}
