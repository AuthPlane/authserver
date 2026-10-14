package testdata

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

// RunRevocationStoreTests runs the shared RevocationStore purge contract.
//
// Purge must remove only rows whose token can no longer verify. A purge that
// removes rows earlier re-enables revoked tokens (revoked_jtis) and detaches
// live access tokens from their family so a later family revocation misses
// them (access_token_jtis). Both failures are silent: nothing errors, the
// token just introspects active again. The factory returns the stores needed
// to seed the token family that access_token_jtis.family_id references.
func RunRevocationStoreTests(t *testing.T, newStores func(*testing.T) (output.RevocationStore, output.TokenStore, output.ClientStore, output.UserStore)) {
	t.Helper()

	setup := func(t *testing.T) (output.RevocationStore, string) {
		t.Helper()
		rev, tokens, clients, users := newStores(t)
		ctx := context.Background()
		if err := clients.Create(ctx, newTestClient("client-1")); err != nil {
			t.Fatalf("seed client-1: %v", err)
		}
		if err := users.Create(ctx, newTestUser("user-1", "user-1@test.com")); err != nil {
			t.Fatalf("seed user-1: %v", err)
		}
		fam := newTestFamily("fam-rev")
		if err := tokens.CreateFamily(ctx, fam); err != nil {
			t.Fatalf("create family: %v", err)
		}
		return rev, fam.ID
	}

	// The port has no tracking-row read, so a family revocation after the
	// purge observes which tracking rows survived: it denylists exactly the
	// family's tracked JTIs.
	t.Run("PurgeExpired_KeepsLiveRevocationsAndTracking", func(t *testing.T) {
		rev, famID := setup(t)
		ctx := context.Background()
		now := time.Now().UTC()

		if err := rev.TrackJTI(ctx, "jti-live", famID, now.Add(time.Hour)); err != nil {
			t.Fatalf("track live: %v", err)
		}
		if err := rev.TrackJTI(ctx, "jti-expired", famID, now.Add(-time.Minute)); err != nil {
			t.Fatalf("track expired: %v", err)
		}
		for jti, exp := range map[string]time.Time{"jti-live": now.Add(time.Hour), "jti-expired": now.Add(-time.Minute)} {
			if err := rev.RevokeJTI(ctx, jti, exp); err != nil {
				t.Fatalf("revoke %s: %v", jti, err)
			}
		}

		n, err := rev.PurgeExpired(ctx)
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if n != 2 {
			t.Errorf("purged %d rows, want 2 (one tracking row, one blacklist row)", n)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-live"); err != nil || !revoked {
			t.Errorf("live revoked JTI lost by purge: IsRevoked = %v, %v; want true", revoked, err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-expired"); err != nil || revoked {
			t.Errorf("expired blacklist row kept: IsRevoked = %v, %v; want false", revoked, err)
		}

		if err := rev.RevokeByFamily(ctx, famID); err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-expired"); err != nil || revoked {
			t.Errorf("expired tracking row kept: family revocation denylisted it (IsRevoked = %v, %v)", revoked, err)
		}
	})

	t.Run("PurgeExpired_FamilyRevocationStillReachesLiveJTI", func(t *testing.T) {
		rev, famID := setup(t)
		ctx := context.Background()

		if err := rev.TrackJTI(ctx, "jti-live", famID, time.Now().UTC().Add(time.Hour)); err != nil {
			t.Fatalf("track live: %v", err)
		}
		if _, err := rev.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if err := rev.RevokeByFamily(ctx, famID); err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-live"); err != nil || !revoked {
			t.Errorf("family revocation after purge missed a live access token: IsRevoked = %v, %v; want true", revoked, err)
		}
	})

	// A token still verifies until the end of second exp + the clock skew, so
	// its denylist and tracking rows must survive a purge run in that last
	// second; rows a few seconds past it must go.
	t.Run("PurgeExpired_KeepsRowsWhileTheTokenVerifies", func(t *testing.T) {
		rev, famID := setup(t)
		ctx := context.Background()
		exp := LastVerifiableExp(t)
		gone := exp.Add(-3 * time.Second)

		// Denylist rows: one at the boundary, one past it. Stored expiries
		// carry the issuance instant's fraction; a whole-second one sorts
		// after every same-second cutoff in SQLite's text comparison and
		// would hide a cutoff one second too late.
		for jti, at := range map[string]time.Time{"jti-denied": exp.Add(time.Millisecond), "jti-denied-gone": gone} {
			if err := rev.TrackJTI(ctx, jti, famID, at); err != nil {
				t.Fatalf("track %s: %v", jti, err)
			}
			if err := rev.RevokeJTI(ctx, jti, at); err != nil {
				t.Fatalf("revoke %s: %v", jti, err)
			}
		}
		// Tracking-only rows. Tracked expiries carry the issuance instant's
		// fraction.
		if err := rev.TrackJTI(ctx, "jti-tracked", famID, exp.Add(50*time.Millisecond)); err != nil {
			t.Fatalf("track: %v", err)
		}
		if err := rev.TrackJTI(ctx, "jti-tracked-gone", famID, gone); err != nil {
			t.Fatalf("track gone: %v", err)
		}
		if _, err := rev.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}
		StillVerifies(t, exp)

		if revoked, err := rev.IsRevoked(ctx, "jti-denied"); err != nil || !revoked {
			t.Errorf("IsRevoked(jti-denied) = %v, %v; want true: the token still verifies", revoked, err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-denied-gone"); err != nil || revoked {
			t.Errorf("IsRevoked(jti-denied-gone) = %v, %v; want false: that token can no longer verify", revoked, err)
		}

		if err := rev.RevokeByFamily(ctx, famID); err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-tracked"); err != nil || !revoked {
			t.Errorf("family revocation missed jti-tracked (IsRevoked = %v, %v): its tracking row was purged while the token verifies", revoked, err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-tracked-gone"); err != nil || revoked {
			t.Errorf("IsRevoked(jti-tracked-gone) = %v, %v; want false: its tracking row should be purged", revoked, err)
		}
	})

	// The denylist row lives exactly as long as the expiry the caller gives,
	// the token's own exp. Purge is the observable: a row whose expiry has
	// passed goes, one still ahead stays.
	t.Run("RevokeJTI_DenylistedUntilGivenExpiry", func(t *testing.T) {
		rev, _ := setup(t)
		ctx := context.Background()
		now := time.Now().UTC()

		if err := rev.RevokeJTI(ctx, "jti-long", now.Add(3*time.Hour)); err != nil {
			t.Fatalf("revoke long-lived: %v", err)
		}
		if err := rev.RevokeJTI(ctx, "jti-past", now.Add(-time.Minute)); err != nil {
			t.Fatalf("revoke past: %v", err)
		}
		if _, err := rev.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-long"); err != nil || !revoked {
			t.Errorf("IsRevoked(jti-long) = %v, %v; want true until its expiry", revoked, err)
		}
		if revoked, err := rev.IsRevoked(ctx, "jti-past"); err != nil || revoked {
			t.Errorf("IsRevoked(jti-past) = %v, %v; want false: its given expiry has passed", revoked, err)
		}
	})

	// Revoking a JTI already on the list keeps the later expiry, in either
	// order, so a second revocation can extend a row but never shorten it.
	t.Run("RevokeJTI_KeepsLaterExpiry", func(t *testing.T) {
		rev, _ := setup(t)
		ctx := context.Background()
		now := time.Now().UTC()

		if err := rev.RevokeJTI(ctx, "jti-shorten", now.Add(time.Hour)); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if err := rev.RevokeJTI(ctx, "jti-shorten", now.Add(-time.Minute)); err != nil {
			t.Fatalf("revoke again, earlier: %v", err)
		}
		if err := rev.RevokeJTI(ctx, "jti-extend", now.Add(-time.Minute)); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if err := rev.RevokeJTI(ctx, "jti-extend", now.Add(time.Hour)); err != nil {
			t.Fatalf("revoke again, later: %v", err)
		}
		if _, err := rev.PurgeExpired(ctx); err != nil {
			t.Fatalf("purge: %v", err)
		}
		for _, jti := range []string{"jti-shorten", "jti-extend"} {
			if revoked, err := rev.IsRevoked(ctx, jti); err != nil || !revoked {
				t.Errorf("IsRevoked(%s) = %v, %v; want true: the later expiry has not passed", jti, revoked, err)
			}
		}
	})

	t.Run("RevokeJTI_ZeroExpiryRefused", func(t *testing.T) {
		rev, _ := setup(t)
		ctx := context.Background()

		if err := rev.RevokeJTI(ctx, "jti-zero", time.Time{}); err == nil {
			t.Error("RevokeJTI with a zero expiry succeeded; want an error")
		}
		if err := rev.RevokeJTI(ctx, "jti-epoch", time.Unix(0, 0)); err == nil {
			t.Error("RevokeJTI with the Unix epoch as expiry succeeded; want an error")
		}
	})
}
