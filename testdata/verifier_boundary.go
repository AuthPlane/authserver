package testdata

import (
	"testing"
	"time"

	"github.com/authplane/authserver/internal/crypto"
)

// LastVerifiableExp returns the earliest exp a token can carry and still
// verify at this moment (the verifier accepts until the end of second
// exp + AccessTokenClockSkew), after waiting until early in a second so a
// short test cannot cross into the next one. A purge run right away must
// keep revocation state for a token with this exp.
//
// It also waits until at least 10 ms into the second, so a cutoff that is
// one second too late falls more than a millisecond past exp and deletes a
// row stored at exp + 1 ms.
func LastVerifiableExp(t *testing.T) time.Time {
	t.Helper()
	now := time.Now()
	for n := now.Nanosecond(); n < 10*int(time.Millisecond) || n > 300*int(time.Millisecond); n = now.Nanosecond() {
		time.Sleep(time.Millisecond)
		now = time.Now()
	}
	nowSec := now.Unix()
	return time.Unix(nowSec-int64(crypto.AccessTokenClockSkew/time.Second), 0).UTC()
}

// StillVerifies fails the test if a token with exp no longer verifies now,
// which would mean the test crossed a second boundary and proved nothing.
func StillVerifies(t *testing.T, exp time.Time) {
	t.Helper()
	if time.Now().Unix() > exp.Unix()+int64(crypto.AccessTokenClockSkew/time.Second) {
		t.Fatalf("test crossed a second boundary: a token with exp %s no longer verifies", exp.Format(time.RFC3339))
	}
}
