package services

import (
	"testing"
	"time"
)

func TestDerivedExpiry_CapsAtSubjectExp(t *testing.T) {
	now := time.Unix(1_000_000, 500_000_000)
	if got := derivedExpiry(now, 15*time.Minute, now.Add(2*time.Minute).Unix()); !got.Equal(time.Unix(now.Add(2*time.Minute).Unix(), 0)) {
		t.Errorf("subject expires first: got %v, want the subject's exp", got)
	}
	if got := derivedExpiry(now, 5*time.Minute, now.Add(time.Hour).Unix()); !got.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("lifetime ends first: got %v, want now + lifetime", got)
	}
}

// The gate sits at exactly one second left: below it the derived token
// would report expires_in 0 or already be expired.
func TestHasLifetimeLeft_OneSecondBoundary(t *testing.T) {
	exp := int64(1_000_000)
	cases := []struct {
		left time.Duration
		want bool
	}{
		{2 * time.Second, true},
		{time.Second, true},
		{time.Second - time.Millisecond, false},
		{500 * time.Millisecond, false},
		{0, false},
		{-5 * time.Second, false},
	}
	for _, c := range cases {
		now := time.Unix(exp, 0).Add(-c.left)
		if got := hasLifetimeLeft(now, exp); got != c.want {
			t.Errorf("%v left: hasLifetimeLeft = %v, want %v", c.left, got, c.want)
		}
	}
}
