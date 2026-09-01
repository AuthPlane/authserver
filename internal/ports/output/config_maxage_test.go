package output

import (
	"net/http"
	"testing"
	"time"
)

// The zero-value clamp lives on the DTO so no consumer can forget it. A zero
// MaxAge must never reach a caller: for sessions it would mint an
// already-expired cookie, for OIDC state it would reject every callback.
func TestEffectiveMaxAge_ClampsNonPositiveToDefault(t *testing.T) {
	sessionCases := map[string]struct {
		in   time.Duration
		want time.Duration
	}{
		"zero falls back":     {0, DefaultSessionMaxAge},
		"negative falls back": {-time.Hour, DefaultSessionMaxAge},
		"positive preserved":  {8 * time.Hour, 8 * time.Hour},
	}
	for name, tc := range sessionCases {
		t.Run("session/"+name, func(t *testing.T) {
			if got := (SessionConfig{MaxAge: tc.in}).EffectiveMaxAge(); got != tc.want {
				t.Errorf("EffectiveMaxAge(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	stateCases := map[string]struct {
		in   time.Duration
		want time.Duration
	}{
		"zero falls back":     {0, DefaultOIDCStateMaxAge},
		"negative falls back": {-time.Minute, DefaultOIDCStateMaxAge},
		"positive preserved":  {2 * time.Minute, 2 * time.Minute},
	}
	for name, tc := range stateCases {
		t.Run("oidcstate/"+name, func(t *testing.T) {
			if got := (OIDCStateConfig{MaxAge: tc.in}).EffectiveMaxAge(); got != tc.want {
				t.Errorf("EffectiveMaxAge(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// EffectiveSameSite clamps the zero value (http.SameSiteDefaultMode, which
// http.SetCookie renders by OMITTING the attribute) up to Lax, so a provider
// that leaves the field unset can't silently emit a cookie with no SameSite.
func TestEffectiveSameSite_ClampsDefaultToLax(t *testing.T) {
	cases := map[string]struct {
		in   http.SameSite
		want http.SameSite
	}{
		"default (0) falls back to Lax": {http.SameSiteDefaultMode, http.SameSiteLaxMode},
		"lax preserved":                 {http.SameSiteLaxMode, http.SameSiteLaxMode},
		"strict preserved":              {http.SameSiteStrictMode, http.SameSiteStrictMode},
		"none preserved":                {http.SameSiteNoneMode, http.SameSiteNoneMode},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := (SessionConfig{SameSite: tc.in}).EffectiveSameSite(); got != tc.want {
				t.Errorf("EffectiveSameSite(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
