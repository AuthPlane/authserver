package cimd

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// The MCP client-registration spec asks authorization servers to cache metadata
// documents "respecting HTTP cache headers". We previously cached every document
// for a fixed configured TTL and read no headers at all, which cut both ways: a
// client rotating a compromised redirect_uri waited out our full TTL before we
// honored the change, and a client serving a day-long max-age was re-fetched
// hourly for nothing.
func TestCacheLifetime(t *testing.T) {
	t.Parallel()

	const configTTL = time.Hour

	cases := []struct {
		name          string
		header        http.Header
		wantTTL       time.Duration
		wantCacheable bool
		why           string
	}{
		{
			name:          "no cache headers falls back to the configured TTL",
			header:        http.Header{},
			wantTTL:       configTTL,
			wantCacheable: true,
			why:           "this is the behavior every deployment had before headers were read",
		},
		{
			name:          "max-age is honored",
			header:        http.Header{"Cache-Control": {"max-age=300"}},
			wantTTL:       5 * time.Minute,
			wantCacheable: true,
		},
		{
			name:          "max-age above the configured ceiling is clamped down",
			header:        http.Header{"Cache-Control": {"max-age=86400"}},
			wantTTL:       configTTL,
			wantCacheable: true,
			why:           "the ceiling is the operator's; a client must not pin its identity for a day",
		},
		{
			name:          "max-age below the floor is clamped up",
			header:        http.Header{"Cache-Control": {"max-age=1"}},
			wantTTL:       minCacheTTL,
			wantCacheable: true,
			why:           "otherwise a client turns each of its authorize requests into an outbound fetch from us",
		},
		{
			name:          "max-age=0 forbids caching",
			header:        http.Header{"Cache-Control": {"max-age=0"}},
			wantCacheable: false,
		},
		{
			name:          "no-store forbids caching",
			header:        http.Header{"Cache-Control": {"no-store"}},
			wantCacheable: false,
		},
		{
			name:          "no-cache forbids caching while we cannot revalidate",
			header:        http.Header{"Cache-Control": {"no-cache"}},
			wantCacheable: false,
			why:           "no-cache permits storage with revalidation, and we have no conditional-request path",
		},
		{
			name:          "directives are matched case-insensitively and trimmed",
			header:        http.Header{"Cache-Control": {"Public,  MAX-AGE=300 "}},
			wantTTL:       5 * time.Minute,
			wantCacheable: true,
		},
		{
			name:          "no-store wins over a max-age in the same field",
			header:        http.Header{"Cache-Control": {"max-age=300, no-store"}},
			wantCacheable: false,
		},
		{
			name:          "a malformed max-age is skipped rather than trusted",
			header:        http.Header{"Cache-Control": {"max-age=abc, no-store"}},
			wantCacheable: false,
		},
		{
			name:          "Cache-Control takes precedence over Expires",
			header:        http.Header{"Cache-Control": {"max-age=300"}, "Expires": {"Mon, 01 Jan 2035 00:00:00 GMT"}},
			wantTTL:       5 * time.Minute,
			wantCacheable: true,
		},
		{
			name:          "a past Expires forbids caching",
			header:        http.Header{"Expires": {"Mon, 01 Jan 2001 00:00:00 GMT"}},
			wantCacheable: false,
		},
		{
			name:          "an unparseable Expires is treated as already expired",
			header:        http.Header{"Expires": {"not-a-date"}},
			wantCacheable: false,
			why:           "RFC 9111 says so, and the safe reading of a broken header is to re-fetch",
		},
		{
			name:          "a far-future Expires is clamped to the configured ceiling",
			header:        http.Header{"Expires": {"Mon, 01 Jan 2035 00:00:00 GMT"}},
			wantTTL:       configTTL,
			wantCacheable: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ttl, cacheable := cacheLifetime(tc.header, configTTL)

			if cacheable != tc.wantCacheable {
				t.Fatalf("cacheable = %v, want %v (%s)", cacheable, tc.wantCacheable, tc.why)
			}
			if !tc.wantCacheable {
				return
			}
			if ttl != tc.wantTTL {
				t.Errorf("ttl = %v, want %v (%s)", ttl, tc.wantTTL, tc.why)
			}
		})
	}
}

// A configured ceiling below the floor must still be honored: the operator's
// value is the ceiling, and a floor that could raise a lifetime above it would
// silently override an explicit setting.
func TestCacheLifetime_ConfigCeilingBelowFloorWins(t *testing.T) {
	t.Parallel()

	const configTTL = 10 * time.Second

	ttl, cacheable := cacheLifetime(http.Header{"Cache-Control": {"max-age=1"}}, configTTL)
	if !cacheable {
		t.Fatal("should be cacheable")
	}
	if ttl > configTTL {
		t.Errorf("ttl = %v, must not exceed the configured ceiling %v", ttl, configTTL)
	}
}

// The gate exists to reject an identifier that resolves back to the origin,
// because an origin-only client_id collapses every client on a domain into one
// consent record and display name. Checking only "" and "/" missed several
// shapes that do exactly that: url.Parse leaves "//" intact and an origin
// server that merges duplicate slashes (nginx by default) serves the root
// document for it, while "/." and "/.." resolve to the origin under RFC 3986
// dot-segment removal.
func TestHasMeaningfulPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want bool
	}{
		// Resolve to the origin — must be rejected.
		{"", false},
		{"/", false},
		{"//", false},
		{"///", false},
		{"/.", false},
		{"/./", false},
		{"/..", false},
		{"/../", false},
		{"/./.", false},
		{"/../..", false},

		// Name a document — must be accepted.
		{"/client.json", true},
		{"/oauth/client-metadata.json", true},
		{"/a", true},
		{"/.well-known/x", true},
		{"//a", true},
		{"/./a", true},
		{"/a//b", true},
		{"/..a", true},
		{"/...", true},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := hasMeaningfulPath(tc.path); got != tc.want {
				t.Errorf("hasMeaningfulPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// url.Parse percent-decodes Path before the gate sees it, so the encoded forms
// must collapse onto the same decision as their literal counterparts.
func TestHasMeaningfulPath_EncodedFormsDecodeFirst(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want bool
	}{
		{"https://example.com/%2e", false},
		{"https://example.com/%2E%2E", false},
		// %2f decodes to "/", so Path becomes "//" — indistinguishable from a
		// literal "//" once url.Parse has decoded it. Rejecting is the safe
		// reading: we cannot tell a segment literally named "/" from an
		// origin-resolving double slash, and the latter is what the gate exists
		// to stop.
		{"https://example.com/%2f", false},
		{"https://example.com/client.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := hasMeaningfulPath(u.Path); got != tc.want {
				t.Errorf("hasMeaningfulPath(%q → Path=%q) = %v, want %v", tc.raw, u.Path, got, tc.want)
			}
		})
	}
}
