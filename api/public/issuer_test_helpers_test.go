//go:build integration

package public_test

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
)

// staticIssuerForTest is an integration-test-local implementation of
// output.IssuerProvider that returns a fixed string for every call. It
// avoids importing internal/adapters/static from integration tests,
// which would violate Gate 0 (one-way-ratchet that forbids new
// internal/ imports in integration tests).
type staticIssuerForTest string

func (s staticIssuerForTest) Issuer(_ context.Context) (string, error) { return string(s), nil }

// rootURLBuilderForTest is an integration-test-local output.URLBuilder that
// emits root paths (empty mount prefix, "/" cookie path), byte-identical to
// the OSS static default. It avoids importing internal/adapters/static from
// integration tests (Gate 0). NewServer requires Deps.URLs to be non-nil;
// testURLBuilder supplies this default for tests that don't exercise prefixing.
type rootURLBuilderForTest struct{}

func (rootURLBuilderForTest) Resolve(_ context.Context, path string) (string, error) {
	return path, nil
}

func testURLBuilder() rootURLBuilderForTest { return rootURLBuilderForTest{} }

// secretProviderForTest is an integration-test-local output.SessionSecretProvider
// that returns a fixed 32-byte secret for every call. It avoids importing
// internal/ports/output / internal/adapters from integration tests (Gate 0).
// NewServer requires Deps.SessionSecretProvider to be non-nil; testSessionSecret
// supplies this default for tests that don't exercise per-request secrets.
type secretProviderForTest []byte

func (s secretProviderForTest) Secret(_ context.Context) ([]byte, error) { return s, nil }

func testSessionSecret() secretProviderForTest {
	return secretProviderForTest("test-secret-32-bytes-long-enough")
}

// staticCORSForTest is an integration-test-local output.CORSConfigProvider that
// returns a fixed allowlist for every call. Returning a bare []string (not an
// output.* type) keeps this file free of internal/ imports (Gate 0).
// NewServer requires Deps.CORSConfigProvider to be non-nil; testCORS supplies
// this default (CORS disabled) for tests that don't exercise CORS.
type staticCORSForTest []string

func (s staticCORSForTest) AllowedOrigins(_ context.Context) ([]string, error) {
	return []string(s), nil
}

func testCORS() staticCORSForTest { return staticCORSForTest(nil) }

// sessionConfigForTest is an integration-test-local output.SessionConfigProvider
// returning a fixed policy. Unlike testCORS/testSessionSecret (which return
// stdlib types), SessionConfig is an output struct, so this file imports
// internal/ports/output (Gate-0 waivered for this seam). Centralizing the helper
// here keeps every other integration file import-free.
type sessionConfigForTest struct{ cfg output.SessionConfig }

func (s sessionConfigForTest) Config(_ context.Context) (output.SessionConfig, error) {
	return s.cfg, nil
}

func testSessionConfig() sessionConfigForTest {
	return sessionConfigForTest{output.SessionConfig{MaxAge: 24 * time.Hour, SameSite: http.SameSiteLaxMode}}
}

// testSessionConfigWith varies the two cookie-policy fields a caller can
// observe on the wire. It lives here rather than at the call site so tests
// that assert cookie attributes stay free of the internal/ports/output import.
func testSessionConfigWith(sameSite http.SameSite, secure bool) sessionConfigForTest {
	return sessionConfigForTest{output.SessionConfig{
		MaxAge:   24 * time.Hour,
		SameSite: sameSite,
		Secure:   secure,
	}}
}

// oidcStateConfigForTest is an integration-test-local
// output.OIDCStateConfigProvider returning a fixed policy. Like
// sessionConfigForTest, it relies on this file's (Gate-0 waivered) output
// import so every other integration file stays import-free.
type oidcStateConfigForTest struct{ cfg output.OIDCStateConfig }

func (s oidcStateConfigForTest) Config(_ context.Context) (output.OIDCStateConfig, error) {
	return s.cfg, nil
}

func testOIDCStateConfig() oidcStateConfigForTest {
	return oidcStateConfigForTest{output.OIDCStateConfig{MaxAge: 10 * time.Minute}}
}

// failingCORSForTest is an integration-test-local output.CORSConfigProvider that
// always fails, used to prove the middleware fails closed (no CORS headers).
type failingCORSForTest struct{}

func (failingCORSForTest) AllowedOrigins(_ context.Context) ([]string, error) {
	return nil, errors.New("cors resolution failed")
}
