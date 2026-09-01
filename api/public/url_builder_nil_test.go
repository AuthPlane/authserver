//go:build integration

package public_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/api/public/oauth"
	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// TestNewServer_NilURLs_Panics confirms apipublic.NewServer requires
// Deps.URLs: a nil URLBuilder panics rather than silently falling back.
func TestNewServer_NilURLs_Panics(t *testing.T) {
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string; value = %v", r, r)
		}
		if !strings.Contains(msg, "URLs") {
			t.Fatalf("panic message = %q, want to mention URLs", msg)
		}
	}()

	_ = apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		Auth:                  authSvc,
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		OIDC:                  mock,
		LoginDisplay: static.NewLoginDisplayProvider(config.OIDCConfig{
			DisplayName:    "Test IdP",
			ShowLocalLogin: true,
		}),
		// URLs intentionally nil: NewServer must panic.
		OIDCStateConfigProvider: testOIDCStateConfig(),
		StateCodec:              newStateCodecForTest([]byte("integration-test-key")),
		SessionCookie:           apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
}

// TestNewServer_NilSessionSecretProvider_Panics confirms apipublic.NewServer
// requires Deps.SessionSecretProvider: a nil provider panics rather than
// silently signing sessions with a random ephemeral secret.
func TestNewServer_NilSessionSecretProvider_Panics(t *testing.T) {
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string; value = %v", r, r)
		}
		if !strings.Contains(msg, "SessionSecretProvider") {
			t.Fatalf("panic message = %q, want to mention SessionSecretProvider", msg)
		}
	}()

	_ = apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider: testCORS(),
		Auth:               authSvc,
		URLs:               testURLBuilder(),
		// SessionSecretProvider intentionally nil: NewServer must panic.
		SessionCookie: apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
}

// TestNewServer_NilCORSConfigProvider_Panics confirms apipublic.NewServer
// requires Deps.CORSConfigProvider: a nil provider panics rather than silently
// falling back to a boot allowlist.
func TestNewServer_NilCORSConfigProvider_Panics(t *testing.T) {
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string; value = %v", r, r)
		}
		if !strings.Contains(msg, "CORSConfigProvider") {
			t.Fatalf("panic message = %q, want to mention CORSConfigProvider", msg)
		}
	}()

	_ = apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		Auth:                  authSvc,
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		// CORSConfigProvider intentionally nil: NewServer must panic.
		SessionCookie: apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
}

// TestRegisterLoginRoutes_NilURLs_Panics asserts that bypassing
// apipublic.NewServer and calling oauth.RegisterLoginRoutes directly with
// LoginDeps.URLs == nil panics at registration time, with a message that
// names the registrar and the missing field. Mirrors the defense-in-depth
// contract documented in F0-03 for OIDCProvider.
func TestRegisterLoginRoutes_NilURLs_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string; value = %v", r, r)
		}
		if !strings.Contains(msg, "URLs") {
			t.Fatalf("panic message = %q, want to mention URLs", msg)
		}
		if !strings.Contains(msg, "RegisterLoginRoutes") {
			t.Fatalf("panic message = %q, want to mention RegisterLoginRoutes", msg)
		}
	}()

	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	sessMW := shared.NewSessionMiddleware(
		static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		testSessionConfig(),
		"authserver_session",
		false,
	)
	mux := http.NewServeMux()

	// Auth and Display populated so the earlier nil-guards do not
	// fire — the URLs nil-check is the one we want to trip.
	oauth.RegisterLoginRoutes(mux, oauth.LoginDeps{
		Auth:    authSvc,
		Display: static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		// URLs intentionally nil.
	}, sessMW, nil, obs)
}

// TestRegisterOIDCRoutes_NilURLs_Panics mirrors the previous test for the
// OIDC federation registrar.
func TestRegisterOIDCRoutes_NilURLs_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string; value = %v", r, r)
		}
		if !strings.Contains(msg, "URLs") {
			t.Fatalf("panic message = %q, want to mention URLs", msg)
		}
		if !strings.Contains(msg, "RegisterOIDCRoutes") {
			t.Fatalf("panic message = %q, want to mention RegisterOIDCRoutes", msg)
		}
	}()

	obs := observability.NewNoop()
	sessMW := shared.NewSessionMiddleware(
		static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		testSessionConfig(),
		"authserver_session",
		false,
	)
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	mux := http.NewServeMux()

	// OIDC and OIDCProvider populated so the earlier nil-guards do not
	// fire — the URLs nil-check is the one we want to trip.
	oauth.RegisterOIDCRoutes(mux, oauth.OIDCDeps{
		OIDC: mock,
		// URLs intentionally nil.
	}, sessMW, obs)
}
