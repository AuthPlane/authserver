//go:build integration

package public_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/api/public/oauth"
	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// TestRegisterLoginRoutes_NilResolver_Panics asserts that calling
// oauth.RegisterLoginRoutes with LoginDeps.Display == nil (and Auth set)
// panics at registration time. LoginDisplay is required — there is no
// silent empty fallback — so a missing provider fails loud at startup
// rather than rendering a broken login page per request.
func TestRegisterLoginRoutes_NilResolver_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string; value = %v", r, r)
		}
		if !strings.Contains(msg, "Display") {
			t.Fatalf("panic message = %q, want to mention Display", msg)
		}
		if !strings.Contains(msg, "RegisterLoginRoutes") {
			t.Fatalf("panic message = %q, want to mention RegisterLoginRoutes", msg)
		}
	}()

	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	sessMW := shared.NewSessionMiddleware(
		testSessionSecret(),
		testSessionConfig(),
		"authserver_session",
		false,
	)
	mux := http.NewServeMux()

	oauth.RegisterLoginRoutes(mux, oauth.LoginDeps{
		Auth: authSvc,
		// Display intentionally nil.
	}, sessMW, nil, obs)
}
