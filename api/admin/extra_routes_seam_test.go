package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/config"
)

const extraTestAPIKey = "test-admin-api-key-123"

// extraDeps builds OptionalDeps carrying one extra route whose handler flips
// called and answers 200.
func extraDeps(pattern string, called *bool) apiadmin.OptionalDeps {
	return apiadmin.OptionalDeps{ExtraRoutes: []apiadmin.ExtraRoute{{
		Pattern: pattern,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*called = true
			w.WriteHeader(http.StatusOK)
		}),
	}}}
}

// getExtra issues a GET with an optional bearer credential and returns the
// response status and headers, closing the body.
func getExtra(t *testing.T, url, bearer string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header
}

func TestExtraRoute_FailClosedWithoutCredential(t *testing.T) {
	called := false
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
		extraDeps("GET /admin/extra", &called),
	)
	status, _ := getExtra(t, ts.URL+"/admin/extra", "")
	if status != http.StatusUnauthorized {
		t.Errorf("extra route without credential must fail closed (401), got %d", status)
	}
	if called {
		t.Error("extra handler must not run without a credential")
	}
}

func TestExtraRoute_ReachableWithAPIKey(t *testing.T) {
	called := false
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
		extraDeps("GET /admin/extra", &called),
	)
	status, _ := getExtra(t, ts.URL+"/admin/extra", extraTestAPIKey)
	if status != http.StatusOK {
		t.Errorf("authenticated extra route must reach the handler (200), got %d", status)
	}
	if !called {
		t.Error("extra handler was not invoked")
	}
}

// TestExtraRoute_InjectedAuthWrapperGatesIt proves an extra route shares the
// single resolved auth wrapper: an injected strategy (418 stub) gates it
// exactly as it gates the built-in business routes.
func TestExtraRoute_InjectedAuthWrapperGatesIt(t *testing.T) {
	wrapCalled := false
	handlerCalled := false
	deps := extraDeps("GET /admin/extra", &handlerCalled)
	deps.Auth = stubAuth{called: &wrapCalled}
	ts := newSeamServer(t, config.AdminConfig{Enabled: true, Address: ":0"}, deps)
	status, _ := getExtra(t, ts.URL+"/admin/extra", "")
	if status != http.StatusTeapot {
		t.Errorf("extra route must be gated by the injected AuthWrapper (418), got %d", status)
	}
	if !wrapCalled {
		t.Error("injected AuthWrapper was not applied to the extra route")
	}
	if handlerCalled {
		t.Error("extra handler must not run when the injected gate rejects")
	}
}

// TestExtraRoute_TraversesObservabilityChain: X-Request-ID is set by the
// RequestID middleware, so its presence on the extra route's response is
// externally observable proof the request went through the sealed chain.
func TestExtraRoute_TraversesObservabilityChain(t *testing.T) {
	called := false
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
		extraDeps("GET /admin/extra", &called),
	)
	_, header := getExtra(t, ts.URL+"/admin/extra", extraTestAPIKey)
	if header.Get("X-Request-ID") == "" {
		t.Error("extra route response must carry X-Request-ID (observability chain)")
	}
}

// mustPanic runs fn and fails the test unless it panics with a message
// containing want.
func mustPanic(t *testing.T, why, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Error(why)
			return
		}
		if !strings.Contains(fmt.Sprint(r), want) {
			t.Errorf("%s: panic %q does not contain %q", why, fmt.Sprint(r), want)
		}
	}()
	fn()
}

func TestExtraRoute_PatternOutsideAdminReturnsErrorAtBoot(t *testing.T) {
	called := false
	_, err := newSeamServerErr(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
		extraDeps("GET /other", &called),
	)
	if err == nil {
		t.Fatal("NewServer must return an error on an extra route outside /admin/")
	}
	if !strings.Contains(err.Error(), "must route under /admin/") {
		t.Errorf("error %q does not mention the /admin/ requirement", err)
	}
}

func TestExtraRoute_NilHandlerReturnsErrorAtBoot(t *testing.T) {
	_, err := newSeamServerErr(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
		apiadmin.OptionalDeps{ExtraRoutes: []apiadmin.ExtraRoute{{Pattern: "GET /admin/extra", Handler: nil}}},
	)
	if err == nil {
		t.Fatal("NewServer must return an error on an extra route with a nil handler")
	}
	if !strings.Contains(err.Error(), "nil handler") {
		t.Errorf("error %q does not mention the nil handler", err)
	}
}

// TestExtraRoute_CollisionWithBuiltinPanicsAtBoot pins the design decision
// that pattern collisions are left to ServeMux's native duplicate-registration
// panic at construction time (a wiring bug, not validated input).
func TestExtraRoute_CollisionWithBuiltinPanicsAtBoot(t *testing.T) {
	called := false
	mustPanic(t, "NewServer must panic when an extra route collides with a built-in route", "conflicts", func() {
		newSeamServer(t,
			config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
			extraDeps("GET /admin/clients", &called),
		)
	})
}

// TestExtraRoute_DuplicateExtraPatternsPanicAtBoot pins that two extra routes
// with the same pattern also hit ServeMux's native equal-specificity panic —
// the guarantee is not limited to collisions with built-in routes.
func TestExtraRoute_DuplicateExtraPatternsPanicAtBoot(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	deps := apiadmin.OptionalDeps{ExtraRoutes: []apiadmin.ExtraRoute{
		{Pattern: "GET /admin/extra", Handler: h},
		{Pattern: "GET /admin/extra", Handler: h},
	}}
	mustPanic(t, "NewServer must panic on two extra routes with the same pattern", "conflicts", func() {
		newSeamServer(t,
			config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
			deps,
		)
	})
}

// TestExtraRoute_MoreSpecificPatternShadowsBuiltin documents the real boundary
// of the collision guarantee: a more-specific extra pattern does NOT conflict
// with a built-in wildcard (no panic, no error) and, by ServeMux precedence,
// takes over that literal path. Here GET /admin/clients/export shadows the
// built-in GET /admin/clients/{id}. This is allowed by design — the extra route
// stays auth-gated; the downstream owns its own patterns.
func TestExtraRoute_MoreSpecificPatternShadowsBuiltin(t *testing.T) {
	called := false
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: extraTestAPIKey},
		extraDeps("GET /admin/clients/export", &called),
	)
	status, _ := getExtra(t, ts.URL+"/admin/clients/export", extraTestAPIKey)
	if status != http.StatusOK {
		t.Errorf("more-specific extra route should serve its path (200), got %d", status)
	}
	if !called {
		t.Error("extra handler should have shadowed the built-in wildcard for its literal path")
	}
}
