package oauth

import (
	"net/url"
	"strings"
	"testing"
)

// contract_test.go is the  Track 2 (Real upstream OAuth contract)
// cadence anchor per the operator-test plan. Track 2's
// goal: prove the AS speaks RFC 6749 / OIDC correctly to real-world
// upstream providers. The full plan calls for per-provider mock
// servers that validate every required parameter the way the real
// provider would (Google, GitHub, Microsoft, Okta, Slack).
//
// This file lands the minimum the gate requires (≥1 passing test
// proving the AS-side authorize-URL builder honors the BrokerProtocol
// contract). The per-provider mocks belong in follow-up PRs — one per
// provider —
// alongside the provider-specific quirk tests (Google's
// access_type=offline, Microsoft's prompt=select_account, Slack's
// nested authed_user.access_token response, etc.) the plan
// enumerates.
//
// We test buildAuthorizeURL directly (same-package) rather than
// driving the adapter end-to-end: the URL builder is the wire
// boundary the AS controls; once it emits a spec-compliant URL,
// downstream behavior is the upstream's responsibility.

func TestAuthorizeURLContract_GoogleShape(t *testing.T) {
	cfg := configData{
		ClientID:     "google-client-id-12345.apps.googleusercontent.com",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		ExtraAuthParams: map[string]string{
			"access_type": "offline", // Google quirk
			"prompt":      "consent", // Google quirk
		},
	}

	got, err := buildAuthorizeURL(cfg, []string{"openid", "email", "profile"},
		"test-pkce-challenge", "test-state-abc", "https://as.example.com/connect/google/callback")
	if err != nil {
		t.Fatalf("buildAuthorizeURL: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	q := u.Query()

	// RFC 6749 §4.1.1 required authorize-request params.
	checkEq(t, q, "client_id", cfg.ClientID)
	checkEq(t, q, "response_type", "code")
	checkEq(t, q, "redirect_uri", "https://as.example.com/connect/google/callback")
	checkEq(t, q, "state", "test-state-abc")
	// scope must be non-empty (Bug 16 from the  demo: Google
	// rejects scope="" at the consent screen).
	checkNonEmpty(t, q, "scope")
	if scope := q.Get("scope"); !containsAll(scope, "openid", "email", "profile") {
		t.Errorf("scope = %q, want all of openid+email+profile", scope)
	}

	// RFC 7636 PKCE — S256 method is the only one MCP accepts.
	checkEq(t, q, "code_challenge", "test-pkce-challenge")
	checkEq(t, q, "code_challenge_method", "S256")

	// Google-specific quirks must round-trip from extra_auth_params.
	checkEq(t, q, "access_type", "offline")
	checkEq(t, q, "prompt", "consent")
}

func TestAuthorizeURLContract_GitHubShape(t *testing.T) {
	// GitHub uses comma-separated scopes per its docs but the AS sends
	// space-separated per RFC 6749 §3.3 — GitHub accepts both. The
	// test pins the AS's spec-compliant emission.
	cfg := configData{
		ClientID:     "Iv1.deadbeef12345678",
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
	}

	got, err := buildAuthorizeURL(cfg, []string{"repo", "read:user"},
		"ghchallenge", "ghstate", "https://as.example.com/connect/github/callback")
	if err != nil {
		t.Fatalf("buildAuthorizeURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()

	checkEq(t, q, "client_id", "Iv1.deadbeef12345678")
	checkEq(t, q, "response_type", "code")
	checkEq(t, q, "code_challenge_method", "S256")
	if scope := q.Get("scope"); scope != "repo read:user" {
		t.Errorf("scope = %q, want %q (RFC 6749 §3.3 space-separated)", scope, "repo read:user")
	}
}

func TestAuthorizeURLContract_RejectsReservedExtraAuthParams(t *testing.T) {
	// Defense in depth: extra_auth_params from operator config must not
	// be able to override RFC 6749 reserved keys (client_id,
	// response_type, redirect_uri, etc.). The reserved-key filter is in
	// brokerproto.ReservedAuthParams; this test is the wire-level proof
	// the filter fires.
	cfg := configData{
		ClientID:     "real-client",
		AuthorizeURL: "https://upstream.example.com/auth",
		TokenURL:     "https://upstream.example.com/token",
		ExtraAuthParams: map[string]string{
			"client_id":     "operator-injected-evil-id", // reserved — must be ignored
			"response_type": "token",                     // reserved — must be ignored
			"access_type":   "offline",                   // not reserved — passes through
		},
	}

	got, err := buildAuthorizeURL(cfg, []string{"read"}, "ch", "st", "https://cb")
	if err != nil {
		t.Fatalf("buildAuthorizeURL: %v", err)
	}
	q, _ := url.ParseQuery(strings.SplitN(got, "?", 2)[1])

	if q.Get("client_id") != "real-client" {
		t.Errorf("client_id was overridden by extra_auth_params: got %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type was overridden by extra_auth_params: got %q", q.Get("response_type"))
	}
	if q.Get("access_type") != "offline" {
		t.Errorf("non-reserved access_type missing: got %q", q.Get("access_type"))
	}
}

func checkEq(t *testing.T, q url.Values, key, want string) {
	t.Helper()
	if got := q.Get(key); got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}

func checkNonEmpty(t *testing.T, q url.Values, key string) {
	t.Helper()
	if q.Get(key) == "" {
		t.Errorf("%s is empty (RFC 6749 violation)", key)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
