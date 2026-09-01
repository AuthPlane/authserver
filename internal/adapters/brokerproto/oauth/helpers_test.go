package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
)

// Error-path coverage for the internal helpers parseConfigData,
// parseCredential, resolveSecret, validateExternalURL, and truncate.
// Audit HIGH-5: lift adapter coverage from 75.8% by exercising the error
// branches the httptest-driven Vend/HandleCallback tests don't reach.

// --- parseConfigData ---

func TestParseConfigData_EmptyBytes(t *testing.T) {
	if _, err := parseConfigData(nil); err == nil {
		t.Fatal("nil bytes: expected error, got nil")
	}
	if _, err := parseConfigData([]byte{}); err == nil {
		t.Fatal("empty bytes: expected error, got nil")
	}
}

func TestParseConfigData_InvalidJSON(t *testing.T) {
	_, err := parseConfigData([]byte(`{"client_id":`))
	if err == nil {
		t.Fatal("malformed JSON: expected error, got nil")
	}
}

func TestParseConfigData_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"missing client_id", `{"authorize_url":"https://x","token_url":"https://y"}`, "client_id"},
		{"missing authorize_url", `{"client_id":"c","token_url":"https://y"}`, "authorize_url"},
		{"missing token_url", `{"client_id":"c","authorize_url":"https://x"}`, "token_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigData([]byte(tc.raw))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q missing field name %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseConfigData_DefaultsResponseFormatStandard(t *testing.T) {
	cfg, err := parseConfigData([]byte(`{"client_id":"c","authorize_url":"https://x","token_url":"https://y"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ResponseFormat != responseFormatStandard {
		t.Errorf("ResponseFormat = %q, want %q (default)", cfg.ResponseFormat, responseFormatStandard)
	}
}

func TestParseConfigData_RejectsUnsupportedResponseFormat(t *testing.T) {
	_, err := parseConfigData([]byte(
		`{"client_id":"c","authorize_url":"https://x","token_url":"https://y","response_format":"xml"}`))
	if err == nil {
		t.Fatal("response_format=xml: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported response_format") {
		t.Errorf("error %q should mention unsupported response_format", err.Error())
	}
}

// --- parseCredential ---

func TestParseCredential_EmptyBytes(t *testing.T) {
	if _, err := parseCredential(nil); err == nil {
		t.Fatal("nil bytes: expected error, got nil")
	}
}

func TestParseCredential_InvalidJSON(t *testing.T) {
	if _, err := parseCredential([]byte(`{not-json`)); err == nil {
		t.Fatal("malformed JSON: expected error, got nil")
	}
}

func TestParseCredential_MissingRefreshToken(t *testing.T) {
	_, err := parseCredential([]byte(`{}`))
	if err == nil {
		t.Fatal("expected error for missing refresh_token, got nil")
	}
	if !strings.Contains(err.Error(), "refresh_token") {
		t.Errorf("error %q should mention refresh_token", err.Error())
	}
}

// --- resolveSecret (reuses stubSecretResolver from adapter_test.go) ---

func TestResolveSecret_EmptyEnvName(t *testing.T) {
	a := &Adapter{secretResolver: &stubSecretResolver{secret: "x"}}
	_, err := a.resolveSecret(context.Background(), &resource.BrokerProvider{ID: "p1"}, "")
	if !errors.Is(err, errSecretLookup) {
		t.Errorf("expected errSecretLookup, got %v", err)
	}
}

func TestResolveSecret_ResolverReturnsError(t *testing.T) {
	want := errors.New("secret unavailable")
	a := &Adapter{secretResolver: &stubSecretResolver{err: want}}
	_, err := a.resolveSecret(context.Background(), &resource.BrokerProvider{ID: "p1"}, "CLIENT_SECRET_X")
	if !errors.Is(err, errSecretLookup) {
		t.Errorf("expected errSecretLookup wrap, got %v", err)
	}
}

func TestResolveSecret_ResolverReturnsEmpty(t *testing.T) {
	a := &Adapter{secretResolver: &stubSecretResolver{secret: ""}}
	_, err := a.resolveSecret(context.Background(), &resource.BrokerProvider{ID: "p1"}, "CLIENT_SECRET_X")
	if !errors.Is(err, errSecretLookup) {
		t.Errorf("expected errSecretLookup, got %v", err)
	}
}

// --- validateExternalURL ---

func TestValidateExternalURL_RejectsLoopbackByDefault(t *testing.T) {
	if err := validateExternalURL("http://127.0.0.1/token", false); err == nil {
		t.Fatal("loopback IP without allowLoopback: expected error, got nil")
	}
}

func TestValidateExternalURL_AllowsLoopbackWhenOptedIn(t *testing.T) {
	if err := validateExternalURL("http://127.0.0.1/token", true); err != nil {
		t.Errorf("loopback with allowLoopback=true: unexpected error: %v", err)
	}
}

func TestValidateExternalURL_RejectsPrivateIP(t *testing.T) {
	for _, host := range []string{"http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.1/"} {
		if err := validateExternalURL(host, false); err == nil {
			t.Errorf("%s: expected SSRF rejection, got nil", host)
		}
	}
}

func TestValidateExternalURL_RejectsLinkLocal(t *testing.T) {
	if err := validateExternalURL("http://169.254.169.254/", false); err == nil {
		t.Fatal("link-local (169.254.169.254 — AWS metadata): expected rejection, got nil")
	}
}

func TestValidateExternalURL_RejectsUnspecified(t *testing.T) {
	if err := validateExternalURL("http://0.0.0.0/", false); err == nil {
		t.Fatal("unspecified address: expected rejection, got nil")
	}
}

// TestValidateExternalURL_RejectsSpecialUseRanges covers the IANA special-use
// ranges not previously enforced — see IsPrivateIP_SpecialUseRanges for the
// authoritative list (RFCs 6890/5737/6598/4193/3849/4291/5771/2544).
// Pre-fix CGNAT / TEST-NETs / multicast / IPv6 ::/documentation slipped past
// stdlib's net.IP.Is* predicates and the broker would happily request them.
func TestValidateExternalURL_RejectsSpecialUseRanges(t *testing.T) {
	for _, c := range []struct {
		host string
		spec string
	}{
		{"http://100.64.5.5/", "RFC 6598 CGNAT"},
		{"http://192.0.2.1/", "RFC 5737 TEST-NET-1"},
		{"http://198.18.0.1/", "RFC 2544 benchmark"},
		{"http://198.51.100.1/", "RFC 5737 TEST-NET-2"},
		{"http://203.0.113.1/", "RFC 5737 TEST-NET-3"},
		{"http://224.0.0.1/", "RFC 5771 multicast"},
		{"http://240.0.0.1/", "RFC 1112 reserved"},
		{"http://255.255.255.255/", "RFC 919 limited broadcast"},
		{"http://[::]/", "RFC 4291 IPv6 unspecified"},
		{"http://[2001:db8::1]/", "RFC 3849 IPv6 documentation"},
		{"http://[ff02::1]/", "RFC 4291 IPv6 multicast"},
	} {
		if err := validateExternalURL(c.host, false); err == nil {
			t.Errorf("%s (%s): expected SSRF rejection, got nil", c.host, c.spec)
		}
	}
}

func TestValidateExternalURL_HostnameSkipsIPCheck(t *testing.T) {
	// A DNS name that doesn't parse as an IP literal is allowed through —
	// runtime DNS resolution + the http.Client transport handle that layer.
	if err := validateExternalURL("https://oauth2.googleapis.com/token", false); err != nil {
		t.Errorf("DNS hostname: unexpected error: %v", err)
	}
}

func TestValidateExternalURL_RejectsMalformed(t *testing.T) {
	// Ports are validated by url.Parse — non-numeric port surfaces an error.
	if err := validateExternalURL("http://example.com:abc/", false); err == nil {
		t.Fatal("malformed URL: expected error, got nil")
	}
}

// --- truncate ---

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 10, ""},
		{"abc", 10, "abc"},
		{"abcdef", 3, "abc..."},
		{"abc", 3, "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := truncate(tc.in, tc.n); got != tc.want {
				t.Errorf("truncate(%q,%d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}
